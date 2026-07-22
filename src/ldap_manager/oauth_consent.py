"""Per-user OAuth consent records (Phase 1.7 consent UI).

When an **untrusted** OAuth client asks for authorization, the user is shown a
consent screen (client + requested scopes) and approves or denies. If they choose
"remember", the grant is recorded here so they are not re-prompted for that client
until the grant no longer covers the requested scopes (or is revoked). First-party
(``trusted``) clients skip consent entirely and never appear here.

A grant is ``(tenant, user, client_id) → the union of scopes granted so far``.
:meth:`has` is satisfied only when the stored grant is a **superset** of what's now
requested, so asking for a *new* scope re-prompts. Stored in Postgres so it's
durable and revocable (the natural home for a standing authorization decision).
"""
from __future__ import annotations

import threading
from typing import List

try:  # optional at import time so unit tests / no-DB deployments still load
    import psycopg  # type: ignore
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore


_DDL = """
CREATE TABLE IF NOT EXISTS oauth_consent (
    tenant      TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, user_id, client_id)
);
"""


def _norm(scopes) -> List[str]:
    return sorted({str(s).strip() for s in (scopes or []) if str(s).strip()})


class OAuthConsentStore:
    def __init__(self, settings):
        self.s = settings
        self._lock = threading.Lock()
        self._ddl_done = False

    def enabled(self) -> bool:
        return bool(self.s.database_url) and psycopg is not None

    def _connect(self):
        if not self.enabled():
            raise RuntimeError("oauth consent store unavailable (no DATABASE_URL / psycopg)")
        conn = psycopg.connect(self.s.database_url)
        if not self._ddl_done:
            with self._lock:
                if not self._ddl_done:
                    with conn.cursor() as cur:
                        cur.execute(_DDL)
                    conn.commit()
                    self._ddl_done = True
        return conn

    def has(self, tenant: str, user_id: str, client_id: str, scopes) -> bool:
        """True iff a stored grant covers **all** the requested scopes."""
        want = set(_norm(scopes))
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT scopes FROM oauth_consent "
                        "WHERE tenant=%s AND user_id=%s AND client_id=%s",
                        (tenant, user_id, client_id))
            row = cur.fetchone()
        if row is None:
            return False
        return want.issubset(set(row[0] or []))

    def grant(self, tenant: str, user_id: str, client_id: str, scopes) -> None:
        """Record consent, unioning with any previously-granted scopes."""
        new = _norm(scopes)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO oauth_consent (tenant, user_id, client_id, scopes) "
                "VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (tenant, user_id, client_id) DO UPDATE SET "
                "  scopes = ("
                "    SELECT array(SELECT DISTINCT unnest(oauth_consent.scopes || EXCLUDED.scopes) ORDER BY 1)"
                "  ), updated_at = now()",
                (tenant, user_id, client_id, new))
            conn.commit()

    def revoke(self, tenant: str, user_id: str, client_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM oauth_consent "
                        "WHERE tenant=%s AND user_id=%s AND client_id=%s",
                        (tenant, user_id, client_id))
            deleted = cur.rowcount > 0
            conn.commit()
        return deleted
