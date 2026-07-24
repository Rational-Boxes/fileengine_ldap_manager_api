# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Per-tenant WebDAV session TTL (PROPOSAL §14.10).

How long a WebDAV-authorizing session-presence entry survives is a tenant's main
WebDAV security-stance knob: a short TTL expires WebDAV soon after the browser
session would lapse (tighter), a longer one favors uninterrupted work. The stance
is per-tenant, overriding the deployment default, clamped to deployment
``MIN``/``MAX`` bounds so a tenant can't pick a pathological value.

http_bridge reads the *effective* TTL at login/refresh (§14.2) to score the Redis
session member; enforcement itself is unchanged.
"""
from __future__ import annotations

import threading
from typing import Optional

try:  # optional at import time so unit tests / no-DB deployments still load
    import psycopg  # type: ignore
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore


def clamp_ttl(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


_DDL = """
CREATE TABLE IF NOT EXISTS tenant_webdav_policy (
    tenant              TEXT PRIMARY KEY,
    session_ttl_seconds INTEGER,          -- NULL = inherit the deployment default
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


class WebDavSessionPolicyStore:
    """Per-tenant WebDAV session TTL, mirroring ``TwoFactorPolicyStore``'s lazy-DDL
    pattern; serves the deployment default with no DB."""

    def __init__(self, settings):
        self.s = settings
        self._lock = threading.Lock()
        self._ddl_done = False

    def enabled(self) -> bool:
        return bool(self.s.database_url) and psycopg is not None

    def _connect(self):
        if not self.enabled():
            raise RuntimeError("WebDAV policy store unavailable (no DATABASE_URL / psycopg)")
        conn = psycopg.connect(self.s.database_url)
        if not self._ddl_done:
            with self._lock:
                if not self._ddl_done:
                    with conn.cursor() as cur:
                        cur.execute(_DDL)
                    conn.commit()
                    self._ddl_done = True
        return conn

    def _raw(self, tenant: str) -> Optional[int]:
        """The tenant's stored override (seconds), or None to inherit the default.
        Never raises when the store is unconfigured — returns None (inherit)."""
        if not self.enabled():
            return None
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT session_ttl_seconds FROM tenant_webdav_policy WHERE tenant=%s",
                        (tenant,))
            row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else None

    def effective_ttl(self, tenant: str) -> int:
        """The TTL http_bridge should use: the tenant override if set, else the
        deployment default — always clamped to the deployment MIN/MAX bounds."""
        raw = self._raw(tenant)
        base = self.s.webdav_session_ttl_default if raw is None else raw
        return clamp_ttl(base, self.s.webdav_session_ttl_min, self.s.webdav_session_ttl_max)

    def get(self, tenant: str) -> dict:
        """Admin view: the stored override (or None = inherit), the effective value,
        and the deployment default + clamp bounds (so the UI can render the range)."""
        return {
            "session_ttl_seconds": self._raw(tenant),
            "effective_ttl_seconds": self.effective_ttl(tenant),
            "default_ttl_seconds": self.s.webdav_session_ttl_default,
            "min_ttl_seconds": self.s.webdav_session_ttl_min,
            "max_ttl_seconds": self.s.webdav_session_ttl_max,
        }

    def set(self, tenant: str, session_ttl_seconds: Optional[int]) -> None:
        """Upsert the override. ``None`` clears it (inherit the deployment default).
        A provided value is clamped to the deployment bounds before storing."""
        val = (None if session_ttl_seconds is None
               else clamp_ttl(int(session_ttl_seconds),
                              self.s.webdav_session_ttl_min, self.s.webdav_session_ttl_max))
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenant_webdav_policy (tenant, session_ttl_seconds, updated_at) "
                "VALUES (%s, %s, now()) "
                "ON CONFLICT (tenant) DO UPDATE SET "
                "session_ttl_seconds=EXCLUDED.session_ttl_seconds, updated_at=now()",
                (tenant, val))
            conn.commit()
