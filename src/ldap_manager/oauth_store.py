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

"""OAuth 2.0 client registry — Postgres-backed (Phase 1.7).

An OAuth *client* is a relying party a tenant admin registers so it can delegate
login to FileEngine (a CMS/web-portal), obtain tokens on its own behalf
(client-credentials, e.g. a service integration), or drive the ONLYOFFICE seam.
Mirrors :class:`ServiceCredentialStore`: a pure relational-DB record (never LDAP),
secret shown **once** and stored only as ``HMAC-SHA256(secret, pepper)``.

Public clients (SPAs / native apps that can't hold a secret) register with
``token_endpoint_auth_method = none`` and **must** use PKCE; confidential clients
carry a secret and may use client-credentials.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from typing import Optional

try:  # optional at import time so unit tests / no-DB deployments still load
    import psycopg  # type: ignore
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore

_CLIENT_PREFIX = "feoc_"    # FileEngine OAuth client id (public)
_SECRET_PREFIX = "feocs_"   # the client secret

GRANT_TYPES = ("authorization_code", "refresh_token", "client_credentials")
RESPONSE_TYPES = ("code",)
AUTH_METHODS = ("client_secret_basic", "client_secret_post", "none")


def generate_client_id() -> str:
    return _CLIENT_PREFIX + secrets.token_urlsafe(12)


def generate_secret() -> str:
    return _SECRET_PREFIX + secrets.token_urlsafe(32)


def hash_secret(pepper: str, secret: str) -> bytes:
    if not pepper:
        raise RuntimeError("OAUTH_CLIENT_SECRET_PEPPER is not set; cannot hash client secrets")
    return hmac.new(pepper.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).digest()


def secret_matches(pepper: str, secret: str, stored_hash: bytes) -> bool:
    return hmac.compare_digest(hash_secret(pepper, secret), bytes(stored_hash))


def verify_pkce(verifier: str, challenge: str, method: str = "S256") -> bool:
    """RFC 7636. ``S256`` (required for public clients) compares
    base64url(sha256(verifier)) to the stored challenge; ``plain`` compares directly."""
    if not verifier or not challenge:
        return False
    if (method or "S256").upper() == "PLAIN" or method == "plain":
        return hmac.compare_digest(verifier, challenge)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)


def normalize_list(values, allowed: tuple) -> list:
    seen = {str(v).strip() for v in (values or []) if str(v).strip()}
    return [v for v in allowed if v in seen]


@dataclass
class OAuthClient:
    client_id: str
    tenant: str
    name: str
    has_secret: bool
    redirect_uris: list
    grant_types: list
    response_types: list
    scopes: list
    token_endpoint_auth_method: str
    trusted: bool          # first-party: skip the interactive consent screen
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""

    def public_dict(self) -> dict:
        return {
            "client_id": self.client_id, "tenant": self.tenant, "name": self.name,
            "has_secret": self.has_secret, "redirect_uris": self.redirect_uris,
            "grant_types": self.grant_types, "response_types": self.response_types,
            "scopes": self.scopes,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "trusted": self.trusted, "created_by": self.created_by,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }


_DDL = """
CREATE TABLE IF NOT EXISTS oauth_client (
    client_id                   TEXT PRIMARY KEY,
    tenant                      TEXT NOT NULL,
    name                        TEXT NOT NULL DEFAULT '',
    secret_hash                 BYTEA,
    redirect_uris               TEXT[] NOT NULL DEFAULT '{}',
    grant_types                 TEXT[] NOT NULL DEFAULT '{authorization_code}',
    response_types              TEXT[] NOT NULL DEFAULT '{code}',
    scopes                      TEXT[] NOT NULL DEFAULT '{openid}',
    token_endpoint_auth_method  TEXT NOT NULL DEFAULT 'client_secret_basic',
    trusted                     BOOLEAN NOT NULL DEFAULT true,
    created_by                  TEXT NOT NULL DEFAULT '',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oauth_client_tenant_idx ON oauth_client (tenant);
"""

_COLS = ("client_id, tenant, name, (secret_hash IS NOT NULL) AS has_secret, redirect_uris, "
         "grant_types, response_types, scopes, token_endpoint_auth_method, trusted, "
         "created_by, created_at::text, updated_at::text")


def _row(r) -> OAuthClient:
    return OAuthClient(
        client_id=r[0], tenant=r[1], name=r[2] or "", has_secret=bool(r[3]),
        redirect_uris=list(r[4] or []), grant_types=list(r[5] or []),
        response_types=list(r[6] or []), scopes=list(r[7] or []),
        token_endpoint_auth_method=r[8], trusted=bool(r[9]), created_by=r[10] or "",
        created_at=r[11] or "", updated_at=r[12] or "")


class OAuthClientStore:
    def __init__(self, settings):
        self.s = settings
        self._lock = threading.Lock()
        self._ddl_done = False

    def enabled(self) -> bool:
        return bool(self.s.database_url) and psycopg is not None

    def _connect(self):
        if not self.enabled():
            raise RuntimeError("oauth client store unavailable (no DATABASE_URL / psycopg)")
        conn = psycopg.connect(self.s.database_url)
        if not self._ddl_done:
            with self._lock:
                if not self._ddl_done:
                    with conn.cursor() as cur:
                        cur.execute(_DDL)
                    conn.commit()
                    self._ddl_done = True
        return conn

    def count_for(self, tenant: str) -> int:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM oauth_client WHERE tenant=%s", (tenant,))
            return int(cur.fetchone()[0])

    def create(self, *, tenant: str, name: str, redirect_uris: list, grant_types: list,
               scopes: list, token_endpoint_auth_method: str, trusted: bool,
               created_by: str, confidential: bool) -> tuple[OAuthClient, Optional[str]]:
        """Register a client. Returns ``(client, secret)`` — the secret (None for a
        public client) is shown once and never stored recoverably."""
        client_id = generate_client_id()
        secret = generate_secret() if confidential else None
        blob = hash_secret(self.s.oauth_client_pepper, secret) if secret else None
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO oauth_client (client_id, tenant, name, secret_hash, redirect_uris, "
                "grant_types, response_types, scopes, token_endpoint_auth_method, trusted, created_by) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING " + _COLS,
                (client_id, tenant, name, blob, list(redirect_uris),
                 normalize_list(grant_types, GRANT_TYPES) or ["authorization_code"],
                 ["code"], list(scopes) or ["openid"], token_endpoint_auth_method,
                 trusted, created_by))
            row = cur.fetchone()
            conn.commit()
        return _row(row), secret

    def list_for(self, tenant: str) -> list:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {_COLS} FROM oauth_client WHERE tenant=%s ORDER BY created_at DESC",
                        (tenant,))
            return [_row(r) for r in cur.fetchall()]

    def get(self, client_id: str) -> Optional[OAuthClient]:
        """Lookup by id across tenants (token/authorize time — the client_id is the key)."""
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {_COLS} FROM oauth_client WHERE client_id=%s", (client_id,))
            row = cur.fetchone()
            return _row(row) if row else None

    def get_for(self, tenant: str, client_id: str) -> Optional[OAuthClient]:
        c = self.get(client_id)
        return c if (c and c.tenant == tenant) else None

    def update(self, tenant: str, client_id: str, **fields) -> Optional[OAuthClient]:
        allowed = ("name", "redirect_uris", "grant_types", "scopes",
                   "token_endpoint_auth_method", "trusted")
        sets, params = [], []
        for k in allowed:
            if k in fields and fields[k] is not None:
                sets.append(f"{k} = %s")
                v = fields[k]
                if k == "grant_types":
                    v = normalize_list(v, GRANT_TYPES) or ["authorization_code"]
                params.append(v)
        if not sets:
            return self.get_for(tenant, client_id)
        sets.append("updated_at = now()")
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"UPDATE oauth_client SET {', '.join(sets)} "
                        f"WHERE client_id=%s AND tenant=%s RETURNING {_COLS}",
                        (*params, client_id, tenant))
            row = cur.fetchone()
            conn.commit()
            return _row(row) if row else None

    def rotate_secret(self, tenant: str, client_id: str) -> Optional[str]:
        secret = generate_secret()
        blob = hash_secret(self.s.oauth_client_pepper, secret)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE oauth_client SET secret_hash=%s, updated_at=now() "
                        "WHERE client_id=%s AND tenant=%s", (blob, client_id, tenant))
            ok = cur.rowcount > 0
            conn.commit()
        return secret if ok else None

    def delete(self, tenant: str, client_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM oauth_client WHERE client_id=%s AND tenant=%s",
                        (client_id, tenant))
            deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def verify_secret(self, client_id: str, secret: str) -> Optional[OAuthClient]:
        """Confidential-client authentication at the token endpoint."""
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {_COLS}, secret_hash FROM oauth_client WHERE client_id=%s",
                        (client_id,))
            row = cur.fetchone()
        if row is None:
            return None
        stored = row[-1]
        if stored is None or not secret_matches(self.s.oauth_client_pepper, secret, stored):
            return None
        return _row(row[:-1])
