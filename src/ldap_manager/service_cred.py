"""Backend-generated service credentials (``key:secret``) for the non-interactive
doors — WebDAV and MCP (PROPOSAL §15/§16).

The identity service owns the store: a 256-bit secret is generated here, shown to
the user exactly **once**, and persisted only as ``HMAC-SHA256(secret, pepper)`` —
never recoverable. A credential is a pure relational-DB record (Postgres), **never
LDAP**; LDAP stays the authority for identity + roles only. Each credential carries
a **scope set** (``webdav`` and/or ``mcp``) so a key is valid only on the door(s) it
lists (least privilege), an optional label, optional expiry, and an optional
per-key IP allowlist for pinning agent keys (§16.5).

Verification is a fast MAC compare (the secret is full-entropy, so a slow KDF buys
nothing) behind a constant-time check; `webdav_bridge` and the MCP door call the
internal verify endpoint that wraps :meth:`ServiceCredentialStore.verify`.
"""
from __future__ import annotations

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


# The doors a credential may be scoped to. The scope set is the authoritative
# control; the key_id prefix (below) is cosmetic (aids secret scanning).
ALL_SCOPES = ("webdav", "mcp")

# Distinctive prefixes so leaked-credential scanners can flag exposure. The key_id
# (public) rides in the Basic username; the secret (never stored in plaintext) is
# the Basic password.
_KEY_PREFIX = "fesk_"      # FileEngine service key (public identifier)
_SECRET_PREFIX = "fesks_"  # the secret material


def normalize_scopes(scopes: Optional[list[str]]) -> list[str]:
    """Lower-case, de-dup, drop unknowns, preserve a stable order. Empty input →
    ``['webdav']`` (the common default)."""
    seen = {s.strip().lower() for s in (scopes or []) if s and s.strip()}
    out = [s for s in ALL_SCOPES if s in seen]
    return out or ["webdav"]


def generate_key_id() -> str:
    return _KEY_PREFIX + secrets.token_urlsafe(12)


def generate_secret() -> str:
    """A 256-bit, URL-safe secret shown once at creation."""
    return _SECRET_PREFIX + secrets.token_urlsafe(32)


def hash_secret(pepper: str, secret: str) -> bytes:
    """``HMAC-SHA256(secret, pepper)`` — what we store. The server pepper defends a
    bare DB read; a fast MAC is sufficient for a full-entropy secret."""
    if not pepper:
        raise RuntimeError("SERVICE_CRED_HASH_PEPPER is not set; cannot hash service secrets")
    return hmac.new(pepper.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).digest()


def secret_matches(pepper: str, secret: str, stored_hash: bytes) -> bool:
    return hmac.compare_digest(hash_secret(pepper, secret), bytes(stored_hash))


@dataclass
class CredentialMeta:
    key_id: str
    label: Optional[str]
    scopes: list[str]
    allowed_cidrs: list[str]
    created_at: str
    last_used_at: Optional[str]
    expires_at: Optional[str]


_DDL = """
CREATE TABLE IF NOT EXISTS service_credential (
    key_id        TEXT PRIMARY KEY,
    tenant        TEXT NOT NULL,
    uid           TEXT NOT NULL,
    secret_hash   BYTEA NOT NULL,
    scopes        TEXT[] NOT NULL DEFAULT '{webdav}',
    label         TEXT,
    allowed_cidrs TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS service_credential_owner_idx ON service_credential (tenant, uid);
"""


class ServiceCredentialStore:
    """Postgres-backed ``key:secret`` credentials, mirroring ``TwoFactorStore``'s
    lazy-DDL pattern."""

    def __init__(self, settings):
        self.s = settings
        self._lock = threading.Lock()
        self._ddl_done = False

    def enabled(self) -> bool:
        return bool(self.s.database_url) and psycopg is not None

    def _connect(self):
        if not self.enabled():
            raise RuntimeError("service-credential store unavailable (no DATABASE_URL / psycopg)")
        conn = psycopg.connect(self.s.database_url)
        if not self._ddl_done:
            with self._lock:
                if not self._ddl_done:
                    with conn.cursor() as cur:
                        cur.execute(_DDL)
                    conn.commit()
                    self._ddl_done = True
        return conn

    # ------------------------------ self-service ----------------------------

    def count_for(self, uid: str) -> int:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM service_credential WHERE uid=%s", (uid,))
            return int(cur.fetchone()[0])

    def create(self, *, tenant: str, uid: str, scopes: list[str], label: Optional[str],
               expires_at=None, allowed_cidrs: Optional[list[str]] = None) -> tuple[str, str]:
        """Mint a credential; returns ``(key_id, secret)`` — the secret is shown
        once and never stored in recoverable form."""
        key_id = generate_key_id()
        secret = generate_secret()
        blob = hash_secret(self.s.service_cred_pepper, secret)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO service_credential "
                "(key_id, tenant, uid, secret_hash, scopes, label, allowed_cidrs, expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (key_id, tenant, uid, blob, normalize_scopes(scopes), label,
                 list(allowed_cidrs or []), expires_at))
            conn.commit()
        return key_id, secret

    def list_for(self, uid: str) -> list[CredentialMeta]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT key_id, label, scopes, allowed_cidrs, created_at, last_used_at, expires_at "
                "FROM service_credential WHERE uid=%s ORDER BY created_at DESC", (uid,))
            rows = cur.fetchall()
        return [CredentialMeta(
            key_id=r[0], label=r[1], scopes=list(r[2] or []), allowed_cidrs=list(r[3] or []),
            created_at=r[4].isoformat() if r[4] else "",
            last_used_at=r[5].isoformat() if r[5] else None,
            expires_at=r[6].isoformat() if r[6] else None) for r in rows]

    def _owned(self, cur, key_id: str, uid: str):
        cur.execute("SELECT tenant, scopes, allowed_cidrs, expires_at "
                    "FROM service_credential WHERE key_id=%s AND uid=%s", (key_id, uid))
        return cur.fetchone()

    def rotate(self, *, key_id: str, uid: str, new_key_id: bool = False) -> Optional[tuple[str, str]]:
        """Regenerate the secret for a credential the caller owns. ``new_key_id``
        issues a fresh key_id (and drops the old) instead of rotating in place. The
        old secret stops working immediately. Returns ``(key_id, secret)`` or None
        if the caller doesn't own ``key_id``."""
        secret = generate_secret()
        blob = hash_secret(self.s.service_cred_pepper, secret)
        with self._connect() as conn, conn.cursor() as cur:
            row = self._owned(cur, key_id, uid)
            if row is None:
                return None
            tenant, scopes, allowed_cidrs, expires_at = row
            if new_key_id:
                fresh = generate_key_id()
                cur.execute(
                    "INSERT INTO service_credential "
                    "(key_id, tenant, uid, secret_hash, scopes, label, allowed_cidrs, expires_at) "
                    "SELECT %s, tenant, uid, %s, scopes, label, allowed_cidrs, expires_at "
                    "FROM service_credential WHERE key_id=%s AND uid=%s",
                    (fresh, blob, key_id, uid))
                cur.execute("DELETE FROM service_credential WHERE key_id=%s AND uid=%s",
                            (key_id, uid))
                out_key = fresh
            else:
                cur.execute("UPDATE service_credential SET secret_hash=%s WHERE key_id=%s AND uid=%s",
                            (blob, key_id, uid))
                out_key = key_id
            conn.commit()
        return out_key, secret

    def revoke(self, *, key_id: str, uid: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM service_credential WHERE key_id=%s AND uid=%s", (key_id, uid))
            deleted = cur.rowcount
            conn.commit()
        return deleted > 0

    # ------------------------------ verification ----------------------------

    def verify(self, *, key_id: str, secret: str, tenant: str, scope: str,
               source_ip: Optional[str] = None) -> Optional[str]:
        """The internal auth path used by the WebDAV/MCP doors. Returns the ``uid``
        iff the key exists, the secret matches, the key is scoped to ``scope`` and
        bound to ``tenant``, isn't expired, and (if an IP allowlist is set) the
        source IP is permitted. Best-effort ``last_used_at`` bump on success."""
        if scope not in ALL_SCOPES:
            return None
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT uid, secret_hash, scopes, allowed_cidrs "
                "FROM service_credential "
                "WHERE key_id=%s AND tenant=%s AND revoked_at IS NULL "
                "AND (expires_at IS NULL OR expires_at > now())",
                (key_id, tenant))
            row = cur.fetchone()
            if row is None:
                return None
            uid, stored_hash, scopes, allowed_cidrs = row
            if scope not in (scopes or []):
                return None
            if not secret_matches(self.s.service_cred_pepper, secret, stored_hash):
                return None
            if allowed_cidrs and not _ip_in_cidrs(source_ip, list(allowed_cidrs)):
                return None
            cur.execute("UPDATE service_credential SET last_used_at=now() WHERE key_id=%s",
                        (key_id,))
            conn.commit()
        return uid


def _ip_in_cidrs(ip: Optional[str], cidrs: list[str]) -> bool:
    """True if ``ip`` falls within any CIDR in ``cidrs``. Missing IP or an
    unparseable entry is treated as *not* matching (fail-closed for the pin)."""
    if not ip:
        return False
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False
