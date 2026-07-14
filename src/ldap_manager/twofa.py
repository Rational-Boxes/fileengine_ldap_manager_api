"""Two-factor authentication (TOTP + email fallback) — the identity service owns
the secret, enrollment, and verification (PROPOSAL §4).

No third-party TOTP dependency: RFC 6238 TOTP is implemented on the stdlib; secrets
are encrypted at rest with ``cryptography.Fernet``; the QR is rendered client-side
from the returned ``otpauth://`` URI (keeps the backend dependency-free and honors
the SPA's strict CSP).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet

try:  # optional at import time so unit tests / no-DB deployments still load
    import psycopg  # type: ignore
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore


# --------------------------- TOTP (RFC 6238 / 4226) ---------------------------
# Defaults are pinned for broad authenticator-app compatibility: many mobile
# authenticators silently assume SHA1 / 6 digits / 30s regardless of the otpauth
# params, so a "fancier" config causes mismatched codes. Do not change these.
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_ALGO = "SHA1"


def random_secret(n_bytes: int = 20) -> str:
    """A base32 (RFC 4648) TOTP secret, unpadded. 20 bytes = 160-bit."""
    return base64.b32encode(secrets.token_bytes(n_bytes)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_at(secret_b32: str, for_time: float,
            period: int = TOTP_PERIOD, digits: int = TOTP_DIGITS) -> str:
    return _hotp(secret_b32, int(for_time // period), digits)


def totp_verify(secret_b32: str, code: str, *, for_time: Optional[float] = None,
                window: int = 1, period: int = TOTP_PERIOD, digits: int = TOTP_DIGITS) -> bool:
    """Constant-time verify, tolerating ±``window`` time-steps of clock skew."""
    code = (code or "").strip()
    if not code.isdigit():
        return False
    now = time.time() if for_time is None else for_time
    counter = int(now // period)
    ok = False
    for w in range(-window, window + 1):
        # Iterate the full window (no early return) to avoid a timing side-channel.
        ok = hmac.compare_digest(_hotp(secret_b32, counter + w, digits), code) or ok
    return ok


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    """The ``otpauth://`` URI the SPA renders as a QR (and shows for manual entry)."""
    # Standard label is "Issuer:account" with a LITERAL colon separator; encode the
    # two components but keep the ":" (authenticators expect it).
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    params = urlencode({
        "secret": secret_b32, "issuer": issuer,
        "algorithm": TOTP_ALGO, "digits": TOTP_DIGITS, "period": TOTP_PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"


# --------------------------- recovery codes ----------------------------------

_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no ambiguous 0/O/1/I


def generate_recovery_codes(n: int = 10) -> list[str]:
    out = []
    for _ in range(n):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        out.append(f"{raw[:5]}-{raw[5:]}")
    return out


def hash_recovery_code(code: str) -> str:
    """Case/format-insensitive hash of a recovery code (stored, never the plaintext)."""
    normalized = code.replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


# --------------------------- secret encryption -------------------------------

def _fernet(totp_secret_key: str) -> Fernet:
    if not totp_secret_key:
        raise RuntimeError("TOTP_SECRET_KEY is not set; cannot encrypt/decrypt 2FA secrets")
    key = totp_secret_key.encode() if isinstance(totp_secret_key, str) else totp_secret_key
    return Fernet(key)


def encrypt_secret(totp_secret_key: str, secret_b32: str) -> bytes:
    return _fernet(totp_secret_key).encrypt(secret_b32.encode("ascii"))


def decrypt_secret(totp_secret_key: str, blob: bytes) -> str:
    return _fernet(totp_secret_key).decrypt(bytes(blob)).decode("ascii")


# --------------------------- method policy (§4.8) ----------------------------

ALL_METHODS = ("totp", "email")  # "webauthn" reserved for V2


def parse_methods(raw: str) -> list[str]:
    return [m.strip().lower() for m in (raw or "").split(",") if m.strip()]


def effective_methods(deployment_cap: list[str],
                      tenant_allowed: Optional[list[str]] = None) -> list[str]:
    """``deployment_cap ∩ tenant_allowed`` (tenant ``None`` inherits the cap),
    dropping unknown methods and preserving a stable order. (PROPOSAL §4.8)"""
    cap = [m for m in deployment_cap if m in ALL_METHODS]
    allowed = cap if tenant_allowed is None else [m for m in tenant_allowed if m in cap]
    return [m for m in ALL_METHODS if m in allowed]


# --------------------------- persistence -------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS user_2fa (
    tenant         TEXT NOT NULL,
    uid            TEXT NOT NULL,
    totp_secret    BYTEA,
    enabled        BOOLEAN NOT NULL DEFAULT false,
    recovery_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, uid)
);
"""


@dataclass
class TwoFactorStatus:
    enabled: bool
    pending: bool            # a secret exists but 2FA has not been verified/enabled yet
    recovery_remaining: int


class TwoFactorStore:
    """Postgres-backed 2FA state, mirroring ``TemplateStore``'s lazy-DDL pattern."""

    def __init__(self, settings):
        self.s = settings
        self._lock = threading.Lock()
        self._ddl_done = False

    def enabled(self) -> bool:
        return bool(self.s.database_url) and psycopg is not None

    def _connect(self):
        if not self.enabled():
            raise RuntimeError("2FA store unavailable (no DATABASE_URL / psycopg)")
        conn = psycopg.connect(self.s.database_url)
        if not self._ddl_done:
            with self._lock:
                if not self._ddl_done:
                    with conn.cursor() as cur:
                        cur.execute(_DDL)
                    conn.commit()
                    self._ddl_done = True
        return conn

    def status(self, tenant: str, uid: str) -> TwoFactorStatus:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT enabled, totp_secret, recovery_codes "
                        "FROM user_2fa WHERE tenant=%s AND uid=%s", (tenant, uid))
            row = cur.fetchone()
        if not row:
            return TwoFactorStatus(False, False, 0)
        enabled, secret, codes = row
        remaining = sum(1 for c in (codes or []) if not c.get("used_at"))
        return TwoFactorStatus(bool(enabled), secret is not None and not enabled, remaining)

    def is_enabled(self, tenant: str, uid: str) -> bool:
        return self.status(tenant, uid).enabled

    def set_pending_secret(self, tenant: str, uid: str, secret_b32: str) -> None:
        blob = encrypt_secret(self.s.totp_secret_key, secret_b32)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO user_2fa (tenant, uid, totp_secret, enabled, updated_at) "
                "VALUES (%s,%s,%s,false, now()) "
                "ON CONFLICT (tenant, uid) DO UPDATE SET "
                "totp_secret=EXCLUDED.totp_secret, enabled=false, updated_at=now()",
                (tenant, uid, blob))
            conn.commit()

    def get_secret(self, tenant: str, uid: str) -> Optional[str]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT totp_secret FROM user_2fa WHERE tenant=%s AND uid=%s", (tenant, uid))
            row = cur.fetchone()
        if not row or row[0] is None:
            return None
        return decrypt_secret(self.s.totp_secret_key, row[0])

    def enable(self, tenant: str, uid: str, recovery_hashes: list[str]) -> None:
        codes = json.dumps([{"hash": h, "used_at": None} for h in recovery_hashes])
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE user_2fa SET enabled=true, recovery_codes=%s, updated_at=now() "
                        "WHERE tenant=%s AND uid=%s", (codes, tenant, uid))
            conn.commit()

    def disable(self, tenant: str, uid: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM user_2fa WHERE tenant=%s AND uid=%s", (tenant, uid))
            conn.commit()

    def consume_recovery_code(self, tenant: str, uid: str, code: str) -> bool:
        """Single-use: mark a matching, unused recovery code as used. Atomic."""
        h = hash_recovery_code(code)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT recovery_codes FROM user_2fa "
                        "WHERE tenant=%s AND uid=%s FOR UPDATE", (tenant, uid))
            row = cur.fetchone()
            if not row:
                return False
            codes = row[0] or []
            for entry in codes:
                if entry.get("hash") == h and not entry.get("used_at"):
                    entry["used_at"] = int(time.time())
                    cur.execute("UPDATE user_2fa SET recovery_codes=%s, updated_at=now() "
                                "WHERE tenant=%s AND uid=%s", (json.dumps(codes), tenant, uid))
                    conn.commit()
                    return True
        return False
