"""Short-lived authorization codes + rotating refresh tokens (Redis, Phase 1.7).

Authorization codes are single-use and short (≤10 min); refresh tokens are longer-
lived and **rotated** on each use (the presented refresh is consumed and a fresh one
issued). Both are stored only as ``sha256(token) → JSON payload`` so a Redis dump
never exposes a usable secret, mirroring :class:`TokenStore`. The payload binds the
grant to a client, the FileEngine user + tenant, scope, and (for codes) the PKCE
challenge and redirect_uri that must match at exchange time.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Optional

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

_CODE = "oauth:code"
_REFRESH = "oauth:refresh"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class OAuthCodeStore:
    def __init__(self, redis_url: str):
        self._r = redis.from_url(redis_url) if (redis and redis_url) else None

    @property
    def enabled(self) -> bool:
        return self._r is not None

    def _key(self, kind: str, token: str) -> str:
        return f"ldapmgr:{kind}:{_hash(token)}"

    # ------------------------------------------------------------- auth codes
    def issue_code(self, payload: dict, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        if self._r is not None:
            self._r.setex(self._key(_CODE, token), ttl_seconds, json.dumps(payload))
        return token

    def consume_code(self, token: str) -> Optional[dict]:
        """Single-use: return the payload and delete it, or None if unknown/expired.

        Deletion is atomic (``GETDEL``) so a replayed code can't be exchanged twice —
        the classic authorization-code injection defense."""
        if self._r is None or not token:
            return None
        key = self._key(_CODE, token)
        raw = None
        try:
            raw = self._r.getdel(key)          # redis-py ≥4.0 / Redis ≥6.2
        except AttributeError:                 # pragma: no cover
            pipe = self._r.pipeline()
            pipe.get(key)
            pipe.delete(key)
            raw = pipe.execute()[0]
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)

    # --------------------------------------------------------- refresh tokens
    def issue_refresh(self, payload: dict, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        if self._r is not None:
            self._r.setex(self._key(_REFRESH, token), ttl_seconds, json.dumps(payload))
        return token

    def consume_refresh(self, token: str) -> Optional[dict]:
        """Rotation: atomically fetch + delete the presented refresh token (the
        caller issues a fresh one). A reused/rotated token is therefore rejected."""
        if self._r is None or not token:
            return None
        key = self._key(_REFRESH, token)
        try:
            raw = self._r.getdel(key)
        except AttributeError:                 # pragma: no cover
            pipe = self._r.pipeline()
            pipe.get(key)
            pipe.delete(key)
            raw = pipe.execute()[0]
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
