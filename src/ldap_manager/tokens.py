"""Single-use invite + reset tokens, stored hashed in Redis (SPECIFICATION.md
§5, §5.2). Separate key namespaces; short TTLs. Only the SHA-256 of the token is
stored, so a Redis dump never exposes a usable secret.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None  # type: ignore

INVITE = "invite"
RESET = "reset"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenStore:
    def __init__(self, redis_url: str):
        self._url = redis_url
        self._r = redis.from_url(redis_url) if (redis and redis_url) else None

    @property
    def enabled(self) -> bool:
        return self._r is not None

    def _key(self, kind: str, token: str) -> str:
        return f"ldapmgr:{kind}:{_hash(token)}"

    def issue(self, kind: str, uid: str, ttl_seconds: int) -> str:
        """Mint a token for ``uid``, store ``hash → uid`` with TTL, return the raw
        token (emailed to the user; never persisted in the clear)."""
        token = secrets.token_urlsafe(32)
        if self._r is not None:
            self._r.setex(self._key(kind, token), ttl_seconds, uid)
        return token

    def consume(self, kind: str, token: str) -> Optional[str]:
        """Validate + single-use: return the ``uid`` and delete the token, or None
        if unknown/expired."""
        if self._r is None or not token:
            return None
        key = self._key(kind, token)
        uid = self._r.get(key)
        if uid is None:
            return None
        self._r.delete(key)
        return uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)

    def revoke_all_for(self, uid: str) -> None:
        """Invalidate any outstanding invite/reset tokens for a user after a
        successful password set (§5.2). Scaffold: with hashed keys this needs a
        per-uid index; TODO wire a secondary set ``ldapmgr:byuid:<uid>``."""
        # TODO(scaffold): maintain a per-uid index set to enable bulk revocation.
        return None
