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

    def _uid_index(self, uid: str) -> str:
        # Hashed so a Redis dump never exposes the address; indexes a user's live
        # token keys for bulk revocation.
        return f"ldapmgr:byuid:{_hash(uid)}"

    def issue(self, kind: str, uid: str, ttl_seconds: int) -> str:
        """Mint a token for ``uid``, store ``hash → uid`` with TTL, index it under
        the uid, and return the raw token (emailed; never persisted in the clear)."""
        token = secrets.token_urlsafe(32)
        if self._r is not None:
            key = self._key(kind, token)
            idx = self._uid_index(uid)
            pipe = self._r.pipeline()
            pipe.setex(key, ttl_seconds, uid)
            pipe.sadd(idx, key)
            # only extend the index's life so it outlives every live token for the uid
            try:
                pipe.expire(idx, ttl_seconds, gt=True)
            except TypeError:  # redis-py without GT support
                pipe.expire(idx, ttl_seconds)
            pipe.execute()
        return token

    def consume(self, kind: str, token: str) -> Optional[str]:
        """Validate + single-use: return the ``uid`` and delete the token (and its
        index entry), or None if unknown/expired."""
        if self._r is None or not token:
            return None
        key = self._key(kind, token)
        uid = self._r.get(key)
        if uid is None:
            return None
        uid = uid.decode("utf-8") if isinstance(uid, bytes) else str(uid)
        pipe = self._r.pipeline()
        pipe.delete(key)
        pipe.srem(self._uid_index(uid), key)
        pipe.execute()
        return uid

    def revoke_all_for(self, uid: str) -> None:
        """Invalidate every outstanding invite/reset token for a user after a
        successful password set (§5.2), via the per-uid index."""
        if self._r is None:
            return
        idx = self._uid_index(uid)
        keys = self._r.smembers(idx)
        pipe = self._r.pipeline()
        for k in keys:
            pipe.delete(k)
        pipe.delete(idx)
        pipe.execute()

    def rate_ok(self, bucket: str, limit: int, window_s: int) -> bool:
        """Fixed-window rate limit: True if ``bucket`` is under ``limit`` in the
        current ``window_s``. No-op (allow) when Redis is off or limit<=0."""
        if self._r is None or limit <= 0:
            return True
        key = f"ldapmgr:rl:{bucket}"
        n = self._r.incr(key)
        if n == 1:
            self._r.expire(key, window_s)
        return n <= limit
