"""Authenticate callers by introspecting their http_bridge bearer token
(SPECIFICATION.md §2), mirroring convert_search_ai.bridge_auth — one login works
across the bridge and this service. Results are cached briefly.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

from .identity import Identity
from .jwt_verify import identity_from_claims, verify_hs256


class BridgeTokenVerifier:
    def __init__(self, base_url: str, ttl_seconds: int = 60, timeout: float = 3.0,
                 jwt_secret: str = ""):
        self.base_url = (base_url or "").rstrip("/")
        self.ttl = ttl_seconds
        self.timeout = timeout
        self.jwt_secret = jwt_secret or ""
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], tuple[Identity, float]] = {}

    @property
    def enabled(self) -> bool:
        # Verifiable if we can check signatures locally OR reach the bridge.
        return bool(self.jwt_secret) or bool(self.base_url)

    def verify(self, token: str, tenant: str) -> Optional[Identity]:
        if not token or not self.enabled:
            return None
        # Local HS256 verification (the bridge's signed JWT) — no round-trip.
        if self.jwt_secret:
            claims = verify_hs256(token, self.jwt_secret)
            if claims is not None:
                got = identity_from_claims(claims, tenant)
                if got is not None:
                    user, roles = got
                    return Identity(user=user, roles=roles,
                                    tenant=tenant or claims.get("tenant", "default"))
                return None
            # A configured secret that fails to verify means an invalid/expired
            # token — do NOT silently fall back to introspection.
            return None
        # No shared secret configured: fall back to bridge introspection (cached).
        key = (token, tenant)
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None and hit[1] > now:
                return hit[0]
        ident = self._introspect(token, tenant)
        if ident is not None:
            with self._lock:
                self._cache[key] = (ident, now + self.ttl)
        return ident

    def _introspect(self, token: str, tenant: str) -> Optional[Identity]:
        req = urllib.request.Request(self.base_url + "/v1/auth/introspect", method="GET")
        req.add_header("Authorization", "Bearer " + token)
        if tenant:
            req.add_header("X-Tenant", tenant)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return None
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return None
        if not data.get("active") or not data.get("user"):
            return None
        return Identity(
            user=data["user"],
            roles=list(data.get("roles") or []),
            tenant=tenant or data.get("tenant", "default"),
        )
