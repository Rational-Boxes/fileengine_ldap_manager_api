"""Small HTTP helpers shared across routers."""
from __future__ import annotations

from fastapi import Request


def client_ip(request: Request) -> str:
    """Real client IP behind the nginx /ldapadmin proxy: first X-Forwarded-For
    hop, then X-Real-IP, then the socket peer."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
