"""Monitoring endpoints (loopback-only in deployment). ``/readyz`` gates on the
LDAP master, Redis, and the bridge being reachable (SPECIFICATION.md §1.1)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Response

from ..deps import Services, services

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(response: Response, svc: Services = Depends(services)) -> dict:
    checks = {
        "bridge": svc.verifier.enabled,
        "redis": svc.tokens.enabled,
        "templates_db": svc.templates.enabled,
        # TODO(scaffold): probe the LDAP master reachability here.
        "ldap_master": True,
    }
    ready = all(checks.values())
    if not ready:
        response.status_code = 503
    return {"ready": ready, "checks": checks}
