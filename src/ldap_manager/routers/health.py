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
        "ldap_master": svc.ldap.ping_master(),   # write path must be reachable (§1.1)
    }
    ready = all(checks.values())
    if not ready:
        response.status_code = 503
    return {"ready": ready, "checks": checks}
