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

"""Self-service profile — any authenticated user edits **only their own** account
(SPECIFICATION.md §5.3). Hard-scoped to the caller's DN; never another user.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from ..deps import Services, require_identity, services
from ..identity import Identity
from ..netutil import client_ip
from ..schemas import PasswordChange, ProfileOut, ProfileUpdate

router = APIRouter(prefix="/v1/me")


@router.get("", response_model=ProfileOut)
def get_me(svc: Services = Depends(services), ident: Identity = Depends(require_identity)) -> ProfileOut:
    user = svc.ldap.get_user(ident.user) or {}
    return ProfileOut(
        uid=ident.user,
        email=user.get("email", ident.user),
        display_name=user.get("display_name", ""),
        given_name=user.get("given_name", ""),
        surname=user.get("surname", ""),
        avatar_url=user.get("avatar_url", ""),
        tenant=ident.tenant,
        roles=ident.roles,
    )


@router.patch("", response_model=ProfileOut)
def update_me(
    body: ProfileUpdate,
    svc: Services = Depends(services),
    ident: Identity = Depends(require_identity),
) -> ProfileOut:
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    svc.ldap.update_profile(ident.user, **fields)   # master write, own DN only
    # Best-effort: a self-service profile edit is a low-stakes cosmetic change.
    # Record which fields changed, not their (possibly PII) values.
    svc.audit.emit(category="user", action="profile_update", outcome="ok", actor=ident.user,
                   tenant=ident.tenant, target_uid=ident.user, target_type="principal",
                   detail={"fields": sorted(fields.keys())})
    return get_me(svc, ident)


@router.post("/password")
def change_password(
    body: PasswordChange,
    request: Request,
    svc: Services = Depends(services),
    ident: Identity = Depends(require_identity),
) -> dict:
    ip = client_ip(request)
    # Verify the current password by binding as the caller (§5.3).
    if not svc.ldap._bind_as(svc.ldap.user_dn(ident.user), body.current_password):
        # A wrong current password is the nearest thing to a login-failure signal
        # this service sees — record it (best-effort; the op is already refused).
        svc.audit.emit(action="password_change", outcome="denied", actor=ident.user,
                       tenant=ident.tenant, actor_roles=ident.roles, source_addr=ip)
        raise HTTPException(status_code=403, detail="current password is incorrect")
    res = svc.policy.validate(body.new_password, uid=ident.user)
    if not res.ok:
        raise HTTPException(status_code=422, detail={"error": "password_policy", "unmet": res.unmet})
    # Fail-closed write-ahead (§6): record the credential change before it applies;
    # refuse rather than change a password un-audited.
    if not svc.audit.emit(action="password_change", outcome="ok", actor=ident.user,
                          tenant=ident.tenant, actor_roles=ident.roles, source_addr=ip):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    try:
        svc.ldap.set_password(ident.user, body.new_password)
    except Exception:
        svc.audit.emit(action="password_change", outcome="error", actor=ident.user,
                       tenant=ident.tenant, actor_roles=ident.roles, source_addr=ip)
        raise
    return {"status": "ok"}
