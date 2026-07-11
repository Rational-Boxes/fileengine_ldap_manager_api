"""Tenant-admin role management (SPECIFICATION.md §4, §7). Every route requires
``administrators`` membership of the caller's tenant and is scoped to that
tenant's ou. Adding an existing user to a role may trigger the ``access_granted``
email (§5-B); ``administrators`` has self-removal / last-admin / undeletable
guards.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..deps import Services, require_tenant_admin, services
from ..identity import Identity
from ..schemas import MemberAdd, RoleCreate, RoleOut

router = APIRouter(prefix="/v1/admin/roles")
ADMINS = "administrators"


@router.get("", response_model=list[RoleOut])
def list_roles(svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    return [RoleOut(**r) for r in svc.ldap.list_roles(ident.tenant)]


@router.post("", response_model=RoleOut, status_code=201)
def create_role(body: RoleCreate, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    # Fail-closed write-ahead (§6): record the privilege change before it applies.
    if not svc.audit.emit(category="user", action="role_create", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=body.name,
                          target_type="role"):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.ldap.create_role(ident.tenant, body.name)
    return RoleOut(name=body.name, dn=svc.ldap.role_dn(ident.tenant, body.name), member_count=0)


@router.delete("/{role}", status_code=204)
def delete_role(role: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    if role == ADMINS:
        raise HTTPException(status_code=400, detail="the administrators group cannot be deleted")
    if not svc.audit.emit(category="user", action="role_delete", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=role,
                          target_type="role"):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.ldap.delete_role(ident.tenant, role)


@router.get("/{role}/members")
def list_members(role: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    return {"members": svc.ldap.list_members(ident.tenant, role)}


@router.post("/{role}/members", status_code=204)
def add_member(role: str, body: MemberAdd, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    # First membership in this tenant → access_granted email (§5-B).
    first_grant = not svc.ldap.is_tenant_member(body.uid, ident.tenant)
    if not svc.audit.emit(category="user", action="role_assign_user", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=body.uid,
                          target_type="principal", detail={"role": role}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.ldap.add_member(ident.tenant, role, body.uid)
    if first_grant:
        _notify_access_granted(svc, ident, body.uid, role)


@router.delete("/{role}/members/{uid}", status_code=204)
def remove_member(role: str, uid: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    if role == ADMINS:
        if uid == ident.user:
            raise HTTPException(status_code=400, detail="you cannot remove yourself from administrators")
        members = svc.ldap.list_members(ident.tenant, ADMINS)
        if len(members) <= 1:
            raise HTTPException(status_code=400, detail="cannot remove the last administrator")
    if not svc.audit.emit(category="user", action="role_remove_user", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=uid,
                          target_type="principal", detail={"role": role}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.ldap.remove_member(ident.tenant, role, uid)


def _notify_access_granted(svc: Services, ident: Identity, uid: str, role: str) -> None:
    """Send the tenant's access_granted template to an existing user (best effort)."""
    if not (svc.mailer.enabled):
        return
    from ..templates import ACCESS_GRANTED
    from .. import email as email_mod
    tmpl = svc.templates.get(ident.tenant, ACCESS_GRANTED)
    user = svc.ldap.get_user(uid) or {}
    html = email_mod.render(tmpl.body, {
        "display_name": user.get("display_name", uid),
        "email": uid,
        "tenant": ident.tenant,
        "app_link": svc.settings.invite_link_base or "",
        "inviter": ident.user,
        "roles": role,
    })
    try:
        svc.mailer.send(uid, tmpl.subject, html)
    except Exception:
        pass
