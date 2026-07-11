"""Tenant-admin user management (SPECIFICATION.md §4, §5-A, §6, §7). Look up
global users (exact/prefix — no enumeration), and create new global users via the
email invite flow. Creating a user never sets a password directly; the invite
sets it (subject to the password policy at accept time).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from ..deps import Services, bearer_token, require_tenant_admin, services
from ..identity import Identity

log = logging.getLogger("ldap_manager.users")
from ..schemas import UserCreate, UserOut
from ..templates import NEW_USER
from .. import email as email_mod
from .. import tokens as tok

router = APIRouter(prefix="/v1/admin/users")


@router.get("", response_model=list[UserOut])
def find_users(
    query: str = Query(min_length=3, description="exact email/uid or ≥3-char prefix"),
    svc: Services = Depends(services),
    ident: Identity = Depends(require_tenant_admin),
):
    out = []
    for u in svc.ldap.find_users(query):
        out.append(UserOut(uid=u["uid"], email=u.get("email", u["uid"]),
                           display_name=u.get("display_name", ""),
                           in_this_tenant=svc.ldap.is_tenant_member(u["uid"], ident.tenant)))
    return out


@router.get("/{uid}", response_model=UserOut)
def get_user(uid: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    u = svc.ldap.get_user(uid)
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    return UserOut(uid=u["uid"], email=u.get("email", u["uid"]), display_name=u.get("display_name", ""),
                   in_this_tenant=svc.ldap.is_tenant_member(uid, ident.tenant))


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, svc: Services = Depends(services),
                ident: Identity = Depends(require_tenant_admin),
                token: str = Depends(bearer_token)):
    """Create a new global user (pending, no password) + assign roles + provision a
    private home folder + send the invite. If the user already exists this is a 409
    — use role assignment instead."""
    email = str(body.email)
    if svc.ldap.get_user(email):
        raise HTTPException(status_code=409, detail="user already exists; assign them to a role instead")
    # Fail-closed write-ahead (§6): record the user creation (+ its role grants)
    # before the directory is mutated.
    if not svc.audit.emit(category="user", action="user_create", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=email,
                          target_type="principal", detail={"roles": list(body.roles)}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.ldap.create_user(email, email, body.display_name)
    for role in body.roles:
        svc.ldap.add_member(ident.tenant, role, email)
    # Private home folder under Users/<uid> (full access to the user, denied to
    # everyone else). Best-effort under the admin's authority — a filesystem hiccup
    # must not undo the created user.
    try:
        svc.home.provision(token, ident.tenant, email)
    except Exception as e:
        log.warning("home folder provisioning failed for %s in %s: %s", email, ident.tenant, e)
    _send_invite(svc, ident, email, body.display_name, body.roles)
    return UserOut(uid=email, email=email, display_name=body.display_name, in_this_tenant=bool(body.roles))


@router.post("/{uid}/reinvite", status_code=204)
def reinvite(uid: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    u = svc.ldap.get_user(uid)
    if not u:
        raise HTTPException(status_code=404, detail="user not found")
    # Best-effort: re-sending an invite is a notification, not a directory change.
    svc.audit.emit(category="user", action="invite_send", outcome="ok", actor=ident.user,
                   tenant=ident.tenant, target_uid=uid, target_type="principal")
    _send_invite(svc, ident, uid, u.get("display_name", uid), [])


def _send_invite(svc: Services, ident: Identity, uid: str, display_name: str, roles: list[str]) -> None:
    if not (svc.tokens.enabled and svc.mailer.enabled and svc.settings.invite_link_base):
        raise HTTPException(status_code=503, detail="invite email not configured (SMTP/Redis/INVITE_LINK_BASE)")
    token = svc.tokens.issue(tok.INVITE, uid, svc.settings.invite_ttl_hours * 3600)
    tmpl = svc.templates.get(ident.tenant, NEW_USER)
    link = f"{svc.settings.invite_link_base}?token={token}"
    html = email_mod.render(tmpl.body, {
        "display_name": display_name or uid,
        "email": uid,
        "tenant": ident.tenant,
        "invite_link": link,
        "expires": f"{svc.settings.invite_ttl_hours}h",
        "inviter": ident.user,
        "roles": ", ".join(roles) or "—",
    })
    svc.mailer.send(uid, tmpl.subject, html)
