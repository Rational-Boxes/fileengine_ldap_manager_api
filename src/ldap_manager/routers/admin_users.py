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
from ..schemas import (AdminUserDetail, RosterUserOut, UserCreate, UserOut, UserRemoveOut,
                       UserRolesUpdate)
from ..templates import NEW_USER
from .. import email as email_mod
from .. import tokens as tok
from .admin_roles import ADMINS, _notify_access_granted

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


@router.get("/roster", response_model=list[RosterUserOut])
def roster(svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    """The tenant's full user roster (§6.1). Declared before ``/{uid}`` so the
    literal path always wins; uids are email addresses, so they cannot collide
    with it in practice, but route order is the guarantee, not that convention."""
    return [
        RosterUserOut(uid=u["uid"], email=u.get("email") or u["uid"],
                      display_name=u.get("display_name", ""), roles=u.get("roles", []),
                      is_admin=ADMINS in u.get("roles", []),
                      orphaned=bool(u.get("orphaned")))
        for u in svc.ldap.list_tenant_users(ident.tenant)
    ]


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
    # One context, rendered into BOTH parts. The subject used to be passed
    # straight through, so the default "You've been invited to {{tenant}}"
    # arrived in the inbox with the braces still in it.
    ctx = {
        "display_name": display_name or uid,
        "email": uid,
        "tenant": ident.tenant,
        "invite_link": link,
        "expires": f"{svc.settings.invite_ttl_hours}h",
        "inviter": ident.user,
        "roles": ", ".join(roles) or "—",
    }
    svc.mailer.send(uid, email_mod.render_subject(tmpl.subject, ctx),
                    email_mod.render(tmpl.body, ctx))


# --------------------------- profile & membership ---------------------------

def _member_or_404(svc: Services, ident: Identity, uid: str) -> tuple[dict, list[str]]:
    """Resolve a uid to a user who holds at least one role in the caller's tenant.

    A global user with no role here is reported as 404 rather than 403: the full
    profile is only this tenant's to see for its own members, and saying "exists,
    but not yours" would leak the directory §6 keeps closed.
    """
    user = svc.ldap.get_user(uid)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    roles = svc.ldap.user_roles(ident.tenant, user["uid"])
    if not roles:
        raise HTTPException(status_code=404, detail="user is not a member of this tenant")
    return user, roles


def _detail(svc: Services, ident: Identity, user: dict, roles: list[str]) -> AdminUserDetail:
    others = [t for t in svc.ldap.user_tenants(user["uid"]) if t != ident.tenant]
    return AdminUserDetail(
        uid=user["uid"], email=user.get("email") or user["uid"],
        display_name=user.get("display_name", ""), given_name=user.get("given_name", ""),
        surname=user.get("surname", ""), avatar_url=user.get("avatar_url", ""),
        tenant=ident.tenant, roles=roles, is_admin=ADMINS in roles,
        other_tenant_count=len(others),
        # Deleting a *global* account is only this tenant's call when no other
        # tenant is relying on it (§4).
        can_delete_account=not others and user["uid"] != ident.user,
    )


@router.get("/{uid}/profile", response_model=AdminUserDetail)
def get_user_profile(uid: str, svc: Services = Depends(services),
                     ident: Identity = Depends(require_tenant_admin)):
    user, roles = _member_or_404(svc, ident, uid)
    return _detail(svc, ident, user, roles)


def _guard_admin_removal(svc: Services, ident: Identity, uid: str) -> None:
    """The same two guards the roles router applies, reused wherever a user can
    lose ``administrators``: no self-removal (lockout), no last administrator."""
    if uid == ident.user:
        raise HTTPException(status_code=400, detail="you cannot remove yourself from administrators")
    if len(svc.ldap.list_members(ident.tenant, ADMINS)) <= 1:
        raise HTTPException(status_code=400, detail="cannot remove the last administrator")


@router.put("/{uid}/roles", response_model=AdminUserDetail)
def set_user_roles(uid: str, body: UserRolesUpdate, svc: Services = Depends(services),
                   ident: Identity = Depends(require_tenant_admin)):
    """Set a member's roles in this tenant to exactly ``roles``. The server diffs
    against current membership so the editor can just submit the checkboxes."""
    user, current = _member_or_404(svc, ident, uid)
    target = user["uid"]
    known = {r["name"] for r in svc.ldap.list_roles(ident.tenant)}
    wanted = {r.strip() for r in body.roles if r and r.strip()}
    unknown = sorted(wanted - known)
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown role(s): {', '.join(unknown)}")
    add = sorted(wanted - set(current))
    drop = sorted(set(current) - wanted)
    if not wanted:
        # Emptying the set is a removal from the tenant, which has its own route
        # (and its own confirmation in the UI) — don't let it happen by accident.
        raise HTTPException(status_code=400,
                            detail="a member must hold at least one role; remove them from the tenant instead")
    if not add and not drop:
        return _detail(svc, ident, user, current)
    if ADMINS in drop:
        _guard_admin_removal(svc, ident, target)
    # Fail-closed write-ahead (§6): the whole diff is recorded before any of it
    # applies, as one privilege change rather than a scatter of add/remove rows.
    if not svc.audit.emit(category="user", action="role_set_user", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=target,
                          target_type="principal",
                          detail={"add": add, "remove": drop, "roles": sorted(wanted)}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    for role in add:
        svc.ldap.add_member(ident.tenant, role, target)
    for role in drop:
        svc.ldap.remove_member(ident.tenant, role, target)
    return _detail(svc, ident, user, sorted(wanted))


@router.delete("/{uid}", response_model=UserRemoveOut)
def remove_user(uid: str, scope: str = Query("tenant", pattern="^(tenant|system)$"),
                svc: Services = Depends(services),
                ident: Identity = Depends(require_tenant_admin)):
    """Remove a user, at one of two scopes.

    ``tenant`` (the default) drops every role they hold here: they lose all access
    to this tenant, and the global account — which may serve other tenants —
    survives. ``system`` also deletes the account itself, and is refused while any
    other tenant still has a role on it. Files the user created stay where they
    are; ownership is the core's record, not the directory's.
    """
    user = svc.ldap.get_user(uid)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    target = user["uid"]
    if target == ident.user:
        raise HTTPException(status_code=400, detail="you cannot remove yourself")
    roles = svc.ldap.user_roles(ident.tenant, target)
    if not roles:
        raise HTTPException(status_code=404, detail="user is not a member of this tenant")
    if ADMINS in roles:
        _guard_admin_removal(svc, ident, target)
    delete_account = scope == "system"
    if delete_account:
        others = [t for t in svc.ldap.user_tenants(target) if t != ident.tenant]
        if others:
            raise HTTPException(
                status_code=409,
                detail=(f"this account is also used by {len(others)} other tenant(s); "
                        "remove them from this tenant instead"))
    action = "user_delete" if delete_account else "user_remove_tenant"
    if not svc.audit.emit(category="user", action=action, outcome="ok", actor=ident.user,
                          tenant=ident.tenant, target_uid=target, target_type="principal",
                          detail={"roles": roles, "scope": scope}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    for role in roles:
        svc.ldap.remove_member(ident.tenant, role, target)
    if delete_account:
        _purge_account_secrets(svc, target)
        svc.ldap.delete_user(target, user.get("dn"))
    return UserRemoveOut(uid=target, scope=scope, roles_removed=roles,
                         account_deleted=delete_account)


def _purge_account_secrets(svc: Services, uid: str) -> None:
    """Best-effort teardown of everything keyed to a deleted account. Each store
    is optional (no DATABASE_URL → disabled), and a failure here must not leave a
    half-deleted user: the directory entry is what actually revokes access, so it
    is deleted either way and the leftovers are logged for cleanup."""
    for name, store, purge in (("2fa", svc.twofa, lambda: svc.twofa.disable(uid)),
                               ("service credentials", svc.service_cred,
                                lambda: svc.service_cred.revoke_all(uid))):
        if not store.enabled:
            continue
        try:
            purge()
        except Exception as e:
            log.warning("could not purge %s for deleted user %s: %s", name, uid, e)
