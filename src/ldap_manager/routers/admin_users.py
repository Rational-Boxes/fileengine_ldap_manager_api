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
    """Invite a user into this tenant, whether or not they already have an account.

    One flow, because a tenant admin should not have to know which case they are
    in — and, more importantly, MUST NOT be told. Whether an email already has a
    platform account is another person's personal information; a response that
    differed by case (the old 409 "user already exists", a "created" flag, a
    different status or message) would leak the whole directory one probe at a time.
    So the two internal paths are indistinguishable from the outside:

    - **No account yet:** create a pending account (no password), assign the roles,
      provision a private home folder, and email a **set-password invite**.
    - **Account exists:** assign the roles they do not already hold and email an
      **informational** "you've been added" notice — never a password operation on
      an account that already has one.

    Both return the SAME shape, built only from what the admin submitted — never
    from the existing account's stored details — so nothing about the account's
    prior existence, name, or membership escapes.
    """
    email = str(body.email)
    # Every named role must exist in this tenant. Checked before any write, because
    # a bogus role would otherwise leave a half-added principal (see §4).
    known = {r["name"] for r in svc.ldap.list_roles(ident.tenant)}
    unknown = sorted(set(body.roles) - known)
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown role(s): {', '.join(unknown)}")

    existing = svc.ldap.get_user(email)
    if existing:
        _add_existing_to_tenant(svc, ident, existing["uid"], body.roles, token)
    else:
        _invite_new_user(svc, ident, email, body.display_name, body.roles, token)

    # Uniform, non-revealing result: echo only the submitted email + the fact that
    # they are now a member (always true — we always assign >=1 role). No display
    # name from the directory, no created/added flag, no status difference.
    return UserOut(uid=email, email=email, display_name=body.display_name, in_this_tenant=True)


def _invite_new_user(svc: Services, ident: Identity, email: str, display_name: str,
                     roles: list[str], token: str) -> None:
    # Fail-closed write-ahead (§6): record the creation (+ its grants) before the
    # directory is mutated.
    if not svc.audit.emit(category="user", action="user_create", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=email,
                          target_type="principal", detail={"roles": list(roles)}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.ldap.create_user(email, email, display_name)
    for role in roles:
        svc.ldap.add_member(ident.tenant, role, email)
    # Private home under Users/<uid>. Best-effort — a filesystem hiccup must not
    # undo the created user.
    try:
        svc.home.provision(token, ident.tenant, email)
    except Exception as e:
        log.warning("home folder provisioning failed for %s in %s: %s", email, ident.tenant, e)
    _send_invite(svc, ident, email, display_name, roles)


def _add_existing_to_tenant(svc: Services, ident: Identity, uid: str,
                            roles: list[str], token: str) -> None:
    """Add an existing account to this tenant: grant the roles it does not already
    hold, provision its home here if new to the tenant, and send the informational
    notice — never a set-password link."""
    was_member = svc.ldap.is_tenant_member(uid, ident.tenant)
    have = set(svc.ldap.user_roles(ident.tenant, uid))
    add = [r for r in roles if r not in have]
    if not svc.audit.emit(category="user", action="user_add_existing", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=uid,
                          target_type="principal", detail={"roles": add}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    for role in add:
        svc.ldap.add_member(ident.tenant, role, uid)
    if not was_member:
        try:
            svc.home.provision(token, ident.tenant, uid)
        except Exception as e:
            log.warning("home folder provisioning failed for %s in %s: %s", uid, ident.tenant, e)
    # Notify only when they actually gained access here (new tenant, or new roles);
    # a pure no-op sends nothing — but the caller's response is identical either way.
    if add:
        _notify_access_granted(svc, ident, uid, ", ".join(add))


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
        # Informative only — how many OTHER tenants also hold this account, as a
        # count and never as names (§6.1). A tenant admin cannot act on the global
        # account regardless (deletion is a sysadmin/LDAP operation); this tells
        # them their "remove from this workspace" leaves the person with access
        # elsewhere.
        other_tenant_count=len(others),
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
def remove_user(uid: str, svc: Services = Depends(services),
                ident: Identity = Depends(require_tenant_admin)):
    """Remove a user from THIS tenant: drop every role they hold here, and purge
    the door keys that let them reach it.

    A tenant admin's authority is bounded by their tenant. This drops the user's
    roles here — so they lose all access to this tenant — and purges their
    tenant-bound service credentials (WebDAV/MCP/BCF/CMIS keys are issued for a
    single tenant, so a key for this tenant must not outlive membership of it).
    The global account, their roles in any OTHER tenant, their keys there, and
    their per-user 2FA enrollment are all untouched, and files they authored stay
    where they are (ownership is the core's record, not the directory's).

    Deleting the global account itself is deliberately NOT here: it spans every
    tenant, so it is a sysadmin operation performed directly in LDAP, not
    something one tenant's admin can do.
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
    if not svc.audit.emit(category="user", action="user_remove_tenant", outcome="ok",
                          actor=ident.user, tenant=ident.tenant, target_uid=target,
                          target_type="principal", detail={"roles": roles}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    for role in roles:
        svc.ldap.remove_member(ident.tenant, role, target)
    purged = _purge_tenant_credentials(svc, ident.tenant, target)
    return UserRemoveOut(uid=target, roles_removed=roles, credentials_purged=purged)


def _purge_tenant_credentials(svc: Services, tenant: str, uid: str) -> int:
    """Revoke the user's tenant-bound service credentials for THIS tenant only.
    Best-effort: the LDAP role removal above is what actually revokes access, so a
    credential-store hiccup must not leave the user a member; the leftover keys are
    logged for cleanup and would in any case fail verification once the roles are
    gone. 2FA is per-user (shared across tenants), so it is NOT touched here."""
    if not svc.service_cred.enabled:
        return 0
    try:
        return svc.service_cred.revoke_all_for_tenant(uid, tenant)
    except Exception as e:
        log.warning("could not purge %s's service credentials in %s: %s", uid, tenant, e)
        return 0
