"""Public (unauthenticated) endpoints: invite accept, password reset, and the
password-policy discovery used for live form validation (SPECIFICATION.md §5,
§5.2, §5.4). Token-gated + rate-limited; the reset request never reveals whether
an address exists.
"""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request

from ..deps import Services, services
from ..schemas import InviteAccept, ResetConfirm, ResetRequest
from ..templates import DEFAULTS, PASSWORD_RESET
from .. import email as email_mod
from .. import tokens as tok

router = APIRouter(prefix="/v1")


@router.get("/password-policy")
def password_policy(svc: Services = Depends(services)) -> dict:
    """Active complexity rules, so the set-password/reset/change forms can validate
    client-side (server stays authoritative)."""
    return svc.policy.describe()


def _set_password_or_422(svc: Services, uid: str, password: str) -> None:
    res = svc.policy.validate(password, uid=uid)
    if not res.ok:
        raise HTTPException(status_code=422, detail={"error": "password_policy", "unmet": res.unmet})
    svc.ldap.set_password(uid, password)
    svc.tokens.revoke_all_for(uid)


@router.post("/invite/accept")
def invite_accept(body: InviteAccept, svc: Services = Depends(services)) -> dict:
    uid = svc.tokens.consume(tok.INVITE, body.token)
    if not uid:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    _set_password_or_422(svc, uid, body.password)
    return {"status": "ok"}


@router.post("/reset/request")
def reset_request(body: ResetRequest, request: Request, svc: Services = Depends(services)) -> dict:
    """Always returns 200 (no account enumeration). Rate-limited per source IP and
    per email; over-limit requests are silently dropped (still 200) so a throttle
    never leaks whether an address exists."""
    s = svc.settings
    email = str(body.email).lower()
    ip = request.client.host if request.client else "unknown"
    within_limits = (
        svc.tokens.rate_ok(f"reset:ip:{ip}", s.reset_rate_per_ip, s.reset_rate_window_s)
        and svc.tokens.rate_ok(f"reset:email:{hashlib.sha256(email.encode()).hexdigest()}",
                               s.reset_rate_per_email, s.reset_rate_window_s)
    )
    # Everything here is best-effort and errors are swallowed so the response is
    # identical whether or not the address exists (no account enumeration, §5.2).
    try:
        user = svc.ldap.get_user(str(body.email)) if within_limits else None
        if user and svc.tokens.enabled and svc.mailer.enabled and svc.settings.reset_link_base:
            token = svc.tokens.issue(tok.RESET, user["uid"], svc.settings.reset_ttl_hours * 3600)
            tmpl = DEFAULTS[PASSWORD_RESET]  # system-level template (§5.2)
            link = f"{svc.settings.reset_link_base}?token={token}"
            html = email_mod.render(tmpl.body, {
                "display_name": user.get("display_name", user["uid"]),
                "email": user["uid"],
                "reset_link": link,
                "expires": f"{svc.settings.reset_ttl_hours}h",
            })
            svc.mailer.send(user["uid"], tmpl.subject, html)
    except Exception:
        pass
    return {"status": "ok"}


@router.post("/reset/confirm")
def reset_confirm(body: ResetConfirm, svc: Services = Depends(services)) -> dict:
    uid = svc.tokens.consume(tok.RESET, body.token)
    if not uid:
        raise HTTPException(status_code=400, detail="invalid or expired token")
    _set_password_or_422(svc, uid, body.password)
    return {"status": "ok"}
