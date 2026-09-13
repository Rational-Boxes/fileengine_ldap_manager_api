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

"""Public (unauthenticated) endpoints: invite accept, password reset, and the
password-policy discovery used for live form validation (SPECIFICATION.md §5,
§5.2, §5.4). Token-gated + rate-limited; the reset request never reveals whether
an address exists.
"""
from __future__ import annotations

import hashlib
import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from ..deps import Services, services
from ..netutil import client_ip
from ..schemas import InviteAccept, ResetConfirm, ResetRequest
from ..templates import DEFAULTS, PASSWORD_RESET
from .. import email as email_mod
from .. import tokens as tok

log = logging.getLogger(__name__)
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
    # peek, not consume: the token must survive a FAILED attempt.
    #
    # Consuming first meant any failure after this line — a password the policy
    # rejects, or the directory refusing the write — destroyed the invitation.
    # The user saw an error, pressed the button again, and got "invalid or
    # expired token" for a link that had been valid seconds earlier, with no way
    # back except asking an administrator for a new one. That is exactly what
    # happened while the directory was refusing password changes over a
    # plaintext connection: one 502, and the invite was gone.
    #
    # Nothing is leaked by leaving it valid: whoever is calling already holds it.
    # A SUCCESSFUL set revokes it anyway — _set_password_or_422 ends in
    # revoke_all_for(uid), which clears every outstanding invite and reset token
    # for that user — so the token still cannot be replayed.
    uid = svc.tokens.peek(tok.INVITE, body.token)
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
    ip = client_ip(request)
    within_limits = (
        svc.tokens.rate_ok(f"reset:ip:{ip}", s.reset_rate_per_ip, s.reset_rate_window_s)
        and svc.tokens.rate_ok(f"reset:email:{hashlib.sha256(email.encode()).hexdigest()}",
                               s.reset_rate_per_email, s.reset_rate_window_s)
    )
    # Record the reset request (best-effort; global scope — no tenant pre-auth).
    # A throttled request is a recon/abuse signal, so it is captured as denied.
    # Never gates the response: the endpoint must stay constant-time/200 (§5.2).
    svc.audit.emit(action="password_reset_request", outcome="ok" if within_limits else "denied",
                   actor=email, scope="global", source_addr=ip)
    # Everything here is best-effort and errors are swallowed so the response is
    # identical whether or not the address exists (no account enumeration, §5.2).
    try:
        user = svc.ldap.get_user(str(body.email)) if within_limits else None
        if user and svc.tokens.enabled and svc.mailer.enabled and svc.settings.reset_link_base:
            token = svc.tokens.issue(tok.RESET, user["uid"], svc.settings.reset_ttl_hours * 3600)
            tmpl = DEFAULTS[PASSWORD_RESET]  # system-level template (§5.2)
            link = f"{svc.settings.reset_link_base}?token={token}"
            # The stock reset subject carries no placeholders, so this one was
            # not visibly broken — but it skipped render() like the other two,
            # which made it a trap for the first person to customize it.
            # The ADDRESS, not the uid. For every account created through this
            # service the two are the same string, which is why addressing the
            # uid worked everywhere it was ever tried. The platform's original
            # administrator is the exception — uid=james, mail=james@… — and for
            # that account the message was handed to SMTP with "james" as the
            # recipient, which no MTA can deliver.
            #
            # _to_user already resolves this: `email` is the mail attribute and
            # falls back to the uid when there is none, so this is correct for
            # both shapes.
            recipient = user.get("email") or user["uid"]
            ctx = {
                "display_name": user.get("display_name", user["uid"]),
                "email": recipient,
                "reset_link": link,
                "expires": f"{svc.settings.reset_ttl_hours}h",
            }
            # The TOKEN is still issued against the uid, deliberately: it is the
            # directory key /reset/confirm sets the password by. Only the
            # delivery address differs.
            svc.mailer.send(recipient, email_mod.render_subject(tmpl.subject, ctx),
                            email_mod.render(tmpl.body, ctx))
    except Exception:
        # Swallowed so the response cannot reveal whether the address exists —
        # but LOGGED, because it was the silence that hid this: a reset that was
        # never delivered looked identical, from every side, to one that was.
        log.exception("password reset for %s could not be completed", email)
    return {"status": "ok"}


@router.post("/reset/confirm")
def reset_confirm(body: ResetConfirm, request: Request, svc: Services = Depends(services)) -> dict:
    ip = client_ip(request)
    # peek, not consume — same reason as invite/accept above, and more likely to
    # bite here: a password that fails the complexity policy is an ordinary
    # first attempt, and it used to kill the reset link on the way out.
    uid = svc.tokens.peek(tok.RESET, body.token)
    if not uid:
        # An invalid/expired reset token is a security signal (a guessed or replayed
        # token) — record the failed completion (best-effort; global scope, no tenant).
        svc.audit.emit(action="password_reset_complete", outcome="denied", actor="unknown",
                       scope="global", source_addr=ip)
        raise HTTPException(status_code=400, detail="invalid or expired token")
    # Fail-closed write-ahead (§6): record the credential change before it applies.
    if not svc.audit.emit(action="password_reset_complete", outcome="ok", actor=uid,
                          scope="global", source_addr=ip):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    try:
        _set_password_or_422(svc, uid, body.password)
    except HTTPException:
        svc.audit.emit(action="password_reset_complete", outcome="error", actor=uid,
                       scope="global", source_addr=ip)
        raise
    return {"status": "ok"}
