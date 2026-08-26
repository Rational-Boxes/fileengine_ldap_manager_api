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

"""Recipient one-time codes for outside share links (share_service spec §6.9).

`ldap_manager` owns the code — generation, delivery, storage, single-use
verification, and the rate limits — exactly as it owns the 2FA code. `share_service`
orchestrates and enforces the recipient allowlist; the core is not involved at
all and never learns an email address was in play.

**These are siblings of the `/internal/2fa/*` pair, not reuses of it.** The 2FA
challenge refuses when a tenant's 2FA policy excludes the `email` method and
renders the 2FA template — neither of which should govern whether an outside
recipient can open a share link. A tenant that mandates hardware tokens for its
own staff has said nothing about how a contractor receives a download code.

Three things here differ from the 2FA handler, each deliberately:

1. **SMTP failure is surfaced, not swallowed.** The 2FA handler folds a send
   failure into ``sent = False`` and returns 200. For share links that is the
   worst possible support experience: a mail misconfiguration is then
   indistinguishable from a mistyped address, and nobody finds out. Here the
   caller is told, so it can raise an attention item for the link's creator.
   The *recipient's* response stays uniform regardless — that uniformity is
   `share_service`'s job, not this door's.
2. **Attempts are counted per (link, email) over a rolling window, not per
   challenge.** A per-challenge counter is defeated by the resend the recipient
   is deliberately offered: burn five, request a fresh code, get five more.
3. **Timing is part of the verdict** (spec §8.4 rung 0). A submission cannot
   plausibly precede the mail carrying the code, and a human re-reads before
   retrying. A tripped check is never rejected differently — the response is
   identical to an ordinary wrong code — it just counts more heavily, so a
   script exhausts its budget almost immediately while a fast-but-real
   recipient does not.
"""
from __future__ import annotations

import logging
import secrets
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from .. import email as email_mod
from ..deps import Services, services
from ..templates import SHARE_OTP_EMAIL

log = logging.getLogger("ldap_manager.share_otp")

router = APIRouter()

# TokenStore kind. Keyed by "{link_uid}|{email}" so one recipient's challenge on
# one link is independent of every other.
KIND = "share_otp"
# The recipient token: proof that an address passed the challenge. Separate kind
# so revoking codes and revoking sessions stay independent.
RECIPIENT_KIND = "share_recipient"


def require_internal(svc: Services = Depends(services),
                     x_internal_auth: str | None = Header(default=None)) -> None:
    """Server-to-server guard, mirroring the 2FA one.

    Falls back to the MFA secret so a deployment that has already configured
    that seam does not need a second one — but allows a distinct
    ``SHARE_INTERNAL_SECRET`` for anyone who wants the two doors separable.
    """
    secret = svc.settings.share_internal_secret or svc.settings.mfa_internal_secret
    if not secret:
        raise HTTPException(status_code=404, detail="internal share API not enabled")
    if not x_internal_auth or not secrets.compare_digest(x_internal_auth, secret):
        raise HTTPException(status_code=403, detail="forbidden")


class ChallengeIn(BaseModel):
    link_uid: str
    email: str
    tenant: str
    sender: str = ""          # the link's creator, for the mail copy


class VerifyIn(BaseModel):
    link_uid: str
    email: str
    tenant: str
    code: str


def _uid(link_uid: str, email: str) -> str:
    return f"{link_uid}|{(email or '').strip().lower()}"


def _sent_key(uid: str) -> str:
    return f"share_otp_sent:{uid}"


def _last_attempt_key(uid: str) -> str:
    return f"share_otp_last:{uid}"


@router.post("/internal/share/email-challenge")
def share_email_challenge(body: ChallengeIn, svc: Services = Depends(services),
                          _: None = Depends(require_internal)) -> dict:
    """Mint a code and mail it.

    The caller has already decided the address is on the link's allowlist; this
    door does not know what a share link is beyond an opaque id.

    Returns ``sent`` plus, when it is False, ``error`` — see the module note on
    why a swallowed SMTP failure is not acceptable here.
    """
    uid = _uid(body.link_uid, body.email)
    s = svc.settings

    # Mail-flood controls (spec §8.4): per (link, email), and per link per day.
    if not svc.tokens.rate_ok(f"share_otp_send:{uid}", s.share_otp_send_per_window,
                              s.share_otp_send_window_s):
        svc.audit.emit(action="share_link_challenge_sent", outcome="denied",
                       actor=body.email, tenant=body.tenant, category="auth",
                       detail={"link_uid": body.link_uid, "reason": "send_rate_limited"})
        return {"sent": False, "error": "rate_limited",
                "retry_after_s": s.share_otp_send_window_s}
    if not svc.tokens.rate_ok(f"share_otp_send_link:{body.link_uid}",
                              s.share_otp_send_per_link_day, 86400):
        svc.audit.emit(action="share_link_challenge_sent", outcome="denied",
                       actor=body.email, tenant=body.tenant, category="auth",
                       detail={"link_uid": body.link_uid, "reason": "link_send_cap"})
        return {"sent": False, "error": "rate_limited", "retry_after_s": 86400}

    code = f"{secrets.randbelow(1_000_000):06d}"
    # issue_code keeps ONE live code per (kind, uid): a new challenge replaces
    # the previous one. That is intentional -- two live codes double the guessing
    # surface -- but it means a delayed earlier mail will now fail, which is why
    # the template says to use the newest.
    svc.tokens.issue_code(KIND, uid, code, s.share_otp_ttl_s)
    now = int(time.time())
    svc.tokens.set_marker(_sent_key(uid), str(now), s.share_otp_ttl_s)

    sent, error = False, None
    try:
        tmpl = svc.templates.get(body.tenant, SHARE_OTP_EMAIL)
        ctx = {"email": body.email, "code": code,
               "expires": f"{s.share_otp_ttl_s // 60} minutes",
               "sender": body.sender or "someone at your correspondent's organization",
               "sent_at": time.strftime("%H:%M UTC", time.gmtime(now))}
        svc.mailer.send(body.email, email_mod.render_subject(tmpl.subject, ctx),
                        email_mod.render(tmpl.body, ctx))
        sent = True
    except Exception as e:  # noqa: BLE001 - reported, never swallowed
        error = f"{type(e).__name__}: {e}"
        log.error("share OTP send FAILED for link %s: %s", body.link_uid, error,
                  exc_info=True)

    svc.audit.emit(action="share_link_challenge_sent",
                   outcome="ok" if sent else "error",
                   actor=body.email, tenant=body.tenant, category="auth",
                   detail={"link_uid": body.link_uid,
                           **({"error": error} if error else {})})
    return {"sent": sent, **({"error": error} if error else {})}


@router.post("/internal/share/email-verify")
def share_email_verify(body: VerifyIn, svc: Services = Depends(services),
                       _: None = Depends(require_internal)) -> dict:
    """Verify a code, single-use and constant-time.

    Returns ``{ok, attempts_remaining, timing_flag}``. ``timing_flag`` is
    informational for the caller's own counters — it must **not** change what
    the recipient is told (spec §8.4 rung 0).
    """
    uid = _uid(body.link_uid, body.email)
    s = svc.settings
    now_ms = int(time.time() * 1000)

    # --- rung 0: timing ---------------------------------------------------
    # Evaluated before the code compare so a scripted burst is counted even when
    # it happens to guess right.
    timing_flag = None
    sent_at = svc.tokens.get_marker(_sent_key(uid))
    if sent_at:
        try:
            elapsed = (now_ms // 1000) - int(sent_at)
            if elapsed < s.share_otp_min_seconds_after_send:
                # Bounded by physics, not by habit: a code cannot be READ before
                # the mail carrying it is delivered.
                timing_flag = "too_soon_after_send"
        except ValueError:
            pass
    last = svc.tokens.get_marker(_last_attempt_key(uid))
    if last and timing_flag is None:
        try:
            if now_ms - int(last) < s.share_otp_min_submit_interval_ms:
                timing_flag = "submit_interval"
        except ValueError:
            pass
    svc.tokens.set_marker(_last_attempt_key(uid), str(now_ms),
                          s.share_otp_attempt_window_s)

    # --- rung 1: attempts, per (link, email) per window -------------------
    # Charged BEFORE the compare, and charged extra for a timing trip, so the
    # budget cannot be replenished by requesting a fresh code.
    weight = s.share_otp_timing_weight if timing_flag else 1
    bucket = f"share_otp_attempt:{uid}"
    allowed = True
    for _i in range(weight):
        allowed = svc.tokens.rate_ok(bucket, s.share_otp_max_attempts,
                                     s.share_otp_attempt_window_s)
    if not allowed:
        svc.audit.emit(action="share_link_challenge_failed", outcome="denied",
                       actor=body.email, tenant=body.tenant, category="auth",
                       detail={"link_uid": body.link_uid, "reason": "locked_out",
                               **({"timing": timing_flag} if timing_flag else {})})
        return {"ok": False, "attempts_remaining": 0, "locked": True,
                "timing_flag": timing_flag}

    ok = bool(svc.tokens.consume_code(KIND, uid, body.code))

    # On success, mint the RECIPIENT TOKEN here rather than in share_service.
    #
    # It is a verification artifact -- "this address proved control recently" --
    # with the same lifecycle as the code that produced it, so it belongs in the
    # same store. Keeping it out of share_service process memory is not a
    # preference: that service is replicated, and a token minted on replica A
    # would be unknown on replica B, where the failure is a generic 404 and the
    # symptom is "the link works sometimes" (spec §7.4). The same trap
    # ReplayGuard's own header names.
    token = None
    if ok:
        token = svc.tokens.issue(RECIPIENT_KIND, uid, s.share_recipient_ttl_s)

    svc.audit.emit(action="share_link_challenge_verified" if ok
                   else "share_link_challenge_failed",
                   outcome="ok" if ok else "denied",
                   actor=body.email, tenant=body.tenant, category="auth",
                   detail={"link_uid": body.link_uid,
                           **({"timing": timing_flag} if timing_flag else {})})
    return {"ok": ok, "locked": False, "timing_flag": timing_flag,
            **({"recipient_token": token,
                "expires_in": s.share_recipient_ttl_s} if token else {})}


class TokenCheckIn(BaseModel):
    link_uid: str
    email: str
    token: str


@router.post("/internal/share/token-check")
def share_token_check(body: TokenCheckIn, svc: Services = Depends(services),
                      _: None = Depends(require_internal)) -> dict:
    """Is this recipient token live, and does it belong to this (link, address)?

    Deliberately NOT single-use: a verified recipient may open more than one
    session inside the window (a re-download after a dropped connection),
    bounded by the link's own use budget rather than by this token. Binding is
    checked rather than assumed -- a token for one link must not open another,
    even though both were minted by the same store."""
    expected = _uid(body.link_uid, body.email)
    holder = svc.tokens.peek(RECIPIENT_KIND, body.token)
    return {"ok": bool(holder) and secrets.compare_digest(holder or "", expected)}
