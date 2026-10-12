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

"""The welcome mail a newly provisioned tenant's first administrator receives.

Internal, server-to-server: called by the tenant play (playbooks/tenant.yml) once
the tenant's directory entries, vhosts and folders exist, so the mail never
arrives before the address it points at works. Guarded by a shared secret, like
the other ``/internal/*`` surfaces.

Unlike ``/reset/request`` this answers truthfully. That endpoint is public and
must not reveal whether an address exists; this one is reachable only with the
internal secret, and its caller — a provisioning run — needs to know whether the
mail went, because "provisioned, nobody told" is the silent failure a run report
exists to surface.

The mail ALWAYS carries a set-your-password link. A new administrator's account
was created with a random password nobody holds, so the link is their only way
in; an existing account keeps its password and the link is simply there. Issuing
it does not change the password — only following it does.
"""
from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from .. import email as email_mod
from .. import tokens as tok
from ..deps import Services, services
from ..templates import DEFAULTS, TENANT_WELCOME

log = logging.getLogger("ldap_manager.tenant_onboarding")

router = APIRouter()


def require_internal(svc: Services = Depends(services),
                     x_internal_auth: str | None = Header(default=None)) -> None:
    secret = svc.settings.onboarding_internal_secret or svc.settings.mfa_internal_secret
    if not secret:
        raise HTTPException(status_code=404, detail="internal onboarding API not enabled")
    if not x_internal_auth or not secrets.compare_digest(x_internal_auth, secret):
        raise HTTPException(status_code=403, detail="forbidden")


class WelcomeIn(BaseModel):
    email: str
    sign_in_url: str
    drive_host: str = ""
    tenant_name: str = ""


@router.post("/internal/tenants/{tenant}/welcome")
def welcome(tenant: str, body: WelcomeIn, svc: Services = Depends(services),
            _: None = Depends(require_internal)) -> dict:
    s = svc.settings
    # Each missing piece is a refusal that says which, not a 200 with nothing sent.
    if not (svc.mailer.enabled and svc.tokens.enabled and s.reset_link_base):
        missing = [n for n, ok in (("SMTP", svc.mailer.enabled),
                                   ("token store", svc.tokens.enabled),
                                   ("RESET_LINK_BASE", bool(s.reset_link_base))) if not ok]
        raise HTTPException(status_code=503,
                            detail="welcome mail cannot be sent: not configured — "
                                   + ", ".join(missing))
    user = svc.ldap.get_user(body.email)
    if not user:
        raise HTTPException(status_code=404, detail=f"no account for {body.email}")

    ttl_h = s.welcome_reset_ttl_hours
    # Against the uid — the key /reset/confirm sets the password by — and addressed
    # to the mail attribute, which differs from the uid for the platform's original
    # administrator (uid=james). See /reset/request.
    token = svc.tokens.issue(tok.RESET, user["uid"], ttl_h * 3600)
    recipient = user.get("email") or user["uid"]
    ctx = {
        "display_name": user.get("display_name") or user["uid"],
        "email": recipient,
        "tenant": tenant,
        "tenant_name": body.tenant_name or tenant,
        "sign_in_url": body.sign_in_url,
        "drive_host": body.drive_host or "your drive address",
        "reset_link": f"{s.reset_link_base}?token={token}",
        "expires": f"{ttl_h}h",
    }
    tmpl = DEFAULTS[TENANT_WELCOME]
    try:
        svc.mailer.send(recipient, email_mod.render_subject(tmpl.subject, ctx),
                        email_mod.render(tmpl.body, ctx))
    except Exception as e:  # noqa: BLE001
        log.exception("welcome mail for tenant %s to %s could not be sent", tenant, recipient)
        svc.audit.emit(action="tenant_welcome_sent", outcome="error", actor="provisioning",
                       tenant=tenant, object=user["uid"], category="admin")
        raise HTTPException(status_code=502, detail=f"the mail server refused it: {e}") from e
    svc.audit.emit(action="tenant_welcome_sent", outcome="ok", actor="provisioning",
                   tenant=tenant, object=user["uid"], category="admin")
    log.info("welcome mail for tenant %s sent to %s", tenant, recipient)
    return {"sent": True, "to": recipient, "uid": user["uid"], "link_expires_hours": ttl_h}
