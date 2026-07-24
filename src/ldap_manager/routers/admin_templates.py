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

"""Tenant-admin email-template management (SPECIFICATION.md §5.1). The two
tenant-customizable kinds only (``new_user``, ``access_granted``); preview and
send-test. ``password_reset`` is system-level and not editable here.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..deps import Services, require_tenant_admin, services
from ..identity import Identity
from ..schemas import TemplateOut, TemplateUpdate
from ..templates import TENANT_KINDS, TemplateError, validate
from .. import email as email_mod

router = APIRouter(prefix="/v1/admin/email-templates")

_SAMPLE = {
    "display_name": "Alex Doe", "email": "alex@example.com", "tenant": "acme",
    "invite_link": "https://app.example.com/set-password?token=SAMPLE",
    "app_link": "https://acme.example.com", "expires": "72h",
    "inviter": "admin@example.com", "roles": "contributors, editors",
}


def _require_kind(kind: str) -> str:
    if kind not in TENANT_KINDS:
        raise HTTPException(status_code=404, detail="unknown or non-editable template kind")
    return kind


@router.get("", response_model=list[TemplateOut])
def list_templates(svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    out = []
    for kind in TENANT_KINDS:
        t = svc.templates.get(ident.tenant, kind)
        out.append(TemplateOut(kind=kind, subject=t.subject, body=t.body, customized=t.customized))
    return out


@router.get("/{kind}", response_model=TemplateOut)
def get_template(kind: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    kind = _require_kind(kind)
    t = svc.templates.get(ident.tenant, kind)
    return TemplateOut(kind=kind, subject=t.subject, body=t.body, customized=t.customized)


@router.put("/{kind}", response_model=TemplateOut)
def put_template(kind: str, body: TemplateUpdate, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    kind = _require_kind(kind)
    try:
        svc.templates.put(ident.tenant, kind, body.subject, body.body)
    except TemplateError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return TemplateOut(kind=kind, subject=body.subject, body=body.body, customized=True)


@router.delete("/{kind}", status_code=204)
def revert_template(kind: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    kind = _require_kind(kind)
    svc.templates.revert(ident.tenant, kind)


@router.post("/{kind}/preview")
def preview(kind: str, body: TemplateUpdate | None = None, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    kind = _require_kind(kind)
    t = svc.templates.get(ident.tenant, kind)
    subject = body.subject if body else t.subject
    html = body.body if body else t.body
    if body:
        try:
            validate(kind, subject, html)
        except TemplateError as e:
            raise HTTPException(status_code=422, detail=str(e))
    return {"subject": email_mod.render(subject, _SAMPLE), "body": email_mod.render(html, _SAMPLE)}


@router.post("/{kind}/test", status_code=204)
def send_test(kind: str, svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)):
    kind = _require_kind(kind)
    if not svc.mailer.enabled:
        raise HTTPException(status_code=503, detail="SMTP not configured")
    t = svc.templates.get(ident.tenant, kind)
    svc.mailer.send(ident.user, "[test] " + email_mod.render(t.subject, _SAMPLE),
                    email_mod.render(t.body, _SAMPLE))
