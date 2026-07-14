"""Two-factor authentication (PROPOSAL §4).

Two surfaces:
  * self-service ``/v1/me/2fa/*`` — a user enrolls/manages their own TOTP
    (bearer-authenticated, hard-scoped to the caller);
  * internal ``/internal/2fa/*`` — the server-to-server API http_bridge calls
    during login (required? / verify / email-challenge), guarded by a shared
    secret (``MFA_INTERNAL_SECRET``).

The identity service owns the secret + verification; http_bridge orchestrates and
mints. The QR is rendered client-side from the returned otpauth:// URI.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from .. import email as email_mod
from .. import twofa
from ..deps import Services, require_identity, require_tenant_admin, services
from ..identity import Identity
from ..netutil import client_ip
from ..templates import TWO_FA_EMAIL

router = APIRouter()

ISSUER = "FileEngine"


def _deployment_cap(svc: Services) -> list[str]:
    """The deployment-wide method cap (MFA_ALLOWED_METHODS) — the ceiling a tenant
    admin can restrict within, never exceed (PROPOSAL §4.8)."""
    return twofa.effective_methods(twofa.parse_methods(svc.settings.mfa_allowed_methods), None)


def _effective_methods(svc: Services, tenant: str) -> list[str]:
    """The methods a tenant actually permits: deployment cap ∩ the tenant policy
    (a tenant with no policy inherits the full cap). (PROPOSAL §4.8)"""
    pol = svc.twofa_policy.get(tenant)
    return twofa.effective_methods(twofa.parse_methods(svc.settings.mfa_allowed_methods),
                                   pol.allowed_methods)


def _env_required_tenants(svc: Services) -> set[str]:
    return {t.strip() for t in (svc.settings.totp_required_tenants or "").split(",") if t.strip()}


def _required(svc: Services, tenant: str) -> bool:
    """Whether 2FA is mandatory for the tenant — the deployment env list
    (TOTP_REQUIRED_TENANTS) OR the tenant admin's stored policy."""
    return tenant in _env_required_tenants(svc) or svc.twofa_policy.get(tenant).require


# ------------------------------ self-service ---------------------------------

class CodeIn(BaseModel):
    code: str


@router.get("/v1/me/2fa/status")
def status(svc: Services = Depends(services), ident: Identity = Depends(require_identity)) -> dict:
    st = svc.twofa.status(ident.tenant, ident.user)
    return {"enabled": st.enabled, "pending": st.pending,
            "recovery_remaining": st.recovery_remaining,
            "required": _required(svc, ident.tenant),
            "methods": _effective_methods(svc, ident.tenant)}


@router.post("/v1/me/2fa/setup")
def setup(svc: Services = Depends(services), ident: Identity = Depends(require_identity)) -> dict:
    if "totp" not in _effective_methods(svc, ident.tenant):
        raise HTTPException(status_code=403, detail="TOTP is not permitted for this tenant")
    if not svc.settings.totp_secret_key:
        raise HTTPException(status_code=503, detail="2FA is not configured (TOTP_SECRET_KEY unset)")
    # Idempotent while enrollment is pending: re-opening setup returns the SAME
    # secret/QR instead of minting a new one. Otherwise a user who re-visits (or
    # double-clicks) ends up with a stale QR already scanned into their app and a
    # different secret stored — so the code they read never matches (the exact
    # lock-out this caused). A fresh secret is only minted when there's no pending
    # enrollment (first time, or re-enrolling after disable).
    st = svc.twofa.status(ident.tenant, ident.user)
    secret = svc.twofa.get_secret(ident.tenant, ident.user) if st.pending else None
    if not secret:
        secret = twofa.random_secret()
        svc.twofa.set_pending_secret(ident.tenant, ident.user, secret)
    svc.audit.emit(action="2fa_setup", outcome="ok", actor=ident.user, tenant=ident.tenant)
    return {"secret": secret,
            "otpauth_uri": twofa.provisioning_uri(secret, ident.user, ISSUER),
            "issuer": ISSUER, "account": ident.user}


@router.post("/v1/me/2fa/verify-setup")
def verify_setup(body: CodeIn, svc: Services = Depends(services),
                 ident: Identity = Depends(require_identity)) -> dict:
    secret = svc.twofa.get_secret(ident.tenant, ident.user)
    if not secret:
        raise HTTPException(status_code=409, detail="no pending 2FA setup; call /setup first")
    if not twofa.totp_verify(secret, body.code):
        svc.audit.emit(action="2fa_verify_setup", outcome="denied", actor=ident.user, tenant=ident.tenant)
        raise HTTPException(status_code=400, detail="invalid code")
    codes = twofa.generate_recovery_codes()
    svc.twofa.enable(ident.tenant, ident.user, [twofa.hash_recovery_code(c) for c in codes])
    svc.audit.emit(action="2fa_verify_setup", outcome="ok", actor=ident.user, tenant=ident.tenant)
    return {"enabled": True, "recovery_codes": codes}


@router.post("/v1/me/2fa/disable")
def disable(body: CodeIn, svc: Services = Depends(services),
            ident: Identity = Depends(require_identity)) -> dict:
    if not svc.twofa.is_enabled(ident.tenant, ident.user):
        return {"enabled": False}
    secret = svc.twofa.get_secret(ident.tenant, ident.user)
    ok = (bool(secret) and twofa.totp_verify(secret, body.code)) \
        or svc.twofa.consume_recovery_code(ident.tenant, ident.user, body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="a valid 2FA or recovery code is required to disable")
    svc.twofa.disable(ident.tenant, ident.user)
    svc.audit.emit(action="2fa_disable", outcome="ok", actor=ident.user, tenant=ident.tenant)
    return {"enabled": False}


@router.post("/v1/me/2fa/recovery-codes")
def regenerate_recovery(body: CodeIn, svc: Services = Depends(services),
                        ident: Identity = Depends(require_identity)) -> dict:
    secret = svc.twofa.get_secret(ident.tenant, ident.user)
    if not (svc.twofa.is_enabled(ident.tenant, ident.user) and secret
            and twofa.totp_verify(secret, body.code)):
        raise HTTPException(status_code=400, detail="a valid TOTP code is required")
    codes = twofa.generate_recovery_codes()
    svc.twofa.enable(ident.tenant, ident.user, [twofa.hash_recovery_code(c) for c in codes])
    svc.audit.emit(action="2fa_recovery_regenerate", outcome="ok", actor=ident.user, tenant=ident.tenant)
    return {"recovery_codes": codes}


# ------------------------------ internal API ---------------------------------

def require_internal(svc: Services = Depends(services),
                     x_internal_auth: str | None = Header(default=None)) -> None:
    secret = svc.settings.mfa_internal_secret
    if not secret:
        raise HTTPException(status_code=404, detail="internal MFA API not enabled")
    if not x_internal_auth or not secrets.compare_digest(x_internal_auth, secret):
        raise HTTPException(status_code=403, detail="forbidden")


class UserTenantIn(BaseModel):
    uid: str
    tenant: str


class VerifyIn(BaseModel):
    uid: str
    tenant: str
    method: str
    code: str


@router.post("/internal/2fa/required")
def internal_required(body: UserTenantIn, svc: Services = Depends(services),
                      _: None = Depends(require_internal)) -> dict:
    enabled = svc.twofa.is_enabled(body.tenant, body.uid)
    must_enroll = _required(svc, body.tenant) and not enabled
    return {"required": enabled or must_enroll, "enabled": enabled,
            "must_enroll": must_enroll, "methods": _effective_methods(svc, body.tenant)}


@router.post("/internal/2fa/verify")
def internal_verify(body: VerifyIn, request: Request, svc: Services = Depends(services),
                    _: None = Depends(require_internal)) -> dict:
    ip = client_ip(request)
    s = svc.settings
    if not (svc.tokens.rate_ok(f"2fa:ip:{ip}", s.mfa_rate_per_ip, s.mfa_rate_window_s)
            and svc.tokens.rate_ok(f"2fa:uid:{body.uid}", s.mfa_rate_per_ip, s.mfa_rate_window_s)):
        raise HTTPException(status_code=429, detail="too many attempts")
    method = body.method.lower()
    if method not in _effective_methods(svc, body.tenant) and method != "recovery":
        raise HTTPException(status_code=400, detail="method not permitted")
    ok = False
    if method == "totp":
        secret = svc.twofa.get_secret(body.tenant, body.uid)
        ok = bool(secret) and twofa.totp_verify(secret, body.code)
    elif method == "email":
        ok = svc.tokens.consume_code("2fa_email", body.uid, body.code)
    elif method == "recovery":
        ok = svc.twofa.consume_recovery_code(body.tenant, body.uid, body.code)
    svc.audit.emit(action="2fa_verify", outcome="ok" if ok else "denied",
                   actor=body.uid, tenant=body.tenant, source_addr=ip, detail={"method": method})
    return {"ok": ok}


@router.post("/internal/2fa/email-challenge")
def internal_email_challenge(body: UserTenantIn, svc: Services = Depends(services),
                             _: None = Depends(require_internal)) -> dict:
    if "email" not in _effective_methods(svc, body.tenant):
        raise HTTPException(status_code=403, detail="email 2FA is not permitted")
    code = f"{secrets.randbelow(1_000_000):06d}"
    svc.tokens.issue_code("2fa_email", body.uid, code, svc.settings.mfa_email_ttl_s)
    sent = False
    try:
        tmpl = svc.templates.get(body.tenant, TWO_FA_EMAIL)
        ctx = {"display_name": body.uid, "email": body.uid, "code": code,
               "expires": f"{svc.settings.mfa_email_ttl_s // 60} minutes"}
        subject = email_mod.render(tmpl.subject, ctx)
        html = email_mod.render(tmpl.body, ctx)
        svc.mailer.send(body.uid, subject, html)
        sent = True
    except Exception:
        sent = False
    svc.audit.emit(action="2fa_challenge", outcome="ok" if sent else "error",
                   actor=body.uid, tenant=body.tenant, detail={"method": "email"})
    return {"sent": sent}


# ------------------------------ tenant-admin policy --------------------------
# A tenant admin sets which 2FA methods their tenant permits (a subset of the
# deployment cap — e.g. disable weaker email recovery for a security-critical
# tenant) and whether 2FA is required for members (PROPOSAL §4.8).

class PolicyIn(BaseModel):
    # A subset of the deployment methods the tenant permits. Omit/null = inherit
    # the full deployment cap (no extra restriction).
    allowed_methods: list[str] | None = None
    require: bool = False


@router.get("/v1/admin/2fa-policy")
def get_policy(svc: Services = Depends(services),
               ident: Identity = Depends(require_tenant_admin)) -> dict:
    cap = _deployment_cap(svc)
    pol = svc.twofa_policy.get(ident.tenant)
    return {
        "deployment_methods": cap,                              # the ceiling (checkbox choices)
        "allowed_methods": _effective_methods(svc, ident.tenant),  # what's in force now
        "require": pol.require,                                 # tenant policy toggle
        "required_by_deployment": ident.tenant in _env_required_tenants(svc),  # env-forced (locked on)
    }


@router.put("/v1/admin/2fa-policy")
def put_policy(body: PolicyIn, svc: Services = Depends(services),
               ident: Identity = Depends(require_tenant_admin)) -> dict:
    cap = _deployment_cap(svc)
    # Normalize + validate the selection against the deployment cap.
    if body.allowed_methods is None:
        chosen = list(cap)          # inherit-everything
    else:
        chosen = [m.strip().lower() for m in body.allowed_methods if m.strip()]
        bad = [m for m in chosen if m not in cap]
        if bad:
            raise HTTPException(status_code=400,
                                detail=f"methods not permitted by this deployment: {', '.join(bad)}")
    # A required tenant must keep at least one usable method, else members could
    # never satisfy the mandate.
    if body.require and not chosen:
        raise HTTPException(status_code=400,
                            detail="cannot require 2FA while allowing no methods")
    # Store None (inherit) when the tenant allows the full cap, so it tracks future
    # deployment-cap changes; otherwise store the explicit restricted list.
    to_store = None if set(chosen) >= set(cap) else chosen
    if not svc.audit.emit(category="admin", action="2fa_policy_update", outcome="ok",
                          actor=ident.user, tenant=ident.tenant,
                          detail={"allowed_methods": chosen, "require": body.require}):
        raise HTTPException(status_code=503, detail="audit log unavailable")
    svc.twofa_policy.set(ident.tenant, to_store, body.require)
    return {
        "deployment_methods": cap,
        "allowed_methods": _effective_methods(svc, ident.tenant),
        "require": svc.twofa_policy.get(ident.tenant).require,
        "required_by_deployment": ident.tenant in _env_required_tenants(svc),
    }
