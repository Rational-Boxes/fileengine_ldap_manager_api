"""Backend-generated service credentials for the WebDAV / MCP doors (PROPOSAL
§15/§16).

Two surfaces, mirroring the 2FA router:
  * self-service ``/v1/me/service-credentials`` — a user creates/lists/rotates/
    revokes their own ``key:secret`` credentials (bearer-authenticated, hard-scoped
    to the caller). The secret is returned **once**, at create/rotate.
  * internal ``/internal/service-cred/verify`` — the server-to-server API the
    WebDAV bridge and MCP door call to authenticate a presented ``key:secret``,
    guarded by a shared secret (``SERVICE_CRED_INTERNAL_SECRET`` / ``MFA_INTERNAL_SECRET``).

There is intentionally **no endpoint to read a secret back**: a lost secret is
resolved by ``rotate``, not retrieval.
"""
from __future__ import annotations

import secrets as _secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel

from .. import service_cred as sc
from ..deps import Services, require_identity, services
from ..identity import Identity

router = APIRouter()


def _store(svc: Services) -> sc.ServiceCredentialStore:
    if not svc.service_cred.enabled():
        raise HTTPException(status_code=503, detail="service-credential store unavailable (no DATABASE_URL)")
    if not svc.settings.service_cred_pepper:
        raise HTTPException(status_code=503,
                            detail="service credentials not configured (SERVICE_CRED_HASH_PEPPER unset)")
    return svc.service_cred


# ------------------------------ self-service ---------------------------------

class CreateIn(BaseModel):
    label: str | None = None
    scopes: list[str] | None = None   # subset of {webdav, mcp}; default webdav


class RotateIn(BaseModel):
    new_key_id: bool = False


def _meta(m: sc.CredentialMeta) -> dict:
    return {"key_id": m.key_id, "label": m.label, "scopes": m.scopes,
            "allowed_cidrs": m.allowed_cidrs, "created_at": m.created_at,
            "last_used_at": m.last_used_at, "expires_at": m.expires_at}


@router.get("/v1/me/service-credentials")
def list_credentials(svc: Services = Depends(services),
                     ident: Identity = Depends(require_identity)) -> dict:
    return {"credentials": [_meta(m) for m in _store(svc).list_for(ident.user)]}


@router.post("/v1/me/service-credentials", status_code=201)
def create_credential(body: CreateIn, svc: Services = Depends(services),
                      ident: Identity = Depends(require_identity)) -> dict:
    store = _store(svc)
    scopes = sc.normalize_scopes(body.scopes)
    if store.count_for(ident.user) >= svc.settings.service_cred_max_per_user:
        raise HTTPException(status_code=409,
                            detail=f"credential limit reached ({svc.settings.service_cred_max_per_user})")
    key_id, secret = store.create(tenant=ident.tenant, uid=ident.user,
                                  scopes=scopes, label=(body.label or None))
    svc.audit.emit(action="webdav_cred_create", outcome="ok", actor=ident.user,
                   tenant=ident.tenant, detail={"key_id": key_id, "scopes": scopes})
    # The ONLY time the secret is returned.
    return {"key_id": key_id, "secret": secret, "scopes": scopes, "label": body.label}


@router.post("/v1/me/service-credentials/{key_id}/rotate")
def rotate_credential(key_id: str, body: RotateIn, svc: Services = Depends(services),
                      ident: Identity = Depends(require_identity)) -> dict:
    out = _store(svc).rotate(key_id=key_id, uid=ident.user, new_key_id=body.new_key_id)
    if out is None:
        raise HTTPException(status_code=404, detail="no such credential")
    new_key, secret = out
    svc.audit.emit(action="webdav_cred_rotate", outcome="ok", actor=ident.user,
                   tenant=ident.tenant, detail={"key_id": new_key, "rotated_from": key_id})
    return {"key_id": new_key, "secret": secret}


@router.delete("/v1/me/service-credentials/{key_id}", status_code=204)
def revoke_credential(key_id: str, svc: Services = Depends(services),
                      ident: Identity = Depends(require_identity)) -> Response:
    if not _store(svc).revoke(key_id=key_id, uid=ident.user):
        raise HTTPException(status_code=404, detail="no such credential")
    svc.audit.emit(action="webdav_cred_revoke", outcome="ok", actor=ident.user,
                   tenant=ident.tenant, detail={"key_id": key_id})
    return Response(status_code=204)


# ------------------------------ internal API ---------------------------------

def _internal_secret(svc: Services) -> str:
    # A dedicated secret if set, else reuse the MFA internal secret so ops manage one.
    return svc.settings.service_cred_internal_secret or svc.settings.mfa_internal_secret


def require_internal(svc: Services = Depends(services),
                     x_internal_auth: str | None = Header(default=None)) -> None:
    secret = _internal_secret(svc)
    if not secret:
        raise HTTPException(status_code=404, detail="internal service-credential API not enabled")
    if not x_internal_auth or not _secrets.compare_digest(x_internal_auth, secret):
        raise HTTPException(status_code=403, detail="forbidden")


class VerifyIn(BaseModel):
    key_id: str
    secret: str
    tenant: str
    scope: str                      # "webdav" | "mcp"
    source_ip: str | None = None    # for the optional per-key IP allowlist (§16.5)


@router.post("/internal/service-cred/verify")
def internal_verify(body: VerifyIn, svc: Services = Depends(services),
                    _: None = Depends(require_internal)) -> dict:
    uid = _store(svc).verify(key_id=body.key_id, secret=body.secret, tenant=body.tenant,
                             scope=body.scope, source_ip=body.source_ip)
    if uid is None:
        raise HTTPException(status_code=401, detail="invalid credential")
    return {"uid": uid, "tenant": body.tenant}
