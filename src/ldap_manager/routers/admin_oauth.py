"""Tenant-admin OAuth client registry (Phase 1.7).

A tenant admin registers the relying parties allowed to delegate to the authority:
CMS/web-portals (authorization_code + PKCE), service integrations
(client_credentials), and the ONLYOFFICE seam. Secrets are shown **once** at
create/rotate and stored only hashed (``oauth_store``). All queries are scoped to
``ident.tenant`` — one tenant's admin never sees another's clients.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from .. import oauth_store
from ..deps import Services, require_tenant_admin, services
from ..identity import Identity

router = APIRouter(prefix="/v1/admin/oauth-clients", tags=["oauth-admin"])


def _enabled_or_404(svc: Services):
    if not svc.settings.oauth_enabled:
        raise HTTPException(status_code=404, detail="oauth authority disabled")
    if not svc.oauth_clients.enabled():
        raise HTTPException(status_code=503, detail="oauth client store unavailable (no DATABASE_URL)")
    if not svc.settings.oauth_client_pepper:
        raise HTTPException(status_code=503, detail="OAUTH_CLIENT_SECRET_PEPPER not configured")


def _validate(body: dict, *, creating: bool) -> dict:
    out: dict = {}
    if creating and not str(body.get("name") or "").strip():
        raise HTTPException(status_code=400, detail="name is required")
    if "name" in body:
        out["name"] = str(body.get("name") or "").strip()

    if "redirect_uris" in body or creating:
        uris = body.get("redirect_uris") or []
        if not isinstance(uris, list) or any(not isinstance(u, str) for u in uris):
            raise HTTPException(status_code=400, detail="redirect_uris must be a list of strings")
        for u in uris:
            if not (u.startswith("https://") or u.startswith("http://localhost")
                    or u.startswith("http://127.0.0.1")):
                raise HTTPException(status_code=400, detail=(
                    f"redirect_uri must be https (or http://localhost): {u!r}"))
        out["redirect_uris"] = uris

    method = None
    if "token_endpoint_auth_method" in body or creating:
        method = str(body.get("token_endpoint_auth_method") or "client_secret_basic")
        if method not in oauth_store.AUTH_METHODS:
            raise HTTPException(status_code=400,
                                detail=f"token_endpoint_auth_method must be one of {list(oauth_store.AUTH_METHODS)}")
        out["token_endpoint_auth_method"] = method

    if "grant_types" in body or creating:
        gts = oauth_store.normalize_list(body.get("grant_types") or ["authorization_code"],
                                         oauth_store.GRANT_TYPES)
        out["grant_types"] = gts or ["authorization_code"]

    if "scopes" in body or creating:
        scopes = [str(s) for s in (body.get("scopes") or ["openid"]) if str(s).strip()]
        out["scopes"] = scopes or ["openid"]

    if "trusted" in body:
        out["trusted"] = bool(body.get("trusted"))

    # A public client (auth method none) can't use client_credentials.
    eff_method = method if method is not None else "client_secret_basic"
    if eff_method == "none" and "client_credentials" in out.get("grant_types", []):
        raise HTTPException(status_code=400,
                            detail="a public client (token_endpoint_auth_method=none) cannot use client_credentials")
    if creating and "authorization_code" in out.get("grant_types", []) and not out.get("redirect_uris"):
        raise HTTPException(status_code=400,
                            detail="authorization_code clients require at least one redirect_uri")
    return out


@router.get("")
def list_clients(svc: Services = Depends(services), ident: Identity = Depends(require_tenant_admin)) -> dict:
    _enabled_or_404(svc)
    return {"clients": [c.public_dict() for c in svc.oauth_clients.list_for(ident.tenant)]}


@router.post("")
def create_client(body: dict = Body(...), svc: Services = Depends(services),
                  ident: Identity = Depends(require_tenant_admin)) -> dict:
    _enabled_or_404(svc)
    if svc.oauth_clients.count_for(ident.tenant) >= svc.settings.oauth_max_clients_per_tenant:
        raise HTTPException(status_code=409, detail="per-tenant client cap reached")
    clean = _validate(body, creating=True)
    method = clean["token_endpoint_auth_method"]
    confidential = method != "none"
    client, secret = svc.oauth_clients.create(
        tenant=ident.tenant, name=clean["name"], redirect_uris=clean["redirect_uris"],
        grant_types=clean["grant_types"], scopes=clean["scopes"],
        token_endpoint_auth_method=method, trusted=clean.get("trusted", True),
        created_by=ident.user, confidential=confidential)
    svc.audit.emit(action="oauth_client_create", actor=ident.user, tenant=ident.tenant,
                   object=client.client_id, outcome="ok", category="admin")
    out = client.public_dict()
    out["client_secret"] = secret          # shown ONCE (None for a public client)
    return out


@router.get("/{client_id}")
def get_client(client_id: str, svc: Services = Depends(services),
               ident: Identity = Depends(require_tenant_admin)) -> dict:
    _enabled_or_404(svc)
    c = svc.oauth_clients.get_for(ident.tenant, client_id)
    if c is None:
        raise HTTPException(status_code=404, detail="client not found")
    return c.public_dict()


@router.put("/{client_id}")
def update_client(client_id: str, body: dict = Body(...), svc: Services = Depends(services),
                  ident: Identity = Depends(require_tenant_admin)) -> dict:
    _enabled_or_404(svc)
    if svc.oauth_clients.get_for(ident.tenant, client_id) is None:
        raise HTTPException(status_code=404, detail="client not found")
    clean = _validate(body, creating=False)
    updated = svc.oauth_clients.update(ident.tenant, client_id, **clean)
    svc.audit.emit(action="oauth_client_update", actor=ident.user, tenant=ident.tenant,
                   object=client_id, outcome="ok", category="admin")
    return updated.public_dict()


@router.post("/{client_id}/rotate-secret")
def rotate_secret(client_id: str, svc: Services = Depends(services),
                  ident: Identity = Depends(require_tenant_admin)) -> dict:
    _enabled_or_404(svc)
    c = svc.oauth_clients.get_for(ident.tenant, client_id)
    if c is None:
        raise HTTPException(status_code=404, detail="client not found")
    if c.token_endpoint_auth_method == "none":
        raise HTTPException(status_code=400, detail="public clients have no secret to rotate")
    secret = svc.oauth_clients.rotate_secret(ident.tenant, client_id)
    svc.audit.emit(action="oauth_client_rotate", actor=ident.user, tenant=ident.tenant,
                   object=client_id, outcome="ok", category="admin")
    return {"client_id": client_id, "client_secret": secret}


@router.delete("/{client_id}")
def delete_client(client_id: str, svc: Services = Depends(services),
                  ident: Identity = Depends(require_tenant_admin)) -> dict:
    _enabled_or_404(svc)
    if not svc.oauth_clients.delete(ident.tenant, client_id):
        raise HTTPException(status_code=404, detail="client not found")
    svc.audit.emit(action="oauth_client_delete", actor=ident.user, tenant=ident.tenant,
                   object=client_id, outcome="ok", category="admin")
    return {"deleted": client_id}
