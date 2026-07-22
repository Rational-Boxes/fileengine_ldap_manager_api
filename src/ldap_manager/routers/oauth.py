"""OAuth 2.0 / OIDC authority endpoints (Phase 1.7).

FileEngine as an authorization server so CMS/web-portals, ONLYOFFICE, and service
integrations delegate to it. Public discovery + JWKS + the authorize/token/userinfo
endpoints live here (no tenant-admin gate); the client *registry* is admin-gated in
``admin_oauth``.

Flow notes:
* ``/authorize`` authenticates the end-user via their bridge bearer token (the SPA
  drives it), validates the request, and 302-redirects an authorization ``code``
  back to the registered ``redirect_uri``. First-party clients (``trusted``) skip
  the consent screen; untrusted clients require the interactive consent UI (frontend
  increment) and are refused here until then.
* ``/token`` implements ``authorization_code`` (+ PKCE), ``refresh_token`` (rotating),
  and ``client_credentials``.
* Every token's ``sub`` is the FileEngine user (or, for client-credentials, the
  client), so it plugs straight into the impersonation rule downstream.
"""
from __future__ import annotations

import time
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .. import oauth_store, oauth_tokens
from ..deps import Services, require_identity, services

router = APIRouter(tags=["oauth"])

_SUPPORTED_SCOPES = list(oauth_tokens.OIDC_SCOPES)


def _enabled_or_404(svc: Services):
    if not svc.settings.oauth_enabled:
        raise HTTPException(status_code=404, detail="oauth authority disabled")
    if not svc.settings.oauth_issuer:
        raise HTTPException(status_code=503, detail="OAUTH_ISSUER not configured")


def _require_stores(svc: Services):
    """The authorize/token flows need the client registry (Postgres) + the code
    store (Redis); a clean 503 when either is unavailable (never a 500)."""
    if not svc.oauth_clients.enabled():
        raise HTTPException(status_code=503, detail="oauth client store unavailable (no DATABASE_URL)")
    if not svc.oauth_codes.enabled:
        raise HTTPException(status_code=503, detail="oauth code store unavailable (no REDIS_URL)")


def _issuer(svc: Services) -> str:
    return svc.settings.oauth_issuer.rstrip("/")


# ------------------------------ discovery + JWKS ----------------------------
@router.get("/.well-known/openid-configuration")
def discovery(svc: Services = Depends(services)) -> dict:
    _enabled_or_404(svc)
    iss = _issuer(svc)
    return {
        "issuer": iss,
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "userinfo_endpoint": f"{iss}/oauth/userinfo",
        "jwks_uri": f"{iss}/oauth/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [svc.oauth_keys.alg],
        "scopes_supported": _SUPPORTED_SCOPES,
        "token_endpoint_auth_methods_supported": list(oauth_store.AUTH_METHODS),
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": ["sub", "email", "email_verified", "name", "preferred_username",
                             "tenant", "roles", "auth_time", "nonce"],
    }


@router.get("/oauth/jwks.json")
def jwks(svc: Services = Depends(services)) -> dict:
    _enabled_or_404(svc)
    return svc.oauth_keys.jwks()


# --------------------------------- authorize --------------------------------
def _redirect_error(redirect_uri: str, error: str, state: str, desc: str = "") -> RedirectResponse:
    params = {"error": error}
    if desc:
        params["error_description"] = desc
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


@router.get("/oauth/authorize")
def authorize(
    request: Request,
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    nonce: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    svc: Services = Depends(services),
    ident=Depends(require_identity),
):
    _enabled_or_404(svc)
    _require_stores(svc)
    client = svc.oauth_clients.get(client_id)
    # Errors that must NOT redirect (unvalidated client/redirect_uri) → 400.
    if client is None:
        raise HTTPException(status_code=400, detail="invalid client_id")
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(status_code=400, detail="redirect_uri not registered for this client")

    # From here, protocol errors redirect back to the (validated) redirect_uri.
    if response_type != "code":
        return _redirect_error(redirect_uri, "unsupported_response_type", state)
    if "authorization_code" not in client.grant_types:
        return _redirect_error(redirect_uri, "unauthorized_client", state)

    requested = [s for s in (scope or "").split() if s]
    granted = [s for s in requested if s in client.scopes]
    if not granted:
        return _redirect_error(redirect_uri, "invalid_scope", state)

    # PKCE: mandatory for public clients; honored for confidential when supplied.
    public = client.token_endpoint_auth_method == "none"
    if public and not code_challenge:
        return _redirect_error(redirect_uri, "invalid_request", state, "code_challenge required")
    if code_challenge and code_challenge_method not in ("S256", "plain"):
        return _redirect_error(redirect_uri, "invalid_request", state, "unsupported code_challenge_method")

    # Consent: first-party (trusted) clients skip it; untrusted require the consent
    # UI (frontend increment) and are refused until it exists.
    if not client.trusted:
        return _redirect_error(redirect_uri, "consent_required", state,
                               "interactive consent not yet available for this client")

    profile = _lookup_profile(svc, ident.user)
    payload = {
        "client_id": client.client_id, "user": ident.user, "tenant": ident.tenant,
        "redirect_uri": redirect_uri, "scope": " ".join(granted), "nonce": nonce,
        "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
        "auth_time": int(time.time()), "roles": list(ident.roles),
        "email": profile["email"], "name": profile["name"],
    }
    code = svc.oauth_codes.issue_code(payload, svc.settings.oauth_code_ttl)
    out = {"code": code}
    if state:
        out["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{sep}{urlencode(out)}", status_code=302)


def _lookup_profile(svc: Services, uid: str) -> dict:
    """Email + display name for OIDC claims; falls back to the uid when LDAP is
    unavailable or the field is empty (best-effort, never fatal)."""
    email = uid if "@" in uid else ""
    name = ""
    try:
        u = svc.ldap.get_user(uid)
        if u is not None:
            email = u.email or email
            name = u.display_name or ""
    except Exception:
        pass
    return {"email": email, "name": name}


# ----------------------------------- token ----------------------------------
def _client_auth(svc: Services, authorization, form_id, form_secret):
    """Resolve the client + whether it authenticated as confidential. Supports
    HTTP Basic and ``client_secret_post``; returns ``(client, confidential_ok)``."""
    import base64
    cid, secret = form_id, form_secret
    if authorization and authorization.lower().startswith("basic "):
        try:
            raw = base64.b64decode(authorization.split(" ", 1)[1]).decode("utf-8")
            cid, secret = raw.split(":", 1)
        except Exception:
            raise HTTPException(status_code=401, detail="invalid client authentication")
    if not cid:
        raise HTTPException(status_code=401, detail="client_id required")
    if secret:
        client = svc.oauth_clients.verify_secret(cid, secret)
        if client is None:
            raise HTTPException(status_code=401, detail="invalid client authentication")
        return client, True
    client = svc.oauth_clients.get(cid)
    if client is None:
        raise HTTPException(status_code=401, detail="unknown client")
    return client, False


def _token_response(svc: Services, *, subject, tenant, client_id, scope, roles,
                    issue_id: bool, issue_refresh: bool, nonce="", auth_time=None,
                    email="", name="") -> dict:
    st = svc.settings
    access = oauth_tokens.issue_access_token(
        svc.oauth_keys, issuer=_issuer(svc), subject=subject, tenant=tenant,
        client_id=client_id, scope=scope, ttl=st.oauth_access_ttl, roles=roles)
    body = {"access_token": access, "token_type": "Bearer",
            "expires_in": st.oauth_access_ttl, "scope": scope}
    if issue_id and "openid" in scope.split():
        body["id_token"] = oauth_tokens.issue_id_token(
            svc.oauth_keys, issuer=_issuer(svc), subject=subject, tenant=tenant,
            client_id=client_id, ttl=st.oauth_id_token_ttl, nonce=nonce,
            auth_time=auth_time, email=email, name=name, roles=roles, scope=scope)
    if issue_refresh and "offline_access" in scope.split():
        body["refresh_token"] = svc.oauth_codes.issue_refresh(
            {"client_id": client_id, "user": subject, "tenant": tenant, "scope": scope,
             "roles": roles, "email": email, "name": name}, st.oauth_refresh_ttl)
    return body


@router.post("/oauth/token")
def token(
    request: Request,
    grant_type: str = Form(""),
    code: str = Form(""),
    redirect_uri: str = Form(""),
    code_verifier: str = Form(""),
    refresh_token: str = Form(""),
    scope: str = Form(""),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    authorization: str | None = Header(default=None),
    svc: Services = Depends(services),
) -> JSONResponse:
    _enabled_or_404(svc)
    _require_stores(svc)
    client, confidential = _client_auth(svc, authorization, client_id, client_secret)

    if grant_type == "authorization_code":
        payload = svc.oauth_codes.consume_code(code)
        if payload is None or payload.get("client_id") != client.client_id:
            raise HTTPException(status_code=400, detail={"error": "invalid_grant"})
        if payload.get("redirect_uri") != redirect_uri:
            raise HTTPException(status_code=400, detail={"error": "invalid_grant",
                                "error_description": "redirect_uri mismatch"})
        challenge = payload.get("code_challenge")
        if challenge:
            if not oauth_store.verify_pkce(code_verifier, challenge,
                                           payload.get("code_challenge_method", "S256")):
                raise HTTPException(status_code=400, detail={"error": "invalid_grant",
                                    "error_description": "PKCE verification failed"})
        elif not confidential:
            raise HTTPException(status_code=401, detail="client authentication required")
        gscope = payload.get("scope", "")
        return JSONResponse(_token_response(
            svc, subject=payload["user"], tenant=payload["tenant"], client_id=client.client_id,
            scope=gscope, roles=payload.get("roles", []), issue_id=True, issue_refresh=True,
            nonce=payload.get("nonce", ""), auth_time=payload.get("auth_time"),
            email=payload.get("email", ""), name=payload.get("name", "")))

    if grant_type == "refresh_token":
        payload = svc.oauth_codes.consume_refresh(refresh_token)
        if payload is None or payload.get("client_id") != client.client_id:
            raise HTTPException(status_code=400, detail={"error": "invalid_grant"})
        gscope = payload.get("scope", "")
        # Downscope only (a refresh may narrow, never widen).
        if scope:
            narrowed = [s for s in scope.split() if s in gscope.split()]
            gscope = " ".join(narrowed) if narrowed else gscope
        return JSONResponse(_token_response(
            svc, subject=payload["user"], tenant=payload["tenant"], client_id=client.client_id,
            scope=gscope, roles=payload.get("roles", []), issue_id=True, issue_refresh=True,
            email=payload.get("email", ""), name=payload.get("name", "")))

    if grant_type == "client_credentials":
        if not confidential:
            raise HTTPException(status_code=401, detail="client authentication required")
        if "client_credentials" not in client.grant_types:
            raise HTTPException(status_code=400, detail={"error": "unauthorized_client"})
        requested = [s for s in (scope or "").split() if s]
        gscope = " ".join([s for s in requested if s in client.scopes]) or " ".join(client.scopes)
        # No id_token / refresh for a service identity; sub is the client itself.
        return JSONResponse(_token_response(
            svc, subject=client.client_id, tenant=client.tenant, client_id=client.client_id,
            scope=gscope, roles=[], issue_id=False, issue_refresh=False))

    raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})


# --------------------------------- userinfo ---------------------------------
@router.get("/oauth/userinfo")
def userinfo(svc: Services = Depends(services),
             authorization: str | None = Header(default=None)) -> dict:
    _enabled_or_404(svc)
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="bearer access token required")
    token_str = authorization.split(" ", 1)[1].strip()
    claims = oauth_tokens.verify_token(svc.oauth_keys, token_str, issuer=_issuer(svc),
                                       token_use="access")
    if claims is None:
        raise HTTPException(status_code=401, detail="invalid access token")
    scopes = set((claims.get("scope") or "").split())
    out = {"sub": claims["sub"], "tenant": claims.get("tenant", "")}
    if scopes & {"profile", "email"}:
        prof = _lookup_profile(svc, claims["sub"])
        if "email" in scopes and prof["email"]:
            out["email"] = prof["email"]
            out["email_verified"] = True
        if "profile" in scopes and prof["name"]:
            out["name"] = prof["name"]
            out["preferred_username"] = claims["sub"]
    if "roles" in scopes and "roles" in claims:
        out["roles"] = claims["roles"]
    return out
