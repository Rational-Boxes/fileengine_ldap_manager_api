"""FastAPI dependencies — the three authorization scopes (SPECIFICATION.md §2):
public (no dep), **self** (any valid bearer token), **tenant admin** (member of
the tenant's ``administrators`` group). Shared services live on ``app.state``.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request

from .audit import AuditEmitter
from .bridge_auth import BridgeTokenVerifier
from .config import Settings
from .email import Mailer
from .homedir import HomeProvisioner
from .identity import Identity
from .ldap_client import LdapClient
from .password_policy import PasswordPolicy
from .templates import TemplateStore
from .tokens import TokenStore
from .twofa import TwoFactorStore, TwoFactorPolicyStore


@dataclass
class Services:
    settings: Settings
    verifier: BridgeTokenVerifier
    ldap: LdapClient
    tokens: TokenStore
    mailer: Mailer
    templates: TemplateStore
    policy: PasswordPolicy
    home: HomeProvisioner
    audit: AuditEmitter
    twofa: TwoFactorStore
    twofa_policy: TwoFactorPolicyStore


def services(request: Request) -> Services:
    return request.app.state.services


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def bearer_token(authorization: str | None = Header(default=None)) -> str:
    """The caller's raw bearer token — forwarded to the bridge to provision a home
    folder under the admin's own authority."""
    return _bearer(authorization)


def require_identity(
    svc: Services = Depends(services),
    authorization: str | None = Header(default=None),
    x_tenant: str | None = Header(default=None),
) -> Identity:
    """Scope: **self** — any caller with a valid http_bridge bearer token."""
    token = _bearer(authorization)
    ident = svc.verifier.verify(token, (x_tenant or "").strip())
    if ident is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return ident


def require_tenant_admin(
    svc: Services = Depends(services),
    ident: Identity = Depends(require_identity),
) -> Identity:
    """Scope: **tenant admin** — caller must be a member of
    ``cn=administrators,ou=<tenant>,<tenant_base>`` (authoritative, from LDAP)."""
    if not svc.ldap.is_tenant_admin(ident.user, ident.tenant):
        raise HTTPException(status_code=403, detail="tenant administrator required")
    return ident
