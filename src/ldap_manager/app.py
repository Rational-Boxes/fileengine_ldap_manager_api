"""FastAPI application factory + entrypoint (SPECIFICATION.md). Served under the
``/ldapadmin`` same-origin proxy (Vite in dev, nginx in prod), so routes here are
mounted at the app root and the proxy adds the prefix.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .audit import AuditEmitter
from .bridge_auth import BridgeTokenVerifier
from .config import Settings, load_settings
from .deps import Services
from .email import Mailer
from .homedir import HomeProvisioner
from .ldap_client import LdapClient, LdapError, MasterUnavailable
from .password_policy import PasswordPolicy
from .templates import TemplateStore
from .tokens import TokenStore
from .twofa import TwoFactorStore
from .routers import admin_roles, admin_templates, admin_users, health, me, public_auth, twofa


def build_services(settings: Settings) -> Services:
    return Services(
        settings=settings,
        verifier=BridgeTokenVerifier(settings.bridge_url, settings.bridge_introspect_ttl,
                                     jwt_secret=settings.jwt_secret),
        ldap=LdapClient(settings),
        tokens=TokenStore(settings.redis_url),
        mailer=Mailer(settings),
        templates=TemplateStore(settings),
        policy=PasswordPolicy(settings.password_policy),
        home=HomeProvisioner(settings.bridge_url),
        audit=AuditEmitter(settings.audit_enabled),
        twofa=TwoFactorStore(settings),
    )


def _install_monitoring_allowlist(app: FastAPI) -> None:
    """Route-scoped IP allowlist for the unauthenticated monitoring endpoints
    (security review L2). The endpoints already bind loopback; when
    FILEENGINE_MONITORING_ALLOW_IPS is set (comma-separated client IPs), a request
    to a monitoring path from a non-listed address is refused with 403. Empty =
    allow any host that reaches the bound address."""
    import os
    from fastapi.responses import JSONResponse

    monitor_paths = {"/healthz", "/readyz", "/poolz"}
    allow = {ip.strip() for ip in
             os.environ.get("FILEENGINE_MONITORING_ALLOW_IPS", "").split(",") if ip.strip()}

    @app.middleware("http")
    async def _guard_monitoring(request, call_next):
        if allow and request.url.path in monitor_paths:
            client = request.client.host if request.client else ""
            if client not in allow:
                return JSONResponse({"error": "forbidden"}, status_code=403)
        return await call_next(request)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(
        title="FileEngine LDAP Manager",
        version="0.1.0",
        description="Tenant user & role administration, self-service profile/password, invite/reset.",
    )
    _install_monitoring_allowlist(app)
    app.state.services = build_services(settings)

    _LDAP_HTTP = {"entryAlreadyExists": 409, "noSuchObject": 404,
                  "insufficientAccessRights": 403, "constraintViolation": 422}

    @app.exception_handler(MasterUnavailable)
    async def _master_down(_req: Request, exc: MasterUnavailable):
        # Writes never fail over to a read replica (§1.1).
        return JSONResponse(status_code=503, content={"detail": "LDAP master unavailable"})

    @app.exception_handler(LdapError)
    async def _ldap_error(_req: Request, exc: LdapError):
        status = _LDAP_HTTP.get(exc.description, 502)
        return JSONResponse(status_code=status,
                            content={"detail": str(exc), "ldap": exc.description})

    # public / self / tenant-admin scopes are enforced per-router via deps
    app.include_router(health.router)
    app.include_router(public_auth.router)
    app.include_router(me.router)
    app.include_router(admin_users.router)
    app.include_router(admin_roles.router)
    app.include_router(admin_templates.router)
    app.include_router(twofa.router)
    return app


def main() -> None:  # pragma: no cover
    import uvicorn

    settings = load_settings()
    uvicorn.run(create_app(settings), host=settings.http_host, port=settings.http_port)


if __name__ == "__main__":  # pragma: no cover
    main()
