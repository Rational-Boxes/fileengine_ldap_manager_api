"""End-to-end 2FA endpoint tests (PROPOSAL §4) against live Postgres + Redis.

Exercises the full enrollment + verification lifecycle through the FastAPI app:
  self-service  status -> setup -> verify-setup -> (recovery-codes / disable)
  internal API  required -> verify(totp|recovery|email) -> email-challenge

Skipped automatically when DATABASE_URL / a JWT secret / a Fernet key aren't
configured (so the pure-unit suite still runs anywhere).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from cryptography.fernet import Fernet

from ldap_manager import twofa
from ldap_manager.app import create_app
from ldap_manager.config import load_settings

# The app loads .env on import of settings; pull the same values for the test.
_settings = load_settings()

pytestmark = pytest.mark.skipif(
    not (_settings.database_url and _settings.jwt_secret and _settings.redis_url),
    reason="live DATABASE_URL + REDIS_URL + FILEENGINE_JWT_SECRET required",
)

TENANT = "acme"
UID = "james@example.com"
INTERNAL_SECRET = "test-internal-secret"
FERNET_KEY = Fernet.generate_key().decode()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _make_jwt(secret: str, *, sub: str, tenant: str, roles: list[str]) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub": sub, "tenant": tenant, "roles": {tenant: roles},
        "exp": int(time.time()) + 3600,
    }).encode())
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


@pytest.fixture()
def client(monkeypatch):
    # Configure 2FA for this app instance without touching the shared .env.
    monkeypatch.setenv("TOTP_SECRET_KEY", FERNET_KEY)
    monkeypatch.setenv("MFA_INTERNAL_SECRET", INTERNAL_SECRET)
    monkeypatch.setenv("MFA_ALLOWED_METHODS", "totp,email")
    monkeypatch.setenv("TOTP_REQUIRED_TENANTS", "")
    # High cap so shared Redis rate buckets don't exhaust across tests in-window.
    monkeypatch.setenv("MFA_RATE_PER_IP", "1000")
    settings = load_settings()
    app = create_app(settings)
    # Clean slate for this (tenant, uid).
    app.state.services.twofa.disable(UID)
    c = TestClient(app)
    c._settings = settings  # type: ignore[attr-defined]
    yield c
    app.state.services.twofa.disable(UID)


def _auth(roles: list[str] | None = None) -> dict:
    tok = _make_jwt(_settings.jwt_secret, sub=UID, tenant=TENANT, roles=roles or [])
    return {"Authorization": f"Bearer {tok}", "X-Tenant": TENANT}


def _internal() -> dict:
    return {"X-Internal-Auth": INTERNAL_SECRET}


def test_full_totp_lifecycle(client):
    h = _auth()

    # status: not enrolled
    r = client.get("/v1/me/2fa/status", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
    assert "totp" in r.json()["methods"]

    # setup -> pending secret + otpauth uri
    r = client.post("/v1/me/2fa/setup", headers=h)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")

    # status now reports pending (secret set, not yet enabled)
    assert client.get("/v1/me/2fa/status", headers=h).json()["pending"] is True

    # a wrong code fails verify-setup
    assert client.post("/v1/me/2fa/verify-setup", headers=h,
                       json={"code": "000000"}).status_code == 400

    # the correct current code enables 2FA and returns recovery codes
    code = twofa.totp_at(secret, time.time())
    r = client.post("/v1/me/2fa/verify-setup", headers=h, json={"code": code})
    assert r.status_code == 200, r.text
    recovery = r.json()["recovery_codes"]
    assert len(recovery) == 10
    assert client.get("/v1/me/2fa/status", headers=h).json()["enabled"] is True

    # internal: required? -> yes (enabled)
    r = client.post("/internal/2fa/required", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT})
    # Per-user enrollment shows enabled; `required` follows the tenant policy —
    # TENANT has no requirement, so enrollment alone does not force a challenge.
    assert r.status_code == 200 and r.json()["enabled"] is True
    assert r.json()["required"] is False and r.json()["tenant_requires"] is False

    # internal verify: correct TOTP -> ok
    code = twofa.totp_at(secret, time.time())
    r = client.post("/internal/2fa/verify", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT, "method": "totp", "code": code})
    assert r.status_code == 200 and r.json()["ok"] is True

    # internal verify: a recovery code works once, then is spent
    rc = recovery[0]
    r = client.post("/internal/2fa/verify", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT, "method": "recovery", "code": rc})
    assert r.json()["ok"] is True
    r = client.post("/internal/2fa/verify", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT, "method": "recovery", "code": rc})
    assert r.json()["ok"] is False

    # disable requires a valid code
    assert client.post("/v1/me/2fa/disable", headers=h,
                       json={"code": "000000"}).status_code == 400
    code = twofa.totp_at(secret, time.time())
    r = client.post("/v1/me/2fa/disable", headers=h, json={"code": code})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert client.get("/v1/me/2fa/status", headers=h).json()["enabled"] is False


def test_email_challenge_and_verify(client):
    # No TOTP enrolled — email fallback issues a code we can consume via internal verify.
    r = client.post("/internal/2fa/email-challenge", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT})
    assert r.status_code == 200, r.text
    # Mailer likely unconfigured in test => sent False, but the code is issued in Redis.

    # Pull the issued code straight from the token store to simulate the user reading email.
    svc = client.app.state.services  # type: ignore[attr-defined]
    # Re-issue deterministically so the test doesn't depend on scraping the mailer.
    svc.tokens.issue_code("2fa_email", UID, "123456", 300)
    r = client.post("/internal/2fa/verify", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT, "method": "email", "code": "123456"})
    assert r.status_code == 200 and r.json()["ok"] is True
    # single-use
    r = client.post("/internal/2fa/verify", headers=_internal(),
                    json={"uid": UID, "tenant": TENANT, "method": "email", "code": "123456"})
    assert r.json()["ok"] is False


def test_internal_requires_secret(client):
    # Missing / wrong internal secret -> forbidden.
    assert client.post("/internal/2fa/required",
                       json={"uid": UID, "tenant": TENANT}).status_code == 403
    assert client.post("/internal/2fa/required", headers={"X-Internal-Auth": "wrong"},
                       json={"uid": UID, "tenant": TENANT}).status_code == 403


def test_setup_is_idempotent_while_pending(client):
    # Re-opening setup during a pending enrollment must return the SAME secret, so
    # a user can't end up with a scanned QR that no longer matches what's stored
    # (the lock-out this caused). A fresh secret is only minted after disable.
    h = _auth()
    client.app.state.services.twofa.disable(UID)  # clean slate
    s1 = client.post("/v1/me/2fa/setup", headers=h).json()["secret"]
    s2 = client.post("/v1/me/2fa/setup", headers=h).json()["secret"]
    assert s1 == s2, "re-opening setup must reuse the pending secret"

    code = twofa.totp_at(s1, time.time())
    assert client.post("/v1/me/2fa/verify-setup", headers=h, json={"code": code}).status_code == 200
    code = twofa.totp_at(s1, time.time())
    assert client.post("/v1/me/2fa/disable", headers=h, json={"code": code}).status_code == 200

    s3 = client.post("/v1/me/2fa/setup", headers=h).json()["secret"]
    assert s3 != s1, "after disable, a fresh enrollment mints a new secret"
    client.app.state.services.twofa.disable(UID)


def test_self_service_requires_bearer(client):
    assert client.get("/v1/me/2fa/status").status_code == 401


def test_tenant_admin_policy(client):
    # The admin endpoints gate on LDAP tenant-admin membership; override that
    # dependency to isolate the policy logic (the gate is shared + tested elsewhere).
    from ldap_manager.deps import require_tenant_admin
    from ldap_manager.identity import Identity
    app = client.app
    app.dependency_overrides[require_tenant_admin] = \
        lambda: Identity(user="admin@x", tenant=TENANT, roles=["tenant_admin"])
    try:
        app.state.services.twofa_policy.set(TENANT, None, False)   # clean slate
        app.state.services.twofa.disable(UID)

        # Default: the tenant inherits the full deployment cap, not required.
        r = client.get("/v1/admin/2fa-policy")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["deployment_methods"] == ["totp", "email"]
        assert body["allowed_methods"] == ["totp", "email"]
        assert body["require"] is False

        # Restrict to authenticator only (disable weaker email recovery).
        r = client.put("/v1/admin/2fa-policy", json={"allowed_methods": ["totp"], "require": False})
        assert r.status_code == 200, r.text
        assert r.json()["allowed_methods"] == ["totp"]

        # The restriction is in force on the self-service + internal surfaces.
        assert client.get("/v1/me/2fa/status", headers=_auth()).json()["methods"] == ["totp"]
        assert client.post("/internal/2fa/email-challenge", headers=_internal(),
                           json={"uid": UID, "tenant": TENANT}).status_code == 403

        # Require 2FA -> a non-enrolled member must enroll.
        r = client.put("/v1/admin/2fa-policy", json={"allowed_methods": ["totp"], "require": True})
        assert r.status_code == 200 and r.json()["require"] is True
        rq = client.post("/internal/2fa/required", headers=_internal(),
                         json={"uid": UID, "tenant": TENANT}).json()
        assert rq["required"] is True and rq["must_enroll"] is True

        # Cannot require 2FA while allowing no method.
        assert client.put("/v1/admin/2fa-policy",
                          json={"allowed_methods": [], "require": True}).status_code == 400
        # A method outside the deployment cap is rejected.
        assert client.put("/v1/admin/2fa-policy",
                          json={"allowed_methods": ["webauthn"], "require": False}).status_code == 400

        # Reset (null = inherit) -> the full cap is permitted again.
        r = client.put("/v1/admin/2fa-policy", json={"allowed_methods": None, "require": False})
        assert r.status_code == 200 and r.json()["allowed_methods"] == ["totp", "email"]
    finally:
        app.dependency_overrides.pop(require_tenant_admin, None)
        app.state.services.twofa_policy.set(TENANT, None, False)
        app.state.services.twofa.disable(UID)
