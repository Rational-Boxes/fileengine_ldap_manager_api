"""OAuth grants refuse a tenant that is not live (§3.4c).

Found 2026-10-01: suspension reached every door holding a bridge session — those
expire within 15 minutes and their refresh goes back through the bridge, which
refuses. OAuth clients (BCF) do not: ldap_manager issues 1-hour access tokens and
14-day refresh tokens, and nothing in the token endpoint asked the tenant's state,
so a suspended tenant's integrations could renew forever.

Every grant mints through one function, so the check is there. The refresh grant
also checks BEFORE consuming the token: rotation deletes it, and a refusal that
destroyed it would force every client to re-authorise after the tenant resumes.
"""
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings
from ldap_manager.oauth_store import OAuthClient
from ldap_manager.routers import oauth as oauth_router
from ldap_manager.tenant_state import TenantStateGate

ISS = "https://files.example.com/ldapadmin"


class _Clients:
    def __init__(self, *clients):
        self.by_id = {c.client_id: c for c in clients}

    def enabled(self):
        return True

    def get(self, cid):
        return self.by_id.get(cid)

    def verify_secret(self, cid, secret):
        c = self.by_id.get(cid)
        return c if c is not None and secret == "s3cret" else None


class _Codes:
    enabled = True

    def __init__(self):
        self.codes, self.refresh = {}, {}

    def issue_code(self, payload, ttl):
        t = f"code{len(self.codes)}"; self.codes[t] = payload; return t

    def consume_code(self, t):
        return self.codes.pop(t, None)

    def issue_refresh(self, payload, ttl):
        t = f"rt{len(self.refresh)}"; self.refresh[t] = payload; return t

    def peek_refresh(self, t):
        return self.refresh.get(t)

    def consume_refresh(self, t):
        return self.refresh.pop(t, None)


def _client(tenant="acme", state="live"):
    app = create_app(Settings(oauth_enabled=True, oauth_issuer=ISS))
    svc = app.state.services
    c = OAuthClient(client_id="bcf-1", tenant=tenant, name="BCF", has_secret=True,
                    redirect_uris=["https://bcf.example/cb"],
                    grant_types=["authorization_code", "refresh_token", "client_credentials"],
                    response_types=["code"], scopes=["openid", "offline_access", "bcf"],
                    token_endpoint_auth_method="client_secret_basic", trusted=True)
    svc.oauth_clients = _Clients(c)
    svc.oauth_codes = _Codes()
    states = {tenant: state}
    oauth_router.TENANT_GATE = TenantStateGate(SimpleNamespace(
        tenant_state=lambda t: {"found": t in states, "state": states.get(t, "")}))
    return TestClient(app), svc, states


AUTH = ("bcf-1", "s3cret")
PAYLOAD = {"client_id": "bcf-1", "user": "u@acme.test", "tenant": "acme",
           "scope": "openid offline_access bcf", "roles": []}


def _refresh(c, rt):
    return c.post("/oauth/token", auth=AUTH, data={"grant_type": "refresh_token",
                                                   "refresh_token": rt})


def test_a_live_tenants_refresh_still_works():
    c, svc, _ = _client()
    rt = svc.oauth_codes.issue_refresh(dict(PAYLOAD), 60)
    r = _refresh(c, rt)
    assert r.status_code == 200, r.text
    assert "access_token" in r.json() and "refresh_token" in r.json()


def test_a_suspended_tenants_refresh_is_refused_and_the_token_survives():
    c, svc, states = _client(state="suspended")
    rt = svc.oauth_codes.issue_refresh(dict(PAYLOAD), 60)
    r = _refresh(c, rt)
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_grant"
    assert rt in svc.oauth_codes.refresh            # NOT burned by the refusal
    # Resumed: the same token works, no re-authorisation.
    states["acme"] = "live"
    oauth_router.TENANT_GATE._cache.clear()
    assert _refresh(c, rt).status_code == 200


def test_a_suspended_tenants_authorization_code_is_refused():
    c, svc, _ = _client(state="suspended")
    code = svc.oauth_codes.issue_code(dict(PAYLOAD, redirect_uri="https://bcf.example/cb"), 60)
    r = c.post("/oauth/token", auth=AUTH, data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "https://bcf.example/cb"})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_grant"


def test_a_suspended_tenants_client_credentials_are_refused():
    c, _, _ = _client(state="suspended")
    r = c.post("/oauth/token", auth=AUTH, data={"grant_type": "client_credentials"})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "unauthorized_client"


def test_an_undeterminable_state_refuses():
    c, svc, _ = _client(tenant="acme", state="live")
    rt = svc.oauth_codes.issue_refresh(dict(PAYLOAD, tenant="ghost"), 60)
    assert _refresh(c, rt).status_code == 400
