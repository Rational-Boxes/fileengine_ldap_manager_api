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

"""End-to-end OAuth 2.0 / OIDC authority flow against live Postgres + Redis.

Exercises the real stores and the full protocol: admin registers a client → the
authorization-code + PKCE flow issues a code → the token endpoint exchanges it for
access + ID + refresh tokens → userinfo → refresh rotation → client-credentials.
The ID token is verified by a third party using only the published JWKS (the point
of an asymmetric authority).

Identity is injected via FastAPI dependency overrides so the flow is isolated from
LDAP/bridge — only the OAuth logic + Postgres + Redis are under test.

Skips unless DATABASE_URL + REDIS_URL are set and reachable:
  DATABASE_URL=postgresql://postgres:postgres@localhost:5434/fileengine \
  REDIS_URL=redis://:password1@localhost:6379/0 \
  pytest tests/test_oauth_e2e.py -q
"""
import base64
import hashlib
import os
import secrets
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings
from ldap_manager.deps import require_identity, require_tenant_admin
from ldap_manager.identity import Identity

ISS = "https://files.example.test/ldapadmin"
TENANT = "acme"
USER = "alice@acme.test"


def _rsa_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(encoding=serialization.Encoding.PEM,
                          format=serialization.PrivateFormat.PKCS8,
                          encryption_algorithm=serialization.NoEncryption()).decode()


def _db_url() -> str:
    return os.environ.get("DATABASE_URL", "")


def _redis_url() -> str:
    return os.environ.get("REDIS_URL", "")


def _skip_reason() -> str:
    if not _db_url() or not _redis_url():
        return "set DATABASE_URL + REDIS_URL to run the OAuth E2E flow"
    try:
        import psycopg
        psycopg.connect(_db_url(), connect_timeout=2).close()
    except Exception as e:
        return f"Postgres unavailable: {e.__class__.__name__}"
    try:
        import redis
        redis.from_url(_redis_url()).ping()
    except Exception as e:
        return f"Redis unavailable: {e.__class__.__name__}"
    return ""


pytestmark = pytest.mark.skipif(bool(_skip_reason()), reason=_skip_reason())


@pytest.fixture
def signing_pem():
    return _rsa_pem()


@pytest.fixture
def client(signing_pem):
    s = Settings(
        oauth_enabled=True, oauth_issuer=ISS, oauth_signing_key=signing_pem,
        oauth_client_pepper="e2e-pepper-" + secrets.token_hex(4),
        database_url=_db_url(), redis_url=_redis_url())
    app = create_app(s)
    admin = Identity(user=USER, tenant=TENANT, roles=["administrators"], authenticated=True)
    app.dependency_overrides[require_identity] = lambda: admin
    app.dependency_overrides[require_tenant_admin] = lambda: admin
    c = TestClient(app, follow_redirects=False)
    c._created = []  # track client_ids for cleanup
    yield c
    for cid in c._created:
        c.delete(f"/v1/admin/oauth-clients/{cid}")


_A = "/v1/admin/oauth-clients"


def _make_client(c, **over):
    body = {"name": "Portal", "redirect_uris": ["https://portal.example.test/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid", "profile", "email", "roles", "offline_access"],
            "token_endpoint_auth_method": "client_secret_basic", "trusted": True}
    body.update(over)
    r = c.post(_A, json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    c._created.append(data["client_id"])
    return data


def _basic(client_id, secret):
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def test_client_registry_crud_and_secret_write_only(client):
    data = _make_client(client, name="CRUD client")
    assert data["client_id"].startswith("feoc_")
    assert data["client_secret"].startswith("feocs_")  # shown once
    cid = data["client_id"]

    got = client.get(f"{_A}/{cid}").json()
    assert "client_secret" not in got and got["has_secret"] is True
    assert got["name"] == "CRUD client"

    lst = client.get(_A).json()["clients"]
    assert cid in [c["client_id"] for c in lst]

    upd = client.put(f"{_A}/{cid}", json={"name": "renamed"}).json()
    assert upd["name"] == "renamed"

    rot = client.post(f"{_A}/{cid}/rotate-secret").json()
    assert rot["client_secret"].startswith("feocs_")


def test_authorization_code_pkce_full_flow(client):
    data = _make_client(client)
    cid, secret = data["client_id"], data["client_secret"]
    verifier, challenge = _pkce()

    # 1) authorize → 302 with a code
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": cid,
        "redirect_uri": "https://portal.example.test/callback",
        "scope": "openid profile email offline_access", "state": "xyz",
        "nonce": "nonce-1", "code_challenge": challenge, "code_challenge_method": "S256"})
    assert r.status_code == 302, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["state"] == ["xyz"] and "code" in q
    code = q["code"][0]

    # 2) token exchange (client Basic auth + PKCE verifier)
    r = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "https://portal.example.test/callback",
        "code_verifier": verifier}, headers=_basic(cid, secret))
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["token_type"] == "Bearer" and tok["access_token"]
    assert tok["id_token"] and tok["refresh_token"]

    # 3) the ID token verifies against the published JWKS (third-party path)
    jwk = client.get("/oauth/jwks.json").json()["keys"][0]
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    idc = jwt.decode(tok["id_token"], pub, algorithms=["RS256"], audience=cid, issuer=ISS)
    assert idc["sub"] == USER and idc["tenant"] == TENANT and idc["nonce"] == "nonce-1"
    assert idc["email"] == USER  # user has '@', so email is populated

    # 4) userinfo with the access token
    ui = client.get("/oauth/userinfo",
                    headers={"Authorization": "Bearer " + tok["access_token"]})
    assert ui.status_code == 200
    assert ui.json()["sub"] == USER and ui.json()["email"] == USER

    # 5) the authorization code is single-use (replay rejected)
    replay = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "https://portal.example.test/callback",
        "code_verifier": verifier}, headers=_basic(cid, secret))
    assert replay.status_code == 400

    # 6) refresh rotation: the refresh yields a new pair; the old refresh dies
    rr = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tok["refresh_token"]},
        headers=_basic(cid, secret))
    assert rr.status_code == 200 and rr.json()["access_token"]
    reuse = client.post("/oauth/token", data={
        "grant_type": "refresh_token", "refresh_token": tok["refresh_token"]},
        headers=_basic(cid, secret))
    assert reuse.status_code == 400  # rotated refresh cannot be replayed


def test_pkce_mismatch_is_rejected(client):
    data = _make_client(client)
    cid, secret = data["client_id"], data["client_secret"]
    _, challenge = _pkce()
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": cid,
        "redirect_uri": "https://portal.example.test/callback",
        "scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256"})
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    bad = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "https://portal.example.test/callback",
        "code_verifier": "the-wrong-verifier"}, headers=_basic(cid, secret))
    assert bad.status_code == 400


def test_authorize_rejects_unregistered_redirect_uri(client):
    data = _make_client(client)
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": data["client_id"],
        "redirect_uri": "https://evil.example.test/steal", "scope": "openid",
        "code_challenge": _pkce()[1]})
    assert r.status_code == 400  # must NOT redirect to an unregistered URI


def test_client_credentials_grant(client):
    data = _make_client(client, name="Service", grant_types=["client_credentials"],
                        redirect_uris=[], scopes=["roles"])
    cid, secret = data["client_id"], data["client_secret"]
    r = client.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "roles"},
                    headers=_basic(cid, secret))
    assert r.status_code == 200, r.text
    tok = r.json()
    assert tok["access_token"] and "refresh_token" not in tok and "id_token" not in tok
    # sub is the client itself (a service identity), scoped to its tenant
    jwk = client.get("/oauth/jwks.json").json()["keys"][0]
    claims = jwt.decode(tok["access_token"], jwt.algorithms.RSAAlgorithm.from_jwk(jwk),
                        algorithms=["RS256"], issuer=ISS, options={"verify_aud": False})
    assert claims["sub"] == cid and claims["tenant"] == TENANT


def test_public_client_requires_pkce(client):
    data = _make_client(client, name="SPA", token_endpoint_auth_method="none",
                        grant_types=["authorization_code"])
    # no code_challenge → redirected back with an error, no code issued
    r = client.get("/oauth/authorize", params={
        "response_type": "code", "client_id": data["client_id"],
        "redirect_uri": "https://portal.example.test/callback", "scope": "openid"})
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q.get("error") == ["invalid_request"] and "code" not in q


# ------------------------------ consent flow --------------------------------
def _authz_body(cid, challenge, **over):
    body = {"response_type": "code", "client_id": cid,
            "redirect_uri": "https://portal.example.test/callback",
            "scope": "openid profile email", "state": "st-1", "nonce": "n-1",
            "code_challenge": challenge, "code_challenge_method": "S256"}
    body.update(over)
    return body


def test_prepare_trusted_client_issues_code_without_consent(client):
    data = _make_client(client, trusted=True)
    _, ch = _pkce()
    r = client.post("/oauth/authorize/prepare", json=_authz_body(data["client_id"], ch))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"] == "redirect"
    q = parse_qs(urlparse(body["url"]).query)
    assert "code" in q and q["state"] == ["st-1"]


def test_prepare_untrusted_client_asks_for_consent(client):
    data = _make_client(client, name="Third Party", trusted=False)
    _, ch = _pkce()
    r = client.post("/oauth/authorize/prepare", json=_authz_body(data["client_id"], ch))
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "consent"
    assert body["client_name"] == "Third Party"
    assert set(body["scopes"]) == {"openid", "profile", "email"}


def test_decision_deny_redirects_access_denied(client):
    data = _make_client(client, trusted=False)
    _, ch = _pkce()
    r = client.post("/oauth/authorize/decision",
                    json={**_authz_body(data["client_id"], ch), "approved": False})
    q = parse_qs(urlparse(r.json()["url"]).query)
    assert q["error"] == ["access_denied"] and q["state"] == ["st-1"] and "code" not in q


def test_decision_approve_issues_code_exchangeable_at_token(client):
    data = _make_client(client, trusted=False)
    cid, secret = data["client_id"], data["client_secret"]
    verifier, ch = _pkce()
    r = client.post("/oauth/authorize/decision",
                    json={**_authz_body(cid, ch), "approved": True})
    code = parse_qs(urlparse(r.json()["url"]).query)["code"][0]
    tok = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": "https://portal.example.test/callback",
        "code_verifier": verifier}, headers=_basic(cid, secret))
    assert tok.status_code == 200 and tok.json()["access_token"] and tok.json()["id_token"]


def test_remembered_consent_skips_the_next_prompt(client):
    data = _make_client(client, trusted=False)
    cid = data["client_id"]
    _, ch = _pkce()
    # deny-less approve with remember → grant recorded
    d = client.post("/oauth/authorize/decision",
                    json={**_authz_body(cid, ch), "approved": True, "remember": True})
    assert d.json()["action"] == "redirect"
    # a subsequent prepare for the same client+scopes auto-redirects (no consent)
    _, ch2 = _pkce()
    p = client.post("/oauth/authorize/prepare", json=_authz_body(cid, ch2))
    assert p.json()["action"] == "redirect" and "code" in parse_qs(urlparse(p.json()["url"]).query)
    # asking for a NEW scope not previously consented re-prompts
    _, ch3 = _pkce()
    p2 = client.post("/oauth/authorize/prepare",
                     json=_authz_body(cid, ch3, scope="openid roles"))
    assert p2.json()["action"] == "consent"


def test_prepare_error_for_unsupported_response_type(client):
    data = _make_client(client, trusted=False)
    _, ch = _pkce()
    r = client.post("/oauth/authorize/prepare",
                    json=_authz_body(data["client_id"], ch, response_type="token"))
    assert r.json()["action"] == "error"
    assert parse_qs(urlparse(r.json()["url"]).query)["error"] == ["unsupported_response_type"]
