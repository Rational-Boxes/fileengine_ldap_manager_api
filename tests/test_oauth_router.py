"""Router-level tests for the OAuth authority that need no DB/Redis (TestClient).

Covers discovery + JWKS shape, the enabled/disabled guards, and the unauthenticated
rejections. The full authorize→token→userinfo flow is in test_oauth_e2e (live)."""
import jwt
from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings

ISS = "https://files.example.com/ldapadmin"


def _client(**over):
    s = Settings(oauth_enabled=over.pop("enabled", True), oauth_issuer=over.pop("issuer", ISS), **over)
    return TestClient(create_app(s))


def test_discovery_document_is_well_formed():
    d = _client().get("/.well-known/openid-configuration").json()
    assert d["issuer"] == ISS
    assert d["authorization_endpoint"] == f"{ISS}/oauth/authorize"
    assert d["token_endpoint"] == f"{ISS}/oauth/token"
    assert d["jwks_uri"] == f"{ISS}/oauth/jwks.json"
    assert d["id_token_signing_alg_values_supported"] == ["RS256"]
    assert "authorization_code" in d["grant_types_supported"]
    assert "client_credentials" in d["grant_types_supported"]
    assert "S256" in d["code_challenge_methods_supported"]
    assert "openid" in d["scopes_supported"]


def test_jwks_is_usable_by_pyjwt():
    j = _client().get("/oauth/jwks.json").json()
    jwk = j["keys"][0]
    assert jwk["kty"] == "RSA" and jwk["use"] == "sig"
    # PyJWT can build a public key from the published JWK (a relying party's path)
    assert jwt.algorithms.RSAAlgorithm.from_jwk(jwk) is not None


def test_disabled_authority_hides_all_endpoints():
    c = _client(enabled=False)
    assert c.get("/.well-known/openid-configuration").status_code == 404
    assert c.get("/oauth/jwks.json").status_code == 404
    assert c.get("/oauth/userinfo", headers={"Authorization": "Bearer x"}).status_code == 404
    assert c.post("/oauth/token", data={"grant_type": "client_credentials"}).status_code == 404


def test_enabled_without_issuer_is_503():
    c = _client(issuer="")
    assert c.get("/.well-known/openid-configuration").status_code == 503


def test_userinfo_requires_bearer():
    c = _client()
    assert c.get("/oauth/userinfo").status_code == 401
    assert c.get("/oauth/userinfo", headers={"Authorization": "Basic x"}).status_code == 401
    # a syntactically-bearer but bogus token is rejected as invalid
    assert c.get("/oauth/userinfo", headers={"Authorization": "Bearer notatoken"}).status_code == 401


def test_admin_registry_requires_auth():
    c = _client()
    assert c.get("/v1/admin/oauth-clients").status_code == 401
    assert c.post("/v1/admin/oauth-clients", json={"name": "x"}).status_code == 401


def test_authorize_and_token_503_without_stores():
    # Enabled authority but no DATABASE_URL/REDIS_URL → a clean 503 (never a 500).
    c = _client()
    assert c.post("/oauth/token", data={"grant_type": "client_credentials",
                                        "client_id": "x"}).status_code == 503
    assert c.get("/oauth/authorize", params={"response_type": "code", "client_id": "x",
                                             "redirect_uri": "https://a/b"},
                 headers={"Authorization": "Bearer t"}).status_code in (401, 503)
