"""Unit tests for OAuth access-token / OIDC ID-token issuance + verification."""
import time

import jwt

from ldap_manager import oauth_tokens as ot
from ldap_manager.oauth_keys import OAuthKeys

ISS = "https://files.example.com/ldapadmin"


def _keys():
    return OAuthKeys("")  # ephemeral is fine for a unit test


def test_access_token_roundtrips_and_carries_binding():
    keys = _keys()
    tok = ot.issue_access_token(keys, issuer=ISS, subject="alice@x", tenant="acme",
                                client_id="feoc_1", scope="openid profile", ttl=3600)
    claims = ot.verify_token(keys, tok, issuer=ISS, token_use="access")
    assert claims is not None
    assert claims["sub"] == "alice@x" and claims["tenant"] == "acme"
    assert claims["client_id"] == "feoc_1" and claims["token_use"] == "access"
    assert "jti" in claims


def test_access_token_roles_only_when_scope_present():
    keys = _keys()
    without = ot.verify_token(keys, ot.issue_access_token(
        keys, issuer=ISS, subject="a", tenant="t", client_id="c", scope="openid",
        ttl=60, roles=["administrators"]), issuer=ISS)
    assert "roles" not in without
    with_roles = ot.verify_token(keys, ot.issue_access_token(
        keys, issuer=ISS, subject="a", tenant="t", client_id="c", scope="openid roles",
        ttl=60, roles=["administrators"]), issuer=ISS)
    assert with_roles["roles"] == ["administrators"]


def test_id_token_audience_is_client_and_claims_gated_by_scope():
    keys = _keys()
    tok = ot.issue_id_token(keys, issuer=ISS, subject="alice@x", tenant="acme",
                            client_id="feoc_1", ttl=3600, nonce="n-123",
                            email="alice@x", name="Alice X", scope="openid email profile")
    # aud must equal the client_id for an ID token
    claims = ot.verify_token(keys, tok, issuer=ISS, audience="feoc_1", token_use="id")
    assert claims["sub"] == "alice@x" and claims["aud"] == "feoc_1"
    assert claims["nonce"] == "n-123" and claims["email"] == "alice@x"
    assert claims["name"] == "Alice X" and claims["auth_time"]


def test_id_token_omits_email_without_email_scope():
    keys = _keys()
    tok = ot.issue_id_token(keys, issuer=ISS, subject="a", tenant="t", client_id="c",
                            ttl=60, email="a@x", name="A", scope="openid")
    claims = ot.verify_token(keys, tok, issuer=ISS, audience="c", token_use="id")
    assert "email" not in claims and "name" not in claims


def test_verify_rejects_wrong_issuer_audience_and_use():
    keys = _keys()
    tok = ot.issue_id_token(keys, issuer=ISS, subject="a", tenant="t", client_id="c",
                            ttl=60, scope="openid")
    assert ot.verify_token(keys, tok, issuer="https://evil", audience="c") is None
    assert ot.verify_token(keys, tok, issuer=ISS, audience="other") is None
    assert ot.verify_token(keys, tok, issuer=ISS, audience="c", token_use="access") is None


def test_verify_rejects_expired_and_tampered():
    keys = _keys()
    # Hand-craft a token whose exp is already in the past (issue_* clamps ttl>=1).
    now = int(time.time())
    expired = jwt.encode(
        {"iss": ISS, "sub": "a", "tenant": "t", "iat": now - 120, "exp": now - 60},
        keys.private_pem(), algorithm="RS256", headers={"kid": keys.kid})
    assert ot.verify_token(keys, expired, issuer=ISS) is None
    good = ot.issue_access_token(keys, issuer=ISS, subject="a", tenant="t",
                                 client_id="c", scope="openid", ttl=60)
    assert ot.verify_token(keys, good + "x", issuer=ISS) is None


def test_tokens_are_verifiable_by_a_third_party_via_jwks():
    """A relying party with only the JWKS (no shared secret) can verify — the point
    of an asymmetric authority."""
    keys = _keys()
    tok = ot.issue_id_token(keys, issuer=ISS, subject="a", tenant="t", client_id="c",
                            ttl=60, scope="openid")
    jwk = keys.jwks()["keys"][0]
    pub = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    claims = jwt.decode(tok, pub, algorithms=["RS256"], audience="c", issuer=ISS)
    assert claims["sub"] == "a"
