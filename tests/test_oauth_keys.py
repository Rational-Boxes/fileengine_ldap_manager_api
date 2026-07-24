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

"""Unit tests for the OAuth RSA signing keys + JWKS (offline)."""
import base64

import jwt

from ldap_manager.oauth_keys import OAuthKeys


def _rsa_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode()


def test_ephemeral_key_when_unset_is_flagged():
    keys = OAuthKeys("")
    assert keys.ephemeral is True
    assert keys.kid and len(keys.kid) == 16
    assert keys.alg == "RS256"


def test_configured_key_is_not_ephemeral_and_kid_is_stable():
    pem = _rsa_pem()
    a, b = OAuthKeys(pem), OAuthKeys(pem)
    assert a.ephemeral is False
    # same key material → same kid (clients cache by kid)
    assert a.kid == b.kid


def test_jwks_shape_and_signature_verification():
    pem = _rsa_pem()
    keys = OAuthKeys(pem)
    jwks = keys.jwks()
    assert list(jwks.keys()) == ["keys"] and len(jwks["keys"]) == 1
    jwk = jwks["keys"][0]
    assert jwk["kty"] == "RSA" and jwk["use"] == "sig" and jwk["alg"] == "RS256"
    assert jwk["kid"] == keys.kid and jwk["n"] and jwk["e"]
    # base64url, no padding
    assert "=" not in jwk["n"] and "=" not in jwk["e"]

    # A token signed with the private key verifies against the JWK's public numbers.
    token = jwt.encode({"hello": "world"}, keys.private_pem(), algorithm="RS256",
                       headers={"kid": keys.kid})
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    assert claims["hello"] == "world"
    # header carries our kid so a client can select the right JWK
    assert jwt.get_unverified_header(token)["kid"] == keys.kid


def test_b64url_uint_roundtrips_public_exponent():
    keys = OAuthKeys(_rsa_pem())
    e = keys.public_jwk()["e"]
    raw = base64.urlsafe_b64decode(e + "=" * (-len(e) % 4))
    assert int.from_bytes(raw, "big") == 65537
