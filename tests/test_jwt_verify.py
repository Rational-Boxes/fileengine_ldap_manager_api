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

"""Local HS256 JWT verification: signature, expiry, tamper + alg-confusion
rejection, and tenant-scoped role extraction from the {tenant:[roles]} claim."""
import base64
import hashlib
import hmac
import json
import time

from ldap_manager.jwt_verify import identity_from_claims, verify_hs256

SECRET = "shared-test-secret"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def mint(claims: dict, secret: str = SECRET, alg: str = "HS256") -> str:
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    sig = _b64(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def test_valid_token_verifies():
    tok = mint({"sub": "a@b", "exp": int(time.time()) + 60, "roles": {"t1": ["users"]}})
    claims = verify_hs256(tok, SECRET)
    assert claims and claims["sub"] == "a@b"


def test_wrong_secret_rejected():
    tok = mint({"sub": "a@b", "exp": int(time.time()) + 60})
    assert verify_hs256(tok, "wrong-secret") is None


def test_expired_rejected():
    tok = mint({"sub": "a@b", "exp": int(time.time()) - 1})
    assert verify_hs256(tok, SECRET) is None


def test_tampered_payload_rejected():
    tok = mint({"sub": "a@b", "exp": int(time.time()) + 60})
    h, _p, s = tok.split(".")
    forged = _b64(json.dumps({"sub": "evil", "exp": int(time.time()) + 60}).encode())
    assert verify_hs256(f"{h}.{forged}.{s}", SECRET) is None


def test_alg_none_rejected():
    # alg-confusion / "alg":"none" must never be accepted
    tok = mint({"sub": "a@b", "exp": int(time.time()) + 60}, alg="none")
    assert verify_hs256(tok, SECRET) is None


def test_malformed_rejected():
    assert verify_hs256("not-a-jwt", SECRET) is None
    assert verify_hs256("", SECRET) is None


def test_identity_is_tenant_scoped():
    claims = {"sub": "a@b", "tenant": "t1",
              "roles": {"t1": ["users", "administrators"], "t2": ["users"]}}
    assert identity_from_claims(claims, "t1") == ("a@b", ["users", "administrators"])
    assert identity_from_claims(claims, "t2") == ("a@b", ["users"])
    # t3 is absent from the map, so the token does not attest membership of it.
    # This used to answer ("a@b", []) — an authenticated caller in a tenant they
    # are not a member of. Membership IS the presence of the key.
    assert identity_from_claims(claims, "t3") is None
    assert identity_from_claims(claims, "") == ("a@b", ["users", "administrators"])  # falls back to token tenant


def test_a_token_is_refused_for_a_tenant_it_does_not_attest():
    """The membership rule this service applies everywhere else, on the token path.

    Every directory operation here already runs against `tenant_dn(tenant)`;
    the token helper was the one path that resolved a non-member to an empty
    role list instead of refusing.
    """
    claims = {"sub": "a@b", "tenant": "alpha", "roles": {"alpha": ["users"]}}
    assert identity_from_claims(claims, "alpha") == ("a@b", ["users"])
    assert identity_from_claims(claims, "beta") is None


def test_membership_with_no_roles_is_still_membership():
    claims = {"sub": "a@b", "tenant": "alpha", "roles": {"alpha": []}}
    assert identity_from_claims(claims, "alpha") == ("a@b", [])


def test_non_bridge_tokens_are_left_alone():
    assert identity_from_claims({"sub": "svc"}, "alpha") == ("svc", [])
