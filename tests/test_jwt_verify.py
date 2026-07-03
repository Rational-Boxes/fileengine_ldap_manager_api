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
    assert identity_from_claims(claims, "t3") == ("a@b", [])          # unknown tenant → no roles
    assert identity_from_claims(claims, "") == ("a@b", ["users", "administrators"])  # falls back to token tenant
