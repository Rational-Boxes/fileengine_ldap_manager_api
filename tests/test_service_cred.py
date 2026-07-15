"""Unit tests for the service-credential crypto/logic core (offline — no DB).

Covers key/secret generation + prefixes, scope normalization, the HMAC-with-pepper
hash + constant-time verify round-trip, and the optional per-key IP allowlist.
The Postgres-backed store is exercised by the integration/E2E suite.
"""
import pytest

from ldap_manager import service_cred as sc


def test_generated_key_and_secret_shapes():
    key_id = sc.generate_key_id()
    secret = sc.generate_secret()
    assert key_id.startswith("fesk_") and len(key_id) > 12
    assert secret.startswith("fesks_") and len(secret) > 20
    # two calls never collide
    assert sc.generate_secret() != secret and sc.generate_key_id() != key_id


def test_normalize_scopes():
    assert sc.normalize_scopes(None) == ["webdav"]
    assert sc.normalize_scopes([]) == ["webdav"]                       # empty → default
    assert sc.normalize_scopes(["MCP", "mcp"]) == ["mcp"]              # lower-case + dedup
    assert sc.normalize_scopes(["mcp", "webdav"]) == ["webdav", "mcp"]  # stable order
    assert sc.normalize_scopes(["bogus"]) == ["webdav"]               # drop unknown → default


def test_hash_and_verify_roundtrip():
    pepper = "pepper-abc"
    secret = sc.generate_secret()
    blob = sc.hash_secret(pepper, secret)
    assert isinstance(blob, bytes) and len(blob) == 32       # SHA-256 digest
    assert sc.secret_matches(pepper, secret, blob)
    assert not sc.secret_matches(pepper, secret + "x", blob)  # wrong secret
    assert not sc.secret_matches("other-pepper", secret, blob)  # wrong pepper


def test_hash_requires_pepper():
    with pytest.raises(RuntimeError):
        sc.hash_secret("", "some-secret")


def test_ip_in_cidrs():
    assert sc._ip_in_cidrs("10.0.0.5", ["10.0.0.0/24"])
    assert sc._ip_in_cidrs("192.168.1.9", ["10.0.0.0/8", "192.168.1.0/24"])
    assert not sc._ip_in_cidrs("10.0.1.5", ["10.0.0.0/24"])
    assert not sc._ip_in_cidrs(None, ["10.0.0.0/24"])       # missing IP → fail-closed
    assert not sc._ip_in_cidrs("10.0.0.5", ["garbage"])     # unparseable entry ignored
