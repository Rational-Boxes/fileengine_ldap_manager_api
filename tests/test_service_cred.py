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
    assert sc.normalize_scopes(["bcf"]) == ["bcf"]                     # BCF-API door
    assert sc.normalize_scopes(["bcf", "webdav"]) == ["webdav", "bcf"]  # stable order incl. bcf
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


def test_api_scope_is_known():
    # The REST door's scope; appended last so existing orderings are unchanged.
    assert sc.normalize_scopes(["api"]) == ["api"]
    assert sc.normalize_scopes(["api", "webdav", "mcp"]) == ["webdav", "mcp", "api"]


def test_secret_generation_tracks_the_stored_hash():
    pepper = "pepper-abc"
    old = sc.hash_secret(pepper, sc.generate_secret())
    new = sc.hash_secret(pepper, sc.generate_secret())
    assert sc.secret_generation(old) == sc.secret_generation(old)   # stable
    assert sc.secret_generation(old) != sc.secret_generation(new)   # rotation changes it
    assert len(sc.secret_generation(old)) == 16


class _FakeCursor:
    def __init__(self, row):
        self.row, self.updates = row, 0

    def execute(self, sql, params=None):
        if sql.startswith("UPDATE"):
            self.updates += 1

    def fetchone(self):
        return self.row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, cur):
        self.cur = cur

    def cursor(self):
        return self.cur

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _store_with(row):
    class S:
        service_cred_pepper = "pepper-abc"
        database_url = "postgres://unused"
    store = sc.ServiceCredentialStore(S())
    cur = _FakeCursor(row)
    store._connect = lambda: _FakeConn(cur)
    return store, cur


def test_status_and_authenticate_share_one_rule():
    secret = sc.generate_secret()
    blob = sc.hash_secret("pepper-abc", secret)
    gen = sc.secret_generation(blob)
    store, cur = _store_with(("alice", blob, ["api"], []))
    assert store.authenticate(key_id="k", secret=secret, tenant="t", scope="api") == ("alice", gen)
    assert store.authenticate(key_id="k", secret=secret + "x", tenant="t", scope="api") is None
    # status needs no secret, and agrees on the generation
    assert store.status(key_id="k", tenant="t", scope="api") == ("alice", gen)
    # a key not scoped to the REST door is refused by both
    assert store.status(key_id="k", tenant="t", scope="webdav") is None
    assert store.verify(key_id="k", secret=secret, tenant="t", scope="mcp") is None


def test_status_refuses_a_missing_or_pinned_out_key():
    blob = sc.hash_secret("pepper-abc", sc.generate_secret())
    store, _ = _store_with(None)                     # revoked / expired / other tenant
    assert store.status(key_id="k", tenant="t", scope="api") is None
    store, _ = _store_with(("alice", blob, ["api"], ["10.0.0.0/8"]))
    assert store.status(key_id="k", tenant="t", scope="api", source_ip="192.0.2.1") is None
    assert store.status(key_id="k", tenant="t", scope="api", source_ip="10.1.2.3") is not None
