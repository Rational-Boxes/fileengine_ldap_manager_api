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

"""The internal service-credential API the REST door relies on (offline).

``/internal/service-cred/verify`` signs a key in and now also returns the
secret's ``generation``; ``/internal/service-cred/status`` answers the REST
door's refresh without the secret. The store runs its real SQL-free logic over a
one-row fake connection, so these pin the HTTP contract the bridge reads:
200 + uid + generation, 401 for a credential that is no good, 403 for a caller
without the internal secret. The live round trip is
http_bridge/tests/test_e2e_api_key.sh.
"""
from fastapi.testclient import TestClient

from ldap_manager import service_cred as sc
from ldap_manager.app import create_app
from ldap_manager.config import Settings

PEPPER = "pepper-abc"
INTERNAL = "internal-secret"


class _Cursor:
    def __init__(self, box):
        self.box = box

    def execute(self, sql, params=None):
        self.box["last_sql"] = sql

    def fetchone(self):
        return self.box["row"]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Conn:
    def __init__(self, box):
        self.box = box

    def cursor(self):
        return _Cursor(self.box)

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _client(row):
    app = create_app(Settings(service_cred_pepper=PEPPER, service_cred_internal_secret=INTERNAL))
    store = app.state.services.service_cred
    box = {"row": row}
    store.enabled = lambda: True
    store._connect = lambda: _Conn(box)
    return TestClient(app), box


def _row(secret, scopes=("api",), cidrs=()):
    return ("alice", sc.hash_secret(PEPPER, secret), list(scopes), list(cidrs))


H = {"X-Internal-Auth": INTERNAL}
BODY = {"key_id": "fesk_k", "tenant": "default", "scope": "api"}


def test_verify_returns_uid_and_generation():
    secret = sc.generate_secret()
    c, box = _client(_row(secret))
    r = c.post("/internal/service-cred/verify", json={**BODY, "secret": secret}, headers=H)
    assert r.status_code == 200
    out = r.json()
    assert out["uid"] == "alice" and out["tenant"] == "default"
    assert out["generation"] == sc.secret_generation(box["row"][1])


def test_verify_refuses_a_wrong_or_empty_secret():
    secret = sc.generate_secret()
    c, _ = _client(_row(secret))
    for bad in (secret + "x", ""):
        r = c.post("/internal/service-cred/verify", json={**BODY, "secret": bad}, headers=H)
        assert r.status_code == 401, bad


def test_status_needs_no_secret_and_agrees_on_generation():
    secret = sc.generate_secret()
    c, _ = _client(_row(secret))
    v = c.post("/internal/service-cred/verify", json={**BODY, "secret": secret}, headers=H).json()
    s = c.post("/internal/service-cred/status", json=BODY, headers=H)
    assert s.status_code == 200
    assert s.json() == {"uid": "alice", "tenant": "default", "generation": v["generation"]}


def test_status_generation_moves_when_the_secret_is_regenerated():
    c, box = _client(_row(sc.generate_secret()))
    before = c.post("/internal/service-cred/status", json=BODY, headers=H).json()["generation"]
    box["row"] = _row(sc.generate_secret())          # rotate in place: same key_id, new hash
    after = c.post("/internal/service-cred/status", json=BODY, headers=H).json()["generation"]
    assert before != after


def test_status_401s_for_a_dead_or_wrong_scope_key():
    c, box = _client(None)                           # revoked / expired / other tenant
    assert c.post("/internal/service-cred/status", json=BODY, headers=H).status_code == 401
    box["row"] = _row(sc.generate_secret(), scopes=("webdav", "mcp"))
    assert c.post("/internal/service-cred/status", json=BODY, headers=H).status_code == 401
    box["row"] = _row(sc.generate_secret(), cidrs=("10.0.0.0/8",))
    r = c.post("/internal/service-cred/status", json={**BODY, "source_ip": "192.0.2.7"}, headers=H)
    assert r.status_code == 401


def test_internal_api_refuses_callers_without_the_internal_secret():
    c, _ = _client(_row(sc.generate_secret()))
    for path in ("/internal/service-cred/status", "/internal/service-cred/verify"):
        body = BODY if path.endswith("status") else {**BODY, "secret": "x"}
        assert c.post(path, json=body).status_code == 403
        assert c.post(path, json=body, headers={"X-Internal-Auth": "nope"}).status_code == 403
