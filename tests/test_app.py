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

"""Smoke tests: the app builds, health works, public endpoints are reachable, and
protected routes reject unauthenticated callers (SPECIFICATION.md §2, §5.4)."""
from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings


def _client() -> TestClient:
    return TestClient(create_app(Settings()))


def test_healthz():
    r = _client().get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_readyz_not_ready_without_deps():
    r = _client().get("/readyz")
    assert r.status_code == 503
    assert r.json()["ready"] is False


def test_password_policy_is_public():
    r = _client().get("/v1/password-policy")
    assert r.status_code == 200
    assert r.json()["min_length"] == 12


def test_reset_request_always_200_no_enumeration():
    # No Redis/SMTP configured → still 200 (never reveals whether the email exists).
    r = _client().post("/v1/reset/request", json={"email": "nobody@example.com"})
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_admin_and_self_routes_require_a_token():
    c = _client()
    assert c.get("/v1/me").status_code == 401
    assert c.get("/v1/admin/roles").status_code == 401
