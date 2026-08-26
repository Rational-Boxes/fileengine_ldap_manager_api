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

"""A single-use token must survive an attempt that FAILED.

Both flows consumed the token before doing the work, so any failure afterwards
destroyed it: the user got an error, retried, and was told the link was invalid
seconds after it had worked. In production this turned one transient 502 into a
permanently dead invitation.
"""
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ldap_manager.deps import services
from ldap_manager.routers import public_auth
from ldap_manager import tokens as tok

GOOD = "Str0ng-Passw0rd!9x"


class FakeTokens:
    """Redis-backed store, reduced to the two behaviours that matter here."""

    def __init__(self):
        self.store = {("invite", "t-ok"): "ada@x.com", ("reset", "r-ok"): "ada@x.com"}
        self.enabled = True

    def peek(self, kind, token):
        return self.store.get((kind, token))

    def consume(self, kind, token):
        return self.store.pop((kind, token), None)

    def revoke_all_for(self, uid):
        for k in [k for k, v in self.store.items() if v == uid]:
            self.store.pop(k)

    def rate_ok(self, *a, **k):
        return True


class FakePolicy:
    def __init__(self):
        self.accept = True

    def validate(self, password, uid=None):
        ok = self.accept
        return type("R", (), {"ok": ok, "unmet": [] if ok else ["too short"]})()

    def describe(self):
        return {}


class FakeLdap:
    def __init__(self):
        self.fail = None
        self.passwords = {}

    def set_password(self, uid, password):
        if self.fail:
            raise self.fail
        self.passwords[uid] = password

    def get_user(self, uid):
        return {"uid": uid, "display_name": "Ada"}


class FakeAudit:
    def __init__(self):
        self.events = []

    def emit(self, **kw):
        self.events.append(kw)
        return True


@pytest.fixture
def svc():
    return type("S", (), {
        "tokens": FakeTokens(), "policy": FakePolicy(), "ldap": FakeLdap(),
        "audit": FakeAudit(), "settings": type("Cfg", (), {})(),
        "mailer": type("M", (), {"enabled": False})(),
    })()


@pytest.fixture
def client(svc):
    app = FastAPI()
    app.include_router(public_auth.router)
    app.dependency_overrides[services] = lambda: svc
    return TestClient(app)


def _accept(client, token="t-ok", password=GOOD):
    return client.post("/v1/invite/accept", json={"token": token, "password": password})


# ------------------------------------------------------------------ invite

def test_a_rejected_password_leaves_the_invitation_usable(svc, client):
    svc.policy.accept = False
    assert _accept(client).status_code == 422
    # The link must still work once they pick a password that passes.
    svc.policy.accept = True
    assert _accept(client).status_code == 200
    assert svc.ldap.passwords["ada@x.com"] == GOOD


def test_a_directory_failure_leaves_the_invitation_usable(svc, client):
    """The production case: the directory refused the write and the invite died
    with it."""
    svc.ldap.fail = HTTPException(status_code=500, detail="LDAP says no")
    assert _accept(client).status_code == 500
    svc.ldap.fail = None
    assert _accept(client).status_code == 200
    assert svc.ldap.passwords["ada@x.com"] == GOOD


def test_a_successful_accept_still_burns_the_token(svc, client):
    """Retryable must not mean replayable."""
    assert _accept(client).status_code == 200
    assert _accept(client).status_code == 400
    assert svc.tokens.peek("invite", "t-ok") is None


def test_an_unknown_token_is_still_rejected(client):
    assert _accept(client, token="nope").status_code == 400


# ------------------------------------------------------------------- reset

def _confirm(client, token="r-ok", password=GOOD):
    return client.post("/v1/reset/confirm", json={"token": token, "password": password})


def test_a_rejected_password_leaves_the_reset_link_usable(svc, client):
    # The likeliest failure of all: a first attempt that misses the complexity
    # policy. It used to kill the emailed link on the way out.
    svc.policy.accept = False
    assert _confirm(client).status_code == 422
    svc.policy.accept = True
    assert _confirm(client).status_code == 200


def test_a_successful_reset_still_burns_the_token(svc, client):
    assert _confirm(client).status_code == 200
    assert _confirm(client).status_code == 400
