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

"""The welcome mail a newly provisioned tenant's administrator receives."""
from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings
from ldap_manager.deps import services

SECRET = "internal-secret"


class _Mailer:
    enabled = True

    def __init__(self, fail: bool = False):
        self.sent: list[tuple[str, str, str]] = []
        self.fail = fail

    def send(self, to, subject, html_body):
        if self.fail:
            raise RuntimeError("550 relay denied")
        self.sent.append((to, subject, html_body))


class _Tokens:
    enabled = True

    def __init__(self):
        self.issued: list[tuple] = []

    def issue(self, kind, subject, ttl):
        self.issued.append((kind, subject, ttl))
        return "tok-123"


def _client(user, *, mailer=None, secret=SECRET, reset_base="https://login.example.com/reset-password"):
    mailer = mailer or _Mailer()
    tokens = _Tokens()
    settings = Settings()
    settings.mfa_internal_secret = secret
    settings.reset_link_base = reset_base
    settings.welcome_reset_ttl_hours = 72
    audits: list[dict] = []
    svc = SimpleNamespace(settings=settings, ldap=SimpleNamespace(get_user=lambda q: user),
                          tokens=tokens, mailer=mailer,
                          audit=SimpleNamespace(emit=lambda **kw: audits.append(kw)))
    app = create_app(Settings())
    app.dependency_overrides[services] = lambda: svc
    return TestClient(app), mailer, tokens, audits


JAMES = {"uid": "james", "email": "james@rationalboxes.com", "display_name": "James"}
BODY = {"email": "james@rationalboxes.com", "sign_in_url": "https://acme.example.com/",
        "drive_host": "acme-drive.example.com", "tenant_name": "Acme"}
H = {"X-Internal-Auth": SECRET}


def test_sends_to_the_mail_attribute_with_a_reset_link_against_the_uid():
    c, mailer, tokens, audits = _client(JAMES)
    r = c.post("/internal/tenants/acme/welcome", json=BODY, headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["sent"] is True
    to, subject, body = mailer.sent[0]
    assert to == "james@rationalboxes.com"
    assert "Acme" in subject
    assert "https://login.example.com/reset-password?token=tok-123" in body
    assert "https://acme.example.com/" in body and "acme-drive.example.com" in body
    assert "72h" in body
    assert tokens.issued == [("reset", "james", 72 * 3600)]
    assert audits and audits[-1]["outcome"] == "ok"


def test_no_placeholder_is_left_unrendered():
    c, mailer, _, _ = _client(JAMES)
    c.post("/internal/tenants/acme/welcome", json=BODY, headers=H)
    _, subject, body = mailer.sent[0]
    assert "{{" not in subject and "{{" not in body


def test_refused_without_the_internal_secret():
    c, mailer, _, _ = _client(JAMES)
    assert c.post("/internal/tenants/acme/welcome", json=BODY).status_code == 403
    assert c.post("/internal/tenants/acme/welcome", json=BODY,
                  headers={"X-Internal-Auth": "wrong"}).status_code == 403
    assert mailer.sent == []


def test_absent_when_no_secret_is_configured():
    c, _, _, _ = _client(JAMES, secret="")
    assert c.post("/internal/tenants/acme/welcome", json=BODY, headers=H).status_code == 404


def test_unknown_account_is_a_truthful_404_not_a_silent_200():
    c, mailer, tokens, _ = _client(None)
    r = c.post("/internal/tenants/acme/welcome", json=BODY, headers=H)
    assert r.status_code == 404
    assert mailer.sent == [] and tokens.issued == []


def test_unconfigured_reset_page_is_reported_by_name():
    c, mailer, _, _ = _client(JAMES, reset_base="")
    r = c.post("/internal/tenants/acme/welcome", json=BODY, headers=H)
    assert r.status_code == 503 and "RESET_LINK_BASE" in r.json()["detail"]
    assert mailer.sent == []


def test_a_refused_send_is_a_failure_not_a_success():
    c, _, _, audits = _client(JAMES, mailer=_Mailer(fail=True))
    r = c.post("/internal/tenants/acme/welcome", json=BODY, headers=H)
    assert r.status_code == 502
    assert audits[-1]["outcome"] == "error"
