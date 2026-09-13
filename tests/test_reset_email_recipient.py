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

"""Where a password-reset email is actually addressed (§5.2).

Every account created through this service has uid == mail, so addressing the
uid worked for all of them and the bug was invisible. The platform's original
administrator is the one account where they differ — uid=james,
mail=james@rationalboxes.com — and that reset was handed to SMTP with "james" as
the recipient. It never arrived, and the endpoint reported success, because the
whole block is wrapped in a swallowing except that exists to prevent account
enumeration.
"""
from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings
from ldap_manager.deps import services


class _Mailer:
    enabled = True

    def __init__(self):
        self.sent: list[tuple[str, str, str]] = []

    def send(self, to, subject, html_body):
        self.sent.append((to, subject, html_body))


class _Tokens:
    enabled = True

    def __init__(self):
        self.issued: list[tuple] = []

    def rate_ok(self, *a, **k):
        return True

    def issue(self, kind, subject, ttl):
        self.issued.append((kind, subject, ttl))
        return "tok-123"


def _app(user: dict | None, mailer=None, tokens=None):
    """An app whose directory returns exactly `user` and whose mailer records."""
    mailer = mailer or _Mailer()
    tokens = tokens or _Tokens()
    settings = Settings()
    settings.reset_link_base = "https://login.example.com/reset-password"
    svc = SimpleNamespace(
        settings=settings,
        ldap=SimpleNamespace(get_user=lambda q: user),
        tokens=tokens,
        mailer=mailer,
        audit=SimpleNamespace(emit=lambda **kw: None),
    )
    app = create_app(Settings())
    app.dependency_overrides[services] = lambda: svc
    return TestClient(app), mailer, tokens


JAMES = {"uid": "james", "email": "james@rationalboxes.com", "display_name": "James"}
NORMAL = {"uid": "jo@example.com", "email": "jo@example.com", "display_name": "Jo"}


def test_email_goes_to_the_mail_attribute_when_it_differs_from_the_uid():
    """The reported failure, directly: the message must be addressed to
    james@rationalboxes.com and never to the bare uid `james`, which no MTA can
    deliver."""
    client, mailer, _ = _app(JAMES)
    r = client.post("/v1/reset/request", json={"email": "james@rationalboxes.com"})
    assert r.status_code == 200
    assert len(mailer.sent) == 1
    to, _subject, _body = mailer.sent[0]
    assert to == "james@rationalboxes.com"
    assert to != "james"


def test_the_body_renders_the_address_for_a_customized_template(monkeypatch):
    """`email` is a DECLARED placeholder for this template (templates.py), even
    though the stock body does not use it — so the first operator to customize
    the body would have had it render the uid. The context has to carry the
    address for the same reason the envelope does.
    """
    from ldap_manager import templates as tmpl_mod
    stock = tmpl_mod.DEFAULTS[tmpl_mod.PASSWORD_RESET]
    customized = type(stock)(subject=stock.subject,
                             body="Hello {{display_name}}, your address is {{email}}. {{reset_link}}")
    monkeypatch.setitem(tmpl_mod.DEFAULTS, tmpl_mod.PASSWORD_RESET, customized)

    client, mailer, _ = _app(JAMES)
    client.post("/v1/reset/request", json={"email": "james@rationalboxes.com"})
    _to, _subject, body = mailer.sent[0]
    assert "james@rationalboxes.com" in body
    assert "your address is james." not in body, "the uid must not be presented as the address"


def test_the_token_is_still_issued_against_the_uid():
    """Only the DELIVERY address changes. The reset token is the directory key
    /reset/confirm sets the password by, so it must stay the uid — getting this
    backwards would send a deliverable email carrying a token that resolves to
    nobody."""
    client, mailer, tokens = _app(JAMES)
    client.post("/v1/reset/request", json={"email": "james@rationalboxes.com"})
    assert tokens.issued[0][1] == "james"


def test_uid_is_used_when_the_entry_has_no_mail_attribute():
    """_to_user falls back to the uid when mail is absent, and for every account
    this service creates the uid IS the address — so the ordinary path must not
    regress."""
    client, mailer, _ = _app({"uid": "jo@example.com", "email": "", "display_name": "Jo"})
    client.post("/v1/reset/request", json={"email": "jo@example.com"})
    assert mailer.sent[0][0] == "jo@example.com"


def test_the_ordinary_account_is_unaffected():
    client, mailer, _ = _app(NORMAL)
    client.post("/v1/reset/request", json={"email": "jo@example.com"})
    assert mailer.sent[0][0] == "jo@example.com"


def test_an_unknown_address_sends_nothing_and_still_returns_200():
    """No account enumeration: the response must not distinguish."""
    client, mailer, _ = _app(None)
    r = client.post("/v1/reset/request", json={"email": "nobody@example.com"})
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert mailer.sent == []


def test_a_failing_mailer_still_returns_200_but_is_logged(caplog):
    """The silence is what hid this for a week. The response must stay constant,
    and the server must say what happened."""
    class Broken(_Mailer):
        def send(self, to, subject, html_body):
            raise RuntimeError("SES rejected the recipient")

    client, _mailer, _ = _app(JAMES, mailer=Broken())
    with caplog.at_level("ERROR"):
        r = client.post("/v1/reset/request", json={"email": "james@rationalboxes.com"})
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert any("could not be completed" in rec.message for rec in caplog.records), \
        "a reset that fails must not fail silently"
