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

"""Recipient OTP for outside share links (share_service spec §6.9, M3).

Against live Redis. The interesting cases are not "does a code verify" but the
four the design turns on: the attempt budget survives a resend, a timing trip
counts heavily while responding identically, an SMTP failure is reported rather
than swallowed, and the send limits actually bind.
"""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import load_settings
from ldap_manager.routers import share_otp

_settings = load_settings()

pytestmark = pytest.mark.skipif(
    not _settings.redis_url, reason="live REDIS_URL required")

TENANT = "acme"
INTERNAL_SECRET = "test-share-internal-secret"


class _Mailer:
    """Captures sends; can be told to fail, to exercise the SMTP path."""

    def __init__(self):
        self.sent = []
        self.fail = False

    def send(self, to, subject, body):
        if self.fail:
            raise RuntimeError("smtp refused")
        self.sent.append({"to": to, "subject": subject, "body": body})

    def last_code(self) -> str:
        import re
        m = re.search(r"<strong>(\d{6})</strong>", self.sent[-1]["body"])
        assert m, f"no code in body: {self.sent[-1]['body'][:200]}"
        return m.group(1)


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("SHARE_INTERNAL_SECRET", INTERNAL_SECRET)
    # Tight windows so the limits are observable inside one test run.
    monkeypatch.setenv("SHARE_OTP_SEND_PER_WINDOW", "3")
    monkeypatch.setenv("SHARE_OTP_MAX_ATTEMPTS", "5")
    monkeypatch.setenv("SHARE_OTP_TIMING_WEIGHT", "5")
    # Timing checks off by default here; individual tests turn them on, so the
    # ordinary cases are not fighting a 5-second floor.
    monkeypatch.setenv("SHARE_OTP_MIN_SECONDS_AFTER_SEND", "0")
    monkeypatch.setenv("SHARE_OTP_MIN_SUBMIT_INTERVAL_MS", "0")
    settings = load_settings()
    app = create_app(settings)
    mailer = _Mailer()
    app.state.services.mailer = mailer
    c = TestClient(app)
    c._mailer = mailer  # type: ignore[attr-defined]
    return c


def _hdr() -> dict:
    return {"X-Internal-Auth": INTERNAL_SECRET}


def _link() -> str:
    """A fresh link id per test — Redis buckets are shared across the suite."""
    return f"link-{uuid.uuid4().hex[:12]}"


def _challenge(c, link, email="recipient@example.com", sender="alice@acme.test"):
    return c.post("/internal/share/email-challenge", headers=_hdr(),
                  json={"link_uid": link, "email": email, "tenant": TENANT,
                        "sender": sender})


def _verify(c, link, code, email="recipient@example.com"):
    return c.post("/internal/share/email-verify", headers=_hdr(),
                  json={"link_uid": link, "email": email, "tenant": TENANT,
                        "code": code})


# --- the guard ------------------------------------------------------------

def test_internal_secret_is_required(client):
    r = client.post("/internal/share/email-challenge",
                    json={"link_uid": "x", "email": "a@b.c", "tenant": TENANT})
    assert r.status_code == 403
    r = client.post("/internal/share/email-challenge",
                    headers={"X-Internal-Auth": "wrong"},
                    json={"link_uid": "x", "email": "a@b.c", "tenant": TENANT})
    assert r.status_code == 403


# --- the happy path -------------------------------------------------------

def test_challenge_mails_a_code_and_verify_consumes_it(client):
    link = _link()
    r = _challenge(client, link)
    assert r.status_code == 200 and r.json()["sent"] is True

    code = client._mailer.last_code()
    assert _verify(client, link, code).json()["ok"] is True
    # Single-use: the same code cannot be replayed.
    assert _verify(client, link, code).json()["ok"] is False


def test_the_mail_carries_what_a_stranger_needs(client):
    """The recipient has no account and did not ask us for anything, so the copy
    has to say who it is from, when it was sent, and when it expires."""
    link = _link()
    _challenge(client, link, sender="alice@acme.test")
    msg = client._mailer.sent[-1]
    assert "alice@acme.test" in msg["subject"] or "alice@acme.test" in msg["body"]
    assert "minutes" in msg["body"]          # the deadline
    assert "newest" in msg["body"]           # which code to use after a resend
    assert "recipient@example.com" in msg["body"]


def test_a_wrong_code_does_not_consume_the_live_one(client):
    link = _link()
    _challenge(client, link)
    code = client._mailer.last_code()
    assert _verify(client, link, "000000").json()["ok"] is False
    assert _verify(client, link, code).json()["ok"] is True


def test_codes_are_scoped_to_the_link_and_the_address(client):
    a, b = _link(), _link()
    _challenge(client, a)
    code_a = client._mailer.last_code()
    _challenge(client, b)
    # A's code must not open B, nor another recipient's challenge on A.
    assert _verify(client, b, code_a).json()["ok"] is False
    assert _verify(client, a, code_a, email="someone-else@example.com").json()["ok"] is False


# --- resend: the budget must not come back with it ------------------------

def test_a_resend_replaces_the_live_code(client):
    link = _link()
    _challenge(client, link)
    first = client._mailer.last_code()
    _challenge(client, link)
    second = client._mailer.last_code()
    assert first != second
    # The delayed first mail is now useless -- which is why the template says
    # to use the newest.
    assert _verify(client, link, first).json()["ok"] is False
    assert _verify(client, link, second).json()["ok"] is True


def test_a_resend_does_not_restore_attempts(client):
    """The reason the bucket is keyed per (link, email) and not per challenge.

    Burn the budget, request a fresh code, and the *correct* code for that fresh
    challenge must still be refused — otherwise 'send another' is an unlimited
    reset on a 6-digit guessing budget.
    """
    link = _link()
    _challenge(client, link)
    for _ in range(5):
        _verify(client, link, "000000")

    _challenge(client, link)                 # a brand-new challenge
    good = client._mailer.last_code()
    r = _verify(client, link, good).json()
    assert r["ok"] is False and r["locked"] is True


# --- rung 0: timing -------------------------------------------------------

def test_submitting_before_the_mail_could_arrive_counts_heavily(client, monkeypatch):
    """A code cannot be READ before the mail carrying it is delivered, so an
    instant submission is a script. It is counted at weight, not rejected
    differently."""
    monkeypatch.setenv("SHARE_OTP_MIN_SECONDS_AFTER_SEND", "30")
    app = create_app(load_settings())
    mailer = _Mailer()
    app.state.services.mailer = mailer
    c = TestClient(app)
    link = _link()
    c.post("/internal/share/email-challenge", headers=_hdr(),
           json={"link_uid": link, "email": "r@example.com", "tenant": TENANT})

    r = c.post("/internal/share/email-verify", headers=_hdr(),
               json={"link_uid": link, "email": "r@example.com",
                     "tenant": TENANT, "code": "000000"}).json()
    assert r["timing_flag"] == "too_soon_after_send"

    # One tripped attempt at weight 5 exhausts a budget of 5, so the next
    # submission is already locked out.
    r2 = c.post("/internal/share/email-verify", headers=_hdr(),
                json={"link_uid": link, "email": "r@example.com",
                      "tenant": TENANT, "code": "111111"}).json()
    assert r2["locked"] is True


def test_a_timing_trip_answers_exactly_like_an_ordinary_wrong_code(client, monkeypatch):
    """Rejecting it differently would teach the script what to tune (spec §8.4)."""
    monkeypatch.setenv("SHARE_OTP_MIN_SECONDS_AFTER_SEND", "30")
    app = create_app(load_settings())
    app.state.services.mailer = _Mailer()
    c = TestClient(app)

    fast, slow = _link(), _link()
    for link in (fast, slow):
        c.post("/internal/share/email-challenge", headers=_hdr(),
               json={"link_uid": link, "email": "r@example.com", "tenant": TENANT})

    tripped = c.post("/internal/share/email-verify", headers=_hdr(),
                     json={"link_uid": fast, "email": "r@example.com",
                           "tenant": TENANT, "code": "000000"})
    time.sleep(0.05)
    ordinary = c.post("/internal/share/email-verify", headers=_hdr(),
                      json={"link_uid": slow, "email": "other@example.com",
                            "tenant": TENANT, "code": "000000"})
    # Same status, same ok/locked shape. `timing_flag` is for the CALLER's
    # counters and must never be relayed to the recipient.
    assert tripped.status_code == ordinary.status_code
    assert tripped.json()["ok"] == ordinary.json()["ok"] is False
    assert tripped.json()["locked"] == ordinary.json()["locked"] is False


# --- send limits and SMTP failure ----------------------------------------

def test_send_limit_binds_per_recipient(client):
    link = _link()
    for _ in range(3):
        assert _challenge(client, link).json()["sent"] is True
    r = _challenge(client, link).json()
    assert r["sent"] is False and r["error"] == "rate_limited"
    assert r["retry_after_s"] > 0


def test_smtp_failure_is_surfaced_not_swallowed(client):
    """The 2FA handler folds a send failure into sent=False and moves on. Here
    the caller must be told, so it can raise an attention item for the link's
    creator -- otherwise a mail misconfiguration is indistinguishable from a
    mistyped address and nobody finds out."""
    client._mailer.fail = True
    r = _challenge(client, _link()).json()
    assert r["sent"] is False
    assert "error" in r and "smtp refused" in r["error"]
    assert r["error"] != "rate_limited"     # distinguishable from a throttle
