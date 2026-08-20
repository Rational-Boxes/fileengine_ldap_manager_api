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

"""The share-link OTP seam (OUTSIDE_SHARE_LINKS §6.9, §8.4).

Rungs 0 and 1 of the abuse escalation live here, because this service owns the
code. Rung 2 — the per-link lockout — lives in share_service, which owns the
link.

The property most of these tests defend is **uniformity**: everything about a
verification attempt is reachable by anyone holding the URL, so a timing trip, a
wrong code and an unlisted address must be indistinguishable in the response.
The timing signal is real and is counted; it just never shows.
"""
from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ldap_manager.deps import services
from ldap_manager.routers import share_otp

SECRET = "internal-secret-for-tests"
LINK = "11111111-2222-3333-4444-555555555555"
EMAIL = "recipient@example.com"
TENANT = "default"


class FakeTokens:
    """A TokenStore stand-in: codes, markers and a rate bucket, all in memory."""

    def __init__(self):
        self.codes: dict = {}
        self.markers: dict = {}
        self.buckets: dict = {}
        self.issued: list = []

    def issue_code(self, kind, uid, ttl_s, length=6):
        code = "123456"
        self.codes[(kind, uid)] = code
        return code

    def consume_code(self, kind, uid, code):
        want = self.codes.get((kind, uid))
        if want is not None and code == want:
            del self.codes[(kind, uid)]
            return True
        return False

    def issue(self, kind, uid, ttl_s):
        tok = f"tok-{kind}-{len(self.issued)}"
        self.issued.append(tok)
        return tok

    def set_marker(self, key, value, ttl_s):
        self.markers[key] = value

    def get_marker(self, key):
        return self.markers.get(key)

    def rate_ok(self, bucket, limit, window_s):
        self.buckets[bucket] = self.buckets.get(bucket, 0) + 1
        return self.buckets[bucket] <= limit

    def peek(self, kind, uid):
        return self.codes.get((kind, uid))


class FakeAudit:
    def __init__(self):
        self.events = []

    def emit(self, **kw):
        self.events.append(kw)
        return True


class FakeMailer:
    def __init__(self):
        self.sent = []
        self.fail = False

    def send(self, to, subject, body):
        if self.fail:
            raise RuntimeError("smtp refused")
        self.sent.append({"to": to, "subject": subject, "body": body})


class FakeTemplates:
    def get(self, tenant, name):
        return type("T", (), {"subject": "Your code", "body": "code: {{code}}"})()


class Settings:
    share_otp_ttl_s = 600
    share_otp_max_attempts = 5
    share_otp_attempt_window_s = 900
    share_otp_send_per_window = 3
    share_otp_send_window_s = 900
    share_otp_send_per_link_day = 20
    share_otp_min_seconds_after_send = 5
    share_otp_min_submit_interval_ms = 1500
    share_otp_timing_weight = 5
    share_recipient_ttl_s = 86400
    share_internal_secret = SECRET
    mfa_internal_secret = ""


@pytest.fixture
def svc():
    return type("S", (), {
        "settings": Settings(), "tokens": FakeTokens(), "audit": FakeAudit(),
        "mailer": FakeMailer(), "templates": FakeTemplates(),
    })()


@pytest.fixture
def client(svc):
    app = FastAPI()
    app.include_router(share_otp.router)
    app.dependency_overrides[services] = lambda: svc
    return TestClient(app)


AUTH = {"X-Internal-Auth": SECRET}


def _challenge(client, email=EMAIL):
    return client.post("/internal/share/email-challenge",
                       json={"link_uid": LINK, "email": email, "tenant": TENANT},
                       headers=AUTH)


def _verify(client, code, email=EMAIL):
    return client.post("/internal/share/email-verify",
                       json={"link_uid": LINK, "email": email, "tenant": TENANT,
                             "code": code}, headers=AUTH)


# --- the server-to-server door -------------------------------------------

def test_the_internal_seam_refuses_without_the_secret(client):
    r = client.post("/internal/share/email-challenge",
                    json={"link_uid": LINK, "email": EMAIL, "tenant": TENANT})
    assert r.status_code == 403


def test_a_wrong_secret_is_refused(client):
    r = client.post("/internal/share/email-challenge",
                    json={"link_uid": LINK, "email": EMAIL, "tenant": TENANT},
                    headers={"X-Internal-Auth": "nope"})
    assert r.status_code == 403


# --- rung 0: timing ------------------------------------------------------

def test_a_submission_before_the_mail_could_arrive_is_counted(svc, client):
    """Bounded by physics, not habit: a code cannot be READ before the mail
    carrying it is delivered, so a submission inside that window is a script."""
    _challenge(client)
    before = svc.tokens.buckets.get(f"share_otp_attempt:{LINK}|{EMAIL}", 0)
    _verify(client, "000000")            # immediately, well inside the window
    after = svc.tokens.buckets[f"share_otp_attempt:{LINK}|{EMAIL}"]
    assert after - before == Settings.share_otp_timing_weight


def test_a_timing_trip_is_invisible_to_the_recipient(svc, client):
    """The whole point of rung 0.

    Everything on the code-entry screen is reachable by anyone holding the URL,
    so if a scripted attempt got a different answer from a human's typo, the
    response would be the very oracle §6.9 closes.
    """
    _challenge(client)
    scripted = _verify(client, "000000").json()

    # A second, unhurried attempt on a fresh challenge — no timing trip.
    svc.tokens.markers.clear()
    svc.tokens.buckets.clear()
    _challenge(client)
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 60)
    human = _verify(client, "000000").json()

    scripted.pop("timing_flag", None)
    human.pop("timing_flag", None)
    assert scripted == human, "a scripted attempt must read exactly like a typo"


def test_a_sub_interval_retry_is_counted_too(svc, client):
    """The other half of rung 0: hammering, regardless of when the mail landed."""
    _challenge(client)
    # Put the send well in the past so only the retry interval can trip.
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 600)
    _verify(client, "000000")
    svc.tokens.buckets.clear()
    _verify(client, "000001")            # immediately after the previous one
    assert svc.tokens.buckets[f"share_otp_attempt:{LINK}|{EMAIL}"] \
        == Settings.share_otp_timing_weight


def test_an_unhurried_attempt_costs_one(svc, client):
    """Guard on the guard: the weight must apply only when a check TRIPS, or
    every ordinary recipient burns their budget five times as fast."""
    _challenge(client)
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 600)
    _verify(client, "000000")
    assert svc.tokens.buckets[f"share_otp_attempt:{LINK}|{EMAIL}"] == 1


def test_timing_is_evaluated_even_when_the_code_is_right(svc, client):
    """Counted BEFORE the compare, so a scripted burst that happens to guess
    right is still recorded as scripted."""
    _challenge(client)
    r = _verify(client, "123456")        # correct, but far too fast
    assert r.json()["ok"] is True
    assert r.json()["timing_flag"] == "too_soon_after_send"


# --- rung 1: attempts per (link, email) ----------------------------------

def test_attempts_are_capped_per_address(svc, client):
    _challenge(client)
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 600)
    last = None
    for _ in range(Settings.share_otp_max_attempts + 1):
        svc.tokens.markers.pop(share_otp._last_attempt_key(f"{LINK}|{EMAIL}"), None)
        last = _verify(client, "000000").json()
    assert last["locked"] is True
    assert last["attempts_remaining"] == 0


def test_one_addresss_lockout_does_not_touch_another(svc, client):
    """The bucket is keyed on (link, email), so one recipient exhausting their
    budget must not lock out the others on the same link."""
    other = "colleague@example.com"
    _challenge(client)
    _challenge(client, email=other)
    for _ in range(Settings.share_otp_max_attempts + 1):
        svc.tokens.markers.pop(share_otp._last_attempt_key(f"{LINK}|{EMAIL}"), None)
        _verify(client, "000000")

    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{other}")] = str(
        int(time.time()) - 600)
    r = _verify(client, "123456", email=other)
    assert r.json()["locked"] is False


def test_the_budget_cannot_be_refilled_by_asking_for_a_new_code(svc, client):
    """Charged against (link, email) and not against the challenge, so
    re-requesting does not hand the attacker a fresh five."""
    _challenge(client)
    for _ in range(3):
        svc.tokens.markers.pop(share_otp._last_attempt_key(f"{LINK}|{EMAIL}"), None)
        _verify(client, "000000")
    spent = svc.tokens.buckets[f"share_otp_attempt:{LINK}|{EMAIL}"]
    _challenge(client)                    # a brand-new code...
    assert svc.tokens.buckets[f"share_otp_attempt:{LINK}|{EMAIL}"] == spent


# --- the happy path and its artifacts ------------------------------------

def test_a_correct_code_mints_a_recipient_token(svc, client):
    _challenge(client)
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 600)
    r = _verify(client, "123456").json()
    assert r["ok"] is True and r["recipient_token"]


def test_a_code_is_single_use(svc, client):
    _challenge(client)
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 600)
    assert _verify(client, "123456").json()["ok"] is True
    svc.tokens.markers.pop(share_otp._last_attempt_key(f"{LINK}|{EMAIL}"), None)
    assert _verify(client, "123456").json()["ok"] is False


def test_a_failed_send_is_reported_rather_than_swallowed(svc, client):
    """The creator has to find out: a mail misconfiguration otherwise looks
    exactly like a recipient who mistyped their address."""
    svc.mailer.fail = True
    r = _challenge(client)
    assert r.json()["sent"] is False
    assert r.json()["error"]
    assert any(e["action"] == "share_link_challenge_sent"
               and e["outcome"] == "error" for e in svc.audit.events)


def test_every_attempt_is_audited(svc, client):
    _challenge(client)
    svc.tokens.markers[share_otp._sent_key(f"{LINK}|{EMAIL}")] = str(
        int(time.time()) - 600)
    _verify(client, "000000")
    actions = [e["action"] for e in svc.audit.events]
    assert "share_link_challenge_sent" in actions
    assert "share_link_challenge_failed" in actions
