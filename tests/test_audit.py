"""Auth auditing: the AuditEmitter wrapper + endpoint wiring (offline).

Emission is exercised with an injected fake publisher, so these run without a
broker. Live emit-to-Redis is covered by audit_service's own publisher tests.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from ldap_manager.app import build_services, create_app
from ldap_manager.audit import AuditEmitter
from ldap_manager.config import Settings


class _FakePub:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def publish(self, **fields):
        self.calls.append(fields)
        return self.result


def test_disabled_emitter_is_noop_and_returns_true():
    a = AuditEmitter(enabled=False)
    assert a.enabled is False
    assert a.emit(action="password_change", outcome="ok", actor="alice", tenant="t") is True


def test_emit_defaults_category_auth_and_iface():
    fp = _FakePub()
    a = AuditEmitter(enabled=True, publisher=fp)
    assert a.emit(action="password_change", outcome="ok", actor="alice", tenant="t") is True
    call = fp.calls[0]
    assert call["category"] == "auth"
    assert call["source_iface"] == "ldapadmin"
    assert call["action"] == "password_change" and call["outcome"] == "ok"


def test_emit_returns_false_when_publish_fails():
    a = AuditEmitter(enabled=True, publisher=_FakePub(result=False))
    assert a.emit(action="password_change", outcome="ok", actor="a", tenant="t") is False


def test_build_services_wires_a_disabled_emitter_by_default():
    svc = build_services(Settings())
    assert svc.audit is not None and svc.audit.enabled is False


def _client_with_fake_audit(fake):
    app = create_app(Settings())
    app.state.services.audit = AuditEmitter(enabled=True, publisher=fake)
    return TestClient(app)


def test_reset_request_emits_and_still_returns_200():
    fake = _FakePub()
    client = _client_with_fake_audit(fake)
    r = client.post("/v1/reset/request", json={"email": "user@example.com"})
    assert r.status_code == 200  # constant 200, no enumeration
    assert any(c["action"] == "password_reset_request" and c["scope"] == "global"
               and c["actor"] == "user@example.com" for c in fake.calls)


def test_reset_confirm_bad_token_emits_denied():
    fake = _FakePub()
    client = _client_with_fake_audit(fake)
    r = client.post("/v1/reset/confirm", json={"token": "nope", "password": "Whatever1!"})
    assert r.status_code == 400
    assert any(c["action"] == "password_reset_complete" and c["outcome"] == "denied"
               for c in fake.calls)
