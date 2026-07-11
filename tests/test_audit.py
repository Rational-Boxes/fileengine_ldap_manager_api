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


# --------------------------- Phase 4: user-management ------------------------
from unittest.mock import MagicMock  # noqa: E402

from ldap_manager.deps import require_identity, require_tenant_admin  # noqa: E402
from ldap_manager.identity import Identity  # noqa: E402

_ADMIN = Identity(user="admin", tenant="acme", roles=["administrators"])


def _admin_client(fake, *, ldap=None):
    app = create_app(Settings())
    svc = app.state.services
    svc.audit = AuditEmitter(enabled=True, publisher=fake)
    svc.ldap = ldap or MagicMock()
    svc.home = MagicMock()
    app.dependency_overrides[require_tenant_admin] = lambda: _ADMIN
    return TestClient(app)


def _emitted(fake, action):
    return [c for c in fake.calls if c["action"] == action and c["category"] == "user"]


def test_create_role_emits_role_create():
    ldap = MagicMock()
    ldap.role_dn.return_value = "cn=editors,ou=acme,dc=x"  # RoleOut.dn must be a str
    fake = _FakePub()
    r = _admin_client(fake, ldap=ldap).post("/v1/admin/roles", json={"name": "editors"})
    assert r.status_code == 201
    hits = _emitted(fake, "role_create")
    assert hits and hits[0]["target_uid"] == "editors" and hits[0]["target_type"] == "role"


def test_create_role_fail_closed_returns_503_when_not_durable():
    fake = _FakePub(result=False)  # publish -> not durable
    r = _admin_client(fake).post("/v1/admin/roles", json={"name": "editors"})
    assert r.status_code == 503


def test_delete_role_emits_role_delete():
    fake = _FakePub()
    r = _admin_client(fake).delete("/v1/admin/roles/editors")
    assert r.status_code == 204
    assert _emitted(fake, "role_delete")


def test_add_member_emits_role_assign_user():
    ldap = MagicMock()
    ldap.is_tenant_member.return_value = True  # not first grant -> skip email
    fake = _FakePub()
    r = _admin_client(fake, ldap=ldap).post("/v1/admin/roles/editors/members", json={"uid": "bob"})
    assert r.status_code == 204
    hits = _emitted(fake, "role_assign_user")
    assert hits and hits[0]["target_uid"] == "bob" and hits[0]["detail"] == {"role": "editors"}


def test_remove_member_emits_role_remove_user():
    ldap = MagicMock()
    ldap.list_members.return_value = ["admin", "bob"]  # not last admin
    fake = _FakePub()
    r = _admin_client(fake, ldap=ldap).delete("/v1/admin/roles/editors/members/bob")
    assert r.status_code == 204
    hits = _emitted(fake, "role_remove_user")
    assert hits and hits[0]["target_uid"] == "bob"


def test_create_user_emits_user_create():
    ldap = MagicMock()
    ldap.get_user.return_value = None  # does not already exist
    fake = _FakePub()
    # The invite machinery may 503 (unconfigured), but the fail-closed write-ahead
    # user_create fires first — that's what Phase 4 adds.
    _admin_client(fake, ldap=ldap).post(
        "/v1/admin/users", json={"email": "new@x.com", "display_name": "New", "roles": ["editors"]},
        headers={"Authorization": "Bearer x"})
    hits = _emitted(fake, "user_create")
    assert hits and hits[0]["target_uid"] == "new@x.com" and hits[0]["detail"] == {"roles": ["editors"]}


def test_profile_update_emits_best_effort():
    ldap = MagicMock()
    ldap.get_user.return_value = {"email": "a@x.com", "display_name": "A",
                                  "given_name": "", "surname": "", "avatar_url": ""}
    fake = _FakePub()
    app = create_app(Settings())
    app.state.services.audit = AuditEmitter(enabled=True, publisher=fake)
    app.state.services.ldap = ldap
    app.dependency_overrides[require_identity] = lambda: Identity(user="alice", tenant="acme", roles=[])
    r = TestClient(app).patch("/v1/me", json={"display_name": "New Name"})
    assert r.status_code == 200
    hits = _emitted(fake, "profile_update")
    assert hits and hits[0]["target_uid"] == "alice"
