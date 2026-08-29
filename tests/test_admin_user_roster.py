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

"""Tenant-admin user administration (SPECIFICATION.md §4, §6.1, §7): the roster,
a member's profile, editing their role membership, and the two removal scopes.

Offline — the directory and the audit sink are faked, and the tenant-admin
dependency is overridden, so this exercises the router's rules (guards, diffing,
the global-account check) rather than LDAP itself.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ldap_manager.app import create_app
from ldap_manager.config import Settings
from ldap_manager.deps import require_tenant_admin, services
from ldap_manager.identity import Identity

TENANT = "acme"
ADMIN = "boss@acme.test"


class FakeLdap:
    """A two-tenant directory: roles per tenant, plus global user entries."""

    def __init__(self):
        self.users = {
            ADMIN: {"uid": ADMIN, "email": ADMIN, "display_name": "The Boss",
                    "given_name": "The", "surname": "Boss", "avatar_url": "",
                    "dn": f"uid={ADMIN},ou=people"},
            "ann@acme.test": {"uid": "ann@acme.test", "email": "ann@acme.test",
                              "display_name": "Ann Adams", "given_name": "Ann",
                              "surname": "Adams", "avatar_url": "",
                              "dn": "uid=ann@acme.test,ou=people"},
            "shared@acme.test": {"uid": "shared@acme.test", "email": "shared@acme.test",
                                 "display_name": "Sam Shared", "given_name": "Sam",
                                 "surname": "Shared", "avatar_url": "",
                                 "dn": "uid=shared@acme.test,ou=people"},
        }
        self.roles = {
            TENANT: {
                "administrators": [ADMIN],
                "editors": ["ann@acme.test", "shared@acme.test"],
                "viewers": [],
            },
            "other": {"viewers": ["shared@acme.test"]},
        }
        self.deleted: list[str] = []

    # --- reads ---
    def get_user(self, uid):
        return self.users.get(uid)

    def list_roles(self, tenant):
        return [{"name": n, "dn": f"cn={n}", "member_count": len(m)}
                for n, m in self.roles.get(tenant, {}).items()]

    def list_members(self, tenant, role):
        return list(self.roles.get(tenant, {}).get(role, []))

    def user_roles(self, tenant, uid):
        return sorted(r for r, m in self.roles.get(tenant, {}).items() if uid in m)

    def user_tenants(self, uid):
        return sorted(t for t, roles in self.roles.items()
                      if any(uid in m for m in roles.values()))

    def list_tenant_users(self, tenant):
        by_uid: dict[str, list[str]] = {}
        for role, members in self.roles.get(tenant, {}).items():
            for uid in members:
                by_uid.setdefault(uid, []).append(role)
        out = []
        for uid, roles in by_uid.items():
            u = dict(self.users.get(uid) or {"uid": uid, "email": uid, "display_name": "", "dn": ""})
            u["roles"] = sorted(roles)
            u["orphaned"] = not u.get("dn")
            out.append(u)
        return sorted(out, key=lambda u: (u.get("display_name") or u["uid"]).lower())

    # --- writes ---
    def add_member(self, tenant, role, uid):
        self.roles[tenant][role].append(uid)

    def remove_member(self, tenant, role, uid):
        self.roles[tenant][role].remove(uid)

    def delete_user(self, uid, dn=None):
        self.deleted.append(uid)
        self.users.pop(uid, None)


class FakeAudit:
    def __init__(self, ok=True):
        self.ok = ok
        self.events: list[dict] = []

    def emit(self, **kw):
        self.events.append(kw)
        return self.ok


class FakeStore:
    """A 2FA / service-credential store that records the purge it was asked for."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.purged: list[str] = []

    def disable(self, uid):
        self.purged.append(uid)

    def revoke_all(self, uid):
        self.purged.append(uid)
        return 1


@pytest.fixture()
def env():
    app = create_app(Settings())
    fake = app.state.services
    fake.ldap = FakeLdap()
    fake.audit = FakeAudit()
    fake.twofa = FakeStore()
    fake.service_cred = FakeStore()
    app.dependency_overrides[services] = lambda: fake
    app.dependency_overrides[require_tenant_admin] = lambda: Identity(
        user=ADMIN, tenant=TENANT, roles=["administrators"])
    yield TestClient(app), fake
    app.dependency_overrides.clear()


# ------------------------------- the roster --------------------------------

def test_roster_lists_every_member_with_their_roles(env):
    c, _ = env
    rows = c.get("/v1/admin/users/roster").json()
    assert [r["uid"] for r in rows] == ["ann@acme.test", "shared@acme.test", ADMIN]
    ann = next(r for r in rows if r["uid"] == "ann@acme.test")
    assert ann["roles"] == ["editors"] and ann["is_admin"] is False
    assert next(r for r in rows if r["uid"] == ADMIN)["is_admin"] is True


def test_roster_path_is_not_read_as_a_uid(env):
    # /roster is declared before /{uid}; a user literally named "roster" is not a
    # thing (uids are emails), but the route order is what guarantees it.
    c, _ = env
    assert c.get("/v1/admin/users/roster").status_code == 200


# ------------------------------ the profile --------------------------------

def test_profile_returns_full_fields_for_a_member(env):
    c, _ = env
    p = c.get("/v1/admin/users/ann@acme.test/profile").json()
    assert p["given_name"] == "Ann" and p["surname"] == "Adams"
    assert p["roles"] == ["editors"] and p["tenant"] == TENANT
    assert p["other_tenant_count"] == 0 and p["can_delete_account"] is True


def test_profile_counts_other_tenants_without_naming_them(env):
    c, _ = env
    p = c.get("/v1/admin/users/shared@acme.test/profile").json()
    assert p["other_tenant_count"] == 1
    # The count travels; the name of the other tenant never leaves the service.
    assert "other" not in [str(v) for v in p.values()]
    assert p["can_delete_account"] is False    # somebody else still needs it


def test_profile_of_a_non_member_is_404_not_403(env):
    c, fake = env
    fake.ldap.users["stranger@elsewhere.test"] = {"uid": "stranger@elsewhere.test",
                                             "email": "stranger@elsewhere.test",
                                             "display_name": "S", "dn": "uid=s"}
    r = c.get("/v1/admin/users/stranger@elsewhere.test/profile")
    assert r.status_code == 404   # "exists but not yours" would leak the directory


def test_admin_cannot_delete_their_own_account(env):
    c, _ = env
    assert c.get(f"/v1/admin/users/{ADMIN}/profile").json()["can_delete_account"] is False


# --------------------------- editing memberships ---------------------------

def test_set_roles_diffs_against_current_membership(env):
    c, fake = env
    r = c.put("/v1/admin/users/ann@acme.test/roles", json={"roles": ["viewers", "editors"]})
    assert r.status_code == 200 and r.json()["roles"] == ["editors", "viewers"]
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == ["editors", "viewers"]
    # One audit row for the whole diff, not one per add/remove.
    diffs = [e for e in fake.audit.events if e["action"] == "role_set_user"]
    assert len(diffs) == 1
    assert diffs[0]["detail"] == {"add": ["viewers"], "remove": [], "roles": ["editors", "viewers"]}


def test_set_roles_rejects_an_unknown_role_before_writing(env):
    c, fake = env
    r = c.put("/v1/admin/users/ann@acme.test/roles", json={"roles": ["editors", "wizards"]})
    assert r.status_code == 400 and "wizards" in r.json()["detail"]
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == ["editors"]
    assert fake.audit.events == []


def test_set_roles_refuses_to_empty_the_set(env):
    # Emptying membership is a removal from the tenant, which has its own route
    # and its own confirmation — it must not happen by unticking every box.
    c, fake = env
    r = c.put("/v1/admin/users/ann@acme.test/roles", json={"roles": []})
    assert r.status_code == 400
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == ["editors"]


def test_set_roles_cannot_drop_your_own_administrators(env):
    c, fake = env
    r = c.put(f"/v1/admin/users/{ADMIN}/roles", json={"roles": ["editors"]})
    assert r.status_code == 400 and "yourself" in r.json()["detail"]
    assert "administrators" in fake.ldap.user_roles(TENANT, ADMIN)


def test_set_roles_cannot_drop_the_last_administrator(env):
    c, fake = env
    fake.ldap.roles[TENANT]["administrators"].append("ann@acme.test")
    app_ident = Identity(user="ann@acme.test", tenant=TENANT, roles=["administrators"])
    c.app.dependency_overrides[require_tenant_admin] = lambda: app_ident
    # Two admins: dropping the *other* one is fine.
    assert c.put(f"/v1/admin/users/{ADMIN}/roles", json={"roles": ["editors"]}).status_code == 200
    fake.ldap.roles[TENANT]["editors"].remove(ADMIN)
    fake.ldap.roles[TENANT]["editors"].append(ADMIN)
    # Now ann is the last one, and she is also the caller.
    r = c.put("/v1/admin/users/ann@acme.test/roles", json={"roles": ["editors"]})
    assert r.status_code == 400


def test_set_roles_is_refused_when_the_audit_log_is_down(env):
    c, fake = env
    fake.audit.ok = False
    r = c.put("/v1/admin/users/ann@acme.test/roles", json={"roles": ["viewers"]})
    assert r.status_code == 503
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == ["editors"]


def test_set_roles_with_no_change_is_a_no_op(env):
    c, fake = env
    assert c.put("/v1/admin/users/ann@acme.test/roles",
                 json={"roles": ["editors"]}).status_code == 200
    assert fake.audit.events == []


# -------------------------------- removal ----------------------------------

def test_tenant_removal_drops_every_role_but_keeps_the_account(env):
    c, fake = env
    r = c.request("DELETE", "/v1/admin/users/ann@acme.test", params={"scope": "tenant"})
    assert r.status_code == 200
    assert r.json() == {"uid": "ann@acme.test", "scope": "tenant",
                        "roles_removed": ["editors"], "account_deleted": False}
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == []
    assert "ann@acme.test" in fake.ldap.users        # global account survives


def test_tenant_removal_is_the_default_scope(env):
    c, fake = env
    assert c.delete("/v1/admin/users/ann@acme.test").json()["account_deleted"] is False
    assert "ann@acme.test" in fake.ldap.users


def test_system_removal_deletes_the_account_and_purges_its_secrets(env):
    c, fake = env
    r = c.request("DELETE", "/v1/admin/users/ann@acme.test", params={"scope": "system"})
    assert r.status_code == 200 and r.json()["account_deleted"] is True
    assert fake.ldap.deleted == ["ann@acme.test"]
    assert fake.twofa.purged == ["ann@acme.test"]
    assert fake.service_cred.purged == ["ann@acme.test"]
    assert [e["action"] for e in fake.audit.events] == ["user_delete"]


def test_system_removal_is_refused_while_another_tenant_uses_the_account(env):
    c, fake = env
    r = c.request("DELETE", "/v1/admin/users/shared@acme.test", params={"scope": "system"})
    assert r.status_code == 409 and "other tenant" in r.json()["detail"]
    assert fake.ldap.deleted == []
    assert fake.ldap.user_roles(TENANT, "shared@acme.test") == ["editors"]  # nothing removed


def test_removal_refuses_self_and_the_last_administrator(env):
    c, fake = env
    assert c.delete(f"/v1/admin/users/{ADMIN}").status_code == 400
    assert fake.ldap.user_roles(TENANT, ADMIN) == ["administrators"]


def test_removing_someone_who_is_not_a_member_is_404(env):
    c, fake = env
    fake.ldap.users["nobody@elsewhere.test"] = {"uid": "nobody@elsewhere.test",
                                                "email": "nobody@elsewhere.test",
                                                "display_name": "", "dn": "uid=n"}
    assert c.delete("/v1/admin/users/nobody@elsewhere.test").status_code == 404


def test_removal_is_refused_when_the_audit_log_is_down(env):
    c, fake = env
    fake.audit.ok = False
    r = c.delete("/v1/admin/users/ann@acme.test")
    assert r.status_code == 503
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == ["editors"]


def test_system_removal_survives_a_failing_secret_purge(env):
    # The directory entry is what actually revokes access; a store that is down
    # must not leave the account half-deleted.
    c, fake = env

    def boom(uid):
        raise RuntimeError("postgres is down")

    fake.service_cred.revoke_all = boom
    r = c.request("DELETE", "/v1/admin/users/ann@acme.test", params={"scope": "system"})
    assert r.status_code == 200 and fake.ldap.deleted == ["ann@acme.test"]


def test_an_unknown_scope_is_rejected(env):
    c, _ = env
    assert c.request("DELETE", "/v1/admin/users/ann@acme.test",
                     params={"scope": "everything"}).status_code == 422
