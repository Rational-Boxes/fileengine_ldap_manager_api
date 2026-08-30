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

from types import SimpleNamespace

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
        self.created: list = []
        self.roles = {
            TENANT: {
                "administrators": [ADMIN],
                "editors": ["ann@acme.test", "shared@acme.test"],
                "viewers": [],
            },
            "other": {"viewers": ["shared@acme.test"]},
        }

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
    def is_tenant_member(self, uid, tenant):
        return any(uid in m for m in self.roles.get(tenant, {}).values())

    def create_user(self, uid, email, display_name):
        self.users[uid] = {"uid": uid, "email": email, "display_name": display_name,
                           "given_name": "", "surname": "", "avatar_url": "",
                           "dn": f"uid={uid},ou=people"}
        self.created.append(uid)

    def add_member(self, tenant, role, uid):
        self.roles.setdefault(tenant, {}).setdefault(role, []).append(uid)

    def remove_member(self, tenant, role, uid):
        self.roles[tenant][role].remove(uid)

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
        self.purged: list = []

    def disable(self, uid):
        self.purged.append(uid)

    def revoke_all_for_tenant(self, uid, tenant):
        self.purged.append((uid, tenant))
        return 2


class FakeMailer:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.sent: list = []

    def send(self, to, subject, body):
        self.sent.append((to, subject, body))


@pytest.fixture()
def env():
    app = create_app(Settings())
    fake = app.state.services
    fake.ldap = FakeLdap()
    fake.audit = FakeAudit()
    fake.twofa = FakeStore()
    fake.service_cred = FakeStore()
    # Both invite emails must be able to send, so the new-account and existing-
    # account paths behave identically (the privacy invariant). Without this the
    # new path 503s on unconfigured email while the existing path 201s — itself a
    # leak of which case ran.
    fake.mailer = FakeMailer()
    fake.tokens = SimpleNamespace(enabled=True, issue=lambda kind, uid, ttl: "tok-123")
    fake.templates = SimpleNamespace(
        get=lambda tenant, kind: SimpleNamespace(subject="Hello {{email}}",
                                                 body="link {{invite_link}}"))
    fake.settings.invite_link_base = "https://app.example/invite"
    app.dependency_overrides[services] = lambda: fake
    app.dependency_overrides[require_tenant_admin] = lambda: Identity(
        user=ADMIN, tenant=TENANT, roles=["administrators"])
    yield TestClient(app), fake
    app.dependency_overrides.clear()


# ------------------------------ the invite gate ----------------------------

def test_invite_requires_at_least_one_role(env):
    # Membership of a tenant IS holding >=1 role, so a role-less invite would
    # create an account that is a member of nothing here. Rejected by the schema
    # before anything is written.
    c, fake = env
    hdr = {"Authorization": "Bearer x"}
    r = c.post("/v1/admin/users", json={"email": "new@acme.com", "display_name": "New"}, headers=hdr)
    assert r.status_code == 422
    r2 = c.post("/v1/admin/users",
                json={"email": "new@acme.com", "display_name": "New", "roles": []}, headers=hdr)
    assert r2.status_code == 422
    assert fake.audit.events == []
    assert "new@acme.com" not in fake.ldap.users


def test_invite_rejects_a_blank_only_role_list(env):
    c, fake = env
    r = c.post("/v1/admin/users",
               json={"email": "new@acme.com", "display_name": "New", "roles": ["", "  "]},
               headers={"Authorization": "Bearer x"})
    assert r.status_code == 422
    assert fake.audit.events == []


def test_invite_rejects_an_unknown_role_before_creating_anything(env):
    # A bogus role would make the grant fail partway and leave a created account
    # that is a member of nothing — so it is caught before the write-ahead.
    c, fake = env
    r = c.post("/v1/admin/users",
               json={"email": "new@acme.com", "display_name": "New", "roles": ["editors", "wizards"]},
               headers={"Authorization": "Bearer x"})
    assert r.status_code == 400 and "wizards" in r.json()["detail"]
    assert fake.audit.events == []
    assert "new@acme.com" not in fake.ldap.users


def test_invite_creates_and_invites_a_brand_new_user(env):
    c, fake = env
    hdr = {"Authorization": "Bearer x"}
    r = c.post("/v1/admin/users",
               json={"email": "new@acme.com", "display_name": "New Person", "roles": ["editors"]},
               headers=hdr)
    assert r.status_code == 201
    assert "new@acme.com" in fake.ldap.created                 # account made
    assert "new@acme.com" in fake.ldap.roles[TENANT]["editors"]
    assert [e["action"] for e in fake.audit.events] == ["user_create"]


def test_invite_adds_an_existing_account_without_recreating_it(env):
    # An account that already exists (in tenant "other"); inviting them into acme
    # must ADD them, not create — and must not send a set-password operation.
    c, fake = env
    fake.ldap.users["existing@acme.com"] = {"uid": "existing@acme.com", "email": "existing@acme.com",
                                           "display_name": "Existing", "dn": "uid=existing"}
    fake.ldap.roles["other"] = {"viewers": ["existing@acme.com"]}
    r = c.post("/v1/admin/users",
               json={"email": "existing@acme.com", "display_name": "ignored", "roles": ["viewers"]},
               headers={"Authorization": "Bearer x"})
    assert r.status_code == 201
    assert fake.ldap.created == []                             # NOT recreated
    assert "existing@acme.com" in fake.ldap.roles[TENANT]["viewers"]
    assert [e["action"] for e in fake.audit.events] == ["user_add_existing"]
    assert fake.mailer.sent                                    # informational email sent


def test_invite_response_is_identical_whether_or_not_the_account_exists(env):
    # The privacy invariant: a tenant admin must not be able to tell, from the
    # response, whether the email already had a platform account — that is someone
    # else's personal information. Same body -> byte-identical status and JSON.
    c, fake = env
    body = {"email": "probe@acme.com", "display_name": "Probe", "roles": ["editors"]}
    hdr = {"Authorization": "Bearer x"}

    # (a) account does NOT exist
    r_new = c.post("/v1/admin/users", json=body, headers=hdr)

    # (b) same request, but now the account DOES exist (in another tenant)
    fake.ldap.users["probe@acme.com"] = {"uid": "probe@acme.com", "email": "probe@acme.com",
                                         "display_name": "Their Real Name", "dn": "uid=probe"}
    fake.ldap.roles["other"] = {"viewers": ["probe@acme.com"]}
    r_exists = c.post("/v1/admin/users", json=body, headers=hdr)

    assert r_new.status_code == r_exists.status_code
    assert r_new.json() == r_exists.json()
    # And the existing account's real name never appears in the response.
    assert "Their Real Name" not in r_exists.text


def test_invite_never_echoes_an_existing_users_stored_details(env):
    c, fake = env
    fake.ldap.users["known@acme.com"] = {"uid": "known@acme.com", "email": "known@acme.com",
                                        "display_name": "Confidential Name", "dn": "uid=known"}
    r = c.post("/v1/admin/users",
               json={"email": "known@acme.com", "display_name": "What Admin Typed", "roles": ["editors"]},
               headers={"Authorization": "Bearer x"})
    body = r.json()
    assert body["display_name"] == "What Admin Typed"          # submitted, not stored
    assert body["in_this_tenant"] is True
    assert "Confidential Name" not in r.text


def test_invite_of_an_existing_member_only_adds_missing_roles(env):
    # A user already an 'editors' member of acme. Inviting with {editors, viewers}
    # adds only viewers; no duplicate add of editors.
    c, fake = env
    fake.ldap.users["mem@acme.com"] = {"uid": "mem@acme.com", "email": "mem@acme.com",
                                      "display_name": "Mem", "dn": "uid=mem"}
    fake.ldap.roles[TENANT]["editors"].append("mem@acme.com")
    before = list(fake.ldap.roles[TENANT]["editors"])
    r = c.post("/v1/admin/users",
               json={"email": "mem@acme.com", "display_name": "Mem", "roles": ["editors", "viewers"]},
               headers={"Authorization": "Bearer x"})
    assert r.status_code == 201
    assert fake.ldap.roles[TENANT]["editors"] == before        # editors unchanged (no dup)
    assert "mem@acme.com" in fake.ldap.roles[TENANT]["viewers"]
    assert fake.ldap.created == []


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
    assert p["other_tenant_count"] == 0 and "can_delete_account" not in p


def test_profile_counts_other_tenants_without_naming_them(env):
    c, _ = env
    p = c.get("/v1/admin/users/shared@acme.test/profile").json()
    assert p["other_tenant_count"] == 1
    # The count travels; the name of the other tenant never leaves the service.
    assert "other" not in [str(v) for v in p.values()]


def test_profile_of_a_non_member_is_404_not_403(env):
    c, fake = env
    fake.ldap.users["stranger@elsewhere.test"] = {"uid": "stranger@elsewhere.test",
                                             "email": "stranger@elsewhere.test",
                                             "display_name": "S", "dn": "uid=s"}
    r = c.get("/v1/admin/users/stranger@elsewhere.test/profile")
    assert r.status_code == 404   # "exists but not yours" would leak the directory


def test_profile_carries_no_account_deletion_affordance(env):
    # Deleting the global account is a sysadmin/LDAP operation, so the tenant-admin
    # profile exposes no such flag at all.
    c, _ = env
    p = c.get(f"/v1/admin/users/{ADMIN}/profile").json()
    assert "can_delete_account" not in p


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

def test_removal_drops_every_role_here_and_keeps_the_account(env):
    c, fake = env
    r = c.delete("/v1/admin/users/ann@acme.test")
    assert r.status_code == 200
    assert r.json() == {"uid": "ann@acme.test", "roles_removed": ["editors"],
                        "credentials_purged": 2}
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == []
    assert "ann@acme.test" in fake.ldap.users        # global account survives


def test_removal_purges_this_tenants_door_keys_only(env):
    # Service credentials are tenant-bound, so removing a user from a tenant must
    # revoke their keys FOR THAT TENANT — passed to the store with the tenant, so
    # their keys elsewhere are untouched.
    c, fake = env
    c.delete("/v1/admin/users/ann@acme.test")
    assert fake.service_cred.purged == [("ann@acme.test", TENANT)]
    # 2FA is per-user (shared across tenants), so a tenant removal never touches it.
    assert fake.twofa.purged == []


def test_removal_does_not_delete_the_global_account(env):
    # There is no account-deletion path in the tenant-admin API at all — that is a
    # sysadmin/LDAP operation. Removing a user only unlinks them from this tenant.
    c, fake = env
    c.delete("/v1/admin/users/shared@acme.test")
    assert "shared@acme.test" in fake.ldap.users
    # shared is also in tenant "other"; that membership is untouched.
    assert "other" in fake.ldap.user_tenants("shared@acme.test")


def test_removal_leaves_other_tenant_roles_untouched(env):
    c, fake = env
    before = fake.ldap.user_roles("other", "shared@acme.test")
    c.delete("/v1/admin/users/shared@acme.test")
    assert fake.ldap.user_roles(TENANT, "shared@acme.test") == []      # gone here
    assert fake.ldap.user_roles("other", "shared@acme.test") == before  # kept there


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
    assert fake.service_cred.purged == []   # nothing torn down when it is refused


def test_removal_survives_a_failing_credential_purge(env):
    # The LDAP role removal is what revokes access; a credential store that is down
    # must not make the removal fail (the leftover keys fail verification anyway
    # once the roles are gone).
    c, fake = env

    def boom(uid, tenant):
        raise RuntimeError("postgres is down")

    fake.service_cred.revoke_all_for_tenant = boom
    r = c.delete("/v1/admin/users/ann@acme.test")
    assert r.status_code == 200
    assert r.json()["credentials_purged"] == 0
    assert fake.ldap.user_roles(TENANT, "ann@acme.test") == []


def test_removal_skips_credential_purge_when_the_store_is_disabled(env):
    c, fake = env
    fake.service_cred.enabled = False
    r = c.delete("/v1/admin/users/ann@acme.test")
    assert r.status_code == 200 and r.json()["credentials_purged"] == 0
    assert fake.service_cred.purged == []
