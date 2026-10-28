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

"""Unit tests for LdapClient logic that needs no directory: DN derivation from the
shared base-DN overrides, and the single-server / master→replica endpoint
selection + write failover (SPECIFICATION.md §1.1, §3)."""
import pytest

from ldap_manager.config import Settings
from ldap_manager.failover import CircuitBreaker, MasterUnavailable
from ldap_manager.ldap_client import (LdapClient, _split_dn, _tenant_from_role_dn,
                                      _uid_from_dn)


def _client(**over) -> LdapClient:
    s = Settings(
        ldap_endpoint="ldap://master:389",
        ldap_user_base="ou=people,dc=x,dc=y",
        ldap_tenant_base="ou=tenants,dc=x,dc=y",
        **over,
    )
    return LdapClient(s)


def test_dns_derive_from_overridden_bases():
    c = _client()
    assert c.user_dn("alice@x") == "uid=alice@x,ou=people,dc=x,dc=y"
    assert c.tenant_dn("acme") == "ou=acme,ou=tenants,dc=x,dc=y"
    assert c.role_dn("acme", "editors") == "cn=editors,ou=acme,ou=tenants,dc=x,dc=y"
    assert c.admin_group_dn("acme") == "cn=administrators,ou=acme,ou=tenants,dc=x,dc=y"


def test_uid_from_dn():
    assert _uid_from_dn("uid=bob@x,ou=people,dc=x,dc=y") == "bob@x"


def test_uid_from_dn_unescapes_so_it_round_trips_back_into_user_dn():
    c = _client()
    dn = c.user_dn("o'brien,jr@x")            # a comma in the uid is escaped in the DN
    assert _uid_from_dn(dn) == "o'brien,jr@x"
    assert c.user_dn(_uid_from_dn(dn)) == dn


def test_split_dn_keeps_escaped_commas_inside_one_rdn():
    assert _split_dn("uid=a\\,b,ou=people,dc=x") == ["uid=a\\,b", "ou=people", "dc=x"]


def test_tenant_from_role_dn():
    assert _tenant_from_role_dn("cn=editors,ou=acme,ou=tenants,dc=x,dc=y") == "acme"
    assert _tenant_from_role_dn("cn=editors,ou=big\\,co,ou=tenants,dc=x") == "big,co"
    assert _tenant_from_role_dn("uid=bob,ou=people,dc=x") == "people"  # first ou wins


def test_single_server_uses_only_master_for_reads_and_writes():
    c = _client()  # no replica
    assert c._endpoints(write=False) == ["ldap://master:389"]
    assert c._endpoints(write=True) == ["ldap://master:389"]


def test_replicated_reads_prefer_master_then_replica_when_healthy():
    c = _client(ldap_endpoint_replica="ldap://replica:389")
    assert c._endpoints(write=False) == ["ldap://master:389", "ldap://replica:389"]


def test_replicated_reads_use_replica_first_while_master_is_tripped():
    now = [1000.0]
    c = _client(ldap_endpoint_replica="ldap://replica:389", failover_cooldown_s=30)
    c._breaker = CircuitBreaker(30, clock=lambda: now[0])
    c._breaker.trip()  # master down for 30s
    assert c._endpoints(write=False) == ["ldap://replica:389", "ldap://master:389"]
    now[0] += 31      # cooldown elapsed → re-probe master first
    assert c._endpoints(write=False) == ["ldap://master:389", "ldap://replica:389"]


def test_replicated_write_during_cooldown_raises_master_unavailable():
    now = [1000.0]
    c = _client(ldap_endpoint_replica="ldap://replica:389", failover_cooldown_s=30)
    c._breaker = CircuitBreaker(30, clock=lambda: now[0])
    c._breaker.trip()
    with pytest.raises(MasterUnavailable):
        c._endpoints(write=True)   # writes never fall back to a replica


def test_dn_under():
    from ldap_manager.ldap_client import _dn_under

    base = "ou=people,dc=x,dc=y"
    assert _dn_under("uid=bob,ou=people,dc=x,dc=y", base)
    assert _dn_under("UID=bob, OU=People,DC=x,DC=y", base)
    assert not _dn_under("uid=svc-csai,ou=services,dc=x,dc=y", base)
    assert not _dn_under(base, base)
    assert not _dn_under("uid=bob,ou=people,dc=other,dc=y", base)


def test_roster_leaves_out_service_accounts_but_keeps_orphaned_users():
    # LoqSmyth, 2026-10-12: the tenant's file_services group carries the four
    # svc-* workers (ou=services), which showed in Users as orphaned stubs.
    from contextlib import contextmanager

    class _Attr:
        def __init__(self, v):
            self.value, self.values = v, v if isinstance(v, list) else [v]

    class _Entry(dict):
        def __getitem__(self, k):
            return _Attr(dict.__getitem__(self, k))

    class _Conn:
        entries = [
            _Entry(cn="administrators", member=["uid=james,ou=people,dc=x,dc=y"]),
            _Entry(cn="file_services", member=[
                "uid=svc-csai,ou=services,dc=x,dc=y",
                "uid=svc-difference,ou=services,dc=x,dc=y"]),
            _Entry(cn="editors", member=["uid=gone@x,ou=people,dc=x,dc=y"]),
        ]

        def search(self, *a, **k):
            return True

    c = _client()
    c._session = contextmanager(lambda write: (yield _Conn()))
    c._fetch_users = lambda conn, uids: {
        "james": {"uid": "james", "email": "james@x", "display_name": "James", "dn": "uid=james,ou=people,dc=x,dc=y"}}
    roster = {u["uid"]: u for u in c.list_tenant_users("loqsmyth")}
    assert set(roster) == {"james", "gone@x"}
    assert roster["gone@x"]["orphaned"] and not roster["james"]["orphaned"]
