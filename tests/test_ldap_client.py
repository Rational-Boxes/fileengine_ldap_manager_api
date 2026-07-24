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
from ldap_manager.ldap_client import LdapClient, _uid_from_dn


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
