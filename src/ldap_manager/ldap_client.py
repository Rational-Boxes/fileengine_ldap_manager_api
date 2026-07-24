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

"""LDAP access layer (SPECIFICATION.md §1.1, §3) — ldap3 implementation.

Owns the connection strategy — **single server or master→replica**, driven by the
same ``FILEENGINE_LDAP_*`` config the bridges read — and all directory reads and
writes with the privileged service bind. DNs are always derived from
``ldap_user_base`` / ``ldap_tenant_base`` (never hard-coded).

- **Reads** may use the replica, with primary failover + cooldown.
- **Writes** always target the writable master; while the master is down (breaker
  tripped) a write raises ``MasterUnavailable`` → HTTP 503.

Kept import-safe when ``ldap3`` isn't installed so unit tests can import the
package without the dependency; the operations then raise at call time.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from .config import Settings
from .failover import CircuitBreaker, MasterUnavailable

try:
    import ldap3  # type: ignore
    from ldap3 import BASE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE  # type: ignore
    from ldap3.core.exceptions import LDAPException  # type: ignore
    from ldap3.utils.conv import escape_filter_chars  # type: ignore
except Exception:  # pragma: no cover
    ldap3 = None  # type: ignore

    def escape_filter_chars(v):  # type: ignore
        return v

__all__ = ["LdapClient", "LdapError", "MasterUnavailable", "LdapUser", "LdapRole"]

USER_OBJECT_CLASSES = ["inetOrgPerson", "organizationalPerson", "person", "top"]
GROUP_OBJECT_CLASSES = ["groupOfNames", "top"]


class LdapError(RuntimeError):
    """A directory operation failed; ``description`` carries the ldap3 result name
    (e.g. ``entryAlreadyExists``, ``noSuchObject``) so callers can map to HTTP."""

    def __init__(self, result: Optional[dict]):
        self.result = result or {}
        super().__init__(self.result.get("message") or self.result.get("description") or "LDAP error")

    @property
    def description(self) -> str:
        return self.result.get("description", "")


class LdapUser(dict):
    """A global user entry: ``uid, email, display_name, given_name, surname, avatar_url``."""


class LdapRole(dict):
    """A tenant role group: ``name, dn, member_count``."""


class LdapClient:
    def __init__(self, settings: Settings):
        self.s = settings
        self._breaker = CircuitBreaker(settings.failover_cooldown_s)

    # ---- DN helpers (derived from the shared base-DN overrides) ----
    def user_dn(self, uid: str) -> str:
        return f"uid={_escape_dn(uid)},{self.s.ldap_user_base}"

    def tenant_dn(self, tenant: str) -> str:
        return f"ou={_escape_dn(tenant)},{self.s.ldap_tenant_base}"

    def role_dn(self, tenant: str, role: str) -> str:
        return f"cn={_escape_dn(role)},{self.tenant_dn(tenant)}"

    def admin_group_dn(self, tenant: str) -> str:
        return self.role_dn(tenant, "administrators")

    # ---- connection strategy (§1.1) ----
    def _endpoints(self, write: bool) -> list[str]:
        master = self.s.ldap_endpoint
        if write:
            if self.s.ldap_replicated and self._breaker.is_degraded():
                raise MasterUnavailable("LDAP master unavailable (failover cooldown)")
            return [master]
        if not self.s.ldap_replicated:
            return [master]
        replica = self.s.ldap_endpoint_replica
        return [master, replica] if self._breaker.should_try_primary() else [replica, master]

    def _open(self, write: bool):
        if ldap3 is None:  # pragma: no cover
            raise RuntimeError("ldap3 is not installed")
        last: Optional[Exception] = None
        for url in self._endpoints(write):
            is_master = url == self.s.ldap_endpoint
            try:
                conn = ldap3.Connection(
                    ldap3.Server(url, get_info=ldap3.NONE, connect_timeout=5),
                    user=self.s.ldap_bind_dn, password=self.s.ldap_bind_password,
                    auto_bind=True, receive_timeout=10,
                )
                if is_master:
                    self._breaker.reset()
                return conn
            except LDAPException as e:  # includes socket-open + bind errors
                last = e
                if is_master:
                    self._breaker.trip()
        if write:
            raise MasterUnavailable(f"LDAP master unavailable: {last}")
        raise RuntimeError(f"LDAP unavailable: {last}")

    @contextmanager
    def _session(self, write: bool) -> Iterator["ldap3.Connection"]:
        conn = self._open(write)
        try:
            yield conn
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    @staticmethod
    def _ok(conn, ok: bool) -> None:
        if not ok:
            raise LdapError(getattr(conn, "result", None))

    def ping_master(self) -> bool:
        """Cheap reachability probe of the writable master, for ``/readyz`` (§1.1).
        Binds the service account; does not affect the failover breaker."""
        if ldap3 is None:  # pragma: no cover
            return False
        try:
            c = ldap3.Connection(
                ldap3.Server(self.s.ldap_endpoint, get_info=ldap3.NONE, connect_timeout=3),
                user=self.s.ldap_bind_dn, password=self.s.ldap_bind_password,
                auto_bind=True, receive_timeout=5,
            )
            c.unbind()
            return True
        except Exception:
            return False

    def _bind_as(self, dn: str, password: str) -> bool:
        """Verify a user's password by binding as them (change-password §5.3)."""
        if ldap3 is None or not password:  # pragma: no cover
            return False
        try:
            c = ldap3.Connection(
                ldap3.Server(self.s.ldap_endpoint, get_info=ldap3.NONE, connect_timeout=5),
                user=dn, password=password, auto_bind=True, receive_timeout=10,
            )
            c.unbind()
            return True
        except LDAPException:
            return False

    # ---- authorization support (§2, §5-B) ----
    def is_tenant_admin(self, uid: str, tenant: str) -> bool:
        return self._is_member(self.admin_group_dn(tenant), self.user_dn(uid))

    def _is_member(self, group_dn: str, user_dn: str) -> bool:
        with self._session(False) as c:
            found = c.search(group_dn, f"(member={escape_filter_chars(user_dn)})",
                             search_scope=BASE, attributes=[])
            return bool(found) and len(c.entries) > 0

    def is_tenant_member(self, uid: str, tenant: str) -> bool:
        user_dn = escape_filter_chars(self.user_dn(uid))
        with self._session(False) as c:
            found = c.search(self.tenant_dn(tenant),
                             f"(&(objectClass=groupOfNames)(member={user_dn}))",
                             search_scope=SUBTREE, attributes=[])
            return bool(found) and len(c.entries) > 0

    # ---- users (global) ----
    def find_users(self, query: str, limit: int = 20) -> list[LdapUser]:
        q = escape_filter_chars(query)
        filt = f"(&(objectClass=inetOrgPerson)(|(uid={q})(uid={q}*)(mail={q})(mail={q}*)(cn={q}*)))"
        with self._session(False) as c:
            c.search(self.s.ldap_user_base, filt, search_scope=SUBTREE,
                     attributes=["uid", "mail", "cn", "displayName"], size_limit=limit)
            return [self._to_user(e) for e in c.entries]

    def get_user(self, uid: str) -> Optional[LdapUser]:
        q = escape_filter_chars(uid)
        attrs = ["uid", "mail", "cn", "displayName", "givenName", "sn", self.s.ldap_avatar_attr]
        with self._session(False) as c:
            c.search(self.s.ldap_user_base, f"(&(objectClass=inetOrgPerson)(|(uid={q})(mail={q})))",
                     search_scope=SUBTREE, attributes=attrs)
            if not c.entries:
                return None
            return self._to_user(c.entries[0])

    def _to_user(self, entry) -> LdapUser:
        def val(attr: str) -> str:
            v = entry[attr].value if attr in entry else None
            if isinstance(v, (list, tuple)):
                v = v[0] if v else None
            return str(v) if v is not None else ""
        uid = val("uid") or val("mail")
        return LdapUser(
            uid=uid, email=val("mail") or uid,
            display_name=val("displayName") or val("cn"),
            given_name=val("givenName"), surname=val("sn"),
            avatar_url=val(self.s.ldap_avatar_attr),
        )

    def create_user(self, uid: str, email: str, display_name: str) -> None:
        parts = (display_name or "").split()
        sn = parts[-1] if parts else uid
        attrs = {"cn": display_name or uid, "sn": sn, "uid": uid, "mail": email}
        if display_name:
            attrs["displayName"] = display_name
        with self._session(True) as c:
            self._ok(c, c.add(self.user_dn(uid), USER_OBJECT_CLASSES, attrs))

    def set_password(self, uid: str, password: str) -> None:
        with self._session(True) as c:
            self._ok(c, c.extend.standard.modify_password(user=self.user_dn(uid), new_password=password))

    def update_profile(self, uid: str, **fields) -> None:
        attr_map = {
            "display_name": ["displayName", "cn"],
            "given_name": ["givenName"],
            "surname": ["sn"],
            "avatar_url": [self.s.ldap_avatar_attr],
        }
        changes: dict[str, list] = {}
        for key, value in fields.items():
            for attr in attr_map.get(key, []):
                changes[attr] = [(MODIFY_REPLACE, [value] if value else [])]
        if not changes:
            return
        with self._session(True) as c:
            self._ok(c, c.modify(self.user_dn(uid), changes))

    # ---- roles / groups (per tenant) ----
    def list_roles(self, tenant: str) -> list[LdapRole]:
        with self._session(False) as c:
            c.search(self.tenant_dn(tenant), "(objectClass=groupOfNames)",
                     search_scope=LEVEL, attributes=["cn", "member"])
            roles = []
            for e in c.entries:
                members = list(e["member"].values) if "member" in e else []
                real = [m for m in members if not self._is_placeholder(m)]
                roles.append(LdapRole(name=str(e["cn"].value), dn=str(e.entry_dn),
                                      member_count=len(real)))
            return roles

    def create_role(self, tenant: str, name: str) -> None:
        # groupOfNames requires ≥1 member; seed with the service bind DN as a benign
        # placeholder (filtered from member listings, keeps the group valid when the
        # last real member is removed).
        with self._session(True) as c:
            self._ok(c, c.add(self.role_dn(tenant, name), GROUP_OBJECT_CLASSES,
                              {"cn": name, "member": [self.s.ldap_bind_dn]}))

    def delete_role(self, tenant: str, name: str) -> None:
        with self._session(True) as c:
            self._ok(c, c.delete(self.role_dn(tenant, name)))

    def list_members(self, tenant: str, role: str) -> list[str]:
        with self._session(False) as c:
            found = c.search(self.role_dn(tenant, role), "(objectClass=groupOfNames)",
                             search_scope=BASE, attributes=["member"])
            if not found or not c.entries:
                raise LdapError({"description": "noSuchObject", "message": "role not found"})
            members = list(c.entries[0]["member"].values) if "member" in c.entries[0] else []
            return [_uid_from_dn(m) for m in members if not self._is_placeholder(m)]

    def add_member(self, tenant: str, role: str, uid: str) -> None:
        with self._session(True) as c:
            self._ok(c, c.modify(self.role_dn(tenant, role),
                                 {"member": [(MODIFY_ADD, [self.user_dn(uid)])]}))

    def remove_member(self, tenant: str, role: str, uid: str) -> None:
        with self._session(True) as c:
            self._ok(c, c.modify(self.role_dn(tenant, role),
                                 {"member": [(MODIFY_DELETE, [self.user_dn(uid)])]}))

    def _is_placeholder(self, dn: str) -> bool:
        return _dn_eq(dn, self.s.ldap_bind_dn)


# ---- DN utilities ----
def _escape_dn(v: str) -> str:
    out = []
    for ch in v or "":
        if ch in ',+"\\<>;=' or ch == "\x00":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _uid_from_dn(dn: str) -> str:
    rdn = (dn or "").split(",", 1)[0]
    if "=" in rdn:
        return rdn.split("=", 1)[1]
    return dn


def _dn_eq(a: str, b: str) -> bool:
    return (a or "").strip().lower() == (b or "").strip().lower()
