"""The authenticated caller's identity, resolved from a bridge token (§2)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Identity:
    """Who is calling, as resolved by the http_bridge introspection endpoint.

    ``roles`` are the caller's already-resolved effective roles for ``tenant``;
    ``is_tenant_admin`` is computed from LDAP group membership of
    ``cn=administrators,ou=<tenant>,<tenant_base>`` (not just the token), see deps.
    """
    user: str
    tenant: str
    roles: list[str] = field(default_factory=list)
    authenticated: bool = True
