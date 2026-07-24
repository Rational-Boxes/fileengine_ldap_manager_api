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
