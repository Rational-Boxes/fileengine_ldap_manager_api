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

"""Request/response models for the API (SPECIFICATION.md §7)."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# --- roles ---
class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class MemberAdd(BaseModel):
    uid: str


class RoleOut(BaseModel):
    name: str
    dn: str
    member_count: int


# --- users (admin) ---
class UserCreate(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=128)
    # At least one role is REQUIRED. Membership of a tenant IS holding >=1 group
    # under its ou (getTenantsForUser), so a user created with no role would not be
    # a member of the tenant at all — an account that never appears on the roster
    # and cannot reach the tenant. Creating a user in a tenant and granting them a
    # role here are the same act; there is no role-less member to create.
    roles: list[str] = Field(min_length=1)

    @field_validator("roles")
    @classmethod
    def _at_least_one_real_role(cls, v: list[str]) -> list[str]:
        cleaned = [r.strip() for r in v if r and r.strip()]
        if not cleaned:
            raise ValueError("at least one role is required (a user with no role is "
                             "not a member of the tenant)")
        return cleaned


class UserOut(BaseModel):
    uid: str
    email: str
    display_name: str = ""
    in_this_tenant: Optional[bool] = None


class RosterUserOut(BaseModel):
    """One row of the tenant roster (§6.1) — the tenant's own membership, so the
    roles held *here* come with it. ``orphaned`` marks a role member whose global
    user entry no longer exists."""
    uid: str
    email: str
    display_name: str = ""
    roles: list[str] = Field(default_factory=list)
    is_admin: bool = False
    orphaned: bool = False


class AdminUserDetail(BaseModel):
    """A tenant member's profile as an admin sees it. ``other_tenant_count`` is a
    count, never the names: which *other* tenants a user belongs to is not this
    tenant admin's business, but the number is what makes the delete guard
    explicable ("belongs to 2 other tenants")."""
    uid: str
    email: str
    display_name: str = ""
    given_name: str = ""
    surname: str = ""
    avatar_url: str = ""
    tenant: str = ""
    roles: list[str] = Field(default_factory=list)
    is_admin: bool = False
    other_tenant_count: int = 0
    can_delete_account: bool = False


class UserRolesUpdate(BaseModel):
    """The complete set of roles the user should hold in this tenant — the server
    diffs against what they hold now, so the client never has to."""
    roles: list[str] = Field(default_factory=list)


class UserRemoveOut(BaseModel):
    uid: str
    scope: str                      # "tenant" | "system"
    roles_removed: list[str] = Field(default_factory=list)
    account_deleted: bool = False


# --- self-service profile (/v1/me) ---
class ProfileOut(BaseModel):
    uid: str
    email: str
    display_name: str = ""
    given_name: str = ""
    surname: str = ""
    avatar_url: str = ""
    tenant: str = ""
    roles: list[str] = Field(default_factory=list)


class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    given_name: Optional[str] = None
    surname: Optional[str] = None
    avatar_url: Optional[str] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


# --- email templates ---
class TemplateOut(BaseModel):
    kind: str
    subject: str
    body: str
    customized: bool


class TemplateUpdate(BaseModel):
    subject: str = Field(min_length=1)
    body: str = Field(min_length=1)


# --- public: invite / reset ---
class InviteAccept(BaseModel):
    token: str
    password: str


class ResetRequest(BaseModel):
    email: EmailStr


class ResetConfirm(BaseModel):
    token: str
    password: str
