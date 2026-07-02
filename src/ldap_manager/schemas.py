"""Request/response models for the API (SPECIFICATION.md §7)."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, EmailStr, Field


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
    roles: list[str] = Field(default_factory=list)


class UserOut(BaseModel):
    uid: str
    email: str
    display_name: str = ""
    in_this_tenant: Optional[bool] = None


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
