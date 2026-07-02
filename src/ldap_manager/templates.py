"""Per-tenant email templates (SPECIFICATION.md §5.1).

Two tenant-customizable kinds (``new_user``, ``access_granted``) plus a
system-level ``password_reset`` default. Custom templates persist in Postgres,
keyed by ``(tenant, kind)``; a missing row falls back to the built-in default
below. Allowed placeholders per kind are validated on save.
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .email import placeholders_in

NEW_USER = "new_user"
ACCESS_GRANTED = "access_granted"
PASSWORD_RESET = "password_reset"   # system-level (not per-tenant)

# Allowed placeholders per kind (§5.1 / §5.2). A PUT with any others is rejected.
ALLOWED: dict[str, set[str]] = {
    NEW_USER: {"display_name", "email", "tenant", "invite_link", "expires", "inviter", "roles"},
    ACCESS_GRANTED: {"display_name", "email", "tenant", "app_link", "inviter", "roles"},
    PASSWORD_RESET: {"display_name", "email", "reset_link", "expires"},
}

TENANT_KINDS = (NEW_USER, ACCESS_GRANTED)


@dataclass
class Template:
    subject: str
    body: str
    customized: bool = False


DEFAULTS: dict[str, Template] = {
    NEW_USER: Template(
        subject="You've been invited to {{tenant}}",
        body=(
            "<p>Hi {{display_name}},</p>"
            "<p>An account has been created for you on <strong>{{tenant}}</strong>"
            " by {{inviter}}. Set your password to get started:</p>"
            "<p><a href=\"{{invite_link}}\">Set your password</a> (expires {{expires}}).</p>"
            "<p>Roles granted: {{roles}}.</p>"
        ),
    ),
    ACCESS_GRANTED: Template(
        subject="You've been granted access to {{tenant}}",
        body=(
            "<p>Hi {{display_name}},</p>"
            "<p>{{inviter}} has granted you access to <strong>{{tenant}}</strong>"
            " (roles: {{roles}}).</p>"
            "<p><a href=\"{{app_link}}\">Open {{tenant}}</a></p>"
        ),
    ),
    PASSWORD_RESET: Template(
        subject="Reset your password",
        body=(
            "<p>Hi {{display_name}},</p>"
            "<p>We received a request to reset your password. If it was you, use"
            " the link below (expires {{expires}}):</p>"
            "<p><a href=\"{{reset_link}}\">Reset your password</a></p>"
            "<p>If you didn't request this, you can ignore this email.</p>"
        ),
    ),
}


class TemplateError(ValueError):
    pass


def validate(kind: str, subject: str, body: str) -> None:
    """Reject unknown kinds or unsupported placeholders (§5.1)."""
    if kind not in ALLOWED:
        raise TemplateError(f"unknown template kind: {kind}")
    used = placeholders_in(subject) | placeholders_in(body)
    unknown = used - ALLOWED[kind]
    if unknown:
        raise TemplateError("unsupported placeholders: " + ", ".join(sorted(unknown)))


class TemplateStore:
    """Postgres-backed per-tenant template store, with built-in defaults.

    Scaffold: the Postgres CRUD is sketched; when ``database_url`` is empty the
    store serves only defaults (writes raise), so the app runs without a DB in dev.
    """

    def __init__(self, settings: Settings):
        self.s = settings
        # TODO(scaffold): open a psycopg pool; ensure the email_templates table
        # (tenant TEXT, kind TEXT, subject TEXT, body TEXT, PRIMARY KEY(tenant,kind)).

    @property
    def enabled(self) -> bool:
        return bool(self.s.database_url)

    def get(self, tenant: str, kind: str) -> Template:
        """Custom row if present, else the built-in default (marked not-customized)."""
        # TODO(scaffold): SELECT subject, body FROM email_templates WHERE tenant,kind.
        return DEFAULTS[kind]

    def put(self, tenant: str, kind: str, subject: str, body: str) -> None:
        validate(kind, subject, body)
        if not self.enabled:
            raise RuntimeError("template store (DATABASE_URL) not configured")
        # TODO(scaffold): UPSERT into email_templates.

    def revert(self, tenant: str, kind: str) -> None:
        """Delete the custom row → fall back to default."""
        # TODO(scaffold): DELETE FROM email_templates WHERE tenant,kind.
        return None
