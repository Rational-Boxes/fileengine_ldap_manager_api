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

"""Per-tenant email templates (SPECIFICATION.md §5.1).

Two tenant-customizable kinds (``new_user``, ``access_granted``) plus a
system-level ``password_reset`` default. Custom templates persist in Postgres,
keyed by ``(tenant, kind)``; a missing row falls back to the built-in default
below. Allowed placeholders per kind are validated on save.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from .config import Settings
from .email import placeholders_in

try:
    import psycopg  # type: ignore
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore

NEW_USER = "new_user"
ACCESS_GRANTED = "access_granted"
PASSWORD_RESET = "password_reset"   # system-level (not per-tenant)
TWO_FA_EMAIL = "2fa_email_code"     # tenant-customizable one-time 2FA email code

# Allowed placeholders per kind (§5.1 / §5.2). A PUT with any others is rejected.
ALLOWED: dict[str, set[str]] = {
    NEW_USER: {"display_name", "email", "tenant", "invite_link", "expires", "inviter", "roles"},
    ACCESS_GRANTED: {"display_name", "email", "tenant", "app_link", "inviter", "roles"},
    PASSWORD_RESET: {"display_name", "email", "reset_link", "expires"},
    TWO_FA_EMAIL: {"display_name", "email", "code", "expires"},
}

TENANT_KINDS = (NEW_USER, ACCESS_GRANTED, TWO_FA_EMAIL)


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
    TWO_FA_EMAIL: Template(
        subject="Your sign-in code",
        body=(
            "<p>Hi {{display_name}},</p>"
            "<p>Your one-time sign-in code is <strong>{{code}}</strong>."
            " It expires in {{expires}}.</p>"
            "<p>If you didn't try to sign in, change your password immediately.</p>"
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


_DDL = """
CREATE TABLE IF NOT EXISTS email_templates (
    tenant   TEXT NOT NULL,
    kind     TEXT NOT NULL,
    subject  TEXT NOT NULL,
    body     TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, kind)
)
"""


class TemplateStore:
    """Postgres-backed per-tenant template store (§5.1), with built-in defaults.

    A missing row falls back to the built-in default. When ``database_url`` is
    empty the store serves only defaults and writes raise, so the app runs without
    a DB in development.
    """

    def __init__(self, settings: Settings):
        self.s = settings
        self._lock = threading.Lock()
        self._ddl_done = False

    @property
    def enabled(self) -> bool:
        return bool(self.s.database_url) and psycopg is not None

    def _connect(self):
        if not self.enabled:
            raise RuntimeError("template store (DATABASE_URL) not configured")
        conn = psycopg.connect(self.s.database_url)
        if not self._ddl_done:
            with self._lock:
                if not self._ddl_done:
                    with conn.cursor() as cur:
                        cur.execute(_DDL)
                    conn.commit()
                    self._ddl_done = True
        return conn

    def get(self, tenant: str, kind: str) -> Template:
        """Custom row if present, else the built-in default (not-customized)."""
        if kind not in ALLOWED:
            raise TemplateError(f"unknown template kind: {kind}")
        if self.enabled:
            with self._connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT subject, body FROM email_templates WHERE tenant=%s AND kind=%s",
                    (tenant, kind),
                )
                row = cur.fetchone()
                if row:
                    return Template(subject=row[0], body=row[1], customized=True)
        return DEFAULTS[kind]

    def put(self, tenant: str, kind: str, subject: str, body: str) -> None:
        validate(kind, subject, body)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO email_templates (tenant, kind, subject, body)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant, kind)
                DO UPDATE SET subject = EXCLUDED.subject, body = EXCLUDED.body,
                              updated_at = now()
                """,
                (tenant, kind, subject, body),
            )
            conn.commit()

    def revert(self, tenant: str, kind: str) -> None:
        """Delete the custom row → fall back to default (no-op if none)."""
        if not self.enabled:
            return
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM email_templates WHERE tenant=%s AND kind=%s", (tenant, kind))
            conn.commit()
