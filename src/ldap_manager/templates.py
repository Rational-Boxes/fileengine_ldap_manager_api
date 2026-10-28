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
SHARE_OTP_EMAIL = "share_otp_code"  # one-time code for an outside share-link recipient
TENANT_WELCOME = "tenant_welcome"   # system-level: a new tenant's first administrator

# Allowed placeholders per kind (§5.1 / §5.2). A PUT with any others is rejected.
ALLOWED: dict[str, set[str]] = {
    NEW_USER: {"display_name", "email", "tenant", "invite_link", "expires", "inviter", "roles"},
    ACCESS_GRANTED: {"display_name", "email", "tenant", "app_link", "inviter", "roles"},
    PASSWORD_RESET: {"display_name", "email", "reset_link", "expires"},
    TWO_FA_EMAIL: {"display_name", "email", "code", "expires"},
    # No `display_name`: the recipient has no account here, so there is no name
    # to greet them by. `sender` is the link's creator -- the one piece of
    # context that tells a stranger why an unfamiliar domain is mailing them.
    SHARE_OTP_EMAIL: {"email", "code", "expires", "sender", "sent_at"},
    TENANT_WELCOME: {"display_name", "email", "tenant", "tenant_name", "sign_in_url",
                     "drive_host", "reset_link", "expires"},
}

TENANT_KINDS = (NEW_USER, ACCESS_GRANTED, TWO_FA_EMAIL, SHARE_OTP_EMAIL)


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
    # The recipient of this mail has no account and did not ask us for anything
    # -- they clicked a link someone sent them. So the copy has to do three jobs
    # the 2FA mail does not: say who the link came from, say when the code was
    # issued (a resend invalidates the previous one, so "use the newest" needs a
    # way to tell them apart), and state the deadline plainly, because a silently
    # stale code is indistinguishable from a mistyped one.
    SHARE_OTP_EMAIL: Template(
        # "the file" is wrong for the two folder shapes, and the body already
        # hedges correctly ("a file or folder"). A subject line that contradicts
        # its own body is the kind of small wrongness that makes a legitimate
        # mail read as a phishing attempt -- which is the last impression this
        # particular message can afford.
        subject="Your code for what {{sender}} shared with you",
        body=(
            "<p>Your one-time code is <strong>{{code}}</strong>.</p>"
            "<p>It expires in {{expires}} (sent {{sent_at}}). If you asked for"
            " more than one code, use the one from the newest email.</p>"
            "<p>This code was requested for a file or folder shared with"
            " {{email}} by {{sender}}. If that means nothing to you, ignore this"
            " message -- the code is useless on its own and we will not email"
            " you again unless someone requests another.</p>"
        ),
    ),
    # Sent once, when the deployment has finished building a tenant. System-level,
    # not tenant-customizable: the tenant's own administrators do not exist as
    # editors until this mail has been read.
    #
    # The reset link is offered whether or not the account is new. A new account
    # was created with a random password nobody knows, so the link is the only way
    # in; an existing account keeps its password, and the link is there for
    # whoever does not remember it. The copy says both, rather than implying the
    # recipient has to act.
    TENANT_WELCOME: Template(
        subject="Your workspace {{tenant_name}} is ready",
        body=(
            "<p>Hi {{display_name}},</p>"
            "<p>The workspace <strong>{{tenant_name}}</strong> has been set up and you"
            " are its administrator.</p>"
            "<p><a href=\"{{sign_in_url}}\">Sign in to {{tenant_name}}</a> with"
            " {{email}}.</p>"
            "<p>If this is a new account, or you do not know its password, set one"
            " here first (the link expires in {{expires}}):<br>"
            "<a href=\"{{reset_link}}\">Set your password</a></p>"
            "<p>Getting started:</p>"
            "<ol>"
            "<li>Sign in and turn on two-factor authentication under your profile.</li>"
            "<li>Add your people under <em>Users &amp; Roles</em>. Each gets their own"
            " invitation and a private home folder.</li>"
            "<li>Your files are also reachable as a network drive (WebDAV) at"
            " {{drive_host}}, using a key you create under your profile.</li>"
            "</ol>"
            "<p>If you did not expect this message, you can ignore it; nothing"
            " changes until someone signs in.</p>"
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
