"""Outbound email: SMTP delivery + safe template rendering (SPECIFICATION.md §5).

Rendering is **placeholder substitution only** — no arbitrary code — so a tenant
admin can customize copy without a code-execution surface. The security-sensitive
``invite_link`` / ``reset_link`` are always built by the service.
"""
from __future__ import annotations

import html
import re
import smtplib
from email.message import EmailMessage

from .config import Settings

_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def render(template_body: str, values: dict[str, str]) -> str:
    """Substitute ``{{key}}`` placeholders with HTML-escaped values. Unknown
    placeholders render empty (they are rejected at save-time by the template
    store, so this is defensive)."""
    def repl(m: "re.Match[str]") -> str:
        return html.escape(str(values.get(m.group(1), "")))
    return _PLACEHOLDER.sub(repl, template_body or "")


def placeholders_in(body: str) -> set[str]:
    return set(_PLACEHOLDER.findall(body or ""))


def to_plain_text(html_body: str) -> str:
    """Very small HTML→text fallback for the multipart alternative."""
    text = re.sub(r"<br\s*/?>", "\n", html_body or "", flags=re.I)
    text = re.sub(r"</p\s*>", "\n\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


class Mailer:
    def __init__(self, settings: Settings):
        self.s = settings

    @property
    def enabled(self) -> bool:
        return bool(self.s.smtp_host and self.s.smtp_from)

    def send(self, to: str, subject: str, html_body: str) -> None:
        if not self.enabled:
            raise RuntimeError("SMTP is not configured")
        msg = EmailMessage()
        msg["From"] = self.s.smtp_from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(to_plain_text(html_body))
        msg.add_alternative(html_body, subtype="html")
        with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=10) as smtp:
            try:
                smtp.starttls()
            except smtplib.SMTPException:
                pass  # server without STARTTLS (dev)
            if self.s.smtp_user:
                smtp.login(self.s.smtp_user, self.s.smtp_password)
            smtp.send_message(msg)
