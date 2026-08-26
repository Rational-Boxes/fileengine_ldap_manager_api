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

"""Every outbound email must render its SUBJECT, not just its body.

Three send paths passed ``tmpl.subject`` straight to the mailer, so the stock
invitation went out titled "You've been invited to {{tenant}}". It survived
because the two paths an administrator uses to CHECK a template — preview and
send-test — both rendered correctly, so the surface used for verification was
the one surface that was not broken.
"""
import re

import pytest

from ldap_manager import email as email_mod
from ldap_manager.templates import DEFAULTS, NEW_USER, ACCESS_GRANTED, PASSWORD_RESET

# A leftover placeholder is the whole failure mode, in either part.
UNRENDERED = re.compile(r"\{\{\s*[a-z_]+\s*\}\}")


class FakeMailer:
    def __init__(self):
        self.sent = []
        self.enabled = True

    def send(self, to, subject, body):
        self.sent.append({"to": to, "subject": subject, "body": body})


def test_render_subject_substitutes():
    out = email_mod.render_subject("Invited to {{tenant}}", {"tenant": "acme"})
    assert out == "Invited to acme"
    assert not UNRENDERED.search(out)


def test_a_subject_is_not_html_and_is_not_escaped():
    """render() escapes for an HTML body. In a subject that is not safety, it is
    corruption the recipient sees in their inbox."""
    assert email_mod.render_subject("To {{tenant}}", {"tenant": "Smith & Co"}) == "To Smith & Co"
    assert email_mod.render_subject("Hi {{display_name}}", {"display_name": "O'Brien"}) == "Hi O'Brien"
    # The body keeps escaping, because there it IS the safety measure.
    assert "&amp;" in email_mod.render("<p>{{tenant}}</p>", {"tenant": "Smith & Co"})


def test_a_value_cannot_break_out_of_the_subject_header():
    """Header injection. EmailMessage refuses a header with CR/LF, so this is not
    exploitable — but it refuses by RAISING, and two send sites swallow
    exceptions, so the practical effect would be an email that silently never
    arrives."""
    out = email_mod.render_subject("To {{tenant}}", {"tenant": "acme\r\nBcc: evil@x.com"})
    assert "\r" not in out and "\n" not in out
    assert "Bcc:" in out          # folded into the subject, not a new header
    # ...and the result is now a header EmailMessage will accept.
    from email.message import EmailMessage
    m = EmailMessage()
    m["Subject"] = out            # must not raise


def test_the_injected_text_stays_inside_the_subject_header():
    """The payload is not removed — it is DEFANGED. It stays part of the subject
    (where it is merely odd-looking text) instead of becoming a header of its
    own, which is the difference that matters."""
    from email import message_from_string
    from email.message import EmailMessage

    m = EmailMessage()
    m["From"] = "a@x.com"
    m["To"] = "b@x.com"
    m["Subject"] = email_mod.render_subject("To {{tenant}}", {"tenant": "x\r\nBcc: y@z.com"})

    parsed = message_from_string(m.as_string())
    assert parsed["Bcc"] is None                    # no header was injected
    assert "Bcc: y@z.com" in parsed["Subject"]      # it is just subject text


def test_an_unrendered_subject_is_detectable():
    """Guards the guard: the regex must actually catch the bug it exists for."""
    assert UNRENDERED.search(DEFAULTS[NEW_USER].subject)
    assert UNRENDERED.search(DEFAULTS[ACCESS_GRANTED].subject)


@pytest.mark.parametrize("kind, ctx", [
    (NEW_USER, {"display_name": "Ada", "email": "ada@x.com", "tenant": "acme",
                "invite_link": "https://x/invite?token=t", "expires": "48h",
                "inviter": "root@x.com", "roles": "editors"}),
    (ACCESS_GRANTED, {"display_name": "Ada", "email": "ada@x.com", "tenant": "acme",
                      "app_link": "https://x", "inviter": "root@x.com", "roles": "editors"}),
    (PASSWORD_RESET, {"display_name": "Ada", "email": "ada@x.com",
                      "reset_link": "https://x/reset?token=t", "expires": "2h"}),
])
def test_every_stock_template_renders_clean_in_both_parts(kind, ctx):
    tmpl = DEFAULTS[kind]
    subject = email_mod.render_subject(tmpl.subject, ctx)
    body = email_mod.render(tmpl.body, ctx)
    assert not UNRENDERED.search(subject), f"{kind} subject: {subject}"
    assert not UNRENDERED.search(body), f"{kind} body"


def test_the_tenant_actually_reaches_the_invitation_subject():
    subject = email_mod.render_subject(DEFAULTS[NEW_USER].subject, {"tenant": "acme"})
    assert "acme" in subject


def test_no_send_site_passes_a_raw_subject():
    """Static guard over the routers.

    The bug was one missing render() call repeated at three call sites, and the
    natural way to add a fourth email is to copy one of them. Reading the source
    is crude, but it is the only check that fails for a send path nobody thought
    to write a test for."""
    import pathlib

    routers = pathlib.Path(email_mod.__file__).parent / "routers"
    offenders = []
    for path in routers.glob("*.py"):
        src = path.read_text()
        for m in re.finditer(r"mailer\.send\(([^)]*)", src, re.S):
            args = m.group(1)
            # Second argument is the subject. Either rendered inline, or a local
            # that was rendered just above (twofa.py builds `subject` first).
            parts = [a.strip() for a in args.split(",")]
            if len(parts) < 2:
                continue
            subject_arg = parts[1]
            if "render_subject(" in args or re.fullmatch(r"subject", subject_arg):
                continue
            offenders.append(f"{path.name}: {subject_arg}")
    assert not offenders, f"subject passed unrendered: {offenders}"
