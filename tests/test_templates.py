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

"""Unit tests for email templates: default fallback (no DB), placeholder
validation, and safe rendering (SPECIFICATION.md §5.1)."""
import pytest

from ldap_manager.config import Settings
from ldap_manager.email import render
from ldap_manager.templates import (ACCESS_GRANTED, DEFAULTS, NEW_USER, PASSWORD_RESET,
                                     TemplateError, TemplateStore, validate)


def test_defaults_only_use_allowed_placeholders():
    # every placeholder in each built-in default must be in that kind's allow-set
    for kind, tmpl in DEFAULTS.items():
        validate(kind, tmpl.subject, tmpl.body)  # must not raise


def test_validate_rejects_unknown_placeholder():
    with pytest.raises(TemplateError):
        validate(NEW_USER, "hi", "link {{password}}")  # password not allowed


def test_validate_rejects_unknown_kind():
    with pytest.raises(TemplateError):
        validate("nope", "s", "b")


def test_store_without_db_serves_the_default_uncustomized():
    store = TemplateStore(Settings())  # no DATABASE_URL
    assert store.enabled is False
    t = store.get("acme", ACCESS_GRANTED)
    assert t.customized is False
    assert t.subject == DEFAULTS[ACCESS_GRANTED].subject


def test_store_put_without_db_raises():
    store = TemplateStore(Settings())
    with pytest.raises(RuntimeError):
        store.put("acme", NEW_USER, "s", "b")


def test_render_substitutes_and_escapes():
    out = render("Hi {{display_name}} <{{email}}>", {"display_name": "A&B", "email": "x@y"})
    assert "A&amp;B" in out and "x@y" in out


def test_password_reset_is_system_level_kind():
    # present as a default + allow-set, but not a tenant-editable kind
    from ldap_manager.templates import TENANT_KINDS
    assert PASSWORD_RESET in DEFAULTS
    assert PASSWORD_RESET not in TENANT_KINDS
