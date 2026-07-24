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

"""Unit tests for the password complexity policy (SPECIFICATION.md §5.4)."""
from ldap_manager.config import PasswordPolicyConfig
from ldap_manager.password_policy import PasswordPolicy


def _policy(**kw) -> PasswordPolicy:
    return PasswordPolicy(PasswordPolicyConfig(**kw))


def test_default_policy_accepts_a_strong_password():
    r = _policy().validate("Str0ng!Passw0rd", uid="alex@example.com", display_name="Alex Doe")
    assert r.ok and r.unmet == []


def test_reports_each_unmet_rule():
    r = _policy().validate("short")   # too short, no upper/digit/symbol
    assert not r.ok
    assert "min_length" in r.unmet
    assert {"require_upper", "require_digit", "require_symbol"} <= set(r.unmet)


def test_min_classes_mode_ignores_specific_class_flags():
    # require any 3 of 4 classes; upper+lower+digit satisfies it without a symbol
    r = _policy(min_classes=3, min_length=8).validate("Abcd1234")
    assert r.ok, r.unmet


def test_rejects_password_containing_email_localpart_or_name():
    r = _policy().validate("Alex!12345678", uid="alex@example.com", display_name="Alex Doe")
    assert "forbid_identity_substring" in r.unmet


def test_max_length_enforced():
    r = _policy(max_length=16).validate("A1!" + "a" * 30)
    assert "max_length" in r.unmet


def test_describe_reflects_active_rules():
    d = _policy(min_length=10, require_symbol=False).describe()
    assert d["min_length"] == 10 and d["require_symbol"] is False
