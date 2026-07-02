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
