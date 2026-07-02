"""Password complexity policy — the single validator enforced on every
password-set path: invite/account-creation, reset-confirm, and self
change-password (SPECIFICATION.md §5.4). No bypass.
"""
from __future__ import annotations

import string
from dataclasses import dataclass, field
from functools import lru_cache

from .config import PasswordPolicyConfig

_SYMBOLS = set(string.punctuation)


@dataclass
class PolicyResult:
    ok: bool
    unmet: list[str] = field(default_factory=list)   # machine-readable rule keys

    @property
    def message(self) -> str:
        return "Password meets the policy." if self.ok else \
            "Password does not meet the policy: " + ", ".join(self.unmet)


@lru_cache(maxsize=8)
def _load_blocklist(path: str) -> frozenset[str]:
    if not path:
        return frozenset()
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return frozenset(line.strip().lower() for line in f if line.strip())
    except OSError:
        return frozenset()


class PasswordPolicy:
    """Validates a password against the configured rules. ``describe()`` returns
    the active rules for the public ``GET /v1/password-policy`` (for live UI
    validation)."""

    def __init__(self, cfg: PasswordPolicyConfig):
        self.cfg = cfg

    def describe(self) -> dict:
        c = self.cfg
        return {
            "min_length": c.min_length,
            "max_length": c.max_length,
            "require_upper": c.require_upper and c.min_classes == 0,
            "require_lower": c.require_lower and c.min_classes == 0,
            "require_digit": c.require_digit and c.min_classes == 0,
            "require_symbol": c.require_symbol and c.min_classes == 0,
            "min_classes": c.min_classes,
            "forbid_identity_substring": True,
        }

    def validate(self, password: str, *, uid: str = "", display_name: str = "") -> PolicyResult:
        c = self.cfg
        unmet: list[str] = []
        pw = password or ""

        if len(pw) < c.min_length:
            unmet.append("min_length")
        if len(pw) > c.max_length:
            unmet.append("max_length")

        classes = {
            "upper": any(ch.isupper() for ch in pw),
            "lower": any(ch.islower() for ch in pw),
            "digit": any(ch.isdigit() for ch in pw),
            "symbol": any(ch in _SYMBOLS for ch in pw),
        }
        if c.min_classes > 0:
            if sum(classes.values()) < c.min_classes:
                unmet.append("min_classes")
        else:
            if c.require_upper and not classes["upper"]:
                unmet.append("require_upper")
            if c.require_lower and not classes["lower"]:
                unmet.append("require_lower")
            if c.require_digit and not classes["digit"]:
                unmet.append("require_digit")
            if c.require_symbol and not classes["symbol"]:
                unmet.append("require_symbol")

        # Must not contain the account's email local-part / uid or display name.
        low = pw.lower()
        for token in (_local_part(uid), display_name):
            token = (token or "").strip().lower()
            if len(token) >= 3 and token in low:
                unmet.append("forbid_identity_substring")
                break

        if pw.lower() in _load_blocklist(c.blocklist_path):
            unmet.append("blocklisted")

        return PolicyResult(ok=not unmet, unmet=unmet)


def _local_part(uid: str) -> str:
    return uid.split("@", 1)[0] if "@" in (uid or "") else (uid or "")
