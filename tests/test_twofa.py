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

"""Unit tests for the 2FA crypto/logic core (offline — no DB/LDAP/SMTP).

Covers the RFC 4226/6238 TOTP implementation (known-answer vectors), skew-window
verification, recovery codes, at-rest secret encryption round-trip, and the §4.8
method-availability policy.
"""
from types import SimpleNamespace

from cryptography.fernet import Fernet

from ldap_manager import twofa


# RFC 4226 Appendix D: secret = ASCII "12345678901234567890" (base32 below),
# HOTP(counter) for counters 0..2 = 755224, 287082, 359152.
RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_hotp_rfc4226_known_answers():
    assert twofa._hotp(RFC_SECRET_B32, 0) == "755224"
    assert twofa._hotp(RFC_SECRET_B32, 1) == "287082"
    assert twofa._hotp(RFC_SECRET_B32, 2) == "359152"


def test_totp_at_uses_time_step():
    # counter = floor(t / 30); t=0 -> counter 0 -> 755224; t=59 -> counter 1 -> 287082
    assert twofa.totp_at(RFC_SECRET_B32, 0) == "755224"
    assert twofa.totp_at(RFC_SECRET_B32, 59) == "287082"


def test_totp_verify_window_and_rejection():
    t = 1000.0
    good = twofa.totp_at(RFC_SECRET_B32, t)
    assert twofa.totp_verify(RFC_SECRET_B32, good, for_time=t)
    # within ±1 step
    assert twofa.totp_verify(RFC_SECRET_B32, good, for_time=t + 25)   # same step
    assert twofa.totp_verify(RFC_SECRET_B32, twofa.totp_at(RFC_SECRET_B32, t - 30), for_time=t)
    assert twofa.totp_verify(RFC_SECRET_B32, twofa.totp_at(RFC_SECRET_B32, t + 30), for_time=t)
    # outside the window
    assert not twofa.totp_verify(RFC_SECRET_B32, twofa.totp_at(RFC_SECRET_B32, t + 120), for_time=t)
    # garbage / wrong
    assert not twofa.totp_verify(RFC_SECRET_B32, "000000", for_time=t)
    assert not twofa.totp_verify(RFC_SECRET_B32, "notacode", for_time=t)
    assert not twofa.totp_verify(RFC_SECRET_B32, "", for_time=t)


def test_random_secret_is_valid_base32():
    s = twofa.random_secret()
    assert len(s) >= 32
    # a fresh secret must produce a verifiable code
    t = 42.0
    assert twofa.totp_verify(s, twofa.totp_at(s, t), for_time=t)


def test_provisioning_uri_shape():
    uri = twofa.provisioning_uri("JBSWY3DPEHPK3PXP", "james@rationalboxes.com", "FileEngine")
    assert uri.startswith("otpauth://totp/FileEngine:james%40rationalboxes.com?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=FileEngine" in uri and "algorithm=SHA1" in uri
    assert "digits=6" in uri and "period=30" in uri


def test_recovery_codes_generate_and_hash():
    codes = twofa.generate_recovery_codes(10)
    assert len(codes) == 10 and len(set(codes)) == 10
    for c in codes:
        assert len(c) == 11 and c[5] == "-"
    # hashing is format/case-insensitive and matches the emitted code
    h = twofa.hash_recovery_code(codes[0])
    assert twofa.hash_recovery_code(codes[0].lower().replace("-", "")) == h
    assert twofa.hash_recovery_code(codes[1]) != h


def test_secret_encryption_round_trip():
    key = Fernet.generate_key().decode()
    blob = twofa.encrypt_secret(key, RFC_SECRET_B32)
    assert bytes(blob) != RFC_SECRET_B32.encode()          # actually encrypted
    assert twofa.decrypt_secret(key, blob) == RFC_SECRET_B32
    # wrong key cannot decrypt
    other = Fernet.generate_key().decode()
    try:
        twofa.decrypt_secret(other, blob)
        assert False, "decrypt with wrong key must fail"
    except Exception:
        pass


def test_method_policy_intersection():
    assert twofa.parse_methods("totp, email ,WEBAUTHN") == ["totp", "email", "webauthn"]
    # deployment cap includes email; tenant None inherits the cap
    assert twofa.effective_methods(["totp", "email"], None) == ["totp", "email"]
    # tenant restricts to totp only
    assert twofa.effective_methods(["totp", "email"], ["totp"]) == ["totp"]
    # deployment cap forbids email -> tenant cannot re-enable it
    assert twofa.effective_methods(["totp"], ["totp", "email"]) == ["totp"]
    # unknown methods are dropped
    assert twofa.effective_methods(["totp", "sms"], None) == ["totp"]
