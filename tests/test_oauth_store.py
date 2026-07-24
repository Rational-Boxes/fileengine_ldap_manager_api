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

"""Unit tests for the OAuth client-registry crypto/logic core (offline — no DB).

The Postgres-backed store methods are exercised by the E2E suite (test_oauth_e2e)."""
import base64
import hashlib

import pytest

from ldap_manager import oauth_store as os_


def test_client_id_and_secret_shapes():
    cid, sec = os_.generate_client_id(), os_.generate_secret()
    assert cid.startswith("feoc_") and len(cid) > 12
    assert sec.startswith("feocs_") and len(sec) > 20
    assert os_.generate_client_id() != cid and os_.generate_secret() != sec


def test_secret_hash_and_verify_roundtrip():
    pepper = "pep-123"
    blob = os_.hash_secret(pepper, "feocs_abc")
    assert isinstance(blob, bytes) and b"feocs_abc" not in blob
    assert os_.secret_matches(pepper, "feocs_abc", blob) is True
    assert os_.secret_matches(pepper, "feocs_wrong", blob) is False
    assert os_.secret_matches("other-pepper", "feocs_abc", blob) is False


def test_hash_requires_pepper():
    with pytest.raises(RuntimeError):
        os_.hash_secret("", "x")


def test_pkce_s256_matches_and_rejects():
    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert os_.verify_pkce(verifier, challenge, "S256") is True
    assert os_.verify_pkce(verifier, challenge, "s256") is True  # method case-insensitive
    assert os_.verify_pkce("wrong", challenge, "S256") is False
    assert os_.verify_pkce("", challenge, "S256") is False
    assert os_.verify_pkce(verifier, "", "S256") is False


def test_pkce_plain():
    assert os_.verify_pkce("xyz", "xyz", "plain") is True
    assert os_.verify_pkce("xyz", "abc", "plain") is False


def test_normalize_list_filters_to_allowed_and_stable_order():
    assert os_.normalize_list(["refresh_token", "authorization_code", "bogus"],
                              os_.GRANT_TYPES) == ["authorization_code", "refresh_token"]
    assert os_.normalize_list([], os_.GRANT_TYPES) == []
    assert os_.normalize_list(["client_credentials"], os_.GRANT_TYPES) == ["client_credentials"]
