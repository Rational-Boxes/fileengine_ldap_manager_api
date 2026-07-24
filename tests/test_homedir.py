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

"""Home-folder provisioning: find Users, create Users/<uid>, and set owner-full +
everyone-deny. The bridge HTTP layer (_request) is stubbed."""
import pytest

from ldap_manager.homedir import FULL_CONTROL, HomeProvisioner, HomeProvisionError


def _provisioner(responses):
    hp = HomeProvisioner("http://bridge")
    calls = []

    def fake(method, path, token, tenant, body=None):
        calls.append((method, path, body))
        return responses.pop(0)

    hp._request = fake  # type: ignore[assignment]
    hp.calls = calls    # type: ignore[attr-defined]
    return hp


def test_creates_home_and_sets_private_acl():
    hp = _provisioner(
        [(200, {"entries": [{"uid": "U", "name": "Users"}]}),   # find Users under root
         (201, {"uid": "H"})]                                    # mkdir Users/<uid>
        + [(204, None)] * len(FULL_CONTROL)                      # one grant per permission
        + [(204, None)]                                          # deny everyone
    )
    assert hp.provision("tok", "acme", "alice@x") == "H"
    grant_calls = hp.calls[2:2 + len(FULL_CONTROL)]
    _, deny_path, deny = hp.calls[2 + len(FULL_CONTROL)]
    # Owner is granted every permission (incl. write), on the home folder.
    assert {c[2]["permission"] for c in grant_calls} == set(FULL_CONTROL)
    assert "w" in {c[2]["permission"] for c in grant_calls}
    assert all(c[2]["principal"] == "alice@x" and c[2]["effect"] == "allow" for c in grant_calls)
    assert all(c[1] == "/v1/nodes/H/permissions" for c in grant_calls)
    assert deny == {"principal": "everyone", "permission": "r", "effect": "deny"}
    assert deny_path == "/v1/nodes/H/permissions"


def test_idempotent_reuses_existing_home():
    hp = _provisioner(
        [(200, {"entries": [{"uid": "U", "name": "Users"}]}),    # find Users
         (409, {"error": "exists"}),                             # mkdir conflicts
         (200, {"entries": [{"uid": "H", "name": "alice@x"}]})]   # find existing home
        + [(204, None)] * len(FULL_CONTROL) + [(204, None)]      # grants + deny
    )
    assert hp.provision("tok", "acme", "alice@x") == "H"


def test_creates_users_folder_when_missing():
    hp = _provisioner(
        [(200, {"entries": []}),   # find Users under root -> missing
         (201, {"uid": "U"}),      # create Users
         (201, {"uid": "H"})]      # mkdir the home folder
        + [(204, None)] * len(FULL_CONTROL) + [(204, None)]  # grants + deny
    )
    assert hp.provision("tok", "acme", "alice@x") == "H"
    assert hp.calls[1] == ("POST", "/v1/dirs/root", {"name": "Users"})  # created on first use


def test_users_creation_failure_raises():
    hp = _provisioner([
        (200, {"entries": []}),      # no Users
        (403, {"error": "denied"}),  # create Users fails
        (200, {"entries": []}),      # re-find still missing
    ])
    with pytest.raises(HomeProvisionError):
        hp.provision("tok", "acme", "alice@x")


def test_acl_failure_raises():
    hp = _provisioner([
        (200, {"entries": [{"uid": "U", "name": "Users"}]}),
        (201, {"uid": "H"}),
        (403, {"error": "denied"}),  # grant fails
        (204, None),
    ])
    with pytest.raises(HomeProvisionError):
        hp.provision("tok", "acme", "alice@x")


def test_disabled_without_bridge_url():
    hp = HomeProvisioner("")
    assert hp.enabled is False
    with pytest.raises(HomeProvisionError):
        hp.provision("tok", "acme", "alice@x")
