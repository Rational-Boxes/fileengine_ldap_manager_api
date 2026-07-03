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


def test_missing_users_folder_raises():
    hp = _provisioner([(200, {"entries": []})])  # no Users folder
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
