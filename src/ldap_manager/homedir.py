"""Provision a private home folder for a newly-created user.

On user creation we create ``Users/<uid>`` in the acting admin's tenant and set
its ACL so the user has full control and everyone else is denied — a private home
folder. We call the http_bridge REST filesystem API with the ADMIN'S bearer token
(the admin who is creating the user), so the folder is created under their
authority in their tenant. The top-level ``Users`` folder is assumed to exist
(seeded; only system_admin may create in root).

Best-effort: failures are reported to the caller but never block user creation —
the LDAP user is the source of truth; the home folder is a convenience.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

# Full owner control, one letter per ACL grant (the permissions API takes a single
# permission per call): read, write, delete, list-deleted, undelete, view-versions,
# retrieve-version, restore-version, manage-ACL.
FULL_CONTROL = ["r", "w", "d", "l", "u", "v", "b", "s", "m"]
USERS_FOLDER = "Users"


class HomeProvisionError(RuntimeError):
    pass


class HomeProvisioner:
    def __init__(self, bridge_url: str, timeout: float = 5.0):
        self.base_url = (bridge_url or "").rstrip("/")
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def _request(self, method: str, path: str, token: str, tenant: str,
                 body: Optional[dict] = None) -> tuple[int, Optional[dict]]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + token)
        if tenant:
            req.add_header("X-Tenant", tenant)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "ignore")
            try:
                return e.code, json.loads(raw) if raw else None
            except ValueError:
                return e.code, None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise HomeProvisionError(f"bridge unreachable: {e}") from e

    def _find_child(self, parent_uid: str, name: str, token: str, tenant: str) -> Optional[str]:
        status, data = self._request("GET", f"/v1/dirs/{parent_uid}", token, tenant)
        if status != 200 or not isinstance(data, dict):
            return None
        for e in data.get("entries", []):
            if e.get("name") == name:
                return e.get("uid")
        return None

    def provision(self, token: str, tenant: str, uid: str) -> str:
        """Create Users/<uid> (idempotent) and set owner-full + everyone-deny.
        Returns the home folder uid. Raises HomeProvisionError on failure."""
        if not self.enabled:
            raise HomeProvisionError("BRIDGE_URL not configured")

        users_uid = self._find_child("root", USERS_FOLDER, token, tenant)
        if not users_uid:
            raise HomeProvisionError(
                f"'{USERS_FOLDER}' folder not found in tenant '{tenant}' "
                "(a system_admin must create it once)")

        # Create the home folder (idempotent: reuse an existing one).
        status, data = self._request("POST", f"/v1/dirs/{users_uid}", token, tenant,
                                     {"name": uid})
        if status == 201 and isinstance(data, dict):
            home_uid = data.get("uid")
        else:
            home_uid = self._find_child(users_uid, uid, token, tenant)
        if not home_uid:
            raise HomeProvisionError(f"could not create home folder for '{uid}': {data}")

        # Owner gets full control — one grant per permission (the API grants a
        # single permission per call).
        for perm in FULL_CONTROL:
            s, _ = self._request("POST", f"/v1/nodes/{home_uid}/permissions", token, tenant,
                                 {"principal": uid, "permission": perm, "effect": "allow"})
            if s not in (200, 204):
                raise HomeProvisionError(f"home folder created but grant '{perm}' failed ({s})")
        # Everyone else is denied read → private / hidden from others.
        s2, _ = self._request("POST", f"/v1/nodes/{home_uid}/permissions", token, tenant,
                              {"principal": "everyone", "permission": "r", "effect": "deny"})
        if s2 not in (200, 204):
            raise HomeProvisionError(f"home folder created but everyone-deny failed ({s2})")
        return home_uid
