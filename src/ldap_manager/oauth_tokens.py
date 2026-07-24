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

"""Issue + verify OAuth 2.0 access tokens and OIDC ID tokens (RS256, Phase 1.7).

All tokens are JWTs signed with the authority's RSA key (``oauth_keys``). Two token
types:

* **access token** — a bearer JWT the resource (``/userinfo``, or a downstream
  FileEngine door) verifies via JWKS; carries ``sub`` (the FileEngine user), the
  ``tenant``, granted ``scope``, and the ``client_id``. ``aud`` is the issuer's
  userinfo/resource identity.
* **ID token** (OIDC) — proves *authentication* to the relying party; ``aud`` is the
  client_id, and it carries the standard identity claims (``sub``, ``email``,
  ``name``, ``tenant``, ``nonce``, ``auth_time``) the client asked for by scope.

The subject (``sub``) is always the FileEngine user identity, so a token minted here
plugs straight into the impersonation rule downstream — every action the token
authorizes executes as that user, never a shared service account.
"""
from __future__ import annotations

import time
import uuid
from typing import Optional

import jwt  # PyJWT

from .oauth_keys import OAuthKeys

# OIDC standard scopes we understand; a client is granted the intersection of what
# it requested and what it's registered for (enforced in the router).
OIDC_SCOPES = ("openid", "profile", "email", "roles", "offline_access")


def _headers(keys: OAuthKeys) -> dict:
    return {"kid": keys.kid, "alg": keys.alg, "typ": "JWT"}


def issue_access_token(keys: OAuthKeys, *, issuer: str, subject: str, tenant: str,
                       client_id: str, scope: str, ttl: int,
                       roles: Optional[list] = None, audience: Optional[str] = None) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience or (issuer.rstrip("/") + "/oauth/userinfo"),
        "client_id": client_id,
        "tenant": tenant,
        "scope": scope,
        "iat": now,
        "exp": now + max(1, int(ttl)),
        "jti": uuid.uuid4().hex,
        "token_use": "access",
    }
    if roles is not None and "roles" in (scope or "").split():
        claims["roles"] = list(roles)
    return jwt.encode(claims, keys.private_pem(), algorithm=keys.alg, headers=_headers(keys))


def issue_id_token(keys: OAuthKeys, *, issuer: str, subject: str, tenant: str,
                   client_id: str, ttl: int, nonce: str = "", auth_time: Optional[int] = None,
                   email: str = "", name: str = "", roles: Optional[list] = None,
                   scope: str = "") -> str:
    now = int(time.time())
    scopes = set((scope or "").split())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": client_id,
        "tenant": tenant,
        "iat": now,
        "exp": now + max(1, int(ttl)),
        "auth_time": int(auth_time if auth_time is not None else now),
        "token_use": "id",
    }
    if nonce:
        claims["nonce"] = nonce
    if "email" in scopes and email:
        claims["email"] = email
        claims["email_verified"] = True
    if "profile" in scopes and name:
        claims["name"] = name
        claims["preferred_username"] = subject
    if "roles" in scopes and roles is not None:
        claims["roles"] = list(roles)
    return jwt.encode(claims, keys.private_pem(), algorithm=keys.alg, headers=_headers(keys))


def verify_token(keys: OAuthKeys, token: str, *, issuer: str,
                 audience: Optional[str] = None, token_use: Optional[str] = None) -> Optional[dict]:
    """Verify a token this authority issued (RS256, our key). Returns the claims or
    ``None``. ``audience`` is checked when given; ``token_use`` (``access``/``id``)
    is checked when given."""
    if not token:
        return None
    from cryptography.hazmat.primitives import serialization
    public_key = serialization.load_pem_private_key(keys.private_pem(), password=None).public_key()
    options = {"require": ["exp", "iat", "iss", "sub"]}
    kwargs = dict(algorithms=[keys.alg], issuer=issuer, options=options)
    if audience is not None:
        kwargs["audience"] = audience
    else:
        kwargs["options"]["verify_aud"] = False
    try:
        claims = jwt.decode(token, public_key, **kwargs)
    except jwt.PyJWTError:
        return None
    if token_use is not None and claims.get("token_use") != token_use:
        return None
    return claims
