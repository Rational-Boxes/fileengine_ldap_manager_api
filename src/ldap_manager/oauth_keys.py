"""RSA signing keys + JWKS for the OAuth 2.0 / OIDC authority (Phase 1.7).

ID tokens and access tokens are signed **asymmetrically (RS256)** so any relying
party — a CMS/web-portal, ONLYOFFICE, or an MCP client — verifies them against the
published JWKS **without a shared secret**. That is the whole point of being an
authority rather than a peer: the private key never leaves this service; the public
key is fetchable at ``/oauth/jwks.json``.

The signing key comes from ``OAUTH_SIGNING_KEY`` (a PEM RSA private key). When the
authority is enabled but no key is configured, an **ephemeral** key is generated so
dev/test works out of the box — with a loud warning, because an ephemeral key means
every restart invalidates previously-issued tokens and can't be shared across nodes.
Production must set a stable key.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import threading

log = logging.getLogger("ldap_manager.oauth_keys")

_ALG = "RS256"


def _b64url_uint(n: int) -> str:
    """Base64url-encode a big-endian unsigned integer (JWK ``n``/``e`` encoding)."""
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


class OAuthKeys:
    """Holds the active RSA private key and derives the public JWKS + a stable kid."""

    def __init__(self, private_pem: str = ""):
        self._lock = threading.Lock()
        self._private_pem = (private_pem or "").strip()
        self._key = None          # cryptography private key object (lazy)
        self._kid = ""
        self._ephemeral = False

    # ------------------------------------------------------------------ load
    def _ensure(self):
        if self._key is not None:
            return
        with self._lock:
            if self._key is not None:
                return
            from cryptography.hazmat.primitives import serialization
            if self._private_pem:
                self._key = serialization.load_pem_private_key(
                    self._private_pem.encode("utf-8"), password=None)
            else:
                from cryptography.hazmat.primitives.asymmetric import rsa
                self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                self._ephemeral = True
                log.warning(
                    "OAUTH_SIGNING_KEY is not set — generated an EPHEMERAL RSA key. "
                    "Tokens will be invalidated on restart and cannot be verified across "
                    "nodes. Set OAUTH_SIGNING_KEY (a stable PEM RSA private key) in production.")
            self._kid = self._compute_kid()

    def _compute_kid(self) -> str:
        """A stable key id: the SHA-256 (first 16 hex) of the DER public key, so the
        same key always yields the same kid and clients can cache by it."""
        from cryptography.hazmat.primitives import serialization
        der = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()[:16]

    # ---------------------------------------------------------------- public
    @property
    def alg(self) -> str:
        return _ALG

    @property
    def kid(self) -> str:
        self._ensure()
        return self._kid

    @property
    def ephemeral(self) -> bool:
        self._ensure()
        return self._ephemeral

    def private_pem(self) -> bytes:
        """The PEM the JWT signer uses (PyJWT accepts the PEM bytes for RS256)."""
        self._ensure()
        from cryptography.hazmat.primitives import serialization
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

    def public_jwk(self) -> dict:
        """The signing key as a public JWK (RSA, use=sig, alg=RS256)."""
        self._ensure()
        nums = self._key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": _ALG,
            "kid": self._kid,
            "n": _b64url_uint(nums.n),
            "e": _b64url_uint(nums.e),
        }

    def jwks(self) -> dict:
        return {"keys": [self.public_jwk()]}
