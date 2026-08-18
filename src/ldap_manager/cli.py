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

"""Mint and manage service credentials from the server.

    python -m ldap_manager.cli credential create --user alice@example.com --scopes webdav

**Why a CLI.** Service credentials are the only way in to the WebDAV and MCP
doors — those refuse the LDAP directory password outright. Until now the only way
to create one was the self-service HTTP route, which needs a bridge JWT and
therefore a completed login including two-factor. That is right for a user in a
browser and wrong for everything else: an operator provisioning a service
account, a headless deployment, an automated test that needs a credential before
it can drive WebDAV or MCP at all.

This runs where the store already lives, reading the same DATABASE_URL and
pepper the service uses, so nothing has to be duplicated or exposed.

**It is an administrative tool and acts as an operator, not as the user.** It
deliberately skips the self-service quota. Everything else is identical — the
same store, the same hashing, the same scopes — so a credential minted here is
indistinguishable from one minted in the browser.

The secret is displayed **once**. It is stored only as an HMAC, so a lost secret
is rotated, never recovered.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from .config import load_settings
from .service_cred import ALL_SCOPES, ServiceCredentialStore, normalize_scopes


def _store() -> ServiceCredentialStore:
    settings = load_settings()
    store = ServiceCredentialStore(settings)
    if not store.enabled():
        raise SystemExit(
            "service-credential store unavailable: DATABASE_URL is unset (or psycopg is "
            "missing).\nRun this on the server, or point DATABASE_URL at the ldap_manager "
            "database.")
    if not settings.service_cred_pepper:
        raise SystemExit(
            "SERVICE_CRED_HASH_PEPPER is unset. Secrets are stored as an HMAC under that "
            "pepper, so minting without it would produce credentials the service cannot "
            "verify.")
    return store


def _emit(payload: dict, as_json: bool, human: str) -> None:
    if as_json:
        # Machine-readable on stdout and nothing else, so a caller can consume it
        # directly — this is what lets a test provision its own credential.
        print(json.dumps(payload))
    else:
        print(human)


def cmd_create(args: argparse.Namespace) -> int:
    store = _store()
    scopes = normalize_scopes(args.scopes.split(",") if args.scopes else None)
    expires_at = None
    if args.expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=args.expires_days)

    key_id, secret = store.create(
        tenant=args.tenant,
        uid=args.user,
        scopes=scopes,
        label=args.label,
        expires_at=expires_at,
        allowed_cidrs=[c.strip() for c in args.cidr.split(",")] if args.cidr else None,
    )

    _emit(
        {"key_id": key_id, "secret": secret, "user": args.user, "tenant": args.tenant,
         "scopes": scopes, "label": args.label,
         "expires_at": expires_at.isoformat() if expires_at else None},
        args.json,
        "\n".join([
            "Service credential created.",
            f"  user   : {args.user}",
            f"  tenant : {args.tenant}",
            f"  scopes : {', '.join(scopes)}",
            f"  key    : {key_id}",
            f"  secret : {secret}",
            "",
            "The secret is shown ONCE — it is stored only as an HMAC and cannot be",
            "recovered. Use it as the HTTP Basic password with the key as the username:",
            f"  curl -u '{key_id}:{secret}' -X PROPFIND https://<host>/",
        ]),
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = _store()
    creds = store.list_for(args.user)
    if args.json:
        print(json.dumps([{
            "key_id": c.key_id, "label": c.label, "scopes": list(c.scopes),
            "allowed_cidrs": list(c.allowed_cidrs or []),
            "created_at": str(c.created_at) if c.created_at else None,
            "last_used_at": str(c.last_used_at) if c.last_used_at else None,
            "expires_at": str(c.expires_at) if c.expires_at else None,
        } for c in creds]))
        return 0

    if not creds:
        print(f"No service credentials for {args.user}.")
        return 0
    print(f"Service credentials for {args.user}:")
    for c in creds:
        used = c.last_used_at or "never used"
        expires = f", expires {c.expires_at}" if c.expires_at else ""
        print(f"  {c.key_id}  [{', '.join(c.scopes)}]  {c.label or '(no label)'}"
              f"  created {c.created_at}, last used {used}{expires}")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    store = _store()
    result = store.rotate(key_id=args.key, uid=args.user, new_key_id=args.new_key_id)
    if not result:
        # The store scopes rotation to the owner, so this is "no such credential
        # for that user" — said plainly rather than reported as success.
        raise SystemExit(f"no credential {args.key} belonging to {args.user}")
    key_id, secret = result
    _emit({"key_id": key_id, "secret": secret, "user": args.user}, args.json,
          "\n".join([
              "Secret rotated. The previous secret stopped working immediately.",
              f"  key    : {key_id}",
              f"  secret : {secret}",
              "",
              "Shown ONCE.",
          ]))
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    store = _store()
    if not store.revoke(key_id=args.key, uid=args.user):
        raise SystemExit(f"no credential {args.key} belonging to {args.user}")
    _emit({"revoked": args.key, "user": args.user}, args.json,
          f"Revoked {args.key} for {args.user}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m ldap_manager.cli",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="group", required=True)

    cred = sub.add_parser("credential", help="service credentials for the WebDAV / MCP / BCF doors")
    cs = cred.add_subparsers(dest="action", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--user", required=True, help="the credential's owner (LDAP uid)")
        p.add_argument("--json", action="store_true",
                       help="emit JSON on stdout, for scripts and tests")

    c = cs.add_parser("create", help="mint a new credential")
    common(c)
    c.add_argument("--tenant", default="default")
    c.add_argument("--scopes", default="webdav",
                   help=f"comma-separated; one or more of {', '.join(ALL_SCOPES)} (default: webdav)")
    c.add_argument("--label", default=None, help="a note about what this credential is for")
    c.add_argument("--expires-days", type=int, default=None,
                   help="expire it after N days (default: no expiry)")
    c.add_argument("--cidr", default=None,
                   help="comma-separated CIDRs the credential may be used from")
    c.set_defaults(func=cmd_create)

    l = cs.add_parser("list", help="list a user's credentials (never their secrets)")
    common(l)
    l.set_defaults(func=cmd_list)

    r = cs.add_parser("rotate", help="issue a new secret for an existing credential")
    common(r)
    r.add_argument("--key", required=True, help="the key_id to rotate")
    r.add_argument("--new-key-id", action="store_true",
                   help="issue a fresh key_id as well, retiring the old one")
    r.set_defaults(func=cmd_rotate)

    v = cs.add_parser("revoke", help="delete a credential")
    common(v)
    v.add_argument("--key", required=True, help="the key_id to revoke")
    v.set_defaults(func=cmd_revoke)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
