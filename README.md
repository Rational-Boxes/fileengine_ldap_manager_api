# FileEngine LDAP Manager

Tenant user & role administration API for FileEngine — a FastAPI service
(mirroring `convert_search_ai`) that lets tenant administrators manage their
tenant's LDAP roles and users, plus self-service profile/password management and
email-based invite/reset flows.

See **[SPECIFICATION.md](SPECIFICATION.md)** for the full design.

## Layout

```
src/ldap_manager/
  config.py          # env config — shared FILEENGINE_LDAP_* + service knobs (§8)
  app.py             # FastAPI factory + entrypoint
  identity.py        # caller identity (from a bridge token)
  bridge_auth.py     # http_bridge token introspection (§2)
  deps.py            # auth scopes: public / self / tenant-admin
  ldap_client.py     # LDAP reads/writes, single-server or master→replica (§1.1)
  failover.py        # primary/replica circuit-breaker
  password_policy.py # complexity gating, shared by every password-set path (§5.4)
  tokens.py          # Redis invite/reset tokens (hashed)
  email.py           # SMTP + safe placeholder rendering
  templates.py       # per-tenant email templates + defaults (§5.1)
  schemas.py         # pydantic request/response models
  routers/           # health, public_auth, me, admin_users/roles/templates (§7)
```

## Access scopes (§2)

- **public** — `/v1/invite/accept`, `/v1/reset/*`, `/v1/password-policy`
- **self** (any bearer token) — `/v1/me*` (own account only)
- **tenant admin** — `/v1/admin/*` (member of the tenant's `administrators`)

## Develop

```bash
pip install -e .[dev]
cp .env.example .env        # configure LDAP/bridge/redis/postgres/SMTP
pytest                      # unit + smoke tests
fileengine-ldap-manager     # run (serves at HTTP_PORT, default 8093)
```

Served in the stack under the same-origin **`/ldapadmin`** proxy (Vite in dev,
nginx in prod), reusing the SPA's http_bridge bearer token.

## Scaffold status

Foundation is complete and runnable (config, password policy, auth scopes, email
rendering, token store, API surface, health). The LDAP directory operations in
`ldap_client.py` (and the Postgres template CRUD in `templates.py`) are marked
`NotImplementedError` / `TODO(scaffold)` — the next step is wiring the `ldap3` /
`psycopg` calls behind the interfaces the routers already use.
