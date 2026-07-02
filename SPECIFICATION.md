# LDAP Manager — Tenant User & Role Administration

A backend REST service that lets **tenant administrators** manage the users and
roles of their own tenant, backing the frontend administrative interface.

> Original intent: allow, within the tenant LDAP space
> `ou=tenants,dc=organization,dc=com` (e.g. `ou=default,ou=tenants,…`), a member
> of that tenant's `administrators` `groupOfNames` to create other role
> `groupOfNames` and to create or assign users. Users exist system-wide under
> `ou=users,dc=organization,dc=com`; new users are created only as needed.
> Implemented as a FastAPI Python service mirroring CSAI.

---

## 1. Architecture

- **FastAPI Python service**, mirroring the CSAI service (project layout, config
  style, logging, Dockerization, `/healthz` `/readyz` bound **loopback-only**).
- Integrations:
  - **OpenLDAP** via `ldap3`, using a **privileged service-bind account** for all
    writes (see §3).
  - **http_bridge** `/v1/auth/introspect` — to authenticate the caller (§2).
  - **Redis** — single-use invite tokens (§5).
  - **SMTP** — invite / set-password emails (§5).
- Deployed as a new `fileengine-ldap-manager` image + compose service, wired into
  `docker_unified` (stage step, compose service, VERSION-tagged).
- **Frontend integration — same-origin proxy, exactly like CSAI.** CSAI is reached
  via a dedicated prefix (`/csai` → the CSAI service on `:8092`); ldap_manager gets
  its own prefix **`/ldapadmin`** → the service (default port `:8093`), proxied the
  same two ways CSAI is:
  - **dev:** a Vite `server.proxy` entry `'/ldapadmin' → http://localhost:8093`;
  - **prod:** an nginx `location /ldapadmin/` reverse-proxy to the container.

  The SPA uses a dedicated client (mirroring `csaiClient`) with base
  `VITE_LDAPADMIN_BASE || '/ldapadmin'`, and sends the same http_bridge bearer
  token it already holds. So all routes in §7 are served under `/ldapadmin`
  (e.g. `POST /ldapadmin/v1/admin/users`).

### 1.1 Distributed architecture & high availability (must match the stack)

- **Stateless + horizontally scalable.** Run N instances behind the `/ldapadmin`
  proxy with no instance affinity; all shared state (invite tokens) lives in the
  shared **Redis**, so any instance serves any request. No local disk state.
- **Both LDAP topologies supported — config-driven, same vars as the bridges:**
  - **Single LDAP server** (default) — `FILEENGINE_LDAP_ENDPOINT_REPLICA` empty:
    all reads *and* writes use the one `FILEENGINE_LDAP_ENDPOINT`; no failover
    logic engaged. This is the baseline deployment.
  - **Master → replica** — `FILEENGINE_LDAP_ENDPOINT` (writable master) +
    `FILEENGINE_LDAP_ENDPOINT_REPLICA` (read replica) with
    `FILEENGINE_FAILOVER_COOLDOWN_S`: reads may use the replica; on primary failure
    reads fail over to the replica for the cooldown window, then retry the
    primary — the exact behavior the HTTP/WebDAV bridges already implement.
  - **Writes always go to the writable master.** Unlike the bridges (which only
    bind / read), this service mutates the directory. Master→replica replication is
    single-master, so a read replica cannot accept writes: user/role mutations
    target the master and return **`503`** with a clear message if it's
    unavailable, rather than failing writes over to a replica. (In single-server
    mode the master *is* the only endpoint.)
  - **Read-after-write consistency.** Because replica lag can briefly hide a
    just-created user/role, a mutation's response is read back from the **master**
    so the admin UI stays consistent (a no-op in single-server mode).
- **Readiness gating for orchestration.** `/readyz` is not-ready unless the LDAP
  **primary** (needed for writes), **Redis**, and the **bridge** introspection
  endpoint are reachable, so the orchestrator routes only to healthy instances;
  `/healthz` is a plain liveness probe. Both bound loopback-only.
- **Resilience.** Pooled / kept-alive LDAP connections with bounded retry +
  backoff, mirroring the bridges.

## 2. Authentication & authorization

- **Caller auth (decision):** the frontend sends the **http_bridge bearer token**
  (the existing SPA session). The service introspects it via the bridge to
  resolve `{user, tenant, roles}` — trusted-upstream, exactly like CSAI. No new
  login surface.
- **Authorization is app-enforced (decision):** for every request the service
  verifies the caller is a `member` of `cn=administrators,ou=<tenant>,ou=tenants,…`
  for the tenant in their token. All operations are hard-scoped to that tenant's
  `ou` (and to global user entries); there is **no cross-tenant access**.
- **Writes (decision):** performed with the **privileged service-bind account**
  — the same `FILEENGINE_LDAP_BIND_DN` / `FILEENGINE_LDAP_BIND_PASSWORD` the
  bridges use (§8) — writing only under `FILEENGINE_LDAP_USER_BASE` and
  `FILEENGINE_LDAP_TENANT_BASE`. The service — not the directory — enforces the
  rules below.

## 3. Directory model

All locations are **derived from the shared `FILEENGINE_LDAP_*` config (§8)** — the
same variables the HTTP/WebDAV bridges read — never hard-coded. The DNs shown are
the defaults; a deployment overrides them via `FILEENGINE_LDAP_DOMAIN`,
`FILEENGINE_LDAP_USER_BASE`, and `FILEENGINE_LDAP_TENANT_BASE`.

- Base DN = `FILEENGINE_LDAP_DOMAIN` (default `dc=rationalboxes,dc=com`).
- **Users (global):** `uid=<email>,${FILEENGINE_LDAP_USER_BASE}`, objectClass
  `inetOrgPerson` (`uid` = email, `cn` = display name, `sn`, `mail`,
  `userPassword`). A user may already exist and belong to several tenants' roles.
- **Tenants:** `ou=<tenant>,${FILEENGINE_LDAP_TENANT_BASE}`.
- **Roles:** `cn=<role>,ou=<tenant>,${FILEENGINE_LDAP_TENANT_BASE}`, objectClass `groupOfNames`,
  `member` = full user DNs. `administrators` confers tenant-admin rights.
- **Role ↔ core:** the http_bridge resolves a user's group memberships to roles at
  auth time, so a role group created here immediately becomes a usable role name
  in the core ACL/permission system (incl. the new tiered evaluator).

## 4. What a tenant admin may do (scope)

Scoped to their own `ou=<tenant>`:
- **Roles:** list / create / delete role groups; add/remove members.
- **Users:** look up global users (exact match, §6), create new global users (via
  the invite flow, §5), and assign/unassign users to this tenant's roles.
- **`administrators` group (decision):** may add/remove members **except
  themselves** (no self-removal → prevents lockout), and the **last administrator
  cannot be removed** (last-admin guard). The `administrators` group itself cannot
  be deleted.
- **Not allowed:** deleting/renaming/disabling global user accounts (they may
  belong to other tenants), editing other tenants' `ou`s, creating/deleting
  tenants, or changing user attributes beyond display name + role membership.

## 5. User notification emails (two kinds, per-tenant templates)

Two events send a tenant-customizable email (templates in §5.1). Both require SMTP.

> **Why every user needs a directory password.** WebDAV authenticates over HTTP
> Basic against LDAP, so **even users who normally sign in via OAuth/SSO must have
> a `userPassword` in the directory** to use WebDAV. The invite/set-password flow
> (§5-A) and the self-service reset (§5.2) are how *any* user — OAuth or not —
> establishes and rotates that WebDAV password. So these flows apply universally,
> not only to password-first accounts.

**A. New user invited** — the person has no account yet (`POST /v1/admin/users`):
1. Service creates `uid=<email>,${FILEENGINE_LDAP_USER_BASE}` (inetOrgPerson) with
   **no usable password** ("pending") and adds it to any requested tenant roles.
2. It mints a random **invite token** (stored **hashed in Redis**, keyed by user
   DN, TTL `INVITE_TTL_HOURS` default 72h) and sends the tenant's **`new_user`**
   template carrying a set-password link (`INVITE_LINK_BASE` + token).
3. `POST /v1/invite/accept {token, password}` (public, no bearer) validates the
   token + expiry, sets `userPassword` (SSHA), clears "pending", deletes the token.
   `POST /v1/admin/users/{uid}/reinvite` resends.

**B. Existing user granted tenant access** — the person already has a system
account and is added to a tenant role: **no** password/invite. When they gain
their *first* membership in this tenant, the service sends the tenant's
**`access_granted`** template (link to the app, the tenant, and the roles
granted). Further role changes within the same tenant don't re-notify.

### 5.1 Email templates (per-tenant, customizable — decision)

Each tenant may customize both emails; until customized, built-in **defaults** are
used. A template has a **subject** and an HTML **body** (plain-text auto-derived),
rendered by **placeholder substitution only** (safe/sandboxed — no arbitrary code;
unknown placeholders rejected on save). The security-sensitive `{{invite_link}}`
is always built by the service, never from input.

| Kind | Trigger | Placeholders |
|---|---|---|
| `new_user` | new user invited (A) | `{{display_name}} {{email}} {{tenant}} {{invite_link}} {{expires}} {{inviter}} {{roles}}` |
| `access_granted` | existing user added to the tenant (B) | `{{display_name}} {{email}} {{tenant}} {{app_link}} {{inviter}} {{roles}}` |

- **Storage:** per-tenant, keyed by `(tenant, kind)`, in **Postgres** (a small
  `email_templates` table — mirroring CSAI's use of Postgres); a missing row falls
  back to the built-in default.
- **Editing (frontend):** a **simple template editor** per kind — subject + body
  fields, the list of available placeholders, a **live preview** rendered with
  sample data, a **revert-to-default**, and a **"send test to me"** action.
  Available only to the tenant's `administrators`.

### 5.2 End-user password reset (self-service, email — decision)

A standard forgot-password flow for **end users** (not admins), served here
because this service owns directory `userPassword` writes. Public, unauthenticated:

1. `POST /v1/reset/request {email}` — if a matching enabled user exists under
   `${FILEENGINE_LDAP_USER_BASE}`, mint a single-use **reset token** (hashed in
   Redis, own namespace, TTL `RESET_TTL_HOURS` default 2h) and email a reset link
   (`RESET_LINK_BASE` + token). **Always responds `200`** regardless of whether the
   address exists (no account enumeration); rate-limited per source IP and per
   email.
2. `POST /v1/reset/confirm {token, password}` — validates the token + expiry, sets
   `userPassword` (SSHA), deletes the token, and invalidates any other outstanding
   reset/invite tokens for that user.
- Uses a **`password_reset`** email. Because a reset has no tenant context (the
  user is global and may belong to several tenants), this template is a
  **system-level default**, not part of the per-tenant editor (a deployment may
  override the default). Placeholders: `{{display_name}} {{email}} {{reset_link}}
  {{expires}}`.
- Writes target the LDAP **master** (§1.1); the reset link, like invites, points at
  the frontend (`RESET_LINK_BASE`).

## 6. User lookup / privacy

Because users are global, unrestricted listing would leak the whole directory
across tenants. Lookup is therefore **exact email/uid** (or a **≥3-char prefix**),
returns limited fields (`uid`, display name, whether already in this tenant), and
is capped + rate-limited. No full enumeration.

## 7. API surface (v1, JSON; every route scoped to the caller's tenant)

| Method & path | Purpose |
|---|---|
| `GET /v1/admin/roles` | list tenant role groups (+ member counts) |
| `POST /v1/admin/roles` `{name}` | create a role group |
| `DELETE /v1/admin/roles/{role}` | delete a role group (not `administrators`) |
| `GET /v1/admin/roles/{role}/members` | list members |
| `POST /v1/admin/roles/{role}/members` `{uid}` | add an existing user to the role (may trigger the `access_granted` email, §5-B) |
| `DELETE /v1/admin/roles/{role}/members/{uid}` | remove (admins: not self / not last) |
| `GET /v1/admin/users?query=<exact/prefix>` | look up global user(s) for assignment |
| `GET /v1/admin/users/{uid}` | view a user (limited fields) |
| `POST /v1/admin/users` `{email, display_name, roles?[]}` | create new global user + invite |
| `POST /v1/admin/users/{uid}/reinvite` | resend the invite |
| `GET /v1/admin/email-templates` | list the tenant's two template kinds (custom or default) |
| `GET /v1/admin/email-templates/{kind}` | get one (`new_user` / `access_granted`) |
| `PUT /v1/admin/email-templates/{kind}` `{subject, body}` | save/override a template |
| `DELETE /v1/admin/email-templates/{kind}` | revert to the built-in default |
| `POST /v1/admin/email-templates/{kind}/preview` `{subject?, body?}` | render with sample data (no send) |
| `POST /v1/admin/email-templates/{kind}/test` | send a test to the caller's own email |
| `POST /v1/invite/accept` `{token, password}` | **public** — set password from an invite |
| `POST /v1/reset/request` `{email}` | **public** — request a password reset (always 200) |
| `POST /v1/reset/confirm` `{token, password}` | **public** — set a new password from a reset token |
| `GET /healthz` · `GET /readyz` | monitoring (loopback-only) |

## 8. Configuration (env, mirrors CSAI; secrets via compose, never baked in)

**LDAP — reuse the *exact* variables the HTTP and WebDAV bridges use** (do not
invent new names); the same `docker_unified` `.env` values then configure all
three services, and any deployment that has overridden the user/tenant locations
applies here automatically:

| Variable | Default | Meaning |
|---|---|---|
| `FILEENGINE_LDAP_ENDPOINT` | `ldap://localhost:1389` | directory URL |
| `FILEENGINE_LDAP_ENDPOINT_REPLICA` | `` | replica URL (HA) |
| `FILEENGINE_FAILOVER_COOLDOWN_S` | `30` | replica failover cooldown |
| `FILEENGINE_LDAP_DOMAIN` | `dc=rationalboxes,dc=com` | base DN |
| `FILEENGINE_LDAP_BIND_DN` | `cn=admin,dc=rationalboxes,dc=com` | privileged service-bind DN (§2 writes) |
| `FILEENGINE_LDAP_BIND_PASSWORD` | `admin` | service-bind password |
| **`FILEENGINE_LDAP_USER_BASE`** | `ou=users,dc=rationalboxes,dc=com` | **override** for the global users location |
| **`FILEENGINE_LDAP_TENANT_BASE`** | `ou=tenants,dc=rationalboxes,dc=com` | **override** for the tenants location |

All user/tenant DNs (§3) are derived from `FILEENGINE_LDAP_USER_BASE` /
`FILEENGINE_LDAP_TENANT_BASE`, never hard-coded — matching the bridges' behavior,
including replica + failover for parity.

**Service-specific:** `BRIDGE_URL` (introspection) · `REDIS_URL` (invite + reset
tokens) · `DATABASE_URL` (Postgres — per-tenant email templates, §5.1) ·
`SMTP_HOST/PORT/USER/PASSWORD/FROM` · `INVITE_LINK_BASE`, `INVITE_TTL_HOURS`
(default 72) · `RESET_LINK_BASE`, `RESET_TTL_HOURS` (default 2) ·
`HTTP_HOST` (default `127.0.0.1`), `HTTP_PORT` (default `8093`),
`HTTP_MONITORING_HOST/PORT` (loopback). Frontend: `VITE_LDAPADMIN_BASE`
(default `/ldapadmin`).

## 9. Audit & security

- Every mutation logged: actor uid, tenant, action, target, result, timestamp
  (service log; optional audit table, mirroring the core `acl_audit` style).
- App-enforced tenant isolation; self-removal + last-admin guards on
  `administrators`.
- Invite tokens: single-use, hashed at rest, short TTL, rate-limited; user-search
  and invite endpoints rate-limited; no directory enumeration.

## 10. Out of scope (this iteration)

Creating/deleting tenants (a global-admin function); deleting/disabling global
users; MFA / external IdP / SSO; a full password-policy engine (basic length
only); editing arbitrary user attributes.

## 11. Assumptions to confirm

1. New-user objectClass = `inetOrgPerson` and `uid` = email (matches the current
   directory, e.g. `testuser@rationalboxes.com`).
2. Role group names are free-form (admin-chosen), not a controlled vocabulary.
3. User lookup is exact/prefix (≥3 chars), not full listing.
4. "Pending"/invite state lives in **Redis** (token) — no new LDAP schema
   attribute is added for it.
5. The service reaches LDAP, Redis, Postgres, the bridge, and SMTP over the
   internal network only (nginx exposes the `/ldapadmin` routes: `/v1/admin/*`,
   `/v1/invite/accept`, `/v1/reset/*`).
6. Per-tenant email templates persist in **Postgres** (`DATABASE_URL`); the
   `password_reset` template is a **system-level default** (not per-tenant, since a
   reset has no tenant context). Invite token TTL 72h, reset token TTL 2h.
7. Password set/reset applies to **all** users incl. OAuth/SSO, because WebDAV
   needs a directory `userPassword` (§5 note).
