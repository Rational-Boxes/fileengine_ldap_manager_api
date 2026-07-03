"""Configuration, read from the environment (SPECIFICATION.md §8).

A ``.env`` in the working directory is loaded automatically (without overriding
values already set in the environment), mirroring convert_search_ai / the MCP
server. **LDAP variables are the same ``FILEENGINE_LDAP_*`` names the HTTP and
WebDAV bridges use** — so one ``docker_unified`` ``.env`` configures all three,
and any deployment override of the user/tenant base DNs applies here too.
Service-specific knobs use plain names (``BRIDGE_URL``, ``SMTP_*``, ``PW_*``, …).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), _strip_value(val))


def _strip_value(val: str) -> str:
    val = val.strip()
    if val[:1] in ("'", '"'):
        q = val[0]
        end = val.find(q, 1)
        return val[1:end] if end != -1 else val[1:]
    if val.startswith("#"):
        return ""
    hi = val.find(" #")
    if hi != -1:
        val = val[:hi]
    return val.strip()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, "").strip() or default)
    except ValueError:
        return default


def _bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class PasswordPolicyConfig:
    min_length: int = 12
    max_length: int = 128
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    min_classes: int = 0          # >0 → require N of the 4 classes instead of specific ones
    blocklist_path: str = ""      # optional file of forbidden passwords (one per line)


@dataclass
class Settings:
    # --- LDAP (shared FILEENGINE_LDAP_* — identical to the bridges, §8) ---
    ldap_endpoint: str = "ldap://localhost:1389"
    ldap_endpoint_replica: str = ""
    failover_cooldown_s: int = 30
    ldap_domain: str = "dc=rationalboxes,dc=com"           # base DN
    ldap_bind_dn: str = "cn=admin,dc=rationalboxes,dc=com"  # privileged service bind
    ldap_bind_password: str = "admin"
    ldap_user_base: str = "ou=users,dc=rationalboxes,dc=com"      # override location
    ldap_tenant_base: str = "ou=tenants,dc=rationalboxes,dc=com"  # override location
    ldap_avatar_attr: str = "labeledURI"                    # self-service avatar link (§5.3)

    # --- service integrations ---
    bridge_url: str = ""          # http_bridge, for token introspection (§2)
    bridge_introspect_ttl: int = 60
    jwt_secret: str = ""          # shared HS256 secret to verify bearer JWTs locally
    redis_url: str = ""           # invite + reset tokens
    database_url: str = ""        # Postgres — per-tenant email templates (§5.1)

    # --- email / invites / reset (§5) ---
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    invite_link_base: str = ""    # frontend URL that carries the token
    invite_ttl_hours: int = 72
    reset_link_base: str = ""
    reset_ttl_hours: int = 2
    reset_rate_per_email: int = 5      # per window, per email
    reset_rate_per_ip: int = 20        # per window, per source IP
    reset_rate_window_s: int = 3600

    # --- password policy (§5.4) ---
    password_policy: PasswordPolicyConfig = field(default_factory=PasswordPolicyConfig)

    # --- HTTP ---
    http_host: str = "127.0.0.1"
    http_port: int = 8093
    monitoring_host: str = "127.0.0.1"
    monitoring_port: int = 8094

    @property
    def ldap_replicated(self) -> bool:
        """True when a read replica is configured (master→replica); else single-server."""
        return bool(self.ldap_endpoint_replica.strip())


def load_settings() -> "Settings":
    load_dotenv()
    return Settings(
        ldap_endpoint=_env("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389"),
        ldap_endpoint_replica=_env("FILEENGINE_LDAP_ENDPOINT_REPLICA", ""),
        failover_cooldown_s=_int("FILEENGINE_FAILOVER_COOLDOWN_S", 30),
        ldap_domain=_env("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com"),
        ldap_bind_dn=_env("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com"),
        ldap_bind_password=_env("FILEENGINE_LDAP_BIND_PASSWORD", "admin"),
        ldap_user_base=_env("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com"),
        ldap_tenant_base=_env("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com"),
        ldap_avatar_attr=_env("LDAP_AVATAR_ATTR", "labeledURI"),
        bridge_url=_env("BRIDGE_URL", ""),
        jwt_secret=_env("FILEENGINE_JWT_SECRET", ""),
        bridge_introspect_ttl=_int("BRIDGE_INTROSPECT_TTL", 60),
        redis_url=_env("REDIS_URL", ""),
        database_url=_env("DATABASE_URL", ""),
        smtp_host=_env("SMTP_HOST", ""),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=_env("SMTP_USER", ""),
        smtp_password=_env("SMTP_PASSWORD", ""),
        smtp_from=_env("SMTP_FROM", ""),
        invite_link_base=_env("INVITE_LINK_BASE", ""),
        invite_ttl_hours=_int("INVITE_TTL_HOURS", 72),
        reset_link_base=_env("RESET_LINK_BASE", ""),
        reset_ttl_hours=_int("RESET_TTL_HOURS", 2),
        reset_rate_per_email=_int("RESET_RATE_PER_EMAIL", 5),
        reset_rate_per_ip=_int("RESET_RATE_PER_IP", 20),
        reset_rate_window_s=_int("RESET_RATE_WINDOW_S", 3600),
        password_policy=PasswordPolicyConfig(
            min_length=_int("PW_MIN_LENGTH", 12),
            max_length=_int("PW_MAX_LENGTH", 128),
            require_upper=_bool("PW_REQUIRE_UPPER", True),
            require_lower=_bool("PW_REQUIRE_LOWER", True),
            require_digit=_bool("PW_REQUIRE_DIGIT", True),
            require_symbol=_bool("PW_REQUIRE_SYMBOL", True),
            min_classes=_int("PW_MIN_CLASSES", 0),
            blocklist_path=_env("PW_BLOCKLIST", ""),
        ),
        http_host=_env("HTTP_HOST", "127.0.0.1"),
        http_port=_int("HTTP_PORT", 8093),
        monitoring_host=_env("HTTP_MONITORING_HOST", "127.0.0.1"),
        monitoring_port=_int("HTTP_MONITORING_PORT", 8094),
    )
