"""Unit tests for the per-tenant WebDAV session-TTL logic (offline — no DB).

Covers the clamp helper and the effective-TTL resolution (inherit default vs
tenant override, always clamped). The Postgres-backed store is exercised by the
integration/E2E suite; here we drive effective_ttl with a stubbed _raw().
"""
from types import SimpleNamespace

from ldap_manager import webdav_policy as wp


def _store(default=43200, lo=300, hi=86400):
    s = SimpleNamespace(database_url="", webdav_session_ttl_default=default,
                        webdav_session_ttl_min=lo, webdav_session_ttl_max=hi)
    return wp.WebDavSessionPolicyStore(s)


def test_clamp_ttl():
    assert wp.clamp_ttl(100, 300, 86400) == 300      # below floor
    assert wp.clamp_ttl(999999, 300, 86400) == 86400  # above ceiling
    assert wp.clamp_ttl(3600, 300, 86400) == 3600     # in range


def test_effective_ttl_inherits_default_clamped():
    st = _store(default=43200)
    st._raw = lambda tenant: None                     # no override → deployment default
    assert st.effective_ttl("acme") == 43200


def test_effective_ttl_uses_override_clamped():
    st = _store(lo=300, hi=86400)
    st._raw = lambda tenant: 3600                     # tenant override, in range
    assert st.effective_ttl("acme") == 3600
    st._raw = lambda tenant: 5                        # override below floor → clamped up
    assert st.effective_ttl("acme") == 300
    st._raw = lambda tenant: 10 ** 9                  # override above ceiling → clamped down
    assert st.effective_ttl("acme") == 86400


def test_default_without_db_is_inherit():
    # No DATABASE_URL → _raw returns None (inherit) without raising.
    st = _store(default=7200)
    assert st._raw("acme") is None
    assert st.effective_ttl("acme") == 7200
