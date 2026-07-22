"""Unit tests for the OAuth code/refresh store (in-memory fake Redis, no server)."""
from ldap_manager.oauth_codes import OAuthCodeStore


class FakeRedis:
    """Minimal Redis for the store: setex + atomic getdel semantics."""
    def __init__(self):
        self.kv: dict[str, bytes] = {}

    def setex(self, k, ttl, v):
        self.kv[k] = v.encode() if isinstance(v, str) else v

    def getdel(self, k):
        return self.kv.pop(k, None)

    def get(self, k):
        return self.kv.get(k)


def _store():
    s = OAuthCodeStore("")          # no real client built
    s._r = FakeRedis()
    return s


def test_auth_code_is_single_use():
    s = _store()
    code = s.issue_code({"client_id": "c", "user": "alice", "scope": "openid"}, 300)
    got = s.consume_code(code)
    assert got == {"client_id": "c", "user": "alice", "scope": "openid"}
    # a second exchange of the same code fails (replay/injection defense)
    assert s.consume_code(code) is None


def test_consume_unknown_code_returns_none():
    s = _store()
    assert s.consume_code("nope") is None
    assert s.consume_code("") is None


def test_refresh_token_rotates():
    s = _store()
    r1 = s.issue_refresh({"client_id": "c", "user": "alice", "scope": "openid offline_access"}, 1000)
    payload = s.consume_refresh(r1)
    assert payload["user"] == "alice"
    # the presented refresh is now consumed (rotation) — reuse is rejected
    assert s.consume_refresh(r1) is None
    # a freshly-issued one works
    r2 = s.issue_refresh(payload, 1000)
    assert s.consume_refresh(r2)["user"] == "alice"


def test_disabled_store_is_noop_safe():
    s = OAuthCodeStore("")          # no client at all
    assert s.enabled is False
    assert s.consume_code("x") is None and s.consume_refresh("x") is None
