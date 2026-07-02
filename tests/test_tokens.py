"""Unit tests for the Redis token store: single-use tokens, the per-uid index
used for bulk revocation, and the fixed-window rate limiter (SPECIFICATION.md §5,
§5.2). Uses a tiny in-memory fake Redis (no server needed)."""
from ldap_manager.tokens import INVITE, RESET, TokenStore


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.sets: dict[str, set] = {}

    # our code uses a pipeline for grouping; applying eagerly is fine for tests
    def pipeline(self):
        return self

    def execute(self):
        return []

    def setex(self, k, ttl, v):
        self.kv[k] = str(v)

    def get(self, k):
        v = self.kv.get(k)
        return v.encode() if v is not None else None

    def delete(self, *ks):
        for k in ks:
            self.kv.pop(k, None)
            self.sets.pop(k, None)

    def sadd(self, k, *vals):
        self.sets.setdefault(k, set()).update(vals)

    def srem(self, k, *vals):
        self.sets.get(k, set()).difference_update(vals)

    def smembers(self, k):
        return set(self.sets.get(k, set()))

    def expire(self, k, ttl, gt=False):
        return True

    def incr(self, k):
        n = int(self.kv.get(k, 0)) + 1
        self.kv[k] = str(n)
        return n


def _store() -> TokenStore:
    s = TokenStore("")          # no real redis
    s._r = FakeRedis()          # inject the fake
    return s


def test_issue_then_consume_is_single_use():
    s = _store()
    tok = s.issue(INVITE, "alice@x", 3600)
    assert s.consume(INVITE, tok) == "alice@x"
    assert s.consume(INVITE, tok) is None      # already consumed


def test_wrong_kind_does_not_consume():
    s = _store()
    tok = s.issue(RESET, "bob@x", 3600)
    assert s.consume(INVITE, tok) is None       # namespaced by kind


def test_revoke_all_for_invalidates_every_token():
    s = _store()
    t1 = s.issue(INVITE, "carol@x", 3600)
    t2 = s.issue(RESET, "carol@x", 3600)
    s.revoke_all_for("carol@x")
    assert s.consume(INVITE, t1) is None
    assert s.consume(RESET, t2) is None


def test_rate_limit_fixed_window():
    s = _store()
    assert s.rate_ok("reset:ip:1.2.3.4", limit=2, window_s=60) is True
    assert s.rate_ok("reset:ip:1.2.3.4", limit=2, window_s=60) is True
    assert s.rate_ok("reset:ip:1.2.3.4", limit=2, window_s=60) is False   # 3rd over limit


def test_rate_limit_disabled_when_limit_zero():
    s = _store()
    assert all(s.rate_ok("b", limit=0, window_s=60) for _ in range(5))


def test_no_redis_is_safe_defaults():
    s = TokenStore("")          # disabled
    assert s.enabled is False
    assert s.rate_ok("b", 1, 60) is True        # allow
    s.revoke_all_for("x")                        # no-op, no error
    assert s.consume(INVITE, "whatever") is None
