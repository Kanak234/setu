import pytest

from setu.events import Kind
from setu.policy import (
    KEY_SIZE, VERDICT_SIZE, Action, DecisionTable, Verdict, comm_hash, key_for,
)


class TestVerdict:
    def test_packs_to_a_fixed_size(self):
        assert len(Verdict(Action.FLAG, 50, 0).pack()) == VERDICT_SIZE

    def test_round_trips(self):
        v = Verdict(Action.THROTTLE, 73, 1_700_000_000)
        assert Verdict.unpack(v.pack()) == v

    @pytest.mark.parametrize("conf", [-1, 101, 1000])
    def test_rejects_confidence_out_of_range(self, conf):
        with pytest.raises(ValueError):
            Verdict(Action.FLAG, conf, 0)

    def test_rejects_negative_expiry(self):
        with pytest.raises(ValueError):
            Verdict(Action.FLAG, 10, -1)

    def test_allow_is_zero(self):
        # A missing BPF map entry reads back as zeroes. That must mean ALLOW,
        # never DENY, or a cold map would block everything.
        assert int(Action.ALLOW) == 0


class TestKeys:
    def test_key_is_a_fixed_size(self):
        assert len(key_for(Kind.EXEC, "bash")) == KEY_SIZE

    def test_same_input_gives_the_same_key(self):
        assert key_for(Kind.EXEC, "bash") == key_for(Kind.EXEC, "bash")

    def test_different_comm_gives_a_different_key(self):
        assert key_for(Kind.EXEC, "bash") != key_for(Kind.EXEC, "zsh")

    def test_different_kind_gives_a_different_key(self):
        assert key_for(Kind.EXEC, "bash") != key_for(Kind.CONNECT, "bash")

    def test_comm_is_truncated_the_way_the_kernel_truncates_it(self):
        assert comm_hash("a" * 15) == comm_hash("a" * 40)


class TestLookup:
    def test_unknown_process_is_allowed(self):
        assert DecisionTable().lookup(Kind.EXEC, "anything").action is Action.ALLOW

    def test_returns_what_was_stored(self):
        t = DecisionTable(now=0)
        t.put(Kind.EXEC, "nc", Verdict(Action.FLAG, 80, 0))
        got = t.lookup(Kind.EXEC, "nc")
        assert got.action is Action.FLAG and got.confidence == 80

    def test_entries_are_scoped_to_their_kind(self):
        t = DecisionTable(now=0)
        t.put(Kind.CONNECT, "curl", Verdict(Action.FLAG, 60, 0))
        assert t.lookup(Kind.EXEC, "curl").action is Action.ALLOW

    def test_zero_expiry_never_expires(self):
        t = DecisionTable(now=10**9)
        t.put(Kind.EXEC, "nc", Verdict(Action.FLAG, 80, 0))
        assert t.lookup(Kind.EXEC, "nc").action is Action.FLAG

    def test_an_expired_entry_decays_to_allow(self):
        t = DecisionTable(now=100)
        t.put(Kind.EXEC, "nc", Verdict(Action.DENY, 99, 50))
        assert t.lookup(Kind.EXEC, "nc").action is Action.ALLOW

    def test_it_expires_on_the_second_it_names(self):
        t = DecisionTable(now=100)
        t.put(Kind.EXEC, "nc", Verdict(Action.DENY, 99, 100))
        assert t.lookup(Kind.EXEC, "nc").action is Action.ALLOW

    def test_still_live_one_second_before(self):
        t = DecisionTable(now=99)
        t.put(Kind.EXEC, "nc", Verdict(Action.DENY, 99, 100))
        assert t.lookup(Kind.EXEC, "nc").action is Action.DENY

    def test_a_stalled_advisor_stops_enforcing(self):
        # The point of the TTL: if nothing refreshes the table, the kernel
        # goes back to allowing rather than enforcing a stale opinion forever.
        t = DecisionTable(now=0)
        t.put(Kind.EXEC, "nc", Verdict(Action.DENY, 99, 300))
        assert t.lookup(Kind.EXEC, "nc").action is Action.DENY
        t.set_now(301)
        assert t.lookup(Kind.EXEC, "nc").action is Action.ALLOW


class TestSweep:
    def test_removes_only_expired_entries(self):
        t = DecisionTable(now=100)
        t.put(Kind.EXEC, "old", Verdict(Action.FLAG, 10, 50))
        t.put(Kind.EXEC, "new", Verdict(Action.FLAG, 10, 500))
        t.put(Kind.EXEC, "forever", Verdict(Action.FLAG, 10, 0))
        assert t.sweep() == 1
        assert len(t) == 2

    def test_is_idempotent(self):
        t = DecisionTable(now=100)
        t.put(Kind.EXEC, "old", Verdict(Action.FLAG, 10, 50))
        t.sweep()
        assert t.sweep() == 0


class TestExport:
    def test_gives_fixed_size_key_value_pairs(self):
        t = DecisionTable(now=0)
        t.put(Kind.EXEC, "a", Verdict(Action.FLAG, 1, 0))
        t.put(Kind.CONNECT, "b", Verdict(Action.DENY, 2, 0))
        rows = t.export()
        assert len(rows) == 2
        assert all(len(k) == KEY_SIZE and len(v) == VERDICT_SIZE for k, v in rows)

    def test_ordering_is_stable(self):
        t = DecisionTable(now=0)
        for c in "dcba":
            t.put(Kind.EXEC, c, Verdict(Action.FLAG, 1, 0))
        assert t.export() == t.export()
