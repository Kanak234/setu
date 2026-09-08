"""The advisor treats the model's reply as untrusted input. These tests are
mostly about what it refuses."""

import json

import pytest

from setu.advisor import (
    MAX_MODEL_ACTION, Advice, Advisor, advice_to_verdict, parse_advice, summarise,
)
from setu.events import Event, Kind
from setu.policy import Action


def ev(comm, kind=Kind.EXEC, ts=0):
    return Event(ts_ns=ts, pid=1, tgid=1, kind=kind, a=0, b=0, comm=comm)


def line(**kw):
    d = {"comm": "nc", "action": "FLAG", "confidence": 80, "why": "unusual"}
    d.update(kw)
    return json.dumps(d)


class TestSummarise:
    def test_counts_per_process_and_kind(self):
        s = summarise([ev("nc"), ev("nc"), ev("nc", Kind.CONNECT)])
        assert "nc:" in s and "EXEC=2" in s and "CONNECT=1" in s

    def test_one_line_per_process(self):
        assert len(summarise([ev("a"), ev("b"), ev("a")]).splitlines()) == 2

    def test_is_ordered_so_the_prompt_is_reproducible(self):
        batch = [ev("z"), ev("a"), ev("m")]
        assert summarise(batch) == summarise(list(reversed(batch)))

    def test_size_grows_with_processes_not_events(self):
        few = summarise([ev("a")])
        many = summarise([ev("a")] * 5000)
        assert len(many) - len(few) < 20


class TestParseAdviceAccepts:
    def test_a_well_formed_line(self):
        [a] = parse_advice(line())
        assert a.comm == "nc" and a.action is Action.FLAG and a.confidence == 80

    def test_several_lines(self):
        assert len(parse_advice(line(comm="a") + "\n" + line(comm="b"))) == 2

    def test_a_lowercase_action(self):
        assert parse_advice(line(action="flag"))[0].action is Action.FLAG

    def test_lines_wrapped_in_a_code_fence(self):
        assert len(parse_advice("```\n" + line() + "\n```")) == 1

    def test_good_lines_among_prose(self):
        text = "Here is what I found:\n" + line() + "\nHope that helps!"
        assert len(parse_advice(text)) == 1

    def test_it_truncates_a_rambling_reason(self):
        assert len(parse_advice(line(why="x" * 500))[0].why) <= 120


class TestParseAdviceRefuses:
    def test_the_model_cannot_escalate_beyond_its_ceiling(self):
        # The whole point: a prompt-injected or confused model must not be
        # able to make the kernel deny things.
        assert parse_advice(line(action="DENY")) == []
        assert parse_advice(line(action="THROTTLE")) == []

    def test_an_unknown_action(self):
        assert parse_advice(line(action="OBLITERATE")) == []

    def test_confidence_out_of_range(self):
        assert parse_advice(line(confidence=900)) == []
        assert parse_advice(line(confidence=-5)) == []

    def test_confidence_that_is_not_an_integer(self):
        assert parse_advice(line(confidence="high")) == []
        assert parse_advice(line(confidence=80.5)) == []

    def test_a_boolean_confidence(self):
        # bool is an int subclass in Python; it must not slip through.
        assert parse_advice('{"comm":"x","action":"FLAG","confidence":true}') == []

    def test_a_missing_comm(self):
        assert parse_advice('{"action":"FLAG","confidence":50}') == []

    def test_an_empty_comm(self):
        assert parse_advice(line(comm="")) == []

    def test_a_comm_longer_than_the_kernel_allows(self):
        assert parse_advice(line(comm="a" * 40)) == []

    def test_a_non_string_comm(self):
        assert parse_advice(line(comm=123)) == []

    def test_malformed_json(self):
        assert parse_advice('{"comm": "nc", "action": ') == []

    def test_plain_prose(self):
        assert parse_advice("I think nc looks suspicious, maybe block it?") == []

    def test_an_empty_reply(self):
        assert parse_advice("") == []

    def test_it_keeps_the_good_line_and_drops_the_bad_one(self):
        [a] = parse_advice(line(comm="ok") + "\n" + line(comm="bad", action="DENY"))
        assert a.comm == "ok"


class TestReviewFailsSafe:
    """A broken advisor must change nothing, never guess."""

    def test_an_empty_batch_does_not_call_the_model(self):
        adv = Advisor("model")
        adv._post = lambda p: pytest.fail("should not have been called")
        assert adv.review([]) == []

    def test_a_network_error_yields_no_advice(self):
        adv = Advisor("model")

        def boom(prompt):
            raise OSError("connection refused")

        adv._post = boom
        assert adv.review([ev("nc")]) == []

    def test_a_timeout_yields_no_advice(self):
        adv = Advisor("model")

        def boom(prompt):
            raise TimeoutError()

        adv._post = boom
        assert adv.review([ev("nc")]) == []

    def test_a_nonsense_reply_yields_no_advice(self):
        adv = Advisor("model")
        adv._post = lambda p: "certainly! here are my thoughts..."
        assert adv.review([ev("nc")]) == []

    def test_a_good_reply_is_returned(self):
        adv = Advisor("model")
        adv._post = lambda p: line()
        assert adv.review([ev("nc")])[0].action is Action.FLAG


class TestAdviceToVerdict:
    def test_it_expires(self):
        v = advice_to_verdict(Advice("nc", Action.FLAG, 80, ""), now=1000, ttl_s=300)
        assert v.expires_s == 1300

    def test_it_carries_the_action_and_confidence_through(self):
        v = advice_to_verdict(Advice("nc", Action.FLAG, 80, ""), now=0)
        assert v.action is Action.FLAG and v.confidence == 80

    def test_nothing_the_model_says_ever_becomes_permanent(self):
        v = advice_to_verdict(Advice("nc", Action.FLAG, 100, ""), now=0)
        assert v.expires_s > 0


def test_the_ceiling_is_flag():
    assert MAX_MODEL_ACTION is Action.FLAG
