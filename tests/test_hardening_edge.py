import json
import urllib.error
import urllib.request
from unittest.mock import patch, MagicMock

from setu.advisor import Advisor, summarise, parse_advice
from setu.events import Event, Kind, WIRE_SIZE
from setu.policy import Action, Verdict, DecisionTable, comm_hash


class TestAdvisorHttpAndEdge:
    def test_post_success_parses_response(self):
        adv = Advisor(model="llama3", endpoint="http://mock-endpoint:11434", timeout=5.0)
        mock_resp_body = json.dumps({"response": "{\"comm\": \"nc\", \"action\": \"FLAG\", \"confidence\": 85, \"why\": \"suspicious\"}"}).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_resp_body
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
            advice = adv.review([Event(ts_ns=100, pid=1, tgid=1, kind=Kind.CONNECT, a=0, b=0, comm="nc")])
            assert len(advice) == 1
            assert advice[0].comm == "nc"
            assert advice[0].action == Action.FLAG
            assert advice[0].confidence == 85

            req = mock_urlopen.call_args[0][0]
            assert req.full_url == "http://mock-endpoint:11434/api/generate"
            body = json.loads(req.data.decode())
            assert body["model"] == "llama3"

    def test_post_url_error_returns_empty(self):
        adv = Advisor(model="test")
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            advice = adv.review([Event(ts_ns=100, pid=1, tgid=1, kind=Kind.EXEC, a=0, b=0, comm="sh")])
            assert advice == []

    def test_post_bad_json_response_returns_empty(self):
        adv = Advisor(model="test")
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"NOT_JSON"
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            advice = adv.review([Event(ts_ns=100, pid=1, tgid=1, kind=Kind.EXEC, a=0, b=0, comm="sh")])
            assert advice == []

    def test_summarise_empty_returns_empty(self):
        assert summarise([]) == ""

    def test_parse_advice_handles_markdown_and_raw_lines(self):
        raw = """
        ```json
        {"comm": "safe_proc", "action": "ALLOW", "confidence": 99, "why": "standard binary"}
        ```
        prose here
        {"comm": "curl", "action": "FLAG", "confidence": 60, "why": "outbound connection"}
        """
        advice = parse_advice(raw)
        assert len(advice) == 2
        assert advice[0].comm == "safe_proc"
        assert advice[1].comm == "curl"

    def test_parse_advice_bounds(self):
        # boundary 0 and 100
        assert len(parse_advice('{"comm": "p1", "action": "ALLOW", "confidence": 0, "why": ""}')) == 1
        assert len(parse_advice('{"comm": "p2", "action": "ALLOW", "confidence": 100, "why": ""}')) == 1
        assert len(parse_advice('{"comm": "p3", "action": "ALLOW", "confidence": 101, "why": ""}')) == 0
        assert len(parse_advice('{"comm": "p4", "action": "ALLOW", "confidence": -1, "why": ""}')) == 0


class TestEventEdgeCases:
    def test_event_comm_unicode_encoding(self):
        e = Event(ts_ns=500, pid=10, tgid=10, kind=Kind.EXEC, a=1, b=2, comm="सेतु")
        packed = e.pack()
        assert len(packed) == WIRE_SIZE
        unpacked = Event.unpack(packed)
        assert isinstance(unpacked.comm, str)

    def test_event_comm_with_null_terminator(self):
        e = Event(ts_ns=500, pid=10, tgid=10, kind=Kind.EXEC, a=1, b=2, comm="proc\x00hidden")
        packed = e.pack()
        unpacked = Event.unpack(packed)
        assert unpacked.comm == "proc"

    def test_event_from_json_kind_variations(self):
        e1 = Event.from_json({"ts_ns": 10, "pid": 2, "tgid": 2, "kind": "EXEC"})
        assert e1.kind == Kind.EXEC
        e2 = Event.from_json({"ts_ns": 10, "pid": 2, "tgid": 2, "kind": 3})
        assert e2.kind == Kind.EXEC


class TestPolicyEdgeCases:
    def test_comm_hash_deterministic_for_long_strings(self):
        h1 = comm_hash("systemd-resolved-super-long-name")
        h2 = comm_hash("systemd-resolved-different-suffix")
        # Truncated to 15 bytes in crc calculation
        assert h1 == h2

    def test_decision_table_overwrites_existing_entry(self):
        table = DecisionTable(now=10)
        table.put(Kind.EXEC, "app", Verdict(Action.FLAG, 40, 100))
        assert table.lookup(Kind.EXEC, "app").confidence == 40

        table.put(Kind.EXEC, "app", Verdict(Action.ALLOW, 90, 100))
        assert table.lookup(Kind.EXEC, "app").confidence == 90
        assert table.lookup(Kind.EXEC, "app").action == Action.ALLOW

    def test_decision_table_expiry_boundaries(self):
        table = DecisionTable(now=50)
        table.put(Kind.EXEC, "app", Verdict(Action.FLAG, 80, 50))
        # At exactly now == expires_s, it decays to ALLOW
        assert table.lookup(Kind.EXEC, "app").action == Action.ALLOW

        table.set_now(49)
        assert table.lookup(Kind.EXEC, "app").action == Action.FLAG
