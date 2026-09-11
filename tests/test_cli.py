import io
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from unittest.mock import patch

from setu.cli import main, health_check
from setu.events import Event
from setu.policy import DecisionTable
from setu import __version__


class TestHealthCheck:
    def test_health_check_passes_on_unaltered_codebase(self):
        results = health_check()
        assert results["wire_size"] == "pass"
        assert results["verdict_size"] == "pass"
        assert results["key_size"] == "pass"
        assert results["allow_is_zero"] == "pass"
        assert results["event_roundtrip"] == "pass"
        assert results["decision_table"] == "pass"

    def test_health_check_detects_event_failure(self, monkeypatch):
        monkeypatch.setattr(Event, "unpack", lambda raw: (_ for _ in ()).throw(ValueError("corrupt")))
        results = health_check()
        assert "fail" in results["event_roundtrip"]

    def test_health_check_detects_decision_table_failure(self, monkeypatch):
        monkeypatch.setattr(DecisionTable, "lookup", lambda self, kind, comm: (_ for _ in ()).throw(RuntimeError("lookup err")))
        results = health_check()
        assert "fail" in results["decision_table"]


class TestCliCommands:
    def test_main_no_args_prints_help_and_exits_2(self, capsys):
        rc = main([])
        captured = capsys.readouterr()
        assert rc == 2
        assert "usage:" in captured.err.lower() or "setu" in captured.err.lower()

    def test_version_command(self, capsys):
        rc = main(["version"])
        captured = capsys.readouterr()
        assert rc == 0
        assert captured.out.strip() == f"setu {__version__}"

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert f"setu {__version__}" in captured.out

    def test_health_command_text(self, capsys):
        rc = main(["health"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "HEALTHY" in captured.out
        assert "[PASS]" in captured.out

    def test_health_command_json(self, capsys):
        rc = main(["health", "--json"])
        captured = capsys.readouterr()
        assert rc == 0
        data = json.loads(captured.out)
        assert data["status"] == "healthy"
        assert data["version"] == __version__
        assert data["checks"]["wire_size"] == "pass"

    def test_health_command_failure(self, monkeypatch, capsys):
        monkeypatch.setattr("setu.cli.health_check", lambda: {"wire_size": "fail"})
        rc = main(["health"])
        captured = capsys.readouterr()
        assert rc == 1
        assert "UNHEALTHY" in captured.out

    def test_review_command_from_stdin(self, monkeypatch, capsys):
        sample_event = json.dumps({
            "ts_ns": 1000,
            "pid": 12,
            "tgid": 12,
            "kind": "EXEC",
            "a": 0,
            "b": 0,
            "comm": "curl"
        })
        mock_stdin = io.StringIO(sample_event + "\n\nmalformed-line\n")
        monkeypatch.setattr("sys.stdin", mock_stdin)

        with patch("setu.advisor.Advisor.review") as mock_review:
            from setu.advisor import Advice, Action
            mock_review.return_value = [Advice(comm="curl", action=Action.FLAG, confidence=80, why="test")]
            rc = main(["review", "-"])
            assert rc == 0
            captured = capsys.readouterr()
            assert "warning: skipping invalid event line" in captured.err
            advice_json = json.loads(captured.out.strip())
            assert advice_json["comm"] == "curl"
            assert advice_json["action"] == "FLAG"
            assert advice_json["confidence"] == 80

    def test_review_command_from_file(self, tmp_path, capsys):
        ev_file = tmp_path / "events.jsonl"
        ev_file.write_text(json.dumps({
            "ts_ns": 2000,
            "pid": 44,
            "tgid": 44,
            "kind": "CONNECT",
            "a": 1,
            "b": 0,
            "comm": "nc"
        }) + "\n")

        with patch("setu.advisor.Advisor.review") as mock_review:
            from setu.advisor import Advice, Action
            mock_review.return_value = [Advice(comm="nc", action=Action.ALLOW, confidence=90, why="safe")]
            rc = main(["review", str(ev_file)])
            assert rc == 0
            captured = capsys.readouterr()
            advice_json = json.loads(captured.out.strip())
            assert advice_json["comm"] == "nc"
            assert advice_json["action"] == "ALLOW"

    def test_module_main_invocation(self):
        root_dir = str(Path(__file__).resolve().parent.parent)
        env = dict(os.environ)
        env["PYTHONPATH"] = root_dir
        res = subprocess.run(
            [sys.executable, "-m", "setu", "health", "--json"],
            cwd=root_dir,
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "healthy"
