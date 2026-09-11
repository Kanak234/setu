"""Command-line interface and diagnostic health checks for SETU."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .advisor import Advisor
from .events import WIRE_SIZE, Event, Kind
from .policy import KEY_SIZE, VERDICT_SIZE, Action, DecisionTable, Verdict


def health_check() -> dict[str, str]:
    """Run self-test diagnostics verifying wire contracts and policy invariants."""
    results = {}

    # 1. Wire size checks
    results["wire_size"] = "pass" if WIRE_SIZE == 52 else "fail"
    results["verdict_size"] = "pass" if VERDICT_SIZE == 8 else "fail"
    results["key_size"] = "pass" if KEY_SIZE == 8 else "fail"

    # 2. Kernel invariant checks
    results["allow_is_zero"] = "pass" if int(Action.ALLOW) == 0 else "fail"

    # 3. Serialization round-trip
    try:
        sample_event = Event(ts_ns=1000, pid=1, tgid=1, kind=Kind.EXEC, a=0, b=0, comm="test")
        unpacked = Event.unpack(sample_event.pack())
        results["event_roundtrip"] = "pass" if unpacked == sample_event else "fail"
    except Exception as exc:
        results["event_roundtrip"] = f"fail: {exc}"

    # 4. Decision table invariants
    try:
        dt = DecisionTable(now=100)
        dt.put(Kind.EXEC, "test", Verdict(Action.FLAG, 50, 200))
        lookup_res = dt.lookup(Kind.EXEC, "test")
        results["decision_table"] = "pass" if lookup_res.action is Action.FLAG else "fail"
    except Exception as exc:
        results["decision_table"] = f"fail: {exc}"

    return results


def run_health(args: argparse.Namespace) -> int:
    checks = health_check()
    all_passed = all(v == "pass" for v in checks.values())
    output = {
        "status": "healthy" if all_passed else "unhealthy",
        "version": __version__,
        "checks": checks,
    }
    if args.json:
        sys.stdout.write(json.dumps(output, indent=2) + "\n")
    else:
        sys.stdout.write(f"SETU Status: {output["status"].upper()} (v{__version__})\n")
        for check, res in checks.items():
            sys.stdout.write(f"  [{res.upper()}] {check}\n")
    return 0 if all_passed else 1


def run_version(args: argparse.Namespace) -> int:
    sys.stdout.write(f"setu {__version__}\n")
    return 0


def run_review(args: argparse.Namespace) -> int:
    events: list[Event] = []
    source = sys.stdin if args.input == "-" else open(args.input, "r", encoding="utf-8")
    with source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                events.append(Event.from_json(data))
            except Exception as err:
                sys.stderr.write(f"warning: skipping invalid event line ({err})\n")

    advisor = Advisor(model=args.model, endpoint=args.endpoint, timeout=args.timeout)
    advice_list = advisor.review(events)
    for adv in advice_list:
        sys.stdout.write(
            json.dumps({
                "comm": adv.comm,
                "action": adv.action.name,
                "confidence": adv.confidence,
                "why": adv.why,
            }) + "\n"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="setu",
        description="Bridge between a local LLM and Linux kernel eBPF.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # health subcommand
    health_p = subparsers.add_parser("health", help="Execute runtime self-tests and diagnostic checks")
    health_p.add_argument("--json", action="store_true", help="Format output as JSON")
    health_p.set_defaults(func=run_health)

    # version subcommand
    version_p = subparsers.add_parser("version", help="Print version information")
    version_p.set_defaults(func=run_version)

    # review subcommand
    review_p = subparsers.add_parser("review", help="Review event batches through the LLM advisor")
    review_p.add_argument("--model", default="llama3", help="Target Ollama model name")
    review_p.add_argument("--endpoint", default="http://localhost:11434", help="Ollama API base URL")
    review_p.add_argument("--timeout", type=float, default=30.0, help="HTTP request timeout in seconds")
    review_p.add_argument("input", nargs="?", default="-", help="Input file containing JSON event lines (defaults to stdin)")
    review_p.set_defaults(func=run_review)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        return args.func(args)
    parser.print_help(sys.stderr)
    return 2
