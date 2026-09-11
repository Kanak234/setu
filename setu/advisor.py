"""Asks a local model what it makes of a batch of events.

Two things matter here.

First, this runs on its own clock. Nothing in the kernel path waits for it.
If the model is slow, or down, or talking nonsense, the decision table simply
does not change and the kernel keeps using what it already has.

Second, the model's output is untrusted input. It is a language model, not an
oracle: it will occasionally return prose, malformed JSON, an unknown action
name, or a confidence of 900. Every field is validated before it can become a
verdict, and anything that fails validation is dropped rather than guessed at.
A model that has a bad day must not be able to widen what the kernel denies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass

from .events import Event
from .policy import Action, Verdict

DEFAULT_ENDPOINT = "http://localhost:11434"

# The model may never escalate past this on its own. Raising it is a
# deliberate decision for a human, not something a prompt can talk us into.
MAX_MODEL_ACTION = Action.FLAG

PROMPT = """You are reviewing process activity summarised from kernel events.

For each process below, answer with one JSON object per line and nothing else:
{{"comm": "<name>", "action": "ALLOW|FLAG", "confidence": <0-100>, "why": "<short>"}}

Use FLAG only when the behaviour is genuinely unusual for that program.
When in doubt use ALLOW.

Activity:
{summary}"""


@dataclass(frozen=True)
class Advice:
    comm: str
    action: Action
    confidence: int
    why: str


def summarise(events: list[Event]) -> str:
    """Collapse a batch into per-process counts, so the prompt stays small
    however many events arrived."""
    per: dict[str, Counter] = {}
    for e in events:
        per.setdefault(e.comm, Counter())[e.kind.name] += 1
    lines = []
    for comm in sorted(per):
        counts = ", ".join(f"{k}={v}" for k, v in sorted(per[comm].items()))
        lines.append(f"- {comm}: {counts}")
    return "\n".join(lines)


def parse_advice(text: str) -> list[Advice]:
    """Pull whatever valid advice the reply contains, discard the rest.

    Deliberately forgiving about surrounding junk and strict about the fields,
    because those are different risks: extra prose is harmless, a malformed
    action is not.
    """
    out: list[Advice] = []
    for line in text.splitlines():
        line = line.strip().strip("`")
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        comm = d.get("comm")
        if not isinstance(comm, str) or not comm or len(comm) > 15:
            continue
        name = str(d.get("action", "")).upper()
        if name not in Action.__members__:
            continue
        action = Action[name]
        if action > MAX_MODEL_ACTION:
            # The model asked for more than it is allowed to ask for.
            continue
        conf = d.get("confidence")
        if not isinstance(conf, int) or isinstance(conf, bool) or not 0 <= conf <= 100:
            continue
        why = d.get("why", "")
        out.append(Advice(comm, action, conf, str(why)[:120]))
    return out


class Advisor:
    def __init__(self, model: str, endpoint: str = DEFAULT_ENDPOINT, timeout: float = 120.0):
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def _post(self, prompt: str) -> str:
        body = json.dumps({
            "model": self.model, "prompt": prompt, "stream": False,
            "options": {"temperature": 0, "num_predict": 400},
        }).encode()
        req = urllib.request.Request(
            f"{self.endpoint}/api/generate", data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read()).get("response", "")

    def review(self, events: list[Event]) -> list[Advice]:
        """Returns [] on any failure. A silent advisor leaves the table alone,
        which is the safe direction."""
        if not events:
            return []
        try:
            reply = self._post(PROMPT.format(summary=summarise(events)))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            return []
        return parse_advice(reply)


def advice_to_verdict(a: Advice, now: int, ttl_s: int = 300) -> Verdict:
    """Advice becomes a verdict that expires. If the advisor stops running,
    the kernel drifts back to ALLOW instead of enforcing a stale opinion."""
    return Verdict(action=a.action, confidence=a.confidence, expires_s=now + ttl_s)
