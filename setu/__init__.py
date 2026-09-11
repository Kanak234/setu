"""सेतु (SETU) — A bridge between a local LLM and the Linux kernel.

eBPF senses and enforces in the kernel; a local model advises in userspace;
neither waits for the other.
"""

from __future__ import annotations

from .advisor import Advice, Advisor, advice_to_verdict
from .events import Event, Kind, WIRE_SIZE
from .policy import Action, DecisionTable, Verdict

__version__ = "0.1.0"
__all__ = [
    "__version__",
    "Advice",
    "Advisor",
    "Action",
    "DecisionTable",
    "Event",
    "Kind",
    "Verdict",
    "WIRE_SIZE",
    "advice_to_verdict",
]
