"""The decision table the kernel reads.

This is the whole safety argument of the project, so it is worth stating
plainly: the kernel never calls the model. It looks up a verdict that was
written here earlier and returns immediately.

That constraint shapes everything below.

  * A verdict is one byte. No floats -- the kernel cannot use the FPU freely.
  * Lookup is a single hash-map read. No loops, so the eBPF verifier is happy
    and the cost does not depend on how much the model has learned.
  * Every entry carries an expiry. A model that stops updating decays back to
    ALLOW rather than freezing whatever it last believed.

Measured on this machine, one trivial Ollama round-trip takes about 5
seconds. A scheduler hook has microseconds. Those two numbers are why the
layers are decoupled instead of chained.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum

from .events import Kind

# struct setu_verdict { u8 action; u8 confidence; u16 _pad; u32 expires_s; }
VERDICT_WIRE = "<BBHI"
VERDICT_SIZE = struct.calcsize(VERDICT_WIRE)

KEY_WIRE = "<HHI"  # kind, _pad, comm_hash
KEY_SIZE = struct.calcsize(KEY_WIRE)


class Action(IntEnum):
    """What the kernel should do. ALLOW is 0 so that a missing map entry --
    which reads back as zeroes -- means 'do nothing', never 'block'."""

    ALLOW = 0
    FLAG = 1
    THROTTLE = 2
    DENY = 3


@dataclass(frozen=True)
class Verdict:
    action: Action
    confidence: int  # 0..100
    expires_s: int   # unix seconds; 0 means never

    def __post_init__(self):
        if not 0 <= self.confidence <= 100:
            raise ValueError(f"confidence must be 0..100, got {self.confidence}")
        if self.expires_s < 0:
            raise ValueError("expires_s cannot be negative")

    def pack(self) -> bytes:
        return struct.pack(VERDICT_WIRE, int(self.action), self.confidence, 0, self.expires_s)

    @classmethod
    def unpack(cls, raw: bytes) -> "Verdict":
        action, conf, _pad, exp = struct.unpack(VERDICT_WIRE, raw)
        return cls(Action(action), conf, exp)


def comm_hash(comm: str) -> int:
    """Stable 32-bit hash of a process name.

    crc32 is used because the BPF side can compute the same value in a bounded
    loop over the 16-byte comm field. A language-specific hash could not be
    reproduced there.
    """
    return zlib.crc32(comm.encode("utf-8")[:15]) & 0xFFFFFFFF


def key_for(kind: Kind, comm: str) -> bytes:
    return struct.pack(KEY_WIRE, int(kind), 0, comm_hash(comm))


class DecisionTable:
    """The userspace mirror of the BPF map.

    Kept as a plain dict so the policy can be tested, replayed and diffed
    without a kernel. `export()` produces exactly the bytes that would be
    written into the map.
    """

    def __init__(self, now: int = 0):
        self._entries: dict[bytes, Verdict] = {}
        self._now = now

    def set_now(self, now: int) -> None:
        self._now = now

    def put(self, kind: Kind, comm: str, verdict: Verdict) -> None:
        self._entries[key_for(kind, comm)] = verdict

    def lookup(self, kind: Kind, comm: str) -> Verdict:
        """What the kernel would decide. Expired or missing entries are ALLOW."""
        v = self._entries.get(key_for(kind, comm))
        if v is None:
            return Verdict(Action.ALLOW, 0, 0)
        if v.expires_s and v.expires_s <= self._now:
            return Verdict(Action.ALLOW, 0, 0)
        return v

    def sweep(self) -> int:
        """Drop expired entries. Returns how many were removed."""
        dead = [k for k, v in self._entries.items() if v.expires_s and v.expires_s <= self._now]
        for k in dead:
            del self._entries[k]
        return len(dead)

    def export(self) -> list[tuple[bytes, bytes]]:
        """Key/value byte pairs, ready for `bpftool map update`."""
        return [(k, v.pack()) for k, v in sorted(self._entries.items())]

    def __len__(self) -> int:
        return len(self._entries)
