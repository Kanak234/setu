"""The event the sensing layer emits, and its wire format.

One record per observation. The BPF side writes these as a fixed-size C
struct into a ring buffer; this module is the single definition of that
layout, so the C header and the Python reader cannot drift apart.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

# struct setu_event { u64 ts_ns; u32 pid; u32 tgid; u16 kind; u16 _pad;
#                     u64 a; u64 b; char comm[16]; }
WIRE = "<QIIHHQQ16s"
WIRE_SIZE = struct.calcsize(WIRE)


class Kind(IntEnum):
    """What the kernel observed. Values are frozen -- the BPF side hardcodes
    them, so renumbering here silently corrupts every decoded event."""

    SCHED_SWITCH = 1
    SCHED_WAKEUP = 2
    EXEC = 3
    FILE_OPEN = 4
    CONNECT = 5


@dataclass(frozen=True)
class Event:
    ts_ns: int
    pid: int
    tgid: int
    kind: Kind
    a: int
    b: int
    comm: str

    @classmethod
    def unpack(cls, raw: bytes) -> "Event":
        if len(raw) != WIRE_SIZE:
            raise ValueError(f"event must be {WIRE_SIZE} bytes, got {len(raw)}")
        ts, pid, tgid, kind, _pad, a, b, comm = struct.unpack(WIRE, raw)
        return cls(
            ts_ns=ts,
            pid=pid,
            tgid=tgid,
            kind=Kind(kind),
            a=a,
            b=b,
            comm=comm.split(b"\x00", 1)[0].decode("utf-8", "replace"),
        )

    def pack(self) -> bytes:
        return struct.pack(
            WIRE, self.ts_ns, self.pid, self.tgid, int(self.kind), 0,
            self.a, self.b, self.comm.encode("utf-8")[:15],
        )

    def as_json(self) -> dict:
        return {
            "ts_ns": self.ts_ns, "pid": self.pid, "tgid": self.tgid,
            "kind": self.kind.name, "a": self.a, "b": self.b, "comm": self.comm,
        }

    @classmethod
    def from_json(cls, d: dict) -> "Event":
        return cls(
            ts_ns=int(d["ts_ns"]), pid=int(d["pid"]), tgid=int(d["tgid"]),
            kind=Kind[d["kind"]] if isinstance(d["kind"], str) else Kind(d["kind"]),
            a=int(d.get("a", 0)), b=int(d.get("b", 0)), comm=d.get("comm", ""),
        )
