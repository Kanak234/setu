import struct

import pytest

from setu.events import WIRE_SIZE, Event, Kind


def make(**kw):
    base = dict(ts_ns=1_000, pid=42, tgid=42, kind=Kind.EXEC, a=0, b=0, comm="bash")
    base.update(kw)
    return Event(**base)


class TestWireFormat:
    def test_packs_to_a_fixed_size(self):
        assert len(make().pack()) == WIRE_SIZE

    def test_size_is_the_same_for_every_event(self):
        assert len(make(comm="x").pack()) == len(make(comm="a-long-name-here").pack())

    def test_round_trips(self):
        e = make(ts_ns=99, pid=7, tgid=8, kind=Kind.CONNECT, a=1, b=2, comm="curl")
        assert Event.unpack(e.pack()) == e

    def test_truncates_comm_to_the_kernel_limit(self):
        # The kernel's comm field is 16 bytes including the terminator.
        e = make(comm="a" * 40)
        assert len(Event.unpack(e.pack()).comm) <= 15

    def test_rejects_a_short_buffer(self):
        with pytest.raises(ValueError):
            Event.unpack(b"\x00" * (WIRE_SIZE - 1))

    def test_rejects_a_long_buffer(self):
        with pytest.raises(ValueError):
            Event.unpack(b"\x00" * (WIRE_SIZE + 1))

    def test_rejects_an_unknown_kind(self):
        raw = bytearray(make().pack())
        struct.pack_into("<H", raw, 16, 250)
        with pytest.raises(ValueError):
            Event.unpack(bytes(raw))

    def test_survives_non_utf8_in_comm(self):
        raw = bytearray(make().pack())
        raw[-16:] = b"\xff\xfe" + b"\x00" * 14
        assert isinstance(Event.unpack(bytes(raw)).comm, str)


class TestJson:
    def test_round_trips(self):
        e = make(kind=Kind.FILE_OPEN, a=3)
        assert Event.from_json(e.as_json()) == e

    def test_kind_is_written_by_name(self):
        assert make(kind=Kind.SCHED_WAKEUP).as_json()["kind"] == "SCHED_WAKEUP"

    def test_accepts_a_numeric_kind(self):
        assert Event.from_json({"ts_ns": 1, "pid": 1, "tgid": 1, "kind": 3}).kind is Kind.EXEC


def test_kind_values_are_frozen():
    # The BPF side hardcodes these. Renumbering silently corrupts every event.
    assert [(k.name, int(k)) for k in Kind] == [
        ("SCHED_SWITCH", 1), ("SCHED_WAKEUP", 2), ("EXEC", 3),
        ("FILE_OPEN", 4), ("CONNECT", 5),
    ]
