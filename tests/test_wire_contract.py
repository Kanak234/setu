"""The C and the Python must agree about every struct on the boundary.

If they drift, nothing crashes -- events decode into plausible nonsense and
map lookups silently miss. That is the worst kind of bug, so it gets a test.
The C is parsed as text because it cannot be compiled here (no clang), which
is precisely why the contract needs pinning from this side.
"""

import re
from pathlib import Path

from setu.events import WIRE_SIZE
from setu.policy import KEY_SIZE, VERDICT_SIZE, Action
from setu.events import Kind

BPF_C = Path(__file__).resolve().parent.parent / "bpf" / "setu.bpf.c"

C_TYPE_SIZES = {"__u8": 1, "__s8": 1, "__u16": 2, "__u32": 4, "__u64": 8, "char": 1}


def defines() -> dict[str, int]:
    """Integer #defines from the BPF source, so array sizes written as macros
    resolve instead of failing to parse."""
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(r"^#define\s+(\w+)\s+(\d+)\s*$", BPF_C.read_text(), re.M)
    }


def struct_size(name: str) -> int:
    """Size of a packed C struct, read out of the source."""
    src = BPF_C.read_text()
    m = re.search(rf"struct {name} \{{(.*?)\}}", src, re.S)
    assert m, f"struct {name} not found in {BPF_C.name}"
    consts = defines()
    total = 0
    for line in m.group(1).splitlines():
        line = line.split("//")[0].strip().rstrip(";")
        if not line:
            continue
        mm = re.match(r"(__u\d+|__s\d+|char)\s+(\w+)(?:\[(\w+)\])?$", line)
        assert mm, f"could not parse field {line!r} in struct {name}"
        count = mm.group(3)
        n = 1 if count is None else (int(count) if count.isdigit() else consts[count])
        total += C_TYPE_SIZES[mm.group(1)] * n
    return total


def test_the_bpf_source_is_present():
    assert BPF_C.exists()


def test_event_struct_matches_python():
    assert struct_size("setu_event") == WIRE_SIZE


def test_key_struct_matches_python():
    assert struct_size("setu_key") == KEY_SIZE


def test_verdict_struct_matches_python():
    assert struct_size("setu_verdict") == VERDICT_SIZE


def test_every_struct_on_the_boundary_is_packed():
    # Without __packed__ the compiler inserts padding and the sizes above stop
    # meaning anything.
    src = BPF_C.read_text()
    for name in ("setu_event", "setu_key", "setu_verdict"):
        m = re.search(rf"struct {name} \{{.*?\}}\s*(__attribute__\(\(packed\)\))?", src, re.S)
        assert m and m.group(1), f"struct {name} is not packed"


def test_kind_numbering_matches_the_c_enum():
    src = BPF_C.read_text()
    for k in Kind:
        assert re.search(rf"SETU_{k.name}\s*=\s*{int(k)}\b", src), \
            f"SETU_{k.name} = {int(k)} missing from the C enum"


def test_the_c_treats_a_missing_entry_as_allow():
    # `if (!v) return 0;` only means ALLOW while ALLOW is 0.
    assert int(Action.ALLOW) == 0
    assert re.search(r"if\s*\(!v\)\s*\n?\s*return 0;", BPF_C.read_text())


def test_the_c_checks_expiry_like_the_python_does():
    assert re.search(r"expires_s\s*&&.*<=\s*now_s", BPF_C.read_text())


def test_the_comm_hash_loop_is_bounded():
    # The eBPF verifier rejects anything it cannot prove terminates.
    src = BPF_C.read_text()
    assert "for (int i = 0; i < SETU_COMM_LEN - 1; i++)" in src
    assert "for (int k = 0; k < 8; k++)" in src


def test_the_ringbuf_drops_rather_than_blocks():
    src = BPF_C.read_text()
    assert re.search(r"if\s*\(!e\)\s*\n\s*return;", src)
