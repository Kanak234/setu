# सेतु · SETU

A bridge between a local language model and the Linux kernel.

The kernel senses and enforces. The model thinks. Neither waits for the other.

```
kernel (eBPF)  ──events──▶  ring buffer  ──▶  daemon  ──▶  Ollama
      ▲                                          │
      └────────── verdict in a BPF map ◀──────────┘
```

## Why it is shaped this way

The obvious idea — run the model in the kernel — cannot work. Kernel space has
no free use of the FPU, a stack measured in kilobytes, no dynamic linking, and
no room to block. An LLM needs all four. A crash there is a panic, not a
segfault.

The measured numbers say the same thing more plainly. On the machine this was
built on, one trivial Ollama round-trip takes **1.4–5 seconds**. A scheduler
hook has **microseconds**. Chaining those two would deadlock the machine.

So the layers are decoupled, and one rule holds everything together:

> **The kernel never calls the model. It reads a verdict written earlier.**

The model fills a table on its own clock. The kernel reads that table in a
single hash lookup and returns. If the model is slow, wrong, or dead, the
kernel is unaffected.

## What the model is not allowed to do

The reply from a language model is untrusted input. It will sometimes return
prose, malformed JSON, an unknown action, or a confidence of 900. Three limits
apply, and each has tests:

- **A ceiling.** The model may raise a verdict no further than `FLAG`. If it
  asks for `DENY` or `THROTTLE`, the advice is discarded. A confused or
  prompt-injected model cannot make the kernel block anything.
- **An expiry.** Every verdict carries a TTL. If the daemon stops, entries
  decay back to `ALLOW` rather than freezing whatever was last believed.
- **`ALLOW` is zero.** A missing BPF map entry reads back as zeroes, so an
  empty or cold map means "do nothing", never "deny everything".

## What is verified, and what is not

Being exact about this, because the gap matters.

**Verified — 78 tests, run on every change:**

- the event wire format: fixed size, round-trip, truncation, malformed input
- the decision table: lookup, per-kind scoping, expiry boundaries, sweep, export
- the advisor's validation: everything in the list above, plus network failure,
  timeout, and nonsense replies all yielding no advice at all
- the C/Python wire contract: struct sizes, packing, enum numbering, and that
  the C really does treat a missing entry as `ALLOW`

**Verified by hand, once, against a real model:** the full path — events →
summary → `rishi-qwen2.5-coder-3b` → validated advice → decision table →
kernel-readable verdicts. 1.4s for a 164-event batch.

**Not verified at all:** `bpf/setu.bpf.c` has never been compiled and never
been loaded. There is no clang on the build machine, and BPF loading needs
root, which is not available here (`unprivileged_bpf_disabled=2`). It is
committed because it is the other half of a wire contract the Python side
already implements — but treat it as a design document until someone compiles
it.

The tests hold the two halves together in the meantime: change a struct in the
C and `tests/test_wire_contract.py` fails.

## Layout

```
bpf/setu.bpf.c     sensing and enforcement. Uncompiled -- see above.
setu/events.py     the event, and the only definition of its wire format
setu/policy.py     the decision table the kernel reads
setu/advisor.py    asks Ollama; validates everything it says
tests/             78 tests
```

## Run the tests

```bash
pip install -e ".[dev]"
pytest
```

No kernel, no root, no model needed — the advisor tests use a stub.

## To go further

Needs a machine where you have root:

```bash
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)
```

Then compile `bpf/setu.bpf.c`, load it, and point the daemon at the pinned
map. Nothing in the Python has to change; the contract is already fixed.

## Status

Early. The thinking layer works and is tested. The kernel layer is written but
unproven. Do not run this anywhere that matters yet.
