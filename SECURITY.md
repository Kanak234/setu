# Security Policy & Architecture Threat Model

## 1. Scope & Core Architectural Guarantees

**SETU** is an asynchronous bridge between the Linux kernel (via eBPF probes) and userspace local language models (Ollama). Because it operates at the kernel-userspace boundary, security and fault isolation are architectural foundations, not afterthoughts.

### Architectural Invariants:
1. **The Kernel Never Calls the Model:**
   - The kernel reads a pre-computed verdict from a pinned eBPF hash map.
   - All map lookups are $O(1)$ and non-blocking with bounded CRC32 hashing.
   - Kernel tracepoints execute in microseconds and never yield or wait on userspace.

2. **Model Replies are Strictly Untrusted Input:**
   - Output from the local LLM is subjected to schema validation, boundary checking, and strict policy ceilings.
   - The model is bounded to a maximum action of `FLAG` (`MAX_MODEL_ACTION`). The model is never permitted to emit `DENY` or `THROTTLE` decisions.
   - Confidence integers are strictly bounded to `[0, 100]` (excluding boolean types).
   - Comm strings are strictly bounded to 15 characters plus null terminator.

3. **Fail-Safe Defaults (Cold Map & Expiry Decays to ALLOW):**
   - In eBPF, a missing map entry returns NULL / zeroes. `Action.ALLOW` is explicitly mapped to `0`. A cold, empty, or uninitialized map always evaluates to `ALLOW`, preventing denial-of-service against the host machine.
   - Every verdict carries an explicit Unix timestamp expiration (`expires_s`). If the userspace daemon stalls or terminates, verdicts decay back to `ALLOW` upon expiry.

4. **Ringbuffer Lossy Backpressure:**
   - Kernel ringbuffer emission reserves space with `bpf_ringbuf_reserve`. If userspace cannot keep up with high event volumes, events are safely dropped without degrading kernel throughput.

---

## 2. Reporting Security Issues

If you discover a vulnerability or flaw in SETU (including BPF verifier bypasses, wire serialization flaws, or policy bypasses):

1. **Do not disclose publicly** via GitHub Issues or discussions.
2. **Email Security Report:** Send details to `kanakprabhakar72@gmail.com`.
3. **Include:**
   - Description of the vulnerability and attack vector.
   - Proof of concept or reproduction script.
   - Potential impact on host kernel stability or security policy.

---

## 3. Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
