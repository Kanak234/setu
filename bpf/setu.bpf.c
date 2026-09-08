// SPDX-License-Identifier: GPL-2.0
//
// SETU sensing layer.
//
// NOT YET COMPILED OR LOADED. This file has never been through clang and has
// never been attached to a running kernel -- see README, "What is verified".
// It is committed because it is the other half of the wire contract that
// setu/events.py and setu/policy.py already implement and test: if the two
// ever disagree about a struct layout, every decoded event is silently wrong.
//
// The design rule this file exists to honour: nothing here calls a model,
// waits on userspace, or allocates. It emits an event and reads a verdict
// that was written earlier. Both are O(1).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SETU_COMM_LEN 16

enum setu_kind {
    SETU_SCHED_SWITCH = 1,
    SETU_SCHED_WAKEUP = 2,
    SETU_EXEC         = 3,
    SETU_FILE_OPEN    = 4,
    SETU_CONNECT      = 5,
};

// Mirrors WIRE in setu/events.py: "<QIIHHQQ16s", 52 bytes.
struct setu_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u16 kind;
    __u16 _pad;
    __u64 a;
    __u64 b;
    char  comm[SETU_COMM_LEN];
} __attribute__((packed));

// Mirrors KEY_WIRE "<HHI" and VERDICT_WIRE "<BBHI" in setu/policy.py.
struct setu_key {
    __u16 kind;
    __u16 _pad;
    __u32 comm_hash;
} __attribute__((packed));

struct setu_verdict {
    __u8  action;      // 0 ALLOW, 1 FLAG, 2 THROTTLE, 3 DENY
    __u8  confidence;
    __u16 _pad;
    __u32 expires_s;
} __attribute__((packed));

// Events out to the daemon. Lossy on purpose: if the daemon cannot keep up,
// events are dropped rather than back-pressuring the kernel.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Decisions in from the daemon. Pinned, so the daemon can update it without
// this program being reloaded.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct setu_key);
    __type(value, struct setu_verdict);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} verdicts SEC(".maps");

// crc32, bounded to SETU_COMM_LEN so the verifier can prove termination.
// Must produce the same value as zlib.crc32 in setu/policy.py -- a mismatch
// means every lookup misses and the table silently does nothing.
static __always_inline __u32 setu_comm_hash(const char *comm)
{
    __u32 crc = 0xFFFFFFFF;

    for (int i = 0; i < SETU_COMM_LEN - 1; i++) {
        char c = comm[i];
        if (c == '\0')
            break;
        crc ^= (__u8)c;
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(__s32)(crc & 1)));
    }
    return ~crc;
}

static __always_inline __u8 setu_lookup(__u16 kind, const char *comm, __u64 now_s)
{
    struct setu_key key = {};
    struct setu_verdict *v;

    key.kind = kind;
    key.comm_hash = setu_comm_hash(comm);

    v = bpf_map_lookup_elem(&verdicts, &key);
    if (!v)
        return 0;                       // unknown -> ALLOW
    if (v->expires_s && (__u64)v->expires_s <= now_s)
        return 0;                       // stale -> ALLOW
    return v->action;
}

static __always_inline void setu_emit(__u16 kind, __u64 a, __u64 b)
{
    struct setu_event *e;
    __u64 id = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;                         // full: drop, never block

    e->ts_ns = bpf_ktime_get_ns();
    e->pid   = (__u32)id;
    e->tgid  = (__u32)(id >> 32);
    e->kind  = kind;
    e->_pad  = 0;
    e->a     = a;
    e->b     = b;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int setu_on_exec(void *ctx)
{
    char comm[SETU_COMM_LEN];
    __u64 now_s = bpf_ktime_get_ns() / 1000000000ULL;

    bpf_get_current_comm(&comm, sizeof(comm));
    setu_emit(SETU_EXEC, setu_lookup(SETU_EXEC, comm, now_s), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int setu_on_connect(void *ctx)
{
    char comm[SETU_COMM_LEN];
    __u64 now_s = bpf_ktime_get_ns() / 1000000000ULL;

    bpf_get_current_comm(&comm, sizeof(comm));
    setu_emit(SETU_CONNECT, setu_lookup(SETU_CONNECT, comm, now_s), 0);
    return 0;
}
