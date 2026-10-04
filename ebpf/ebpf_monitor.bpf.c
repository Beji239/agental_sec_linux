// SPDX-License-Identifier: GPL-2.0
// ebpf/ebpf_monitor.bpf.c
//
// AgentalSec's kernel camera.
//
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
// WHY THIS FILE EXISTS
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//
// The owner's words, and they are the specification: "Today a program that
// lives five seconds inside a sixty-second poll gap is invisible."
//
// Every sensor in this application learns what is happening by ASKING. The
// process monitor walks /proc once a poll; the event monitor reads journald in
// batches; the local integrity sensor stats files. Between two asks, nothing is
// observed at all. A process that starts, does something, and exits inside that
// gap is not merely missed -- it leaves no row anywhere, so the app cannot even
// report that it might have missed it. The gap is invisible from the inside.
//
// This program closes that gap for the two events that matter most, by making
// the KERNEL report them instead of asking it what it remembers:
//
//   sched_process_exec   every successful execve: what ran, under which pid,
//                        with its parent's identity. This is the one that sees
//                        the five-second process.
//
//   sys_enter_connect    every connect(2) call: which pid opened a connection
//                        to which address and port. This is what puts a NAME
//                        on traffic, which the packet capture cannot do on its
//                        own because it only sees frames.
//
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
// WHAT THIS DELIBERATELY DOES NOT DO
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//
// No file-write tracing, no DNS parsing, no packet payloads. Not because they
// are hard but because they are the tiers that come after these two are proven
// on a real host, and a program that traces everything is one whose output
// nobody reads. The next tiers are named in the module's own coverage block so
// their absence is a stated limit rather than a silent one.
//
// IT DOES NOT DECIDE ANYTHING. Every event is a FACT: this pid, this name, this
// moment. The judgement lives in the app, in Python, where it can be tested and
// where a rule can be read by a person. A BPF program that classified would be
// a detector nobody can review and nobody can turn off.
//
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
// WHAT IT COSTS
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//
// Both programs are attached to tracepoints and do one ringbuf reserve + one
// memcpy each. There is NO per-event syscall and no per-event allocation: the
// ring buffer is mapped once and the kernel writes into it. The measured cost
// on this host is in the module header; the honest summary is that it is
// cheaper than the 60-second /proc walk it exists to complement, and it is
// bounded by construction (see the drop counter below).
//
// A FULL RING BUFFER DROPS EVENTS, AND THAT IS COUNTED. `dropped` is a
// per-cpu counter incremented when the reserve fails. It is read out and
// reported by the userspace side, so "the camera was overwhelmed" is a number
// the app can show rather than a silent hole -- which is the whole honesty
// discipline of this project applied to the one component that can lose data
// faster than any other.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define PATH_LEN      256
#define ARG_LEN       128

#define EVENT_EXEC    1
#define EVENT_CONNECT 2

// One event. Sized to stay inside a single ringbuf record with room to spare;
// a record larger than the ring is never deliverable, so the buffer sizes here
// are a correctness constraint and not a style choice.
//
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
// `reserved` IS NOT PADDING AND IT MUST NOT BE REMOVED.
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//
// It occupies the four bytes the compiler inserts by alignment between `ppid`
// and `ts_ns`, and it is declared here so that BOTH halves of this ABI name
// the same 344 bytes. MEASURED, in the 2026-09-23 audit round:
//
//     bpftool btf dump file ebpf_monitor.bpf.o  ->  event_t size_bytes = 344
//     struct.calcsize(EVENT_FMT) in the loader   ->  344
//
// A future field goes IN THIS SLOT rather than at the end of the struct. The
// alternative -- appending -- changes sizeof(event_t), and a loader built
// against the old size reads the new records four bytes short, which this
// project has already paid for once: struct.unpack does not fail on a short
// format, it returns plausible garbage.
struct event_t {
    __u32 kind;
    __u32 pid;         // thread id that acted
    __u32 tgid;        // process id
    __u32 ppid;
    __u64 ts_ns;
    __u32 uid;
    __u32 reserved;    // the compiler's own alignment slot; a spare u32 for a
                       // future field, deliberately NOT a named member
    char  comm[TASK_COMM_LEN];         // what acted
    char  parent_comm[TASK_COMM_LEN];  // who started it
    // kind == EVENT_EXEC
    char  filename[PATH_LEN];
    // kind == EVENT_CONNECT
    __u32 daddr;       // IPv4, network byte order as stored
    __u16 dport;       // host byte order
    __u16 family;      // AF_INET / AF_INET6
    __u8  addr6[16];   // for AF_INET6
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);        // 16 MB
} events SEC(".maps");

// Per-cpu drop counters. Index 0 = exec, 1 = connect. Read by userspace and
// reported; a camera that cannot keep up has to say so.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

static __always_inline void note_drop(__u32 key)
{
    __u64 *counter = bpf_map_lookup_elem(&dropped, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline void fill_identity(struct event_t *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task)
        return;
    // THE PARENT CHAIN, one level. Read through CO-RE with BPF_CORE_READ so
    // this keeps working across kernels whose task_struct layout differs; a
    // hardcoded offset would be correct on exactly one kernel and silently
    // wrong on the next.
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        e->ppid = BPF_CORE_READ(parent, tgid);
        BPF_CORE_READ_STR_INTO(&e->parent_comm, parent, comm);
    }
}

// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
// EXEC -- the headline. A program that lives and dies between two polls.
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//
// The tracepoint's own format, declared here rather than included, because the
// tracepoint structs are not in vmlinux.h: they belong to the tracefs ABI and
// are stable, unlike the internal structs vmlinux.h carries.
struct trace_event_raw_sched_process_exec_local {
    struct trace_entry ent;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
    char __data[0];
};

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec_local *ctx)
{
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_drop(0);
        return 0;
    }

    e->kind = EVENT_EXEC;
    fill_identity(e);

    // __data_loc encodes an offset in its low 16 bits and a length above.
    // Reading it with the mask is the documented way; using the field directly
    // would read an offset as a pointer.
    __u32 loc = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)ctx + loc);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
// CONNECT -- which pid opened a connection to where.
// ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
//
// The syscall tracepoint rather than a kprobe on tcp_connect, deliberately: it
// fires for UDP as well, so a DNS lookup that uses connect() is seen, and it
// carries the userspace sockaddr which is what the process actually asked for.
struct trace_event_raw_sys_enter_local {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
    char __data[0];
};

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter_local *ctx)
{
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        note_drop(1);
        return 0;
    }

    e->kind = EVENT_CONNECT;
    fill_identity(e);

    // args[1] is the sockaddr the process handed to the kernel. It lives in
    // USER memory, so bpf_probe_read_user, and the family decides how much of
    // it to believe.
    void *uaddr = (void *)ctx->args[1];
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) == 0) {
        e->family = family;
        if (family == 2 /* AF_INET */) {
            // struct sockaddr_in: family(2) port(2) addr(4)
            __u16 port = 0;
            __u32 addr = 0;
            bpf_probe_read_user(&port, sizeof(port), uaddr + 2);
            bpf_probe_read_user(&addr, sizeof(addr), uaddr + 4);
            e->dport = __builtin_bswap16(port);   // network -> host
            e->daddr = addr;
        } else if (family == 10 /* AF_INET6 */) {
            __u16 port = 0;
            bpf_probe_read_user(&port, sizeof(port), uaddr + 2);
            e->dport = __builtin_bswap16(port);
            bpf_probe_read_user(&e->addr6, sizeof(e->addr6), uaddr + 8);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
