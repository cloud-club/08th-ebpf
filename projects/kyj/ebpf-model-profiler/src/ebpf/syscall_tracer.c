// src/ebpf/syscall_tracer.c - Generic syscall tracing using eBPF
//
// This program traces system calls and measures their latency.
// It uses kprobe/kretprobe to hook into syscall entry and exit points.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include "common.h"

// Hash map to store start timestamps keyed by thread ID
BPF_HASH(start_times, u64, u64);

// Hash map to store PID filter (PIDs we want to trace)
BPF_HASH(pid_filter, u32, u8);

// Perf output buffer for sending events to user space
BPF_PERF_OUTPUT(events);

/**
 * should_trace - Check if we should trace this PID
 * @pid: Process ID to check
 *
 * Returns 1 if tracing is enabled for this PID, 0 otherwise
 */
static inline int should_trace(u32 pid) {
    u8 *val = pid_filter.lookup(&pid);
    // If filter is empty (val == NULL), trace everything
    // Otherwise, only trace if PID is in filter
    return (val == NULL) ? 0 : 1;
}

/**
 * trace_syscall_enter - Trace syscall entry point
 *
 * This is called when a traced syscall is entered.
 * Records the entry timestamp for latency calculation.
 */
int trace_syscall_enter(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    // Check if we should trace this PID
    if (!should_trace(pid)) {
        return 0;
    }

    // Record start time for this thread
    u64 ts = bpf_ktime_get_ns();
    start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_syscall_exit - Trace syscall exit point
 * @syscall_name: Name of the syscall (passed as parameter)
 *
 * This is called when a traced syscall exits.
 * Calculates duration and sends event to user space.
 */
int trace_syscall_exit(struct pt_regs *ctx, const char *syscall_name) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    // Check if we should trace this PID
    if (!should_trace(pid)) {
        return 0;
    }

    // Look up start time
    u64 *start_ts = start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0; // No entry event found
    }

    // Calculate duration
    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    // Prepare event structure
    struct syscall_event event = {};
    event.pid = pid;
    event.tid = tid;
    event.timestamp_ns = end_ts;
    event.duration_ns = duration;
    event.event_type = EVENT_TYPE_SYSCALL_EXIT;
    event.ret_val = PT_REGS_RC(ctx);

    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Copy syscall name (would be passed as parameter in real implementation)
    __builtin_memcpy(event.syscall_name, "generic", 8);

    // Send event to user space
    events.perf_submit(ctx, &event, sizeof(event));

    // Clean up
    start_times.delete(&pid_tgid);

    return 0;
}

/**
 * Specific syscall tracers
 * These attach to individual syscalls we're interested in
 */

// Trace openat syscall
int trace_openat_enter(struct pt_regs *ctx) {
    return trace_syscall_enter(ctx);
}

int trace_openat_exit(struct pt_regs *ctx) {
    return trace_syscall_exit(ctx, "openat");
}

// Trace read syscall
int trace_read_enter(struct pt_regs *ctx) {
    return trace_syscall_enter(ctx);
}

int trace_read_exit(struct pt_regs *ctx) {
    return trace_syscall_exit(ctx, "read");
}

// Trace write syscall
int trace_write_enter(struct pt_regs *ctx) {
    return trace_syscall_enter(ctx);
}

int trace_write_exit(struct pt_regs *ctx) {
    return trace_syscall_exit(ctx, "write");
}

// Trace nanosleep (for inference time simulation)
int trace_nanosleep_enter(struct pt_regs *ctx) {
    return trace_syscall_enter(ctx);
}

int trace_nanosleep_exit(struct pt_regs *ctx) {
    return trace_syscall_exit(ctx, "nanosleep");
}
