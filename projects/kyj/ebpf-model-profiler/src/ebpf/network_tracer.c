// src/ebpf/network_tracer.c - Network syscall tracing (sendto, recvfrom)
//
// This program specifically traces network-related system calls to measure
// network I/O latency in model serving applications.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include "common.h"

// Hash map to store start timestamps for network calls
BPF_HASH(net_start_times, u64, u64);

// Hash map for PID filtering
BPF_HASH(net_pid_filter, u32, u8);

// Perf output for network events
BPF_PERF_OUTPUT(net_events);

/**
 * should_trace_net - Check if we should trace this PID for network events
 */
static inline int should_trace_net(u32 pid) {
    u8 *val = net_pid_filter.lookup(&pid);
    return (val == NULL) ? 0 : 1;
}

/**
 * trace_sendto_enter - Trace sendto syscall entry
 *
 * sendto is used to send data on a socket, commonly used in HTTP responses
 */
int trace_sendto_enter(struct pt_regs *ctx, int sockfd, void *buf, size_t len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_net(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    net_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_sendto_exit - Trace sendto syscall exit
 */
int trace_sendto_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_net(pid)) {
        return 0;
    }

    u64 *start_ts = net_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    // Prepare network event
    struct network_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_NETWORK;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "sendto", 7);

    // Get bytes sent (return value of sendto)
    s64 ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        event.bytes = ret;
    }

    net_events.perf_submit(ctx, &event, sizeof(event));
    net_start_times.delete(&pid_tgid);

    return 0;
}

/**
 * trace_recvfrom_enter - Trace recvfrom syscall entry
 *
 * recvfrom is used to receive data on a socket, commonly used for HTTP requests
 */
int trace_recvfrom_enter(struct pt_regs *ctx, int sockfd, void *buf, size_t len) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_net(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    net_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_recvfrom_exit - Trace recvfrom syscall exit
 */
int trace_recvfrom_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_net(pid)) {
        return 0;
    }

    u64 *start_ts = net_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    struct network_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_NETWORK;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "recvfrom", 9);

    s64 ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        event.bytes = ret;
    }

    net_events.perf_submit(ctx, &event, sizeof(event));
    net_start_times.delete(&pid_tgid);

    return 0;
}

/**
 * trace_sendmsg_enter - Trace sendmsg syscall entry
 */
int trace_sendmsg_enter(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_net(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    net_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_sendmsg_exit - Trace sendmsg syscall exit
 */
int trace_sendmsg_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_net(pid)) {
        return 0;
    }

    u64 *start_ts = net_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    struct network_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_NETWORK;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "sendmsg", 8);

    s64 ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        event.bytes = ret;
    }

    net_events.perf_submit(ctx, &event, sizeof(event));
    net_start_times.delete(&pid_tgid);

    return 0;
}
