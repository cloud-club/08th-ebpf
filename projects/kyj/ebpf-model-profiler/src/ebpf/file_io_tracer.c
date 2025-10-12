// src/ebpf/file_io_tracer.c - File I/O syscall tracing (read, write, openat)
//
// This program traces file I/O operations to measure disk latency
// in model serving applications (e.g., loading model weights).

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "common.h"

// Hash map to store start timestamps for file I/O calls
BPF_HASH(io_start_times, u64, u64);

// Hash map for storing file descriptor info
BPF_HASH(fd_info, u32, u32);

// Hash map for PID filtering
BPF_HASH(io_pid_filter, u32, u8);

// Perf output for file I/O events
BPF_PERF_OUTPUT(io_events);

/**
 * should_trace_io - Check if we should trace this PID for I/O events
 */
static inline int should_trace_io(u32 pid) {
    u8 *val = io_pid_filter.lookup(&pid);
    return (val == NULL) ? 0 : 1;
}

/**
 * trace_openat_enter - Trace openat syscall entry
 *
 * openat is used to open files, critical for loading model weights
 */
int trace_io_openat_enter(struct pt_regs *ctx, int dirfd, const char *pathname) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    io_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_openat_exit - Trace openat syscall exit
 */
int trace_io_openat_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 *start_ts = io_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    struct file_io_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_FILE_IO;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "openat", 7);

    // Get file descriptor from return value
    s64 fd = PT_REGS_RC(ctx);
    if (fd >= 0) {
        event.fd = fd;
    }

    io_events.perf_submit(ctx, &event, sizeof(event));
    io_start_times.delete(&pid_tgid);

    return 0;
}

/**
 * trace_read_enter - Trace read syscall entry
 *
 * read is used to read data from files (e.g., model weights)
 */
int trace_io_read_enter(struct pt_regs *ctx, int fd, void *buf, size_t count) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    io_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_read_exit - Trace read syscall exit
 */
int trace_io_read_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 *start_ts = io_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    struct file_io_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_FILE_IO;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "read", 5);

    // Get bytes read from return value
    s64 ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        event.bytes = ret;
    }

    io_events.perf_submit(ctx, &event, sizeof(event));
    io_start_times.delete(&pid_tgid);

    return 0;
}

/**
 * trace_write_enter - Trace write syscall entry
 */
int trace_io_write_enter(struct pt_regs *ctx, int fd, const void *buf, size_t count) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    io_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_write_exit - Trace write syscall exit
 */
int trace_io_write_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 *start_ts = io_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    struct file_io_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_FILE_IO;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "write", 6);

    s64 ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        event.bytes = ret;
    }

    io_events.perf_submit(ctx, &event, sizeof(event));
    io_start_times.delete(&pid_tgid);

    return 0;
}

/**
 * trace_fsync_enter - Trace fsync syscall entry
 *
 * fsync is used to flush file data to disk
 */
int trace_io_fsync_enter(struct pt_regs *ctx, int fd) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    io_start_times.update(&pid_tgid, &ts);

    return 0;
}

/**
 * trace_fsync_exit - Trace fsync syscall exit
 */
int trace_io_fsync_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    if (!should_trace_io(pid)) {
        return 0;
    }

    u64 *start_ts = io_start_times.lookup(&pid_tgid);
    if (start_ts == 0) {
        return 0;
    }

    u64 end_ts = bpf_ktime_get_ns();
    u64 duration = end_ts - *start_ts;

    struct file_io_event event = {};
    event.base.pid = pid;
    event.base.tid = tid;
    event.base.timestamp_ns = end_ts;
    event.base.duration_ns = duration;
    event.base.event_type = EVENT_TYPE_FILE_IO;
    event.base.ret_val = PT_REGS_RC(ctx);

    bpf_get_current_comm(&event.base.comm, sizeof(event.base.comm));
    __builtin_memcpy(event.base.syscall_name, "fsync", 6);

    io_events.perf_submit(ctx, &event, sizeof(event));
    io_start_times.delete(&pid_tgid);

    return 0;
}
