// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_RUNNING        0
#define TASK_INTERRUPTIBLE  1
#define TASK_UNINTERRUPTIBLE 2

char LICENSE[] SEC("license") = "GPL";

struct cpu_event {
    u64 last_timestamp;
    u64 total_time_ns;
    u64 switch_count;
    u32 cpu_burst;
    u32 io_burst;
};

struct fault_event {
    u64 user_faults;
    u64 kernel_faults;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // PID
    __type(value, struct cpu_event);
    __uint(max_entries, 10240);
} cpu_usage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // PID
    __type(value, struct fault_event);
    __uint(max_entries, 10240);
} page_faults SEC(".maps");

// === CPU TIME ===
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u32 prev_pid = ctx->prev_pid;
    u32 next_pid = ctx->next_pid;
    u64 ts = bpf_ktime_get_ns();

    if (prev_pid > 0) {
        struct cpu_event *evt = bpf_map_lookup_elem(&cpu_usage, &prev_pid);
        if (evt) {
		u64 delta = ts - evt->last_timestamp;
		evt->total_time_ns += delta;
		__sync_fetch_and_add(&evt->switch_count, 1);
	}
    }

    if (next_pid > 0) {
	struct cpu_event *evt = bpf_map_lookup_elem(&cpu_usage, &next_pid);
	if (evt) {
        	// 이미 있으면, switch_count 증가 + last_timestamp 갱신
        	evt->last_timestamp = ts;
		__sync_fetch_and_add(&evt->switch_count, 1);
		// prev_state 기반으로 I/O burst 카운트
                if (ctx->prev_state & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)) {
                        __sync_fetch_and_add(&evt->io_burst, 1);
                }
    	} else {
        // 처음 들어오는 PID라면 새로 추가
        struct cpu_event new_evt = {};
        new_evt.last_timestamp = ts;
        new_evt.switch_count = 0;
	new_evt.total_time_ns = 0;
	new_evt.cpu_burst = 0;
	new_evt.io_burst = 0;
        bpf_map_update_elem(&cpu_usage, &next_pid, &new_evt, BPF_ANY);
    	}
    }

    return 0;
}

// === PAGE FAULT (USER) ===
SEC("tracepoint/exceptions/page_fault_user")
int handle_page_fault_user(struct trace_event_raw_page_fault *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fault_event *evt = bpf_map_lookup_elem(&page_faults, &pid);

    if (!evt) {
        struct fault_event new_evt = {};
        new_evt.user_faults = 1;
        bpf_map_update_elem(&page_faults, &pid, &new_evt, BPF_ANY);
    } else {
        evt->user_faults += 1;
    }

    return 0;
}

// === PAGE FAULT (KERNEL) ===
SEC("tracepoint/exceptions/page_fault_kernel")
int handle_page_fault_kernel(struct trace_event_raw_page_fault *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fault_event *evt = bpf_map_lookup_elem(&page_faults, &pid);

    if (!evt) {
        struct fault_event new_evt = {};
        new_evt.kernel_faults = 1;
        bpf_map_update_elem(&page_faults, &pid, &new_evt, BPF_ANY);
    } else {
        evt->kernel_faults += 1;
    }

    return 0;
}
