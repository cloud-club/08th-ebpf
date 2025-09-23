//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10
#define TCP_LISTEN 10
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7
#define TCP_TIME_WAIT 6
#define TCP_FIN_WAIT1 4
#define TCP_FIN_WAIT2 5
#define TCP_CLOSING 11
#define TCP_LAST_ACK 9
#define TCP_CLOSE_WAIT 8

struct tcp_event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  state;
    __u8  family;
    __u64 timestamp;
};

struct tcp_port_stats {
    __u64 active_connections;
    __u64 total_connections;
    __u64 last_updated;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // port number
    __type(value, struct tcp_port_stats);
} port_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  // socket pointer
    __type(value, __u16); // port number
} socket_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline bool is_listening_port(struct sock *sk, __u16 port) {
    // Check if this is a server socket (listening or has been accepting connections)
    __u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);

    // For established connections, check if local port indicates server
    // Typically server ports are < 32768 or well-known ports
    if (state == TCP_ESTABLISHED) {
        // Check if the socket is bound to INADDR_ANY (0.0.0.0) or specific IP
        __u32 rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        // If bound address is set, it's likely a server socket
        return port < 32768 || rcv_saddr != 0;
    }

    return state == TCP_LISTEN;
}

SEC("kprobe/tcp_set_state")
int trace_tcp_set_state(void *ctx) {
    // For kprobes, we need to read the arguments differently
    // On both x86_64 and arm64, first arg is typically at offset 0 from ctx
    struct sock *sk = NULL;
    int new_state = 0;

    // Read the socket pointer - first argument
    bpf_probe_read(&sk, sizeof(sk), ctx);
    if (!sk)
        return 0;

    // Read new_state - second argument (offset depends on architecture)
    // For simplicity, we'll read it from the socket state after transition
    // since we can't reliably get the second parameter across architectures

    __u8 old_state = BPF_CORE_READ(sk, __sk_common.skc_state);
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family != AF_INET && family != AF_INET6)
        return 0;

    __u16 sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // Only track server-side connections (where we're listening on sport)
    if (sport == 0 || dport == 0)
        return 0;

    // Skip client connections (high ephemeral ports connecting out)
    if (sport >= 32768 && old_state != TCP_LISTEN)
        return 0;

    __u64 sk_ptr = (__u64)sk;
    struct tcp_port_stats *stats, zero_stats = {};

    // Handle new connection establishment
    if (new_state == TCP_ESTABLISHED && old_state != TCP_ESTABLISHED) {
        stats = bpf_map_lookup_elem(&port_metrics, &sport);
        if (!stats) {
            bpf_map_update_elem(&port_metrics, &sport, &zero_stats, BPF_ANY);
            stats = bpf_map_lookup_elem(&port_metrics, &sport);
            if (!stats)
                return 0;
        }

        __sync_fetch_and_add(&stats->active_connections, 1);
        __sync_fetch_and_add(&stats->total_connections, 1);
        stats->last_updated = bpf_ktime_get_ns();

        // Track this socket
        bpf_map_update_elem(&socket_ports, &sk_ptr, &sport, BPF_ANY);

        // Send event
        struct tcp_event event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.sport = sport;
        event.dport = dport;
        event.state = new_state;
        event.family = family;
        event.timestamp = bpf_ktime_get_ns();

        if (family == AF_INET) {
            event.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            event.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        }

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    // Handle connection closing
    else if ((new_state == TCP_CLOSE || new_state == TCP_TIME_WAIT) &&
             old_state == TCP_ESTABLISHED) {
        __u16 *tracked_port = bpf_map_lookup_elem(&socket_ports, &sk_ptr);
        if (tracked_port) {
            stats = bpf_map_lookup_elem(&port_metrics, tracked_port);
            if (stats && stats->active_connections > 0) {
                __sync_fetch_and_sub(&stats->active_connections, 1);
                stats->last_updated = bpf_ktime_get_ns();
            }
            bpf_map_delete_elem(&socket_ports, &sk_ptr);
        }
    }

    return 0;
}

struct trace_accept_ctx {
    __u64 __pad[16];  // Padding to handle different architectures
    void *sk;
};

SEC("kprobe/inet_csk_accept")
int trace_accept(struct trace_accept_ctx *ctx) {
    struct sock *sk;

    // Read parameter using CO-RE
    bpf_core_read(&sk, sizeof(sk), &ctx->sk);

    if (!sk)
        return 0;

    __u16 sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    if (sport == 0)
        return 0;

    // Track that this port is accepting connections
    struct tcp_port_stats *stats, zero_stats = {};
    stats = bpf_map_lookup_elem(&port_metrics, &sport);
    if (!stats) {
        bpf_map_update_elem(&port_metrics, &sport, &zero_stats, BPF_ANY);
    }

    return 0;
}