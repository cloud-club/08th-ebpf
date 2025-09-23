//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

struct tcp_connection {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct port_metrics {
    __u64 syn_received;      // SYN packets received (new connection attempts)
    __u64 syn_ack_sent;      // SYN-ACK packets sent (accepted connections)
    __u64 established;       // Established connections (ACK after SYN-ACK)
    __u64 fin_received;      // FIN packets received
    __u64 rst_received;      // RST packets received
    __u64 bytes_received;    // Total bytes received
    __u64 bytes_sent;        // Total bytes sent
    __u64 packets_received;  // Total packets received
    __u64 packets_sent;      // Total packets sent
    __u64 last_updated;      // Last update timestamp
};

// Map to track metrics per port
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // port number
    __type(value, struct port_metrics);
} port_stats SEC(".maps");

// Map to track active connections
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct tcp_connection);
    __type(value, __u64);  // timestamp
} active_connections SEC(".maps");

// Parse TCP packet and update metrics
static __always_inline int process_tcp_packet(struct __sk_buff *skb, bool is_ingress) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->protocol != IPPROTO_TCP)
        return 0;

    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return 0;

    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 flags = tcp->syn << 1 | tcp->fin | tcp->rst << 2 | tcp->ack << 4;

    // Determine which port to track (local port for server connections)
    __u16 tracked_port;
    struct tcp_connection conn = {};

    if (is_ingress) {
        // Incoming packet - track destination port if it's a server port
        tracked_port = dport;
        conn.saddr = bpf_ntohl(ip->saddr);
        conn.daddr = bpf_ntohl(ip->daddr);
        conn.sport = sport;
        conn.dport = dport;
    } else {
        // Outgoing packet - track source port if it's a server port
        tracked_port = sport;
        conn.saddr = bpf_ntohl(ip->daddr);  // Reverse for connection key
        conn.daddr = bpf_ntohl(ip->saddr);
        conn.sport = dport;
        conn.dport = sport;
    }

    // Skip high ephemeral ports (likely client ports)
    if (tracked_port >= 32768)
        return 0;

    // Get or create port metrics
    struct port_metrics *metrics = bpf_map_lookup_elem(&port_stats, &tracked_port);
    struct port_metrics new_metrics = {};
    if (!metrics) {
        metrics = &new_metrics;
        bpf_map_update_elem(&port_stats, &tracked_port, metrics, BPF_ANY);
        metrics = bpf_map_lookup_elem(&port_stats, &tracked_port);
        if (!metrics)
            return 0;
    }

    __u64 timestamp = bpf_ktime_get_ns();
    __u32 packet_len = bpf_ntohs(ip->tot_len);

    // Update metrics based on packet direction and flags
    if (is_ingress) {
        __sync_fetch_and_add(&metrics->packets_received, 1);
        __sync_fetch_and_add(&metrics->bytes_received, packet_len);

        if (flags & TCP_SYN && !(flags & TCP_ACK)) {
            // New connection attempt (SYN)
            __sync_fetch_and_add(&metrics->syn_received, 1);

            // Track new connection
            bpf_map_update_elem(&active_connections, &conn, &timestamp, BPF_ANY);
        } else if (flags & TCP_FIN) {
            // Connection closing
            __sync_fetch_and_add(&metrics->fin_received, 1);
            bpf_map_delete_elem(&active_connections, &conn);
        } else if (flags & TCP_RST) {
            // Connection reset
            __sync_fetch_and_add(&metrics->rst_received, 1);
            bpf_map_delete_elem(&active_connections, &conn);
        } else if (flags & TCP_ACK && !(flags & TCP_SYN)) {
            // Check if this completes a handshake
            __u64 *conn_time = bpf_map_lookup_elem(&active_connections, &conn);
            if (conn_time && (timestamp - *conn_time) < 1000000000) { // Within 1 second
                __sync_fetch_and_add(&metrics->established, 1);
            }
        }
    } else {
        __sync_fetch_and_add(&metrics->packets_sent, 1);
        __sync_fetch_and_add(&metrics->bytes_sent, packet_len);

        if (flags & TCP_SYN && flags & TCP_ACK) {
            // SYN-ACK response (server accepting connection)
            __sync_fetch_and_add(&metrics->syn_ack_sent, 1);
        }
    }

    metrics->last_updated = timestamp;

    return 0;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return process_tcp_packet(skb, true);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return process_tcp_packet(skb, false);
}