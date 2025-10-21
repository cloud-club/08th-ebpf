//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6

// TCP connection statistics per interface
struct tcp_stats {
    __u64 packets;
    __u64 bytes;
    __u64 syn_packets;
    __u64 syn_ack_packets;
    __u64 fin_packets;
    __u64 rst_packets;
};

// Key for the map (interface index)
struct stats_key {
    __u32 ifindex;
};

// Map to store TCP statistics per interface
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct stats_key);
    __type(value, struct tcp_stats);
} tcp_stats_map SEC(".maps");

// TC egress hook to track TCP packets on actual interface
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct stats_key key = {};
    struct tcp_stats *stats;
    struct tcp_stats new_stats = {};

    // Get interface index from skb
    key.ifindex = skb->ifindex;

    // Ensure we have enough data for ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    __u8 protocol = 0;
    void *tcp_hdr = NULL;

    // Parse IPv4
    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)iph + sizeof(struct iphdr) > data_end)
            return 0;

        // Check if IP header length is valid
        __u8 ihl = iph->ihl;
        if (ihl < 5)
            return 0;

        protocol = iph->protocol;
        tcp_hdr = (void *)iph + (ihl * 4);
    }
    // Parse IPv6
    else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)ip6h + sizeof(struct ipv6hdr) > data_end)
            return 0;

        protocol = ip6h->nexthdr;
        tcp_hdr = (void *)ip6h + sizeof(struct ipv6hdr);
    } else {
        return 0;
    }

    // Only process TCP packets
    if (protocol != IPPROTO_TCP)
        return 0;

    // Parse TCP header
    struct tcphdr *tcph = tcp_hdr;
    if ((void *)tcph + sizeof(struct tcphdr) > data_end)
        return 0;

    // Lookup or create stats entry
    stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&tcp_stats_map, &key, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&tcp_stats_map, &key);
        if (!stats)
            return 0;
    }

    // Update packet and byte counters
    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, skb->len);

    // Track TCP flags
    if (tcph->syn && !tcph->ack) {
        __sync_fetch_and_add(&stats->syn_packets, 1);
    }
    if (tcph->syn && tcph->ack) {
        __sync_fetch_and_add(&stats->syn_ack_packets, 1);
    }
    if (tcph->fin) {
        __sync_fetch_and_add(&stats->fin_packets, 1);
    }
    if (tcph->rst) {
        __sync_fetch_and_add(&stats->rst_packets, 1);
    }

    return 0; // Return 0 to allow packet to continue
}