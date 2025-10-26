//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// TC 액션 상수 정의 (linux/pkt_cls.h 대신)
#define TC_ACT_OK 0     // 패킷 정상 처리 완료 
#define TC_ACT_SHOT 2   // 패킷 처리 실패

// Ethernet 프로토콜 상수 (linux/if_ether.h 대신)
#define ETH_P_IP 0x0800 // IPv4 (네트워크 바이트 오더)

struct packet_event {
    __u64 ts_ns;   // 타임스탬프 (ns)
    __u8 protocol; // L4 프로토콜 (TCP=6, UDP=17)
    __u8 direction;  // 0: egress, 1: ingress
    __u16 sport;   // 소스 포트
    __u16 dport;   // 목적지 포트
    __u32 saddr;   // 소스 IPv4 주소
    __u32 daddr;   // 목적지 IPv4 주소
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tc")
int handle_packet(struct __sk_buff *skb) {
    struct packet_event *event;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    // L2 헤더 검사
    if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;
    
    // IPv4만 처리 (h_proto는 네트워크 바이트 오더)
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // L4 프로토콜 검사 (TCP/UDP만)
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // 포트 정보 추출
    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    // ringbuf에 이벤트 push
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;

    event->ts_ns = bpf_ktime_get_ns();
    event->protocol = ip->protocol;
    event->direction = (skb->ingress_ifindex != 0) ? 1 : 0;
    event->sport = sport;
    event->dport = dport;
    event->saddr = ip->saddr;
    event->daddr = ip->daddr;

    bpf_ringbuf_submit(event, 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
