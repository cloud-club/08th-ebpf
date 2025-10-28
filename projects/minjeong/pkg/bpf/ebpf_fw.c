//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// TC 액션
#define TC_ACT_OK 0      // 패킷 통과
#define TC_ACT_SHOT 2    // 패킷 차단

// Ethernet 프로토콜
#define ETH_P_IP 0x0800

// 방향
#define DIR_INBOUND  0
#define DIR_OUTBOUND 1

// 액션
#define ACTION_DENY  0
#define ACTION_ALLOW 1

// 프로토콜
#define PROTO_ANY 0
#define PROTO_TCP 6
#define PROTO_UDP 17

#define MAX_RULES 30

// 방화벽 규칙 구조체
struct firewall_rule {
    __u32 src_ip;        // 출발지 IP (0 = ANY)
    __u32 dst_ip;        // 목적지 IP (0 = ANY)
    __u16 port;          // 포트 (0 = ANY)
    __u8  protocol;      // 프로토콜 (0 = ANY, 6 = TCP, 17 = UDP)
    __u8  direction;     // 방향 (0 = IN, 1 = OUT)
    __u8  action;        // 액션 (0 = DENY, 1 = ALLOW)
    __u8  valid;         // 활성화 여부 (0 = 비활성, 1 = 활성)
};

// 기본 정책 구조체
struct default_policy {
    __u8 inbound;        // 기본 inbound 정책
    __u8 outbound;       // 기본 outbound 정책
};

// 규칙 배열 Map (순서 보장)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);   // 인덱스
    __type(value, struct firewall_rule);
} rules_array SEC(".maps");

// 기본 정책 Map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);  // 0: inbound, 1: outbound
    __type(key, __u32);
    __type(value, __u8);     // action
} default_policy SEC(".maps");

// 규칙 매칭 함수
static __always_inline int match_rule(struct firewall_rule *rule,
                                       __u32 src_ip, __u32 dst_ip,
                                       __u16 port, __u8 protocol,
                                       __u8 direction) {
    if (!rule)
        return 0;
    
    // 방향 검사
    if (rule->direction != direction)
        return 0;
    
    // 프로토콜 검사
    if (rule->protocol != PROTO_ANY && rule->protocol != protocol)
        return 0;
    
    // 포트 검사
    if (rule->port != 0 && rule->port != port)
        return 0;
    
    // Inbound: src_ip 검사, Outbound: dst_ip 검사
    if (direction == DIR_INBOUND) {
        if (rule->src_ip != 0 && rule->src_ip != src_ip)
            return 0;
    } else {
        if (rule->dst_ip != 0 && rule->dst_ip != dst_ip)
            return 0;
    }
    
    return 1;  // 매칭 성공
}

SEC("tc")
int firewall_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    
    // L2 헤더 검사
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // IPv4만 처리
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // L3 헤더 검사
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // TCP/UDP만 처리
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    // 포트 추출
    __u16 sport = 0;
    __u16 dport = 0;

    __u8 ihl = ip->ihl;
    __u32 ip_hdr_len = ihl * 4;
    void *l4_hdr = (void *)ip + ip_hdr_len;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }
    
    // 패킷 방향 결정
    __u8 direction = (skb->ingress_ifindex != 0) ? DIR_INBOUND : DIR_OUTBOUND;
    __u16 check_port = dport;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    // 규칙 순회 (First-Match)
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < MAX_RULES; i++) {
        __u32 idx = i;
        struct firewall_rule *rule = bpf_map_lookup_elem(&rules_array, &idx);
        
        if (!rule || rule->valid == 0)
            continue;
        
        // 규칙 매칭 시도
        if (match_rule(rule, ip->saddr, ip->daddr, check_port, 
                       ip->protocol, direction)) {
            // 매칭된 규칙의 액션 적용
            if (rule->action == ACTION_ALLOW)
                return TC_ACT_OK;     // 허용
            else
                return TC_ACT_SHOT;   // 차단
        }
    }
    
    // 어떤 규칙도 매칭되지 않으면 기본 정책 적용
    __u32 policy_key = direction;
    __u8 *default_action = bpf_map_lookup_elem(&default_policy, &policy_key);

    if (!default_action)
        return TC_ACT_SHOT;
    
    if (*default_action == ACTION_ALLOW)
        return TC_ACT_OK;
    
    return TC_ACT_SHOT;  // 기본: 차단
}

char _license[] SEC("license") = "GPL";
