#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// 패킷 파싱 함수
static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_info *info) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet 헤더 체크
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }

    // IPv4만 처리
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return -1;
    }

    // IP 헤더 체크
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return -1;
    }

    // IP 정보 추출
    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;
    info->protocol = ip->protocol;
    info->src_port = 0;
    info->dst_port = 0;

    // TCP/UDP 포트 정보 추출
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end) {
            return 0; // 포트 정보 없어도 IP는 유효
        }
        info->src_port = bpf_ntohs(tcp->source);
        info->dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end) {
            return 0; // 포트 정보 없어도 IP는 유효
        }
        info->src_port = bpf_ntohs(udp->source);
        info->dst_port = bpf_ntohs(udp->dest);
    }

    return 0;
}

// 규칙 매칭 함수
static __always_inline int match_rule(struct packet_info *info, struct routing_rule *rule) {
    // 비활성화된 규칙은 스킵
    if (!rule->enabled) {
        return 0;
    }

    // 소스 IP 체크
    if (rule->src_ip_mask != 0) {
        if ((info->src_ip & rule->src_ip_mask) != (rule->src_ip & rule->src_ip_mask)) {
            return 0;
        }
    }

    // 목적지 IP 체크
    if (rule->dst_ip_mask != 0) {
        if ((info->dst_ip & rule->dst_ip_mask) != (rule->dst_ip & rule->dst_ip_mask)) {
            return 0;
        }
    }

    // 소스 포트 체크
    if (rule->src_port != 0 && rule->src_port != info->src_port) {
        return 0;
    }

    // 목적지 포트 체크
    if (rule->dst_port != 0 && rule->dst_port != info->dst_port) {
        return 0;
    }

    // 프로토콜 체크
    if (rule->protocol != PROTO_ANY && rule->protocol != info->protocol) {
        return 0;
    }

    return 1; // 매칭됨
}

// 통계 업데이트 함수
static __always_inline void update_stats(__u8 action) {
    __u32 key = 0;
    struct packet_stats *stats = bpf_map_lookup_elem(&stats_map, &key);

    if (stats) {
        __sync_fetch_and_add(&stats->total_packets, 1); // 총 패킷 수 증가

        switch (action) {
            case ACTION_DROP:
                __sync_fetch_and_add(&stats->dropped_packets, 1); // 차단된 패킷 수 증가
                break;
            case ACTION_PASS:
                __sync_fetch_and_add(&stats->passed_packets, 1); // 통과된 패킷 수 증가
                break;
            case ACTION_REDIRECT:
                __sync_fetch_and_add(&stats->redirected_packets, 1); // 리다이렉트된 패킷 수 증가
                break;
        }

        __sync_fetch_and_add(&stats->matched_packets, 1); // 매칭된 패킷 수 증가
        stats->last_updated = bpf_ktime_get_ns(); // 마지막 업데이트 시간 업데이트
    }
}

// 메인 XDP 프로그램
SEC("xdp")
int xdp_router_main(struct xdp_md *ctx) {
    struct packet_info pkt_info = {0};

    // 패킷 파싱
    if (parse_packet(ctx, &pkt_info) < 0) {
        return XDP_PASS; // 파싱 실패 시 통과
    }

    struct routing_rule *matched_rule = NULL;
    __u8 highest_priority = 0;

    // 규칙 맵을 순회하면서 매칭되는 규칙 찾기
    for (__u32 rule_id = 1; rule_id <= 100; rule_id++) {
        struct routing_rule *rule = bpf_map_lookup_elem(&rules_map, &rule_id);
        if (!rule) {
            continue;
        }

        // 비활성화된 규칙은 스킵
        if (!rule->enabled) {
            continue;
        }

        // 이미 더 높은 우선순위의 매칭 규칙이 있으면 스킵
        if (matched_rule && rule->priority >= highest_priority) {
            continue;
        }

        if (match_rule(&pkt_info, rule)) {
            matched_rule = rule;
            highest_priority = rule->priority;
            
            // 우선순위 0이면 즉시 종료
            if (rule->priority == 0) {
                break;
            }
        }
    }

    // 매칭된 규칙에 따라 액션 수행
    __u8 action = ACTION_PASS; // 기본 액션

    if (matched_rule) {
        action = matched_rule->action;
        update_stats(action);

        bpf_printk("Rule %d matched action=%d\n", matched_rule->id, action);
    }

    // 액션에 따른 XDP 리턴 코드
    switch (action) {
        case ACTION_DROP:
            return XDP_DROP;
        case ACTION_PASS:
            return XDP_PASS;
        case ACTION_REDIRECT:
            // 패킷을 다른 인터페이스로 리다이렉트
            if (matched_rule->redirect_interface == 0) {
                return XDP_TX;
            } else {
                return bpf_redirect(matched_rule->redirect_interface, 0);
            }
        default:
            return XDP_PASS;
    }
}
