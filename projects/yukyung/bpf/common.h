#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 타입 정의
#ifndef __u8
#define __u8  unsigned char
#endif
#ifndef __u16
#define __u16 unsigned short
#endif
#ifndef __u32
#define __u32 unsigned int
#endif
#ifndef __u64
#define __u64 unsigned long long
#endif

// 액션 정의
#define ACTION_DROP     0
#define ACTION_PASS     1
#define ACTION_REDIRECT 2

// 프로토콜 정의
#define PROTO_ANY  0
#define PROTO_TCP  6
#define PROTO_UDP  17
#define PROTO_ICMP 1

// 라우팅 규칙 구조체
struct routing_rule {
    __u32 id;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_ip_mask;
    __u32 dst_ip_mask;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  action;
    __u8  priority;
    __u8  enabled;
    __u32 redirect_interface;
};

// 통계 구조체
struct packet_stats {
    __u64 total_packets;
    __u64 matched_packets;
    __u64 dropped_packets;
    __u64 passed_packets;
    __u64 redirected_packets;
    __u64 last_updated;
};

// 패킷 정보 구조체
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

// eBPF 맵 정의
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);           // rule ID
    __type(value, struct routing_rule);
} rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct packet_stats);
} stats_map SEC(".maps");

// 헬퍼 함수
static __always_inline int parse_packet(struct xdp_md *ctx, struct packet_info *info);
static __always_inline int match_rule(struct packet_info *info, struct routing_rule *rule);
static __always_inline void update_stats(__u8 action);

#endif /* __COMMON_H__ */
