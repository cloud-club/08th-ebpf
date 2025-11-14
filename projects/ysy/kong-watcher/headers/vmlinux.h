/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// 기본 타입 정의
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __sum16;

// 구조체 정의
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

/* Common definitions */
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* XDP return codes */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

/* XDP context structure */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* Ethernet header */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

/* IP header */
struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

/* TCP header */
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 res1:4, doff:4;
    __u8 fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

/* UDP header */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

/* Network device structure (simplified) */
struct net_device {
    char name[16];
    int ifindex;
};

/* Socket buffer structure (simplified) */
struct sk_buff {
    struct net_device *dev;
    __u32 len;
    __u32 data_len;
    void *data;
    void *head;
    void *end;
};

/* Helper macros */
#define __constant_htons(x) ((__be16)___constant_swab16((x)))
#define __bpf_ntohs(x) ((__be16)___constant_swab16((x)))
#define __bpf_ntohl(x) ((__be32)___constant_swab32((x)))
#define __bpf_htons(x) ((__be16)___constant_swab16((x)))

/* Byte order conversion */
static inline __u16 ___constant_swab16(__u16 x)
{
    return ((__u16)((((__u16)(x) & (__u16)0x00ffU) << 8) |
                    (((__u16)(x) & (__u16)0xff00U) >> 8)));
}

static inline __u32 ___constant_swab32(__u32 x)
{
    return ((__u32)((((__u32)(x) & (__u32)0x000000ffUL) << 24) |
                    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |
                    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |
                    (((__u32)(x) & (__u32)0xff000000UL) >> 24)));
}

/* PT_REGS 매크로 */
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

/* eBPF 헬퍼 함수들 */
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name
#define __always_inline __attribute__((always_inline)) static inline

/* BPF 맵 타입 */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27

/* BPF 액션 */
#define BPF_ANY 0
#define XDP_PASS 2

/* eBPF 헬퍼 함수 선언 */
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;

/* 원자적 연산 */
#define __sync_fetch_and_add(ptr, value) __atomic_fetch_add(ptr, value, __ATOMIC_RELAXED)

#endif /* __VMLINUX_H__ */
