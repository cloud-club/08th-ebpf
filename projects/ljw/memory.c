// +build ignore

#include <linux/bpf.h> 
#include <bpf/bpf_helpers.h> 
#include <bpf/bpf_tracing.h> 
#define PAGE_SIZE 4096 
#define MAX_PAGE_CHANGE 1000000 // 단일 이벤트에서 예상되는 최대 페이지 변경량 (약 4GB). 비정상적인 값을 필터링하는 데 사용.


// BPF 맵 정의: rss_bytes
// 각 프로세스의 현재 RSS(상주 세트 크기) 바이트를 저장합니다.
struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 1024); 
    __type(key, __u32);   // 키: 프로세스 ID (pid_t)
    __type(value, __s64); // 값: 현재 RSS 바이트
} rss_bytes SEC(".maps"); 

// BPF 맵 정의: peak_rss_bytes
// 각 프로세스의 최대 RSS 바이트를 저장합니다.
struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 1024); 
    __type(key, __u32);   // 키: 프로세스 ID (pid_t)
    __type(value, __s64); // 값: 최대 RSS 바이트
} peak_rss_bytes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u32 ebpf_pid;
        __u32 target_pid;
    });
} debug_pids SEC(".maps");

// BPF 맵 정의: target_pid_map
// 모니터링할 대상 프로세스의 PID를 저장합니다.
// Go 애플리케이션에서 이 맵에 자신의 PID를 넣어 eBPF 프로그램이 해당 PID만 추적하도록 합니다.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __uint(max_entries, 1); 
    __type(key, __u32); // 키: 0 (단일 항목이므로)
    __type(value, __u32); // 값: 대상 PID
} target_pid_map SEC(".maps"); 

// rss_stat 트레이스포인트의 데이터 구조 정의
// 커널의 kmem:rss_stat 트레이스포인트에서 전달되는 인자들을 나타냅니다.
struct rss_stat_args {
    long long __unused; 
    int curr;           
    int member;         
    long size;          // 페이지 변경량 (+ 또는 -)
};

// tracepoint: 커널의 RSS 통계가 변경될 때마다 실행되는 eBPF 프로그램
SEC("tracepoint/kmem/rss_stat")
int trace_rss_stat(struct rss_stat_args *ctx) {
    // 비정상적으로 크거나 작은 페이지 변경량 필터링
    // 단일 이벤트에서 페이지 변경량이 MAX_PAGE_CHANGE를 초과하지 않는다고 가정
    if (ctx->size > MAX_PAGE_CHANGE || ctx->size < -MAX_PAGE_CHANGE) {
        return 0; // 비정상적인 값은 무시하고 종료
    }

    // 현재 이벤트가 발생한 프로세스의 PID 가져오기
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 타겟 PID 맵에서 모니터링할 대상 PID 조회
    __u32 key = 0;
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);

    struct {
        __u32 ebpf_pid;
        __u32 target_pid;
    } debug_val = { .ebpf_pid = pid, .target_pid = (target_pid ? *target_pid : 0) };
    bpf_map_update_elem(&debug_pids, &key, &debug_val, BPF_ANY);

    // target_pid가 설정되지 않았거나 현재 pid와 다르면 이벤트를 무시
    // if (target_pid == NULL || *target_pid != pid) {
    //     return 0;
    // }



    // rss_bytes 맵에서 현재 PID의 기존 RSS 값 조회
    __s64* existing_value = bpf_map_lookup_elem(&rss_bytes, &pid);
    __s64 new_value;

    // 페이지 변경량을 바이트 단위로 변환
    __s64 change_in_bytes = (__s64)ctx->size * PAGE_SIZE; 

    // 기존 값이 있으면 누적하고, 없으면 현재 변경량을 초기 값으로 설정
    if (existing_value) {
        new_value = *existing_value + change_in_bytes;
    } else {
        new_value = change_in_bytes;
    }

    // 새로운 누적 RSS 값으로 맵 업데이트 
    bpf_map_update_elem(&rss_bytes, &pid, &new_value, BPF_ANY);

    // peak_rss_bytes 맵에서 현재 PID의 최대 RSS 값 조회 및 업데이트
    __s64* peak_value = bpf_map_lookup_elem(&peak_rss_bytes, &pid);
    if (peak_value) {
        if (new_value > *peak_value) {
            bpf_map_update_elem(&peak_rss_bytes, &pid, &new_value, BPF_ANY);
        }
    } else {
        // peak_value가 없으면, new_value로 새로 추가
        bpf_map_update_elem(&peak_rss_bytes, &pid, &new_value, BPF_ANY);
    }

    // 계산된 RSS 값이 0보다 작으면 (프로세스 종료 또는 메모리 해제 시) 맵에서 해당 항목 삭제
    if (new_value < 0) {
        bpf_map_delete_elem(&rss_bytes, &pid);
        return 0;
    }

    return 0; 
}

char LICENSE[] SEC("license") = "GPL"; 
