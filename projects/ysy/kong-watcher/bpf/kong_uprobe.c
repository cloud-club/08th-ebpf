#include "vmlinux.h"
#include <stddef.h>

// HTTP 요청 정보 구조체 (스택 크기 제한으로 축소)
struct http_request {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8 method; // HTTP 메서드 (GET=1, POST=2, PUT=3, DELETE=4, etc.)
    __u32 status_code;
    char path[64]; // HTTP 경로 (축소)
    char host[32]; // Host 헤더 (축소)
};

// BPF 맵들
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32); // PID
    __type(value, struct http_request);
} http_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_events SEC(".maps");

// Kong Gateway 특화 HTTP 메서드 파싱 함수
static __always_inline __u8 parse_http_method(const char *data, __u32 len) {
    if (len < 3) return 0;
    
    // Kong Gateway에서 자주 사용되는 HTTP 메서드 우선 처리
    // GET (가장 일반적)
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') return 1;
    
    // POST (API 호출)
    if (len >= 4 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 2;
    
    // PUT (리소스 업데이트)
    if (data[0] == 'P' && data[1] == 'U' && data[2] == 'T') return 3;
    
    // DELETE (리소스 삭제)
    if (len >= 6 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && 
        data[4] == 'T' && data[5] == 'E') return 4;
    
    // PATCH (부분 업데이트)
    if (len >= 5 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H') return 5;
    
    // HEAD (헤더만 요청)
    if (len >= 4 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return 6;
    
    // OPTIONS (CORS)
    if (len >= 7 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && 
        data[4] == 'O' && data[5] == 'N' && data[6] == 'S') return 7;
    
    return 0; // UNKNOWN
}

// HTTP 경로 추출 함수
static __always_inline void extract_http_path(const char *data, __u32 len, char *path) {
    __u32 i = 0;
    __u32 path_start = 0;
    __u32 path_end = 0;
    
    // 첫 번째 공백 찾기 (메서드 뒤)
    for (i = 0; i < len && i < 20; i++) {
        if (data[i] == ' ') {
            path_start = i + 1;
            break;
        }
    }
    
    // 두 번째 공백 찾기 (경로 끝)
    for (i = path_start; i < len && i < path_start + 255; i++) {
        if (data[i] == ' ') {
            path_end = i;
            break;
        }
    }
    
    if (path_start < path_end && path_end - path_start < 63) {
        // Kong Gateway 특화 경로 패턴 인식
        if (path_end - path_start >= 8 && data[path_start] == '/' && data[path_start+1] == 's' && data[path_start+2] == 'e' && data[path_start+3] == 'r' && data[path_start+4] == 'v' && data[path_start+5] == 'i' && data[path_start+6] == 'c' && data[path_start+7] == 'e') {
            // /services 경로 감지
            bpf_probe_read_user_str(path, path_end - path_start + 1, data + path_start);
        } else if (path_end - path_start >= 6 && data[path_start] == '/' && data[path_start+1] == 'r' && data[path_start+2] == 'o' && data[path_start+3] == 'u' && data[path_start+4] == 't' && data[path_start+5] == 'e') {
            // /routes 경로 감지
            bpf_probe_read_user_str(path, path_end - path_start + 1, data + path_start);
        } else {
            // 일반 경로
            bpf_probe_read_user_str(path, path_end - path_start + 1, data + path_start);
        }
    } else {
        bpf_probe_read_user_str(path, 2, "/");
    }
}

// HTTP 헤더 추출 함수
static __always_inline void extract_http_header(const char *data, __u32 len, 
                                               const char *header_name, char *header_value) {
    __u32 i, j;
    __u32 header_len = 0;
    
    // 헤더 이름 길이 계산
    while (header_name[header_len] != '\0') header_len++;
    
    // 헤더 검색
    for (i = 0; i < len - header_len - 2; i++) {
        // 헤더 이름 매치
        for (j = 0; j < header_len; j++) {
            if (data[i + j] != header_name[j]) break;
        }
        
        if (j == header_len && data[i + j] == ':') {
            // 헤더 값 추출
            __u32 value_start = i + j + 1;
            __u32 value_end = value_start;
            
            // 공백 건너뛰기
            while (value_start < len && (data[value_start] == ' ' || data[value_start] == '\t')) {
                value_start++;
            }
            
            // 값 끝 찾기
            while (value_end < len && data[value_end] != '\r' && data[value_end] != '\n') {
                value_end++;
            }
            
            if (value_start < value_end && value_end - value_start < 255) {
                bpf_probe_read_user_str(header_value, value_end - value_start + 1, data + value_start);
            }
            break;
        }
    }
}

// Kong Gateway 프로세스 필터링을 위한 맵
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32); // PID
    __type(value, __u8); // 1: Kong Gateway, 0: 기타
} kong_processes SEC(".maps");

// libc read 함수 uprobe
SEC("uprobe/read")
int uprobe_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0; // Kong Gateway가 아닌 프로세스는 무시
    }
    
    // 파일 디스크립터 확인
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3) return 0; // 표준 입출력 제외
    
    // 버퍼 포인터와 크기
    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    if (count < 4 || count > 8192) return 0; // HTTP 요청 크기 범위
    
    // HTTP 요청인지 확인
    char http_check[4] = {};
    if (bpf_probe_read_user(http_check, 4, buf) != 0) return 0;
    
    // HTTP 메서드 확인
    __u8 method = parse_http_method(http_check, 4);
    if (method == 0) return 0;
    
    // HTTP 요청 구조체 생성
    struct http_request req = {};
    req.pid = pid;
    req.tid = tid;
    req.timestamp = bpf_ktime_get_ns();
    req.method = method;
    
    // HTTP 경로 추출
    extract_http_path(buf, count, req.path);
    
    // HTTP 헤더 추출
    extract_http_header(buf, count, "Host", req.host);
    
    // 맵에 저장
    bpf_map_update_elem(&http_requests, &pid, &req, BPF_ANY);
    
    // 이벤트 생성
    struct http_request *event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
    if (event) {
        *event = req;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// libc write 함수 uprobe
SEC("uprobe/write")
int uprobe_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0; // Kong Gateway가 아닌 프로세스는 무시
    }
    
    // 파일 디스크립터 확인
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3) return 0;
    
    // 버퍼 포인터와 크기
    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    if (count < 12 || count > 8192) return 0; // HTTP 응답 크기 범위
    
    // HTTP 응답인지 확인
    char http_check[8] = {};
    if (bpf_probe_read_user(http_check, 8, buf) != 0) return 0;
    
    if (http_check[0] != 'H' || http_check[1] != 'T' || 
        http_check[2] != 'T' || http_check[3] != 'P') return 0;
    
    // HTTP 상태 코드 추출
    __u32 status_code = 0;
    for (int i = 4; i < 8 && buf[i] >= '0' && buf[i] <= '9'; i++) {
        status_code = status_code * 10 + (buf[i] - '0');
    }
    
    // 기존 요청 정보 업데이트
    struct http_request *req = bpf_map_lookup_elem(&http_requests, &pid);
    if (req) {
        req->status_code = status_code;
        req->timestamp = bpf_ktime_get_ns();
        
        // 업데이트된 이벤트 생성
        struct http_request *event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
        if (event) {
            *event = *req;
            bpf_ringbuf_submit(event, 0);
        }
    }
    
    return 0;
}

// libc send 함수 uprobe
SEC("uprobe/send")
int uprobe_send(struct pt_regs *ctx) {
    // read와 유사한 로직으로 HTTP 요청 감지
    return uprobe_read(ctx);
}

// libc recv 함수 uprobe
SEC("uprobe/recv")
int uprobe_recv(struct pt_regs *ctx) {
    // write와 유사한 로직으로 HTTP 응답 감지
    return uprobe_write(ctx);
}

// Kong Gateway 특화 uprobe (nginx 함수들)
SEC("uprobe/ngx_http_process_request")
int uprobe_ngx_http_process_request(struct pt_regs *ctx) {
    // nginx HTTP 요청 처리 함수 후킹
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // nginx 요청 구조체에서 HTTP 정보 추출
    // 실제 구현에서는 nginx 내부 구조체를 파싱해야 함
    
    return 0;
}

// Kong Gateway 특화 uprobe (OpenResty/Lua 함수들)
SEC("uprobe/lua_pcall")
int uprobe_lua_pcall(struct pt_regs *ctx) {
    // Lua 함수 호출 후킹 (Kong의 Lua 플러그인)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Lua 스택에서 HTTP 정보 추출
    // 실제 구현에서는 Lua 스택을 파싱해야 함
    
    return 0;
}

char _license[] SEC("license") = "GPL";
