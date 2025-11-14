#include "vmlinux.h"

// HTTP 요청 정보 구조체 (uprobe용)
struct http_request {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    __u8 method; // HTTP 메서드 (GET=1, POST=2, PUT=3, DELETE=4, etc.)
    __u32 status_code;
    __u32 response_time_ns; // 응답 시간 (나노초)
    char path[64];
    char host[32];
    char remote_addr[16];
    char user_agent[128];
    __u8 error_code; // 에러 코드 (0=정상, 1=파싱오류, 2=메모리오류)
};

// Kong Gateway 프로세스 맵
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u8);
} kong_processes SEC(".maps");

// 요청 시작 시간 추적 맵
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} request_start_times SEC(".maps");

// HTTP 요청 맵 (PID별)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct http_request);
} http_requests SEC(".maps");

// 실시간 HTTP 이벤트
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} http_events SEC(".maps");

// HTTP 메서드 파싱 (개선된 버전)
static __u8 parse_http_method(const char *data, __u64 size) {
    if (size < 3) return 0;
    
    // GET
    if (size >= 3 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T') return 1;
    // POST
    if (size >= 4 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 2;
    // PUT
    if (size >= 3 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T') return 3;
    // DELETE
    if (size >= 6 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && 
        data[4] == 'T' && data[5] == 'E') return 4;
    // PATCH
    if (size >= 5 && data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && 
        data[4] == 'H') return 5;
    // HEAD
    if (size >= 4 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D') return 6;
    // OPTIONS
    if (size >= 7 && data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I' && 
        data[4] == 'O' && data[5] == 'N' && data[6] == 'S') return 7;
    
    return 0;
}

// HTTP 경로 추출 (개선된 버전)
static __u8 extract_http_path(const char *data, __u64 size, char *path) {
    __u64 i = 0;
    __u64 path_start = 0;
    __u64 path_end = 0;
    
    // 첫 번째 공백 이후부터 경로 시작
    for (i = 0; i < size && i < 64; i++) {
        if (data[i] == ' ') {
            path_start = i + 1;
            break;
        }
    }
    
    if (path_start == 0) return 1; // 파싱 오류
    
    // 두 번째 공백까지가 경로
    for (i = path_start; i < size && i < path_start + 63; i++) {
        if (data[i] == ' ' || data[i] == '?') {
            path_end = i;
            break;
        }
    }
    
    if (path_end == 0) path_end = size;
    
    // 경로 복사
    __u64 path_len = path_end - path_start;
    if (path_len > 63) path_len = 63;
    
    for (i = 0; i < path_len; i++) {
        path[i] = data[path_start + i];
    }
    path[path_len] = '\0';
    
    return 0; // 성공
}

// HTTP 헤더 추출 (개선된 버전)
static __u8 extract_http_header(const char *data, __u64 size, const char *header_name, char *header_value, __u64 max_value_len) {
    __u64 i, j;
    __u64 header_len = 0;
    
    // 헤더 이름 길이 계산
    while (header_name[header_len] != '\0' && header_len < 32) header_len++;
    if (header_len == 0) return 1; // 잘못된 헤더 이름
    
    // 헤더 찾기
    for (i = 0; i < size - header_len - 2; i++) {
        // 헤더 이름 매칭
        __u8 match = 1;
        for (j = 0; j < header_len; j++) {
            if (data[i + j] != header_name[j]) {
                match = 0;
                break;
            }
        }
        
        if (match && data[i + header_len] == ':') {
            // 헤더 값 추출
            __u64 value_start = i + header_len + 1;
            while (value_start < size && (data[value_start] == ' ' || data[value_start] == '\t')) {
                value_start++;
            }
            
            __u64 value_end = value_start;
            while (value_end < size && data[value_end] != '\r' && data[value_end] != '\n') {
                value_end++;
            }
            
            __u64 value_len = value_end - value_start;
            if (value_len > max_value_len - 1) value_len = max_value_len - 1;
            
            for (j = 0; j < value_len; j++) {
                header_value[j] = data[value_start + j];
            }
            header_value[value_len] = '\0';
            return 0; // 성공
        }
    }
    
    return 1; // 헤더를 찾지 못함
}

// Kong HTTP 요청 처리 함수 uprobe (개선된 버전)
SEC("uprobe/ngx_http_process_request")
int uprobe_kong_http_request(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid & 0xFFFFFFFF;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0;
    }
    
    // 요청 시작 시간 기록
    __u64 start_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&request_start_times, &pid, &start_time, BPF_ANY);
    
    // HTTP 요청 구조체 생성
    struct http_request req = {};
    req.pid = pid;
    req.tid = tid;
    req.timestamp = start_time;
    req.method = 1; // 기본값: GET
    req.status_code = 0; // 아직 응답 없음
    req.response_time_ns = 0;
    req.error_code = 0;
    
    // 기본 경로 설정
    __builtin_memcpy(req.path, "/", 1);
    req.path[1] = '\0';
    
    // 기본 호스트 설정
    __builtin_memcpy(req.host, "localhost", 9);
    req.host[9] = '\0';
    
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

// Kong HTTP 응답 처리 함수 uprobe (개선된 버전)
SEC("uprobe/ngx_http_send_response")
int uprobe_kong_http_response(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0;
    }
    
    // 응답 시간 계산
    __u64 *start_time = bpf_map_lookup_elem(&request_start_times, &pid);
    __u64 current_time = bpf_ktime_get_ns();
    __u64 response_time = 0;
    
    if (start_time) {
        response_time = current_time - *start_time;
        // 시작 시간 맵에서 제거
        bpf_map_delete_elem(&request_start_times, &pid);
    }
    
    // HTTP 응답 정보 업데이트
    struct http_request *req = bpf_map_lookup_elem(&http_requests, &pid);
    if (req) {
        req->status_code = 200; // 실제로는 nginx 구조체에서 추출
        req->timestamp = current_time;
        req->response_time_ns = response_time;
        
        // 이벤트 생성
        struct http_request *event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
        if (event) {
            *event = *req;
            bpf_ringbuf_submit(event, 0);
        }
        
        // 요청 맵에서 제거
        bpf_map_delete_elem(&http_requests, &pid);
    }
    
    return 0;
}

// Kong Lua 핸들러 uprobe (개선된 버전)
SEC("uprobe/kong_http_handler")
int uprobe_kong_lua_handler(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0;
    }
    
    // Kong Lua 핸들러에서 HTTP 정보 추출
    // 실제 구현시 Kong의 Lua C API 분석 필요
    // 현재는 기본적인 로깅만 수행
    
    // 요청 시작 시간 기록 (만약 아직 기록되지 않았다면)
    __u64 *existing_start = bpf_map_lookup_elem(&request_start_times, &pid);
    if (!existing_start) {
        __u64 start_time = bpf_ktime_get_ns();
        bpf_map_update_elem(&request_start_times, &pid, &start_time, BPF_ANY);
    }
    
    return 0;
}

// libc read 함수 uprobe (개선된 버전)
SEC("uprobe/read")
int uprobe_read(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0;
    }
    
    // 파일 디스크립터 확인
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3) return 0; // 표준 입출력 제외
    
    // 버퍼 포인터와 크기
    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    if (count < 4 || count > 8192) return 0;
    
    // HTTP 요청인지 확인
    char http_check[4] = {};
    long ret = bpf_probe_read_user(http_check, 4, buf);
    if (ret != 0) {
        // 메모리 읽기 실패
        return 0;
    }
    
    // HTTP 메서드 확인
    __u8 method = parse_http_method(http_check, 4);
    if (method == 0) return 0;
    
    // 요청 시작 시간 기록
    __u64 start_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&request_start_times, &pid, &start_time, BPF_ANY);
    
    // HTTP 요청 구조체 생성
    struct http_request req = {};
    req.pid = pid;
    req.tid = pid_tgid & 0xFFFFFFFF;
    req.timestamp = start_time;
    req.method = method;
    req.status_code = 0; // 아직 응답 없음
    req.response_time_ns = 0;
    req.error_code = 0;
    
    // HTTP 경로 추출
    if (extract_http_path(buf, count, req.path) != 0) {
        req.error_code = 1; // 파싱 오류
    }
    
    // HTTP 헤더 추출
    if (extract_http_header(buf, count, "Host", req.host, 32) != 0) {
        __builtin_memcpy(req.host, "unknown", 7);
        req.host[7] = '\0';
    }
    
    if (extract_http_header(buf, count, "User-Agent", req.user_agent, 128) != 0) {
        __builtin_memcpy(req.user_agent, "unknown", 7);
        req.user_agent[7] = '\0';
    }
    
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

// libc write 함수 uprobe (HTTP 응답) - 개선된 버전
SEC("uprobe/write")
int uprobe_write(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Kong Gateway 프로세스인지 확인
    __u8 *is_kong = bpf_map_lookup_elem(&kong_processes, &pid);
    if (!is_kong || *is_kong != 1) {
        return 0;
    }
    
    // 파일 디스크립터 확인
    int fd = (int)PT_REGS_PARM1(ctx);
    if (fd < 3) return 0;
    
    // 버퍼 포인터와 크기
    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    
    if (count < 4 || count > 8192) return 0;
    
    // HTTP 응답인지 확인
    char http_check[4] = {};
    long ret = bpf_probe_read_user(http_check, 4, buf);
    if (ret != 0) {
        // 메모리 읽기 실패
        return 0;
    }
    
    // HTTP/1.1 응답 확인
    if (http_check[0] != 'H' || http_check[1] != 'T' || 
        http_check[2] != 'T' || http_check[3] != 'P') return 0;
    
    // 응답 시간 계산
    __u64 *start_time = bpf_map_lookup_elem(&request_start_times, &pid);
    __u64 current_time = bpf_ktime_get_ns();
    __u64 response_time = 0;
    
    if (start_time) {
        response_time = current_time - *start_time;
        // 시작 시간 맵에서 제거
        bpf_map_delete_elem(&request_start_times, &pid);
    }
    
    // HTTP 상태 코드 추출
    __u32 status_code = 200;
    char status_line[16] = {};
    ret = bpf_probe_read_user(status_line, 15, buf);
    if (ret == 0) {
        // "HTTP/1.1 200 OK" 형태에서 상태 코드 추출
        for (int i = 0; i < 12; i++) {
            if (status_line[i] == ' ' && i + 3 < 15) {
                status_code = (status_line[i+1] - '0') * 100 + 
                             (status_line[i+2] - '0') * 10 + 
                             (status_line[i+3] - '0');
                break;
            }
        }
    }
    
    // HTTP 요청 구조체 업데이트
    struct http_request *req = bpf_map_lookup_elem(&http_requests, &pid);
    if (req) {
        req->status_code = status_code;
        req->timestamp = current_time;
        req->response_time_ns = response_time;
        
        // 이벤트 생성
        struct http_request *event = bpf_ringbuf_reserve(&http_events, sizeof(*event), 0);
        if (event) {
            *event = *req;
            bpf_ringbuf_submit(event, 0);
        }
        
        // 요청 맵에서 제거
        bpf_map_delete_elem(&http_requests, &pid);
    }
    
    return 0;
}
