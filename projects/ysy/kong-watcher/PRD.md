# Kong Gateway eBPF Monitor - Product Requirements Document

## 프로젝트 개요
Kong Gateway와 같은 Pod에서 실행되는 사이드카 컨테이너를 통해 Kong Gateway의 HTTP 트래픽을 실시간으로 모니터링하는 eBPF 기반 솔루션

## 구현 목표
같은 Pod에서 동작하는 Kong Gateway 애플리케이션의 HTTP 트래픽을 실시간으로 모니터링하여 다음 정보를 제공:

- **HTTP Method별 통계**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- **도메인별 통계**: Host 헤더 기반 도메인별 요청 분석
- **경로별 통계**: HTTP 경로별 요청 패턴 분석
- **응답 시간 측정**: 요청-응답 간 소요 시간 추적
- **에러 추적**: HTTP 상태 코드 및 에러 패턴 분석

## 아키텍처

### 사이드카 모델
```
┌─────────────────────────────────────────┐
│              Same Pod                   │
│                                         │
│  ┌─────────────────┐  ┌───────────────┐ │
│  │ eBPF Monitor     │  │ Kong Gateway  │ │
│  │ Container        │  │ Container     │ │
│  │                  │  │               │ │
│  │ [uprobe] ────────┼──┼→ [HTTP API]   │ │
│  │                  │  │               │ │
│  └─────────────────┘  └───────────────┘ │
│                                         │
└─────────────────────────────────────────┘
           ↑
    External Traffic
    (from other pods/services)
```

### 기술 스택
- **eBPF 기술**: uprobe를 사용한 사용자 공간 함수 추적
- **언어**: Go (사용자 공간), C (eBPF 프로그램)
- **프레임워크**: Cilium eBPF Go 라이브러리
- **배포**: Kubernetes 사이드카 컨테이너

## eBPF Map 구조

### Map이란?
eBPF 프로그램에서 커널 공간과 유저 공간, 또는 eBPF 프로그램 간에 데이터를 주고받을 수 있도록 해주는 데이터 구조

- **key/value 형태**의 자료구조
- 커널과 유저 공간 모두 동일한 메모리 구조 정의를 공유
- **BTF(BPF Type Format)** 방식을 사용하는 최신 표준
- 타입 정보와 다양한 속성(유형, key/value 타입, entry 수 등)을 선언적으로 명시

### 구현된 Map들

#### 1. BPF_HASH - Kong 프로세스 추적 (`kong_processes`)
- **목적**: Kong Gateway 프로세스 식별 및 관리
- **키**: PID (uint32)
- **값**: Kong 프로세스 플래그 (uint8)
- **최대 엔트리**: 1,000개

#### 2. BPF_HASH - 요청 시작 시간 추적 (`request_start_times`)
- **목적**: HTTP 요청의 시작 시간을 기록하여 응답 시간 계산
- **키**: PID (uint32)
- **값**: 시작 시간 (uint64, 나노초)
- **최대 엔트리**: 10,000개

#### 3. BPF_HASH - HTTP 요청 정보 (`http_requests`)
- **목적**: 진행 중인 HTTP 요청 정보 저장
- **키**: PID (uint32)
- **값**: HTTP 요청 구조체
- **최대 엔트리**: 10,000개

#### 4. BPF_RINGBUF - 실시간 이벤트 (`http_events`)
- **목적**: 실시간 HTTP 이벤트 스트림
- **버퍼 크기**: 256KB
- **이벤트 구조**: HTTP 요청/응답 정보
- **특징**: 거의 딜레이 없는 실시간 이벤트 전송

## eBPF 프로그램 구조

### uprobe 프로그램들

#### 1. `uprobe_read` - HTTP 요청 추적
- **대상**: libc read() 함수
- **목적**: Kong 프로세스의 HTTP 요청 데이터 읽기 추적
- **기능**: HTTP 메서드, 경로, 헤더 파싱

#### 2. `uprobe_write` - HTTP 응답 추적
- **대상**: libc write() 함수
- **목적**: Kong 프로세스의 HTTP 응답 데이터 쓰기 추적
- **기능**: HTTP 상태 코드 추출, 응답 시간 계산

#### 3. `uprobe_kong_http_request` - Kong HTTP 요청 처리
- **대상**: nginx ngx_http_process_request() 함수
- **목적**: Kong의 내부 HTTP 요청 처리 추적
- **기능**: Kong 특화 요청 정보 수집

#### 4. `uprobe_kong_http_response` - Kong HTTP 응답 처리
- **대상**: nginx ngx_http_send_response() 함수
- **목적**: Kong의 내부 HTTP 응답 처리 추적
- **기능**: Kong 특화 응답 정보 수집

#### 5. `uprobe_kong_lua_handler` - Kong Lua 핸들러
- **대상**: Kong Lua 핸들러 함수
- **목적**: Kong의 Lua 플러그인 실행 추적
- **기능**: Lua 핸들러 실행 정보 수집

## 데이터 구조

### HTTP 요청 정보 구조체
```c
struct http_request {
    __u32 pid;              // 프로세스 ID
    __u32 tid;              // 스레드 ID
    __u64 timestamp;        // 타임스탬프 (나노초)
    __u8 method;           // HTTP 메서드 (1=GET, 2=POST, ...)
    __u32 status_code;      // HTTP 상태 코드
    __u32 response_time_ns; // 응답 시간 (나노초)
    char path[64];          // HTTP 경로
    char host[32];          // Host 헤더
    char remote_addr[16];   // 클라이언트 IP
    char user_agent[128];   // User-Agent 헤더
    __u8 error_code;        // 에러 코드 (0=정상, 1=파싱오류, 2=메모리오류)
};
```

## Kubernetes 배포

### 사이드카 컨테이너 설정
- **이미지**: kong-watcher:latest
- **권한**: privileged 모드 (eBPF 프로그램 로드 필요)
- **Capabilities**: SYS_ADMIN, SYS_RESOURCE, NET_ADMIN
- **볼륨 마운트**: /host/proc, /host/sys, /host/dev

### 환경 변수
- `LOG_LEVEL`: 로그 레벨 (debug, info, warn, error)
- `ENABLE_JSON_LOG`: JSON 로그 활성화 (true/false)
- `KONG_PROCESS_NAME`: Kong 프로세스 이름 지정
- `STATS_INTERVAL`: 통계 출력 간격

### 리소스 요구사항
- **CPU**: 100m (요청), 200m (제한)
- **메모리**: 128Mi (요청), 256Mi (제한)

## 모니터링 기능

### 실시간 통계
- 총 요청 수
- 총 응답 수
- 에러 수
- 평균 응답 시간
- 마지막 요청 시간

### 로그 출력
- 구조화된 로그 (JSON/텍스트)
- HTTP 요청/응답 상세 정보
- 에러 및 경고 로그
- 디버그 정보

### 이벤트 스트림
- 실시간 HTTP 이벤트
- 요청-응답 매칭
- 성능 메트릭
- 에러 추적

## 보안 고려사항

### 권한 관리
- 최소 권한 원칙 적용
- 필요한 capabilities만 추가
- privileged 모드 사용 (eBPF 로드 필요)

### 데이터 보호
- 민감한 헤더 정보 마스킹 옵션
- 로그 레벨별 정보 제어
- 메모리 사용량 제한

## 성능 특성

### 오버헤드
- **CPU 오버헤드**: < 1% (일반적인 워크로드)
- **메모리 사용량**: < 256MB
- **네트워크 지연**: 거의 없음 (uprobe 기반)

### 확장성
- 다중 Kong 인스턴스 지원
- 수평적 확장 가능
- 실시간 이벤트 처리

## 향후 개선 계획

### 기능 확장
- Kong 플러그인별 모니터링
- 사용자 정의 메트릭 지원
- 알림 및 알람 기능

### 성능 최적화
- 메모리 사용량 최적화
- CPU 오버헤드 감소
- 더 정확한 응답 시간 측정

### 통합 기능
- Prometheus 메트릭 내보내기
- Grafana 대시보드 연동
- ELK 스택 통합
