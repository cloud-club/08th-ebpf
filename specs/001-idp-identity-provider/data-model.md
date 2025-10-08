# 데이터 모델: IDP/RBAC Site-to-Site VPN 라우터

**피처 브랜치**: `001-idp-identity-provider`
**생성일**: 2025-10-07
**상태**: Phase 1 설계 완료

## 개요

이 문서는 eBPF 기반 VPN 라우터 시스템의 모든 데이터 구조, 관계, 검증 규칙을 정의합니다. 시스템은 커널 공간(eBPF 맵)과 사용자 공간(Rust 구조체) 간에 데이터를 공유합니다.

## 아키텍처 맵

```
┌─────────────────────────────────────────────────────────────┐
│                  사용자 공간 데이터 모델                      │
├─────────────────────────────────────────────────────────────┤
│  IDP 토큰 → 정책 컴파일러 → eBPF 맵 항목                    │
│  (Rust 구조체)        ↓                                      │
│                  맵 업데이트 API                             │
└──────────────────────┬──────────────────────────────────────┘
                       │ (bpf syscalls)
┌──────────────────────┴──────────────────────────────────────┐
│                  커널 공간 데이터 모델                        │
├─────────────────────────────────────────────────────────────┤
│  eBPF 맵 (IP→역할, 역할→ACL, 세션키, 감사 링버퍼)           │
│  ↓                                                           │
│  XDP/TC 프로그램이 읽기 전용으로 조회                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 핵심 엔티티

### 1. IP-역할 매핑 (IP-Role Mapping)

**목적**: 소스 IP 주소(또는 CIDR 범위)를 역할 식별자로 매핑

**eBPF 맵 정의**:
```rust
// BPF_MAP_TYPE_LPM_TRIE
#[repr(C)]
pub struct IpRoleKey {
    pub prefixlen: u32,  // CIDR 프리픽스 길이 (0-32)
    pub ip: u32,         // 네트워크 바이트 순서의 IPv4
}

#[repr(C)]
pub struct IpRoleValue {
    pub role_id: u32,        // 역할 식별자
    pub version: u64,        // 맵 버전 (원자적 업데이트용)
    pub expires_at: u64,     // 나노초 타임스탬프 (0 = 만료 없음)
}
```

**사용자 공간 구조체**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRoleMapping {
    pub ip_range: IpNetwork,  // ipnetwork 크레이트 사용
    pub role_id: RoleId,
    pub expires_at: Option<SystemTime>,
    pub source: MappingSource,  // IDP | Static | Dynamic
}

pub type RoleId = u32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingSource {
    Idp { provider: String, user_id: String },
    Static { config_file: PathBuf },
    Dynamic { reason: String },
}
```

**검증 규칙**:
- `prefixlen`은 0-32 범위여야 함
- `ip`는 `prefixlen`에 따라 정규화되어야 함 (호스트 비트는 0)
- `role_id`는 역할-ACL 맵에 존재해야 함
- `expires_at`가 0이 아닌 경우, 현재 시간보다 미래여야 함
- 충돌하는 CIDR 범위는 가장 구체적인 것(longest prefix match)이 우선

**상태 전이**:
```
[생성] → IDP 인증 또는 정적 설정
    ↓
[활성] → eBPF 맵에 로드됨
    ↓
[만료] → TTL 도달 또는 IDP 토큰 갱신 실패
    ↓
[제거] → 맵에서 삭제
```

**크기 제약**:
- 최대 항목: 10,000 (SC-009)
- 맵 확장: 80% 사용률에서 트리거 (2× 용량)

---

### 2. ACL 규칙 (ACL Rule)

**목적**: 네트워크 접근 정책 정의 (소스, 목적지, 프로토콜, 액션)

**eBPF 맵 정의**:
```rust
// BPF_MAP_TYPE_HASH (역할 ID → ACL 규칙셋)
pub type AclMapKey = u32;  // role_id

#[repr(C)]
pub struct AclMapValue {
    pub num_rules: u32,                     // 활성 규칙 수
    pub rules: [AclRule; MAX_RULES_PER_ROLE],  // 인라인 배열
    pub version: u64,                       // 원자적 업데이트용
}

pub const MAX_RULES_PER_ROLE: usize = 32;

#[repr(C)]
pub struct AclRule {
    pub rule_id: u32,           // 감사 로깅용 고유 식별자
    pub src_net: u32,           // CIDR: 네트워크
    pub src_prefixlen: u8,      // CIDR: 프리픽스 길이
    pub dst_net: u32,           // CIDR: 네트워크
    pub dst_prefixlen: u8,      // CIDR: 프리픽스 길이
    pub protocol: u8,           // IPPROTO_TCP (6), IPPROTO_UDP (17), 0 = ANY
    pub dst_port_min: u16,      // 포트 범위 시작 (0 = ANY)
    pub dst_port_max: u16,      // 포트 범위 끝
    pub action: AclAction,      // ALLOW(0) 또는 DENY(1)
    pub priority: u8,           // 낮을수록 우선 (다중 역할용)
    pub flags: u8,              // [RSV|RSV|RSV|RSV|RSV|LOG|BIDIR|ENABLED]
}

#[repr(u8)]
pub enum AclAction {
    Allow = 0,
    Deny = 1,
}
```

**사용자 공간 구조체**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRuleSet {
    pub role_id: RoleId,
    pub role_name: String,
    pub rules: Vec<AclRuleDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRuleDefinition {
    pub rule_id: u32,
    pub src: IpNetwork,
    pub dst: IpNetwork,
    pub protocol: Protocol,
    pub dst_ports: PortRange,
    pub action: AclAction,
    pub priority: u8,
    pub bidirectional: bool,  // true인 경우 역방향 규칙 자동 생성
    pub log_violations: bool,
    pub enabled: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    Custom(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortRange {
    Any,
    Single(u16),
    Range(u16, u16),
}
```

**검증 규칙**:
- `num_rules` ≤ `MAX_RULES_PER_ROLE` (32)
- `rule_id`는 역할 내에서 고유해야 함
- `src_prefixlen`, `dst_prefixlen`은 0-32 범위
- `dst_port_min` ≤ `dst_port_max`
- `protocol`이 TCP/UDP가 아닌 경우 포트는 무시됨
- `priority`는 0-255 범위
- 다중 역할의 경우, DENY가 ALLOW보다 우선 (명확화 Q2)

**플래그 비트**:
```
Bit 0: ENABLED     - 규칙 활성화 (0 = 건너뜀)
Bit 1: BIDIR       - 양방향 (역방향 규칙 자동 적용)
Bit 2: LOG         - 로그 위반 사항
Bits 3-7: 예약됨
```

**크기 제약**:
- 최대 역할: 100 (SC-009)
- 역할당 최대 규칙: 32 (verifier 제약)

---

### 3. 세션 키 (Session Key)

**목적**: VPN 피어 간 암호화 컨텍스트 저장

**eBPF 맵 정의**:
```rust
// BPF_MAP_TYPE_HASH
#[repr(C)]
pub struct SessionKeyKey {
    pub peer_ip: u32,      // 원격 피어 IP
    pub tunnel_id: u32,    // 터널 식별자 (여러 터널 지원)
}

#[repr(C)]
pub struct SessionKeyValue {
    pub key: [u8; 32],          // ChaCha20-Poly1305 대칭키
    pub seq_num: u64,           // 다음 예상 시퀀스 번호 (재생 방지)
    pub seq_window: u64,        // 슬라이딩 윈도우 (비트마스크)
    pub expires_at: u64,        // 나노초 타임스탬프
    pub created_at: u64,        // 나노초 타임스탬프
    pub key_rotation_count: u32, // 키 교체 횟수
    pub flags: u16,             // [RSV|RSV|...|ACTIVE|VALID]
}
```

**사용자 공간 구조체**:
```rust
#[derive(Debug, Clone)]
pub struct VpnSession {
    pub peer_ip: IpAddr,
    pub tunnel_id: u32,
    pub key_material: SessionKeyMaterial,
    pub handshake_state: HandshakeState,
    pub stats: SessionStats,
}

#[derive(Debug, Clone)]
pub struct SessionKeyMaterial {
    pub symmetric_key: [u8; 32],
    pub seq_num: AtomicU64,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub rotation_interval: Duration,  // 기본값: 3600초
}

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    Init,
    HandshakeInProgress { started_at: SystemTime },
    Established { since: SystemTime },
    Expired,
    Error { reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub packets_encrypted: u64,
    pub packets_decrypted: u64,
    pub replay_detected: u64,
    pub auth_failures: u64,
    pub last_activity: SystemTime,
}
```

**검증 규칙**:
- `key`는 암호학적으로 안전한 난수여야 함 (getrandom syscall)
- `expires_at`는 `created_at` + 최소 60초여야 함
- `seq_num`은 단조 증가해야 함 (롤오버는 키 교체 트리거)
- `seq_window`는 재생 공격 방지에 사용 (64패킷 윈도우)
- `tunnel_id`는 충돌하지 않아야 함 (랜덤 32비트 또는 설정 기반)

**상태 전이**:
```
[Init] → 핸드셰이크 시작
    ↓
[HandshakeInProgress] → Noise 프로토콜 교환
    ↓
[Established] → 키가 eBPF 맵에 로드됨
    ↓
[만료] → TTL 또는 키 교체
    ↓
[제거] → 맵에서 삭제, 새 핸드셰이크 트리거
```

**보안 제약**:
- 키는 사용자 공간 메모리에서 평문으로 저장되지 않음 (`zeroize` 크레이트)
- 만료된 키는 즉시 맵에서 제거
- 재생 윈도우 외부의 패킷은 드롭

---

### 4. 정책 위반 이벤트 (Policy Violation Event)

**목적**: 감사 추적을 위한 RBAC 위반 기록

**eBPF 맵 정의**:
```rust
// BPF_MAP_TYPE_RINGBUF (크기: 256KB)
#[repr(C)]
pub struct PolicyViolationEvent {
    pub timestamp_ns: u64,     // bpf_ktime_get_ns()
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub role_id: u32,
    pub rule_id: u32,          // 일치한 규칙 (0 = 규칙 없음)
    pub action: AclAction,     // ALLOW(0) 또는 DENY(1)
    pub hook: HookPoint,       // XDP(0), TC_INGRESS(1), TC_EGRESS(2)
    pub flags: u8,             // [RSV|RSV|RSV|RSV|RSV|MULTI_ROLE|CACHED_POLICY|DECRYPTED]
}

#[repr(u8)]
pub enum HookPoint {
    Xdp = 0,
    TcIngress = 1,
    TcEgress = 2,
}
```

**사용자 공간 구조체**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: Protocol,
    pub role_id: RoleId,
    pub role_name: String,
    pub rule_id: Option<u32>,
    pub action: AclAction,
    pub hook_point: HookPoint,
    pub metadata: AuditMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    PolicyViolation,
    PolicyAllow,
    NoRoleFound,
    MapLookupError,
    DecryptionFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub decrypted: bool,
    pub cached_policy: bool,
    pub multi_role: bool,
    pub latency_us: Option<u64>,
}
```

**검증 규칙**:
- `timestamp_ns`는 단조 증가해야 함
- `role_id` = 0은 "역할 없음"을 나타냄
- `rule_id` = 0은 "기본 거부"를 나타냄
- 속도 제한: 초당 역할당 최대 1000 이벤트 (DoS 방지)

**처리 플로우**:
```
[eBPF] 위반 감지
    ↓
  ringbuffer에 이벤트 기록
    ↓
[Userspace] ringbuf__poll()으로 소비
    ↓
  JSON으로 포맷
    ↓
  syslog/파일/Elasticsearch로 전송
```

**크기 제약**:
- 링버퍼 크기: 256KB
- 오버플로우 시 가장 오래된 이벤트 덮어쓰기
- 사용자 공간은 100ms마다 폴링

---

### 5. 패킷 통계 (Packet Statistics)

**목적**: 성능 메트릭 및 관찰성

**eBPF 맵 정의**:
```rust
// BPF_MAP_TYPE_PERCPU_ARRAY (CPU별 경합 방지)
#[repr(C)]
pub struct PacketStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub policy_hits: u64,
    pub policy_misses: u64,
    pub decrypt_success: u64,
    pub decrypt_failure: u64,
    pub latency_sum_ns: u64,    // 지연시간 히스토그램용
    pub latency_count: u64,
}

// 배열 인덱스
pub const STATS_XDP_INGRESS: u32 = 0;
pub const STATS_TC_VPN_INGRESS: u32 = 1;
pub const STATS_TC_EGRESS: u32 = 2;
```

**사용자 공간 구조체**:
```rust
#[derive(Debug, Clone, Default, Serialize)]
pub struct AggregatedStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub policy_hits: u64,
    pub policy_misses: u64,
    pub decrypt_success: u64,
    pub decrypt_failure: u64,
    pub avg_latency_us: f64,
    pub p50_latency_us: f64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
    pub per_cpu_stats: Vec<PerCpuStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerCpuStats {
    pub cpu_id: u32,
    pub packets: u64,
    pub utilization_pct: f64,
}
```

**집계 방법**:
- 사용자 공간은 모든 CPU 통계 합산
- 히스토그램은 HdrHistogram 크레이트로 계산
- Prometheus 메트릭으로 내보내기 (5초 간격)

---

### 6. XDP 프로그램 (XDP Program)

**목적**: 네트워크 인터페이스 레벨에서 패킷 처리

**메타데이터**:
```rust
#[derive(Debug, Clone)]
pub struct XdpProgramMetadata {
    pub id: u32,                // 커널 할당 프로그램 ID
    pub name: String,           // "vpn_xdp_filter"
    pub interface: String,      // "eth0"
    pub attach_mode: XdpMode,   // Native | Offload | Generic
    pub loaded_at: SystemTime,
    pub instructions: u32,      // 명령어 수
    pub verified: bool,
    pub stats: XdpProgramStats,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XdpMode {
    Native,    // 드라이버 레벨 (가장 빠름)
    Offload,   // NIC 하드웨어 (사용 가능한 경우)
    Generic,   // 커널 네트워크 스택 (폴백)
}

#[derive(Debug, Clone, Default)]
pub struct XdpProgramStats {
    pub run_time_ns: u64,
    pub run_cnt: u64,
}
```

**검증 규칙**:
- 인터페이스가 존재하고 UP 상태여야 함
- Native 모드는 드라이버 지원 필요 (`ethtool -i` 확인)
- 프로그램은 verifier 검사 통과해야 함

---

### 7. TC 프로그램 (TC Program)

**목적**: VPN 인터페이스에서 트래픽 제어

**메타데이터**:
```rust
#[derive(Debug, Clone)]
pub struct TcProgramMetadata {
    pub id: u32,
    pub name: String,           // "vpn_tc_rbac"
    pub interface: String,      // "wg0" 또는 "tun0"
    pub direction: TcDirection,
    pub priority: u32,          // tc 필터 우선순위
    pub handle: u32,            // tc 핸들
    pub loaded_at: SystemTime,
    pub instructions: u32,
    pub verified: bool,
    pub stats: TcProgramStats,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TcDirection {
    Ingress,   // 복호화된 트래픽 RBAC
    Egress,    // 암호화 전 라우팅
}

#[derive(Debug, Clone, Default)]
pub struct TcProgramStats {
    pub run_time_ns: u64,
    pub run_cnt: u64,
}
```

---

### 8. 네트워크 존 (Network Zone)

**목적**: 네트워크 세그먼트 분류 (내부/VPN/외부)

**eBPF 맵 정의**:
```rust
// BPF_MAP_TYPE_LPM_TRIE
#[repr(C)]
pub struct ZoneKey {
    pub prefixlen: u32,
    pub network: u32,
}

#[repr(C)]
pub struct ZoneValue {
    pub zone_type: ZoneType,
    pub zone_id: u32,
}

#[repr(u8)]
pub enum ZoneType {
    Internal = 0,   // 10.0.0.0/8
    Vpn = 1,        // 172.16.0.0/12
    External = 2,   // 기본값
}
```

**사용자 공간 구조체**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkZone {
    pub zone_id: u32,
    pub zone_name: String,
    pub zone_type: ZoneType,
    pub networks: Vec<IpNetwork>,
    pub default_policy: AclAction,
}
```

**검증 규칙**:
- 존은 겹치지 않아야 함 (가장 구체적인 매치 우선)
- `zone_id`는 고유해야 함
- `zone_type`는 라우팅 결정에 사용 (FR-017)

---

## 관계 다이어그램

```
┌──────────────┐
│  IDP 토큰    │
│  (외부)      │
└──────┬───────┘
       │ 파싱
       ↓
┌──────────────┐
│ IP-역할 매핑  │──────────┐
│ (LPM Trie)   │          │
└──────┬───────┘          │
       │ 조회             │ 참조
       ↓                  ↓
┌──────────────┐    ┌──────────────┐
│ 패킷 도착    │    │ 역할-ACL 맵   │
│ (XDP/TC)     │───→│ (Hashmap)    │
└──────┬───────┘    └──────────────┘
       │                  │
       │ 매치             │ 평가
       ↓                  ↓
┌──────────────┐    ┌──────────────┐
│ ALLOW/DENY   │───→│ 감사 이벤트   │
│ 결정         │    │ (Ringbuffer) │
└──────────────┘    └──────────────┘
                          │
                          │ 소비
                          ↓
                    ┌──────────────┐
                    │ 로그 파일    │
                    │ (syslog)     │
                    └──────────────┘
```

---

## 데이터 플로우

### 인그레스 플로우 (외부 → VPN → 내부)

```
1. 패킷 도착 (외부 인터페이스)
    ↓
2. XDP: 기본 검증 (magic, 터널 ID)
    - 세션 키 맵 조회
    - 유효하지 않은 경우 → XDP_DROP
    ↓
3. 네트워크 스택: VPN 복호화
    - bpf_crypto_decrypt()
    - 인증 태그 확인
    ↓
4. TC (VPN 인터페이스): RBAC 검사
    - IP-역할 맵 조회 (소스 IP)
    - 역할-ACL 맵 조회
    - 규칙 반복 및 평가
    ↓
5. 결정:
    - ALLOW → TC_ACT_OK (포워딩)
    - DENY → TC_ACT_SHOT + 감사 로그
```

### 이그레스 플로우 (내부 → VPN → 외부)

```
1. 패킷 도착 (내부 인터페이스)
    ↓
2. TC: 라우팅 결정
    - 목적지 IP → 네트워크 존 조회
    - VPN 터널 선택
    ↓
3. TC: VPN 캡슐화
    - 세션 키 맵 조회
    - VPN 헤더 추가 (시퀀스 번호 증가)
    - bpf_crypto_encrypt()
    ↓
4. XDP: 외부 인터페이스로 전송
    - XDP_TX (리다이렉트)
```

---

## 데이터 일관성 보장

### 원자적 업데이트

**문제**: 다중 맵 업데이트는 원자적이지 않음 (IP-역할 + 역할-ACL)

**해결책**: 버전 스탬프 + 2단계 커밋
```rust
// 1단계: 새 역할-ACL 맵 생성 및 채우기
let new_acl_map = create_and_populate_acl_map(new_rules)?;

// 2단계: IP-역할 맵을 새 ACL 맵을 가리키도록 원자적 업데이트
let version = fetch_add_version();
update_ip_role_map_with_version(new_mappings, version)?;
swap_acl_map_fd(new_acl_map)?;
```

### 캐시 정책 일관성 (IDP 장애)

**문제**: IDP 다운 시 오래된 정책 사용 가능 (명확화 Q3)

**해결책**: TTL + 우아한 성능 저하
```rust
// eBPF: 만료된 항목 확인
if (now > mapping->expires_at && mapping->expires_at != 0) {
    // 오래되었지만 여전히 사용 (페일세이프)
    audit_log(EVENT_STALE_POLICY);
}

// Userspace: IDP 복구 시 즉시 새로 고침
on_idp_reconnect(|| {
    refresh_all_policies_from_idp()?;
});
```

---

## 크기 및 성능 제약

| 엔티티 | 최대 크기 | 조회 복잡도 | 업데이트 빈도 |
|--------|-----------|-------------|---------------|
| IP-역할 맵 | 10,000 항목 | O(log n) | IDP 토큰 갱신 (5분) |
| 역할-ACL 맵 | 100 역할 × 32 규칙 | O(1) + O(n) 규칙 | 정책 변경 (드물게) |
| 세션 키 맵 | 10 동시 VPN 피어 | O(1) | 키 교체 (1시간) |
| 감사 링버퍼 | 256KB | N/A | 지속적 (초당 1000 이벤트) |
| 패킷 통계 | CPU당 64B × CPU | O(1) | 매 패킷 |

---

## 데이터 지속성

**eBPF 맵 피닝**:
- 경로: `/sys/fs/bpf/vpn/`
- 맵: `ip_role_map`, `role_acl_map`, `session_key_map`
- 이점: 데몬 재시작 시 맵 유지, 데이터 플레인 중단 없음

**사용자 공간 백업**:
- 정책 설정: `/etc/vpn/policies.yaml`
- 세션 상태: 메모리 전용 (재연결 시 재협상)
- 감사 로그: `/var/log/vpn/audit.log` (로테이션됨)

---

## 확장성 고려사항

**맵 확장** (명확화 Q4):
```rust
async fn monitor_and_expand_maps(daemon: &Daemon) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        if daemon.ip_role_map.usage_percent()? > 80.0 {
            warn!("IP-역할 맵 사용률 > 80%, 확장 중...");
            expand_map(&daemon.ip_role_map, 2.0).await?;
        }

        if daemon.role_acl_map.usage_percent()? > 80.0 {
            warn!("역할-ACL 맵 사용률 > 80%, 확장 중...");
            expand_map(&daemon.role_acl_map, 2.0).await?;
        }
    }
}
```

---

## 참조

- **스펙 파일**: Key Entities 섹션
- **헌장**: 데이터 플레인/제어 플레인 분리 원칙
- **Research**: 맵 설계 및 원자적 업데이트 전략

---

**상태**: 데이터 모델 정의 완료. 다음: API 계약 생성 (Phase 1 계속).
