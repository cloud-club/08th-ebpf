# 연구: IDP/RBAC Site-to-Site VPN 라우터

**피처 브랜치**: `001-idp-identity-provider`
**연구 날짜**: 2025-10-07
**상태**: 완료

## 요약

이 문서는 IDP 통합 및 RBAC 강제를 포함한 eBPF 기반 Site-to-Site VPN 라우터 구현을 위한 모든 기술적 결정사항, 고려된 대안, 근거를 기록합니다. 시스템은 이중 플레인 아키텍처를 사용합니다: eBPF 프로그램(XDP/TC)은 커널 공간에서 데이터 플레인 작업을 처리하고, Rust 사용자 공간 데몬이 제어 플레인을 관리합니다.

## 핵심 아키텍처 결정

### 결정 1: 이중 플레인 eBPF 아키텍처

**결정**: 데이터 플레인(eBPF 커널 프로그램)과 제어 플레인(Rust 사용자 공간 데몬) 간 엄격한 분리 구현

**근거**:
- **성능**: 커널 공간 패킷 처리는 컨텍스트 스위치를 제거하여 10μs 이하 지연시간(p99) 달성
- **격리**: 제어 플레인 크래시가 패킷 포워딩에 영향을 주지 않음; 손상된 데몬이 패킷을 직접 조작할 수 없음
- **확장성**: eBPF 프로그램은 사용자 공간 개입 없이 초당 수백만 패킷 처리 가능

**아키텍처**:
```
┌─────────────────────────────────────────────────────────────┐
│                    데이터 플레인 (커널)                       │
├─────────────────────────────────────────────────────────────┤
│  XDP 프로그램 (인그레스)         TC 프로그램 (이그레스/VPN)   │
│  - 고속 경로 포워딩              - 복호화 후 RBAC 검사        │
│  - 조기 드롭                     - 정책 강제                 │
│  - 패킷 분류                     - 감사 로깅 트리거           │
└──────────────────┬──────────────────────────┬───────────────┘
                   │      eBPF 맵              │
                   │  (통신 브릿지)            │
┌──────────────────┴──────────────────────────┴───────────────┐
│                 제어 플레인 (사용자 공간)                     │
├─────────────────────────────────────────────────────────────┤
│  Rust 데몬                                                   │
│  - IDP 통합 (OIDC/SAML)                                     │
│  - 정책 컴파일 (IP→역할, 역할→ACL)                          │
│  - 맵 관리 (원자적 업데이트)                                │
│  - 원격 측정 집계 (ringbuffer 소비자)                       │
│  - VPN 터널 키 교환                                         │
└─────────────────────────────────────────────────────────────┘
```

**고려된 대안**:
- **사용자 공간 패킷 처리 (DPDK)**: 높은 CPU 격리 요구사항과 복잡성으로 인해 거부
- **Linux netfilter (iptables/nftables)**: 높은 지연시간과 제한된 프로그래밍 가능성으로 거부
- **XDP 단일 설계**: TC 인그레스 이후에만 사용 가능한 내부 패킷 헤더에 접근이 필요한 복호화 후 RBAC 때문에 거부

**참조**:
- 헌장 원칙 I: 커널 우선 아키텍처
- 헌장 원칙 VI: 엄격한 플레인 분리

---

### 결정 2: 이중 훅 전략 (XDP + TC)

**결정**: 외부 인터페이스에 XDP 프로그램을, VPN 인터페이스에 TC 프로그램을 배포

**근거**:
- **XDP (외부 인터페이스)**:
  - NIC 드라이버 레벨에서 동작 (가장 빠른 훅 지점)
  - 고속 포워딩 결정에 이상적 (10μs p99 목표)
  - 비용이 많이 드는 처리 전에 악의적 패킷 드롭 가능
  - 액션: `XDP_DROP`, `XDP_PASS`, `XDP_TX` (리다이렉트)

- **TC (VPN 인터페이스)**:
  - L3 복호화 이후 동작 (내부 IP 헤더 접근 가능)
  - 복호화된 트래픽에 대한 RBAC 강제 가능
  - 세부 정책 매칭을 위한 전체 패킷 컨텍스트 접근 가능
  - 액션: `TC_ACT_OK` (통과), `TC_ACT_SHOT` (드롭)

**패킷 플로우**:
```
외부 패킷 → NIC → XDP 프로그램 → 네트워크 스택 → VPN 복호화
                      ↓
                  (고속 드롭)

복호화된 패킷 → TC 프로그램 → RBAC 검사 → 포워드/드롭 → 이그레스
                    ↓
              (정책 강제)
```

**사용자 입력 통합**: "이중 훅 전략: 외부 인터페이스에는 고속 포워딩 및 초기 드롭을 위한 XDP 프로그램을 사용하고, VPN 인터페이스에는 복호화된 트래픽에 대한 세부 RBAC 정책 시행을 위한 TC 프로그램을 사용"

**고려된 대안**:
- **XDP 전용 설계**: 복호화된 내부 헤더 검사 불가
- **TC 전용 설계**: 드라이버 레벨 조기 드롭 최적화 놓침
- **VPN 인터페이스의 XDP**: 복호화가 네트워크 스택에서 발생하여 XDP에 보이지 않음

---

### 결정 3: 사용자 공간 제어 플레인을 위한 Rust

**결정**: 모든 사용자 공간 컴포넌트(데몬, 정책 컴파일러, IDP 클라이언트, 원격 측정)를 `libbpf-rs` 또는 `aya`를 사용하여 Rust로 구현

**근거**:
- **메모리 안전성**: 전체 클래스의 CVE 제거 (버퍼 오버플로우, use-after-free, double-free)
- **제로 비용 추상화**: 안전성 손상 없이 C와 동등한 성능
- **생태계**:
  - `aya`: 순수 Rust eBPF 라이브러리 (C 의존성 없음)
  - `libbpf-rs`: libbpf에 대한 안전한 Rust 바인딩 (검증된 안정성)
  - 풍부한 비동기 생태계 (Tokio) - IDP HTTP 클라이언트용
  - 강력한 파서 콤비네이터 라이브러리 (nom, pest) - 정책 DSL용

**Unsafe 정책**:
- `unsafe` 블록은 다음에만 허용:
  - 커널과의 FFI 경계 (시스템콜, ioctl)
  - 문서화된 불변성이 있는 성능 중요 섹션
- 모든 `unsafe` 사용은 다음 필요:
  - 불변성을 설명하는 인라인 안전 주석
  - 두 번째 엔지니어의 코드 리뷰
  - 입력 검증을 위한 퍼즈 테스팅

**사용자 입력 통합**: "시스템은 eBPF 커널 프로그램과 사용자 공간 제어 플레인 데몬 모두에 Rust를 사용해야 합니다"

**고려된 대안**:
- **libbpf를 사용한 C**: 복잡한 정책 컴파일러에서 메모리 버그 위험 높음
- **Go**: 더 큰 바이너리 크기, GC 중단이 저지연 요구사항과 양립 불가
- **Python**: 핫 패스 사용자 공간 작업(맵 업데이트)에 너무 느림

**라이브러리 선택**: `libbpf-rs`보다 `aya` 권장:
- C 툴체인 의존성 없음 (크로스 컴파일 용이)
- 더 나은 Rust 인체공학 (맵을 위한 derive 매크로)
- 최신 eBPF 기능을 위한 활발한 개발

**참조**:
- 헌장 원칙 II: 메모리 안전성 (Rust 사용자 공간)

---

### 결정 4: 정책 저장을 위한 eBPF 맵 설계

**결정**: 정책 배포를 위해 원자적 업데이트가 가능한 여러 BPF 맵 사용

**맵 스키마**:

1. **IP-역할 맵** (BPF_MAP_TYPE_LPM_TRIE):
   ```rust
   Key: struct { u32 prefixlen; u32 ip; }  // CIDR 지원
   Value: u32 role_id
   ```
   - CIDR 범위 지원 (예: 10.0.0.0/8 → role_admin)
   - O(log n) 조회 복잡도
   - 최대 항목: 10,000 (SC-009 기준)

2. **역할-ACL 맵** (BPF_MAP_TYPE_HASH):
   ```rust
   Key: u32 role_id
   Value: struct AclRuleSet {
       u32 num_rules;
       struct AclRule rules[MAX_RULES_PER_ROLE]; // 인라인 배열
   }
   ```
   - 역할 해석 후 O(1) 조회
   - 각 ACL 규칙: { src_net, dst_net, proto, port, action }

3. **세션 키 맵** (BPF_MAP_TYPE_HASH):
   ```rust
   Key: struct { u32 peer_ip; u32 tunnel_id; }
   Value: struct CryptoContext {
       u8 key[32];     // 사용자 공간의 대칭키
       u64 seq_num;    // 재생 공격 방지
       u64 expires_at; // 나노초 타임스탬프
   }
   ```

4. **감사 링버퍼** (BPF_MAP_TYPE_RINGBUF):
   - 사용자 공간이 이벤트를 비동기로 소비
   - 형식: `{ timestamp, src_ip, dst_ip, role_id, rule_id, action }`
   - 크기: 256KB (버스트 시 손실 방지)

**원자적 업데이트 전략**:
- **맵 스와핑**: 새 맵 생성, 채우기, `bpf_map_update_elem`으로 포인터 원자적 스왑
- **버전 업데이트**: 값 구조체에 `u64 version` 포함, eBPF가 신선도 확인
- **피닝**: 맵을 `/sys/fs/bpf/vpn/`에 피닝하여 데몬 재시작 시에도 유지

**사용자 입력 통합**: "사용자 공간 데몬은 Source IP → Role ID및 Role ID → ACL 규칙 세트 매핑을 저장하기 위해 BPF 맵(LPM Trie)을 관리해야 하며, 이 맵을 원자적(Atomic)으로 업데이트해야 합니다"

**고려된 대안**:
- **단일 플랫 맵 (IP→ACL)**: 항목 폭증(IP × 규칙)으로 거부
- **사용자 공간 조회**: 지연시간 요구사항 위반 (>50μs 컨텍스트 스위치)
- **Per-CPU 맵**: 읽기 중심 정책 조회에 과도함

**참조**:
- 헌장 원칙 V: 저지연 성능

---

### 결정 5: 커스텀 VPN 프로토콜 설계

**결정**: WireGuard/IPsec 대신 eBPF 암호화 프리미티브를 사용한 커스텀 경량 VPN 프로토콜 구현

**근거**:
- **학습 목표**: eBPF 패킷 조작, 캡슐화, 암호화 API에 대한 깊은 이해 가능
- **최적화 가능성**: 범용 WireGuard 대비 정확한 사용 사례에 맞게 프로토콜 오버헤드 조정 가능
- **제어**: 핸드셰이크, 재생 방지, 키 교체 로직에 대한 완전한 가시성

**프로토콜 설계**:

**터널 헤더** (최소 오버헤드):
```c
struct vpn_header {
    u32 magic;       // 0xVPN0001 (버전 + 식별)
    u32 tunnel_id;   // 세션 식별자
    u64 seq_num;     // 재생 방지 카운터
    u16 inner_len;   // 페이로드 길이
    u8  flags;       // [RSV|RSV|RSV|RSV|RSV|FRG|ACK|SYN]
    u8  reserved;
    u8  auth_tag[16]; // AEAD 인증 태그
} __attribute__((packed));  // 총: 32 바이트
```

**패킷 처리**:

**캡슐화 (이그레스 TC)**:
```
[원본 IP 패킷]
    → eBPF가 맵에서 세션 키 읽기
    → bpf_skb_store_bytes()로 VPN 헤더 앞에 추가
    → bpf_crypto_encrypt() (커널 crypto API 사용)
    → [외부 IP][VPN 헤더][암호화된 페이로드][인증 태그]
```

**디캡슐화 (인그레스 XDP → TC)**:
```
[외부 IP][VPN 헤더][암호화된 페이로드][인증 태그]
    → XDP: 기본 검증 (magic, tunnel_id 조회)
    → 네트워크 스택으로 전달
    → TC: bpf_crypto_decrypt(), 인증 태그 확인
    → VPN 헤더 제거
    → [원본 IP 패킷] → RBAC 검사
```

**암호화 알고리즘**: ChaCha20-Poly1305
- eBPF 호환성을 위해 선택 (bpf_crypto_* 헬퍼 지원)
- AES-NI 없는 CPU에서 AES보다 빠름
- 인증된 암호화 (무결성 + 기밀성)

**키 교환** (사용자 공간):
- 단순화된 Noise 프로토콜 (XX 패턴)
- 사용자 공간 데몬이 Diffie-Hellman 수행
- 협상된 키를 세션 키 맵에 로드
- 3600초마다 키 교체

**보안 고려사항**:
- **재생 방지**: 단조 증가 시퀀스 번호, 64비트 윈도우
- **Forward Secrecy**: 주기적 키 재협상
- **서비스 거부**: XDP에서 속도 제한 (잘못된 패킷 조기 드롭)

**사용자 입력 통합**: 명확화 Q5 (커스텀 VPN 프로토콜 구현) 및 FR-019 요구사항 반영

**고려된 대안**:
- **WireGuard 커널 모듈**: 교육적 가치 낮음, 블랙박스 접근
- **IPsec**: 복잡한 상태 머신, 높은 오버헤드
- **사용자 공간 암호화 (OpenSSL)**: 커널 우선 원칙 위반, 지연시간 페널티

**위험**:
- **구현 복잡성**: 암호화 프로토콜은 어려움; 광범위한 테스팅 필요
- **보안 감사**: 프로덕션 사용 전 커스텀 암호화 코드는 전문가 리뷰 필요
- **제한된 eBPF 암호화**: 일부 알고리즘은 헬퍼 지원 없을 수 있음 (키 교환만 사용자 공간으로 폴백)

**완화**:
- 단계별 구현: 사용자 공간 암호화로 시작, 점진적으로 eBPF로 마이그레이션
- 광범위한 퍼즈 테스팅 (AFL, libFuzzer)
- 핸드셰이크 정확성을 위해 Noise 프로토콜 사양 참조

**참조**:
- FR-019, FR-019-1, FR-019-2, FR-019-3
- 명확화 세션 2025-10-07: 커스텀 VPN 프로토콜 선택

---

### 결정 6: CO-RE (Compile Once – Run Everywhere)

**결정**: 모든 eBPF 프로그램은 커널 이식성을 위해 BTF와 CO-RE 재배치 사용 필수

**근거**:
- **대상 환경**: 이기종 커널에 걸친 배포 (클라우드 VM, 온프레미스 서버, 엣지 디바이스)
- **운영 단순성**: 단일 바이너리 배포로 타겟별 컴파일 제거
- **유지보수**: 커널 버전별 코드 분기 방지

**구현**:
- **BTF 요구사항**: 최소 Linux 5.10 LTS (BTF 지원)
- **툴체인**: Clang with `-g -O2 -target bpf -D__TARGET_ARCH_x86_64`
- **라이브러리**: 자동 CO-RE 재배치 처리를 위한 `libbpf` 또는 `aya`
- **헬퍼**: 직접 구조체 멤버 접근 대신 `bpf_core_read()` 사용

**테스팅 매트릭스**:
| 커널 버전 | 배포판 | 테스트 환경 |
|-----------|--------|-------------|
| 5.10 LTS | Debian 11 | CI VM (qemu) |
| 5.15 LTS | Ubuntu 22.04 | CI VM (qemu) |
| 6.1 LTS | Debian 12 | CI VM (qemu) |

**우아한 성능 저하**: BTF를 사용할 수 없는 경우, 데몬이 오류 발생: "커널에 BTF 지원이 없습니다. Linux 5.10+ 이상으로 업그레이드하거나 커널 헤더로 재컴파일하세요."

**참조**:
- 헌장 원칙 III: CO-RE 이식성
- SC-012: 3개 이상 커널 버전 호환성 요구사항

---

### 결정 7: Verifier 준수 전략

**결정**: 해킹 없이 verifier를 통과하도록 eBPF 프로그램 설계; 복잡도 관리를 위해 tail call 사용

**제약사항**:
- **명령어 제한**: 프로그램 경로당 1M 명령어 (Linux 5.13+)
- **스택 제한**: 프로그램당 512 바이트
- **루프 경계**: 명시적이거나 증명 가능한 종료

**복잡도 관리**:

**Tail Call 아키텍처** (필요 시):
```
[XDP 진입점]
    ↓
  기본 검증 (magic 검사, 길이 검사)
    ↓
  bpf_tail_call(prog_array, STAGE_ACL_EVAL)
    ↓
[ACL 평가 프로그램]
    ↓
  규칙 반복 (제한된 루프: MAX_RULES_PER_ROLE=32)
    ↓
  bpf_tail_call(prog_array, STAGE_FORWARD)
    ↓
[포워딩 프로그램]
```

**제한된 반복**:
```c
#define MAX_ACL_RULES 32  // 컴파일 타임 상수

#pragma unroll
for (int i = 0; i < MAX_ACL_RULES; i++) {
    if (i >= acl->num_rules) break;
    // 규칙 평가
}
```

**Verifier 디버깅**:
- CI 아티팩트에 실패한 로드의 verifier 로그 저장: `bpftool prog load <obj> 2>&1 | tee verifier.log`
- 커널 내 디버깅을 위해 `bpf_printk()` 사용 (3개 인자 제한)
- `bpf_trace_printk` 출력은 `/sys/kernel/debug/tracing/trace_pipe`에서 확인

**참조**:
- 헌장 원칙 IV: Verifier 준수

---

### 결정 8: IDP 통합 아키텍처

**결정**: 사용자 공간 데몬이 IDP(OIDC/SAML)와 통합하고 신원을 IP→역할 매핑으로 변환

**통합 플로우**:
```
[사용자 인증]
    → IDP (OIDC/SAML)
    → 데몬이 토큰 수신 (JWT/SAML assertion)
    → 클레임 추출: { user_id, roles[], ip_address }
    → IP→역할 매핑 컴파일
    → eBPF 맵 업데이트 (원자적 스왑)
    → (선택적) 만료를 위한 TTL 설정
```

**토큰 처리**:
- **자동 갱신**: 데몬이 토큰 만료 모니터링 (명확화 Q1)
- **갱신 윈도우**: 만료 5분 전 갱신
- **실패 모드**: IDP 접근 불가 시, 캐시된 정책 사용 (명확화 Q3)

**OIDC 구현** (Rust):
```rust
use openidconnect::{
    core::CoreClient, IssuerUrl, ClientId, ClientSecret,
    AuthenticationFlow, OAuth2TokenResponse,
};

// 주기적 작업 (Tokio interval)
tokio::spawn(async {
    loop {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let token = refresh_token(&client, &refresh_token).await?;
        let ip_role_map = extract_claims(&token)?;
        ebpf_map_update(ip_role_map).await?;
    }
});
```

**다중 역할 처리** (명확화 Q2):
- **정책**: 명시적 DENY가 우선; 그 외 ALLOW 합집합
- **구현**: eBPF가 사용자의 모든 역할 반복, 첫 DENY가 승리

**참조**:
- FR-022, FR-023, FR-023-1, FR-025
- 명확화 Q1, Q2, Q3

---

### 결정 9: 관찰성 및 원격 측정

**결정**: 비동기 감사 로깅을 위해 BPF ringbuffer 사용; 메트릭 내보내기를 위해 Prometheus 사용

**감사 로깅**:
- **메커니즘**: `BPF_MAP_TYPE_RINGBUF` (perf events보다 우수: 낮은 오버헤드, 간단한 API)
- **이벤트 구조**:
  ```rust
  struct PolicyViolation {
      u64 timestamp_ns;
      u32 src_ip;
      u32 dst_ip;
      u16 src_port;
      u16 dst_port;
      u8  protocol;
      u32 role_id;
      u32 rule_id;
      u8  action;  // ALLOW(0), DENY(1)
  }
  ```
- **사용자 공간 소비자**: 데몬이 `ringbuf__poll()`을 통해 이벤트 읽기, JSON으로 포맷, syslog에 기록

**메트릭** (Prometheus 형식):
```
vpn_packets_total{direction="ingress",action="pass"} 1234567
vpn_packets_total{direction="ingress",action="drop"} 890
vpn_policy_violations_total{role="admin"} 12
vpn_latency_microseconds{quantile="0.5"} 8
vpn_latency_microseconds{quantile="0.99"} 15
```

**지연시간 측정**:
- eBPF: 패킷 도착과 결정 시 `bpf_ktime_get_ns()`
- per-CPU 맵에 히스토그램 저장 (경합 방지)
- 사용자 공간이 Prometheus summary로 집계

**사용자 입력 통합**: "정책 위반 로깅은 감사 데이터를 사용자 공간 로거로 비동기적으로 전송하기 위해 BPF 링 버퍼 메커니즘을 활용해야 합니다"

**참조**:
- FR-009, FR-010, FR-011
- 헌장: 관찰성 섹션

---

### 결정 10: 맵 크기 조정 및 동적 확장

**결정**: 용량 도달 시 동적 맵 확장 구현 (명확화 Q4)

**전략**:
- **초기 크기**: 1,000 항목 (IP-역할), 100 ACL 규칙셋
- **증가 트리거**: 사용률 > 80% 시
- **확장**: 새 맵 생성 (2× 용량), 항목 복사, 원자적 스왑
- **커널 제한**: `ulimit -l` (잠긴 메모리) 및 `bpf_stats` 예산 준수

**구현**:
```rust
async fn expand_map_if_needed(map: &LpmTrieMap) -> Result<()> {
    let usage = map.get_usage_percent()?;
    if usage > 80.0 {
        let new_capacity = map.capacity() * 2;
        let new_map = LpmTrieMap::create(new_capacity)?;

        // 기존 항목 복사
        for (k, v) in map.iter() {
            new_map.insert(k, v)?;
        }

        // 원자적 스왑 (프로그램이 새 맵 FD 사용하도록 업데이트)
        prog.update_map_fd("ip_role_map", new_map.fd())?;

        log::info!("맵 확장: {} → {} 항목",
            map.capacity(), new_capacity);
    }
    Ok(())
}
```

**제약사항**:
- 최대 맵 크기는 커널 메모리로 제한
- 확장은 짧은(<1ms) 업데이트 지연시간 유발 (핫 패스 아님)

**참조**:
- 명확화 Q4
- 엣지 케이스: 맵 크기 초과

---

## 성능 목표

| 메트릭 | 목표 | 측정 방법 |
|--------|------|-----------|
| 고속 경로 지연시간 (p99) | 10 μs | XDP에서 `bpf_ktime_get_ns()` |
| 정책 중심 지연시간 (p99) | 50 μs | 전체 RBAC가 있는 TC 프로그램 |
| 처리량 | 1M pps @ 80% CPU | `iperf3` + `mpstat` |
| IDP 정책 동기화 | < 5초 | 종단간: IDP 변경 → eBPF 맵 |
| 맵 업데이트 지연시간 | < 1 ms | 생성/스왑 사이 시간 |

**참조**:
- SC-005, SC-006, SC-007, SC-008
- 헌장 원칙 V: 저지연 성능

---

## 테스팅 전략

### 단위 테스트 (Rust)
- 모의 eBPF 맵 작업
- 정책 컴파일러 로직 (YAML → 맵 항목)
- IDP 토큰 파서 (유효/무효/만료 토큰)

### 통합 테스트 (커널)
- 테스트 네트워크 네임스페이스에 eBPF 프로그램 로드
- `ip netns exec`를 통해 패킷 주입, XDP/TC 액션 검증
- 맵 조회가 예상 값 반환하는지 검증

### 성능 테스트
- `tc-bpf-bench`: XDP/TC 지연시간 마이크로벤치마크
- `iperf3`: 부하 시 종단간 처리량
- `perf`: 핫스팟 프로파일링 (eBPF + 사용자 공간)

### 커널 호환성
- CI 매트릭스: 5.10 LTS, 5.15 LTS, 6.1 LTS
- BTF 존재 검증: `bpftool btf dump file /sys/kernel/btf/vmlinux`
- 모든 대상에서 CO-RE 재배치 성공 테스트

### 보안 테스트
- 정책 파서 퍼즈 (AFL++): `cargo afl fuzz -i in -o out target/release/policy_parser`
- Verifier 스트레스: 최대 복잡도 프로그램 로드
- 재생 공격 시뮬레이션: 오래된 시퀀스 번호 재사용

**참조**:
- 헌장: 테스팅 게이트 섹션
- SC-001, SC-002, SC-003, SC-004

---

## 위험 및 완화

| 위험 | 영향 | 가능성 | 완화 |
|------|------|--------|------|
| 커스텀 VPN 암호화 버그 | 치명적 (데이터 유출) | 중간 | 광범위한 퍼징, 보안 감사, 점진적 롤아웃 |
| eBPF verifier가 복잡한 프로그램 거부 | 높음 (기능 불완전) | 낮음 | Tail call 아키텍처, 제한된 루프 |
| 대상 커널에서 BTF 사용 불가 | 중간 (배포 차단) | 낮음 | 최소 커널 버전 강제 (5.10+) |
| 맵 확장이 패킷 손실 유발 | 중간 (짧은 중단) | 낮음 | 낮은 트래픽 시간대 확장, 메트릭 모니터링 |
| IDP 토큰 갱신 실패 | 중간 (인증 다운타임) | 중간 | 마지막 알려진 정책 캐시 (명확화 Q3) |

---

## 의존성

### 빌드 타임
- **Rust**: 1.75+ (안정적인 aya 기능용)
- **Clang/LLVM**: 15+ (BTF를 사용한 eBPF 컴파일용)
- **libbpf** 또는 **aya**: eBPF 로더 라이브러리
- **Cargo 플러그인**: `cargo-bpf` (aya 사용 시)

### 런타임
- **Linux 커널**: 5.10 LTS 최소 (BTF 지원)
- **IDP 엔드포인트**: OIDC/SAML 2.0 호환 제공자
- **네트워크**: 전용 VPN 인터페이스 (예: wg0, ipsec0, 또는 커스텀 tun0)

### 테스팅
- **qemu**: 다중 커널 테스팅용
- **bpftool**: 내부 검사 및 디버깅
- **iperf3**: 성능 벤치마킹
- **AFL++**: 퍼즈 테스팅

---

## 미해결 질문 (없음)

모든 명확화가 명확화 세션 2025-10-07에서 해결됨:
- ✅ IDP 토큰 만료 정책 → 자동 갱신
- ✅ 다중 역할 권한 병합 → 명시적 DENY 우선 + 합집합
- ✅ IDP 장애 처리 → 캐시 기반 폴백
- ✅ 맵 크기 초과 → 동적 확장
- ✅ VPN 프로토콜 선택 → 커스텀 구현

---

## 참조

### eBPF 문서
- [eBPF.io - 소개](https://ebpf.io/what-is-ebpf/)
- [Linux 커널 BPF 문서](https://www.kernel.org/doc/html/latest/bpf/)
- [Cilium eBPF 가이드](https://docs.cilium.io/en/stable/bpf/)

### XDP/TC 프로그래밍
- [XDP 튜토리얼](https://github.com/xdp-project/xdp-tutorial)
- [BPF 및 XDP 참조 가이드](https://docs.cilium.io/en/stable/bpf/)

### Rust eBPF 라이브러리
- [aya 문서](https://aya-rs.dev/)
- [libbpf-rs GitHub](https://github.com/libbpf/libbpf-rs)

### VPN 및 암호화
- [Noise 프로토콜 프레임워크](http://noiseprotocol.org/)
- [ChaCha20-Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
- [WireGuard 백서](https://www.wireguard.com/papers/wireguard.pdf) (비교용)

### 보안
- [OWASP VPN 보안](https://owasp.org/www-community/vulnerabilities/VPN_Security)
- [Rust 보안 가이드](https://anssi-fr.github.io/rust-guide/)

---

**상태**: 연구 완료. Phase 1 (설계 및 계약) 준비 완료.
