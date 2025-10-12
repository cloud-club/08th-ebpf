# 태스크: IDP/RBAC Site-to-Site VPN 라우터

**피처 브랜치**: `001-idp-identity-provider`
**입력**: `/specs/001-idp-identity-provider/`의 설계 문서
**전제 조건**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**테스트**: 명세서에서 테스트를 명시적으로 요청하지 않았으므로 테스트 태스크는 생략. eBPF 구현 및 학습에 집중.

**구성**: 태스크는 사용자 스토리(US1-US6)별로 그룹화되어 각 eBPF 기능을 독립적으로 구현하고 테스트할 수 있도록 함.

## 형식: `[P] [Story] 설명`
- **[P]**: 병렬 실행 가능 (다른 파일, 의존성 없음)
- **[Story]**: 이 태스크가 속한 사용자 스토리 (US1-US6)
- plan.md의 프로젝트 구조를 기반으로 정확한 파일 경로 포함

## 프로젝트 구조

```
vpn-router/
  crates/
    vpn-router-daemon/     # 메인 데몬 (Rust 사용자 공간)
    vpn-router-cli/        # CLI 도구
    vpn-router-ebpf/       # eBPF 프로그램 (aya)
      ebpf/
        xdp_filter/        # XDP 프로그램
        tc_rbac/           # TC 프로그램
    vpn-router-types/      # 공유 타입
  tests/integration/       # 통합 테스트
  scripts/                 # 헬퍼 스크립트
  config/                  # 설정 예제
```

---

## Phase 1: 셋업 (공유 인프라)

**목적**: 프로젝트 초기화 및 빌드 환경 구성

- [ ] T001 `vpn-router/Cargo.toml`에 4개 크레이트(daemon, cli, ebpf, types)를 가진 Cargo workspace 구조 생성
- [ ] T002 [P] `crates/vpn-router-types/`에 공유 데이터 구조체를 가진 `vpn-router-types` 크레이트 초기화
- [ ] T003 [P] `crates/vpn-router-daemon/`에 tokio, clap, serde 의존성을 가진 `vpn-router-daemon` 크레이트 초기화
- [ ] T004 [P] `crates/vpn-router-cli/`에 clap, reqwest 의존성을 가진 `vpn-router-cli` 크레이트 초기화
- [ ] T005 [P] `crates/vpn-router-ebpf/`에 aya 프레임워크를 사용하는 `vpn-router-ebpf` 크레이트 초기화
- [ ] T006 [P] `.github/workflows/ci.yml`에 CI/CD 파이프라인 구성: Rust 빌드, Clang eBPF 컴파일, 3개 커널 버전 테스트 (5.10, 5.15, 6.1 LTS)
- [ ] T007 [P] 린팅 도구 구성: `cargo clippy --deny warnings`, `cargo fmt`, `cargo audit`
- [ ] T008 네트워크 네임스페이스 생성을 위한 헬퍼 스크립트 `scripts/setup-test-env.sh` 작성 (quickstart.md 참고)
- [ ] T009 plan.md의 모든 섹션을 포함하는 예제 설정 파일 `config/config.example.yaml` 생성

**체크포인트**: 프로젝트 구조 준비 완료, 빌드 성공

---

## Phase 2: 기초 (선행 필수 요소)

**목적**: 모든 사용자 스토리가 구현되기 전에 완료되어야 하는 핵심 인프라

**⚠️ 중요**: 이 단계가 완료되기 전에는 사용자 스토리 작업을 시작할 수 없음

- [ ] T010 `crates/vpn-router-types/src/lib.rs`에 공유 데이터 타입 정의: `IpRoleKey`, `IpRoleValue`, `AclRule`, `AclMapValue`, `SessionKeyValue` (모두 eBPF 호환성을 위해 `#[repr(C)]`)
- [ ] T011 [P] `crates/vpn-router-types/src/policy.rs`에 정책 타입 정의: `IpRoleMapping`, `AclRuleSet`, `RoleId`, `Protocol`, `PortRange`, `AclAction`
- [ ] T012 [P] `crates/vpn-router-types/src/session.rs`에 세션 타입 정의: `VpnSession`, `SessionKeyMaterial`, `HandshakeState`, `SessionStats`
- [ ] T013 [P] `crates/vpn-router-types/src/maps.rs`에 맵 메타데이터 타입 정의: `XdpProgramMetadata`, `TcProgramMetadata`, `NetworkZone`
- [ ] T014 `crates/vpn-router-daemon/src/config.rs`에 YAML 설정을 위한 설정 파서 구현 (`serde_yaml` 사용)
- [ ] T015 [P] `crates/vpn-router-daemon/src/daemon.rs`에 JSON/텍스트 출력을 가진 `tracing` 크레이트를 사용하여 로깅 인프라 구성
- [ ] T016 [P] `crates/vpn-router-daemon/src/error.rs`에 eBPF, IDP, VPN 작업을 위한 커스텀 오류 타입으로 오류 처리 타입 구성
- [ ] T017 `crates/vpn-router-ebpf/src/lib.rs`에 맵 생성, `/sys/fs/bpf/vpn/`에 피닝, 원자적 업데이트를 위한 eBPF 맵 헬퍼 유틸리티 생성
- [ ] T018 `crates/vpn-router-ebpf/Cargo.toml`에서 Clang으로 XDP/TC 프로그램을 컴파일하고 BTF를 생성하도록 eBPF 빌드 파이프라인 구성

**체크포인트**: 기초 준비 완료 - 이제 사용자 스토리 구현을 병렬로 시작할 수 있음

---

## Phase 3: User Story 1 - 기본 eBPF 프로그램 구현 (우선순위: P1) 🎯 MVP

**목표**: 간단한 규칙에 따라 패킷을 필터링할 수 있는 기본 XDP 프로그램을 네트워크 인터페이스에 로드하고 실행

**eBPF 핵심 역량**: XDP 프로그램 생성, 로딩, 기본 패킷 처리 (FR-001, FR-002, FR-003)

**독립 테스트**: 특정 IP에서 패킷 전송, tcpdump를 사용하여 XDP 프로그램이 패킷을 드롭/통과시키는지 확인

### User Story 1 구현

- [ ] T019 [P] [US1] `crates/vpn-router-ebpf/ebpf/xdp_filter/src/main.rs`에 기본 XDP_PASS/XDP_DROP 로직을 가진 XDP 프로그램 진입점 생성
- [ ] T020 [US1] XDP 프로그램에서 `ptr_at` 헬퍼를 사용하여 Ethernet 헤더 파싱 구현
- [ ] T021 [US1] XDP 프로그램에서 IPv4 헤더 파싱 및 검증 (체크섬, 프로토콜 필드) 구현
- [ ] T022 [US1] XDP 프로그램에서 TCP/UDP 헤더 파싱 구현
- [ ] T023 [US1] 기본 패킷 필터링 로직 추가: 허용 목록에 대해 소스 IP 확인, 권한 없는 IP에 대해 XDP_DROP 반환
- [ ] T024 [US1] `crates/vpn-router-daemon/src/ebpf/xdp.rs`에 `aya::Bpf`를 사용하여 임베디드 바이트에서 프로그램을 로드하는 XDP 프로그램 로더 생성
- [ ] T025 [US1] Native/Generic 모드에서 오류 처리와 함께 네트워크 인터페이스에 XDP 프로그램 연결 구현
- [ ] T026 [US1] `crates/vpn-router-daemon/src/ebpf/xdp.rs`에 XDP 프로그램 메타데이터 수집 추가: 프로그램 ID, 명령어 수, 인터페이스 이름, 연결 모드
- [ ] T027 [US1] 데몬에 `bpf_prog_get_info_by_fd()`를 통해 프로그램 통계를 쿼리하는 bpftool 통합 추가
- [ ] T028 [US1] `crates/vpn-router-cli/src/commands/status.rs`에 XDP 프로그램 상태(로드/실행 중, 인터페이스, 패킷 수)를 표시하는 CLI 명령 `vpn-router status` 생성

**체크포인트**: 이 시점에서 User Story 1이 완전히 작동해야 함 - XDP 프로그램이 로드, 연결되고 패킷을 필터링함

---

## Phase 4: User Story 2 - eBPF Maps을 통한 동적 정책 적용 (우선순위: P2)

**목표**: eBPF 맵을 사용하여 프로그램을 다시 로드하지 않고 사용자 공간에서 IP→역할 및 역할→ACL 정책을 동적으로 업데이트

**eBPF 핵심 역량**: eBPF Maps (hashmap, LPM trie), 사용자 공간-커널 데이터 동기화 (FR-004~FR-008)

**독립 테스트**: CLI를 사용하여 IP-역할 매핑을 추가/제거, 데몬 재시작 없이 XDP 프로그램이 업데이트된 정책을 적용하는지 확인

### User Story 2 구현

- [ ] T029 [P] [US2] `crates/vpn-router-ebpf/ebpf/xdp_filter/src/main.rs`에 `BPF_MAP_TYPE_LPM_TRIE`, key=`IpRoleKey`, value=`IpRoleValue`를 가진 IP-역할 LPM Trie 맵 정의 생성
- [ ] T030 [P] [US2] XDP 프로그램에 `BPF_MAP_TYPE_HASH`, key=`u32` (role_id), value=`AclMapValue` (ACL 규칙 배열)를 가진 역할-ACL Hash 맵 정의 생성
- [ ] T031 [US2] XDP 프로그램에서 IP-to-역할 조회 구현: LPM Trie에서 `bpf_map_lookup_elem()`, 미스 처리 (기본 거부)
- [ ] T032 [US2] XDP 프로그램에서 역할-to-ACL 조회 구현: 해시 맵에서 role_id 조회, 규칙 반복 (`#pragma unroll`을 사용한 제한된 루프, MAX_RULES_PER_ROLE=32)
- [ ] T033 [US2] ACL 규칙 평가 로직 구현: src/dst IP, 프로토콜, 포트 범위 매칭, ALLOW 또는 DENY 액션 반환
- [ ] T034 [US2] 다중 역할 처리 추가: 사용자가 여러 역할을 가진 경우, 모두 반복하고 DENY가 우선 (명확화 Q2에 따라)
- [ ] T035 [US2] `crates/vpn-router-daemon/src/policy/maps.rs`에 IP-역할 및 역할-ACL 맵에 대한 aya::Map API를 래핑하는 사용자 공간 맵 관리자 생성
- [ ] T036 [US2] `crates/vpn-router-daemon/src/policy/maps.rs`에 원자적 맵 업데이트 전략 구현: 버전 스탬핑, 맵 스왑, `/sys/fs/bpf/vpn/ip_role_map`에 피닝
- [ ] T037 [P] [US2] `crates/vpn-router-cli/src/commands/policy.rs`에 --ip-range, --role-id, --role-name 인자를 가진 CLI 명령 `vpn-router policy add ip-role` 생성
- [ ] T038 [P] [US2] --role-id, --src, --dst, --protocol, --dst-ports, --action, --priority, --bidirectional 인자를 가진 CLI 명령 `vpn-router policy add acl-rule` 생성
- [ ] T039 [P] [US2] bpftool 또는 aya 반복을 사용하여 맵에서 모든 정책을 덤프하는 CLI 명령 `vpn-router policy list` 생성
- [ ] T040 [P] [US2] 맵에서 항목을 제거하는 CLI 명령 `vpn-router policy delete <POLICY_ID>` 생성
- [ ] T041 [US2] `crates/vpn-router-daemon/src/api/mod.rs`에 정책 CRUD를 위한 axum 프레임워크를 사용하는 REST API 엔드포인트 `POST /policies` 추가
- [ ] T042 [US2] 페이지네이션으로 모든 정책을 나열하는 REST API 엔드포인트 `GET /policies` 추가
- [ ] T043 [US2] 설정 파일 또는 IDP에서 맵 재로드를 트리거하는 REST API 엔드포인트 `POST /policies/reload` 추가

**체크포인트**: 이 시점에서 User Stories 1과 2가 모두 독립적으로 작동해야 함 - 정책을 동적으로 업데이트할 수 있음

---

## Phase 5: User Story 3 - 실시간 감사 로깅 시스템 (우선순위: P3)

**목표**: 정책 위반 및 허용된 트래픽을 ringbuffer에 기록, 사용자 공간에서 이벤트 소비, JSON 로그로 출력

**eBPF 핵심 역량**: Ringbuffer/Perf events, Per-CPU 맵, 고성능 데이터 전송 (FR-009~FR-013)

**독립 테스트**: 정책 위반 트리거, 올바른 메타데이터(타임스탬프, IP, 역할, 액션)를 가진 100개 이벤트가 로그 파일에 나타나는지 확인

### User Story 3 구현

- [ ] T044 [P] [US3] `crates/vpn-router-ebpf/ebpf/xdp_filter/src/main.rs`에 `BPF_MAP_TYPE_RINGBUF`, 크기 256KB를 가진 Ringbuffer 맵 생성
- [ ] T045 [P] [US3] XDP 프로그램에 패킷 카운터(총, 통과, 드롭, 지연시간)를 위한 `BPF_MAP_TYPE_PERCPU_ARRAY`를 가진 Per-CPU 통계 맵 생성
- [ ] T046 [US3] XDP 프로그램에 감사 이벤트 로깅 추가: DENY 액션 시, `bpf_ringbuf_reserve()` 호출, `PolicyViolationEvent` 구조체 채우기, `bpf_ringbuf_submit()`
- [ ] T047 [US3] XDP 프로그램에 지연시간 측정 추가: 진입 및 종료 시 `bpf_ktime_get_ns()` 호출, per-CPU 통계 맵에 델타 저장
- [ ] T048 [US3] `crates/vpn-router-daemon/src/audit/logger.rs`에 비동기 폴링(100ms 간격)을 가진 `aya::maps::RingBuf`를 사용하여 ringbuffer 소비자 구현
- [ ] T049 [US3] `crates/vpn-router-daemon/src/audit/formatter.rs`에 이벤트를 ISO 8601 타임스탬프가 있는 JSON으로 변환하는 감사 로그 포맷터 생성
- [ ] T050 [P] [US3] 회전(`tracing-appender` 사용)이 있는 파일 `/var/log/vpn-router/audit.log`에 감사 로그 출력 추가
- [ ] T051 [P] [US3] facility LOG_LOCAL0으로 `syslog` 크레이트를 사용하여 syslog에 감사 로그 출력 추가
- [ ] T052 [US3] `crates/vpn-router-cli/src/commands/audit.rs`에 --start-time, --end-time, --action, --role, --follow 필터를 가진 CLI 명령 `vpn-router audit events` 생성
- [ ] T053 [US3] 시간 범위로 JSON 파일에 감사 로그를 덤프하는 CLI 명령 `vpn-router audit export` 생성
- [ ] T054 [US3] 쿼리 파라미터 start_time, end_time, action, role, page, page_size를 가진 REST API 엔드포인트 `GET /audit/events` 추가
- [ ] T055 [US3] eBPF에서 감사 이벤트에 대한 속도 제한 구현: DoS 방지를 위해 역할당 맵을 사용하여 최대 1000 이벤트/초

**체크포인트**: 모든 사용자 스토리 1, 2, 3이 이제 독립적으로 작동 - 완전한 감사 추적 가능

---

## Phase 6: User Story 4 - 네트워크 존 매핑 (LPM Trie) (우선순위: P4)

**목표**: LPM Trie를 사용하여 목적지 IP를 네트워크 존(내부/VPN/외부)에 매핑하고 라우팅 결정

**eBPF 핵심 역량**: LPM (Longest Prefix Match) Trie, CIDR 기반 라우팅 (FR-014~FR-017)

**독립 테스트**: CIDR 범위로 여러 존 구성, 다양한 IP로 패킷 전송, 올바른 존으로 라우팅되는지 확인

### User Story 4 구현

- [ ] T056 [US4] `crates/vpn-router-ebpf/ebpf/xdp_filter/src/main.rs`에 key=`ZoneKey` (prefixlen + network), value=`ZoneValue` (zone_type, zone_id)를 가진 네트워크 존 LPM Trie 맵 생성
- [ ] T057 [US4] XDP 프로그램에서 목적지 IP 조회 구현: 존 맵에서 `bpf_map_lookup_elem()`, ZoneType 가져오기 (INTERNAL=0, VPN=1, EXTERNAL=2)
- [ ] T058 [US4] 존 기반 라우팅 로직 추가: dst_zone == INTERNAL && src_zone == EXTERNAL인 경우, 엄격한 RBAC 적용; dst_zone == VPN인 경우, 터널 캡슐화 준비
- [ ] T059 [US4] 존 간 정책 적용 구현: ACL 규칙이 존 전환을 허용하는지 확인 (예: EXTERNAL→INTERNAL에는 명시적 ALLOW 필요)
- [ ] T060 [US4] `crates/vpn-router-daemon/src/policy/zones.rs`에 YAML 설정에서 존을 로드하는 존 설정 파서 생성
- [ ] T061 [US4] 데몬 시작 시 설정에서 CIDR 범위를 LPM Trie에 삽입하는 존 맵 채우기 로직 추가
- [ ] T062 [US4] `crates/vpn-router-cli/src/commands/map.rs`에 존 매핑을 표시하는 CLI 명령 `vpn-router map info zone_map` 생성
- [ ] T063 [US4] 모든 존 매핑을 YAML로 내보내는 CLI 명령 `vpn-router map dump zone_map` 생성

**체크포인트**: User Stories 1-4가 이제 작동 - 존이 정교한 라우팅 로직을 가능하게 함

---

## Phase 7: User Story 5 - VPN 터널 통합 및 TC eBPF (우선순위: P5)

**목표**: TC eBPF를 사용하여 VPN 터널 트래픽 처리(인그레스 복호화, 이그레스 암호화) 및 복호화된 내부 패킷에 RBAC 적용

**eBPF 핵심 역량**: TC (Traffic Control) eBPF, 프로그램 체이닝, 터널 암호화 통합 (FR-018~FR-021)

**독립 테스트**: VPN 터널 생성, 암호화된 패킷 전송, TC가 복호화하고 내부 IP 헤더를 기반으로 RBAC를 적용하는지 확인

### User Story 5 구현

- [ ] T064 [P] [US5] `crates/vpn-router-ebpf/ebpf/tc_rbac/src/main.rs`에 `SEC("classifier")` 섹션을 가진 TC 인그레스 프로그램 진입점 생성
- [ ] T065 [P] [US5] TC 프로그램에 key=`SessionKeyKey` (peer_ip + tunnel_id), value=`SessionKeyValue` (key, seq_num, expires_at)를 가진 세션 키 Hash 맵 생성
- [ ] T066 [US5] TC 프로그램에서 VPN 헤더 파싱 구현: `skb->data`에서 커스텀 VPN 헤더(magic, tunnel_id, seq_num, auth_tag) 읽기
- [ ] T067 [US5] TC 프로그램에 세션 키 조회 추가: session_key_map에서 tunnel_id 조회, 키가 존재하고 만료되지 않았는지 검증
- [ ] T068 [US5] 재생 공격 방지 추가: 저장된 seq_num + 슬라이딩 윈도우(64비트 비트마스크)에 대해 seq_num 확인, 재생 감지 시 거부
- [ ] T069 [US5] 패킷 복호화 구현: ChaCha20-Poly1305로 `bpf_crypto_decrypt()` 호출, auth_tag 검증, 성공 시 seq_num 업데이트
- [ ] T070 [US5] 내부 패킷 RBAC 추가: 복호화 후, 내부 IP 헤더 파싱, IP-역할 + ACL 조회 수행 (US2 로직 재사용), DENY 시 TC_ACT_SHOT 반환
- [ ] T071 [US5] VPN 캡슐화를 위한 TC 이그레스 프로그램 생성: zone_map에서 dst IP 조회, dst_zone == VPN인 경우, 세션 키 조회, 패킷 암호화, VPN 헤더 앞에 추가
- [ ] T072 [US5] `crates/vpn-router-daemon/src/ebpf/tc.rs`에 aya를 사용하여 VPN 인터페이스의 인그레스/이그레스 훅에 TC 프로그램을 연결하는 TC 프로그램 로더 생성
- [ ] T073 [US5] `crates/vpn-router-daemon/src/vpn/session.rs`에 VPN 세션 관리자 구현: 세션 생성/삭제, session_key_map 채우기
- [ ] T074 [US5] 사용자 공간에 키 교환 로직(Noise 프로토콜 XX 패턴) 추가: Diffie-Hellman 핸드셰이크, 대칭키 도출, 맵에 저장
- [ ] T075 [US5] 자동 키 교체 추가: 3600초마다 키를 교체하는 tokio 태스크 생성, 새 핸드셰이크 트리거, 맵 원자적 업데이트
- [ ] T076 [P] [US5] `crates/vpn-router-cli/src/commands/session.rs`에 활성 VPN 세션을 표시하는 CLI 명령 `vpn-router session list` 생성
- [ ] T077 [P] [US5] 핸드셰이크를 시작하는 CLI 명령 `vpn-router session create --peer-ip <IP> --tunnel-id <ID>` 생성
- [ ] T078 [P] [US5] 세션을 종료하고 맵에서 키를 제거하는 CLI 명령 `vpn-router session delete <TUNNEL_ID>` 생성
- [ ] T079 [P] [US5] 키 교체를 수동으로 트리거하는 CLI 명령 `vpn-router session rotate-key <TUNNEL_ID>` 생성
- [ ] T080 [US5] REST API 엔드포인트 추가: `POST /sessions`, `GET /sessions`, `DELETE /sessions/{tunnel_id}`, `POST /sessions/{tunnel_id}/rotate`

**체크포인트**: User Stories 1-5 완료 - 전체 VPN 터널 + RBAC 파이프라인 작동

---

## Phase 8: User Story 6 - IDP 통합 및 자동 정책 동기화 (우선순위: P6)

**목표**: OIDC/SAML IDP와 통합하여 사용자 ID, 역할, IP 매핑을 자동으로 가져오고 5분마다 eBPF 맵에 동기화

**eBPF 핵심 역량**: 사용자 공간 제어 플레인 통합, 원자적 eBPF 맵 업데이트, 제어/데이터 플레인 분리 (FR-022~FR-026)

**독립 테스트**: IDP에서 사용자 역할 변경, 데몬 재시작 없이 5초 이내에 eBPF 맵에서 정책 업데이트 확인

### User Story 6 구현

- [ ] T081 [P] [US6] `crates/vpn-router-daemon/Cargo.toml`에 IDP 의존성 추가: `openidconnect`, `reqwest`, `jsonwebtoken`
- [ ] T082 [US6] `crates/vpn-router-daemon/src/idp/oidc.rs`에 IDP 클라이언트 생성: `.well-known/openid-configuration`을 사용하여 OIDC 엔드포인트 검색
- [ ] T083 [US6] OIDC 인증 플로우 구현: IDP로 리디렉션, 인증 코드를 토큰으로 교환, access_token 및 refresh_token 저장
- [ ] T084 [US6] `crates/vpn-router-daemon/src/idp/token.rs`에 클레임을 추출하는 토큰 파서 구현: user_id, roles[], ip_address, exp (만료)
- [ ] T085 [US6] `crates/vpn-router-daemon/src/policy/compiler.rs`에 IDP 토큰을 IP-역할 매핑 및 ACL 규칙으로 변환하는 정책 컴파일러 생성
- [ ] T086 [US6] 자동 토큰 새로 고침 구현: 60초마다 토큰 만료를 확인하는 tokio 태스크 생성, 만료 5분 전에 새로 고침 (명확화 Q1에 따라)
- [ ] T087 [US6] `crates/vpn-router-daemon/src/idp/sync.rs`에 IDP 동기화 로직 추가: IDP userinfo 엔드포인트에서 모든 사용자 가져오기, 정책 일괄 컴파일, 맵 원자적 업데이트
- [ ] T088 [US6] 주기적 동기화 추가: 300초(5분)마다 IDP 동기화를 호출하는 tokio 간격 태스크 생성
- [ ] T089 [US6] IDP 장애 조치 구현: IDP 연결 실패 시, 마지막 성공한 동기화의 캐시된 정책 사용 (명확화 Q3에 따라), 경고 로그
- [ ] T090 [US6] 정책 버전 관리 추가: 각 업데이트마다 맵 버전 카운터 증가, eBPF 프로그램이 버전을 확인하여 오래된 읽기 감지
- [ ] T091 [P] [US6] `crates/vpn-router-cli/src/commands/idp.rs`에 IDP 연결 상태를 표시하는 CLI 명령 `vpn-router idp config` 생성
- [ ] T092 [P] [US6] IDP 동기화를 수동으로 트리거하는 CLI 명령 `vpn-router idp sync` 생성
- [ ] T093 [P] [US6] IDP 연결을 검증하는 CLI 명령 `vpn-router idp test-connection` 생성
- [ ] T094 [US6] REST API 엔드포인트 추가: `GET /idp/config`, `POST /idp/sync`, `GET /idp/status`
- [ ] T095 [US6] 동기화 상태를 추적하는 Prometheus 메트릭 `vpn_idp_sync_total{status="success|failure"}` 추가
- [ ] T096 [US6] 동기화 지연시간을 위한 Prometheus 메트릭 `vpn_idp_sync_duration_seconds` 히스토그램 추가

**체크포인트**: 모든 사용자 스토리 1-6 완료 - 자동 동기화를 가진 전체 IDP-to-eBPF 파이프라인

---

## Phase 9: 마무리 및 횡단 관심사

**목적**: 여러 사용자 스토리에 영향을 미치는 개선 사항 및 시스템 완성

- [ ] T097 [P] `crates/vpn-router-daemon/src/api/metrics.rs`에 contracts/metrics-api.md의 모든 60+ 메트릭을 포함하는 Prometheus 메트릭 엔드포인트 `GET /metrics` 구현
- [ ] T098 [P] 메트릭 수집 추가: 패킷 카운터, 지연시간 히스토그램 (p50/p95/p99), 정책 조회, 세션 통계, 맵 사용량, IDP 동기화 통계, CPU 사용량
- [ ] T099 [P] `config/grafana-dashboard.json`에 8개 패널을 가진 Grafana 대시보드 JSON 생성: 개요, 패킷, 지연시간, 정책, 세션, 맵, IDP, 리소스
- [ ] T100 CLI 구현 완료: contracts/cli-interface.md의 모든 명령 추가: `daemon start/stop/restart/logs`, `map list/info/dump`, `policy import/export/reload`, `status health`
- [ ] T101 [P] CLI 출력 형식 추가: 테이블 (기본, `prettytable-rs` 사용), JSON (`serde_json`), YAML (`serde_yaml`)
- [ ] T102 [P] CLI 셸 자동 완성 추가: clap의 `CommandFactory::command().gen_completions()`를 사용하여 bash/zsh/fish 자동 완성 생성
- [ ] T103 [P] LimitMEMLOCK=infinity, Restart=on-failure, after=network.target를 가진 systemd 서비스 파일 `config/systemd/vpn-router.service` 추가
- [ ] T104 [P] quickstart.md의 모든 단계를 자동화하는 포괄적인 빠른 시작 스크립트 `scripts/quickstart.sh` 생성: 의존성 설치, 빌드, 테스트 환경 구성, 데몬 시작, 테스트 실행
- [ ] T105 동적 맵 확장 추가: 60초마다 맵 사용량 모니터링, >80%인 경우, 2배 용량으로 새 맵 생성, 항목 복사, 원자적 스왑 (명확화 Q4에 따라)
- [ ] T106 [P] verifier 디버깅 추가: 프로그램 로드 실패 시, `bpf_prog_load`로 verifier 로그 캡처 및 `verifier.log` 파일에 저장
- [ ] T107 [P] CO-RE 검증 추가: 데몬 시작 시 BTF 가용성 확인, 커널 < 5.10 또는 BTF가 컴파일되지 않은 경우 명확한 메시지로 오류 발생
- [ ] T108 tail call 아키텍처 구현 (필요한 경우): 복잡한 XDP 프로그램을 단계(기본 검증, ACL 평가, 포워딩)로 분할, `bpf_tail_call()`을 사용하여 체인
- [ ] T109 XDP/TC 지연시간을 위한 `tc-bpf-bench` 및 처리량을 위한 `iperf3`을 사용하는 성능 벤치마킹 스크립트 `scripts/bench.sh` 추가, SC-005, SC-006, SC-007 확인
- [ ] T110 [P] 문서 업데이트: 데이터/제어 플레인 다이어그램이 있는 `docs/architecture.md`, 맵 스키마 및 프로그램 로직이 있는 `docs/ebpf-details.md` 생성
- [ ] T111 [P] 문제 해결 가이드 `docs/troubleshooting.md` 생성: BTF 누락, RLIMIT_MEMLOCK, IDP 연결 실패, 높은 패킷 드롭, verifier 오류
- [ ] T112 보안 강화 추가: `zeroize` 크레이트를 사용하여 메모리의 세션 키 제로화, 데몬용 `seccomp` 프로필 추가, 모든 사용자 입력 검증
- [ ] T113 quickstart.md 검증 실행: quickstart.md의 모든 명령을 end-to-end로 실행, 출력이 예상 결과와 일치하는지 확인
- [ ] T114 오류 처리 개선 추가: `anyhow`를 사용하여 모든 `.unwrap()`을 컨텍스트가 있는 적절한 오류 전파로 변환, cli-interface.md에 따라 오류 코드 추가
- [ ] T115 clippy 실행 및 모든 경고 해결: `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] T116 cargo audit 실행: `cargo audit` 및 모든 취약점 수정/확인
- [ ] T117 [P] XDP 프로그램이 로드되고 패킷을 드롭하는지 확인하는 통합 테스트 `tests/integration/test_xdp_filtering.rs` 추가 (US1)
- [ ] T118 [P] IP-역할-ACL 파이프라인을 확인하는 통합 테스트 `tests/integration/test_policy_enforcement.rs` 추가 (US2)
- [ ] T119 [P] ringbuffer 이벤트를 확인하는 통합 테스트 `tests/integration/test_audit_logging.rs` 추가 (US3)
- [ ] T120 [P] IDP 토큰 파싱 및 맵 업데이트를 확인하는 통합 테스트 `tests/integration/test_idp_sync.rs` 추가 (US6)

---

## 의존성 및 실행 순서

### Phase 의존성

- **Setup (Phase 1)**: 의존성 없음 - 즉시 시작 가능
- **Foundational (Phase 2)**: Setup 완료에 의존 - 모든 사용자 스토리를 차단
- **User Stories (Phase 3-8)**: 모두 Foundational phase 완료에 의존
  - 충분한 팀 역량이 있으면 사용자 스토리를 병렬로 진행 가능
  - 또는 우선순위 순서로 순차적으로: US1 → US2 → US3 → US4 → US5 → US6
- **Polish (Phase 9)**: 원하는 모든 사용자 스토리 완료에 의존

### User Story 의존성

- **US1 (P1)**: Foundational 후 시작 가능 - 다른 스토리에 의존성 없음
- **US2 (P2)**: Foundational 후 시작 가능 - US1의 XDP 프로그램을 기반으로 하지만 독립적으로 테스트 가능
- **US3 (P3)**: Foundational 후 시작 가능 - US2의 정책 로직과 통합하지만 독립적
- **US4 (P4)**: Foundational 후 시작 가능 - 새로운 맵 타입 추가, US2의 조회 로직과 함께 작동
- **US5 (P5)**: Foundational 후 시작 가능 - TC 프로그램 필요, RBAC를 위해 US2/US4와 함께 작동하지만 독립적
- **US6 (P6)**: US2 완료 후 시작 가능 (맵 업데이트 API 필요) - IDP가 모든 이전 스토리와 통합

### 각 User Story 내에서

- 사용하는 프로그램 로직 전에 eBPF 맵 정의
- eBPF 프로그램 정의 후 사용자 공간 로더
- REST API 엔드포인트 후 CLI 명령
- 핵심 서비스 로직 후 REST API

### 크리티컬 패스 (순차적 MVP)

```
Setup → Foundational → US1 → US2 → US3 → US4 → US5 → US6 → Polish
```

### 병렬 기회

- [P]로 표시된 모든 Setup 태스크는 병렬 실행 가능 (T002-T005)
- [P]로 표시된 모든 Foundational 태스크는 병렬 실행 가능 (T011-T013, T015-T017)
- Foundational 완료 후, 다른 개발자가 작업 가능:
  - 개발자 A: US1 + US2 (핵심 eBPF)
  - 개발자 B: US3 + US4 (관찰성 + 라우팅)
  - 개발자 C: US5 (VPN 터널)
  - 개발자 D: US6 (IDP 통합)
- 스토리 내에서 [P]로 표시된 모든 CLI 명령은 병렬 구현 가능
- [P]로 표시된 모든 API 엔드포인트는 병렬 구현 가능
- [P]로 표시된 통합 테스트는 병렬 작성 가능

---

## 병렬 예제: User Story 2

```bash
# 모든 맵 생성 태스크를 함께 시작:
Task T029: "IP-역할 LPM Trie 맵 생성"
Task T030: "역할-ACL Hash 맵 생성"

# 맵이 존재한 후, 모든 CLI 명령을 병렬로 시작:
Task T037: "CLI 명령 policy add ip-role 생성"
Task T038: "CLI 명령 policy add acl-rule 생성"
Task T039: "CLI 명령 policy list 생성"
Task T040: "CLI 명령 policy delete 생성"
```

---

## 구현 전략

### MVP 우선 (User Story 1-2만)

**목표**: 동적 정책 업데이트를 가진 기본 eBPF 패킷 필터링 시연

1. Phase 1 완료: Setup (T001-T009) - ~2-3일
2. Phase 2 완료: Foundational (T010-T018) - ~3-4일
3. Phase 3 완료: User Story 1 (T019-T028) - ~4-5일
4. Phase 4 완료: User Story 2 (T029-T043) - ~5-7일
5. **중지 및 검증**: XDP 필터링 + 동적 정책 업데이트를 독립적으로 테스트
6. **결과물**: CLI 제어를 가진 작동하는 eBPF 기반 패킷 필터

**총 MVP 시간**: ~2-3주 (단일 개발자)

### 점진적 제공

1. **스프린트 1**: Setup + Foundational (T001-T018) → 빌드 환경 준비
2. **스프린트 2**: US1 + US2 (T019-T043) → 독립 테스트 → **데모 1: 기본 eBPF 필터링**
3. **스프린트 3**: US3 + US4 (T044-T063) → 독립 테스트 → **데모 2: 감사 로깅 + 존 라우팅**
4. **스프린트 4**: US5 (T064-T080) → 독립 테스트 → **데모 3: VPN 터널 통합**
5. **스프린트 5**: US6 (T081-T096) → 독립 테스트 → **데모 4: IDP 자동 동기화**
6. **스프린트 6**: Polish (T097-T120) → 전체 시스템 통합 → **릴리스 1.0**

각 스프린트는 이전 스토리를 깨지 않고 가치를 추가합니다.

### 병렬 팀 전략

Foundational phase 후 여러 개발자와 함께:

1. **Setup + Foundational을 함께 완료** (1주차)
2. **Foundational 완료 후** (2주차+):
   - 개발자 A: US1 (XDP 기초, T019-T028)
   - 개발자 B: US2 (맵 + 정책, T029-T043)
3. **3주차**:
   - 개발자 A: US3 (감사 로깅, T044-T055)
   - 개발자 B: US4 (존 라우팅, T056-T063)
4. **4-5주차**:
   - 개발자 A: US5 (VPN + TC, T064-T080)
   - 개발자 B: US6 (IDP 통합, T081-T096)
5. **6주차**: 모든 개발자가 Polish + 통합 테스트 진행

---

## 성공 기준 검증

각 태스크는 spec.md의 특정 성공 기준에 기여합니다:

| 성공 기준 | 관련 태스크 | 검증 방법 |
|---------|-----------|---------|
| SC-001: 기본 XDP 프로그램 동작 | T019-T028 (US1) | `tc-bpf-bench` 실행, 프로그램이 로드되고 패킷을 처리하는지 확인 |
| SC-002: eBPF hashmap 동적 정책 | T029-T043 (US2) | CLI를 통해 1000개 IP-역할 매핑 추가, 조회가 작동하는지 확인 |
| SC-003: Ringbuffer 감사 로깅 | T044-T055 (US3) | 1000개 이벤트 생성, 사용자 공간으로 <1ms 지연시간 확인 |
| SC-004: LPM trie CIDR 매칭 | T056-T063 (US4) | 겹치는 CIDR 추가, longest-prefix-match가 작동하는지 확인 |
| SC-005: 기본 패킷 처리 지연시간 <1μs (p99) | T019-T028, T109 (US1) | 성능 벤치마크 실행, p99 지연시간이 목표를 충족하는지 확인 |
| SC-006: 정책 적용 지연시간 <10μs (p99) | T029-T043, T109 (US2) | 정책 로드된 상태로 실행, p99 지연시간 확인 |
| SC-007: 고부하 처리량 1M pps @ 80% CPU | T109 (벤치마크) | 10Gbps로 iperf3 실행, mpstat로 CPU 모니터링 |
| SC-008: 10,000개 이벤트 로깅 <1ms 오버헤드 | T044-T055, T109 (US3) | 10k 이벤트 생성, 패킷 드롭 없는지 확인 |
| SC-009: 10,000 IP-역할 매핑 + 100 ACL 규칙 | T029-T043, T105 (US2) | CLI를 통해 10k 매핑 로드, 맵 용량 확인 |
| SC-010: 사용자 공간 정책 업데이트 <1초 | T029-T043 (US2) | API를 통해 정책 추가, eBPF 맵까지 시간 측정 |
| SC-011: 감사 이벤트 95% 정확도 | T044-T055 (US3) | 기록된 이벤트를 실제 위반과 비교 |
| SC-012: 3개 커널 버전 호환 (5.10, 5.15, 6.1) | T006, T107 (CI) | qemu로 3개 LTS 커널에서 CI 테스트 실행 |
| SC-013: IDP 정책 동기화 <5초 | T081-T096 (US6) | IDP에서 역할 변경, 동기화 지연시간 측정 |
| SC-014: 10개 VPN 세션 동시 지원 | T064-T080 (US5) | 10개 터널 생성, 모든 세션이 작동하는지 확인 |

---

## 참고 사항

- **[P] 태스크**: 다른 파일, 충돌 없이 병렬 실행 가능
- **[Story] 라벨**: 추적성을 위해 태스크를 특정 사용자 스토리(US1-US6)에 매핑
- **eBPF 집중**: 각 사용자 스토리에서 eBPF 기능 학습 강조
- **테스트 없음**: 명세서에서 테스트를 명시적으로 요청하지 않았으므로 구현에 집중하기 위해 생략
- **Verifier 준수**: 모든 eBPF 프로그램은 verifier를 통과해야 함 - 제한된 루프, 필요 시 tail call 사용
- **CO-RE 필수**: 모든 프로그램은 커널 이식성을 위해 BTF + `bpf_core_read()` 사용
- **원자적 업데이트**: 모든 맵 업데이트는 제로 다운타임을 위해 버전 스탬핑 + 피닝 사용
- **자주 커밋**: 각 태스크 또는 논리적 그룹 후
- **체크포인트에서 중지**: 진행하기 전에 각 사용자 스토리를 독립적으로 검증
- **피해야 할 것**: 동일한 파일 충돌, eBPF의 무제한 루프, 데이터 플레인의 차단 작업

---

**총 태스크**: 9개 phase에 걸쳐 120개 태스크
**예상 시간**: 4-6주 (단일 개발자), 2-3주 (4인 팀)
**MVP 범위**: Phases 1-4 (User Stories 1-2) = 43개 태스크 = ~2-3주