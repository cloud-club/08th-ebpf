# 빠른 시작 가이드: IDP/RBAC VPN 라우터

**대상**: 개발자, 시스템 관리자
**소요 시간**: 30-45분
**난이도**: 중급

## 사전 요구사항

### 시스템 요구사항
- **OS**: Linux 5.10 LTS 이상 (BTF 지원 필요)
- **CPU**: x86_64 (eBPF CO-RE 지원)
- **메모리**: 최소 4GB RAM
- **네트워크**: 2개 이상의 네트워크 인터페이스

### 소프트웨어 요구사항
- **Rust**: 1.75 이상
- **Clang/LLVM**: 15 이상
- **Docker**: 20.10 이상 (테스트 환경용, 선택)
- **bpftool**: eBPF 디버깅용
- **ip**: iproute2 패키지

### 커널 기능 확인
```bash
# BTF 지원 확인
bpftool btf dump file /sys/kernel/btf/vmlinux | head

# eBPF 기능 확인
zgrep CONFIG_BPF /proc/config.gz
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_JIT=y

# 커널 버전 확인
uname -r
# 5.10.0 이상이어야 함
```

---

## 단계 1: 프로젝트 클론 및 빌드

### 1.1 저장소 클론
```bash
git clone https://github.com/your-org/vpn-router.git
cd vpn-router
git checkout 001-idp-identity-provider
```

### 1.2 의존성 설치
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    bpftool

# RHEL/CentOS
sudo yum install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    kernel-devel \
    bpftool
```

### 1.3 Rust 설치 (없는 경우)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version  # 1.75 이상 확인
```

### 1.4 프로젝트 빌드
```bash
# eBPF 프로그램 + 사용자 공간 데몬 빌드
cargo build --release

# 빌드 결과 확인
ls -lh target/release/vpn-router-daemon
ls -lh target/bpf/vpn_xdp.o
ls -lh target/bpf/vpn_tc.o
```

---

## 단계 2: 테스트 환경 구성

### 2.1 네트워크 네임스페이스 생성

테스트를 위한 격리된 네트워크 환경 생성:

```bash
#!/bin/bash
# scripts/setup-test-env.sh

# 네임스페이스 생성
sudo ip netns add vpn-external
sudo ip netns add vpn-internal

# veth 쌍 생성 (외부 네트워크)
sudo ip link add veth-ext-host type veth peer name veth-ext-vpn
sudo ip link set veth-ext-vpn netns vpn-external

# veth 쌍 생성 (내부 네트워크)
sudo ip link add veth-int-host type veth peer name veth-int-vpn
sudo ip link set veth-int-vpn netns vpn-internal

# IP 주소 할당 (호스트 측)
sudo ip addr add 10.0.0.1/24 dev veth-ext-host
sudo ip addr add 172.16.0.1/24 dev veth-int-host
sudo ip link set veth-ext-host up
sudo ip link set veth-int-host up

# IP 주소 할당 (네임스페이스 측)
sudo ip netns exec vpn-external ip addr add 10.0.0.10/24 dev veth-ext-vpn
sudo ip netns exec vpn-external ip link set veth-ext-vpn up
sudo ip netns exec vpn-external ip link set lo up

sudo ip netns exec vpn-internal ip addr add 172.16.0.10/24 dev veth-int-vpn
sudo ip netns exec vpn-internal ip link set veth-int-vpn up
sudo ip netns exec vpn-internal ip link set lo up

echo "테스트 환경 구성 완료"
```

실행:
```bash
chmod +x scripts/setup-test-env.sh
sudo ./scripts/setup-test-env.sh
```

### 2.2 테스트 IDP 서버 시작 (선택)

개발용 모의 IDP 서버:

```bash
# Docker로 Keycloak 실행
docker run -d \
  --name test-idp \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev

# 초기화 대기 (약 30초)
sleep 30

# Keycloak 접속: http://localhost:8080
# 사용자명: admin, 비밀번호: admin
```

---

## 단계 3: 설정 파일 작성

### 3.1 기본 설정

`/etc/vpn-router/config.yaml` 생성:

```yaml
# VPN 라우터 설정
daemon:
  api_listen: "127.0.0.1:9090"
  log_level: info
  log_format: json

# 네트워크 인터페이스
interfaces:
  external: veth-ext-host  # 외부 트래픽용
  vpn: tun0                # VPN 터널 인터페이스 (생성됨)

# IDP 통합
idp:
  enabled: true
  provider: oidc
  oidc:
    issuer_url: "http://localhost:8080/realms/master"
    client_id: "vpn-router"
    client_secret: "<YOUR_CLIENT_SECRET>"
    scopes: ["openid", "profile", "email", "roles"]
  sync_interval_seconds: 300  # 5분

# 정적 정책 (IDP 폴백용)
policies:
  ip_role_mappings:
    - ip_range: "10.0.0.0/24"
      role_id: 1001
      role_name: "admin"
      source: static

  acl_rules:
    - role_id: 1001
      role_name: "admin"
      src: "10.0.0.0/24"
      dst: "172.16.0.0/24"
      protocol: any
      action: allow
      description: "Admin full access"

# VPN 설정
vpn:
  protocol: custom  # 커스텀 VPN 프로토콜
  listen_port: 51820
  peers:
    - peer_ip: "192.168.100.5"
      tunnel_id: 1001
      pre_shared_key: "<BASE64_ENCODED_KEY>"

# eBPF 설정
ebpf:
  maps:
    ip_role_map_size: 10000
    role_acl_map_size: 100
    session_key_map_size: 10
  programs:
    xdp_mode: native  # native | offload | generic
    tc_direction: both  # ingress | egress | both

# 관찰성
observability:
  metrics:
    enabled: true
    listen: "127.0.0.1:9090"
  audit_log:
    enabled: true
    file: "/var/log/vpn-router/audit.log"
    rotation_size_mb: 100
    max_files: 10
```

### 3.2 설정 검증
```bash
# 설정 파일 문법 확인
cargo run --release -- config validate /etc/vpn-router/config.yaml

# 출력:
# ✓ 설정 파일 문법 정상
# ✓ IDP 연결 테스트 성공
# ✓ 네트워크 인터페이스 존재 확인
```

---

## 단계 4: 데몬 시작

### 4.1 수동 시작 (개발 모드)

```bash
# eBPF 프로그램 로드 권한을 위해 root 필요
sudo target/release/vpn-router-daemon \
  --config /etc/vpn-router/config.yaml \
  --log-level debug

# 출력:
# [2025-10-07 15:00:00] INFO  vpn_router::daemon: Starting VPN Router daemon v1.0.0
# [2025-10-07 15:00:00] INFO  vpn_router::ebpf: Loading XDP program on veth-ext-host
# [2025-10-07 15:00:01] INFO  vpn_router::ebpf: XDP program loaded successfully (id=42)
# [2025-10-07 15:00:01] INFO  vpn_router::ebpf: Loading TC program on tun0
# [2025-10-07 15:00:02] INFO  vpn_router::ebpf: TC program loaded successfully (id=43)
# [2025-10-07 15:00:02] INFO  vpn_router::idp: Connecting to IDP at http://localhost:8080
# [2025-10-07 15:00:03] INFO  vpn_router::idp: IDP connection successful
# [2025-10-07 15:00:03] INFO  vpn_router::idp: Synced 25 users, 5 roles
# [2025-10-07 15:00:03] INFO  vpn_router::api: API server listening on 127.0.0.1:9090
# [2025-10-07 15:00:03] INFO  vpn_router::daemon: VPN Router ready
```

### 4.2 systemd 서비스 (프로덕션 모드)

`/etc/systemd/system/vpn-router.service`:

```ini
[Unit]
Description=IDP/RBAC Site-to-Site VPN Router
Documentation=https://github.com/your-org/vpn-router
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/vpn-router-daemon --config /etc/vpn-router/config.yaml
Restart=on-failure
RestartSec=10s

# eBPF 리소스 제한
LimitMEMLOCK=infinity
LimitNOFILE=65536

# 로깅
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vpn-router

[Install]
WantedBy=multi-user.target
```

서비스 시작:
```bash
sudo systemctl daemon-reload
sudo systemctl enable vpn-router
sudo systemctl start vpn-router
sudo systemctl status vpn-router
```

---

## 단계 5: 동작 확인

### 5.1 상태 확인

```bash
# CLI를 통한 상태 확인
vpn-router status

# 출력:
# Status: Healthy
# Uptime: 1m 23s
# eBPF Programs: Loaded (2/2)
# IDP Connected: Yes
# Active VPN Sessions: 1
```

### 5.2 eBPF 프로그램 확인

```bash
# XDP 프로그램 확인
sudo bpftool prog show type xdp
# 42: xdp  name vpn_xdp_filter  tag 1a2b3c4d5e6f7890  gpl
#     loaded_at 2025-10-07T15:00:01+0000  uid 0
#     xlated 1024B  jited 768B  memlock 4096B
#     map_ids 10,11,12

# TC 프로그램 확인
sudo bpftool prog show type sched_cls
# 43: sched_cls  name vpn_tc_rbac  tag 9a8b7c6d5e4f3210  gpl
#     loaded_at 2025-10-07T15:00:02+0000  uid 0
#     xlated 2048B  jited 1536B  memlock 4096B
#     map_ids 10,11,13,14
```

### 5.3 eBPF 맵 확인

```bash
# 로드된 맵 목록
sudo bpftool map show
# 10: lpm_trie  name ip_role_map  flags 0x1
#     key 8B  value 16B  max_entries 10000  memlock 163840B
# 11: hash  name role_acl_map  flags 0x0
#     key 4B  value 1088B  max_entries 100  memlock 114688B
# 12: hash  name session_key_map  flags 0x0
#     key 8B  value 72B  max_entries 10  memlock 4096B
# 13: ringbuf  name audit_ringbuf  flags 0x0
#     max_entries 262144  memlock 262144B

# IP-역할 맵 덤프
sudo bpftool map dump name ip_role_map
# key: 08 00 00 00 0a 00 00 00  # 10.0.0.0/8
# value: e9 03 00 00 01 00 00 00  # role_id=1001
```

### 5.4 정책 테스트

```bash
# 허용된 트래픽 테스트 (admin 역할)
sudo ip netns exec vpn-external ping -c 3 172.16.0.10

# 출력:
# PING 172.16.0.10 (172.16.0.10) 56(84) bytes of data.
# 64 bytes from 172.16.0.10: icmp_seq=1 ttl=64 time=0.123 ms
# 64 bytes from 172.16.0.10: icmp_seq=2 ttl=64 time=0.098 ms
# 64 bytes from 172.16.0.10: icmp_seq=3 ttl=64 time=0.105 ms

# 통계 확인
vpn-router policy list
vpn-router audit events --action allow --page-size 5
```

---

## 단계 6: VPN 세션 설정

### 6.1 VPN 피어 추가

```bash
# 새 VPN 세션 생성
vpn-router session create \
  --peer-ip 192.168.100.5 \
  --tunnel-id 1001

# 출력:
# Session created:
#   Tunnel ID: 1001
#   Peer IP: 192.168.100.5
#   State: HandshakeInProgress
```

### 6.2 세션 상태 모니터링

```bash
# 세션 목록
vpn-router session list

# 출력:
# Tunnel ID  Peer IP         State         Created
# 1001       192.168.100.5   Established   2025-10-07 15:05:00

# 세션 세부 정보
vpn-router session show 1001

# 출력:
# Tunnel ID: 1001
# Peer IP: 192.168.100.5
# State: Established
# Created: 2025-10-07 15:05:00 UTC
# Statistics:
#   Packets Encrypted: 1,234
#   Packets Decrypted: 1,198
#   Replay Detected: 0
#   Auth Failures: 0
```

---

## 단계 7: 모니터링 설정

### 7.1 메트릭 확인

```bash
# Prometheus 메트릭 엔드포인트
curl http://localhost:9090/metrics | grep vpn_

# 출력:
# vpn_packets_total{direction="ingress",action="pass",hook="xdp"} 12345
# vpn_latency_microseconds{hook="xdp",quantile="0.99"} 8.3
# vpn_policy_lookups_total{map="ip_role",result="hit"} 12000
# vpn_sessions_active 1
```

### 7.2 Prometheus 설정 (선택)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'vpn-router'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9090']
```

Prometheus 시작:
```bash
docker run -d \
  --name prometheus \
  -p 9091:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

Grafana 대시보드 임포트:
```bash
# Grafana 접속: http://localhost:3000
# 데이터 소스: Prometheus (http://host.docker.internal:9091)
# 대시보드: specs/001-idp-identity-provider/grafana-dashboard.json
```

---

## 단계 8: IDP 통합 테스트

### 8.1 IDP에서 사용자 생성

Keycloak 관리 콘솔에서:
1. Users → Add user
2. Username: `alice`, Email: `alice@example.com`
3. Credentials → Set password: `password123`
4. Role mappings → Assign role: `admin`
5. Attributes → Add: `ip_address` = `10.0.0.50`

### 8.2 IDP 동기화

```bash
# 수동 동기화 트리거
vpn-router idp sync

# 출력:
# Syncing with IDP...
# Users synced: 26 (1 new)
# Roles synced: 5
# Policies updated: 1
# Completed in 1.2 seconds

# 새 매핑 확인
vpn-router policy list --role admin

# 출력:
# ID                    Type           Details
# a1b2c3d4-...          IP-Role        10.0.0.50 → admin (source: IDP)
```

### 8.3 자동 갱신 확인

```bash
# 데몬 로그에서 자동 동기화 확인
sudo journalctl -u vpn-router -f | grep "IDP sync"

# 출력 (5분마다):
# [2025-10-07 15:10:00] INFO vpn_router::idp: IDP sync started
# [2025-10-07 15:10:01] INFO vpn_router::idp: Users synced: 26, Roles: 5
# [2025-10-07 15:10:01] INFO vpn_router::idp: IDP sync completed
```

---

## 문제 해결

### 문제 1: eBPF 프로그램 로드 실패

**증상**:
```
Error: Failed to load XDP program: Operation not permitted
```

**해결책**:
```bash
# 1. RLIMIT_MEMLOCK 확인
ulimit -l
# unlimited 또는 큰 값이어야 함

# 2. 한도 증가
sudo sh -c 'echo "* soft memlock unlimited" >> /etc/security/limits.conf'
sudo sh -c 'echo "* hard memlock unlimited" >> /etc/security/limits.conf'

# 3. 재로그인 후 다시 시도
```

### 문제 2: BTF 지원 없음

**증상**:
```
Error: Kernel lacks BTF support
```

**해결책**:
```bash
# BTF가 활성화된 커널로 업그레이드
# Debian/Ubuntu:
sudo apt install linux-image-$(uname -r | cut -d'-' -f1-2)-generic

# 또는 커널 5.10 LTS 이상으로 업그레이드
```

### 문제 3: IDP 연결 실패

**증상**:
```
Error: Failed to connect to IDP: Connection refused
```

**해결책**:
```bash
# 1. IDP 서버 실행 확인
curl http://localhost:8080/realms/master/.well-known/openid-configuration

# 2. 네트워크 연결 확인
ping localhost

# 3. 방화벽 규칙 확인
sudo iptables -L -n | grep 8080

# 4. IDP 비활성화 (테스트용)
# config.yaml에서:
idp:
  enabled: false
```

### 문제 4: 높은 패킷 드롭률

**증상**:
```
vpn_packets_total{action="drop"} 높은 값
```

**디버깅**:
```bash
# 1. Verifier 로그 확인
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep bpf

# 2. eBPF 프로그램 통계
sudo bpftool prog show id 42 --json | jq

# 3. 맵 조회 확인
sudo bpftool map dump name ip_role_map

# 4. 감사 로그 확인
vpn-router audit events --action deny
```

---

## 다음 단계

### 프로덕션 배포 체크리스트

- [ ] 커널 버전 확인 (5.10 LTS 이상)
- [ ] IDP 프로덕션 엔드포인트 설정
- [ ] TLS/SSL 인증서 구성
- [ ] 방화벽 규칙 구성
- [ ] 모니터링 및 알림 설정
- [ ] 백업 및 재해 복구 계획
- [ ] 로그 로테이션 설정
- [ ] 성능 튜닝 (CPU 친화도, 버퍼 크기)

### 추가 학습 자료

- **eBPF 프로그래밍**: [eBPF.io](https://ebpf.io/)
- **Rust eBPF**: [Aya Book](https://aya-rs.dev/book/)
- **VPN 프로토콜**: [Noise Protocol](http://noiseprotocol.org/)
- **RBAC 설계**: [NIST RBAC](https://csrc.nist.gov/projects/role-based-access-control)

---

## 지원

문제가 발생하거나 질문이 있으신 경우:
- **이슈 트래커**: https://github.com/your-org/vpn-router/issues
- **문서**: https://docs.vpn-router.example.com
- **커뮤니티**: https://discord.gg/vpn-router

---

**상태**: 빠른 시작 가이드 완료.