# CLI 인터페이스: VPN 라우터 관리 도구

**명령어**: `vpn-router` (또는 `vpnctl`)
**언어**: Rust
**상태**: Phase 1 설계

## 개요

`vpn-router` CLI는 VPN 라우터 제어 플레인 데몬과 상호작용하여 정책 관리, VPN 세션 제어, 시스템 모니터링 기능을 제공합니다.

---

## 설치 및 설정

### 설치
```bash
# Cargo를 통한 설치
cargo install vpn-router-cli

# 또는 바이너리 다운로드
wget https://releases.example.com/vpn-router-cli-latest-linux-x86_64.tar.gz
tar xzf vpn-router-cli-latest-linux-x86_64.tar.gz
sudo mv vpn-router /usr/local/bin/
```

### 설정 파일
```yaml
# ~/.vpn-router/config.yaml
daemon_url: http://localhost:9090
api_token: <JWT_TOKEN>
timeout_seconds: 30
output_format: table  # table | json | yaml
```

---

## 전역 플래그

모든 명령어에 사용 가능한 전역 플래그:

```
--daemon-url <URL>      데몬 API 엔드포인트 (기본값: http://localhost:9090)
--token <TOKEN>         API 인증 토큰
--format <FORMAT>       출력 형식: table | json | yaml (기본값: table)
--verbose, -v           상세 출력 활성화
--quiet, -q             오류만 출력
--no-color              색상 출력 비활성화
--help, -h              도움말 표시
--version, -V           버전 정보 표시
```

---

## 명령어 구조

```
vpn-router [GLOBAL_FLAGS] <COMMAND> [SUBCOMMAND] [OPTIONS] [ARGS]
```

### 명령어 그룹

1. **status** - 시스템 상태 확인
2. **policy** - 정책 관리
3. **session** - VPN 세션 관리
4. **idp** - IDP 통합 관리
5. **map** - eBPF 맵 관리
6. **audit** - 감사 로그 조회
7. **daemon** - 데몬 제어

---

## 1. STATUS - 시스템 상태

### `vpn-router status`

시스템 전체 상태 요약 표시

**예제**:
```bash
vpn-router status
```

**출력** (테이블 형식):
```
Status: Healthy
Uptime: 3d 12h 45m 23s
eBPF Programs: Loaded (3/3)
IDP Connected: Yes
Last Policy Sync: 2025-10-07 14:32:15 UTC

Programs:
  XDP (eth0): Running, 1.2M packets, avg 8.3µs
  TC Ingress (wg0): Running, 850K packets, avg 12.1µs
  TC Egress (wg0): Running, 840K packets, avg 10.5µs

Maps:
  ip_role_map: 1,234 / 10,000 (12.3%)
  role_acl_map: 45 / 100 (45.0%)
  session_key_map: 3 / 10 (30.0%)

Active VPN Sessions: 3
Total Encrypted Packets: 1,840,523
Total Decrypted Packets: 1,833,198
```

**플래그**:
- `--watch, -w` - 1초마다 자동 새로고침

---

### `vpn-router status health`

헬스체크만 간단히 표시 (스크립트용)

**예제**:
```bash
vpn-router status health
# 종료 코드: 0 (정상), 1 (비정상)
```

**출력**:
```
healthy
```

---

## 2. POLICY - 정책 관리

### `vpn-router policy list`

모든 정책 목록 조회

**예제**:
```bash
# 모든 정책
vpn-router policy list

# 특정 역할 필터링
vpn-router policy list --role admin

# JSON 출력
vpn-router policy list --format json
```

**출력** (테이블 형식):
```
ID                                     Type           Details
─────────────────────────────────────────────────────────────────
a1b2c3d4-...                           IP-Role        10.0.0.0/8 → admin
b2c3d4e5-...                           ACL Rule       admin: 10.0.0.0/8 → 172.16.0.0/12 (tcp/443) ALLOW
c3d4e5f6-...                           IP-Role        192.168.1.0/24 → guest
```

**플래그**:
- `--role <ROLE_ID>` - 특정 역할로 필터링
- `--type <TYPE>` - ip-role 또는 acl-rule로 필터링
- `--page <NUM>` - 페이지 번호
- `--page-size <NUM>` - 페이지당 항목 수

---

### `vpn-router policy show <POLICY_ID>`

특정 정책 세부 정보 조회

**예제**:
```bash
vpn-router policy show a1b2c3d4-...
```

**출력**:
```
Policy ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Type: IP-Role Mapping
Created: 2025-10-07 10:15:32 UTC
Updated: 2025-10-07 14:22:18 UTC
Version: 3

IP Range: 10.0.0.0/8
Role ID: 1001
Role Name: admin
Expires At: Never
Source: IDP (provider: auth0, user: alice@example.com)
```

---

### `vpn-router policy add ip-role`

IP-역할 매핑 추가

**예제**:
```bash
# 대화형 모드
vpn-router policy add ip-role

# 비대화형 모드
vpn-router policy add ip-role \
  --ip-range 10.0.0.0/8 \
  --role-id 1001 \
  --role-name admin \
  --expires-at 2025-12-31T23:59:59Z
```

**플래그**:
- `--ip-range <CIDR>` - IP 범위 (필수)
- `--role-id <ID>` - 역할 ID (필수)
- `--role-name <NAME>` - 역할 이름 (필수)
- `--expires-at <TIMESTAMP>` - 만료 시간 (선택, ISO 8601 형식)
- `--source <SOURCE>` - 소스 (idp | static | dynamic)

---

### `vpn-router policy add acl-rule`

ACL 규칙 추가

**예제**:
```bash
vpn-router policy add acl-rule \
  --role-id 1001 \
  --role-name admin \
  --src 10.0.0.0/8 \
  --dst 172.16.0.0/12 \
  --protocol tcp \
  --dst-ports 443,8443 \
  --action allow \
  --priority 10 \
  --bidirectional \
  --log-violations \
  --description "Admin to internal services"
```

**플래그**:
- `--role-id <ID>` - 역할 ID (필수)
- `--role-name <NAME>` - 역할 이름 (필수)
- `--src <CIDR>` - 소스 네트워크 (필수)
- `--dst <CIDR>` - 목적지 네트워크 (필수)
- `--protocol <PROTO>` - any | tcp | udp | icmp (기본값: any)
- `--dst-ports <PORTS>` - 목적지 포트 (예: 80, 80-443, 80,443,8080)
- `--action <ACTION>` - allow | deny (필수)
- `--priority <NUM>` - 우선순위 0-255 (기본값: 128)
- `--bidirectional` - 양방향 규칙
- `--log-violations` - 위반 시 로그 기록
- `--description <TEXT>` - 설명

---

### `vpn-router policy update <POLICY_ID>`

정책 업데이트

**예제**:
```bash
vpn-router policy update a1b2c3d4-... --expires-at 2026-01-01T00:00:00Z
```

---

### `vpn-router policy delete <POLICY_ID>`

정책 삭제

**예제**:
```bash
vpn-router policy delete a1b2c3d4-...

# 확인 없이 삭제
vpn-router policy delete a1b2c3d4-... --yes
```

---

### `vpn-router policy reload`

설정 파일 또는 IDP에서 정책 다시 로드

**예제**:
```bash
vpn-router policy reload

# 특정 파일에서 로드
vpn-router policy reload --from-file /etc/vpn/policies.yaml
```

---

### `vpn-router policy import <FILE>`

YAML/JSON 파일에서 정책 일괄 가져오기

**예제**:
```bash
vpn-router policy import policies.yaml
```

**파일 형식** (YAML):
```yaml
policies:
  - type: ip_role_mapping
    ip_range: 10.0.0.0/8
    role_id: 1001
    role_name: admin
  - type: acl_rule
    role_id: 1001
    role_name: admin
    src: 10.0.0.0/8
    dst: 172.16.0.0/12
    protocol: tcp
    dst_ports: "443"
    action: allow
    priority: 10
    description: "Admin access to internal"
```

---

### `vpn-router policy export`

현재 정책을 YAML/JSON으로 내보내기

**예제**:
```bash
vpn-router policy export --format yaml > policies.yaml
```

---

## 3. SESSION - VPN 세션 관리

### `vpn-router session list`

활성 VPN 세션 목록 조회

**예제**:
```bash
vpn-router session list
```

**출력**:
```
Tunnel ID  Peer IP         State         Created                Encrypted  Decrypted  Key Rotations
────────────────────────────────────────────────────────────────────────────────────────────────────
1001       192.168.100.5   Established   2025-10-07 08:00:15    842,103    839,982    2
1002       192.168.100.6   Established   2025-10-07 09:15:42    521,034    520,112    1
1003       192.168.100.7   Handshake     2025-10-07 14:30:01    0          0          0
```

---

### `vpn-router session show <TUNNEL_ID>`

특정 VPN 세션 세부 정보 조회

**예제**:
```bash
vpn-router session show 1001
```

**출력**:
```
Tunnel ID: 1001
Peer IP: 192.168.100.5
State: Established
Created: 2025-10-07 08:00:15 UTC
Expires: 2025-10-07 09:00:15 UTC
Last Activity: 2025-10-07 08:55:32 UTC

Statistics:
  Packets Encrypted: 842,103
  Packets Decrypted: 839,982
  Replay Detected: 0
  Auth Failures: 0

Key Rotation Count: 2
Last Key Rotation: 2025-10-07 08:30:15 UTC
Next Key Rotation: 2025-10-07 09:00:15 UTC
```

---

### `vpn-router session create`

새 VPN 세션 시작

**예제**:
```bash
# 대화형
vpn-router session create

# 비대화형
vpn-router session create --peer-ip 192.168.100.10 --tunnel-id 1005
```

**플래그**:
- `--peer-ip <IP>` - 피어 IP 주소 (필수)
- `--tunnel-id <ID>` - 터널 ID (선택, 생략 시 자동 할당)

---

### `vpn-router session delete <TUNNEL_ID>`

VPN 세션 종료

**예제**:
```bash
vpn-router session delete 1003
```

---

### `vpn-router session rotate-key <TUNNEL_ID>`

세션 키 수동 교체

**예제**:
```bash
vpn-router session rotate-key 1001
```

---

## 4. IDP - IDP 통합 관리

### `vpn-router idp config`

현재 IDP 설정 조회

**예제**:
```bash
vpn-router idp config
```

**출력**:
```
Provider: OIDC
Enabled: Yes
Issuer URL: https://auth.example.com
Client ID: vpn-router-client
Scopes: openid, profile, email, roles
Sync Interval: 300 seconds (5 minutes)
Last Sync: 2025-10-07 14:32:15 UTC
```

---

### `vpn-router idp config set`

IDP 설정 업데이트

**예제**:
```bash
vpn-router idp config set \
  --provider oidc \
  --issuer-url https://auth.example.com \
  --client-id vpn-router-client \
  --client-secret <SECRET> \
  --scopes openid,profile,email,roles \
  --sync-interval 300
```

---

### `vpn-router idp sync`

IDP에서 정책 즉시 동기화

**예제**:
```bash
vpn-router idp sync
```

**출력**:
```
Syncing with IDP...
Users synced: 125
Roles synced: 8
Policies updated: 342
Completed in 2.3 seconds
```

---

### `vpn-router idp test-connection`

IDP 연결 테스트

**예제**:
```bash
vpn-router idp test-connection
```

**출력**:
```
Testing connection to https://auth.example.com...
✓ OIDC discovery successful
✓ Token endpoint reachable
✓ User info endpoint reachable
Connection: OK
```

---

## 5. MAP - eBPF 맵 관리

### `vpn-router map list`

모든 eBPF 맵 정보 조회

**예제**:
```bash
vpn-router map list
```

**출력**:
```
Name               Type                Key Size  Value Size  Max Entries  Current  Usage
─────────────────────────────────────────────────────────────────────────────────────────
ip_role_map        LPM_TRIE            8         16          10,000       1,234    12.3%
role_acl_map       HASH                4         1,088       100          45       45.0%
session_key_map    HASH                8         72          10           3        30.0%
audit_ringbuf      RINGBUF             N/A       N/A         262,144      N/A      N/A
stats_map          PERCPU_ARRAY        4         64          3            3        100.0%
```

---

### `vpn-router map info <MAP_NAME>`

특정 맵 세부 정보 조회

**예제**:
```bash
vpn-router map info ip_role_map
```

**출력**:
```
Map Name: ip_role_map
Type: BPF_MAP_TYPE_LPM_TRIE
Key Size: 8 bytes
Value Size: 16 bytes
Max Entries: 10,000
Current Entries: 1,234
Usage: 12.3%
Pinned Path: /sys/fs/bpf/vpn/ip_role_map
Created: 2025-10-07 08:00:00 UTC
Last Updated: 2025-10-07 14:32:15 UTC
```

---

### `vpn-router map dump <MAP_NAME>`

맵 내용 전체 덤프

**예제**:
```bash
# 테이블 출력
vpn-router map dump ip_role_map

# JSON 출력
vpn-router map dump ip_role_map --format json > ip_role_map_dump.json

# 파일로 저장
vpn-router map dump ip_role_map --output dump.yaml
```

**출력** (테이블 형식):
```
IP Range          Prefix Len  Role ID  Role Name  Expires At           Version
───────────────────────────────────────────────────────────────────────────────
10.0.0.0          8           1001     admin      Never                3
192.168.1.0       24          1002     guest      2025-12-31 23:59:59  1
```

---

## 6. AUDIT - 감사 로그 조회

### `vpn-router audit events`

감사 이벤트 조회

**예제**:
```bash
# 최근 100개 이벤트
vpn-router audit events

# 시간 범위 지정
vpn-router audit events \
  --start-time "2025-10-07 00:00:00" \
  --end-time "2025-10-07 23:59:59"

# 거부된 이벤트만
vpn-router audit events --action deny

# 특정 역할 필터링
vpn-router audit events --role admin
```

**출력**:
```
Timestamp              Event Type          Src                    Dst                    Action  Role
───────────────────────────────────────────────────────────────────────────────────────────────────────
2025-10-07 14:55:32    PolicyViolation     10.0.0.5:52341        172.16.10.8:22         DENY    guest
2025-10-07 14:55:31    PolicyAllow         10.0.0.12:45123       172.16.5.100:443       ALLOW   admin
2025-10-07 14:55:30    PolicyViolation     192.168.1.100:33421   172.16.20.50:3389      DENY    guest
```

**플래그**:
- `--start-time <TIME>` - 시작 시간 (ISO 8601 또는 "YYYY-MM-DD HH:MM:SS")
- `--end-time <TIME>` - 종료 시간
- `--action <ACTION>` - allow | deny
- `--role <ROLE_ID>` - 역할 ID 또는 이름
- `--page <NUM>` - 페이지 번호
- `--page-size <NUM>` - 페이지당 항목 수 (기본값: 100)
- `--follow, -f` - 실시간 스트리밍 (tail -f 같은 동작)

---

### `vpn-router audit export`

감사 로그를 파일로 내보내기

**예제**:
```bash
vpn-router audit export \
  --start-time "2025-10-01" \
  --end-time "2025-10-31" \
  --format json \
  --output october-audit.json
```

---

## 7. DAEMON - 데몬 제어

### `vpn-router daemon start`

데몬 시작 (systemd 통합)

**예제**:
```bash
sudo vpn-router daemon start

# systemd를 통해
sudo systemctl start vpn-router
```

---

### `vpn-router daemon stop`

데몬 중지

**예제**:
```bash
sudo vpn-router daemon stop
```

---

### `vpn-router daemon restart`

데몬 재시작

**예제**:
```bash
sudo vpn-router daemon restart
```

---

### `vpn-router daemon logs`

데몬 로그 조회

**예제**:
```bash
# 마지막 100줄
vpn-router daemon logs

# 실시간 팔로우
vpn-router daemon logs --follow

# 특정 레벨만
vpn-router daemon logs --level error
```

**플래그**:
- `--follow, -f` - 실시간 로그 스트리밍
- `--lines <NUM>` - 출력 줄 수 (기본값: 100)
- `--level <LEVEL>` - 로그 레벨: error | warn | info | debug | trace

---

## 출력 형식

### Table (기본값)
```
vpn-router policy list
```
사람이 읽기 좋은 테이블 형식

### JSON
```
vpn-router policy list --format json
```
기계 파싱용 JSON 출력

### YAML
```
vpn-router policy list --format yaml
```
설정 파일 호환 YAML 출력

---

## 자동 완성

### Bash
```bash
echo 'eval "$(vpn-router completions bash)"' >> ~/.bashrc
source ~/.bashrc
```

### Zsh
```zsh
echo 'eval "$(vpn-router completions zsh)"' >> ~/.zshrc
source ~/.zshrc
```

### Fish
```fish
vpn-router completions fish | source
```

---

## 종료 코드

| 코드 | 의미 |
|------|------|
| 0 | 성공 |
| 1 | 일반 오류 |
| 2 | 잘못된 사용법 (인자 오류) |
| 3 | 인증 실패 |
| 4 | 데몬 연결 실패 |
| 5 | 리소스를 찾을 수 없음 (404) |
| 6 | 충돌 (409) |
| 7 | 서버 오류 (500) |

---

## 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `VPN_ROUTER_URL` | 데몬 API URL | `http://localhost:9090` |
| `VPN_ROUTER_TOKEN` | API 인증 토큰 | (없음) |
| `VPN_ROUTER_FORMAT` | 출력 형식 | `table` |
| `VPN_ROUTER_NO_COLOR` | 색상 비활성화 (1 = 비활성화) | (없음) |
| `VPN_ROUTER_TIMEOUT` | API 타임아웃 (초) | `30` |

---

## 예제 워크플로우

### 1. 새 사용자 정책 추가
```bash
# 1. IP-역할 매핑 추가
vpn-router policy add ip-role \
  --ip-range 10.0.50.0/24 \
  --role-id 1003 \
  --role-name developer

# 2. ACL 규칙 추가 (개발 서버 접근)
vpn-router policy add acl-rule \
  --role-id 1003 \
  --role-name developer \
  --src 10.0.50.0/24 \
  --dst 172.16.100.0/24 \
  --protocol tcp \
  --dst-ports 22,80,443 \
  --action allow \
  --description "Developer access to dev servers"

# 3. 정책 적용 확인
vpn-router policy list --role developer
```

### 2. VPN 세션 모니터링
```bash
# 실시간 상태 모니터링
vpn-router status --watch

# 특정 세션 상세 조회
vpn-router session show 1001

# 문제가 있는 세션 재시작
vpn-router session delete 1001
vpn-router session create --peer-ip 192.168.100.5 --tunnel-id 1001
```

### 3. 감사 로그 분석
```bash
# 오늘 거부된 모든 접근 시도
vpn-router audit events \
  --action deny \
  --start-time "$(date +%Y-%m-%d) 00:00:00"

# 특정 역할의 활동 추적
vpn-router audit events --role admin --follow

# 월별 보고서 생성
vpn-router audit export \
  --start-time "2025-10-01" \
  --end-time "2025-10-31" \
  --format json \
  --output october-report.json
```

---

## 참조

- 제어 플레인 API: `control-api.yaml`
- 메트릭 API: `metrics-api.md`
- 데이터 모델: `data-model.md`

---

**상태**: CLI 인터페이스 설계 완료.
