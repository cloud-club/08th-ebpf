# 메트릭 API: Prometheus 엔드포인트

**엔드포인트**: `/metrics`
**프로토콜**: HTTP
**형식**: Prometheus 텍스트 형식
**상태**: Phase 1 설계

## 개요

VPN 라우터 데몬은 Prometheus 호환 메트릭을 `/metrics` 엔드포인트를 통해 노출합니다. 모든 메트릭은 eBPF 맵과 사용자 공간 통계에서 수집됩니다.

---

## 엔드포인트

```
GET http://localhost:9090/metrics
```

**인증**: 없음 (내부 네트워크 전용 권장)

**응답 예제**:
```
# HELP vpn_packets_total Total number of packets processed
# TYPE vpn_packets_total counter
vpn_packets_total{direction="ingress",action="pass",hook="xdp"} 1234567
vpn_packets_total{direction="ingress",action="drop",hook="xdp"} 890
vpn_packets_total{direction="ingress",action="pass",hook="tc"} 850432
vpn_packets_total{direction="egress",action="pass",hook="tc"} 848123

# HELP vpn_latency_microseconds Packet processing latency
# TYPE vpn_latency_microseconds summary
vpn_latency_microseconds{hook="xdp",quantile="0.5"} 7.2
vpn_latency_microseconds{hook="xdp",quantile="0.95"} 9.8
vpn_latency_microseconds{hook="xdp",quantile="0.99"} 12.3
vpn_latency_microseconds_sum{hook="xdp"} 8932145.6
vpn_latency_microseconds_count{hook="xdp"} 1234567
...
```

---

## 메트릭 카탈로그

### 1. 패킷 통계

#### `vpn_packets_total`
총 처리된 패킷 수 (카운터)

**레이블**:
- `direction`: ingress | egress
- `action`: pass | drop
- `hook`: xdp | tc_ingress | tc_egress

**예제**:
```
vpn_packets_total{direction="ingress",action="pass",hook="xdp"} 1234567
vpn_packets_total{direction="ingress",action="drop",hook="xdp"} 890
```

---

#### `vpn_bytes_total`
총 처리된 바이트 수 (카운터)

**레이블**:
- `direction`: ingress | egress
- `hook`: xdp | tc_ingress | tc_egress

**예제**:
```
vpn_bytes_total{direction="ingress",hook="xdp"} 1024567890
vpn_bytes_total{direction="egress",hook="tc"} 998765432
```

---

### 2. 지연시간 메트릭

#### `vpn_latency_microseconds`
패킷 처리 지연시간 (서머리)

**레이블**:
- `hook`: xdp | tc_ingress | tc_egress
- `quantile`: 0.5 | 0.95 | 0.99

**예제**:
```
vpn_latency_microseconds{hook="xdp",quantile="0.5"} 7.2
vpn_latency_microseconds{hook="xdp",quantile="0.95"} 9.8
vpn_latency_microseconds{hook="xdp",quantile="0.99"} 12.3
vpn_latency_microseconds_sum{hook="xdp"} 8932145.6
vpn_latency_microseconds_count{hook="xdp"} 1234567
```

**계산 방법**:
- eBPF: `bpf_ktime_get_ns()`로 시작/종료 시간 측정
- 사용자 공간: Per-CPU 맵에서 히스토그램 집계
- HdrHistogram 라이브러리로 분위수 계산

---

### 3. 정책 메트릭

#### `vpn_policy_lookups_total`
정책 조회 횟수 (카운터)

**레이블**:
- `map`: ip_role | role_acl | network_zone
- `result`: hit | miss

**예제**:
```
vpn_policy_lookups_total{map="ip_role",result="hit"} 1230000
vpn_policy_lookups_total{map="ip_role",result="miss"} 4567
vpn_policy_lookups_total{map="role_acl",result="hit"} 1225433
```

---

#### `vpn_policy_violations_total`
정책 위반 횟수 (카운터)

**레이블**:
- `role`: 역할 이름 (admin, guest, ...)
- `action`: deny
- `rule_id`: ACL 규칙 ID (선택)

**예제**:
```
vpn_policy_violations_total{role="guest",action="deny"} 123
vpn_policy_violations_total{role="developer",action="deny"} 45
```

---

#### `vpn_policy_entries`
현재 로드된 정책 항목 수 (게이지)

**레이블**:
- `type`: ip_role | acl_rule

**예제**:
```
vpn_policy_entries{type="ip_role"} 1234
vpn_policy_entries{type="acl_rule"} 456
```

---

### 4. VPN 세션 메트릭

#### `vpn_sessions_active`
현재 활성 VPN 세션 수 (게이지)

**레이블**: 없음

**예제**:
```
vpn_sessions_active 3
```

---

#### `vpn_session_packets_total`
VPN 세션 패킷 통계 (카운터)

**레이블**:
- `tunnel_id`: 터널 ID
- `direction`: encrypted | decrypted

**예제**:
```
vpn_session_packets_total{tunnel_id="1001",direction="encrypted"} 842103
vpn_session_packets_total{tunnel_id="1001",direction="decrypted"} 839982
```

---

#### `vpn_session_errors_total`
VPN 세션 오류 통계 (카운터)

**레이블**:
- `tunnel_id`: 터널 ID
- `error_type`: replay_detected | auth_failure | decrypt_failure

**예제**:
```
vpn_session_errors_total{tunnel_id="1001",error_type="replay_detected"} 0
vpn_session_errors_total{tunnel_id="1002",error_type="auth_failure"} 3
```

---

#### `vpn_session_key_rotations_total`
키 교체 횟수 (카운터)

**레이블**:
- `tunnel_id`: 터널 ID

**예제**:
```
vpn_session_key_rotations_total{tunnel_id="1001"} 12
```

---

### 5. eBPF 맵 메트릭

#### `vpn_ebpf_map_entries`
eBPF 맵 항목 수 (게이지)

**레이블**:
- `map_name`: ip_role_map | role_acl_map | session_key_map | stats_map
- `status`: current | max

**예제**:
```
vpn_ebpf_map_entries{map_name="ip_role_map",status="current"} 1234
vpn_ebpf_map_entries{map_name="ip_role_map",status="max"} 10000
vpn_ebpf_map_entries{map_name="role_acl_map",status="current"} 45
vpn_ebpf_map_entries{map_name="role_acl_map",status="max"} 100
```

---

#### `vpn_ebpf_map_usage_ratio`
eBPF 맵 사용률 (게이지, 0.0-1.0)

**레이블**:
- `map_name`: 맵 이름

**예제**:
```
vpn_ebpf_map_usage_ratio{map_name="ip_role_map"} 0.1234
vpn_ebpf_map_usage_ratio{map_name="role_acl_map"} 0.45
```

---

#### `vpn_ebpf_map_operations_total`
eBPF 맵 작업 횟수 (카운터)

**레이블**:
- `map_name`: 맵 이름
- `operation`: lookup | update | delete

**예제**:
```
vpn_ebpf_map_operations_total{map_name="ip_role_map",operation="lookup"} 1234567
vpn_ebpf_map_operations_total{map_name="ip_role_map",operation="update"} 125
vpn_ebpf_map_operations_total{map_name="ip_role_map",operation="delete"} 23
```

---

### 6. eBPF 프로그램 메트릭

#### `vpn_ebpf_program_run_count_total`
eBPF 프로그램 실행 횟수 (카운터)

**레이블**:
- `program`: xdp | tc_ingress | tc_egress
- `interface`: eth0 | wg0 | ...

**예제**:
```
vpn_ebpf_program_run_count_total{program="xdp",interface="eth0"} 1234567
vpn_ebpf_program_run_count_total{program="tc_ingress",interface="wg0"} 850432
```

---

#### `vpn_ebpf_program_run_time_nanoseconds_total`
eBPF 프로그램 총 실행 시간 (카운터)

**레이블**:
- `program`: xdp | tc_ingress | tc_egress

**예제**:
```
vpn_ebpf_program_run_time_nanoseconds_total{program="xdp"} 8932145678
```

---

### 7. IDP 통합 메트릭

#### `vpn_idp_sync_total`
IDP 동기화 횟수 (카운터)

**레이블**:
- `status`: success | failure

**예제**:
```
vpn_idp_sync_total{status="success"} 245
vpn_idp_sync_total{status="failure"} 3
```

---

#### `vpn_idp_sync_duration_seconds`
IDP 동기화 소요 시간 (히스토그램)

**레이블**: 없음

**예제**:
```
vpn_idp_sync_duration_seconds_bucket{le="1"} 240
vpn_idp_sync_duration_seconds_bucket{le="2"} 245
vpn_idp_sync_duration_seconds_bucket{le="5"} 248
vpn_idp_sync_duration_seconds_bucket{le="+Inf"} 248
vpn_idp_sync_duration_seconds_sum 523.4
vpn_idp_sync_duration_seconds_count 248
```

---

#### `vpn_idp_users_synced`
마지막 동기화에서 가져온 사용자 수 (게이지)

**레이블**: 없음

**예제**:
```
vpn_idp_users_synced 125
```

---

#### `vpn_idp_connected`
IDP 연결 상태 (게이지, 1 = 연결됨, 0 = 연결 끊김)

**레이블**: 없음

**예제**:
```
vpn_idp_connected 1
```

---

### 8. 시스템 메트릭

#### `vpn_daemon_uptime_seconds`
데몬 가동 시간 (게이지)

**레이블**: 없음

**예제**:
```
vpn_daemon_uptime_seconds 302415
```

---

#### `vpn_daemon_restarts_total`
데몬 재시작 횟수 (카운터)

**레이블**: 없음

**예제**:
```
vpn_daemon_restarts_total 2
```

---

#### `vpn_daemon_memory_bytes`
데몬 메모리 사용량 (게이지)

**레이블**:
- `type`: resident | virtual

**예제**:
```
vpn_daemon_memory_bytes{type="resident"} 52428800
vpn_daemon_memory_bytes{type="virtual"} 104857600
```

---

#### `vpn_daemon_cpu_seconds_total`
데몬 CPU 사용 시간 (카운터)

**레이블**: 없음

**예제**:
```
vpn_daemon_cpu_seconds_total 1234.56
```

---

### 9. CPU 통계

#### `vpn_cpu_usage_percent`
CPU별 사용률 (게이지)

**레이블**:
- `cpu`: CPU ID (0, 1, 2, ...)

**예제**:
```
vpn_cpu_usage_percent{cpu="0"} 25.3
vpn_cpu_usage_percent{cpu="1"} 18.7
vpn_cpu_usage_percent{cpu="2"} 32.1
```

---

### 10. 오류 메트릭

#### `vpn_errors_total`
오류 횟수 (카운터)

**레이블**:
- `component`: xdp | tc | daemon | idp | crypto
- `error_type`: verifier_failed | map_lookup_error | alloc_failed | ...

**예제**:
```
vpn_errors_total{component="tc",error_type="map_lookup_error"} 12
vpn_errors_total{component="daemon",error_type="idp_timeout"} 3
```

---

## Prometheus 스크랩 설정

### prometheus.yml

```yaml
scrape_configs:
  - job_name: 'vpn-router'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:9090']
        labels:
          service: 'vpn-router'
          environment: 'production'
          datacenter: 'dc1'
```

---

## 권장 알림 규칙

### alerts.yml

```yaml
groups:
  - name: vpn_router_alerts
    interval: 30s
    rules:
      # 높은 드롭률
      - alert: HighPacketDropRate
        expr: |
          rate(vpn_packets_total{action="drop"}[5m])
          / rate(vpn_packets_total[5m])
          > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "높은 패킷 드롭률 감지 ({{ $value | humanizePercentage }})"
          description: "{{ $labels.hook }}에서 패킷 드롭률이 5%를 초과했습니다."

      # 높은 지연시간
      - alert: HighPacketLatency
        expr: |
          vpn_latency_microseconds{quantile="0.99"} > 50
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "높은 패킷 처리 지연시간 ({{ $value }}µs)"
          description: "{{ $labels.hook }}의 p99 지연시간이 50µs를 초과했습니다."

      # 맵 용량 부족
      - alert: eBPFMapNearCapacity
        expr: vpn_ebpf_map_usage_ratio > 0.8
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "eBPF 맵 용량 80% 초과 ({{ $labels.map_name }})"
          description: "맵 확장이 곧 필요할 수 있습니다."

      # IDP 연결 끊김
      - alert: IDPDisconnected
        expr: vpn_idp_connected == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "IDP 연결 끊김"
          description: "IDP와의 연결이 끊어졌습니다. 캐시된 정책을 사용 중입니다."

      # 정책 위반 급증
      - alert: PolicyViolationSpike
        expr: |
          rate(vpn_policy_violations_total[5m]) > 100
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "정책 위반 급증 ({{ $value }}/s)"
          description: "{{ $labels.role }} 역할에서 비정상적으로 많은 정책 위반이 감지되었습니다."

      # VPN 세션 오류
      - alert: VPNSessionErrors
        expr: |
          rate(vpn_session_errors_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "VPN 세션 오류 (tunnel {{ $labels.tunnel_id }})"
          description: "터널에서 {{ $labels.error_type }} 오류가 급증했습니다."

      # 데몬 다운
      - alert: DaemonDown
        expr: up{job="vpn-router"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "VPN 라우터 데몬 다운"
          description: "VPN 라우터 데몬이 응답하지 않습니다."
```

---

## Grafana 대시보드

### 권장 패널

**1. 개요**
- 가동 시간 게이지
- 활성 세션 수
- 초당 패킷 수 (그래프)
- 평균 지연시간 (그래프)

**2. 패킷 통계**
- 인그레스/이그레스 패킷 (적층 영역 차트)
- 드롭률 (%) (선 차트)
- 훅별 패킷 분포 (파이 차트)

**3. 지연시간**
- p50/p95/p99 지연시간 (다중 선 차트)
- 히트맵 (지연시간 분포)

**4. 정책**
- 정책 조회 성공률 (게이지)
- 역할별 위반 (막대 차트)
- 시간별 위반 추세 (선 차트)

**5. VPN 세션**
- 세션 상태 분포 (파이 차트)
- 터널별 트래픽 (적층 영역 차트)
- 오류율 (선 차트)

**6. eBPF 맵**
- 맵 사용률 (게이지)
- 맵 작업 속도 (선 차트)

**7. IDP**
- 동기화 성공률 (게이지)
- 동기화 소요 시간 (히스토그램)
- 연결 상태 (상태 표시등)

**8. 시스템 리소스**
- CPU 사용률 (그래프)
- 메모리 사용량 (그래프)
- CPU별 부하 (히트맵)

---

## PromQL 쿼리 예제

### 초당 패킷 수
```promql
rate(vpn_packets_total[5m])
```

### 드롭률
```promql
rate(vpn_packets_total{action="drop"}[5m])
/ rate(vpn_packets_total[5m])
```

### 평균 지연시간
```promql
rate(vpn_latency_microseconds_sum[5m])
/ rate(vpn_latency_microseconds_count[5m])
```

### 정책 조회 성공률
```promql
sum(rate(vpn_policy_lookups_total{result="hit"}[5m]))
/ sum(rate(vpn_policy_lookups_total[5m]))
```

### 상위 5개 위반 역할
```promql
topk(5, sum by (role) (rate(vpn_policy_violations_total[5m])))
```

### 맵 확장 필요 예측 (선형 회귀)
```promql
predict_linear(vpn_ebpf_map_entries{map_name="ip_role_map",status="current"}[1h], 3600)
> vpn_ebpf_map_entries{map_name="ip_role_map",status="max"}
```

---

## 메트릭 수집 성능

### 오버헤드
- eBPF 통계 수집: **< 10ns** per 패킷 (per-CPU 맵)
- 사용자 공간 집계: **5초** 간격 (비동기)
- Prometheus 스크랩: **15초** 간격 (권장)

### 카디널리티
- 예상 메트릭 시계열: **~500** (맵 10개 × 터널 10개 × 훅 3개)
- 레이블 값 제한: 역할 100개, 터널 10개

---

## 참조

- Prometheus 문서: https://prometheus.io/docs/
- Grafana 대시보드: https://grafana.com/docs/
- eBPF 통계: `data-model.md` - Packet Statistics 섹션

---

**상태**: 메트릭 API 설계 완료.