# Kong Gateway eBPF Monitor - Linux 전용

Kong Gateway의 HTTP 트래픽을 실시간으로 모니터링하는 eBPF 기반 사이드카 컨테이너입니다.

## ⚠️ 중요 사항

**이 프로젝트는 Linux 환경에서만 빌드 및 실행할 수 있습니다.** eBPF는 Linux 커널 전용 기술이므로 macOS나 Windows에서는 빌드할 수 없습니다.

## 🏗️ 아키텍처

### eBPF 프로그램 구조

```
bpf/kong_uprobe_sidecar.c
├── HTTP 요청/응답 모니터링
├── Kong Gateway 프로세스 추적
├── 실시간 이벤트 스트리밍
└── 성능 메트릭 수집
```

### BPF Maps

- **`kong_processes`**: Kong 프로세스 추적 (HASH)
- **`request_start_times`**: 요청 시작 시간 추적 (HASH)
- **`http_requests`**: HTTP 요청 데이터 (HASH)
- **`events`**: 실시간 이벤트 스트림 (RINGBUF)

### Uprobe 핸들러

- **`uprobe_kong_http_request`**: Kong HTTP 요청 처리
- **`uprobe_kong_http_response`**: Kong HTTP 응답 처리
- **`uprobe_read`**: 시스템 read 호출 모니터링
- **`uprobe_write`**: 시스템 write 호출 모니터링
- **`uprobe_kong_lua_handler`**: Kong Lua 핸들러 모니터링

## 🚀 빌드 및 배포

### Docker 이미지 빌드

```bash
# 멀티 아키텍처 빌드 및 푸시 (기본)
make buildx

# 로컬 빌드만
make build

# 이미지 푸시만
make push

# 도움말
make help
```

### 변수 설정

```bash
# 이미지 이름 변경
make buildx IMG=my-registry.com/kong-watcher:v1.0.0

# 버전 변경
make buildx VERSION=2.0.0

# 커밋 SHA 변경
make buildx COMMIT_SHA=abc123
```

## 🐳 Kubernetes 사이드카 배포

### 1. 사이드카 설정

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kong-gateway-with-monitor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kong-gateway-with-monitor
  template:
    metadata:
      labels:
        app: kong-gateway-with-monitor
    spec:
      containers:
      - name: kong-gateway
        image: kong:3.4
        # Kong Gateway 설정...
        
      - name: kong-ebpf-monitor
        image: kong-watcher:latest
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_RESOURCE
            - NET_ADMIN
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: dev
          mountPath: /host/dev
          readOnly: true
        env:
        - name: LOG_LEVEL
          value: "info"
        - name: ENABLE_JSON_LOG
          value: "true"
        - name: KONG_PROCESS_NAME
          value: "kong"
        - name: STATS_INTERVAL
          value: "30s"
        resources:
          limits:
            memory: "256Mi"
            cpu: "200m"
          requests:
            memory: "128Mi"
            cpu: "100m"
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: dev
        hostPath:
          path: /dev
```

### 2. 배포 명령어

```bash
# Kubernetes 배포
kubectl apply -f kong-sidecar.yaml

# 상태 확인
kubectl get pods -l app=kong-gateway-with-monitor

# 로그 확인
kubectl logs -l app=kong-gateway-with-monitor -c kong-ebpf-monitor
```

## 🔧 로컬 테스트

### 1. Kong Gateway 실행

```bash
# Kong Gateway 설치 및 실행
docker run -d --name kong \
    -e "KONG_DATABASE=off" \
    -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" \
    -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" \
    -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
    -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" \
    -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
    -p 8000:8000 \
    -p 8001:8001 \
    kong:3.4
```

### 2. eBPF 모니터 실행

```bash
# 빌드 후 실행
make build
sudo ./kong-watcher
```

### 3. 테스트 요청

```bash
# Kong Gateway에 테스트 요청
curl -X GET http://localhost:8000/
curl -X POST http://localhost:8000/test \
    -H "Content-Type: application/json" \
    -d '{"test": "data"}'
```

## 📊 모니터링 데이터

### 수집되는 메트릭

- **HTTP 요청 수**: 총 요청 수
- **HTTP 응답 수**: 총 응답 수
- **평균 응답 시간**: 요청-응답 간격
- **에러 수**: 4xx, 5xx 응답 수
- **처리 중인 요청**: 현재 처리 중인 요청 수

### 로그 출력 예시

```json
{
  "level": "info",
  "msg": "HTTP Request",
  "method": "GET",
  "host": "localhost:8000",
  "path": "/",
  "status_code": 200,
  "response_time_ns": 1500000,
  "error_code": 0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## 🛠️ 개발 환경 설정

### 로컬 개발

```bash
# Go 모듈 정리
go mod tidy

# eBPF 코드 생성
GOOS=linux GOARCH=amd64 go generate ./...

# 로컬 빌드
go build -o kong-watcher *.go

# 실행 (sudo 권한 필요)
sudo ./kong-watcher
```

### eBPF 디버깅

```bash
# bpftool 설치
sudo apt-get install bpftool  # Ubuntu/Debian
sudo yum install bpftool      # CentOS/RHEL
sudo apk add bpftool          # Alpine

# eBPF 프로그램 확인
sudo bpftool prog list
sudo bpftool map list
```

## 🔍 문제 해결

### 빌드 오류
```bash
# Linux 환경 확인
uname -s  # Linux여야 함

# 커널 버전 확인
uname -r  # 4.18+ 여야 함
```

### 실행 오류
```bash
# 권한 확인
sudo ./kong-watcher

# Kong 프로세스 확인
ps aux | grep kong
```

### 사이드카 오류
```bash
# Pod 로그 확인
kubectl logs <pod-name> -c kong-ebpf-monitor

# Pod 상태 확인
kubectl describe pod <pod-name>
```

## 📚 추가 자료

- [eBPF 공식 문서](https://ebpf.io/)
- [Cilium eBPF 라이브러리](https://github.com/cilium/ebpf)
- [Kong Gateway 문서](https://docs.konghq.com/)
- [Kubernetes 사이드카 패턴](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)

## 🤝 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

---

**⚠️ 주의**: 이 프로젝트는 Linux 환경에서만 빌드 및 실행할 수 있습니다. macOS나 Windows에서는 빌드할 수 없습니다.
