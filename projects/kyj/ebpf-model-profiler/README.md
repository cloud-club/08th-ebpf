# eBPF Model Serving Latency Profiler

## 프로젝트 소개
모델 서빙 API(FastAPI, Flask 등)의 시스템 콜 단위 지연을 eBPF로 추적하고 분석하는 도구입니다.
애플리케이션 코드 수정 없이 커널 레벨에서 요청→응답 과정을 분석합니다.

## 주요 기능
- **Syscall 추적**: openat, read, write, sendto, recvfrom 등 주요 시스템 콜 모니터링
- **Latency Breakdown**: 파일 I/O, 네트워크, 모델 추론 등 각 구간별 지연 시간 측정
- **다양한 Export 형식**: Prometheus, JSON, stdout 지원
- **요청 단위 추적**: 개별 API 요청의 전체 lifecycle 분석
- **Hotspot Detection**: 성능 병목 지점 자동 탐지

## 설치 방법

### 1. BCC 설치
```bash
# Ubuntu/Debian
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

# 또는 스크립트 사용
./scripts/setup_bcc.sh
```

### 2. Python 패키지 설치
```bash
pip install -e .
# 또는
make install
```

## 빠른 시작 가이드

### 1. 예제 애플리케이션 실행
```bash
cd examples/fastapi_app
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 2. 프로파일러 시작
```bash
# PID를 찾아서
ps aux | grep uvicorn

# 프로파일링 시작
sudo ebpf-profiler start --pid <PID>
```

### 3. 부하 테스트
```bash
cd examples/load_test
python simple_test.py
```

### 4. 결과 확인
```bash
# stdout 출력
sudo ebpf-profiler export --format stdout

# JSON 파일로 저장
sudo ebpf-profiler export --format json > results.json

# Prometheus 메트릭 노출
sudo ebpf-profiler export --format prometheus
```

## 사용 예제

### CLI 사용법
```bash
# 설정 파일을 사용한 프로파일링
sudo ebpf-profiler start --pid 1234 --config configs/production.yaml

# 특정 syscall만 추적
sudo ebpf-profiler start --pid 1234 --syscalls "read,write,sendto"

# 최소 지연 시간 필터링
sudo ebpf-profiler start --pid 1234 --min-duration 1000  # 1ms 이상만
```

## 아키텍처 개요

```
┌─────────────────────────────────────────────────────┐
│                  User Application                    │
│              (FastAPI/Flask Model Server)            │
└────────────────────┬────────────────────────────────┘
                     │ syscalls
                     ▼
┌─────────────────────────────────────────────────────┐
│                  Linux Kernel                        │
│  ┌──────────────────────────────────────────────┐  │
│  │           eBPF Programs (BCC)                │  │
│  │  - syscall_tracer.c                          │  │
│  │  - network_tracer.c                          │  │
│  │  - file_io_tracer.c                          │  │
│  └──────────────┬───────────────────────────────┘  │
└─────────────────┼───────────────────────────────────┘
                  │ perf events
                  ▼
┌─────────────────────────────────────────────────────┐
│            Python Collector (User Space)            │
│  ┌──────────────────────────────────────────────┐  │
│  │  tracer.py → event_handler.py                │  │
│  │            → request_tracker.py              │  │
│  │            → aggregator.py                   │  │
│  └──────────────┬───────────────────────────────┘  │
└─────────────────┼───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│                   Analyzer                          │
│  - Latency Breakdown                                │
│  - Hotspot Detection                                │
│  - Report Generation                                │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│                  Exporters                          │
│  - Prometheus (port 9090)                           │
│  - JSON files                                       │
│  - stdout (human-readable)                          │
└─────────────────────────────────────────────────────┘
```

## 요구사항
- Linux Kernel 4.9+ (eBPF 지원)
- Python 3.8+
- BCC (BPF Compiler Collection)
- Root 권한 (eBPF 프로그램 로드를 위해 필요)

## 문서
- [아키텍처 상세](docs/architecture.md)
- [개발 가이드](docs/development.md)
- [API 문서](docs/api.md)
- [트러블슈팅](docs/troubleshooting.md)

## 라이선스
Apache License 2.0

## 기여
이슈와 PR은 언제나 환영합니다!
