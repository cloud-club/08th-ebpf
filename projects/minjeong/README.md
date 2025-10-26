# eBPF 기반 Stateless 방화벽

> 아직 미완성 상태로, 완성 이후 실행 화면을 추가할 예정입니다.

## 개요

- 이 프로젝트는 Linux 커널의 eBPF 기술과 Go 언어를 활용하여 Stateless 방화벽을 구현합니다.
- eBPF 프로그램를 네트워크 인터페이스의 TC(Traffic Control) hook에 연결하여 인/아웃바운드 패킷을 검사하고, Go로 작성된 CLI 애플리케이션을 통해 방화벽 정책을 동적으로 관리하는 것을 목표로 합니다.

## 주요 기능

- Stateless 패킷 필터링: 수신 및 발신되는 패킷의 IP, 포트, 프로토콜 정보를 기반으로 정책을 적용합니다.
- 동적 정책 관리: CLI를 통해 방화벽 규칙(Allow/Deny)을 실시간으로 추가, 삭제, 조회할 수 있습니다.
- eBPF Map 활용: 방화벽 정책은 eBPF Map에 저장되어 커널단의 eBPF 프로그램과 사용자 공간의 Go 애플리케이션 간에 효율적으로 데이터를 공유합니다.
- 패킷 캡처: 네트워크 패킷을 실시간으로 캡처하는 기능을 제공합니다.
- CLI 명령: `cobra` 라이브러리를 사용하여 사용하기 쉬운 명령줄 인터페이스를 제공합니다.

## 프로젝트 구조

```plain text
.
├── cmd/                # CLI 명령어 구현
├── pkg/                # 프로젝트 핵심 로직
│   ├── bpf/            # eBPF 프로그램 (C, Go)
│   ├── policy/         # 방화벽 정책 관리
│   └── rule/           # 방화벽 규칙 구조 정의
├── main.go             # 프로그램 진입점
├── go.mod
└── Makefile
```

## 아키텍처

### C (eBPF Program)

- `pkg/bpf/ebpf_fw.c`: TC hook에 연결되어 패킷 필터링을 수행하는 eBPF 프로그램입니다.
  - eBPF Map을 통해 Go 애플리케이션과 정책 및 데이터를 주고받습니다.
  - 정책에 따라 패킷을 허용(`TC_ACT_OK`) 또는 차단(`TC_ACT_SHOT`) 합니다.
- `pkg/bpf/ebpf_pcap.c`: TC hook에 연결되어 패킷 캡처를 수행하는 eBPF 프로그램입니다.

### Go (CLI & 정책 관리)

- `cmd/`: `cobra`를 사용한 CLI 명령어 정의 부분입니다. 사용자 입력을 받아 정책 관리 로직을 호출합니다.
- `pkg/policy/`: 방화벽 정책을 관리하는 핵심 로직입니다. eBPF Map을 업데이트하여 커널단의 필터링 규칙을 변경합니다.
- `pkg/bpf/`: C로 작성된 eBPF 프로그램을 Go 애플리케이션에 로드하고 관리하는 역할을 합니다.

## CLI 명령어

```shell
# 방화벽 활성화
ebpfw enable

# 방화벽 비활성화
ebpfw disable

# 방화벽 활성화/비활성화 상태 조회
ebpfw status

# 방화벽 규칙 목록 출력
ebpfw list

# 방화벽 규칙 추가 (포트, 프로토콜, 방향은 필수)
# 예: ebpfw add allow 80 tcp in 192.168.0.1
ebpfw add [allow|deny] [port] [protocol] [in|out] [ip]

# 방화벽 규칙 번호로 삭제
ebpfw remove [number]

# 모든 방화벽 규칙 삭제
ebpfw reset

# 방화벽 규칙 순서 이동
ebpfw move [from] [to]

# 기본 정책 조회
ebpfw default

# 기본 정책 변경 (기본적으로 모든 패킷을 허용할지, 차단할지 설정)
ebpfw default [allow|deny] [in|out]

# 네트워크 패킷 모니터링 시작
ebpfw monitor
```