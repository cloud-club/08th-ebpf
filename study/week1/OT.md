# Week 1 - OT (Orientation)

## 🎯 스터디 소개
### eBPF 스터디 - 커널 모니터링하기 대작전
- **목표**: eBPF로 커널 레벨 정보를 활용한 작은 프로젝트 완성
- **기간**: 8주 과정
- **핵심**: 원리 학습 + 실제 프로덕트 개발

### 왜 eBPF인가?
- 커널 재컴파일 없이 커널 기능 확장
- 성능 오버헤드 최소화로 프로덕션 환경 적용 가능
- 네트워킹, 보안, 모니터링 등 다양한 분야 활용

## 👥 참여자 소개
### 자기소개 시간
- 이름 & 소속
- 해보고 싶은 것 (간단하게, 아직 잘 모르면 안해도 돼요!)

## 📋 스터디 진행 방식

### 일정
| 구분 | 내용 | 장소 |
|------|------|------|
| 시간 | 매주 목요일 오후 8시 | - |
| 1주차 (OT) | 오프라인 필수 | 강남교보타워 10층 A동 |
| 2-7주차 | 온라인/오프라인 선택 | Google Meet / 오프라인 |
| 8주차 (발표) | 오프라인 필수 | 강남교보타워 10층 A동 |

### 스터디 규칙
1. **학습 기록**: `/study/week{num}/{name}.md`에 정리
2. **프로젝트**: `/project/{name}/` 디렉토리에 개발
3. **Git 관리**: main branch 직접 push (PR 없이)
4. **출석**: 3회 이상 불참 시 수료 불가

## 🔍 eBPF 개요

### eBPF란?
**extended Berkeley Packet Filter**
- 커널 공간에서 안전하게 사용자 코드 실행
- 원래 패킷 필터링 용도 → 범용 커널 프로그래밍 플랫폼으로 진화

### 핵심 구성 요소
```
User Space          Kernel Space
    │                    │
    ├─ BPF Program ─────→├─ Verifier (안전성 검증)
    │                    ├─ JIT Compiler (최적화)
    ├─ BPF Maps ←───────→├─ Execution (실행)
    │                    └─ Helpers (커널 함수)
```

## 🛠 개발 환경 설정

### 시스템 요구사항
OrbStack 사용 (권장)

### OrbStack을 이용한 개발 환경 설정 (권장)

#### 1. OrbStack 설치
```bash
# macOS에서 OrbStack 설치
brew install --cask orbstack

```
**또는 https://orbstack.dev/download 에서 직접 다운로드**

#### 2. 스터디 VM 환경 자동 구성
```bash
# 저장소 클론
git clone https://github.com/cloud-club/08th-ebpf.git
cd 08th-ebpf

# VM 생성 및 eBPF 개발환경 자동 설정
./manage launch

# VM 접속
./manage shell
```

#### 3. VM 관리 명령어
```bash
./manage launch   # VM 생성 및 개발환경 설정
./manage shell    # VM 셸 접속
./manage destroy  # VM 삭제
```

### 수동 설치 (대안)
Linux 환경이 이미 있거나 직접 설정하려는 경우:
> 테스트 안해봐서 확실하지 않을수도 있어요 😅

```bash
# 스터디 저장소의 설치 스크립트 사용
git clone https://github.com/cloud-club/08th-ebpf.git
cd 08th-ebpf

# scripts/dependencies/apt.sh 실행으로 필요 패키지 설치
./scripts/dependencies/apt.sh

# 추가로 eBPF 도구 설치
sudo apt-get install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    bpftrace

# 설치 확인
bpftrace --version
python3 -c "import bcc; print('✅ BCC 설치 완료')"
```

설치되는 주요 패키지:
- **개발 도구**: build-essential, clang, llvm
- **eBPF 관련**: libelf-dev, bpftool, bpftrace, bpfcc-tools
- **기타 유틸리티**: git, curl, wget, net-tools

## 🚀 bpftrace 첫 실습

### 1. Hello World
```bash
# 1초마다 메시지 출력
sudo bpftrace -e 'BEGIN { printf("eBPF 스터디 시작!\n"); } 
                  interval:s:1 { printf("Hello from kernel! %d\n", pid); }'
```

### 2. 파일 오픈 추적
```bash
# 어떤 프로세스가 어떤 파일을 여는지 모니터링
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat {
    printf("%-6d %-16s %s\n", pid, comm, str(args->filename));
}'
```

### 3. 네트워크 연결 모니터링
```bash
# TCP 연결 추적
sudo bpftrace -e 'tracepoint:sock:inet_sock_set_state {
    if (args->newstate == 1) {  // TCP_ESTABLISHED
        printf("New connection: %s:%d\n", comm, pid);
    }
}'
```

### 4. 프로세스 생성 감지
```bash
# 새 프로세스 생성 모니터링
sudo bpftrace -e 'tracepoint:sched:sched_process_fork {
    printf("Parent [%d] %s created Child [%d]\n", 
           pid, comm, args->child_pid);
}'
```

## 📚 커리큘럼 상세

| 주차 | 내용 | 과제 |
|------|------|------|
| **Week 1** | OT, eBPF 소개, bpftrace | 환경 설정 & bpftrace 실습 |
| **Week 2** | BPF Maps, CO-RE, 데이터 구조 | BPF 프로그램 구조 분석 |
| **Week 3** | Tracepoint, Kprobe 탐색 | 관심 hook point 조사 |
| **Week 4** | 실전 데이터 수집 | 터미널에서 데이터 추출 |
| **Week 5-6** | Python BCC 개발 | User space 연동 구현 |
| **Week 7** | 프로젝트 통합 | 최종 애플리케이션 개발 |
| **Week 8** | 결과 발표 | 프로젝트 시연 & 공유 |

## 🎯 Week 1 과제

### 필수
1. ✅ 개발 환경 설정 완료
2. ✅ bpftrace one-liner 5개 실행 & 결과 캡처
3. ✅ `/study/week1/{name}.md`에 학습 내용 정리

### 선택
- BPF 프로그램 lifecycle 이해
- 관심있는 eBPF 프로젝트 1개 조사

### 제출 양식 예시
```markdown
# Week 1 - {이름}

## 환경 설정
- OS: Ubuntu 22.04
- Kernel: 5.15.0
- 설치 도구: bpftrace 0.16.0, bcc 0.24.0

## bpftrace 실습
### 1. 시스템 콜 카운트
\`\`\`bash
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
\`\`\`
[실행 결과 스크린샷]

## 학습 내용
- eBPF의 동작 원리
- Verifier의 역할
- [추가 학습 내용]
```

## 💡 Tips & Tricks

### 권한 문제 해결
```bash
# bpftrace 실행 시 권한 오류
sudo setcap cap_sys_admin+eip $(which bpftrace)

# 또는 sudo 그룹 추가
sudo usermod -aG sudo $USER
```

### 유용한 명령어
```bash
# 사용 가능한 tracepoint 확인
sudo bpftrace -l 'tracepoint:*'

# 특정 함수의 kprobe 확인
sudo bpftrace -l 'kprobe:*tcp*'

# BCC 예제 실행
sudo python3 /usr/share/bcc/examples/hello_world.py
```

## 📖 참고 자료

### 필수 자료
- [eBPF.io - What is eBPF?](https://ebpf.io/what-is-ebpf/)
- [bpftrace One-Liner Tutorial](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md)
- [BCC Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md)

### 추천 자료
- [Brendan Gregg's Blog](https://www.brendangregg.com/ebpf.html)
- [Learning eBPF (O'Reilly)](https://www.oreilly.com/library/view/learning-ebpf/9781098135119/)
- [eBPF Summit Videos](https://ebpf.io/summit-2023/)
