### 구성

```
kernel: uname -r (6.8.0-1039-aws)
커널 버전에 따라 제공하는 tracepoint가 다름

tracepoint 확인 및 ebpf 코드 작성 시 참고
sudo cat /sys/kernel/debug/tracing/available_events
```

### 빌드 방법

```
# 해당 레포의 scripts/dependencies에 설치 존재
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev make 

# vmlinux.h 생성
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# bpf.o 생성 (bpf_helpher.h 등 필요할 경우 -I 옵션 활용
(위치 찾기: find /usr/src/linux-headers-$(uname -r) -name bpf_helpers.h)
clang -O2 -g -target bpf -I/usr/src/linux-headers-$(uname -r)/tools/bpf/resolve_btfids/libbpf/include -c bpf/cpu_mem_monitor.bpf.c -o bpf/cpu_mem_monitor.bpf.o

# User 영역에서 보기 위한 Go 기반 컬렉터 활용
# go 설치
wget https://go.dev/dl/go1.22.7.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.7.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Go eBPF 패키지를 cilium에서 가져옴
go get github.com/cilium/ebpf

# 실행
go run main.go
```


### eBPF Map

```
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // PID
    __type(value, struct cpu_event);  # cpu 사용 시점, 총 사용 시간
    __uint(max_entries, 10240);  # 최대 엔트리 수
} cpu_usage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // PID
    __type(value, struct fault_event);  # User Fault, Kernel Fault
    __uint(max_entries, 10240);
} page_faults SEC(".maps");
```

____

# 1. CPU 분석
```
CPU 점유 시간 + 스위칭 빈도를 통한 CPU burst, I/O burst Process 탐지

CPU burst Process: 특정 프로세스가 일정 시간 동안 과도하게 CPU를 점유
I/O burst Process: I/O로 인해 스위칭이 빈번하게 발생


**CPU 점유 시 프로세스 상태 기반 스위칭 count 집계 후 I/O, CPU burst 판단**
#main.go    
ioRatio := float64(evt.IOburst) / float64(total) * 100
burstType := "I/O-bound"
if ioRatio < 30 { // IO-burst 비율이 30% 미만이면 CPU-bound
    burstType = "CPU-bound"
}
cpuUsageRatio := float64(evt.TotalTimeNs) / (float64(interval.Nanoseconds()) * float64(numCPUs)) * 100
cmd := getCmdName(nextPID)

// CPU 40 % 점유 시 출력
if cpuUsageRatio > 40 {
fmt.Printf("[%s] I/O Switches: %-6d PID %-6d CMD: (%-15s) | CPU: %6.2f%% | Switches: %-5d\n", burstType, evt.IOburst, nextPID, cmd, cpuUsageRatio * float64(numCPUs), evt.SwitchCount}

# cpu.bpf.c
// prev_state 기반으로 I/O burst 카운트
if (ctx->prev_state & (TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)) {
    __sync_fetch_and_add(&evt->io_burst, 1);
}
```
<img width="723" height="370" alt="스크린샷 2025-10-26 오후 11 11 39" src="https://github.com/user-attachments/assets/db93c654-0205-4f41-a82a-f26ed9f5fa93" />



___
# 2. Memory 분석

___
# 3. Disk 분석




