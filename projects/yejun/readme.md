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



