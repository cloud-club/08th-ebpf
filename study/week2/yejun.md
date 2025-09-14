```
Week 2
eBPF 데이터 타입 및 데이터를 가져오는 원리에 대한 스터디

eBPF Docs와 유튜브에 공유된 컨퍼런스를 참고하여 작성, References 참고
```

## What is eBPF?

user space, kernel space 내에서 프로그램을 실행할 수 있도록 하여 어플리케이션 개발자가 런타임에 OS의 기능을 사용할 수 있도록 하는 기술
```
Sandboxed program: 프로그램이 시스템 전체에 접근하지 못하게 제한된 격리 환경에서 동작
- 격리(Isolation)
- 보안(Security)
- 제한된 권한(Limited privileges)

eBPF 프로그램은 검증기(Verifier) + 제한된 ISA + Helper API 덕분에 커널 안에서 실행되지만, 완전히 제한된(샌드박스된) 환경 속에서만 동작
```

## Introduction to eBPF

### Hook

<img width="516" height="271" alt="스크린샷 2025-09-14 오후 10 46 03" src="https://github.com/user-attachments/assets/03cbfb2f-2110-4181-a6ae-d00f72527ea1" />

eBPF 프로그램은 이벤트 기반이며 커널이나 애플리케이션이 특정 Hook 포인트를 통과할 때 실행

미리 정의된 Hook(ex. tracepoint)에는 시스템 호출, 함수 입력/종료, 커널 추적 지점, 네트워크 이벤트 및 기타 여러 가지 항목이 포함

미리 정의된 Hook이 존재하지 않는 경우, 커널 프로브(kprobe) 또는 사용자 프로브(uprobe)를 생성하여 커널 또는 사용자 애플리케이션의 거의 모든 곳에 eBPF 프로그램을 연결할 수 있음

<img width="828" height="472" alt="스크린샷 2025-09-14 오후 10 48 50" src="https://github.com/user-attachments/assets/4e8b8a9b-3bb9-42e6-ae05-1c3e40706051" />

```
커널 프로브, 사용자 프로브를 정의한 bpftrace 실행파일인 .bt는 bpfrace tools를 참고하여 가져다 쓰거나 수정하여 활용할 수 있으므로 참고

https://github.com/bpftrace/bpftrace/tree/master/tools
```

### How are eBPF programs written?

<img width="363" height="164" alt="스크린샷 2025-09-14 오후 10 51 50" src="https://github.com/user-attachments/assets/1a5eaa89-80f8-4c6e-8ce3-021b2c45769b" />

리눅스 커널은 eBPF 프로그램이 바이트코드 형태로 로드되어야 함

물론 바이트코드를 직접 작성하는 것은 가능하지만, 더 일반적인 개발 관행은 LLVM과 같은 컴파일러 모음을 활용하여 C 코드를 eBPF 바이트코드로 컴파일하는 것

<img width="842" height="195" alt="image" src="https://github.com/user-attachments/assets/5dece35c-721f-4408-abfb-eb2f7de357a1" />

C Lang에 대한 컴파일러 뿐만아니라 Go, Rust, C++, bcc tools(Python)로 컴파일러 지원

### Maps

eBPF 프로그램은 eBPF 맵의 개념을 활용하여 다양한 데이터 구조에 데이터를 저장하고 검색할 수 있음

eBPF 맵은 eBPF 프로그램뿐만 아니라 사용자 공간의 애플리케이션에서도 시스템 호출을 통해 액세스할 수 있음 (Helper Calls)

<img width="832" height="326" alt="스크린샷 2025-09-14 오후 11 05 11" src="https://github.com/user-attachments/assets/551c919a-dbb9-4253-9422-69bd9aa61801" />

- Key-Value 기반 데이터 구조
- 커널 내부에서 동작하는 eBPF 프로그램 ↔ 사용자 공간 애플리케이션 간 데이터 공유 가능
- eBPF 프로그램 여러 개가 동일한 Map을 공유할 수도 있음
- 다양한 타입의 Map이 있어서 용도에 맞게 선택 가능

#### Maps Type
- Hash Table / Array
  - 기본적인 key-value 저장소
  - 예: 프로세스 ID → 카운터, 소켓  FD → 통계
- Per-CPU Map
  - CPU마다 독립적인 값을 저장 → 동시성 이슈 줄이고 lock-free 성능 보장
- LRU Hash / LRU Array
  - 오래 안 쓰인 엔트리를 자동으로 교체 (캐시 구현에 적합)
- Ring Buffer
  - eBPF 프로그램이 이벤트를 기록하면, 사용자 공간에서 순차적으로 읽음
  - 성능 좋고 이벤트 스트리밍에 적합 (기존 perf buffer 대체)
- Stack Trace Map
  - 커널/유저 스택 트레이스를 저장 (성능 분석, flame graph 생성용)
- LPM (Longest Prefix Match) Trie
  - 네트워크 라우팅/ACL 같은 prefix 기반 매칭에 사용

eBPF 프로그램에서 Map Type을 지정
```
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} packet_count_map SEC(".maps");
```

user space의 C 소스로 해당 Maps에 접근하여 통계 등 활용
```
    // eBPF Map FD 열기 (/sys/fs/bpf는 bpf 전용 가상 파일시스템)
    map_fd = bpf_obj_get("/sys/fs/bpf/packet_count_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    // Map 값 읽기
    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("Packet count: %llu\n", value);
    } else {
        perror("bpf_map_lookup_elem");
    }
```
- bpf_obj_get()로 커널에 로드된 Map 접근
- bpf_map_lookup_elem()로 Key 기반 값 조회
- 필요하면 bpf_map_update_elem()로 값 갱신 가능
___

자세한 내용은 해당 docs 참고: https://ebpf.io/what-is-ebpf
____

## References

- https://ebpf.io/what-is-ebpf
- https://deview.kr/2020/sessions/382
- https://youtu.be/Wzge0hb_MSE?si=0_OkuBnb2aXBumt4
