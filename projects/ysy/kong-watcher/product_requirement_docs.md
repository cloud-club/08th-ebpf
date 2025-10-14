

# 구현하고자 하는 것.
같은 파드에서 동작하는 kong 게이트웨이 애플리케이션의 트래픽을 모니터링하도록 함

HTTP Method별, 도메인별, path 별 각각 구분할 수 있어야한다.
```
┌─────────────────────────────────────────┐
│              Same Pod                   │
│                                         │
│  ┌─────────────────┐  ┌───────────────┐ │
│  │ eBPF Monitor    │  │ Your App      │ │
│  │ Container       │  │ Container     │ │
│  │                 │  │               │ │
│  │ [eBPF Program] ─┼──┼→ [HTTP API]   │ │
│  │                 │  │               │ │
│  └─────────────────┘  └───────────────┘ │
│                                         │
└─────────────────────────────────────────┘
           ↑
    External Traffic
    (from other pods/services)
```
## 필요한 Map
먼저, Map 이란?

eBPF 프로그램에서 커널 공간과 유저 공간, 또는 eBPF 프로그램 간에 데이터를 주고받을 수 있도록 해주는 데이터 구조

key/value 형태의 자료구조로, 커널과 유저 공간 모두 동일한 메모리 구조 정의를 공유해야 함

BTF(BPF Type Format) 방식을 사용하는 것이 최신 표준. BTF 기반 map은 타입 정보와 다양한 속성(유형, key/value 타입, entry 수 등)을 선언적으로 명시할 수 있음

커널 eBPF 프로그램에서는 bpf_map_lookup_elem, bpf_map_update_elem 등의 helper 함수를 이용해 map에 접근/수정

유저 공간에서는 syscall(BPF_MAP_LOOKUP_ELEM 등)과 libbpf의 API(bpf_map_create 등)로 map을 생성 및 조작

https://docs.ebpf.io/linux/concepts/maps/

### BPF_HASH
연결 별 상세 상태(예: 소켓, TCP/UDP 커넥션 등)를 추적

key 구조에 소스/목적지 IP·포트, 프로토콜 등 정보를 포함해 커넥션별로 값(통계 등)을 저장하여, 각각의 세션 이벤트 및 통계를 누적·조회할 수 있음

### BPF_ARRAY
인덱스(예: 컨테이너ID 또는 고정된 내부 태그)별로 값을 저장하는 배열형 map

각 컨테이너(또는 서비스·Worker 등)에 대해 집계된 통계(요청 수, 에러 수, 전송/수신 바이트 등)를 저장/조회할 경우 사용할 수 있음

키가 int 타입이며, 값에 여러 개의 메트릭 구조체를 넣을 수 있어, 서비스별 집계 용이

### BPF_RINGBUF_OUTPUT
실시간 이벤트(push 모델) 전송에 쓰이는 신규 방출/수집용 ring buffer map

커널에서 이벤트를 생성하여 유저 공간(e.g. 사이드카 컨테이너)로 거의 딜레이 없음

실시간 트래픽, 알림, 통지 이벤트(즉각적인 트리거, 짧은 payload, 지속적인 event stream)에 적합


## 정리
BPF_HASH(ConnKey, ConnStats) - 연결별 상세 추적

BPF_ARRAY(ContainerStats) - 컨테이너별 집계

BPF_RINGBUF_OUTPUT(TrafficEvent) - 실시간 이벤트
