# eBPF Storage Exporter

eBPF를 사용하여 노드의 스토리지 관련 메트릭을 수집하는 Prometheus exporter입니다.

현재는 노드(시스템) 전체의 Block I/O 지표만 수집하고 있지만, 추후 각 블록 디바이스 장치 별(또는 k8s pv?) I/O 지표를 수집하도록 확장할 계획입니다.

## 수집하는 메트릭

- `storage_read_bytes_per_sec`: 초당 읽기 바이트 수 (실시간 처리율)
- `storage_write_bytes_per_sec`: 초당 쓰기 바이트 수 (실시간 처리율)
- `storage_read_ops_per_sec`: 초당 읽기 작업 수 (IOPS)
- `storage_write_ops_per_sec`: 초당 쓰기 작업 수 (IOPS)

## 메트릭 수집 방법 및 개선해야할 점

리눅스 커널 [TracePoint](https://docs.kernel.org/core-api/tracepoint.html) 중 Block IO 부분을 참고하여 `trace_block_rq_complete` TracePoint를 삽입하였습니다.

해당 Tracepoint는 디바이스 드라이버로부터 성공적으로 처리된 Block IO에 대한 정보를 반환하며, 완료된 요청에 대한 섹터 수에 전통적인 섹터 사이즈인 512를 곱해 처리된 바이트 수를 계산합니다.

또한 trace_block_rq_complete의 주요 argument 중 rwbs라고 하는 I/O 플래그를 바탕으로 읽기/쓰기 바이트/카운트의 누적합을 eBPS Map에 저장한 후, 이를 유저스페이스로 가져올 때 `(현재 누적합 - 이전 누적합) / (현재 시간 - 이전 시간)`의 간단한 공식으로 메트릭을 계산하였습니다.

아래는 TracePoint 관련 코드입니다.
```c
TRACEPOINT_PROBE(block, block_rq_complete) {
    u32 key = 0;
    struct io_stats_t *stats = io_stats.lookup(&key);
    struct io_stats_t new_stats = {};
    
    if (stats) {
        new_stats = *stats;
    }
    
    u32 bytes = args->nr_sector * SECTOR_SIZE;

    if (args->rwbs[0] == 'R') {
        new_stats.read_bytes += bytes;
        new_stats.read_count++;
    } else if (args->rwbs[0] == 'W') {
        new_stats.write_bytes += bytes;
        new_stats.write_count++;
    }

    io_stats.update(&key, &new_stats);
    return 0;
}
```

개선해야 할 부분은 현재 처리한 바이트를 계산할 때 전통적인 섹터 사이즈인 `512byte`를 사용하고 있지만, 최근 블록 디바이스 별로 `2048` ~ `4096` 등 다양한 섹터 사이즈를 가지고 있어, 이를 동적으로 세팅하거나 환경 변수 방식으로 설정하도록 하는 기능이 필요합니다.

또한 현재 커널스페이스의 메트릭 집계 시 예외처리하는 로직이 부족합니다.
따라서 I/O 예외 발생 시 처리한 바이트 수에 쓰레기 값이 들어갈 확률이 있어 세세한 예외처리를 추가해야할 것으로 보입니다.

## 파일 구조

```
ysh/
├── ebpf/
│   └── ebpf_program.c          # eBPF 커널 프로그램 (블록 I/O 추적)
│
├── Python 모듈
│   ├── storage_exporter.py     # 메인 엔트리포인트 (HTTP 서버)
│   ├── metrics_collector.py    # BPF 맵에서 메트릭 수집 및 rate 계산
│   ├── http_handler.py         # HTTP 요청 처리 (/metrics 엔드포인트)
│   └── prometheus_formatter.py # Prometheus 형식으로 메트릭 변환
│
├── 설정 및 실행 파일들
│   ├── run.sh                  # 개발 환경 실행 스크립트
│   ├── requirements.txt        # Python 의존성
│   └── Dockerfile             # 컨테이너 이미지 빌드용
│
├── 문서
│   └── README.md              # 프로젝트 설명 및 사용법
```

## 실행 방법

### 개발환경에서 직접 실행
```bash
sudo ./run.sh
```

## 메트릭 확인

```bash
curl http://localhost:8080/metrics
```
