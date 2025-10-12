# Architecture

## Overview

The eBPF Model Serving Latency Profiler is designed to trace and analyze system call latency in model serving applications without requiring any application code changes.

## Components

### 1. eBPF Programs (Kernel Space)

Located in `src/ebpf/`, these C programs run in the Linux kernel:

- **syscall_tracer.c**: Generic syscall tracing with kprobe/kretprobe
- **network_tracer.c**: Network-specific tracing (sendto, recvfrom, etc.)
- **file_io_tracer.c**: File I/O tracing (read, write, openat, etc.)
- **common.h**: Shared data structures and definitions

These programs:
- Attach to kernel probe points
- Record syscall entry/exit timestamps
- Filter by PID
- Send events to user space via perf buffers

### 2. Collector (User Space)

Located in `src/collector/`, these Python modules handle event collection:

- **tracer.py**: Main BCC-based tracer, loads eBPF programs
- **event_handler.py**: Processes raw events from kernel
- **request_tracker.py**: Correlates events into requests
- **aggregator.py**: Computes statistics and aggregates data

### 3. Analyzer

Located in `src/analyzer/`, these modules analyze collected data:

- **latency_analyzer.py**: Core latency analysis
- **breakdown.py**: Breakdown by syscall, category, time
- **hotspot_detector.py**: Identifies performance bottlenecks
- **report_generator.py**: Generates reports in various formats

### 4. Exporters

Located in `src/exporters/`, these modules export results:

- **prometheus.py**: Prometheus metrics exporter
- **json_exporter.py**: JSON file exporter
- **stdout.py**: Console output with colors

### 5. CLI

`src/cli.py` provides the command-line interface using Click.

## Data Flow

```
┌─────────────────────┐
│  User Application   │
│  (Model Server)     │
└──────────┬──────────┘
           │ syscalls
           ▼
┌─────────────────────┐
│   Linux Kernel      │
│  ┌──────────────┐   │
│  │ eBPF Programs│   │
│  │ - Probes     │   │
│  │ - Filtering  │   │
│  └──────┬───────┘   │
└─────────┼───────────┘
          │ perf events
          ▼
┌─────────────────────┐
│   Collector         │
│  - Event Handler    │
│  - Request Tracker  │
│  - Aggregator       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Analyzer          │
│  - Latency Analysis │
│  - Hotspot Detection│
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Exporters         │
│  - Prometheus       │
│  - JSON             │
│  - Stdout           │
└─────────────────────┘
```

## Key Design Decisions

### 1. BCC vs libbpf

We use BCC (BPF Compiler Collection) because:
- Easier development and debugging
- Built-in Python bindings
- Good documentation and examples
- Handles BTF and CO-RE automatically

### 2. Request Correlation

Requests are correlated by Thread ID (TID) with heuristics:
- Each TID is assumed to handle one request at a time
- Timeout mechanism for incomplete requests
- Can be extended with custom markers

### 3. Minimal Overhead

To minimize performance impact:
- PID filtering in kernel space
- Configurable sampling rates
- Minimal data structures
- Efficient perf buffers

### 4. Modularity

Each component is independent:
- Collectors can work with different analyzers
- Exporters are pluggable
- eBPF programs can be extended independently

## Security Considerations

- Requires root privileges (CAP_SYS_ADMIN)
- Only traces specified PIDs
- No access to syscall arguments/data
- Read-only observation

## Performance Impact

Expected overhead:
- CPU: < 5% at high event rates
- Memory: ~100MB for buffers and data structures
- No impact on traced application's functionality

## Limitations

1. **Kernel Version**: Requires Linux 4.9+ (5.0+ recommended)
2. **Root Required**: Must run with root privileges
3. **Per-Process**: Traces specific PIDs, not global
4. **Syscall Level**: Does not trace application-level events
5. **No Arguments**: Does not capture syscall arguments for privacy/security

## Extension Points

The architecture allows for easy extensions:

1. **New Syscalls**: Add to eBPF programs
2. **Custom Metrics**: Extend Prometheus exporter
3. **New Exporters**: Implement exporter interface
4. **Advanced Correlation**: Enhance request tracker
5. **ML-based Analysis**: Add to analyzer module
