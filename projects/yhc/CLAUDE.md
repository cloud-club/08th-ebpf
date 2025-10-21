# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TCP metrics Prometheus exporter using eBPF. Tracks TCP connection state transitions (active/passive connections, failures, resets) via kernel hooks and exposes them as Prometheus metrics on port 9090.

## Repository Structure

- Located at `/projects/yhc/` within the larger eBPF study repository
- Main repository root is at `../../` containing study materials and other projects
- Study materials are organized in `../../study/week{num}/` directories

## Development Commands

```bash
# Generate eBPF Go bindings from C code
make generate
# Or: go generate ./...

# Build the application (includes generate step)
make build

# Run (requires sudo for eBPF operations)
make run
# Or: sudo ./monitor eth0

# Clean generated files
make clean

# Full build pipeline
make all
```

## VM Management

Test in isolated VM environment (from repository root):
```bash
../../manage launch    # Launch VM
../../manage shell     # Access VM
../../manage destroy   # Destroy VM
../../manage shell {command}  # Run single command in VM
```

## Architecture

### Two-Layer Design
1. **Kernel Space (tcp_monitor.c)**: eBPF program using fentry hook on `tcp_set_state()` to track TCP state transitions. Stores cumulative statistics in a BPF_MAP_TYPE_ARRAY map.

2. **User Space (main.go)**: Go application that:
   - Loads eBPF objects using cilium/ebpf with bpf2go-generated bindings
   - Attaches fentry tracing program to kernel function
   - Polls BPF map every 5 seconds via `collectMetrics()`
   - Exposes Prometheus metrics via HTTP endpoint at `:9090/metrics`

### Data Flow
TCP state change → kernel hook → BPF map update → Go polling → Prometheus gauge update → HTTP /metrics endpoint

## Key Dependencies

- Go 1.25.1
- cilium/ebpf v0.19.0 (eBPF loading/management)
- prometheus/client_golang v1.23.2 (metrics exposition)
- vmlinux.h (kernel type definitions, pre-generated)

## Tracked Metrics

- `tcp_active_connections_total`: Client-initiated connections (SYN_SENT → ESTABLISHED)
- `tcp_passive_connections_total`: Server-side connections (SYN_RECV → ESTABLISHED)
- `tcp_failed_connections_total`: Connection failures (SYN_SENT → CLOSE)
- `tcp_resets_sent_total`: Reset connections sent
- `tcp_resets_received_total`: Reset connections received