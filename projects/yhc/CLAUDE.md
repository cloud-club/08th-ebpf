# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an individual eBPF project within the Cloud Club's 8th eBPF study group. The project implements a Prometheus exporter that collects network-related metrics using eBPF technology for kernel-level monitoring.

## Repository Structure

- Located at `/projects/yhc/` within the larger eBPF study repository
- Main repository root is at `../../` containing study materials and other projects
- Study materials are organized in `../../study/week{num}/` directories
- Individual projects are stored in `../../projects/{name}/`

## Development Commands

### Build and Run
```bash
# Run the Go application
go run main.go

# Build the application
go build -o yhc main.go
```

### Dependencies
- Go 1.24.5
- cilium/ebpf v0.19.0 (Go library for eBPF)
- vmlinux.h (kernel headers for eBPF programs)

### VM Management (from repository root)
```bash
# Launch VM with development environment
../../manage launch

# Access VM shell
../../manage shell

# Destroy VM
../../manage destroy
```

## Key Files

- `vmlinux.h`: Generated kernel headers containing Linux kernel type definitions required for eBPF programs
- `go.mod`: Go module configuration with cilium/ebpf dependency
- `main.go`: Entry point for the application (currently a placeholder)

## eBPF Development Context

This project implements a Prometheus exporter that collects network metrics using eBPF. Key aspects:
- Exposing network statistics as Prometheus metrics (typically on port 9090 or similar)
- Tracking network events like packet counts, bytes transferred, connection states
- Using eBPF hooks for network stack monitoring (TC, XDP, socket operations)
- Moving network telemetry data from kernel space to user space
- Implementing HTTP endpoint for Prometheus to scrape metrics

The exporter will use Go with cilium/ebpf to load eBPF programs and expose collected metrics in Prometheus format.