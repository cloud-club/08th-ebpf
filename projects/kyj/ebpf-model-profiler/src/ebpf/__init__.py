# src/ebpf/__init__.py - eBPF programs module
"""
eBPF programs for tracing syscalls and kernel events.

This module contains C programs that run in the kernel space:
- syscall_tracer.c: Generic syscall tracing
- network_tracer.c: Network-specific tracing (sendto, recvfrom)
- file_io_tracer.c: File I/O tracing (read, write, openat)
- common.h: Shared data structures and definitions
"""
