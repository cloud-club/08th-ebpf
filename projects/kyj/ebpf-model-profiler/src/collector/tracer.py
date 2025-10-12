# src/collector/tracer.py - Main eBPF tracer using BCC
"""
Main tracer class for loading and managing eBPF programs.
Uses BCC (BPF Compiler Collection) to compile and load eBPF programs into the kernel.
"""

import os
from bcc import BPF
from pathlib import Path
from typing import Optional, List, Dict, Callable
import logging


class LatencyTracer:
    """
    Main tracer for collecting syscall latency data using eBPF.

    This class loads eBPF programs, attaches them to kernel probe points,
    and manages the lifecycle of the tracing session.
    """

    def __init__(self, config: Dict):
        """
        Initialize the LatencyTracer.

        Args:
            config: Configuration dictionary containing:
                - pid: Process ID to trace
                - syscalls: List of syscalls to trace
                - buffer_size: Perf buffer size
                - sampling_rate: Sampling rate (0.0-1.0)
        """
        self.config = config
        self.pid = config.get('pid')
        self.syscalls = config.get('syscalls', [])
        self.buffer_size = config.get('buffer_size', 256)

        self.bpf = None
        self.event_handlers = {}
        self.running = False

        self.logger = logging.getLogger(__name__)

        # Path to eBPF C programs
        self.ebpf_dir = Path(__file__).parent.parent / 'ebpf'

    def load_ebpf_program(self, program_path: str) -> str:
        """
        Load eBPF C program from file.

        Args:
            program_path: Path to the C program file

        Returns:
            Program source code as string
        """
        with open(program_path, 'r') as f:
            return f.read()

    def initialize(self):
        """
        Initialize BCC and load eBPF programs.
        """
        self.logger.info(f"Initializing tracer for PID {self.pid}")

        # Load syscall tracer program
        syscall_prog = self.load_ebpf_program(self.ebpf_dir / 'syscall_tracer.c')

        # Compile and load eBPF program
        try:
            self.bpf = BPF(text=syscall_prog)
            self.logger.info("eBPF program loaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to load eBPF program: {e}")
            raise

        # Set PID filter if specified
        if self.pid:
            self._set_pid_filter()

        # Attach to syscalls
        self._attach_syscalls()

    def _set_pid_filter(self):
        """
        Set PID filter in eBPF map to only trace specific process.
        """
        pid_filter = self.bpf.get_table("pid_filter")
        pid_filter[self.bpf.ctype.c_uint(self.pid)] = self.bpf.ctype.c_ubyte(1)
        self.logger.info(f"PID filter set to {self.pid}")

    def _attach_syscalls(self):
        """
        Attach kprobes/kretprobes to specified syscalls.
        """
        for syscall in self.syscalls:
            try:
                # Attach entry probe
                self.bpf.attach_kprobe(
                    event=f"__{syscall}",
                    fn_name=f"trace_{syscall}_enter"
                )

                # Attach exit probe
                self.bpf.attach_kretprobe(
                    event=f"__{syscall}",
                    fn_name=f"trace_{syscall}_exit"
                )

                self.logger.info(f"Attached probes to {syscall}")
            except Exception as e:
                self.logger.warning(f"Failed to attach to {syscall}: {e}")

    def register_event_handler(self, event_type: str, handler: Callable):
        """
        Register a callback handler for specific event types.

        Args:
            event_type: Type of event ('syscall', 'network', 'file_io')
            handler: Callback function to process events
        """
        self.event_handlers[event_type] = handler

    def start(self):
        """
        Start the tracing session.
        Opens perf buffers and begins collecting events.
        """
        if self.bpf is None:
            raise RuntimeError("Tracer not initialized. Call initialize() first.")

        self.logger.info("Starting tracing session...")
        self.running = True

        # Open perf buffer
        self.bpf["events"].open_perf_buffer(
            self._handle_event,
            page_cnt=self.buffer_size
        )

        # Poll for events
        try:
            while self.running:
                self.bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        finally:
            self.stop()

    def _handle_event(self, cpu, data, size):
        """
        Internal handler for perf buffer events.
        Dispatches events to registered handlers.

        Args:
            cpu: CPU number where event occurred
            data: Raw event data
            size: Size of event data
        """
        event = self.bpf["events"].event(data)

        # Dispatch to appropriate handler
        if 'syscall' in self.event_handlers:
            self.event_handlers['syscall'](event)

    def stop(self):
        """
        Stop the tracing session and cleanup resources.
        """
        self.logger.info("Stopping tracing session...")
        self.running = False

        if self.bpf:
            # Detach all probes
            for syscall in self.syscalls:
                try:
                    self.bpf.detach_kprobe(event=f"__{syscall}")
                    self.bpf.detach_kretprobe(event=f"__{syscall}")
                except:
                    pass

        self.logger.info("Tracer stopped")

    def get_stats(self) -> Dict:
        """
        Get current statistics from eBPF maps.

        Returns:
            Dictionary containing current statistics
        """
        stats = {}

        if self.bpf:
            # Get start_times map statistics
            start_times = self.bpf.get_table("start_times")
            stats['active_traces'] = len(start_times)

        return stats
