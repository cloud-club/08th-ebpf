# tests/test_tracer.py - Tests for tracer module
"""
Unit tests for the LatencyTracer class.
"""

import pytest
from unittest.mock import Mock, patch
from src.collector.tracer import LatencyTracer


class TestLatencyTracer:
    """Test cases for LatencyTracer"""

    def test_tracer_initialization(self):
        """Test tracer initialization with config"""
        config = {
            'pid': 1234,
            'syscalls': ['read', 'write'],
            'buffer_size': 256
        }

        tracer = LatencyTracer(config)

        assert tracer.pid == 1234
        assert tracer.syscalls == ['read', 'write']
        assert tracer.buffer_size == 256
        assert tracer.bpf is None
        assert tracer.running is False

    def test_load_ebpf_program(self):
        """Test loading eBPF program from file"""
        # This test would require actual eBPF program files
        # Placeholder for now
        pass

    def test_register_event_handler(self):
        """Test registering event handlers"""
        config = {'pid': 1234, 'syscalls': []}
        tracer = LatencyTracer(config)

        handler = Mock()
        tracer.register_event_handler('syscall', handler)

        assert 'syscall' in tracer.event_handlers
        assert tracer.event_handlers['syscall'] == handler
