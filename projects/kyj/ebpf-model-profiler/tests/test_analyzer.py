# tests/test_analyzer.py - Tests for analyzer module
"""
Unit tests for the LatencyAnalyzer class.
"""

import pytest
from src.analyzer.latency_analyzer import LatencyAnalyzer
from src.collector.event_handler import SyscallEvent
from src.collector.request_tracker import Request


class TestLatencyAnalyzer:
    """Test cases for LatencyAnalyzer"""

    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        analyzer = LatencyAnalyzer()
        assert analyzer.slow_threshold_us == 1000
        assert analyzer.very_slow_threshold_us == 10000

    def test_analyze_request_with_empty_request(self):
        """Test analyzing an empty request"""
        analyzer = LatencyAnalyzer()

        request = Request(
            request_id="test_001",
            start_time=0.0,
            end_time=1.0,
            pid=1234,
            tid=5678
        )

        analysis = analyzer.analyze_request(request)

        assert analysis['request_id'] == "test_001"
        assert 'syscall_breakdown' in analysis
        assert 'category_breakdown' in analysis
        assert 'slow_events' in analysis

    def test_find_slow_events(self):
        """Test finding slow events"""
        analyzer = LatencyAnalyzer(config={'slow_threshold_us': 1000})

        # Create mock events
        fast_event = SyscallEvent(
            pid=1234, tid=5678, timestamp_ns=1000, duration_ns=500000,  # 500us
            comm="test", syscall_id=0, syscall_name="read",
            event_type=2, ret_val=100
        )

        slow_event = SyscallEvent(
            pid=1234, tid=5678, timestamp_ns=2000, duration_ns=5000000,  # 5000us
            comm="test", syscall_id=0, syscall_name="write",
            event_type=2, ret_val=100
        )

        request = Request(
            request_id="test_002",
            start_time=0.0,
            end_time=1.0,
            pid=1234,
            tid=5678
        )
        request.syscall_events = [fast_event, slow_event]

        analysis = analyzer.analyze_request(request)
        slow_events = analysis['slow_events']

        assert len(slow_events) == 1
        assert slow_events[0]['syscall'] == 'write'
        assert slow_events[0]['severity'] == 'slow'
