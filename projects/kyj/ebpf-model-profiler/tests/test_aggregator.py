# tests/test_aggregator.py - Tests for aggregator module
"""
Unit tests for the EventAggregator class.
"""

import pytest
from src.collector.aggregator import EventAggregator
from src.collector.event_handler import SyscallEvent


class TestEventAggregator:
    """Test cases for EventAggregator"""

    def test_aggregator_initialization(self):
        """Test aggregator initialization"""
        aggregator = EventAggregator()
        assert aggregator.total_events == 0
        assert len(aggregator.events_by_syscall) == 0

    def test_add_event(self):
        """Test adding events to aggregator"""
        aggregator = EventAggregator()

        event = SyscallEvent(
            pid=1234, tid=5678, timestamp_ns=1000, duration_ns=1000000,  # 1ms
            comm="test", syscall_id=0, syscall_name="read",
            event_type=2, ret_val=100
        )

        aggregator.add_event(event)

        assert aggregator.total_events == 1
        assert 'read' in aggregator.events_by_syscall
        assert len(aggregator.events_by_syscall['read']) == 1

    def test_get_syscall_stats(self):
        """Test getting statistics for a syscall"""
        aggregator = EventAggregator()

        # Add multiple events
        for i in range(10):
            event = SyscallEvent(
                pid=1234, tid=5678, timestamp_ns=i*1000,
                duration_ns=(i+1) * 100000,  # varying durations
                comm="test", syscall_id=0, syscall_name="read",
                event_type=2, ret_val=100
            )
            aggregator.add_event(event)

        stats = aggregator.get_syscall_stats('read')

        assert stats is not None
        assert stats['count'] == 10
        assert 'mean_us' in stats
        assert 'median_us' in stats
        assert 'min_us' in stats
        assert 'max_us' in stats

    def test_get_summary(self):
        """Test getting overall summary"""
        aggregator = EventAggregator()

        # Add events
        for i in range(5):
            event = SyscallEvent(
                pid=1234, tid=5678, timestamp_ns=i*1000,
                duration_ns=1000000,  # 1ms
                comm="test", syscall_id=0, syscall_name="read",
                event_type=2, ret_val=100
            )
            aggregator.add_event(event)

        summary = aggregator.get_summary()

        assert summary['total_events'] == 5
        assert summary['unique_syscalls'] == 1
        assert 'mean_latency_us' in summary
