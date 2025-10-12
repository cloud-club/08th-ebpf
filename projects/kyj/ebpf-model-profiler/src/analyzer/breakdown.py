# src/analyzer/breakdown.py - Detailed breakdown analysis
"""
Provides detailed breakdown analysis of latency by various dimensions.
"""

from typing import Dict, List
from collections import defaultdict
import logging


class BreakdownAnalyzer:
    """
    Analyzes latency breakdown by different dimensions.

    Provides detailed breakdown by syscall, category, time ranges, etc.
    """

    def __init__(self):
        """
        Initialize the breakdown analyzer.
        """
        self.logger = logging.getLogger(__name__)

    def breakdown_by_syscall(self, events: List) -> Dict[str, Dict]:
        """
        Break down events by syscall type.

        Args:
            events: List of event objects

        Returns:
            Dictionary with per-syscall statistics
        """
        breakdown = defaultdict(lambda: {
            'count': 0,
            'total_time_ms': 0.0,
            'min_us': float('inf'),
            'max_us': 0.0,
            'durations': []
        })

        for event in events:
            syscall = event.syscall_name
            duration_us = event.duration_us

            breakdown[syscall]['count'] += 1
            breakdown[syscall]['total_time_ms'] += event.duration_ms
            breakdown[syscall]['min_us'] = min(breakdown[syscall]['min_us'], duration_us)
            breakdown[syscall]['max_us'] = max(breakdown[syscall]['max_us'], duration_us)
            breakdown[syscall]['durations'].append(duration_us)

        # Calculate averages
        for syscall, data in breakdown.items():
            if data['durations']:
                data['avg_us'] = sum(data['durations']) / len(data['durations'])
                del data['durations']  # Remove raw durations from output

        return dict(breakdown)

    def breakdown_by_time_bucket(self, events: List, bucket_size_ms: float = 100) -> Dict:
        """
        Break down events by time buckets.

        Args:
            events: List of event objects
            bucket_size_ms: Size of time bucket in milliseconds

        Returns:
            Dictionary mapping time buckets to event counts
        """
        if not events:
            return {}

        # Find time range
        min_time = min(e.timestamp_ns for e in events)
        max_time = max(e.timestamp_ns for e in events)

        bucket_size_ns = bucket_size_ms * 1_000_000

        # Create buckets
        buckets = defaultdict(int)

        for event in events:
            bucket_idx = int((event.timestamp_ns - min_time) / bucket_size_ns)
            buckets[bucket_idx] += 1

        return dict(buckets)

    def breakdown_by_latency_range(self, events: List) -> Dict[str, int]:
        """
        Break down events by latency ranges.

        Args:
            events: List of event objects

        Returns:
            Dictionary mapping latency ranges to counts
        """
        ranges = {
            '0-100us': 0,
            '100-500us': 0,
            '500us-1ms': 0,
            '1-5ms': 0,
            '5-10ms': 0,
            '10-50ms': 0,
            '50ms+': 0
        }

        for event in events:
            duration_us = event.duration_us

            if duration_us < 100:
                ranges['0-100us'] += 1
            elif duration_us < 500:
                ranges['100-500us'] += 1
            elif duration_us < 1000:
                ranges['500us-1ms'] += 1
            elif duration_us < 5000:
                ranges['1-5ms'] += 1
            elif duration_us < 10000:
                ranges['5-10ms'] += 1
            elif duration_us < 50000:
                ranges['10-50ms'] += 1
            else:
                ranges['50ms+'] += 1

        return ranges

    def breakdown_by_return_code(self, events: List) -> Dict[str, Dict]:
        """
        Break down events by syscall return codes.

        Args:
            events: List of event objects

        Returns:
            Dictionary with return code statistics
        """
        breakdown = defaultdict(lambda: {'count': 0, 'syscalls': defaultdict(int)})

        for event in events:
            ret_val = event.ret_val

            # Categorize return value
            if ret_val >= 0:
                category = 'success'
            elif ret_val == -1:
                category = 'error'
            else:
                category = f'error_{abs(ret_val)}'

            breakdown[category]['count'] += 1
            breakdown[category]['syscalls'][event.syscall_name] += 1

        return dict(breakdown)

    def calculate_percentiles(self, events: List, syscall: str = None) -> Dict[str, float]:
        """
        Calculate latency percentiles.

        Args:
            events: List of event objects
            syscall: Optional syscall name to filter by

        Returns:
            Dictionary with percentile values
        """
        if syscall:
            events = [e for e in events if e.syscall_name == syscall]

        if not events:
            return {}

        durations = sorted([e.duration_us for e in events])
        n = len(durations)

        percentiles = {
            'p50': durations[int(n * 0.50)] if n > 0 else 0,
            'p75': durations[int(n * 0.75)] if n > 0 else 0,
            'p90': durations[int(n * 0.90)] if n > 0 else 0,
            'p95': durations[int(n * 0.95)] if n > 0 else 0,
            'p99': durations[int(n * 0.99)] if n > 0 else 0,
            'p999': durations[int(n * 0.999)] if n > 0 else 0,
        }

        return percentiles
