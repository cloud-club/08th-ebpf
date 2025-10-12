# src/collector/aggregator.py - Event aggregation and statistics
"""
Aggregates events and computes statistics for analysis.
Provides summary metrics and percentile calculations.
"""

from typing import Dict, List, Optional
from collections import defaultdict
import statistics
import logging


class EventAggregator:
    """
    Aggregates events and computes statistics.

    Collects events and provides summary metrics like mean, median,
    percentiles, and counts grouped by syscall type.
    """

    def __init__(self):
        """
        Initialize the event aggregator.
        """
        # Events grouped by syscall name
        self.events_by_syscall: Dict[str, List] = defaultdict(list)

        # Latency buckets (microseconds)
        self.latency_buckets = [10, 50, 100, 500, 1000, 5000, 10000]
        self.latency_histogram: Dict[str, Dict[int, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        self.total_events = 0
        self.logger = logging.getLogger(__name__)

    def add_event(self, event):
        """
        Add an event to the aggregator.

        Args:
            event: Event object (SyscallEvent or subclass)
        """
        syscall_name = event.syscall_name
        self.events_by_syscall[syscall_name].append(event)

        # Update histogram
        duration_us = event.duration_us
        for bucket in self.latency_buckets:
            if duration_us <= bucket:
                self.latency_histogram[syscall_name][bucket] += 1
                break
        else:
            # Exceeds all buckets
            self.latency_histogram[syscall_name][float('inf')] += 1

        self.total_events += 1

    def get_syscall_stats(self, syscall_name: str) -> Optional[Dict]:
        """
        Get statistics for a specific syscall.

        Args:
            syscall_name: Name of the syscall

        Returns:
            Dictionary containing statistics or None if no events
        """
        events = self.events_by_syscall.get(syscall_name, [])

        if not events:
            return None

        durations_us = [e.duration_us for e in events]

        stats = {
            'count': len(events),
            'mean_us': statistics.mean(durations_us),
            'median_us': statistics.median(durations_us),
            'min_us': min(durations_us),
            'max_us': max(durations_us),
            'total_time_ms': sum(durations_us) / 1000.0
        }

        # Calculate percentiles
        if len(durations_us) >= 2:
            sorted_durations = sorted(durations_us)
            stats['p50_us'] = self._percentile(sorted_durations, 0.50)
            stats['p95_us'] = self._percentile(sorted_durations, 0.95)
            stats['p99_us'] = self._percentile(sorted_durations, 0.99)

            if len(durations_us) > 1:
                stats['stdev_us'] = statistics.stdev(durations_us)

        return stats

    def get_all_stats(self) -> Dict[str, Dict]:
        """
        Get statistics for all syscalls.

        Returns:
            Dictionary mapping syscall names to their statistics
        """
        all_stats = {}

        for syscall_name in self.events_by_syscall.keys():
            stats = self.get_syscall_stats(syscall_name)
            if stats:
                all_stats[syscall_name] = stats

        return all_stats

    def get_top_syscalls(self, n: int = 10, sort_by: str = 'total_time_ms') -> List[tuple]:
        """
        Get top N syscalls by a specific metric.

        Args:
            n: Number of top syscalls to return
            sort_by: Metric to sort by ('total_time_ms', 'count', 'mean_us')

        Returns:
            List of (syscall_name, stats) tuples
        """
        all_stats = self.get_all_stats()

        # Sort by specified metric
        sorted_syscalls = sorted(
            all_stats.items(),
            key=lambda x: x[1].get(sort_by, 0),
            reverse=True
        )

        return sorted_syscalls[:n]

    def get_latency_distribution(self, syscall_name: str) -> Dict[int, int]:
        """
        Get latency distribution histogram for a syscall.

        Args:
            syscall_name: Name of the syscall

        Returns:
            Dictionary mapping bucket thresholds to counts
        """
        return dict(self.latency_histogram.get(syscall_name, {}))

    def get_summary(self) -> Dict:
        """
        Get overall summary statistics.

        Returns:
            Dictionary with summary statistics
        """
        all_durations = []
        for events in self.events_by_syscall.values():
            all_durations.extend([e.duration_us for e in events])

        summary = {
            'total_events': self.total_events,
            'unique_syscalls': len(self.events_by_syscall),
            'total_syscalls': sum(len(events) for events in self.events_by_syscall.values())
        }

        if all_durations:
            summary['mean_latency_us'] = statistics.mean(all_durations)
            summary['median_latency_us'] = statistics.median(all_durations)
            summary['min_latency_us'] = min(all_durations)
            summary['max_latency_us'] = max(all_durations)
            summary['total_time_ms'] = sum(all_durations) / 1000.0

        return summary

    def reset(self):
        """
        Reset all statistics and clear events.
        """
        self.events_by_syscall.clear()
        self.latency_histogram.clear()
        self.total_events = 0
        self.logger.info("Aggregator reset")

    @staticmethod
    def _percentile(sorted_data: List[float], percentile: float) -> float:
        """
        Calculate percentile from sorted data.

        Args:
            sorted_data: List of values in sorted order
            percentile: Percentile to calculate (0.0-1.0)

        Returns:
            Percentile value
        """
        n = len(sorted_data)
        if n == 0:
            return 0.0

        index = percentile * (n - 1)
        lower = int(index)
        upper = min(lower + 1, n - 1)
        weight = index - lower

        return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight
