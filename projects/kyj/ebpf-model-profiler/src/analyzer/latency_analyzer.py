# src/analyzer/latency_analyzer.py - Core latency analysis
"""
Core latency analysis functionality.
Analyzes syscall latency patterns and identifies performance issues.
"""

from typing import List, Dict, Optional
from collections import defaultdict
import statistics
import logging


class LatencyAnalyzer:
    """
    Analyzes latency patterns from collected events.

    Provides analysis of latency distributions, trends, and anomalies.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the latency analyzer.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Thresholds for flagging issues (microseconds)
        self.slow_threshold_us = self.config.get('slow_threshold_us', 1000)
        self.very_slow_threshold_us = self.config.get('very_slow_threshold_us', 10000)

    def analyze_request(self, request) -> Dict:
        """
        Analyze a single request's latency breakdown.

        Args:
            request: Request object with events

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'request_id': request.request_id,
            'total_duration_ms': request.duration_ms,
            'syscall_breakdown': self._analyze_syscall_breakdown(request),
            'category_breakdown': self._analyze_category_breakdown(request),
            'slow_events': self._find_slow_events(request),
            'event_counts': self._count_events_by_type(request)
        }

        return analysis

    def _analyze_syscall_breakdown(self, request) -> Dict[str, float]:
        """
        Break down latency by individual syscall types.

        Args:
            request: Request object

        Returns:
            Dictionary mapping syscall names to total time in ms
        """
        breakdown = defaultdict(float)

        all_events = (
            request.syscall_events +
            request.network_events +
            request.file_io_events
        )

        for event in all_events:
            breakdown[event.syscall_name] += event.duration_ms

        return dict(breakdown)

    def _analyze_category_breakdown(self, request) -> Dict[str, Dict]:
        """
        Break down latency by categories (network, file I/O, other).

        Args:
            request: Request object

        Returns:
            Dictionary with category breakdown
        """
        breakdown = {
            'network': {
                'total_ms': request.total_network_time_ms,
                'count': len(request.network_events),
                'percentage': 0.0
            },
            'file_io': {
                'total_ms': request.total_file_io_time_ms,
                'count': len(request.file_io_events),
                'percentage': 0.0
            },
            'other': {
                'total_ms': request.total_syscall_time_ms,
                'count': len(request.syscall_events),
                'percentage': 0.0
            }
        }

        # Calculate percentages
        total_time = (
            request.total_network_time_ms +
            request.total_file_io_time_ms +
            request.total_syscall_time_ms
        )

        if total_time > 0:
            for category in breakdown.values():
                category['percentage'] = (category['total_ms'] / total_time) * 100

        return breakdown

    def _find_slow_events(self, request) -> List[Dict]:
        """
        Find events that exceed slow thresholds.

        Args:
            request: Request object

        Returns:
            List of slow event details
        """
        slow_events = []

        all_events = (
            request.syscall_events +
            request.network_events +
            request.file_io_events
        )

        for event in all_events:
            if event.duration_us >= self.slow_threshold_us:
                severity = 'slow' if event.duration_us < self.very_slow_threshold_us else 'very_slow'

                slow_events.append({
                    'syscall': event.syscall_name,
                    'duration_us': event.duration_us,
                    'severity': severity,
                    'timestamp': event.timestamp_ns
                })

        # Sort by duration descending
        slow_events.sort(key=lambda x: x['duration_us'], reverse=True)

        return slow_events

    def _count_events_by_type(self, request) -> Dict[str, int]:
        """
        Count events by type.

        Args:
            request: Request object

        Returns:
            Dictionary with event counts
        """
        return {
            'network': len(request.network_events),
            'file_io': len(request.file_io_events),
            'other': len(request.syscall_events),
            'total': (
                len(request.network_events) +
                len(request.file_io_events) +
                len(request.syscall_events)
            )
        }

    def analyze_multiple_requests(self, requests: List) -> Dict:
        """
        Analyze multiple requests and find patterns.

        Args:
            requests: List of Request objects

        Returns:
            Dictionary with aggregate analysis
        """
        if not requests:
            return {}

        analyses = [self.analyze_request(req) for req in requests]

        aggregate = {
            'total_requests': len(requests),
            'avg_duration_ms': statistics.mean([r.duration_ms for r in requests if r.duration_ms]),
            'median_duration_ms': statistics.median([r.duration_ms for r in requests if r.duration_ms]),
            'slowest_requests': self._find_slowest_requests(analyses),
            'common_slow_syscalls': self._find_common_slow_syscalls(analyses),
            'category_averages': self._calculate_category_averages(analyses)
        }

        return aggregate

    def _find_slowest_requests(self, analyses: List[Dict], n: int = 5) -> List[Dict]:
        """
        Find N slowest requests.

        Args:
            analyses: List of request analyses
            n: Number of slowest requests to return

        Returns:
            List of slowest request summaries
        """
        sorted_analyses = sorted(
            analyses,
            key=lambda x: x.get('total_duration_ms', 0) or 0,
            reverse=True
        )

        return [{
            'request_id': a['request_id'],
            'duration_ms': a['total_duration_ms'],
            'slow_events_count': len(a['slow_events'])
        } for a in sorted_analyses[:n]]

    def _find_common_slow_syscalls(self, analyses: List[Dict]) -> Dict[str, int]:
        """
        Find syscalls that commonly appear in slow events.

        Args:
            analyses: List of request analyses

        Returns:
            Dictionary mapping syscall names to count of slow occurrences
        """
        slow_syscall_counts = defaultdict(int)

        for analysis in analyses:
            for slow_event in analysis['slow_events']:
                slow_syscall_counts[slow_event['syscall']] += 1

        # Sort by count
        sorted_syscalls = dict(
            sorted(slow_syscall_counts.items(), key=lambda x: x[1], reverse=True)
        )

        return sorted_syscalls

    def _calculate_category_averages(self, analyses: List[Dict]) -> Dict[str, float]:
        """
        Calculate average time spent in each category.

        Args:
            analyses: List of request analyses

        Returns:
            Dictionary with average times per category
        """
        categories = ['network', 'file_io', 'other']
        averages = {}

        for category in categories:
            times = [
                a['category_breakdown'][category]['total_ms']
                for a in analyses
                if category in a.get('category_breakdown', {})
            ]

            if times:
                averages[f'{category}_avg_ms'] = statistics.mean(times)
            else:
                averages[f'{category}_avg_ms'] = 0.0

        return averages
