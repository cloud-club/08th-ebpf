# src/analyzer/hotspot_detector.py - Performance hotspot detection
"""
Detects performance hotspots and bottlenecks in the traced application.
"""

from typing import List, Dict, Tuple
from collections import defaultdict
import logging


class HotspotDetector:
    """
    Detects performance hotspots and bottlenecks.

    Identifies syscalls or patterns that contribute most to latency.
    """

    def __init__(self, config: Dict = None):
        """
        Initialize the hotspot detector.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Thresholds for hotspot detection
        self.time_threshold_percent = self.config.get('time_threshold_percent', 10.0)
        self.count_threshold = self.config.get('count_threshold', 5)

    def detect_hotspots(self, events: List) -> List[Dict]:
        """
        Detect performance hotspots from events.

        Args:
            events: List of event objects

        Returns:
            List of hotspot dictionaries
        """
        if not events:
            return []

        # Calculate total time
        total_time_ms = sum(e.duration_ms for e in events)

        # Group by syscall
        syscall_stats = self._group_by_syscall(events)

        # Find hotspots
        hotspots = []

        for syscall, stats in syscall_stats.items():
            time_percent = (stats['total_time_ms'] / total_time_ms) * 100

            # Check if this is a hotspot
            if time_percent >= self.time_threshold_percent or stats['count'] >= self.count_threshold:
                hotspot = {
                    'syscall': syscall,
                    'total_time_ms': stats['total_time_ms'],
                    'time_percent': time_percent,
                    'count': stats['count'],
                    'avg_latency_us': stats['avg_latency_us'],
                    'max_latency_us': stats['max_latency_us'],
                    'severity': self._calculate_severity(time_percent, stats['count'])
                }

                hotspots.append(hotspot)

        # Sort by time percentage descending
        hotspots.sort(key=lambda x: x['time_percent'], reverse=True)

        return hotspots

    def _group_by_syscall(self, events: List) -> Dict[str, Dict]:
        """
        Group events by syscall and calculate statistics.

        Args:
            events: List of event objects

        Returns:
            Dictionary with per-syscall statistics
        """
        grouped = defaultdict(lambda: {
            'count': 0,
            'total_time_ms': 0.0,
            'durations': []
        })

        for event in events:
            syscall = event.syscall_name
            grouped[syscall]['count'] += 1
            grouped[syscall]['total_time_ms'] += event.duration_ms
            grouped[syscall]['durations'].append(event.duration_us)

        # Calculate averages and max
        for syscall, stats in grouped.items():
            durations = stats['durations']
            stats['avg_latency_us'] = sum(durations) / len(durations)
            stats['max_latency_us'] = max(durations)
            del stats['durations']

        return dict(grouped)

    def _calculate_severity(self, time_percent: float, count: int) -> str:
        """
        Calculate severity level of a hotspot.

        Args:
            time_percent: Percentage of total time
            count: Number of occurrences

        Returns:
            Severity level string
        """
        if time_percent >= 30 or count >= 100:
            return 'high'
        elif time_percent >= 15 or count >= 20:
            return 'medium'
        else:
            return 'low'

    def detect_sequential_patterns(self, events: List) -> List[Dict]:
        """
        Detect common sequential patterns of syscalls.

        Args:
            events: List of event objects (should be ordered by timestamp)

        Returns:
            List of pattern dictionaries
        """
        if len(events) < 2:
            return []

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp_ns)

        # Find patterns (sequences of 2-3 syscalls)
        patterns = defaultdict(lambda: {'count': 0, 'avg_total_time_ms': []})

        # Look for 2-syscall patterns
        for i in range(len(sorted_events) - 1):
            pattern = f"{sorted_events[i].syscall_name} -> {sorted_events[i+1].syscall_name}"
            total_time = sorted_events[i].duration_ms + sorted_events[i+1].duration_ms

            patterns[pattern]['count'] += 1
            patterns[pattern]['avg_total_time_ms'].append(total_time)

        # Calculate averages
        result = []
        for pattern, stats in patterns.items():
            if stats['count'] >= 3:  # Only patterns that occur at least 3 times
                result.append({
                    'pattern': pattern,
                    'count': stats['count'],
                    'avg_total_time_ms': sum(stats['avg_total_time_ms']) / len(stats['avg_total_time_ms'])
                })

        # Sort by count descending
        result.sort(key=lambda x: x['count'], reverse=True)

        return result

    def detect_outliers(self, events: List, threshold_factor: float = 3.0) -> List[Dict]:
        """
        Detect outlier events with unusually high latency.

        Args:
            events: List of event objects
            threshold_factor: Factor above mean to consider outlier

        Returns:
            List of outlier event details
        """
        if not events:
            return []

        # Group by syscall
        syscall_groups = defaultdict(list)
        for event in events:
            syscall_groups[event.syscall_name].append(event)

        outliers = []

        # Find outliers in each group
        for syscall, group_events in syscall_groups.items():
            if len(group_events) < 2:
                continue

            durations = [e.duration_us for e in group_events]
            mean_duration = sum(durations) / len(durations)
            threshold = mean_duration * threshold_factor

            for event in group_events:
                if event.duration_us > threshold:
                    outliers.append({
                        'syscall': syscall,
                        'duration_us': event.duration_us,
                        'mean_us': mean_duration,
                        'factor_above_mean': event.duration_us / mean_duration,
                        'timestamp_ns': event.timestamp_ns,
                        'pid': event.pid,
                        'tid': event.tid
                    })

        # Sort by factor above mean
        outliers.sort(key=lambda x: x['factor_above_mean'], reverse=True)

        return outliers

    def suggest_optimizations(self, hotspots: List[Dict]) -> List[str]:
        """
        Suggest optimizations based on detected hotspots.

        Args:
            hotspots: List of hotspot dictionaries

        Returns:
            List of optimization suggestions
        """
        suggestions = []

        for hotspot in hotspots:
            syscall = hotspot['syscall']
            time_percent = hotspot['time_percent']

            if syscall in ['read', 'write'] and time_percent > 20:
                suggestions.append(
                    f"Consider using buffered I/O or increasing buffer sizes "
                    f"({syscall} accounts for {time_percent:.1f}% of total time)"
                )

            elif syscall in ['openat'] and hotspot['count'] > 50:
                suggestions.append(
                    f"Consider caching file descriptors or keeping files open "
                    f"({hotspot['count']} openat calls detected)"
                )

            elif syscall in ['sendto', 'recvfrom'] and time_percent > 25:
                suggestions.append(
                    f"Network I/O is a bottleneck ({time_percent:.1f}% of total time). "
                    f"Consider using connection pooling or async I/O"
                )

            elif hotspot['avg_latency_us'] > 10000:
                suggestions.append(
                    f"{syscall} has high average latency ({hotspot['avg_latency_us']:.0f}us). "
                    f"Consider investigating underlying resource contention"
                )

        return suggestions
