# src/exporters/stdout.py - Console output exporter
"""
Exports profiling results to stdout in human-readable format.
"""

from typing import Dict, List
from colorama import Fore, Style, init
import logging


# Initialize colorama
init(autoreset=True)


class StdoutExporter:
    """
    Exports profiling results to stdout with colored output.

    Provides formatted, human-readable console output.
    """

    def __init__(self, use_colors: bool = True):
        """
        Initialize the stdout exporter.

        Args:
            use_colors: Whether to use colored output
        """
        self.use_colors = use_colors
        self.logger = logging.getLogger(__name__)

    def print_event(self, event):
        """
        Print a single event to stdout.

        Args:
            event: Event object
        """
        color = self._get_color_for_latency(event.duration_us)

        print(f"{color}[{event.syscall_name:12}] "
              f"PID={event.pid:6} TID={event.tid:6} "
              f"Duration={event.duration_us:8.0f}us "
              f"Ret={event.ret_val:4}{Style.RESET_ALL}")

    def print_events(self, events: List, limit: int = 50):
        """
        Print multiple events to stdout.

        Args:
            events: List of event objects
            limit: Maximum number of events to print
        """
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Events (showing {min(len(events), limit)} of {len(events)}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        for event in events[:limit]:
            self.print_event(event)

        if len(events) > limit:
            print(f"\n{Fore.YELLOW}... and {len(events) - limit} more events{Style.RESET_ALL}")

    def print_request(self, request):
        """
        Print request summary to stdout.

        Args:
            request: Request object
        """
        print(f"\n{Fore.GREEN}Request: {request.request_id}{Style.RESET_ALL}")
        print(f"  Duration: {request.duration_ms:.2f}ms")
        print(f"  Events:")
        print(f"    - Network: {len(request.network_events)} ({request.total_network_time_ms:.2f}ms)")
        print(f"    - File I/O: {len(request.file_io_events)} ({request.total_file_io_time_ms:.2f}ms)")
        print(f"    - Other: {len(request.syscall_events)} ({request.total_syscall_time_ms:.2f}ms)")

    def print_stats(self, stats: Dict):
        """
        Print statistics to stdout.

        Args:
            stats: Statistics dictionary
        """
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Statistics{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        if 'summary' in stats:
            summary = stats['summary']
            print(f"{Fore.YELLOW}Summary:{Style.RESET_ALL}")
            print(f"  Total Events: {summary.get('total_events', 0)}")
            print(f"  Unique Syscalls: {summary.get('unique_syscalls', 0)}")
            if 'mean_latency_us' in summary:
                print(f"  Average Latency: {summary['mean_latency_us']:.0f}us")
                print(f"  Median Latency: {summary.get('median_latency_us', 0):.0f}us")
                print(f"  Min Latency: {summary.get('min_latency_us', 0):.0f}us")
                print(f"  Max Latency: {summary.get('max_latency_us', 0):.0f}us")

        print()

    def print_hotspots(self, hotspots: List[Dict]):
        """
        Print hotspots to stdout.

        Args:
            hotspots: List of hotspot dictionaries
        """
        if not hotspots:
            return

        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Performance Hotspots{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        print(f"{'Rank':<6} {'Syscall':<15} {'Time (ms)':<12} {'%':<8} {'Count':<8} {'Avg (us)':<10} {'Severity':<10}")
        print(f"{'-'*80}")

        for i, hotspot in enumerate(hotspots[:10], 1):
            severity_color = self._get_severity_color(hotspot['severity'])

            print(f"{i:<6} "
                  f"{hotspot['syscall']:<15} "
                  f"{hotspot['total_time_ms']:<12.2f} "
                  f"{hotspot['time_percent']:<8.1f} "
                  f"{hotspot['count']:<8} "
                  f"{hotspot['avg_latency_us']:<10.0f} "
                  f"{severity_color}{hotspot['severity']:<10}{Style.RESET_ALL}")

    def print_analysis(self, analysis: Dict):
        """
        Print complete analysis to stdout.

        Args:
            analysis: Analysis dictionary
        """
        # Print summary if available
        if 'summary' in analysis:
            self.print_stats({'summary': analysis['summary']})

        # Print hotspots
        if 'hotspots' in analysis:
            self.print_hotspots(analysis['hotspots'])

        # Print slowest requests
        if 'slowest_requests' in analysis and analysis['slowest_requests']:
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Slowest Requests{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

            for i, req in enumerate(analysis['slowest_requests'][:5], 1):
                print(f"{i}. {req['request_id']} - {req['duration_ms']:.2f}ms "
                      f"({req.get('slow_events_count', 0)} slow events)")

        # Print optimization suggestions
        if 'suggestions' in analysis and analysis['suggestions']:
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Optimization Suggestions{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

            for i, suggestion in enumerate(analysis['suggestions'], 1):
                print(f"{Fore.GREEN}{i}. {suggestion}{Style.RESET_ALL}")

        print()

    def _get_color_for_latency(self, latency_us: float) -> str:
        """
        Get color based on latency threshold.

        Args:
            latency_us: Latency in microseconds

        Returns:
            Color code
        """
        if not self.use_colors:
            return ""

        if latency_us > 10000:
            return Fore.RED
        elif latency_us > 1000:
            return Fore.YELLOW
        else:
            return Fore.GREEN

    def _get_severity_color(self, severity: str) -> str:
        """
        Get color based on severity level.

        Args:
            severity: Severity level string

        Returns:
            Color code
        """
        if not self.use_colors:
            return ""

        if severity == 'high':
            return Fore.RED
        elif severity == 'medium':
            return Fore.YELLOW
        else:
            return Fore.GREEN
