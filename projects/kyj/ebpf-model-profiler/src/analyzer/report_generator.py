# src/analyzer/report_generator.py - Report generation
"""
Generates human-readable reports from analysis results.
"""

from typing import Dict, List
from datetime import datetime
import json
import logging


class ReportGenerator:
    """
    Generates reports from analysis results in various formats.
    """

    def __init__(self):
        """
        Initialize the report generator.
        """
        self.logger = logging.getLogger(__name__)

    def generate_text_report(self, analysis: Dict) -> str:
        """
        Generate a human-readable text report.

        Args:
            analysis: Analysis results dictionary

        Returns:
            Formatted text report
        """
        lines = []
        lines.append("=" * 80)
        lines.append("eBPF Model Serving Latency Profiler - Report")
        lines.append("=" * 80)
        lines.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Summary section
        if 'summary' in analysis:
            lines.append("SUMMARY")
            lines.append("-" * 80)
            summary = analysis['summary']
            lines.append(f"Total Requests: {summary.get('total_requests', 0)}")
            lines.append(f"Average Duration: {summary.get('avg_duration_ms', 0):.2f}ms")
            lines.append(f"Median Duration: {summary.get('median_duration_ms', 0):.2f}ms")
            lines.append("")

        # Hotspots section
        if 'hotspots' in analysis and analysis['hotspots']:
            lines.append("PERFORMANCE HOTSPOTS")
            lines.append("-" * 80)
            for i, hotspot in enumerate(analysis['hotspots'][:10], 1):
                lines.append(f"{i}. {hotspot['syscall']}")
                lines.append(f"   Time: {hotspot['total_time_ms']:.2f}ms ({hotspot['time_percent']:.1f}%)")
                lines.append(f"   Count: {hotspot['count']}")
                lines.append(f"   Avg Latency: {hotspot['avg_latency_us']:.0f}us")
                lines.append(f"   Severity: {hotspot['severity']}")
                lines.append("")

        # Slowest requests
        if 'slowest_requests' in analysis and analysis['slowest_requests']:
            lines.append("SLOWEST REQUESTS")
            lines.append("-" * 80)
            for i, req in enumerate(analysis['slowest_requests'][:5], 1):
                lines.append(f"{i}. Request {req['request_id']}")
                lines.append(f"   Duration: {req['duration_ms']:.2f}ms")
                lines.append(f"   Slow Events: {req.get('slow_events_count', 0)}")
                lines.append("")

        # Category breakdown
        if 'category_averages' in analysis:
            lines.append("AVERAGE TIME BY CATEGORY")
            lines.append("-" * 80)
            cat = analysis['category_averages']
            lines.append(f"Network I/O:  {cat.get('network_avg_ms', 0):.2f}ms")
            lines.append(f"File I/O:     {cat.get('file_io_avg_ms', 0):.2f}ms")
            lines.append(f"Other:        {cat.get('other_avg_ms', 0):.2f}ms")
            lines.append("")

        # Optimization suggestions
        if 'suggestions' in analysis and analysis['suggestions']:
            lines.append("OPTIMIZATION SUGGESTIONS")
            lines.append("-" * 80)
            for i, suggestion in enumerate(analysis['suggestions'], 1):
                lines.append(f"{i}. {suggestion}")
            lines.append("")

        lines.append("=" * 80)

        return "\n".join(lines)

    def generate_json_report(self, analysis: Dict) -> str:
        """
        Generate a JSON report.

        Args:
            analysis: Analysis results dictionary

        Returns:
            JSON string
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis
        }

        return json.dumps(report, indent=2)

    def generate_csv_hotspots(self, hotspots: List[Dict]) -> str:
        """
        Generate CSV format for hotspots.

        Args:
            hotspots: List of hotspot dictionaries

        Returns:
            CSV string
        """
        lines = []
        lines.append("syscall,total_time_ms,time_percent,count,avg_latency_us,max_latency_us,severity")

        for hotspot in hotspots:
            lines.append(
                f"{hotspot['syscall']},"
                f"{hotspot['total_time_ms']:.2f},"
                f"{hotspot['time_percent']:.2f},"
                f"{hotspot['count']},"
                f"{hotspot['avg_latency_us']:.0f},"
                f"{hotspot['max_latency_us']:.0f},"
                f"{hotspot['severity']}"
            )

        return "\n".join(lines)

    def generate_markdown_report(self, analysis: Dict) -> str:
        """
        Generate a Markdown report.

        Args:
            analysis: Analysis results dictionary

        Returns:
            Markdown formatted report
        """
        lines = []
        lines.append("# eBPF Model Serving Latency Profiler Report")
        lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Summary
        if 'summary' in analysis:
            lines.append("## Summary\n")
            summary = analysis['summary']
            lines.append(f"- **Total Requests:** {summary.get('total_requests', 0)}")
            lines.append(f"- **Average Duration:** {summary.get('avg_duration_ms', 0):.2f}ms")
            lines.append(f"- **Median Duration:** {summary.get('median_duration_ms', 0):.2f}ms\n")

        # Hotspots
        if 'hotspots' in analysis and analysis['hotspots']:
            lines.append("## Performance Hotspots\n")
            lines.append("| Syscall | Total Time (ms) | % | Count | Avg Latency (us) | Severity |")
            lines.append("|---------|----------------|---|-------|-----------------|----------|")
            for hotspot in analysis['hotspots'][:10]:
                lines.append(
                    f"| {hotspot['syscall']} | {hotspot['total_time_ms']:.2f} | "
                    f"{hotspot['time_percent']:.1f}% | {hotspot['count']} | "
                    f"{hotspot['avg_latency_us']:.0f} | {hotspot['severity']} |"
                )
            lines.append("")

        # Optimization suggestions
        if 'suggestions' in analysis and analysis['suggestions']:
            lines.append("## Optimization Suggestions\n")
            for i, suggestion in enumerate(analysis['suggestions'], 1):
                lines.append(f"{i}. {suggestion}")
            lines.append("")

        return "\n".join(lines)

    def generate_summary(self, stats: Dict) -> str:
        """
        Generate a quick summary string.

        Args:
            stats: Statistics dictionary

        Returns:
            Summary string
        """
        summary = f"Total Events: {stats.get('total_events', 0)} | "
        summary += f"Unique Syscalls: {stats.get('unique_syscalls', 0)} | "
        summary += f"Avg Latency: {stats.get('mean_latency_us', 0):.0f}us"

        return summary
