# src/exporters/json_exporter.py - JSON format exporter
"""
Exports profiling results as JSON files.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import logging


class JSONExporter:
    """
    Exports profiling results to JSON format.

    Provides structured JSON output for further processing or visualization.
    """

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the JSON exporter.

        Args:
            output_dir: Directory to save JSON files (default: current directory)
        """
        self.output_dir = Path(output_dir) if output_dir else Path('.')
        self.logger = logging.getLogger(__name__)

        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_events(self, events: List, filename: Optional[str] = None) -> str:
        """
        Export events to JSON file.

        Args:
            events: List of event objects
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to output file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'events_{timestamp}.json'

        output_path = self.output_dir / filename

        # Convert events to dictionaries
        events_data = []
        for event in events:
            event_dict = {
                'pid': event.pid,
                'tid': event.tid,
                'timestamp_ns': event.timestamp_ns,
                'duration_ns': event.duration_ns,
                'duration_us': event.duration_us,
                'comm': event.comm,
                'syscall_name': event.syscall_name,
                'ret_val': event.ret_val
            }

            # Add extra fields for network/file I/O events
            if hasattr(event, 'bytes'):
                event_dict['bytes'] = event.bytes
            if hasattr(event, 'fd'):
                event_dict['fd'] = event.fd
            if hasattr(event, 'path'):
                event_dict['path'] = event.path

            events_data.append(event_dict)

        # Write to file
        with open(output_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'event_count': len(events_data),
                'events': events_data
            }, f, indent=2)

        self.logger.info(f"Exported {len(events_data)} events to {output_path}")
        return str(output_path)

    def export_requests(self, requests: List, filename: Optional[str] = None) -> str:
        """
        Export requests to JSON file.

        Args:
            requests: List of Request objects
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to output file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'requests_{timestamp}.json'

        output_path = self.output_dir / filename

        # Convert requests to dictionaries
        requests_data = []
        for request in requests:
            request_dict = {
                'request_id': request.request_id,
                'pid': request.pid,
                'tid': request.tid,
                'start_time': request.start_time,
                'end_time': request.end_time,
                'duration_ms': request.duration_ms,
                'total_syscall_time_ms': request.total_syscall_time_ms,
                'total_network_time_ms': request.total_network_time_ms,
                'total_file_io_time_ms': request.total_file_io_time_ms,
                'event_counts': {
                    'syscall': len(request.syscall_events),
                    'network': len(request.network_events),
                    'file_io': len(request.file_io_events)
                }
            }

            requests_data.append(request_dict)

        # Write to file
        with open(output_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'request_count': len(requests_data),
                'requests': requests_data
            }, f, indent=2)

        self.logger.info(f"Exported {len(requests_data)} requests to {output_path}")
        return str(output_path)

    def export_analysis(self, analysis: Dict, filename: Optional[str] = None) -> str:
        """
        Export analysis results to JSON file.

        Args:
            analysis: Analysis dictionary
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to output file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'analysis_{timestamp}.json'

        output_path = self.output_dir / filename

        # Add metadata
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis
        }

        # Write to file
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)

        self.logger.info(f"Exported analysis to {output_path}")
        return str(output_path)

    def export_stats(self, stats: Dict, filename: Optional[str] = None) -> str:
        """
        Export statistics to JSON file.

        Args:
            stats: Statistics dictionary
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to output file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'stats_{timestamp}.json'

        output_path = self.output_dir / filename

        # Add metadata
        output_data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': stats
        }

        # Write to file
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)

        self.logger.info(f"Exported statistics to {output_path}")
        return str(output_path)
