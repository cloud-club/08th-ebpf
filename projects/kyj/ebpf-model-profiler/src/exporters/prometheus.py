# src/exporters/prometheus.py - Prometheus metrics exporter
"""
Exports profiling metrics in Prometheus format.
Provides HTTP endpoint for Prometheus to scrape.
"""

from prometheus_client import Counter, Histogram, Gauge, start_http_server, REGISTRY
from typing import Dict, List
import logging
import time


class PrometheusExporter:
    """
    Exports metrics to Prometheus.

    Exposes an HTTP endpoint that Prometheus can scrape for metrics.
    """

    def __init__(self, port: int = 9090):
        """
        Initialize the Prometheus exporter.

        Args:
            port: Port to expose metrics on
        """
        self.port = port
        self.logger = logging.getLogger(__name__)

        # Define metrics
        self.syscall_duration = Histogram(
            'ebpf_profiler_syscall_duration_microseconds',
            'Duration of syscalls in microseconds',
            ['syscall', 'pid'],
            buckets=[10, 50, 100, 500, 1000, 5000, 10000, 50000]
        )

        self.syscall_count = Counter(
            'ebpf_profiler_syscall_count_total',
            'Total number of syscalls',
            ['syscall', 'pid']
        )

        self.request_duration = Histogram(
            'ebpf_profiler_request_duration_milliseconds',
            'Duration of requests in milliseconds',
            ['pid'],
            buckets=[10, 50, 100, 200, 500, 1000, 2000, 5000]
        )

        self.request_count = Counter(
            'ebpf_profiler_request_count_total',
            'Total number of requests',
            ['pid']
        )

        self.network_bytes = Counter(
            'ebpf_profiler_network_bytes_total',
            'Total network bytes transferred',
            ['direction', 'pid']
        )

        self.file_io_bytes = Counter(
            'ebpf_profiler_file_io_bytes_total',
            'Total file I/O bytes',
            ['operation', 'pid']
        )

        self.active_requests = Gauge(
            'ebpf_profiler_active_requests',
            'Number of active requests',
            ['pid']
        )

        self.logger.info(f"Prometheus exporter initialized on port {port}")

    def start(self):
        """
        Start the Prometheus HTTP server.
        """
        try:
            start_http_server(self.port)
            self.logger.info(f"Prometheus metrics available at http://localhost:{self.port}/metrics")
        except Exception as e:
            self.logger.error(f"Failed to start Prometheus server: {e}")
            raise

    def record_syscall(self, event):
        """
        Record a syscall event.

        Args:
            event: Event object (SyscallEvent or subclass)
        """
        pid = str(event.pid)
        syscall = event.syscall_name

        # Record duration
        self.syscall_duration.labels(syscall=syscall, pid=pid).observe(event.duration_us)

        # Increment counter
        self.syscall_count.labels(syscall=syscall, pid=pid).inc()

        # Record bytes for network/file I/O
        if hasattr(event, 'bytes') and event.bytes > 0:
            if syscall in ['sendto', 'sendmsg']:
                self.network_bytes.labels(direction='sent', pid=pid).inc(event.bytes)
            elif syscall in ['recvfrom', 'recvmsg']:
                self.network_bytes.labels(direction='received', pid=pid).inc(event.bytes)
            elif syscall in ['read', 'write']:
                operation = 'read' if syscall == 'read' else 'write'
                self.file_io_bytes.labels(operation=operation, pid=pid).inc(event.bytes)

    def record_request(self, request):
        """
        Record a completed request.

        Args:
            request: Request object
        """
        pid = str(request.pid)

        if request.duration_ms:
            self.request_duration.labels(pid=pid).observe(request.duration_ms)

        self.request_count.labels(pid=pid).inc()

    def update_active_requests(self, pid: int, count: int):
        """
        Update the number of active requests.

        Args:
            pid: Process ID
            count: Number of active requests
        """
        self.active_requests.labels(pid=str(pid)).set(count)

    def get_metrics_text(self) -> str:
        """
        Get current metrics in Prometheus text format.

        Returns:
            Metrics as text
        """
        from prometheus_client import generate_latest
        return generate_latest(REGISTRY).decode('utf-8')
