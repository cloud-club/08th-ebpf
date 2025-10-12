#!/usr/bin/env python3
"""
eBPF Storage Exporter
eBPF를 사용하여 노드의 스토리지 I/O 메트릭을 수집하고 Prometheus Format으로 제공하는 exporter
"""

from http.server import HTTPServer
from metrics_collector import MetricsCollector
from http_handler import MetricsHandler

def main():
    print("Starting eBPF Storage Exporter...")
    collector = MetricsCollector()

    def handler(*args, **kwargs):
        return MetricsHandler(collector, *args, **kwargs)

    server = HTTPServer(('127.0.0.1', 8080), handler)
    print("Metrics server running on http://127.0.0.1:8080/metrics")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()

if __name__ == "__main__":
    main()
