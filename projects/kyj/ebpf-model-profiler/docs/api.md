# API Documentation

## CLI Commands

### ebpf-profiler start

Start profiling a process.

```bash
ebpf-profiler start [OPTIONS]
```

**Options:**
- `--pid INTEGER` [required]: Process ID to trace
- `--config PATH`: Configuration file (default: configs/default.yaml)
- `--duration INTEGER`: Duration in seconds
- `--syscalls TEXT`: Comma-separated list of syscalls
- `--output-format [stdout|json|prometheus]`: Output format

**Examples:**

```bash
# Basic usage
sudo ebpf-profiler start --pid 1234

# With custom config
sudo ebpf-profiler start --pid 1234 --config configs/production.yaml

# Specific syscalls only
sudo ebpf-profiler start --pid 1234 --syscalls "read,write,sendto"

# Limited duration
sudo ebpf-profiler start --pid 1234 --duration 60
```

### ebpf-profiler export

Export collected data.

```bash
ebpf-profiler export [OPTIONS]
```

**Options:**
- `--format [json|prometheus|stdout]`: Export format
- `--output PATH`: Output file path (for JSON)

**Examples:**

```bash
# Export as JSON
sudo ebpf-profiler export --format json --output results.json

# Start Prometheus endpoint
sudo ebpf-profiler export --format prometheus
```

### ebpf-profiler check

Check system prerequisites.

```bash
ebpf-profiler check
```

### ebpf-profiler info

Show information about a process.

```bash
ebpf-profiler info PID
```

## Python API

### LatencyTracer

Main tracer class for collecting syscall events.

```python
from src.collector.tracer import LatencyTracer

config = {
    'pid': 1234,
    'syscalls': ['read', 'write'],
    'buffer_size': 256
}

tracer = LatencyTracer(config)
tracer.initialize()
tracer.start()
```

**Methods:**

- `initialize()`: Load eBPF programs
- `start()`: Begin tracing
- `stop()`: Stop tracing
- `register_event_handler(event_type, handler)`: Register callback
- `get_stats()`: Get current statistics

### EventHandler

Process raw events from eBPF.

```python
from src.collector.event_handler import EventHandler

handler = EventHandler()

def on_event(event):
    print(f"Syscall: {event.syscall_name}, Latency: {event.duration_us}us")

handler.register_callback(on_event)
```

**Methods:**

- `register_callback(callback)`: Register event callback
- `handle_syscall_event(raw_event)`: Process syscall event
- `handle_network_event(raw_event)`: Process network event
- `handle_file_io_event(raw_event)`: Process file I/O event
- `get_stats()`: Get handler statistics

### EventAggregator

Aggregate events and compute statistics.

```python
from src.collector.aggregator import EventAggregator

aggregator = EventAggregator()
aggregator.add_event(event)

stats = aggregator.get_syscall_stats('read')
print(f"Mean latency: {stats['mean_us']}us")

top_syscalls = aggregator.get_top_syscalls(n=10)
```

**Methods:**

- `add_event(event)`: Add event to aggregator
- `get_syscall_stats(syscall_name)`: Get stats for specific syscall
- `get_all_stats()`: Get stats for all syscalls
- `get_top_syscalls(n, sort_by)`: Get top N syscalls
- `get_summary()`: Get overall summary
- `reset()`: Clear all data

### LatencyAnalyzer

Analyze latency patterns.

```python
from src.analyzer.latency_analyzer import LatencyAnalyzer

analyzer = LatencyAnalyzer()
analysis = analyzer.analyze_request(request)

print(f"Total duration: {analysis['total_duration_ms']}ms")
print(f"Slow events: {len(analysis['slow_events'])}")
```

**Methods:**

- `analyze_request(request)`: Analyze single request
- `analyze_multiple_requests(requests)`: Analyze multiple requests

### HotspotDetector

Detect performance hotspots.

```python
from src.analyzer.hotspot_detector import HotspotDetector

detector = HotspotDetector()
hotspots = detector.detect_hotspots(events)

for hotspot in hotspots:
    print(f"{hotspot['syscall']}: {hotspot['time_percent']:.1f}%")

suggestions = detector.suggest_optimizations(hotspots)
```

**Methods:**

- `detect_hotspots(events)`: Detect hotspots
- `detect_sequential_patterns(events)`: Find common patterns
- `detect_outliers(events)`: Find outlier events
- `suggest_optimizations(hotspots)`: Get optimization suggestions

### PrometheusExporter

Export metrics to Prometheus.

```python
from src.exporters.prometheus import PrometheusExporter

exporter = PrometheusExporter(port=9090)
exporter.start()

# Record events
exporter.record_syscall(event)
exporter.record_request(request)

# Metrics available at http://localhost:9090/metrics
```

**Methods:**

- `start()`: Start HTTP server
- `record_syscall(event)`: Record syscall event
- `record_request(request)`: Record request
- `update_active_requests(pid, count)`: Update gauge

### JSONExporter

Export data as JSON.

```python
from src.exporters.json_exporter import JSONExporter

exporter = JSONExporter(output_dir='./output')
exporter.export_events(events, 'events.json')
exporter.export_analysis(analysis, 'analysis.json')
```

**Methods:**

- `export_events(events, filename)`: Export events
- `export_requests(requests, filename)`: Export requests
- `export_analysis(analysis, filename)`: Export analysis
- `export_stats(stats, filename)`: Export statistics

### ReportGenerator

Generate reports in various formats.

```python
from src.analyzer.report_generator import ReportGenerator

generator = ReportGenerator()

# Text report
text = generator.generate_text_report(analysis)
print(text)

# JSON report
json_str = generator.generate_json_report(analysis)

# Markdown report
markdown = generator.generate_markdown_report(analysis)
```

**Methods:**

- `generate_text_report(analysis)`: Generate text report
- `generate_json_report(analysis)`: Generate JSON report
- `generate_markdown_report(analysis)`: Generate Markdown report
- `generate_csv_hotspots(hotspots)`: Generate CSV
- `generate_summary(stats)`: Generate quick summary

## Configuration File Format

### YAML Configuration

```yaml
profiler:
  sampling_rate: 1.0
  buffer_size: 256

syscalls:
  trace:
    - read
    - write

filters:
  min_duration_us: 100

output:
  format: stdout
  prometheus_port: 9090

analysis:
  slow_threshold_us: 1000
```

### Config Class

```python
from src.utils.config import Config

config = Config('configs/default.yaml')

# Get values
buffer_size = config.get('profiler.buffer_size')

# Set values
config.set('profiler.buffer_size', 512)

# Save
config.save_to_file('configs/custom.yaml')
```

## Event Data Structures

### SyscallEvent

```python
@dataclass
class SyscallEvent:
    pid: int
    tid: int
    timestamp_ns: int
    duration_ns: int
    comm: str
    syscall_id: int
    syscall_name: str
    event_type: int
    ret_val: int

    # Properties
    duration_us: float  # Duration in microseconds
    duration_ms: float  # Duration in milliseconds
```

### Request

```python
@dataclass
class Request:
    request_id: str
    start_time: float
    end_time: Optional[float]
    pid: int
    tid: int

    syscall_events: List
    network_events: List
    file_io_events: List

    # Properties
    duration_ms: Optional[float]
    total_syscall_time_ms: float
    total_network_time_ms: float
    total_file_io_time_ms: float
```
