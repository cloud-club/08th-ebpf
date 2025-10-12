# Development Guide

## Setting Up Development Environment

### Prerequisites

- Linux system with kernel 4.9+ (5.0+ recommended)
- Python 3.8+
- BCC (BPF Compiler Collection)
- Root/sudo access

### Installation

```bash
# Clone repository
git clone <repo-url>
cd ebpf-model-profiler

# Install BCC
./scripts/setup_bcc.sh

# Install Python dependencies
pip install -e ".[dev]"

# Or use make
make dev-install
```

### Verify Installation

```bash
# Check kernel support
python scripts/check_kernel.py

# Or use CLI
ebpf-profiler check
```

## Project Structure

```
ebpf-model-profiler/
├── src/                    # Source code
│   ├── ebpf/              # eBPF C programs
│   ├── collector/         # Event collection
│   ├── analyzer/          # Analysis modules
│   ├── exporters/         # Output exporters
│   ├── utils/             # Utilities
│   └── cli.py             # CLI interface
├── examples/              # Example applications
├── tests/                 # Unit tests
├── configs/               # Configuration files
├── scripts/               # Utility scripts
├── dashboards/            # Grafana/Prometheus
└── docs/                  # Documentation
```

## Development Workflow

### 1. Adding a New Syscall Tracer

#### Step 1: Update eBPF Program

Edit `src/ebpf/syscall_tracer.c`:

```c
// Add entry trace function
int trace_<syscall>_enter(struct pt_regs *ctx) {
    return trace_syscall_enter(ctx);
}

// Add exit trace function
int trace_<syscall>_exit(struct pt_regs *ctx) {
    return trace_syscall_exit(ctx, "<syscall>");
}
```

#### Step 2: Update Tracer

Edit `src/collector/tracer.py`:

```python
# Add to _attach_syscalls method
self.bpf.attach_kprobe(
    event=f"__sys_{syscall}",
    fn_name=f"trace_{syscall}_enter"
)
self.bpf.attach_kretprobe(
    event=f"__sys_{syscall}",
    fn_name=f"trace_{syscall}_exit"
)
```

#### Step 3: Update Configuration

Add to `configs/syscalls.yaml`:

```yaml
syscalls:
  <syscall>:
    category: <category>
    description: "<description>"
```

### 2. Adding a New Exporter

Create `src/exporters/new_exporter.py`:

```python
class NewExporter:
    def __init__(self, config):
        self.config = config

    def export_events(self, events):
        # Implementation
        pass

    def export_analysis(self, analysis):
        # Implementation
        pass
```

Register in CLI (`src/cli.py`):

```python
from src.exporters.new_exporter import NewExporter

# Use in command
exporter = NewExporter(config)
exporter.export_analysis(analysis)
```

### 3. Adding Analysis Features

Create new analyzer in `src/analyzer/`:

```python
class CustomAnalyzer:
    def analyze(self, events):
        # Your analysis logic
        return results
```

Integrate in main analysis flow.

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/test_tracer.py::TestLatencyTracer::test_initialization
```

### Writing Tests

```python
# tests/test_new_feature.py
import pytest
from src.module import NewClass

class TestNewFeature:
    def test_something(self):
        obj = NewClass()
        result = obj.method()
        assert result == expected
```

### Integration Testing

```bash
# Start example app
cd examples/fastapi_app
python app.py &
APP_PID=$!

# Run profiler
sudo ebpf-profiler start --pid $APP_PID --duration 10

# Generate load
cd ../load_test
python simple_test.py

# Check results
# ...

# Cleanup
kill $APP_PID
```

## Debugging

### eBPF Program Debugging

```bash
# Check BPF program compilation
python -c "from bcc import BPF; BPF(src_file='src/ebpf/syscall_tracer.c')"

# Enable BCC debug output
export BCC_DEBUG=1
```

### Python Debugging

```python
# Add to code
import logging
logging.basicConfig(level=logging.DEBUG)

# Or use debugger
import pdb; pdb.set_trace()
```

### Checking Events

```bash
# Use BCC trace tool to verify events
sudo trace -t -p <PID> 'r::__sys_read' 'r::__sys_write'
```

## Code Style

### Python

Follow PEP 8:

```bash
# Format with black
black src/

# Lint with flake8
flake8 src/

# Type check with mypy
mypy src/
```

### C (eBPF)

Follow kernel coding style:

```bash
# Use clang-format
clang-format -i src/ebpf/*.c
```

## Documentation

### Adding Documentation

- API docs: Use docstrings
- Architecture: Update `docs/architecture.md`
- User guide: Update `README.md`

### Building Docs

```bash
# If using Sphinx
cd docs
make html
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run tests and linting
5. Submit pull request

## Performance Profiling

Profile the profiler itself:

```bash
# Use cProfile
python -m cProfile -o profile.stats src/cli.py start --pid <PID>

# Analyze with snakeviz
snakeviz profile.stats
```

## Troubleshooting

### Common Issues

1. **"Permission denied" errors**
   - Solution: Run with sudo

2. **"BPF program failed to load"**
   - Check kernel version
   - Verify BCC installation
   - Check dmesg for errors

3. **No events captured**
   - Verify PID is correct
   - Check syscalls are configured
   - Ensure process is active

### Getting Help

- Check `docs/troubleshooting.md`
- Review GitHub issues
- Enable debug logging
