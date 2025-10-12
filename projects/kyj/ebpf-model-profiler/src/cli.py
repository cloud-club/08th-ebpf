# src/cli.py - Command-line interface
"""
Command-line interface for the eBPF Model Serving Latency Profiler.
"""

import click
import sys
from pathlib import Path

from src.utils.logger import setup_logging
from src.utils.config import Config
from src.utils.helpers import check_prerequisites, validate_pid, get_process_name


@click.group()
@click.option('--log-level', default='INFO', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']))
@click.option('--log-file', type=click.Path(), help='Log file path')
@click.pass_context
def cli(ctx, log_level, log_file):
    """
    eBPF Model Serving Latency Profiler

    A tool for profiling model serving APIs at the syscall level using eBPF.
    """
    ctx.ensure_object(dict)

    # Setup logging
    setup_logging(level=log_level, log_file=log_file)

    # Store context
    ctx.obj['log_level'] = log_level
    ctx.obj['log_file'] = log_file


@cli.command()
@click.option('--pid', type=int, required=True, help='Process ID to trace')
@click.option('--config', type=click.Path(exists=True), default='configs/default.yaml', help='Configuration file')
@click.option('--duration', type=int, help='Duration to run profiler (seconds)')
@click.option('--syscalls', help='Comma-separated list of syscalls to trace')
@click.option('--output-format', type=click.Choice(['stdout', 'json', 'prometheus']), default='stdout', help='Output format')
@click.pass_context
def start(ctx, pid, config, duration, syscalls, output_format):
    """
    Start profiling a process.

    Example:
        ebpf-profiler start --pid 1234
        ebpf-profiler start --pid 1234 --config configs/production.yaml
        ebpf-profiler start --pid 1234 --syscalls "read,write,sendto"
    """
    from src.collector.tracer import LatencyTracer
    from src.collector.event_handler import EventHandler
    from src.collector.request_tracker import RequestTracker
    from src.collector.aggregator import EventAggregator
    from src.exporters.stdout import StdoutExporter
    import logging

    logger = logging.getLogger(__name__)

    # Check prerequisites
    if not check_prerequisites():
        click.echo("Prerequisites check failed. Please fix issues above.", err=True)
        sys.exit(1)

    # Validate PID
    if not validate_pid(pid):
        click.echo(f"Error: PID {pid} not found or not accessible", err=True)
        sys.exit(1)

    process_name = get_process_name(pid)
    logger.info(f"Starting profiler for PID {pid} ({process_name})")

    # Load configuration
    cfg = Config(config)

    # Override config with CLI options
    if syscalls:
        cfg.set('syscalls.trace', syscalls.split(','))
    cfg.set('output.format', output_format)

    # Initialize components
    tracer_config = {
        'pid': pid,
        'syscalls': cfg.get('syscalls.trace', []),
        'buffer_size': cfg.get('profiler.buffer_size', 256),
        'sampling_rate': cfg.get('profiler.sampling_rate', 1.0)
    }

    tracer = LatencyTracer(tracer_config)
    event_handler = EventHandler()
    request_tracker = RequestTracker()
    aggregator = EventAggregator()
    exporter = StdoutExporter()

    # Register event callback
    def on_event(event):
        request_tracker.add_event(event)
        aggregator.add_event(event)

    event_handler.register_callback(on_event)
    tracer.register_event_handler('syscall', event_handler.handle_syscall_event)

    # Initialize and start tracing
    try:
        tracer.initialize()
        logger.info("Tracing started. Press Ctrl+C to stop.")

        if duration:
            import time
            start_time = time.time()
            while time.time() - start_time < duration:
                time.sleep(1)
            tracer.stop()
        else:
            tracer.start()

    except KeyboardInterrupt:
        logger.info("Stopping profiler...")
    except Exception as e:
        logger.error(f"Error during profiling: {e}")
        sys.exit(1)
    finally:
        # Print results
        stats = aggregator.get_summary()
        exporter.print_stats({'summary': stats})

        # Show top syscalls
        top_syscalls = aggregator.get_top_syscalls(n=10)
        if top_syscalls:
            click.echo("\nTop 10 syscalls by total time:")
            for syscall, stats in top_syscalls:
                click.echo(f"  {syscall}: {stats['total_time_ms']:.2f}ms ({stats['count']} calls)")


@cli.command()
@click.option('--format', 'output_format', type=click.Choice(['json', 'prometheus', 'stdout']), default='stdout', help='Export format')
@click.option('--output', type=click.Path(), help='Output file (for JSON format)')
@click.pass_context
def export(ctx, output_format, output):
    """
    Export collected profiling data.

    Example:
        ebpf-profiler export --format json --output results.json
        ebpf-profiler export --format prometheus
    """
    click.echo(f"Exporting data in {output_format} format...")
    # Implementation would load saved data and export
    click.echo("Note: This command requires a running profiler or saved data")


@cli.command()
def check():
    """
    Check system prerequisites for running the profiler.

    Verifies:
    - Root privileges
    - BCC installation
    - Kernel eBPF support
    """
    if check_prerequisites():
        click.echo("\n✓ All prerequisites met!")
        sys.exit(0)
    else:
        click.echo("\n✗ Some prerequisites are missing")
        sys.exit(1)


@cli.command()
@click.argument('pid', type=int)
def info(pid):
    """
    Show information about a process.

    Example:
        ebpf-profiler info 1234
    """
    if not validate_pid(pid):
        click.echo(f"Error: PID {pid} not found", err=True)
        sys.exit(1)

    process_name = get_process_name(pid)
    click.echo(f"Process ID: {pid}")
    click.echo(f"Process Name: {process_name}")

    # Additional process info could be added here
    try:
        with open(f"/proc/{pid}/cmdline", 'r') as f:
            cmdline = f.read().replace('\x00', ' ').strip()
            click.echo(f"Command Line: {cmdline}")
    except:
        pass


if __name__ == '__main__':
    cli(obj={})
