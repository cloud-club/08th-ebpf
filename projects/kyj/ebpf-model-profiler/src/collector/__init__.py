# src/collector/__init__.py - Event collection module
"""
Collector module for gathering eBPF events from kernel space.

This module provides:
- tracer.py: Main BCC-based tracer for loading eBPF programs
- event_handler.py: Handler for processing perf events
- request_tracker.py: Request lifecycle tracking
- aggregator.py: Event aggregation and statistics
"""
