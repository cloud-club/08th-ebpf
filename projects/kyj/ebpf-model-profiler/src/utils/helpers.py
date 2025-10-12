# src/utils/helpers.py - Helper functions
"""
General utility and helper functions.
"""

import os
import sys
from typing import Optional
import subprocess
import logging


logger = logging.getLogger(__name__)


def check_root_privileges() -> bool:
    """
    Check if running with root privileges.

    Returns:
        True if running as root, False otherwise
    """
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def check_bcc_installed() -> bool:
    """
    Check if BCC is installed and available.

    Returns:
        True if BCC is available, False otherwise
    """
    try:
        import bcc
        return True
    except ImportError:
        return False


def check_kernel_version() -> tuple:
    """
    Get Linux kernel version.

    Returns:
        Tuple of (major, minor, patch) version numbers
    """
    try:
        result = subprocess.run(
            ['uname', '-r'],
            capture_output=True,
            text=True,
            check=True
        )

        version_str = result.stdout.strip().split('-')[0]
        parts = version_str.split('.')

        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0

        return (major, minor, patch)

    except Exception as e:
        logger.error(f"Failed to get kernel version: {e}")
        return (0, 0, 0)


def check_ebpf_support() -> bool:
    """
    Check if the kernel supports eBPF.

    Returns:
        True if eBPF is supported, False otherwise
    """
    major, minor, _ = check_kernel_version()

    # eBPF requires kernel 4.1+, but BCC works best with 4.9+
    if major < 4 or (major == 4 and minor < 9):
        logger.warning(f"Kernel version {major}.{minor} may not fully support eBPF (4.9+ recommended)")
        return False

    return True


def validate_pid(pid: int) -> bool:
    """
    Validate that a PID exists and is accessible.

    Args:
        pid: Process ID to validate

    Returns:
        True if PID is valid, False otherwise
    """
    try:
        # Check if process exists
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def format_bytes(bytes_count: int) -> str:
    """
    Format bytes into human-readable string.

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0

    return f"{bytes_count:.1f} PB"


def format_duration(duration_ns: int) -> str:
    """
    Format duration in nanoseconds to human-readable string.

    Args:
        duration_ns: Duration in nanoseconds

    Returns:
        Formatted string (e.g., "1.5 ms")
    """
    if duration_ns < 1000:
        return f"{duration_ns}ns"
    elif duration_ns < 1_000_000:
        return f"{duration_ns/1000:.1f}us"
    elif duration_ns < 1_000_000_000:
        return f"{duration_ns/1_000_000:.1f}ms"
    else:
        return f"{duration_ns/1_000_000_000:.1f}s"


def get_process_name(pid: int) -> Optional[str]:
    """
    Get process name from PID.

    Args:
        pid: Process ID

    Returns:
        Process name or None if not found
    """
    try:
        with open(f"/proc/{pid}/comm", 'r') as f:
            return f.read().strip()
    except Exception:
        return None


def check_prerequisites() -> bool:
    """
    Check all prerequisites for running the profiler.

    Returns:
        True if all prerequisites are met, False otherwise
    """
    checks = [
        ("Root privileges", check_root_privileges()),
        ("BCC installed", check_bcc_installed()),
        ("eBPF support", check_ebpf_support()),
    ]

    all_passed = True

    print("Checking prerequisites...")
    for name, passed in checks:
        status = "✓" if passed else "✗"
        print(f"  {status} {name}")

        if not passed:
            all_passed = False

    return all_passed
