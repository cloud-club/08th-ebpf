#!/usr/bin/env python3
# scripts/check_kernel.py - Check kernel version and eBPF support

import sys
import subprocess
import os


def check_kernel_version():
    """Check if kernel version supports eBPF"""
    try:
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
        version_str = result.stdout.strip()

        # Parse version
        parts = version_str.split('.')
        major = int(parts[0])
        minor = int(parts[1].split('-')[0])

        print(f"Kernel version: {version_str}")
        print(f"  Major: {major}, Minor: {minor}")

        # Check minimum version (4.9 recommended for BCC)
        if major < 4 or (major == 4 and minor < 9):
            print("⚠ Warning: Kernel 4.9+ recommended for full eBPF support")
            return False
        else:
            print("✓ Kernel version supports eBPF")
            return True

    except Exception as e:
        print(f"✗ Failed to check kernel version: {e}")
        return False


def check_bpf_syscall():
    """Check if BPF syscall is available"""
    try:
        # Check if /proc/sys/kernel/unprivileged_bpf_disabled exists
        bpf_disabled_path = "/proc/sys/kernel/unprivileged_bpf_disabled"

        if os.path.exists(bpf_disabled_path):
            with open(bpf_disabled_path, 'r') as f:
                value = f.read().strip()
                print(f"BPF syscall status: {'disabled' if value == '1' else 'enabled'} for unprivileged users")

        print("✓ BPF syscall available")
        return True

    except Exception as e:
        print(f"⚠ Could not check BPF syscall: {e}")
        return True  # Don't fail if we can't check


def check_debugfs():
    """Check if debugfs is mounted"""
    try:
        result = subprocess.run(['mount'], capture_output=True, text=True)

        if 'debugfs' in result.stdout:
            print("✓ debugfs is mounted")
            return True
        else:
            print("⚠ debugfs is not mounted (may be needed for some features)")
            return False

    except Exception as e:
        print(f"⚠ Could not check debugfs: {e}")
        return False


def check_tracefs():
    """Check if tracefs is mounted"""
    try:
        result = subprocess.run(['mount'], capture_output=True, text=True)

        if 'tracefs' in result.stdout:
            print("✓ tracefs is mounted")
            return True
        else:
            print("⚠ tracefs is not mounted (may be needed for some features)")
            return False

    except Exception as e:
        print(f"⚠ Could not check tracefs: {e}")
        return False


def check_root():
    """Check if running as root"""
    if os.geteuid() == 0:
        print("✓ Running as root")
        return True
    else:
        print("⚠ Not running as root (required for eBPF)")
        return False


def main():
    """Run all checks"""
    print("="*60)
    print("eBPF Kernel Support Check")
    print("="*60)
    print()

    checks = [
        ("Kernel version", check_kernel_version()),
        ("BPF syscall", check_bpf_syscall()),
        ("Root privileges", check_root()),
        ("debugfs", check_debugfs()),
        ("tracefs", check_tracefs()),
    ]

    print()
    print("="*60)
    print("Summary")
    print("="*60)

    required_checks = checks[:3]  # First 3 are required
    optional_checks = checks[3:]   # Rest are optional

    all_required = all(result for _, result in required_checks)

    if all_required:
        print("✓ All required checks passed")
        sys.exit(0)
    else:
        print("✗ Some required checks failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
