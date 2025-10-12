# Troubleshooting Guide

## Common Issues

### 1. Permission Denied

**Error:**
```
Permission denied: Unable to load eBPF program
```

**Cause:** Not running with root privileges

**Solution:**
```bash
# Run with sudo
sudo ebpf-profiler start --pid 1234

# Or check current user
id
# Should show uid=0(root) or use sudo
```

### 2. BCC Not Found

**Error:**
```
ModuleNotFoundError: No module named 'bcc'
```

**Cause:** BCC not installed

**Solution:**
```bash
# Install BCC
./scripts/setup_bcc.sh

# Or manually for Ubuntu/Debian
sudo apt-get install python3-bpfcc

# Verify installation
python3 -c "import bcc; print('BCC installed')"
```

### 3. Kernel Too Old

**Error:**
```
Kernel version X.X does not support eBPF
```

**Cause:** Kernel version < 4.9

**Solution:**
```bash
# Check kernel version
uname -r

# Upgrade kernel (Ubuntu)
sudo apt-get update
sudo apt-get install linux-generic-hwe-20.04

# Reboot
sudo reboot
```

### 4. No Events Captured

**Problem:** Profiler runs but captures no events

**Possible Causes:**

1. **Wrong PID**
   ```bash
   # Verify PID exists
   ps aux | grep <process_name>

   # Use correct PID
   sudo ebpf-profiler start --pid <correct_pid>
   ```

2. **Process Not Active**
   ```bash
   # Generate some load
   cd examples/load_test
   python simple_test.py
   ```

3. **Syscalls Not Configured**
   ```bash
   # Check config
   cat configs/default.yaml

   # Add syscalls
   sudo ebpf-profiler start --pid 1234 --syscalls "read,write,sendto"
   ```

4. **Filter Too Restrictive**
   ```yaml
   # Edit config - lower min duration
   filters:
     min_duration_us: 1  # Lower threshold
   ```

### 5. BPF Program Failed to Load

**Error:**
```
libbpf: failed to create map: Invalid argument
```

**Possible Causes:**

1. **Syntax Error in C Code**
   ```bash
   # Test compilation
   python3 -c "from bcc import BPF; BPF(src_file='src/ebpf/syscall_tracer.c')"
   ```

2. **Missing Kernel Headers**
   ```bash
   # Install headers
   sudo apt-get install linux-headers-$(uname -r)
   ```

3. **Resource Limits**
   ```bash
   # Check ulimits
   ulimit -a

   # Increase if needed
   ulimit -n 65536
   ```

### 6. High CPU Usage

**Problem:** Profiler uses too much CPU

**Solutions:**

1. **Reduce Sampling Rate**
   ```yaml
   profiler:
     sampling_rate: 0.1  # Sample 10% of events
   ```

2. **Increase Min Duration Filter**
   ```yaml
   filters:
     min_duration_us: 1000  # Only capture events > 1ms
   ```

3. **Trace Fewer Syscalls**
   ```yaml
   syscalls:
     trace:
       - read
       - write
       # Remove less important syscalls
   ```

### 7. Memory Issues

**Problem:** High memory usage

**Solutions:**

1. **Limit Event Buffer**
   ```yaml
   profiler:
     buffer_size: 128  # Reduce buffer size

   filters:
     max_events: 10000  # Limit stored events
   ```

2. **Export Frequently**
   ```bash
   # Export to file periodically
   sudo ebpf-profiler start --pid 1234 --duration 60
   # Process and clear
   ```

### 8. Prometheus Metrics Not Showing

**Problem:** Prometheus endpoint returns no data

**Checks:**

1. **Verify Endpoint**
   ```bash
   # Check if server is running
   curl http://localhost:9090/metrics
   ```

2. **Check Configuration**
   ```yaml
   output:
     format: prometheus
     prometheus_port: 9090
   ```

3. **Verify Events Are Being Captured**
   ```bash
   # Use stdout format first to verify
   sudo ebpf-profiler start --pid 1234 --output-format stdout
   ```

### 9. Can't Find Process

**Error:**
```
Error: PID 1234 not found or not accessible
```

**Solutions:**

1. **Find Correct PID**
   ```bash
   # List processes
   ps aux | grep <process_name>

   # Or use pgrep
   pgrep -f <process_name>
   ```

2. **Process in Different Namespace**
   ```bash
   # Check namespaces
   sudo lsns

   # Enter namespace if needed
   sudo nsenter -t <pid> -p -m
   ```

### 10. Attachment Failed

**Error:**
```
Failed to attach to syscall: No such file or directory
```

**Causes:**

1. **Syscall Not Available**
   ```bash
   # Check available syscalls
   sudo cat /proc/kallsyms | grep sys_read

   # Some syscalls have different names on different kernels
   ```

2. **Kernel Configuration**
   ```bash
   # Check if kprobes are enabled
   cat /proc/sys/kernel/kptr_restrict
   # Should be 0 or 1, not 2

   # Temporarily allow
   echo 1 | sudo tee /proc/sys/kernel/kptr_restrict
   ```

## Debugging Tips

### Enable Debug Logging

```bash
# Run with debug level
sudo ebpf-profiler --log-level DEBUG start --pid 1234

# Or set environment variable
export BCC_DEBUG=1
```

### Check dmesg for Kernel Messages

```bash
# View kernel messages
sudo dmesg | tail -50

# Watch live
sudo dmesg -w
```

### Use BCC Tools Directly

```bash
# Test with BCC trace tool
sudo trace -p 1234 'r::__sys_read'

# Profile syscalls
sudo funccount -p 1234 'sys_*'

# Check syscall latency
sudo argdist -p 1234 -C 'r::__sys_read():int:$retval'
```

### Verify eBPF Features

```bash
# Run kernel check script
python scripts/check_kernel.py

# Or use bpftool
sudo bpftool feature probe
```

## Getting Help

If issues persist:

1. **Check Logs**
   ```bash
   # Enable file logging
   sudo ebpf-profiler --log-file /tmp/profiler.log start --pid 1234
   cat /tmp/profiler.log
   ```

2. **Collect System Info**
   ```bash
   uname -a
   cat /etc/os-release
   python3 --version
   python3 -c "import bcc; print(bcc.__version__)"
   ```

3. **Create Minimal Reproduction**
   ```bash
   # Use example app
   cd examples/fastapi_app
   python app.py &
   sudo ebpf-profiler start --pid $!
   ```

4. **Open GitHub Issue**
   - Include system info
   - Include error messages
   - Include steps to reproduce

## Performance Tuning

### For High-Throughput Applications

```yaml
profiler:
  sampling_rate: 0.1  # Sample 10%
  buffer_size: 512    # Larger buffer

filters:
  min_duration_us: 500  # Higher threshold

syscalls:
  trace:  # Only critical syscalls
    - read
    - write
```

### For Low-Latency Analysis

```yaml
profiler:
  sampling_rate: 1.0
  buffer_size: 256

filters:
  min_duration_us: 1  # Capture all

analysis:
  slow_threshold_us: 100  # Lower threshold
```

### For Long-Running Profiling

```yaml
profiler:
  request_timeout: 300.0  # 5 minutes

filters:
  max_events: 50000  # Limit memory

output:
  format: json  # Periodic export
```
