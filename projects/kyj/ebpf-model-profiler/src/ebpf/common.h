// src/ebpf/common.h - Common data structures and definitions for eBPF programs

#ifndef __COMMON_H
#define __COMMON_H

// Maximum length for string fields
#define COMM_LEN 16
#define SYSCALL_NAME_LEN 32
#define PATH_LEN 256

// Event types
#define EVENT_TYPE_SYSCALL_ENTER 1
#define EVENT_TYPE_SYSCALL_EXIT  2
#define EVENT_TYPE_NETWORK       3
#define EVENT_TYPE_FILE_IO       4

/**
 * syscall_event - Structure to hold syscall event data
 * @pid: Process ID
 * @tid: Thread ID
 * @timestamp_ns: Timestamp in nanoseconds
 * @duration_ns: Duration in nanoseconds (for exit events)
 * @comm: Command name (process name)
 * @syscall_id: System call number
 * @syscall_name: Human-readable syscall name
 * @event_type: Type of event (enter/exit)
 * @ret_val: Return value of syscall
 */
struct syscall_event {
    u32 pid;
    u32 tid;
    u64 timestamp_ns;
    u64 duration_ns;
    char comm[COMM_LEN];
    u32 syscall_id;
    char syscall_name[SYSCALL_NAME_LEN];
    u32 event_type;
    s64 ret_val;
};

/**
 * request_context - Context for tracking request lifecycle
 * @request_id: Unique identifier for the request
 * @start_time: Request start timestamp
 * @pid: Process ID handling the request
 * @tid: Thread ID handling the request
 */
struct request_context {
    u64 request_id;
    u64 start_time;
    u32 pid;
    u32 tid;
};

/**
 * file_io_event - File I/O specific event data
 * @base: Base syscall event
 * @fd: File descriptor
 * @bytes: Number of bytes read/written
 * @path: File path (for openat)
 */
struct file_io_event {
    struct syscall_event base;
    u32 fd;
    u64 bytes;
    char path[PATH_LEN];
};

/**
 * network_event - Network I/O specific event data
 * @base: Base syscall event
 * @fd: Socket file descriptor
 * @bytes: Number of bytes sent/received
 * @sport: Source port
 * @dport: Destination port
 */
struct network_event {
    struct syscall_event base;
    u32 fd;
    u64 bytes;
    u16 sport;
    u16 dport;
};

#endif // __COMMON_H
