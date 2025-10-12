# src/collector/event_handler.py - Event processing and handling
"""
Event handler for processing eBPF events from the kernel.
Converts raw event data into structured objects.
"""

from dataclasses import dataclass
from typing import Dict, List, Callable, Optional
import time
import logging


@dataclass
class SyscallEvent:
    """
    Structured representation of a syscall event.
    """
    pid: int
    tid: int
    timestamp_ns: int
    duration_ns: int
    comm: str
    syscall_id: int
    syscall_name: str
    event_type: int
    ret_val: int

    @property
    def duration_us(self) -> float:
        """Duration in microseconds"""
        return self.duration_ns / 1000.0

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds"""
        return self.duration_ns / 1_000_000.0


@dataclass
class NetworkEvent(SyscallEvent):
    """
    Network-specific event with additional fields.
    """
    fd: int = 0
    bytes: int = 0
    sport: int = 0
    dport: int = 0


@dataclass
class FileIOEvent(SyscallEvent):
    """
    File I/O specific event with additional fields.
    """
    fd: int = 0
    bytes: int = 0
    path: str = ""


class EventHandler:
    """
    Handles incoming eBPF events and routes them to appropriate processors.
    """

    def __init__(self):
        """
        Initialize the event handler.
        """
        self.event_callbacks: List[Callable] = []
        self.event_count = 0
        self.error_count = 0

        self.logger = logging.getLogger(__name__)

    def register_callback(self, callback: Callable):
        """
        Register a callback function to be called for each event.

        Args:
            callback: Function that takes an event object as parameter
        """
        self.event_callbacks.append(callback)

    def handle_syscall_event(self, raw_event) -> Optional[SyscallEvent]:
        """
        Process a raw syscall event from eBPF.

        Args:
            raw_event: Raw event data from BCC

        Returns:
            Processed SyscallEvent object or None if processing failed
        """
        try:
            event = SyscallEvent(
                pid=raw_event.pid,
                tid=raw_event.tid,
                timestamp_ns=raw_event.timestamp_ns,
                duration_ns=raw_event.duration_ns,
                comm=raw_event.comm.decode('utf-8', 'replace'),
                syscall_id=raw_event.syscall_id,
                syscall_name=raw_event.syscall_name.decode('utf-8', 'replace'),
                event_type=raw_event.event_type,
                ret_val=raw_event.ret_val
            )

            self.event_count += 1

            # Call all registered callbacks
            for callback in self.event_callbacks:
                callback(event)

            return event

        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
            self.error_count += 1
            return None

    def handle_network_event(self, raw_event) -> Optional[NetworkEvent]:
        """
        Process a raw network event from eBPF.

        Args:
            raw_event: Raw network event data from BCC

        Returns:
            Processed NetworkEvent object or None if processing failed
        """
        try:
            event = NetworkEvent(
                pid=raw_event.base.pid,
                tid=raw_event.base.tid,
                timestamp_ns=raw_event.base.timestamp_ns,
                duration_ns=raw_event.base.duration_ns,
                comm=raw_event.base.comm.decode('utf-8', 'replace'),
                syscall_id=raw_event.base.syscall_id,
                syscall_name=raw_event.base.syscall_name.decode('utf-8', 'replace'),
                event_type=raw_event.base.event_type,
                ret_val=raw_event.base.ret_val,
                fd=raw_event.fd,
                bytes=raw_event.bytes,
                sport=raw_event.sport,
                dport=raw_event.dport
            )

            self.event_count += 1

            for callback in self.event_callbacks:
                callback(event)

            return event

        except Exception as e:
            self.logger.error(f"Error processing network event: {e}")
            self.error_count += 1
            return None

    def handle_file_io_event(self, raw_event) -> Optional[FileIOEvent]:
        """
        Process a raw file I/O event from eBPF.

        Args:
            raw_event: Raw file I/O event data from BCC

        Returns:
            Processed FileIOEvent object or None if processing failed
        """
        try:
            event = FileIOEvent(
                pid=raw_event.base.pid,
                tid=raw_event.base.tid,
                timestamp_ns=raw_event.base.timestamp_ns,
                duration_ns=raw_event.base.duration_ns,
                comm=raw_event.base.comm.decode('utf-8', 'replace'),
                syscall_id=raw_event.base.syscall_id,
                syscall_name=raw_event.base.syscall_name.decode('utf-8', 'replace'),
                event_type=raw_event.base.event_type,
                ret_val=raw_event.base.ret_val,
                fd=raw_event.fd,
                bytes=raw_event.bytes,
                path=raw_event.path.decode('utf-8', 'replace')
            )

            self.event_count += 1

            for callback in self.event_callbacks:
                callback(event)

            return event

        except Exception as e:
            self.logger.error(f"Error processing file I/O event: {e}")
            self.error_count += 1
            return None

    def get_stats(self) -> Dict:
        """
        Get handler statistics.

        Returns:
            Dictionary with event processing statistics
        """
        return {
            'total_events': self.event_count,
            'errors': self.error_count,
            'callbacks_registered': len(self.event_callbacks)
        }
