# src/collector/request_tracker.py - Request lifecycle tracking
"""
Tracks individual API requests and their associated syscall events.
Correlates events into request-level metrics.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import time
import logging


@dataclass
class Request:
    """
    Represents a single API request and its lifecycle events.
    """
    request_id: str
    start_time: float
    end_time: Optional[float] = None
    pid: int = 0
    tid: int = 0

    # Event lists by category
    syscall_events: List = field(default_factory=list)
    network_events: List = field(default_factory=list)
    file_io_events: List = field(default_factory=list)

    @property
    def duration_ms(self) -> Optional[float]:
        """Total request duration in milliseconds"""
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return None

    @property
    def total_syscall_time_ms(self) -> float:
        """Total time spent in syscalls (milliseconds)"""
        total_ns = sum(e.duration_ns for e in self.syscall_events)
        return total_ns / 1_000_000.0

    @property
    def total_network_time_ms(self) -> float:
        """Total time spent in network I/O (milliseconds)"""
        total_ns = sum(e.duration_ns for e in self.network_events)
        return total_ns / 1_000_000.0

    @property
    def total_file_io_time_ms(self) -> float:
        """Total time spent in file I/O (milliseconds)"""
        total_ns = sum(e.duration_ns for e in self.file_io_events)
        return total_ns / 1_000_000.0

    def add_event(self, event):
        """Add an event to this request"""
        # Categorize event
        syscall_name = event.syscall_name.lower()

        if syscall_name in ['sendto', 'recvfrom', 'sendmsg', 'recvmsg']:
            self.network_events.append(event)
        elif syscall_name in ['read', 'write', 'openat', 'fsync']:
            self.file_io_events.append(event)
        else:
            self.syscall_events.append(event)


class RequestTracker:
    """
    Tracks and correlates events into request-level metrics.

    Uses thread ID and timing heuristics to group events into requests.
    """

    def __init__(self, request_timeout: float = 30.0):
        """
        Initialize the request tracker.

        Args:
            request_timeout: Timeout in seconds for incomplete requests
        """
        self.request_timeout = request_timeout

        # Active requests by thread ID
        self.active_requests: Dict[int, Request] = {}

        # Completed requests
        self.completed_requests: List[Request] = []

        # Request counter for generating IDs
        self.request_counter = 0

        self.logger = logging.getLogger(__name__)

    def start_request(self, tid: int, pid: int) -> Request:
        """
        Start tracking a new request for a thread.

        Args:
            tid: Thread ID
            pid: Process ID

        Returns:
            New Request object
        """
        request_id = f"req_{self.request_counter:08d}"
        self.request_counter += 1

        request = Request(
            request_id=request_id,
            start_time=time.time(),
            pid=pid,
            tid=tid
        )

        self.active_requests[tid] = request
        self.logger.debug(f"Started tracking request {request_id} on TID {tid}")

        return request

    def add_event(self, event):
        """
        Add an event to the appropriate request.

        Args:
            event: Event object (SyscallEvent, NetworkEvent, or FileIOEvent)
        """
        tid = event.tid

        # Get or create request for this thread
        if tid not in self.active_requests:
            request = self.start_request(tid, event.pid)
        else:
            request = self.active_requests[tid]

        # Add event to request
        request.add_event(event)

    def end_request(self, tid: int) -> Optional[Request]:
        """
        Mark a request as complete and move to completed list.

        Args:
            tid: Thread ID

        Returns:
            Completed Request object or None
        """
        if tid not in self.active_requests:
            return None

        request = self.active_requests.pop(tid)
        request.end_time = time.time()

        self.completed_requests.append(request)
        self.logger.debug(f"Completed request {request.request_id} ({request.duration_ms:.2f}ms)")

        return request

    def cleanup_stale_requests(self):
        """
        Clean up requests that have timed out.
        Moves stale active requests to completed list.
        """
        current_time = time.time()
        stale_tids = []

        for tid, request in self.active_requests.items():
            if (current_time - request.start_time) > self.request_timeout:
                stale_tids.append(tid)

        for tid in stale_tids:
            self.logger.warning(f"Request {self.active_requests[tid].request_id} timed out")
            self.end_request(tid)

    def get_request_by_tid(self, tid: int) -> Optional[Request]:
        """
        Get active request for a thread ID.

        Args:
            tid: Thread ID

        Returns:
            Request object or None
        """
        return self.active_requests.get(tid)

    def get_stats(self) -> Dict:
        """
        Get tracker statistics.

        Returns:
            Dictionary with tracker statistics
        """
        return {
            'active_requests': len(self.active_requests),
            'completed_requests': len(self.completed_requests),
            'total_requests': self.request_counter
        }

    def get_completed_requests(self, limit: Optional[int] = None) -> List[Request]:
        """
        Get list of completed requests.

        Args:
            limit: Maximum number of requests to return

        Returns:
            List of Request objects
        """
        if limit:
            return self.completed_requests[-limit:]
        return self.completed_requests
