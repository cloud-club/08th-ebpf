package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 tcpMonitor tcp_monitor.c -- -I../

type TcpEvent struct {
	Pid       uint32
	Saddr     uint32
	Daddr     uint32
	Sport     uint16
	Dport     uint16
	State     uint8
	Family    uint8
	Timestamp uint64
}

type TcpPortStats struct {
	ActiveConnections uint64
	TotalConnections  uint64
	LastUpdated       uint64
}

type TCPMonitor struct {
	objs   tcpMonitorObjects
	links  []link.Link
	reader *perf.Reader
}

func NewTCPMonitor() (*TCPMonitor, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load pre-compiled BPF programs and maps
	objs := tcpMonitorObjects{}
	if err := loadTcpMonitorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	monitor := &TCPMonitor{
		objs:  objs,
		links: make([]link.Link, 0),
	}

	// Attach kprobes
	kp1, err := link.Kprobe("tcp_set_state", objs.TraceTcpSetState, nil)
	if err != nil {
		monitor.Close()
		return nil, fmt.Errorf("attaching kprobe tcp_set_state: %w", err)
	}
	monitor.links = append(monitor.links, kp1)

	kp2, err := link.Kprobe("inet_csk_accept", objs.TraceAccept, nil)
	if err != nil {
		monitor.Close()
		return nil, fmt.Errorf("attaching kprobe inet_csk_accept: %w", err)
	}
	monitor.links = append(monitor.links, kp2)

	// Create perf event reader
	reader, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		monitor.Close()
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}
	monitor.reader = reader

	return monitor, nil
}

func (m *TCPMonitor) GetPortStats() (map[uint16]TcpPortStats, error) {
	stats := make(map[uint16]TcpPortStats)

	var port uint16
	var portStats TcpPortStats

	iter := m.objs.PortMetrics.Iterate()
	for iter.Next(&port, &portStats) {
		stats[port] = portStats
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating port metrics: %w", err)
	}

	return stats, nil
}

func (m *TCPMonitor) ReadEvents() (<-chan TcpEvent, <-chan error) {
	events := make(chan TcpEvent, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		for {
			record, err := m.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				errs <- fmt.Errorf("reading from perf buffer: %w", err)
				return
			}

			if len(record.RawSample) < int(unsafe.Sizeof(TcpEvent{})) {
				log.Printf("Warning: received incomplete event data")
				continue
			}

			var event TcpEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Warning: failed to decode event: %v", err)
				continue
			}

			events <- event
		}
	}()

	return events, errs
}

func (m *TCPMonitor) Close() error {
	var errs []error

	if m.reader != nil {
		if err := m.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing perf reader: %w", err))
		}
	}

	for _, l := range m.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing link: %w", err))
		}
	}

	if err := m.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing BPF objects: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errs)
	}

	return nil
}

// Helper function to format IPv4 address
func FormatIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24))
}