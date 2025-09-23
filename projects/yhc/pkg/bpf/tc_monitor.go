package bpf

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 tcMonitor tc_monitor.c -- -I../

type TcpConnection struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type PortMetrics struct {
	SynReceived     uint64
	SynAckSent      uint64
	Established     uint64
	FinReceived     uint64
	RstReceived     uint64
	BytesReceived   uint64
	BytesSent       uint64
	PacketsReceived uint64
	PacketsSent     uint64
	LastUpdated     uint64
}

type TCMonitor struct {
	objs      tcMonitorObjects
	tcnl      *tc.Tc
	iface     string
	qdisc     *tc.Object
}

func NewTCMonitor(interfaceName string) (*TCMonitor, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load pre-compiled BPF programs and maps
	objs := tcMonitorObjects{}
	if err := loadTcMonitorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Get interface index
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to get interface %s: %w", interfaceName, err)
	}

	// Open TC netlink connection
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to open tc: %w", err)
	}

	monitor := &TCMonitor{
		objs:  objs,
		tcnl:  tcnl,
		iface: interfaceName,
	}

	// Create clsact qdisc
	qdisc := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  tc.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Try to add qdisc, ignore if it already exists
	if err := tcnl.Qdisc().Add(qdisc); err != nil {
		log.Printf("Note: qdisc may already exist: %v", err)
	}
	monitor.qdisc = qdisc

	// Attach ingress filter
	ingressFilter := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  1,
			Parent:  tc.HandleMinIngress,
			Info:    0x10300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.BPF{
				FD:    uint32(objs.TcIngress.FD()),
				Name:  "tc_ingress",
				Flags: 0x1, // direct action
			},
		},
	}

	if err := tcnl.Filter().Add(ingressFilter); err != nil {
		monitor.Close()
		return nil, fmt.Errorf("failed to attach ingress filter: %w", err)
	}

	// Attach egress filter
	egressFilter := &tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  2,
			Parent:  tc.HandleMinEgress,
			Info:    0x10300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.BPF{
				FD:    uint32(objs.TcEgress.FD()),
				Name:  "tc_egress",
				Flags: 0x1, // direct action
			},
		},
	}

	if err := tcnl.Filter().Add(egressFilter); err != nil {
		monitor.Close()
		return nil, fmt.Errorf("failed to attach egress filter: %w", err)
	}

	return monitor, nil
}

func (m *TCMonitor) GetPortMetrics() (map[uint16]PortMetrics, error) {
	metrics := make(map[uint16]PortMetrics)

	var port uint16
	var portMetrics PortMetrics

	iter := m.objs.PortStats.Iterate()
	for iter.Next(&port, &portMetrics) {
		metrics[port] = portMetrics
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating port metrics: %w", err)
	}

	return metrics, nil
}

func (m *TCMonitor) GetActiveConnections() (map[TcpConnection]uint64, error) {
	connections := make(map[TcpConnection]uint64)

	var conn TcpConnection
	var timestamp uint64

	iter := m.objs.ActiveConnections.Iterate()
	for iter.Next(&conn, &timestamp) {
		connections[conn] = timestamp
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating connections: %w", err)
	}

	return connections, nil
}

func (m *TCMonitor) Close() error {
	var errs []error

	// Remove TC filters if attached
	if m.tcnl != nil && m.qdisc != nil {
		iface, err := net.InterfaceByName(m.iface)
		if err == nil {
			// Try to delete filters
			m.tcnl.Filter().Delete(&tc.Object{
				Msg: tc.Msg{
					Family:  unix.AF_UNSPEC,
					Ifindex: uint32(iface.Index),
					Handle:  1,
					Parent:  tc.HandleMinIngress,
				},
			})

			m.tcnl.Filter().Delete(&tc.Object{
				Msg: tc.Msg{
					Family:  unix.AF_UNSPEC,
					Ifindex: uint32(iface.Index),
					Handle:  2,
					Parent:  tc.HandleMinEgress,
				},
			})
		}

		if err := m.tcnl.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing tc: %w", err))
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
		byte(addr>>24),
		byte(addr>>16),
		byte(addr>>8),
		byte(addr))
}