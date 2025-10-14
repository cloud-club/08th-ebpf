package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64,amd64 -type tcp_stats -type stats_key tcp_monitor tcp_monitor.c

// Prometheus metrics with interface label
var (
	tcpPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tcp_packets_total",
			Help: "Total number of TCP packets",
		},
		[]string{"interface"},
	)
	tcpSynPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tcp_syn_packets_total",
			Help: "Total number of TCP SYN packets",
		},
		[]string{"interface"},
	)
	tcpSynAckPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tcp_syn_ack_packets_total",
			Help: "Total number of TCP SYN-ACK packets",
		},
		[]string{"interface"},
	)
	tcpFinPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tcp_fin_packets_total",
			Help: "Total number of TCP FIN packets",
		},
		[]string{"interface"},
	)
	tcpRstPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "tcp_rst_packets_total",
			Help: "Total number of TCP RST packets",
		},
		[]string{"interface"},
	)

	registry = prometheus.NewRegistry()
)

func init() {
	// Register only our custom metrics, not the default Go metrics
	registry.MustRegister(tcpPackets)
	registry.MustRegister(tcpSynPackets)
	registry.MustRegister(tcpSynAckPackets)
	registry.MustRegister(tcpFinPackets)
	registry.MustRegister(tcpRstPackets)
}

type attachment struct {
	filter *netlink.BpfFilter
	qdisc  *netlink.GenericQdisc
}

type interfaceManager struct {
	objs        *tcp_monitorObjects
	attachments map[int]attachment // key is interface index
	mu          sync.Mutex
}

func (im *interfaceManager) attachToInterface(link netlink.Link) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	ifindex := link.Attrs().Index
	ifname := link.Attrs().Name

	// Skip if already attached
	if _, exists := im.attachments[ifindex]; exists {
		return nil
	}

	// Create qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to add clsact qdisc: %w", err)
		}
	}

	// Create TC filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           im.objs.tcp_monitorPrograms.TcEgress.FD(),
		Name:         "tc_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to attach TC filter: %w", err)
	}

	im.attachments[ifindex] = attachment{filter: filter, qdisc: qdisc}
	log.Printf("eBPF TC program attached to %s (index=%d)", ifname, ifindex)
	return nil
}

func (im *interfaceManager) detachFromInterface(ifindex int) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if att, exists := im.attachments[ifindex]; exists {
		netlink.FilterDel(att.filter)
		netlink.QdiscDel(att.qdisc)
		delete(im.attachments, ifindex)
		log.Printf("eBPF TC program detached from interface (index=%d)", ifindex)
	}
}

func (im *interfaceManager) cleanup() {
	im.mu.Lock()
	defer im.mu.Unlock()

	for ifindex, att := range im.attachments {
		netlink.FilterDel(att.filter)
		netlink.QdiscDel(att.qdisc)
		delete(im.attachments, ifindex)
	}
}

func (im *interfaceManager) discoverAndAttach() {
	links, err := netlink.LinkList()
	if err != nil {
		log.Printf("Error listing interfaces: %v", err)
		return
	}

	// Track current interfaces
	currentInterfaces := make(map[int]bool)

	// Attach to all current interfaces
	for _, link := range links {
		ifindex := link.Attrs().Index
		currentInterfaces[ifindex] = true

		if err := im.attachToInterface(link); err != nil {
			log.Printf("Warning: failed to attach to %s: %v", link.Attrs().Name, err)
		}
	}

	// Detach from interfaces that no longer exist
	im.mu.Lock()
	for ifindex := range im.attachments {
		if !currentInterfaces[ifindex] {
			im.mu.Unlock()
			im.detachFromInterface(ifindex)
			im.mu.Lock()
		}
	}
	im.mu.Unlock()
}

func main() {
	// Load eBPF objects
	var objs tcp_monitorObjects
	if err := loadTcp_monitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Initialize interface manager
	manager := &interfaceManager{
		objs:        &objs,
		attachments: make(map[int]attachment),
	}
	defer manager.cleanup()

	// Initial interface discovery and attachment
	manager.discoverAndAttach()

	// Start periodic interface discovery (every 10 seconds)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			manager.discoverAndAttach()
		}
	}()

	// Start metrics collection
	go collectMetrics(&objs)

	// Start HTTP server for Prometheus with custom registry
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle("/metrics", loggingMiddleware(handler))
	go func() {
		log.Println("Starting HTTP server on :9090")
		if err := http.ListenAndServe(":9090", nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
}

func collectMetrics(objs *tcp_monitorObjects) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Iterate over all entries in the map
		var key tcp_monitorStatsKey
		var stats tcp_monitorTcpStats

		iter := objs.tcp_monitorMaps.TcpStatsMap.Iterate()
		for iter.Next(&key, &stats) {
			// Get interface name from index
			ifname := getInterfaceName(key.Ifindex)

			// Update Prometheus metrics with interface label
			tcpPackets.WithLabelValues(ifname).Set(float64(stats.Packets))
			tcpSynPackets.WithLabelValues(ifname).Set(float64(stats.SynPackets))
			tcpSynAckPackets.WithLabelValues(ifname).Set(float64(stats.SynAckPackets))
			tcpFinPackets.WithLabelValues(ifname).Set(float64(stats.FinPackets))
			tcpRstPackets.WithLabelValues(ifname).Set(float64(stats.RstPackets))
		}

		if err := iter.Err(); err != nil {
			log.Printf("error iterating map: %v", err)
		}
	}
}

func getInterfaceName(ifindex uint32) string {
	// Try to get the interface name by index
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return fmt.Sprintf("if%d", ifindex)
	}
	return iface.Name
}

// Logging middleware for HTTP access logs
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log request
		log.Printf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Call the next handler
		next.ServeHTTP(w, r)

		// Log response time
		duration := time.Since(start)
		log.Printf("Response: %s %s completed in %v", r.Method, r.URL.Path, duration)
	})
}