package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64,amd64 -type tcp_stats -type stats_key tcp_monitor tcp_monitor.c

type attachment struct {
	filter *netlink.BpfFilter
	qdisc  *netlink.GenericQdisc
	ifname string
}

type interfaceManager struct {
	objs        *tcp_monitorObjects
	attachments map[int]attachment // key is interface index
	mu          sync.Mutex
}

func newInterfaceManager(objs *tcp_monitorObjects) *interfaceManager {
	return &interfaceManager{
		objs:        objs,
		attachments: make(map[int]attachment),
	}
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

	im.attachments[ifindex] = attachment{filter: filter, qdisc: qdisc, ifname: ifname}
	log.Printf("eBPF TC program attached to interface %s (index=%d)", ifname, ifindex)
	return nil
}

func (im *interfaceManager) detachFromInterface(ifindex int) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if att, exists := im.attachments[ifindex]; exists {
		netlink.FilterDel(att.filter)
		netlink.QdiscDel(att.qdisc)
		delete(im.attachments, ifindex)
		log.Printf("eBPF TC program detached from interface %s (index=%d)", att.ifname, ifindex)
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

	// Track current UP interfaces
	currentInterfaces := make(map[int]bool)

	// Attach to all UP interfaces
	for _, link := range links {
		attrs := link.Attrs()
		ifindex := attrs.Index
		ifname := attrs.Name
		isUp := attrs.OperState == netlink.OperUp

		if isUp {
			currentInterfaces[ifindex] = true

			if err := im.attachToInterface(link); err != nil {
				log.Printf("Warning: failed to attach to %s: %v", ifname, err)
			}
		} else {
			// Interface is down, detach if currently attached
			if _, attached := im.attachments[ifindex]; attached {
				log.Printf("Interface %s is down, detaching", ifname)
				im.detachFromInterface(ifindex)
			}
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

func (im *interfaceManager) startPeriodicDiscovery() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			im.discoverAndAttach()
		}
	}()
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
