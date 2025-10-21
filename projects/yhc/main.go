package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Load eBPF objects
	var objs tcp_monitorObjects
	if err := loadTcp_monitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Initialize interface manager
	manager := newInterfaceManager(&objs)
	defer manager.cleanup()

	// Initial interface discovery and attachment
	manager.discoverAndAttach()

	// Start periodic interface discovery
	manager.startPeriodicDiscovery()

	// Start metrics collection
	go collectMetrics(&objs)

	// Start HTTP server
	startHTTPServer()

	// Wait for signal
	waitForShutdown()
}

func waitForShutdown() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
}