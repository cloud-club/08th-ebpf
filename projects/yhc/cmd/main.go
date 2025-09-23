package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloud-club/08th-ebpf/projects/yhc/pkg/tcp"
	sample "github.com/cloud-club/08th-ebpf/projects/yhc/pkg/sample"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		cancel()
	}()

	// Initialize sample metrics (if still needed)
	sampleMetrics := sample.NewNetworkMetrics()
	_ = sampleMetrics // Keep for now, can be removed later

	// Initialize TCP collector
	tcpCollector, err := tcp.NewCollector()
	if err != nil {
		log.Fatalf("Failed to create TCP collector: %v", err)
	}
	defer tcpCollector.Stop()

	// Start TCP metrics collection
	if err := tcpCollector.Start(ctx); err != nil {
		log.Fatalf("Failed to start TCP collector: %v", err)
	}

	// Setup HTTP server
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
<head><title>eBPF Network Exporter</title></head>
<body>
<h1>eBPF Network Exporter</h1>
<p><a href='/metrics'>Metrics</a></p>
<h2>Active Monitoring</h2>
<ul>
<li>TCP connection metrics (per port)</li>
<li>Active connections</li>
<li>Total connections</li>
<li>Connection events</li>
</ul>
</body>
</html>`))
	})

	addr := ":9187"
	log.Printf("Starting Prometheus exporter on %s", addr)
	log.Printf("Metrics available at http://localhost:9187/metrics")
	log.Printf("Note: This exporter requires root privileges to load eBPF programs")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
