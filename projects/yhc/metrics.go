package main

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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

func startHTTPServer() {
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle("/metrics", loggingMiddleware(handler))
	go func() {
		log.Println("Starting HTTP server on :9598")
		if err := http.ListenAndServe(":9598", nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
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
