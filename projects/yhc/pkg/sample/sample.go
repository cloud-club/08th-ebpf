package sample

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

// NetworkMetrics holds all Prometheus metrics for network monitoring
type NetworkMetrics struct {
	PacketsTotal      *prometheus.CounterVec
	ActiveConnections prometheus.Gauge
	BytesTransferred  *prometheus.CounterVec
	ConnectionLatency *prometheus.HistogramVec
}

// NewNetworkMetrics creates and registers all network-related metrics
func NewNetworkMetrics() *NetworkMetrics {
	metrics := &NetworkMetrics{
		PacketsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "network_packets_total",
				Help: "Total number of network packets processed",
			},
			[]string{"direction", "protocol"},
		),
		ActiveConnections: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "network_active_connections",
				Help: "Number of active network connections",
			},
		),
		BytesTransferred: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "network_bytes_transferred_total",
				Help: "Total bytes transferred over the network",
			},
			[]string{"direction", "protocol"},
		),
		ConnectionLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "network_connection_latency_seconds",
				Help:    "Connection latency in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"protocol"},
		),
	}

	// Register all metrics
	prometheus.MustRegister(
		metrics.PacketsTotal,
		metrics.ActiveConnections,
		metrics.BytesTransferred,
		metrics.ConnectionLatency,
	)

	// Initialize with zero values
	metrics.initializeMetrics()

	return metrics
}

// initializeMetrics sets initial values for all metrics
func (m *NetworkMetrics) initializeMetrics() {
	// Initialize packet counters
	m.PacketsTotal.WithLabelValues("ingress", "tcp").Add(0)
	m.PacketsTotal.WithLabelValues("egress", "tcp").Add(0)
	m.PacketsTotal.WithLabelValues("ingress", "udp").Add(0)
	m.PacketsTotal.WithLabelValues("egress", "udp").Add(0)

	// Initialize bytes transferred
	m.BytesTransferred.WithLabelValues("ingress", "tcp").Add(0)
	m.BytesTransferred.WithLabelValues("egress", "tcp").Add(0)
	m.BytesTransferred.WithLabelValues("ingress", "udp").Add(0)
	m.BytesTransferred.WithLabelValues("egress", "udp").Add(0)

	// Initialize connections gauge
	m.ActiveConnections.Set(0)
}

// Handler returns the Prometheus HTTP handler for metrics endpoint
func (m *NetworkMetrics) Handler() http.Handler {
	return promhttp.Handler()
}

// UpdatePacketCount increments the packet counter for given direction and protocol
func (m *NetworkMetrics) UpdatePacketCount(direction, protocol string, count float64) {
	m.PacketsTotal.WithLabelValues(direction, protocol).Add(count)
}

// UpdateBytesTransferred increments the bytes transferred counter
func (m *NetworkMetrics) UpdateBytesTransferred(direction, protocol string, bytes float64) {
	m.BytesTransferred.WithLabelValues(direction, protocol).Add(bytes)
}

// SetActiveConnections updates the active connections gauge
func (m *NetworkMetrics) SetActiveConnections(count float64) {
	m.ActiveConnections.Set(count)
}

// ObserveConnectionLatency records a connection latency observation
func (m *NetworkMetrics) ObserveConnectionLatency(protocol string, latency float64) {
	m.ConnectionLatency.WithLabelValues(protocol).Observe(latency)
}