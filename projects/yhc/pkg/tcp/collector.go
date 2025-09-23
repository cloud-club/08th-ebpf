package tcp

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cloud-club/08th-ebpf/projects/yhc/pkg/bpf"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector collects TCP connection metrics using eBPF
type Collector struct {
	monitor *bpf.TCPMonitor

	// Prometheus metrics
	activeConnections *prometheus.GaugeVec
	totalConnections  *prometheus.CounterVec
	connectionEvents  *prometheus.CounterVec

	mu     sync.RWMutex
	ports  map[uint16]*PortMetrics
	cancel context.CancelFunc
}

// PortMetrics holds metrics for a specific port
type PortMetrics struct {
	Port              uint16
	ActiveConnections uint64
	TotalConnections  uint64
	LastUpdated       time.Time
}

// NewCollector creates a new TCP metrics collector
func NewCollector() (*Collector, error) {
	// Initialize BPF monitor
	monitor, err := bpf.NewTCPMonitor()
	if err != nil {
		return nil, fmt.Errorf("failed to create TCP monitor: %w", err)
	}

	c := &Collector{
		monitor: monitor,
		ports:   make(map[uint16]*PortMetrics),

		// Define Prometheus metrics
		activeConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "tcp_active_connections",
				Help: "Number of active TCP connections per port",
			},
			[]string{"port"},
		),
		totalConnections: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tcp_total_connections",
				Help: "Total number of TCP connections accepted per port",
			},
			[]string{"port"},
		),
		connectionEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "tcp_connection_events_total",
				Help: "TCP connection state change events",
			},
			[]string{"port", "event"},
		),
	}

	// Register metrics
	prometheus.MustRegister(
		c.activeConnections,
		c.totalConnections,
		c.connectionEvents,
	)

	return c, nil
}

// Start begins collecting metrics
func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	// Start goroutine to update metrics from BPF maps
	go c.updateMetricsLoop(ctx)

	// Start goroutine to process BPF events
	go c.processEventsLoop(ctx)

	return nil
}

// updateMetricsLoop periodically reads metrics from BPF maps
func (c *Collector) updateMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.updateMetrics(); err != nil {
				log.Printf("Error updating metrics: %v", err)
			}
		}
	}
}

// updateMetrics reads current metrics from BPF maps
func (c *Collector) updateMetrics() error {
	stats, err := c.monitor.GetPortStats()
	if err != nil {
		return fmt.Errorf("failed to get port stats: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for port, stat := range stats {
		portStr := fmt.Sprintf("%d", port)

		// Update Prometheus metrics
		c.activeConnections.WithLabelValues(portStr).Set(float64(stat.ActiveConnections))
		c.totalConnections.WithLabelValues(portStr).Add(float64(stat.TotalConnections))

		// Update internal state
		if pm, exists := c.ports[port]; exists {
			// Calculate new connections since last update
			newConns := stat.TotalConnections - pm.TotalConnections
			if newConns > 0 {
				c.connectionEvents.WithLabelValues(portStr, "new").Add(float64(newConns))
			}

			pm.ActiveConnections = stat.ActiveConnections
			pm.TotalConnections = stat.TotalConnections
			pm.LastUpdated = time.Now()
		} else {
			// First time seeing this port
			c.ports[port] = &PortMetrics{
				Port:              port,
				ActiveConnections: stat.ActiveConnections,
				TotalConnections:  stat.TotalConnections,
				LastUpdated:       time.Now(),
			}
			if stat.TotalConnections > 0 {
				c.connectionEvents.WithLabelValues(portStr, "new").Add(float64(stat.TotalConnections))
			}
		}
	}

	return nil
}

// processEventsLoop processes events from the BPF perf buffer
func (c *Collector) processEventsLoop(ctx context.Context) {
	events, errs := c.monitor.ReadEvents()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errs:
			if err != nil {
				log.Printf("Error reading BPF events: %v", err)
				return
			}
		case event := <-events:
			c.handleEvent(event)
		}
	}
}

// handleEvent processes a single TCP event
func (c *Collector) handleEvent(event bpf.TcpEvent) {
	portStr := fmt.Sprintf("%d", event.Sport)

	// Track connection state changes
	switch event.State {
	case 1: // TCP_ESTABLISHED
		c.connectionEvents.WithLabelValues(portStr, "established").Inc()
		log.Printf("New connection on port %d from %s:%d",
			event.Sport,
			bpf.FormatIPv4(event.Saddr),
			event.Dport)
	case 7: // TCP_CLOSE
		c.connectionEvents.WithLabelValues(portStr, "closed").Inc()
	case 6: // TCP_TIME_WAIT
		c.connectionEvents.WithLabelValues(portStr, "time_wait").Inc()
	}
}

// GetPortMetrics returns metrics for all monitored ports
func (c *Collector) GetPortMetrics() map[uint16]*PortMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[uint16]*PortMetrics)
	for port, metrics := range c.ports {
		result[port] = &PortMetrics{
			Port:              metrics.Port,
			ActiveConnections: metrics.ActiveConnections,
			TotalConnections:  metrics.TotalConnections,
			LastUpdated:       metrics.LastUpdated,
		}
	}

	return result
}

// Stop stops the collector and cleans up resources
func (c *Collector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}

	if c.monitor != nil {
		return c.monitor.Close()
	}

	return nil
}