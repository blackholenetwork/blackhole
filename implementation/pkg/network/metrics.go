package network

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the network layer
type Metrics struct {
	// Connection metrics
	ActiveConnections   prometheus.Gauge
	TotalConnections    prometheus.Counter
	FailedConnections   prometheus.Counter
	ConnectionDuration  prometheus.Histogram
	ConnectionLatency   prometheus.Histogram
	
	// Peer metrics
	ConnectedPeers      prometheus.Gauge
	DiscoveredPeers     prometheus.Counter
	PeersByDirection    *prometheus.GaugeVec
	PeersByProtocol     *prometheus.GaugeVec
	
	// Stream metrics
	ActiveStreams       prometheus.Gauge
	TotalStreams        prometheus.Counter
	StreamDuration      prometheus.Histogram
	StreamsByProtocol   *prometheus.GaugeVec
	
	// Bandwidth metrics
	BytesSent           prometheus.Counter
	BytesReceived       prometheus.Counter
	BandwidthRate       *prometheus.GaugeVec
	MessageSize         *prometheus.HistogramVec
	
	// Protocol metrics
	ProtocolMessages    *prometheus.CounterVec
	ProtocolErrors      *prometheus.CounterVec
	ProtocolLatency     *prometheus.HistogramVec
	
	// Transport metrics
	TransportConnections *prometheus.GaugeVec
	TransportErrors      *prometheus.CounterVec
	TransportLatency     *prometheus.HistogramVec
	
	// DHT metrics
	DHTQueries          prometheus.Counter
	DHTQueryDuration    prometheus.Histogram
	DHTRoutingTableSize prometheus.Gauge
	
	// Resource metrics
	MemoryUsage         prometheus.Gauge
	GoroutineCount      prometheus.Gauge
	FileDescriptors     prometheus.Gauge
	
	// Performance metrics
	ConnectionSetupTime prometheus.Histogram
	HandshakeTime       *prometheus.HistogramVec
	
	// Custom buckets for different metrics
	latencyBuckets   []float64
	sizeBuckets      []float64
	durationBuckets  []float64
}

// NewMetrics creates and registers all metrics
func NewMetrics() (*Metrics, error) {
	// Define custom buckets for better granularity
	latencyBuckets := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	sizeBuckets := []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304}
	durationBuckets := prometheus.ExponentialBuckets(0.1, 2, 15)

	m := &Metrics{
		latencyBuckets:  latencyBuckets,
		sizeBuckets:     sizeBuckets,
		durationBuckets: durationBuckets,
		
		// Connection metrics
		ActiveConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_active_connections",
			Help: "Number of active connections",
		}),
		TotalConnections: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_total_connections",
			Help: "Total number of connections established",
		}),
		FailedConnections: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_failed_connections",
			Help: "Total number of failed connection attempts",
		}),
		ConnectionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "blackhole_connection_duration_seconds",
			Help:    "Connection duration in seconds",
			Buckets: durationBuckets,
		}),
		ConnectionLatency: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "blackhole_connection_latency_seconds",
			Help:    "Connection establishment latency in seconds",
			Buckets: latencyBuckets,
		}),
		
		// Peer metrics
		ConnectedPeers: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_connected_peers",
			Help: "Number of connected peers",
		}),
		DiscoveredPeers: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_discovered_peers",
			Help: "Total number of discovered peers",
		}),
		PeersByDirection: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "blackhole_peers_by_direction",
				Help: "Number of peers by connection direction",
			},
			[]string{"direction"},
		),
		PeersByProtocol: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "blackhole_peers_by_protocol",
				Help: "Number of peers supporting each protocol",
			},
			[]string{"protocol"},
		),
		
		// Stream metrics
		ActiveStreams: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_active_streams",
			Help: "Number of active streams",
		}),
		TotalStreams: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_total_streams",
			Help: "Total number of streams created",
		}),
		StreamDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "blackhole_stream_duration_seconds",
			Help:    "Stream duration in seconds",
			Buckets: durationBuckets,
		}),
		StreamsByProtocol: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "blackhole_streams_by_protocol",
				Help: "Number of active streams by protocol",
			},
			[]string{"protocol"},
		),
		
		// Bandwidth metrics
		BytesSent: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_bytes_sent_total",
			Help: "Total bytes sent",
		}),
		BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_bytes_received_total",
			Help: "Total bytes received",
		}),
		BandwidthRate: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "blackhole_bandwidth_rate_bytes_per_second",
				Help: "Current bandwidth rate in bytes per second",
			},
			[]string{"direction"},
		),
		MessageSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "blackhole_message_size_bytes",
				Help:    "Size of messages in bytes",
				Buckets: sizeBuckets,
			},
			[]string{"protocol", "direction"},
		),
		
		// Protocol metrics
		ProtocolMessages: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blackhole_protocol_messages_total",
				Help: "Total protocol messages by type",
			},
			[]string{"protocol", "message_type"},
		),
		ProtocolErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blackhole_protocol_errors_total",
				Help: "Total protocol errors by type",
			},
			[]string{"protocol", "error_type"},
		),
		ProtocolLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "blackhole_protocol_latency_seconds",
				Help:    "Protocol operation latency in seconds",
				Buckets: latencyBuckets,
			},
			[]string{"protocol", "operation"},
		),
		
		// Transport metrics
		TransportConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "blackhole_transport_connections",
				Help: "Number of connections by transport type",
			},
			[]string{"transport"},
		),
		TransportErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blackhole_transport_errors_total",
				Help: "Total transport errors by type",
			},
			[]string{"transport", "error_type"},
		),
		TransportLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "blackhole_transport_latency_seconds",
				Help:    "Transport connection latency by type",
				Buckets: latencyBuckets,
			},
			[]string{"transport"},
		),
		
		// DHT metrics
		DHTQueries: promauto.NewCounter(prometheus.CounterOpts{
			Name: "blackhole_dht_queries_total",
			Help: "Total number of DHT queries",
		}),
		DHTQueryDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "blackhole_dht_query_duration_seconds",
			Help:    "DHT query duration in seconds",
			Buckets: durationBuckets,
		}),
		DHTRoutingTableSize: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_dht_routing_table_size",
			Help: "Number of peers in DHT routing table",
		}),
		
		// Resource metrics
		MemoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_memory_usage_bytes",
			Help: "Current memory usage in bytes",
		}),
		GoroutineCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_goroutine_count",
			Help: "Current number of goroutines",
		}),
		FileDescriptors: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "blackhole_file_descriptors",
			Help: "Current number of open file descriptors",
		}),
		
		// Performance metrics
		ConnectionSetupTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "blackhole_connection_setup_time_seconds",
			Help:    "Time to establish connections in seconds",
			Buckets: latencyBuckets,
		}),
		HandshakeTime: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "blackhole_handshake_time_seconds",
				Help:    "Security handshake time by protocol",
				Buckets: latencyBuckets,
			},
			[]string{"protocol"},
		),
	}

	return m, nil
}

// RecordConnectionOpened records a new connection
func (m *Metrics) RecordConnectionOpened() {
	m.ActiveConnections.Inc()
	m.TotalConnections.Inc()
}

// RecordConnectionClosed records a closed connection
func (m *Metrics) RecordConnectionClosed(duration float64) {
	m.ActiveConnections.Dec()
	m.ConnectionDuration.Observe(duration)
}

// RecordConnectionFailed records a failed connection attempt
func (m *Metrics) RecordConnectionFailed() {
	m.FailedConnections.Inc()
}

// RecordConnectionLatency records connection establishment latency
func (m *Metrics) RecordConnectionLatency(latency time.Duration) {
	m.ConnectionLatency.Observe(latency.Seconds())
}

// RecordStreamOpened records a new stream
func (m *Metrics) RecordStreamOpened() {
	m.ActiveStreams.Inc()
	m.TotalStreams.Inc()
}

// RecordStreamClosed records a closed stream
func (m *Metrics) RecordStreamClosed(duration float64) {
	m.ActiveStreams.Dec()
	if duration > 0 {
		m.StreamDuration.Observe(duration)
	}
}

// RecordBytesTransferred records bytes sent or received
func (m *Metrics) RecordBytesTransferred(sent, received uint64) {
	m.BytesSent.Add(float64(sent))
	m.BytesReceived.Add(float64(received))
}

// UpdateBandwidthRate updates the current bandwidth rate
func (m *Metrics) UpdateBandwidthRate(direction string, bytesPerSecond float64) {
	m.BandwidthRate.WithLabelValues(direction).Set(bytesPerSecond)
}

// RecordMessageSize records the size of a message
func (m *Metrics) RecordMessageSize(protocol, direction string, size int) {
	m.MessageSize.WithLabelValues(protocol, direction).Observe(float64(size))
}

// RecordProtocolMessage records a protocol message
func (m *Metrics) RecordProtocolMessage(protocol, messageType string) {
	m.ProtocolMessages.WithLabelValues(protocol, messageType).Inc()
}

// RecordProtocolError records a protocol error
func (m *Metrics) RecordProtocolError(protocol, errorType string) {
	m.ProtocolErrors.WithLabelValues(protocol, errorType).Inc()
}

// RecordProtocolLatency records protocol operation latency
func (m *Metrics) RecordProtocolLatency(protocol, operation string, latency time.Duration) {
	m.ProtocolLatency.WithLabelValues(protocol, operation).Observe(latency.Seconds())
}

// UpdateTransportConnections updates connection count for a transport
func (m *Metrics) UpdateTransportConnections(transport string, count float64) {
	m.TransportConnections.WithLabelValues(transport).Set(count)
}

// RecordTransportError records a transport error
func (m *Metrics) RecordTransportError(transport, errorType string) {
	m.TransportErrors.WithLabelValues(transport, errorType).Inc()
}

// RecordTransportLatency records transport connection latency
func (m *Metrics) RecordTransportLatency(transport string, latency time.Duration) {
	m.TransportLatency.WithLabelValues(transport).Observe(latency.Seconds())
}

// RecordDHTQuery records a DHT query
func (m *Metrics) RecordDHTQuery(duration time.Duration) {
	m.DHTQueries.Inc()
	m.DHTQueryDuration.Observe(duration.Seconds())
}

// UpdateDHTRoutingTableSize updates the DHT routing table size
func (m *Metrics) UpdateDHTRoutingTableSize(size int) {
	m.DHTRoutingTableSize.Set(float64(size))
}

// UpdatePeersByDirection updates peer count by direction
func (m *Metrics) UpdatePeersByDirection(inbound, outbound int) {
	m.PeersByDirection.WithLabelValues("inbound").Set(float64(inbound))
	m.PeersByDirection.WithLabelValues("outbound").Set(float64(outbound))
}

// UpdatePeersByProtocol updates peer count by protocol
func (m *Metrics) UpdatePeersByProtocol(protocol string, count int) {
	m.PeersByProtocol.WithLabelValues(protocol).Set(float64(count))
}

// UpdateStreamsByProtocol updates stream count by protocol
func (m *Metrics) UpdateStreamsByProtocol(protocol string, count int) {
	m.StreamsByProtocol.WithLabelValues(protocol).Set(float64(count))
}

// UpdateResourceMetrics updates resource usage metrics
func (m *Metrics) UpdateResourceMetrics(memoryBytes uint64, goroutines int, fileDescriptors int) {
	m.MemoryUsage.Set(float64(memoryBytes))
	m.GoroutineCount.Set(float64(goroutines))
	m.FileDescriptors.Set(float64(fileDescriptors))
}

// RecordHandshakeTime records security handshake time
func (m *Metrics) RecordHandshakeTime(protocol string, duration time.Duration) {
	m.HandshakeTime.WithLabelValues(protocol).Observe(duration.Seconds())
}