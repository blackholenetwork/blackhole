package network

import (
	"github.com/prometheus/client_golang/prometheus"
)

// NewNoopMetrics creates a metrics instance with unregistered collectors
// This is used when metrics are disabled to avoid registration conflicts
func NewNoopMetrics() *Metrics {
	return &Metrics{
		// Connection metrics
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_active_connections",
		}),
		TotalConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_total_connections",
		}),
		FailedConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_failed_connections",
		}),
		ConnectionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "noop_connection_duration",
		}),
		ConnectionLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "noop_connection_latency",
		}),
		
		// Peer metrics
		ConnectedPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_connected_peers",
		}),
		DiscoveredPeers: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_discovered_peers",
		}),
		PeersByDirection: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "noop_peers_by_direction",
		}, []string{"direction"}),
		PeersByProtocol: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "noop_peers_by_protocol",
		}, []string{"protocol"}),
		
		// Stream metrics
		ActiveStreams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_active_streams",
		}),
		TotalStreams: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_total_streams",
		}),
		StreamDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "noop_stream_duration",
		}),
		StreamsByProtocol: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "noop_streams_by_protocol",
		}, []string{"protocol"}),
		
		// Bandwidth metrics
		BytesSent: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_bytes_sent",
		}),
		BytesReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_bytes_received",
		}),
		BandwidthRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "noop_bandwidth_rate",
		}, []string{"direction"}),
		MessageSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "noop_message_size",
		}, []string{"direction"}),
		
		// Protocol metrics
		ProtocolMessages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "noop_protocol_messages",
		}, []string{"protocol", "type"}),
		ProtocolErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "noop_protocol_errors",
		}, []string{"protocol", "error"}),
		ProtocolLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "noop_protocol_latency",
		}, []string{"protocol", "operation"}),
		
		// Transport metrics
		TransportConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "noop_transport_connections",
		}, []string{"transport"}),
		TransportErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "noop_transport_errors",
		}, []string{"transport", "error"}),
		TransportLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "noop_transport_latency",
		}, []string{"transport"}),
		
		// DHT metrics
		DHTQueries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "noop_dht_queries",
		}),
		DHTQueryDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "noop_dht_query_duration",
		}),
		DHTRoutingTableSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_dht_routing_table_size",
		}),
		
		// Resource metrics
		MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_memory_usage",
		}),
		GoroutineCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_goroutine_count",
		}),
		FileDescriptors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "noop_file_descriptors",
		}),
		
		// Performance metrics
		ConnectionSetupTime: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "noop_connection_setup_time",
		}),
		HandshakeTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "noop_handshake_time",
		}, []string{"protocol"}),
		
		// Custom buckets
		latencyBuckets:  []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		sizeBuckets:     []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304},
		durationBuckets: prometheus.ExponentialBuckets(0.1, 2, 15),
	}
}