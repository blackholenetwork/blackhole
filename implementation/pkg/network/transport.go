package network

import (
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
)

// TransportConfig defines the transport layer configuration
type TransportConfig struct {
	TCP       *TCPConfig       `yaml:"tcp"`
	QUIC      *QUICConfig      `yaml:"quic"`
	WebSocket *WebSocketConfig `yaml:"websocket"`
	WebRTC    *WebRTCConfig    `yaml:"webrtc"`
}

// TCPConfig defines TCP transport configuration
type TCPConfig struct {
	Enabled          bool          `yaml:"enabled"`
	PortReuse        bool          `yaml:"port_reuse"`
	KeepAlive        time.Duration `yaml:"keep_alive"`
	NoDelay          bool          `yaml:"no_delay"`
	SocketBufferSize int           `yaml:"socket_buffer_size"`
}

// QUICConfig defines QUIC transport configuration
type QUICConfig struct {
	Enabled               bool          `yaml:"enabled"`
	KeepAlivePeriod      time.Duration `yaml:"keep_alive_period"`
	MaxIdleTimeout       time.Duration `yaml:"max_idle_timeout"`
	MaxIncomingStreams   int64         `yaml:"max_incoming_streams"`
	StatelessResetKey    []byte        `yaml:"stateless_reset_key"`
	DisableVersionNegotiation bool     `yaml:"disable_version_negotiation"`
}

// WebSocketConfig defines WebSocket transport configuration
type WebSocketConfig struct {
	Enabled           bool   `yaml:"enabled"`
	TLSEnabled        bool   `yaml:"tls_enabled"`
	HandshakeTimeout  time.Duration `yaml:"handshake_timeout"`
	ReadBufferSize    int    `yaml:"read_buffer_size"`
	WriteBufferSize   int    `yaml:"write_buffer_size"`
}

// WebRTCConfig defines WebRTC transport configuration
type WebRTCConfig struct {
	Enabled bool `yaml:"enabled"`
}

// buildTransportOptions creates libp2p transport options based on config
func buildTransportOptions(config *TransportConfig) ([]libp2p.Option, error) {
	var opts []libp2p.Option
	
	// Validate at least one transport is enabled
	if !isAnyTransportEnabled(config) {
		return nil, fmt.Errorf("at least one transport must be enabled")
	}
	
	// Configure TCP transport
	if config.TCP != nil && config.TCP.Enabled {
		opts = append(opts, libp2p.Transport(tcp.NewTCPTransport))
	}
	
	// Configure QUIC transport
	if config.QUIC != nil && config.QUIC.Enabled {
		opts = append(opts, libp2p.Transport(libp2pquic.NewTransport))
	}
	
	// Configure WebSocket transport
	if config.WebSocket != nil && config.WebSocket.Enabled {
		opts = append(opts, libp2p.Transport(websocket.New))
	}
	
	return opts, nil
}

// isAnyTransportEnabled checks if at least one transport is enabled
func isAnyTransportEnabled(config *TransportConfig) bool {
	if config.TCP != nil && config.TCP.Enabled {
		return true
	}
	if config.QUIC != nil && config.QUIC.Enabled {
		return true
	}
	if config.WebSocket != nil && config.WebSocket.Enabled {
		return true
	}
	if config.WebRTC != nil && config.WebRTC.Enabled {
		return true
	}
	return false
}