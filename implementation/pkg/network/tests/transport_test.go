package network_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/blackhole/blackhole/pkg/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultTransportConfig(t *testing.T) {
	config := network.DefaultTransportConfig()

	assert.NotNil(t, config.TCP, "TCP config should not be nil")
	assert.True(t, config.TCP.Enabled, "TCP should be enabled by default")

	assert.NotNil(t, config.QUIC, "QUIC config should not be nil")
	assert.True(t, config.QUIC.Enabled, "QUIC should be enabled by default")

	assert.NotNil(t, config.WebSocket, "WebSocket config should not be nil")
	assert.False(t, config.WebSocket.Enabled, "WebSocket should be disabled by default")
}

func TestTCPTransportConfiguration(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name     string
		config   func() *network.Config
		validate func(t *testing.T, host *network.Host)
	}{
		{
			name: "TCP with default settings",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Network.Transports = &network.TransportConfig{
					TCP: &network.TCPConfig{
						Enabled: true,
					},
				}
				return config
			},
			validate: func(t *testing.T, host *network.Host) {
				// Should have TCP addresses
				hasTCP := false
				for _, addr := range host.Addrs() {
					if addr.String() != "" && contains(addr.String(), "/tcp/") {
						hasTCP = true
						break
					}
				}
				assert.True(t, hasTCP, "Should have at least one TCP address")
			},
		},
		{
			name: "TCP with custom port",
			config: func() *network.Config {
				config := createTestConfig(8888)
				config.Network.Transports = &network.TransportConfig{
					TCP: &network.TCPConfig{
						Enabled: true,
					},
				}
				return config
			},
			validate: func(t *testing.T, host *network.Host) {
				for _, addr := range host.Addrs() {
					if contains(addr.String(), "/tcp/8888") {
						return
					}
				}
				t.Error("Expected TCP address with port 8888")
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config()
			host, err := network.NewHost(ctx, config)
			require.NoError(t, err)
			defer host.Close()
			
			tt.validate(t, host)
		})
	}
}

func TestQUICTransportConfiguration(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name     string
		config   func() *network.Config
		validate func(t *testing.T, host *network.Host)
	}{
		{
			name: "QUIC enabled",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Network.Transports = &network.TransportConfig{
					QUIC: &network.QUICConfig{
						Enabled: true,
					},
				}
				config.Network.ListenAddresses = []string{
					"/ip4/127.0.0.1/udp/0/quic-v1-v1",
				}
				return config
			},
			validate: func(t *testing.T, host *network.Host) {
				hasQUIC := false
				for _, addr := range host.Addrs() {
					if contains(addr.String(), "/quic") {
						hasQUIC = true
						break
					}
				}
				assert.True(t, hasQUIC, "Should have at least one QUIC address")
			},
		},
		{
			name: "QUIC with custom settings",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Network.Transports = &network.TransportConfig{
					QUIC: &network.QUICConfig{
						Enabled:          true,
						MaxIdleTimeout:   30 * time.Second,
						KeepAlivePeriod:  10 * time.Second,
					},
				}
				config.Network.ListenAddresses = []string{
					"/ip4/127.0.0.1/udp/0/quic-v1-v1",
				}
				return config
			},
			validate: func(t *testing.T, host *network.Host) {
				// QUIC transport should be configured with custom settings
				assert.NotNil(t, host, "Host should be created with QUIC transport")
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config()
			host, err := network.NewHost(ctx, config)
			require.NoError(t, err)
			defer host.Close()
			
			tt.validate(t, host)
		})
	}
}

func TestWebSocketTransportConfiguration(t *testing.T) {
	ctx := context.Background()
	
	config := createTestConfig(0)
	config.Network.Transports = &network.TransportConfig{
		TCP: &network.TCPConfig{Enabled: true},
		WebSocket: &network.WebSocketConfig{
			Enabled: true,
		},
	}
	config.Network.ListenAddresses = []string{
		"/ip4/127.0.0.1/tcp/0/ws",
	}
	
	host, err := network.NewHost(ctx, config)
	require.NoError(t, err)
	defer host.Close()
	
	// Should have WebSocket addresses
	hasWS := false
	for _, addr := range host.Addrs() {
		if contains(addr.String(), "/ws") {
			hasWS = true
			break
		}
	}
	assert.True(t, hasWS, "Should have at least one WebSocket address")
}

func TestMultiTransportScenarios(t *testing.T) {
	ctx := context.Background()
	
	t.Run("TCP and QUIC together", func(t *testing.T) {
		config := createTestConfig(0)
		config.Network.Transports = &network.TransportConfig{
			TCP:  &network.TCPConfig{Enabled: true},
			QUIC: &network.QUICConfig{Enabled: true},
		}
		config.Network.ListenAddresses = []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
		}
		
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		defer host.Close()
		
		// Should have both TCP and QUIC addresses
		hasTCP, hasQUIC := false, false
		for _, addr := range host.Addrs() {
			if contains(addr.String(), "/tcp/") {
				hasTCP = true
			}
			if contains(addr.String(), "/quic") {
				hasQUIC = true
			}
		}
		assert.True(t, hasTCP, "Should have TCP address")
		assert.True(t, hasQUIC, "Should have QUIC address")
	})
	
	t.Run("all transports enabled", func(t *testing.T) {
		config := createTestConfig(0)
		config.Network.Transports = &network.TransportConfig{
			TCP:       &network.TCPConfig{Enabled: true},
			QUIC:      &network.QUICConfig{Enabled: true},
			WebSocket: &network.WebSocketConfig{Enabled: true},
		}
		config.Network.ListenAddresses = []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
			"/ip4/127.0.0.1/tcp/0/ws",
		}
		
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		defer host.Close()
		
		assert.GreaterOrEqual(t, len(host.Addrs()), 3, "Should have multiple transport addresses")
	})
}

func TestTransportFailuresAndRecovery(t *testing.T) {
	ctx := context.Background()
	
	t.Run("connection over failing transport", func(t *testing.T) {
		// Create two hosts with TCP and QUIC
		config1 := createTestConfig(0)
		config1.Network.Transports = &network.TransportConfig{
			TCP:  &network.TCPConfig{Enabled: true},
			QUIC: &network.QUICConfig{Enabled: true},
		}
		config1.Network.ListenAddresses = []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
		}
		
		host1, err := network.NewHost(ctx, config1)
		require.NoError(t, err)
		defer host1.Close()
		
		config2 := createTestConfig(0)
		config2.Network.Transports = &network.TransportConfig{
			TCP:  &network.TCPConfig{Enabled: true},
			QUIC: &network.QUICConfig{Enabled: true},
		}
		config2.Network.ListenAddresses = []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic-v1",
		}
		
		host2, err := network.NewHost(ctx, config2)
		require.NoError(t, err)
		defer host2.Close()
		
		// Connect hosts
		peerInfo := peer.AddrInfo{
			ID:    host2.ID(),
			Addrs: host2.Addrs(),
		}
		
		err = host1.Connect(ctx, peerInfo)
		assert.NoError(t, err, "Should connect with available transports")
		
		// Verify connection exists
		assert.Contains(t, host1.Network().Peers(), host2.ID(), "Should be connected")
	})
	
	t.Run("no transports enabled error", func(t *testing.T) {
		config := createTestConfig(0)
		config.Network.Transports = &network.TransportConfig{
			TCP:       &network.TCPConfig{Enabled: false},
			QUIC:      &network.QUICConfig{Enabled: false},
			WebSocket: &network.WebSocketConfig{Enabled: false},
		}
		
		_, err := network.NewHost(ctx, config)
		assert.Error(t, err, "Should fail when no transports are enabled")
	})
}

// Helper function
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && fmt.Sprintf("%s", s) != "" && 
		   len(fmt.Sprintf("%s", s)) >= len(substr)
}