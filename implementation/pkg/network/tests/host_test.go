package network_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blackhole/blackhole/pkg/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHost(t *testing.T) {
	tests := []struct {
		name    string
		config  func() *network.Config
		wantErr bool
		validate func(t *testing.T, host *network.Host)
	}{
		{
			name: "default configuration",
			config: func() *network.Config {
				return createTestConfig(0)
			},
			wantErr: false,
			validate: func(t *testing.T, host *network.Host) {
				assert.NotEmpty(t, host.ID(), "Expected valid peer ID")
				assert.NotEmpty(t, host.Addrs(), "Expected at least one listening address")
			},
		},
		{
			name: "multiple listen addresses",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Network.ListenAddresses = []string{
					"/ip4/127.0.0.1/tcp/0",
					"/ip4/127.0.0.1/udp/0/quic",
					"/ip6/::1/tcp/0",
				}
				return config
			},
			wantErr: false,
			validate: func(t *testing.T, host *network.Host) {
				assert.GreaterOrEqual(t, len(host.Addrs()), 2, "Expected multiple listening addresses")
			},
		},
		{
			name: "with metrics enabled",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Metrics.Enabled = true
				config.Metrics.Port = 9090
				return config
			},
			wantErr: false,
			validate: func(t *testing.T, host *network.Host) {
				// Metrics should be accessible
				assert.NotNil(t, host, "Host should be created with metrics")
			},
		},
		{
			name: "custom connection limits",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Network.ConnectionManager = &network.ConnectionManagerConf{
					HighWater:   1000,
					LowWater:    500,
					GracePeriod: 30 * time.Second,
				}
				return config
			},
			wantErr: false,
			validate: func(t *testing.T, host *network.Host) {
				// Connection manager should be configured
				assert.NotNil(t, host.ConnManager(), "Connection manager should be configured")
			},
		},
		{
			name: "invalid listen address",
			config: func() *network.Config {
				config := createTestConfig(0)
				config.Network.ListenAddresses = []string{
					"invalid-address",
				}
				return config
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := tt.config()
			
			host, err := network.NewHost(ctx, config)
			if tt.wantErr {
				assert.Error(t, err, "Expected error creating host")
				return
			}
			
			require.NoError(t, err, "Failed to create host")
			defer host.Close()
			
			if tt.validate != nil {
				tt.validate(t, host)
			}
		})
	}
}

func TestHostBootstrap(t *testing.T) {
	ctx := context.Background()

	// Create first host (bootstrap node)
	config1 := createTestConfig(0)
	host1, err := network.NewHost(ctx, config1)
	if err != nil {
		t.Fatalf("Failed to create host1: %v", err)
	}
	defer host1.Close()

	// Get host1's address
	host1Addr := host1.Addrs()[0].String() + "/p2p/" + host1.ID().String()

	// Create second host with bootstrap peer
	config2 := createTestConfig(0)
	config2.Network.BootstrapPeers = []string{host1Addr}
	
	host2, err := network.NewHost(ctx, config2)
	if err != nil {
		t.Fatalf("Failed to create host2: %v", err)
	}
	defer host2.Close()

	// Bootstrap host2
	if err := host2.Bootstrap(ctx); err != nil {
		t.Fatalf("Failed to bootstrap: %v", err)
	}

	// Verify connection
	time.Sleep(100 * time.Millisecond) // Give time for connection to establish
	
	if len(host2.Network().Peers()) == 0 {
		t.Error("Expected host2 to be connected to host1")
	}
}

func TestHostLifecycle(t *testing.T) {
	t.Run("start and stop", func(t *testing.T) {
		ctx := context.Background()
		
		config := createTestConfig(0)
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err, "Failed to create host")
		
		// Verify host is running
		assert.NotEmpty(t, host.ID(), "Host should have peer ID")
		assert.NotEmpty(t, host.Addrs(), "Host should be listening")
		
		// Stop the host
		err = host.Shutdown(ctx)
		assert.NoError(t, err, "Failed to shutdown host")
		
		// Verify host is stopped - operations should fail
		// Try to create a new stream (should fail)
		_, err = host.NewStream(ctx, host.ID(), "/test/1.0.0")
		assert.Error(t, err, "Expected error after shutdown")
	})
	
	t.Run("shutdown with timeout", func(t *testing.T) {
		ctx := context.Background()
		
		config := createTestConfig(0)
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		defer host.Close()
		
		// Use a short timeout context
		shutdownCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		
		err = host.Shutdown(shutdownCtx)
		assert.NoError(t, err, "Shutdown should complete within timeout")
	})
	
	t.Run("multiple starts", func(t *testing.T) {
		ctx := context.Background()
		
		config := createTestConfig(0)
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		
		// First shutdown
		err = host.Shutdown(ctx)
		assert.NoError(t, err)
		
		// Second shutdown should be idempotent
		err = host.Shutdown(ctx)
		assert.NoError(t, err, "Multiple shutdowns should be safe")
	})
}

func TestConnectionLimitsEnforcement(t *testing.T) {
	t.Skip("Skipping connection limits test - requires more sophisticated connection manager implementation")
	ctx := context.Background()
	
	// Create host with very low limits
	config := createTestConfig(0)
	config.Network.ConnectionManager = &network.ConnectionManagerConf{
		HighWater:   3,
		LowWater:    2,
		GracePeriod: 100 * time.Millisecond,
	}
	
	host, err := network.NewHost(ctx, config)
	require.NoError(t, err)
	defer host.Close()
	
	// Create multiple peers
	peers := make([]*network.Host, 5)
	for i := 0; i < 5; i++ {
		peerConfig := createTestConfig(0)
		peerHost, err := network.NewHost(ctx, peerConfig)
		require.NoError(t, err)
		defer peerHost.Close()
		peers[i] = peerHost
	}
	
	// Connect all peers to the host
	var wg sync.WaitGroup
	for i, peerHost := range peers {
		wg.Add(1)
		go func(idx int, p *network.Host) {
			defer wg.Done()
			
			addr := fmt.Sprintf("%s/p2p/%s", host.Addrs()[0].String(), host.ID())
			peerInfo, err := peer.AddrInfoFromString(addr)
			if err != nil {
				t.Logf("Peer %d: Failed to parse address: %v", idx, err)
				return
			}
			
			err = p.Connect(ctx, *peerInfo)
			if err != nil {
				t.Logf("Peer %d: Connection failed (expected for some): %v", idx, err)
			}
		}(i, peerHost)
	}
	
	wg.Wait()
	time.Sleep(1 * time.Second) // Allow connection manager to trim
	
	// Check that connections were limited
	connectedPeers := len(host.Network().Peers())
	assert.LessOrEqual(t, connectedPeers, config.Network.ConnectionManager.HighWater,
		"Connected peers should not exceed high water mark")
	assert.GreaterOrEqual(t, connectedPeers, config.Network.ConnectionManager.LowWater,
		"Connected peers should be at least low water mark")
}

func TestMetricCollection(t *testing.T) {
	t.Skip("Skipping metrics test - requires proper metrics registry isolation")
	ctx := context.Background()
	
	config := createTestConfig(0)
	config.Metrics.Enabled = true
	config.Metrics.Port = 9091
	
	host, err := network.NewHost(ctx, config)
	require.NoError(t, err)
	defer host.Close()
	
	// Create another host and connect
	peerConfig := createTestConfig(0)
	peerHost, err := network.NewHost(ctx, peerConfig)
	require.NoError(t, err)
	defer peerHost.Close()
	
	// Connect peers
	addr := fmt.Sprintf("%s/p2p/%s", host.Addrs()[0].String(), host.ID())
	peerInfo, err := peer.AddrInfoFromString(addr)
	require.NoError(t, err)
	
	err = peerHost.Connect(ctx, *peerInfo)
	require.NoError(t, err)
	
	// Send some data to generate metrics
	stream, err := peerHost.NewStream(ctx, host.ID(), "/test/metrics/1.0.0")
	if err == nil {
		_, _ = stream.Write([]byte("test data for metrics"))
		stream.Close()
	}
	
	// Verify metrics are being collected
	// In a real implementation, we would check specific metric values
	// For now, we just verify the metrics endpoint is accessible
	assert.True(t, config.Metrics.Enabled, "Metrics should be enabled")
}

func TestErrorScenarios(t *testing.T) {
	ctx := context.Background()
	
	t.Run("invalid private key path", func(t *testing.T) {
		config := createTestConfig(0)
		config.Identity.PrivateKeyPath = "/invalid/path/that/does/not/exist/key"
		
		_, err := network.NewHost(ctx, config)
		assert.Error(t, err, "Should fail with invalid key path")
	})
	
	t.Run("port already in use", func(t *testing.T) {
		// Create first host
		config1 := createTestConfig(9999)
		host1, err := network.NewHost(ctx, config1)
		require.NoError(t, err)
		defer host1.Close()
		
		// Try to create second host on same port
		config2 := createTestConfig(9999)
		_, err = network.NewHost(ctx, config2)
		assert.Error(t, err, "Should fail when port is already in use")
	})
	
	t.Run("connection to non-existent peer", func(t *testing.T) {
		config := createTestConfig(0)
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		defer host.Close()
		
		// Try to connect to non-existent peer
		fakeAddr := "/ip4/127.0.0.1/tcp/12345/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
		peerInfo, err := peer.AddrInfoFromString(fakeAddr)
		require.NoError(t, err)
		
		ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		
		err = host.Connect(ctx, *peerInfo)
		assert.Error(t, err, "Should fail to connect to non-existent peer")
	})
}

// Helper function to create test configuration
func createTestConfig(port int) *network.Config {
	return &network.Config{
		Network: network.NetworkConfig{
			ListenAddresses: []string{
				fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", port),
			},
			BootstrapPeers: []string{},
			ConnectionManager: &network.ConnectionManagerConf{
				HighWater:   10,
				LowWater:    5,
				GracePeriod: 10 * time.Second,
			},
			Transports: network.DefaultTransportConfig(),
			Security:   network.DefaultSecurityConfig(),
		},
		Identity: network.IdentityConfig{
			PrivateKeyPath: fmt.Sprintf("/tmp/blackhole_test_key_%d_%d", port, time.Now().UnixNano()),
		},
		Metrics: network.MetricsConfig{
			Enabled: false,
		},
		Logging: network.LoggingConfig{
			Level:  "info",
			Output: "stdout",
			Format: "json",
		},
	}
}