package network_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/blackhole/blackhole/pkg/network"
	"github.com/libp2p/go-libp2p/core/crypto"
	libnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLS13Configuration(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name     string
		config   func() *network.SecurityConfig
		wantErr  bool
		validate func(t *testing.T, host *network.Host)
	}{
		{
			name: "TLS 1.3 enabled",
			config: func() *network.SecurityConfig {
				return &network.SecurityConfig{
					TLS: &network.TLSConfig{
						Enabled:    true,
						MinVersion: tls.VersionTLS13,
						CipherSuites: []uint16{
							tls.TLS_AES_128_GCM_SHA256,
							tls.TLS_AES_256_GCM_SHA384,
							tls.TLS_CHACHA20_POLY1305_SHA256,
						},
					},
				}
			},
			wantErr: false,
			validate: func(t *testing.T, host *network.Host) {
				// Verify TLS is configured
				assert.NotNil(t, host, "Host should be created with TLS")
			},
		},
		{
			name: "TLS with custom cipher suites",
			config: func() *network.SecurityConfig {
				return &network.SecurityConfig{
					TLS: &network.TLSConfig{
						Enabled:    true,
						MinVersion: tls.VersionTLS13,
						CipherSuites: []uint16{
							tls.TLS_AES_256_GCM_SHA384,
						},
					},
				}
			},
			wantErr: false,
		},
		{
			name: "TLS with invalid version",
			config: func() *network.SecurityConfig {
				return &network.SecurityConfig{
					TLS: &network.TLSConfig{
						Enabled:    true,
						MinVersion: tls.VersionTLS10, // Too old
					},
				}
			},
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := createTestConfig(0)
			config.Network.Security = tt.config()
			
			host, err := network.NewHost(ctx, config)
			if tt.wantErr {
				assert.Error(t, err, "Expected error with invalid TLS config")
				return
			}
			
			require.NoError(t, err)
			defer host.Close()
			
			if tt.validate != nil {
				tt.validate(t, host)
			}
		})
	}
}

func TestNoiseProtocol(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name   string
		config func() *network.SecurityConfig
	}{
		{
			name: "Noise enabled",
			config: func() *network.SecurityConfig {
				return &network.SecurityConfig{
					Noise: &network.NoiseConfig{
						Enabled: true,
					},
				}
			},
		},
		{
			name: "Noise with custom patterns",
			config: func() *network.SecurityConfig {
				return &network.SecurityConfig{
					Noise: &network.NoiseConfig{
						Enabled:  true,
						Patterns: []string{"XX", "IK"},
					},
				}
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create two hosts with Noise
			config1 := createTestConfig(0)
			config1.Network.Security = tt.config()
			
			host1, err := network.NewHost(ctx, config1)
			require.NoError(t, err)
			defer host1.Close()
			
			config2 := createTestConfig(0)
			config2.Network.Security = tt.config()
			
			host2, err := network.NewHost(ctx, config2)
			require.NoError(t, err)
			defer host2.Close()
			
			// Connect hosts
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			
			err = host1.Connect(ctx, peerInfo)
			assert.NoError(t, err, "Should connect with Noise protocol")
			
			// Verify secure connection
			conns := host1.Network().ConnsToPeer(host2.ID())
			assert.NotEmpty(t, conns, "Should have connection")
			
			// Send encrypted data
			protocolID := protocol.ID("/noise-test/1.0.0")
			testData := []byte("sensitive data")
			received := make(chan []byte, 1)
			
			host2.SetStreamHandler(protocolID, func(s libnetwork.Stream) {
				defer s.Close()
				buf := make([]byte, len(testData))
				if n, err := s.Read(buf); err == nil {
					received <- buf[:n]
				}
			})
			
			stream, err := host1.NewStream(ctx, host2.ID(), protocolID)
			require.NoError(t, err)
			defer stream.Close()
			
			_, err = stream.Write(testData)
			require.NoError(t, err)
			
			select {
			case data := <-received:
				assert.Equal(t, testData, data, "Data should be transmitted securely")
			case <-time.After(2 * time.Second):
				t.Fatal("Timeout waiting for data")
			}
		})
	}
}

func TestCertificateValidation(t *testing.T) {
	ctx := context.Background()
	
	t.Run("valid certificate", func(t *testing.T) {
		config := createTestConfig(0)
		config.Network.Security = &network.SecurityConfig{
			TLS: &network.TLSConfig{
				Enabled:    true,
				MinVersion: tls.VersionTLS13,
			},
		}
		
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		defer host.Close()
		
		// Host should have valid peer ID derived from key
		assert.NotEmpty(t, host.ID(), "Should have valid peer ID")
		
		// Verify key matches peer ID
		pubKey := host.Peerstore().PubKey(host.ID())
		assert.NotNil(t, pubKey, "Should have public key in peerstore")
		
		derivedID, err := peer.IDFromPublicKey(pubKey)
		require.NoError(t, err)
		assert.Equal(t, host.ID(), derivedID, "Peer ID should match public key")
	})
	
	t.Run("certificate rotation", func(t *testing.T) {
		// Create host with initial key
		config1 := createTestConfig(0)
		host1, err := network.NewHost(ctx, config1)
		require.NoError(t, err)
		
		id1 := host1.ID()
		host1.Close()
		
		// Create new host with different key
		config2 := createTestConfig(0)
		config2.Identity.PrivateKeyPath = "/tmp/blackhole_test_key_rotated"
		
		host2, err := network.NewHost(ctx, config2)
		require.NoError(t, err)
		defer host2.Close()
		
		id2 := host2.ID()
		assert.NotEqual(t, id1, id2, "New key should produce different peer ID")
	})
}

func TestSecurityProtocolNegotiation(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name     string
		config1  *network.SecurityConfig
		config2  *network.SecurityConfig
		shouldConnect bool
	}{
		{
			name: "both support TLS and Noise",
			config1: &network.SecurityConfig{
				TLS:   &network.TLSConfig{Enabled: true, MinVersion: tls.VersionTLS13},
				Noise: &network.NoiseConfig{Enabled: true},
			},
			config2: &network.SecurityConfig{
				TLS:   &network.TLSConfig{Enabled: true, MinVersion: tls.VersionTLS13},
				Noise: &network.NoiseConfig{Enabled: true},
			},
			shouldConnect: true,
		},
		{
			name: "TLS only to Noise only",
			config1: &network.SecurityConfig{
				TLS: &network.TLSConfig{Enabled: true, MinVersion: tls.VersionTLS13},
			},
			config2: &network.SecurityConfig{
				Noise: &network.NoiseConfig{Enabled: true},
			},
			shouldConnect: false,
		},
		{
			name: "mixed protocols negotiate common",
			config1: &network.SecurityConfig{
				TLS:   &network.TLSConfig{Enabled: true, MinVersion: tls.VersionTLS13},
				Noise: &network.NoiseConfig{Enabled: false},
			},
			config2: &network.SecurityConfig{
				TLS:   &network.TLSConfig{Enabled: true, MinVersion: tls.VersionTLS13},
				Noise: &network.NoiseConfig{Enabled: true},
			},
			shouldConnect: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create first host
			config1 := createTestConfig(0)
			config1.Network.Security = tt.config1
			
			host1, err := network.NewHost(ctx, config1)
			require.NoError(t, err)
			defer host1.Close()
			
			// Create second host
			config2 := createTestConfig(0)
			config2.Network.Security = tt.config2
			
			host2, err := network.NewHost(ctx, config2)
			require.NoError(t, err)
			defer host2.Close()
			
			// Try to connect
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			
			connectCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			
			err = host1.Connect(connectCtx, peerInfo)
			
			if tt.shouldConnect {
				assert.NoError(t, err, "Hosts should negotiate common security protocol")
				assert.Contains(t, host1.Network().Peers(), host2.ID())
			} else {
				assert.Error(t, err, "Hosts should fail to connect without common protocol")
			}
		})
	}
}

func TestSecureMultiplexing(t *testing.T) {
	ctx := context.Background()
	
	// Create hosts with security enabled
	config1 := createTestConfig(0)
	config1.Network.Security = network.DefaultSecurityConfig()
	
	host1, err := network.NewHost(ctx, config1)
	require.NoError(t, err)
	defer host1.Close()
	
	config2 := createTestConfig(0)
	config2.Network.Security = network.DefaultSecurityConfig()
	
	host2, err := network.NewHost(ctx, config2)
	require.NoError(t, err)
	defer host2.Close()
	
	// Connect hosts
	peerInfo := peer.AddrInfo{
		ID:    host2.ID(),
		Addrs: host2.Addrs(),
	}
	
	err = host1.Connect(ctx, peerInfo)
	require.NoError(t, err)
	
	// Create multiple secure streams
	numStreams := 10
	streams := make([]libnetwork.Stream, numStreams)
	received := make([]chan []byte, numStreams)
	
	for i := 0; i < numStreams; i++ {
		protocolID := protocol.ID(fmt.Sprintf("/secure-mux-test/%d/1.0.0", i))
		received[i] = make(chan []byte, 1)
		idx := i
		
		host2.SetStreamHandler(protocolID, func(s libnetwork.Stream) {
			defer s.Close()
			buf := make([]byte, 1024)
			n, err := s.Read(buf)
			if err != nil {
				return
			}
			received[idx] <- buf[:n]
		})
		
		stream, err := host1.NewStream(ctx, host2.ID(), protocolID)
		require.NoError(t, err)
		streams[i] = stream
	}
	
	// Send different data on each stream
	for i, stream := range streams {
		data := []byte(fmt.Sprintf("secure stream %d data", i))
		_, err := stream.Write(data)
		require.NoError(t, err)
		stream.Close()
	}
	
	// Verify all data received correctly
	for i := 0; i < numStreams; i++ {
		select {
		case data := <-received[i]:
			expected := fmt.Sprintf("secure stream %d data", i)
			assert.Equal(t, expected, string(data), "Stream %d data mismatch", i)
		case <-time.After(2 * time.Second):
			t.Fatalf("Timeout waiting for stream %d", i)
		}
	}
}

func TestKeyManagement(t *testing.T) {
	ctx := context.Background()
	
	t.Run("generate new key", func(t *testing.T) {
		config := createTestConfig(0)
		config.Identity.PrivateKeyPath = "/tmp/blackhole_test_new_key"
		
		host, err := network.NewHost(ctx, config)
		require.NoError(t, err)
		defer host.Close()
		
		// Verify key was generated
		assert.NotEmpty(t, host.ID())
		
		// Verify key type
		privKey := host.Peerstore().PrivKey(host.ID())
		assert.NotNil(t, privKey)
		assert.Equal(t, crypto.Ed25519, privKey.Type())
	})
	
	t.Run("load existing key", func(t *testing.T) {
		keyPath := "/tmp/blackhole_test_existing_key"
		
		// Create host with new key
		config1 := createTestConfig(0)
		config1.Identity.PrivateKeyPath = keyPath
		
		host1, err := network.NewHost(ctx, config1)
		require.NoError(t, err)
		id1 := host1.ID()
		host1.Close()
		
		// Create another host with same key
		config2 := createTestConfig(0)
		config2.Identity.PrivateKeyPath = keyPath
		
		host2, err := network.NewHost(ctx, config2)
		require.NoError(t, err)
		defer host2.Close()
		
		// Should have same peer ID
		assert.Equal(t, id1, host2.ID(), "Same key should produce same peer ID")
	})
}