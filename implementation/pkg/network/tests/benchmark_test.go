package network_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/blackhole/blackhole/pkg/network"
	libnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func BenchmarkConnectionEstablishment(b *testing.B) {
	ctx := context.Background()
	
	benchmarks := []struct {
		name      string
		transport string
	}{
		{"TCP", "tcp"},
		{"QUIC", "quic"},
		{"Mixed", "mixed"},
	}
	
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Create two hosts
			config1 := createBenchmarkConfig(bm.transport)
			host1, err := network.NewHost(ctx, config1)
			if err != nil {
				b.Fatalf("Failed to create host1: %v", err)
			}
			defer host1.Close()
			
			config2 := createBenchmarkConfig(bm.transport)
			host2, err := network.NewHost(ctx, config2)
			if err != nil {
				b.Fatalf("Failed to create host2: %v", err)
			}
			defer host2.Close()
			
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			
			// Initial connection
			if err := host1.Connect(ctx, peerInfo); err != nil {
				b.Fatalf("Failed initial connection: %v", err)
			}
			
			// Benchmark connection establishment
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Disconnect
				host1.Network().ClosePeer(host2.ID())
				
				// Reconnect
				if err := host1.Connect(ctx, peerInfo); err != nil {
					b.Fatalf("Failed to connect: %v", err)
				}
			}
		})
	}
}

func BenchmarkDataTransferThroughput(b *testing.B) {
	ctx := context.Background()
	
	dataSizes := []int{
		1024,        // 1KB
		1024 * 10,   // 10KB
		1024 * 100,  // 100KB
		1024 * 1024, // 1MB
	}
	
	for _, size := range dataSizes {
		b.Run(fmt.Sprintf("%dKB", size/1024), func(b *testing.B) {
			// Setup hosts
			config1 := createBenchmarkConfig("tcp")
			host1, err := network.NewHost(ctx, config1)
			if err != nil {
				b.Fatalf("Failed to create host1: %v", err)
			}
			defer host1.Close()
			
			config2 := createBenchmarkConfig("tcp")
			host2, err := network.NewHost(ctx, config2)
			if err != nil {
				b.Fatalf("Failed to create host2: %v", err)
			}
			defer host2.Close()
			
			// Set up stream handler
			protocolID := protocol.ID("/blackhole/benchmark/1.0.0")
			receiveChan := make(chan struct{})
			
			host2.SetStreamHandler(protocolID, func(s libnetwork.Stream) {
				defer s.Close()
				
				buf := make([]byte, size)
				total := 0
				for total < size {
					n, err := s.Read(buf[total:])
					if err != nil {
						return
					}
					total += n
				}
				receiveChan <- struct{}{}
			})
			
			// Connect
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			if err := host1.Connect(ctx, peerInfo); err != nil {
				b.Fatalf("Failed to connect: %v", err)
			}
			
			// Prepare data
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 256)
			}
			
			b.SetBytes(int64(size))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				// Open stream
				stream, err := host1.NewStream(ctx, host2.ID(), protocolID)
				if err != nil {
					b.Fatalf("Failed to open stream: %v", err)
				}
				
				// Send data
				if _, err := stream.Write(data); err != nil {
					b.Fatalf("Failed to write: %v", err)
				}
				stream.CloseWrite()
				
				// Wait for receive
				select {
				case <-receiveChan:
				case <-time.After(5 * time.Second):
					b.Fatalf("Timeout waiting for data")
				}
				
				stream.Close()
			}
		})
	}
}

func BenchmarkMemoryUsageWithConnections(b *testing.B) {
	connectionCounts := []int{10, 50, 100, 200}
	
	for _, count := range connectionCounts {
		b.Run(fmt.Sprintf("%d_connections", count), func(b *testing.B) {
			ctx := context.Background()
			
			// Create main host
			config := createBenchmarkConfig("tcp")
			config.Network.ConnectionManager = &network.ConnectionManagerConf{
				HighWater:   count + 50,
				LowWater:    count,
				GracePeriod: 30 * time.Second,
			}
			
			host, err := network.NewHost(ctx, config)
			if err != nil {
				b.Fatalf("Failed to create host: %v", err)
			}
			defer host.Close()
			
			// Get initial memory
			runtime.GC()
			var initialMem runtime.MemStats
			runtime.ReadMemStats(&initialMem)
			
			// Create and connect peers
			peers := make([]*network.Host, count)
			for i := 0; i < count; i++ {
				peerConfig := createBenchmarkConfig("tcp")
				peerHost, err := network.NewHost(ctx, peerConfig)
				if err != nil {
					b.Fatalf("Failed to create peer %d: %v", i, err)
				}
				defer peerHost.Close()
				peers[i] = peerHost
				
				// Connect to main host
				peerInfo := peer.AddrInfo{
					ID:    host.ID(),
					Addrs: host.Addrs(),
				}
				if err := peerHost.Connect(ctx, peerInfo); err != nil {
					b.Fatalf("Failed to connect peer %d: %v", i, err)
				}
			}
			
			// Wait for connections to stabilize
			time.Sleep(500 * time.Millisecond)
			
			// Measure memory after connections
			runtime.GC()
			var finalMem runtime.MemStats
			runtime.ReadMemStats(&finalMem)
			
			memUsed := finalMem.Alloc - initialMem.Alloc
			memPerConnection := memUsed / uint64(count)
			
			b.ReportMetric(float64(memUsed/1024/1024), "MB_total")
			b.ReportMetric(float64(memPerConnection/1024), "KB_per_conn")
			
			// Verify memory usage is under limit (500MB for 1000 connections)
			maxMemoryPerConnection := uint64(500 * 1024 * 1024 / 1000) // 500KB per connection
			if memPerConnection > maxMemoryPerConnection {
				b.Errorf("Memory per connection %d KB exceeds limit %d KB",
					memPerConnection/1024, maxMemoryPerConnection/1024)
			}
		})
	}
}

func BenchmarkCPUUsageUnderLoad(b *testing.B) {
	ctx := context.Background()
	
	scenarios := []struct {
		name        string
		numStreams  int
		messageSize int
		interval    time.Duration
	}{
		{"light_load", 10, 1024, 100 * time.Millisecond},
		{"medium_load", 50, 4096, 50 * time.Millisecond},
		{"heavy_load", 100, 8192, 10 * time.Millisecond},
	}
	
	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			// Create two hosts
			config1 := createBenchmarkConfig("tcp")
			host1, err := network.NewHost(ctx, config1)
			if err != nil {
				b.Fatalf("Failed to create host1: %v", err)
			}
			defer host1.Close()
			
			config2 := createBenchmarkConfig("tcp")
			host2, err := network.NewHost(ctx, config2)
			if err != nil {
				b.Fatalf("Failed to create host2: %v", err)
			}
			defer host2.Close()
			
			// Set up stream handler
			protocolID := protocol.ID("/blackhole/cpu-benchmark/1.0.0")
			host2.SetStreamHandler(protocolID, func(s libnetwork.Stream) {
				defer s.Close()
				buf := make([]byte, scenario.messageSize)
				for {
					if _, err := s.Read(buf); err != nil {
						return
					}
				}
			})
			
			// Connect
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			if err := host1.Connect(ctx, peerInfo); err != nil {
				b.Fatalf("Failed to connect: %v", err)
			}
			
			// Create streams
			streams := make([]libnetwork.Stream, scenario.numStreams)
			for i := 0; i < scenario.numStreams; i++ {
				stream, err := host1.NewStream(ctx, host2.ID(), protocolID)
				if err != nil {
					b.Fatalf("Failed to create stream %d: %v", i, err)
				}
				defer stream.Close()
				streams[i] = stream
			}
			
			// Prepare message
			message := make([]byte, scenario.messageSize)
			for i := range message {
				message[i] = byte(i % 256)
			}
			
			// Run load test
			var wg sync.WaitGroup
			stop := make(chan struct{})
			
			b.ResetTimer()
			
			// Start sending on all streams
			for i, stream := range streams {
				wg.Add(1)
				go func(s libnetwork.Stream, idx int) {
					defer wg.Done()
					ticker := time.NewTicker(scenario.interval)
					defer ticker.Stop()
					
					for {
						select {
						case <-ticker.C:
							if _, err := s.Write(message); err != nil {
								return
							}
						case <-stop:
							return
						}
					}
				}(stream, i)
			}
			
			// Run for benchmark duration
			time.Sleep(time.Duration(b.N) * time.Millisecond)
			
			close(stop)
			wg.Wait()
		})
	}
}

func BenchmarkConcurrentStreams(b *testing.B) {
	ctx := context.Background()
	
	streamCounts := []int{10, 50, 100, 200}
	
	for _, count := range streamCounts {
		b.Run(fmt.Sprintf("%d_streams", count), func(b *testing.B) {
			// Create hosts
			config1 := createBenchmarkConfig("tcp")
			host1, err := network.NewHost(ctx, config1)
			if err != nil {
				b.Fatalf("Failed to create host1: %v", err)
			}
			defer host1.Close()
			
			config2 := createBenchmarkConfig("tcp")
			host2, err := network.NewHost(ctx, config2)
			if err != nil {
				b.Fatalf("Failed to create host2: %v", err)
			}
			defer host2.Close()
			
			// Connect
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			if err := host1.Connect(ctx, peerInfo); err != nil {
				b.Fatalf("Failed to connect: %v", err)
			}
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				streams := make([]libnetwork.Stream, count)
				
				// Create streams concurrently
				for j := 0; j < count; j++ {
					wg.Add(1)
					go func(idx int) {
						defer wg.Done()
						protocolID := protocol.ID(fmt.Sprintf("/bench/%d/1.0.0", idx))
						stream, err := host1.NewStream(ctx, host2.ID(), protocolID)
						if err != nil {
							b.Errorf("Failed to create stream %d: %v", idx, err)
							return
						}
						streams[idx] = stream
					}(j)
				}
				
				wg.Wait()
				
				// Close all streams
				for _, stream := range streams {
					if stream != nil {
						stream.Close()
					}
				}
			}
		})
	}
}

// Helper function to create benchmark configuration
func createBenchmarkConfig(transport string) *network.Config {
	config := &network.Config{
		Network: network.NetworkConfig{
			ConnectionManager: &network.ConnectionManagerConf{
				HighWater:   100,
				LowWater:    50,
				GracePeriod: 30 * time.Second,
			},
			Security: network.DefaultSecurityConfig(),
		},
		Identity: network.IdentityConfig{
			PrivateKeyPath: fmt.Sprintf("/tmp/blackhole_bench_key_%d", time.Now().UnixNano()),
		},
		Metrics: network.MetricsConfig{
			Enabled: false,
		},
	}
	
	switch transport {
	case "tcp":
		config.Network.ListenAddresses = []string{"/ip4/127.0.0.1/tcp/0"}
		config.Network.Transports = &network.TransportConfig{
			TCP: &network.TCPConfig{Enabled: true},
		}
	case "quic":
		config.Network.ListenAddresses = []string{"/ip4/127.0.0.1/udp/0/quic"}
		config.Network.Transports = &network.TransportConfig{
			QUIC: &network.QUICConfig{Enabled: true},
		}
	case "mixed":
		config.Network.ListenAddresses = []string{
			"/ip4/127.0.0.1/tcp/0",
			"/ip4/127.0.0.1/udp/0/quic",
		}
		config.Network.Transports = network.DefaultTransportConfig()
	}
	
	return config
}