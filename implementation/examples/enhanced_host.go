package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/blackhole/blackhole/pkg/network"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// Create a default configuration
	config := &network.Config{
		Network: network.NetworkConfig{
			ListenAddresses: []string{
				"/ip4/0.0.0.0/tcp/4001",
				"/ip4/0.0.0.0/udp/4001/quic-v1",
				"/ip6/::/tcp/4001",
				"/ip6/::/udp/4001/quic-v1",
			},
			BootstrapPeers: []string{
				// Add bootstrap peers here if needed
			},
			ConnectionManager: &network.ConnectionManagerConf{
				HighWater:   900,
				LowWater:    600,
				GracePeriod: 20 * time.Second,
			},
			Transports: &network.TransportConfig{
				TCP: &network.TCPConfig{
					Enabled:   true,
					PortReuse: true,
					KeepAlive: 30 * time.Second,
					NoDelay:   true,
				},
				QUIC: &network.QUICConfig{
					Enabled:            true,
					KeepAlive:          true,
					MaxIdleTimeout:     30 * time.Second,
					MaxIncomingStreams: 1000,
				},
				WebSocket: &network.WebSocketConfig{
					Enabled:    true,
					TLSEnabled: true,
				},
			},
			Security: &network.SecurityConfig{
				TLS: &network.TLSConfig{
					Enabled:               true,
					PreferServerCiphers:   true,
					SessionTicketsEnabled: true,
				},
				Noise: &network.NoiseConfig{
					Enabled: true,
				},
			},
		},
		Identity: network.IdentityConfig{
			PrivateKeyPath: "./blackhole_key",
		},
		Metrics: network.MetricsConfig{
			Enabled: true,
			Address: ":9090",
			Path:    "/metrics",
		},
		Logging: network.LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Discovery: network.DiscoveryConfig{
			MDNS: &network.MDNSConfig{
				Enabled:  true,
				Interval: 10 * time.Second,
			},
			DHT: &network.DHTConfig{
				Enabled: true,
				Mode:    "auto",
			},
		},
		Resources: network.ResourceConfig{
			MaxMemory:          "500MB",
			MaxFileDescriptors: 4096,
			MaxConnections:     1000,
		},
	}

	// Create the host
	ctx := context.Background()
	host, err := network.NewHost(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}

	// Start the host
	if err := host.Start(); err != nil {
		log.Fatalf("Failed to start host: %v", err)
	}

	fmt.Printf("Host started with ID: %s\n", host.ID())
	fmt.Println("Listening on:")
	for _, addr := range host.Addrs() {
		fmt.Printf("  %s/p2p/%s\n", addr, host.ID())
	}

	// Start metrics server if enabled
	if config.Metrics.Enabled {
		go func() {
			http.Handle(config.Metrics.Path, promhttp.Handler())
			log.Printf("Metrics server listening on %s%s", config.Metrics.Address, config.Metrics.Path)
			if err := http.ListenAndServe(config.Metrics.Address, nil); err != nil {
				log.Printf("Metrics server error: %v", err)
			}
		}()
	}

	// Example: Set up a simple protocol handler
	const protocolID = "/blackhole/example/1.0.0"
	host.SetStreamHandler(protocolID, func(s libp2pnetwork.Stream) {
		defer s.Close()
		
		// Read message
		buf := make([]byte, 1024)
		n, err := s.Read(buf)
		if err != nil {
			log.Printf("Error reading from stream: %v", err)
			return
		}
		
		msg := string(buf[:n])
		log.Printf("Received message: %s", msg)
		
		// Send response
		response := fmt.Sprintf("Echo: %s", msg)
		if _, err := s.Write([]byte(response)); err != nil {
			log.Printf("Error writing to stream: %v", err)
		}
	})

	// Example: Discover peers periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				peerChan, err := host.DiscoverPeers(ctx, "blackhole-example")
				if err != nil {
					log.Printf("Failed to discover peers: %v", err)
					cancel()
					continue
				}
				
				for peer := range peerChan {
					if peer.ID != host.ID() {
						log.Printf("Discovered peer: %s", peer.ID)
						// Optionally connect to discovered peers
						if err := host.Connect(ctx, peer); err != nil {
							log.Printf("Failed to connect to peer %s: %v", peer.ID, err)
						}
					}
				}
				cancel()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Example: Print metrics periodically
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				metrics := host.GetMetrics()
				if metrics != nil {
					connManager := host.(*network.Host).GetConnectionManager()
					if connManager != nil {
						connections := connManager.GetAllConnections()
						fmt.Printf("\n=== Network Status ===\n")
						fmt.Printf("Connected peers: %d\n", len(connections))
						fmt.Printf("Active connections: %d\n", len(host.Network().Conns()))
						
						for _, conn := range connections {
							fmt.Printf("  Peer: %s, Direction: %s, Streams: %d, Latency: %v\n",
								conn.PeerID.ShortString(),
								conn.Direction,
								conn.Streams,
								conn.Latency,
							)
						}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	if err := host.Stop(); err != nil {
		log.Printf("Error stopping host: %v", err)
	}
	fmt.Println("Host stopped successfully")
}