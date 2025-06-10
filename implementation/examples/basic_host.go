package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/blackhole/blackhole/pkg/network"
	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const exampleProtocol = protocol.ID("/blackhole/example/1.0.0")

func main() {
	ctx := context.Background()

	// Create a basic configuration
	config := &network.Config{
		Network: network.NetworkConfig{
			ListenAddresses: []string{
				"/ip4/0.0.0.0/tcp/4001",
			},
			BootstrapPeers:    []string{},
			ConnectionManager: nil, // Use defaults
			Transports:        network.DefaultTransportConfig(),
			Security:          network.DefaultSecurityConfig(),
		},
		Identity: network.IdentityConfig{
			PrivateKeyPath: "~/.blackhole/example_key",
		},
		Metrics: network.MetricsConfig{
			Enabled: false,
		},
		Logging: network.LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}

	// Note: defaults are applied automatically in NewHost

	// Create the host
	host, err := network.NewHost(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	// Get identity information
	identityInfo, err := network.GetIdentityInfo(host)
	if err != nil {
		log.Fatalf("Failed to get identity info: %v", err)
	}

	fmt.Printf("Host created successfully!\n")
	fmt.Printf("Peer ID: %s\n", identityInfo.PeerID)
	fmt.Printf("Addresses:\n")
	for _, addr := range identityInfo.Addresses {
		fmt.Printf("  %s\n", addr)
	}

	// Set up a simple echo protocol handler
	host.SetStreamHandler(exampleProtocol, func(stream libp2pnetwork.Stream) {
		defer stream.Close()

		// Read message
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Error reading from stream: %v", err)
			return
		}

		message := string(buf[:n])
		log.Printf("Received message: %s", message)

		// Echo back
		response := fmt.Sprintf("Echo: %s", message)
		if _, err := stream.Write([]byte(response)); err != nil {
			log.Printf("Error writing to stream: %v", err)
			return
		}
	})

	// Run for a while
	fmt.Printf("\nHost is running. It will shut down in 30 seconds...\n")
	fmt.Printf("To connect from another node, use one of the addresses above with the peer ID.\n")
	fmt.Printf("Example: /ip4/127.0.0.1/tcp/4001/p2p/%s\n", identityInfo.PeerID)

	time.Sleep(30 * time.Second)

	fmt.Printf("\nShutting down...\n")
}

// Example of connecting to another peer
func connectToPeer(ctx context.Context, host *network.Host, peerAddr string) error {
	// Parse peer address
	peerInfo, err := peer.AddrInfoFromString(peerAddr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	// Connect
	if err := host.Connect(ctx, *peerInfo); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	fmt.Printf("Connected to peer: %s\n", peerInfo.ID)

	// Open a stream
	stream, err := host.NewStream(ctx, peerInfo.ID, exampleProtocol)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Send a message
	message := "Hello, Blackhole!"
	if _, err := stream.Write([]byte(message)); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	fmt.Printf("Received response: %s\n", string(buf[:n]))

	return nil
}