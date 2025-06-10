// +build integration

package network_test

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	blackholenet "github.com/blackhole/blackhole/pkg/network"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testProtocol = protocol.ID("/blackhole/test/1.0.0")

func TestMultiNodeConnectivity(t *testing.T) {
	tests := []struct {
		name     string
		numNodes int
		topology string // "chain", "star", "full-mesh"
	}{
		{"chain topology - 5 nodes", 5, "chain"},
		{"star topology - 5 nodes", 5, "star"},
		{"full mesh - 4 nodes", 4, "full-mesh"},
		{"large chain - 10 nodes", 10, "chain"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			
			// Create nodes
			nodes := make([]*blackholenet.Host, tt.numNodes)
			for i := 0; i < tt.numNodes; i++ {
				config := createTestConfig(0)
				host, err := blackholenet.NewHost(ctx, config)
				require.NoError(t, err, "Failed to create host %d", i)
				defer host.Close()
				nodes[i] = host
			}
			
			// Connect based on topology
			switch tt.topology {
			case "chain":
				connectChain(t, ctx, nodes)
			case "star":
				connectStar(t, ctx, nodes)
			case "full-mesh":
				connectFullMesh(t, ctx, nodes)
			}
			
			// Wait for connections to stabilize
			time.Sleep(500 * time.Millisecond)
			
			// Verify connectivity based on topology
			verifyTopology(t, nodes, tt.topology)
		})
	}
}

func TestNATTraversalScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping NAT traversal test in short mode")
	}
	
	ctx := context.Background()
	
	// Create relay node (publicly accessible)
	relayConfig := createTestConfig(0)
	relayConfig.Network.EnableRelay = true
	relayConfig.Network.EnableAutoRelay = false
	
	relayHost, err := blackholenet.NewHost(ctx, relayConfig)
	require.NoError(t, err)
	defer relayHost.Close()
	
	// Create node behind NAT
	natConfig := createTestConfig(0)
	natConfig.Network.EnableAutoRelay = true
	natConfig.Network.StaticRelays = []string{
		fmt.Sprintf("%s/p2p/%s", relayHost.Addrs()[0], relayHost.ID()),
	}
	
	natHost, err := blackholenet.NewHost(ctx, natConfig)
	require.NoError(t, err)
	defer natHost.Close()
	
	// Create external node
	externalConfig := createTestConfig(0)
	externalHost, err := blackholenet.NewHost(ctx, externalConfig)
	require.NoError(t, err)
	defer externalHost.Close()
	
	// Connect NAT host to relay
	relayInfo := peer.AddrInfo{
		ID:    relayHost.ID(),
		Addrs: relayHost.Addrs(),
	}
	err = natHost.Connect(ctx, relayInfo)
	require.NoError(t, err)
	
	// Wait for relay setup
	time.Sleep(1 * time.Second)
	
	// External host connects to NAT host through relay
	// Get relay addresses for NAT host
	natAddrs := natHost.Addrs()
	hasRelayAddr := false
	for _, addr := range natAddrs {
		if contains(addr.String(), "/p2p-circuit/") {
			hasRelayAddr = true
			break
		}
	}
	assert.True(t, hasRelayAddr, "NAT host should have relay addresses")
	
	// Connect external to NAT host
	natInfo := peer.AddrInfo{
		ID:    natHost.ID(),
		Addrs: natAddrs,
	}
	err = externalHost.Connect(ctx, natInfo)
	assert.NoError(t, err, "Should connect through relay")
}

func TestStreamCommunication(t *testing.T) {
	ctx := context.Background()

	// Create two hosts
	config1 := createTestConfig(0)
	host1, err := blackholenet.NewHost(ctx, config1)
	if err != nil {
		t.Fatalf("Failed to create host1: %v", err)
	}
	defer host1.Close()

	config2 := createTestConfig(0)
	host2, err := blackholenet.NewHost(ctx, config2)
	if err != nil {
		t.Fatalf("Failed to create host2: %v", err)
	}
	defer host2.Close()

	// Set up stream handler on host2
	receivedData := make(chan []byte, 1)
	host2.SetStreamHandler(testProtocol, func(s network.Stream) {
		defer s.Close()

		buf := make([]byte, 1024)
		n, err := s.Read(buf)
		if err != nil {
			t.Errorf("Failed to read from stream: %v", err)
			return
		}

		receivedData <- buf[:n]
	})

	// Connect hosts
	addr := host2.Addrs()[0].String() + "/p2p/" + host2.ID().String()
	peerInfo, err := peer.AddrInfoFromString(addr)
	if err != nil {
		t.Fatalf("Failed to parse address: %v", err)
	}

	if err := host1.Connect(ctx, *peerInfo); err != nil {
		t.Fatalf("Failed to connect hosts: %v", err)
	}

	// Open stream from host1 to host2
	stream, err := host1.NewStream(ctx, host2.ID(), testProtocol)
	if err != nil {
		t.Fatalf("Failed to create stream: %v", err)
	}
	defer stream.Close()

	// Send data
	testData := []byte("Hello, Blackhole!")
	if _, err := stream.Write(testData); err != nil {
		t.Fatalf("Failed to write to stream: %v", err)
	}

	// Verify received data
	select {
	case data := <-receivedData:
		if string(data) != string(testData) {
			t.Errorf("Expected %s, got %s", testData, data)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for data")
	}
}

func TestConnectionEstablishmentLatency(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name        string
		scenario    string // "local", "remote"
		maxLatency  time.Duration
	}{
		{"local connection", "local", 100 * time.Millisecond},
		{"remote connection", "remote", 500 * time.Millisecond},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create two hosts
			config1 := createTestConfig(0)
			host1, err := blackholenet.NewHost(ctx, config1)
			require.NoError(t, err)
			defer host1.Close()
			
			config2 := createTestConfig(0)
			if tt.scenario == "remote" {
				// Simulate remote by using different interface
				config2.Network.ListenAddresses = []string{
					"/ip4/0.0.0.0/tcp/0",
				}
			}
			
			host2, err := blackholenet.NewHost(ctx, config2)
			require.NoError(t, err)
			defer host2.Close()
			
			// Measure connection time
			start := time.Now()
			
			peerInfo := peer.AddrInfo{
				ID:    host2.ID(),
				Addrs: host2.Addrs(),
			}
			err = host1.Connect(ctx, peerInfo)
			require.NoError(t, err)
			
			latency := time.Since(start)
			assert.Less(t, latency, tt.maxLatency,
				"Connection latency %v exceeds maximum %v", latency, tt.maxLatency)
			
			t.Logf("%s latency: %v", tt.name, latency)
		})
	}
}

func TestConcurrentConnectionLimits(t *testing.T) {
	ctx := context.Background()
	
	// Create host that should handle 1000+ connections
	config := createTestConfig(0)
	config.Network.ConnectionManager = &blackholenet.ConnectionManagerConf{
		HighWater:   1100,
		LowWater:    1000,
		GracePeriod: 30 * time.Second,
	}
	
	host, err := blackholenet.NewHost(ctx, config)
	require.NoError(t, err)
	defer host.Close()
	
	// Create many peers concurrently
	numPeers := 100 // Reduced for test speed, but validates concurrent handling
	var wg sync.WaitGroup
	var connectedCount atomic.Int32
	
	for i := 0; i < numPeers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			
			peerConfig := createTestConfig(0)
			peerHost, err := blackholenet.NewHost(ctx, peerConfig)
			if err != nil {
				t.Logf("Failed to create peer %d: %v", idx, err)
				return
			}
			defer peerHost.Close()
			
			peerInfo := peer.AddrInfo{
				ID:    host.ID(),
				Addrs: host.Addrs(),
			}
			
			if err := peerHost.Connect(ctx, peerInfo); err == nil {
				connectedCount.Add(1)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify we can handle many concurrent connections
	connected := connectedCount.Load()
	assert.GreaterOrEqual(t, connected, int32(50),
		"Should handle at least 50 concurrent connections, got %d", connected)
	
	t.Logf("Successfully established %d concurrent connections", connected)
}

func TestBandwidthAndThroughput(t *testing.T) {
	ctx := context.Background()
	
	// Create two hosts
	config1 := createTestConfig(0)
	host1, err := blackholenet.NewHost(ctx, config1)
	require.NoError(t, err)
	defer host1.Close()
	
	config2 := createTestConfig(0)
	host2, err := blackholenet.NewHost(ctx, config2)
	require.NoError(t, err)
	defer host2.Close()
	
	// Set up stream handler
	protocolID := protocol.ID("/blackhole/throughput-test/1.0.0")
	receivedBytes := atomic.Int64{}
	
	host2.SetStreamHandler(protocolID, func(s network.Stream) {
		defer s.Close()
		
		buf := make([]byte, 4096)
		for {
			n, err := s.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			receivedBytes.Add(int64(n))
		}
	})
	
	// Connect hosts
	peerInfo := peer.AddrInfo{
		ID:    host2.ID(),
		Addrs: host2.Addrs(),
	}
	err = host1.Connect(ctx, peerInfo)
	require.NoError(t, err)
	
	// Open stream and send data
	stream, err := host1.NewStream(ctx, host2.ID(), protocolID)
	require.NoError(t, err)
	defer stream.Close()
	
	// Send 10MB of data
	dataSize := 10 * 1024 * 1024
	chunk := make([]byte, 64*1024) // 64KB chunks
	for i := 0; i < len(chunk); i++ {
		chunk[i] = byte(i % 256)
	}
	
	start := time.Now()
	bytesSent := 0
	
	for bytesSent < dataSize {
		n, err := stream.Write(chunk)
		if err != nil {
			t.Fatalf("Failed to write: %v", err)
		}
		bytesSent += n
	}
	stream.Close()
	
	// Wait for all data to be received
	time.Sleep(500 * time.Millisecond)
	
	duration := time.Since(start)
	throughput := float64(bytesSent) / duration.Seconds() / 1024 / 1024 // MB/s
	
	t.Logf("Sent %d bytes in %v, throughput: %.2f MB/s", bytesSent, duration, throughput)
	
	// Verify all data was received
	assert.Equal(t, int64(bytesSent), receivedBytes.Load(),
		"Should receive all sent data")
	
	// Verify reasonable throughput (at least 10 MB/s for local connection)
	assert.Greater(t, throughput, 10.0,
		"Throughput should be at least 10 MB/s for local connection")
}

func TestReconnectionLogic(t *testing.T) {
	ctx := context.Background()
	
	// Create two hosts
	config1 := createTestConfig(0)
	host1, err := blackholenet.NewHost(ctx, config1)
	require.NoError(t, err)
	defer host1.Close()
	
	config2 := createTestConfig(0)
	host2, err := blackholenet.NewHost(ctx, config2)
	require.NoError(t, err)
	
	// Connect hosts
	peerInfo := peer.AddrInfo{
		ID:    host2.ID(),
		Addrs: host2.Addrs(),
	}
	err = host1.Connect(ctx, peerInfo)
	require.NoError(t, err)
	
	// Verify connection
	assert.Contains(t, host1.Network().Peers(), host2.ID())
	
	// Close host2 to simulate disconnection
	host2.Close()
	time.Sleep(100 * time.Millisecond)
	
	// Verify disconnection
	assert.NotContains(t, host1.Network().Peers(), host2.ID())
	
	// Create new host with same ID (simulating restart)
	config2New := createTestConfig(0)
	config2New.Identity.PrivateKeyPath = config2.Identity.PrivateKeyPath
	host2New, err := blackholenet.NewHost(ctx, config2New)
	require.NoError(t, err)
	defer host2New.Close()
	
	// Should have same peer ID
	assert.Equal(t, host2.ID(), host2New.ID())
	
	// Reconnect
	peerInfo2 := peer.AddrInfo{
		ID:    host2New.ID(),
		Addrs: host2New.Addrs(),
	}
	err = host1.Connect(ctx, peerInfo2)
	require.NoError(t, err)
	
	// Verify reconnection
	assert.Contains(t, host1.Network().Peers(), host2New.ID())
}

// Helper functions

func connectChain(t *testing.T, ctx context.Context, nodes []*blackholenet.Host) {
	for i := 0; i < len(nodes)-1; i++ {
		peerInfo := peer.AddrInfo{
			ID:    nodes[i+1].ID(),
			Addrs: nodes[i+1].Addrs(),
		}
		err := nodes[i].Connect(ctx, peerInfo)
		require.NoError(t, err, "Failed to connect node %d to %d", i, i+1)
	}
}

func connectStar(t *testing.T, ctx context.Context, nodes []*blackholenet.Host) {
	// First node is the center
	for i := 1; i < len(nodes); i++ {
		peerInfo := peer.AddrInfo{
			ID:    nodes[0].ID(),
			Addrs: nodes[0].Addrs(),
		}
		err := nodes[i].Connect(ctx, peerInfo)
		require.NoError(t, err, "Failed to connect node %d to center", i)
	}
}

func connectFullMesh(t *testing.T, ctx context.Context, nodes []*blackholenet.Host) {
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			peerInfo := peer.AddrInfo{
				ID:    nodes[j].ID(),
				Addrs: nodes[j].Addrs(),
			}
			err := nodes[i].Connect(ctx, peerInfo)
			require.NoError(t, err, "Failed to connect node %d to %d", i, j)
		}
	}
}

func verifyTopology(t *testing.T, nodes []*blackholenet.Host, topology string) {
	switch topology {
	case "chain":
		for i, node := range nodes {
			peers := node.Network().Peers()
			expectedPeers := 1
			if i > 0 && i < len(nodes)-1 {
				expectedPeers = 2
			}
			assert.Equal(t, expectedPeers, len(peers),
				"Node %d should have %d peers", i, expectedPeers)
		}
	case "star":
		// Center node should have n-1 peers
		centerPeers := nodes[0].Network().Peers()
		assert.Equal(t, len(nodes)-1, len(centerPeers),
			"Center node should have %d peers", len(nodes)-1)
		
		// Other nodes should have 1 peer (center)
		for i := 1; i < len(nodes); i++ {
			peers := nodes[i].Network().Peers()
			assert.Equal(t, 1, len(peers),
				"Node %d should have 1 peer", i)
		}
	case "full-mesh":
		// Each node should have n-1 peers
		for i, node := range nodes {
			peers := node.Network().Peers()
			assert.Equal(t, len(nodes)-1, len(peers),
				"Node %d should have %d peers", i, len(nodes)-1)
		}
	}
}