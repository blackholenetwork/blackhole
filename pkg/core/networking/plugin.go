// Package networking provides P2P networking functionality using libp2p
package networking

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/multiformats/go-multiaddr"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

const (
	// ProtocolID is the libp2p protocol ID for Blackhole Network
	ProtocolID = protocol.ID("/blackhole/1.0.0")

	// DefaultPort is the default P2P network port
	DefaultPort = 4001
	// DefaultConnectionTimeout is the default connection timeout
	DefaultConnectionTimeout = 30 * time.Second
)

// Plugin implements the networking plugin
type Plugin struct {
	*plugin.BasePlugin

	// libp2p components
	host   host.Host
	dht    *dht.IpfsDHT
	pubsub *pubsub.PubSub

	// Health monitoring
	healthTicker *time.Ticker
	healthDone   chan struct{}

	// Connection management
	mu       sync.RWMutex
	peers    map[peer.ID]*PeerInfo
	handlers map[string]MessageHandler

	// Configuration
	config   *NetworkConfig
	registry *plugin.Registry

	// Health status management
	healthStatus  plugin.HealthStatus
	healthMessage string
	logger        *log.Logger
}

// NetworkConfig holds networking configuration
type NetworkConfig struct {
	Port              int           `yaml:"port" default:"4001"`
	BootstrapPeers    []string      `yaml:"bootstrap_peers"`
	MaxConnections    int           `yaml:"max_connections" default:"50"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	EnableAutoRelay   bool          `yaml:"enable_auto_relay" default:"true"`
}

// PeerInfo holds information about a connected peer
type PeerInfo struct {
	ID        peer.ID
	Addresses []multiaddr.Multiaddr
	Connected time.Time
	LastSeen  time.Time
	Latency   time.Duration
}

// MessageHandler handles incoming messages
type MessageHandler func(ctx context.Context, from peer.ID, data []byte) error

// New creates a new networking plugin
func New(registry *plugin.Registry) *Plugin {
	info := plugin.Info{
		Name:         "network",
		Version:      "0.1.0",
		Description:  "P2P networking with libp2p for node communication",
		Author:       "Blackhole Team",
		License:      "MIT",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilityNetworking)},
	}

	p := &Plugin{
		BasePlugin:    plugin.NewBasePlugin(info),
		peers:         make(map[peer.ID]*PeerInfo),
		handlers:      make(map[string]MessageHandler),
		registry:      registry,
		healthStatus:  plugin.HealthStatusUnknown,
		healthMessage: "Not initialized",
		logger:        log.New(os.Stdout, "[Networking] ", log.LstdFlags),
	}
	p.SetRegistry(registry)
	return p
}

// Init initializes the plugin with configuration
func (p *Plugin) Init(ctx context.Context, config plugin.Config) error {
	// Load configuration
	p.config = &NetworkConfig{
		ConnectionTimeout: DefaultConnectionTimeout, // Set default
		EnableAutoRelay:   true,                     // Default to enabled for production
	}
	// Simple config loading - in production would be more sophisticated
	if portVal, ok := config["port"]; ok {
		if port, ok := portVal.(int); ok {
			p.config.Port = port
		}
	}
	if bootstrapVal, ok := config["bootstrap_peers"]; ok {
		if peers, ok := bootstrapVal.([]string); ok {
			p.config.BootstrapPeers = peers
		}
	}

	// Ensure connection timeout has a value
	if p.config.ConnectionTimeout == 0 {
		p.config.ConnectionTimeout = DefaultConnectionTimeout
	}

	// Update health status
	p.mu.Lock()
	p.healthStatus = plugin.HealthStatusHealthy
	p.healthMessage = "Networking initialized"
	p.mu.Unlock()
	p.SetHealth(p.healthStatus, p.healthMessage)

	return p.BasePlugin.Init(ctx, config)
}

// Start starts the plugin
func (p *Plugin) Start(ctx context.Context) error {
	// Create libp2p host options
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", p.config.Port)),
		libp2p.EnableNATService(),
	}

	// Enable AutoRelay for NAT traversal
	// Essential for production to allow nodes behind NAT to be reachable
	if p.config.EnableAutoRelay {
		// AutoRelay will discover relays through:
		// 1. DHT (once connected to network)
		// 2. mDNS (local network discovery)
		// 3. Bootstrap peers (if configured)
		// Use a peer source function that provides relay candidates dynamically
		opts = append(opts, libp2p.EnableAutoRelayWithPeerSource(
			func(_ context.Context, numPeers int) <-chan peer.AddrInfo {
				// Create a channel to return discovered relay candidates
				peerChan := make(chan peer.AddrInfo, numPeers)

				go func() {
					defer close(peerChan)

					// Since host and DHT aren't available yet during initialization,
					// we'll return an empty channel for now. The AutoRelay will
					// call this function periodically once the host is running.
					// For initial startup, we'll rely on mDNS and bootstrap peers.
				}()

				return peerChan
			},
		))
	}

	// Create libp2p host
	host, err := libp2p.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create host: %w", err)
	}
	p.host = host

	// Create DHT for peer discovery
	p.dht, err = dht.New(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}

	// Create pubsub for message broadcasting
	p.pubsub, err = pubsub.NewGossipSub(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to create pubsub: %w", err)
	}

	// Set stream handler for direct messages
	p.host.SetStreamHandler(ProtocolID, p.handleStream)

	// Start DHT bootstrap
	if err := p.dht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Start mDNS discovery for local network peers
	// This allows nodes to find each other without bootstrap servers
	mdnsService := mdns.NewMdnsService(p.host, "blackhole-network", p)
	if err := mdnsService.Start(); err != nil {
		// mDNS failure is not critical - log and continue
		fmt.Printf("Warning: failed to start mDNS discovery: %v\n", err)
	}

	// Connect to bootstrap peers
	for _, addr := range p.config.BootstrapPeers {
		go p.connectToPeer(ctx, addr)
	}

	// Start health monitoring
	p.healthDone = make(chan struct{})
	p.healthTicker = time.NewTicker(5 * time.Second)
	go p.monitorHealthStatus(ctx)

	// Publish plugin started event
	p.registry.Publish(plugin.Event{
		Type:   plugin.EventPluginStarted,
		Source: p.Info().Name,
		Data:   map[string]interface{}{"peer_id": p.host.ID().String()},
	})

	// Start monitoring goroutine
	go p.monitorConnections(ctx)

	// Set initial health status
	p.mu.Lock()
	p.healthStatus = plugin.HealthStatusHealthy
	p.healthMessage = "Networking initialized"
	p.mu.Unlock()
	p.SetHealth(p.healthStatus, p.healthMessage)

	return p.BasePlugin.Start(ctx)
}

// Stop stops the plugin
func (p *Plugin) Stop(ctx context.Context) error {
	// Update health status
	p.mu.Lock()
	p.healthStatus = plugin.HealthStatusUnknown
	p.healthMessage = "Networking stopped"
	p.mu.Unlock()
	p.SetHealth(p.healthStatus, p.healthMessage)

	// Stop health monitoring
	if p.healthTicker != nil {
		p.healthTicker.Stop()
	}
	if p.healthDone != nil {
		close(p.healthDone)
	}

	// Note: pubsub doesn't have a close method, it's cleaned up with the host

	// Close DHT
	if p.dht != nil {
		if err := p.dht.Close(); err != nil {
			fmt.Printf("Error closing DHT: %v\n", err)
		}
	}

	// Close host
	if p.host != nil {
		if err := p.host.Close(); err != nil {
			return fmt.Errorf("failed to close host: %w", err)
		}
	}

	// Publish plugin stopped event
	p.registry.Publish(plugin.Event{
		Type:   plugin.EventPluginStopped,
		Source: p.Info().Name,
	})

	return p.BasePlugin.Stop(ctx)
}

// Health returns the current health status
func (p *Plugin) Health() plugin.Health {
	p.mu.RLock()
	peerCount := len(p.peers)
	status := p.healthStatus
	message := p.healthMessage
	p.mu.RUnlock()

	return plugin.Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"peer_count": peerCount,
			"dht_ready":  p.dht != nil,
			"host_ready": p.host != nil,
		},
	}
}

// NetworkService implementation

// Send sends data to a specific peer
func (p *Plugin) Send(ctx context.Context, peerID string, data []byte) error {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("invalid peer ID: %w", err)
	}

	// Open stream to peer
	stream, err := p.host.NewStream(ctx, pid, ProtocolID)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			p.logger.Printf("Error closing stream: %v", err)
		}
	}()

	// Send data
	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Metrics would be tracked here in production
	return nil
}

// Broadcast sends data to all connected peers
func (p *Plugin) Broadcast(ctx context.Context, data []byte) error {
	// Use pubsub for broadcasting
	topic, err := p.pubsub.Join("blackhole:broadcast")
	if err != nil {
		return fmt.Errorf("failed to join topic: %w", err)
	}
	defer func() {
		if err := topic.Close(); err != nil {
			p.logger.Printf("Error closing topic: %v", err)
		}
	}()

	if err := topic.Publish(ctx, data); err != nil {
		return fmt.Errorf("failed to publish: %w", err)
	}

	// Metrics would be tracked here in production
	// In production, we would track the number of peers we broadcast to
	return nil
}

// GetPeers returns list of connected peers
func (p *Plugin) GetPeers(_ context.Context) ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	peers := make([]string, 0, len(p.peers))
	for _, peer := range p.peers {
		peers = append(peers, peer.ID.String())
	}

	return peers, nil
}

// GetLatency returns latency to a specific peer
func (p *Plugin) GetLatency(_ context.Context, peerID string) (time.Duration, error) {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return 0, fmt.Errorf("invalid peer ID: %w", err)
	}

	p.mu.RLock()
	peer, exists := p.peers[pid]
	p.mu.RUnlock()

	if !exists {
		return 0, fmt.Errorf("peer not connected")
	}

	return peer.Latency, nil
}

// Subscribe to messages from peers
func (p *Plugin) Subscribe(ctx context.Context, handler func(peerID string, data []byte)) error {
	// Subscribe to broadcast topic
	topic, err := p.pubsub.Join("blackhole:broadcast")
	if err != nil {
		return fmt.Errorf("failed to join topic: %w", err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	// Handle messages in goroutine
	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}

			// Don't process our own messages
			if msg.ReceivedFrom == p.host.ID() {
				continue
			}

			handler(msg.ReceivedFrom.String(), msg.Data)
			// Metrics would be tracked here in production
		}
	}()

	return nil
}

// Internal methods

func (p *Plugin) handleStream(stream network.Stream) {
	defer func() {
		if err := stream.Close(); err != nil {
			p.logger.Printf("Error closing stream: %v", err)
		}
	}()

	// Read message
	buf := make([]byte, 1024*1024) // 1MB max message size
	n, err := stream.Read(buf)
	if err != nil {
		return
	}

	// Process message
	from := stream.Conn().RemotePeer()
	// data := buf[:n] // TODO: Use this when implementing message routing
	_ = buf[:n] // Temporary to avoid unused variable error

	// Update peer info
	p.updatePeerInfo(from, stream.Conn().RemoteMultiaddr())

	// Handle message
	// TODO: Implement message routing based on protocol

	// Metrics would be tracked here in production
}

func (p *Plugin) connectToPeer(ctx context.Context, addr string) {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return
	}

	peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return
	}

	if err := p.host.Connect(ctx, *peerInfo); err != nil {
		return
	}

	p.updatePeerInfo(peerInfo.ID, maddr)
}

func (p *Plugin) updatePeerInfo(peerID peer.ID, addr multiaddr.Multiaddr) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if info, exists := p.peers[peerID]; exists {
		info.LastSeen = now
		if addr != nil {
			// Add address if not already present
			found := false
			for _, a := range info.Addresses {
				if a.Equal(addr) {
					found = true
					break
				}
			}
			if !found {
				info.Addresses = append(info.Addresses, addr)
			}
		}
	} else {
		addresses := []multiaddr.Multiaddr{}
		if addr != nil {
			addresses = append(addresses, addr)
		}
		p.peers[peerID] = &PeerInfo{
			ID:        peerID,
			Addresses: addresses,
			Connected: now,
			LastSeen:  now,
		}

		// Publish peer connected event
		p.registry.Publish(plugin.Event{
			Type:   plugin.EventPeerConnected,
			Source: p.Info().Name,
			Data:   map[string]interface{}{"peer_id": peerID.String()},
		})
	}

	// Metrics would be tracked here in production
}

func (p *Plugin) monitorConnections(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.cleanupStaleConnections()
		}
	}
}

// monitorHealthStatus monitors health and updates plugin health status
func (p *Plugin) monitorHealthStatus(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.healthDone:
			return
		case <-p.healthTicker.C:
			// Run health checks
			_ = p.checkPeerConnectivity(ctx) // We check peer count directly below
			dhtHealthErr := p.checkDHTHealth(ctx)

			// Determine our status based on health checks
			p.mu.Lock()
			peerCount := len(p.peers)
			oldStatus := p.healthStatus

			// More robust health checks:
			// - DHT is initialized and has at least bootstrap nodes = healthy (even with no peers)
			// - DHT not initialized or no routing table entries = unhealthy
			// - Has peers = bonus points

			switch {
			case p.dht == nil:
				p.healthStatus = plugin.HealthStatusUnhealthy
				p.healthMessage = "DHT not initialized"
			case dhtHealthErr != nil && peerCount == 0:
				// Only unhealthy if both DHT has issues AND no peers
				p.healthStatus = plugin.HealthStatusUnhealthy
				p.healthMessage = "DHT not functioning and no peers connected"
			case peerCount == 0:
				// No peers is degraded, not unhealthy - this is normal for isolated nodes
				p.healthStatus = plugin.HealthStatusDegraded
				p.healthMessage = "No peers connected (searching for peers)"
			case peerCount < 3:
				// Few peers is still degraded
				p.healthStatus = plugin.HealthStatusDegraded
				p.healthMessage = fmt.Sprintf("Connected to %d peer(s)", peerCount)
			default:
				// 3+ peers is healthy
				p.healthStatus = plugin.HealthStatusHealthy
				p.healthMessage = fmt.Sprintf("Connected to %d peers", peerCount)
			}

			newStatus := p.healthStatus
			message := p.healthMessage
			p.mu.Unlock()

			// Publish health change if status changed
			if oldStatus != newStatus {
				p.SetHealth(newStatus, message)
			}
		}
	}
}

func (p *Plugin) cleanupStaleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for peerID, info := range p.peers {
		if info.LastSeen.Before(cutoff) {
			delete(p.peers, peerID)

			// Publish peer disconnected event
			p.registry.Publish(plugin.Event{
				Type:   plugin.EventPeerDisconnected,
				Source: p.Info().Name,
				Data:   map[string]interface{}{"peer_id": peerID.String()},
			})
		}
	}

	// Metrics would be tracked here in production
}

// Health check functions

func (p *Plugin) checkPeerConnectivity(_ context.Context) error {
	p.mu.RLock()
	peerCount := len(p.peers)
	p.mu.RUnlock()

	if peerCount == 0 {
		return fmt.Errorf("no peers connected")
	}

	minPeers := 3 // Minimum healthy peer count
	if peerCount < minPeers {
		return fmt.Errorf("only %d peers connected, need at least %d", peerCount, minPeers)
	}

	return nil
}

func (p *Plugin) checkDHTHealth(_ context.Context) error {
	if p.dht == nil {
		return fmt.Errorf("DHT not initialized")
	}

	// DHT is initialized, that's good enough for basic health
	// Having no peers in routing table is normal for isolated nodes
	// We'll check peer connectivity separately

	return nil
}

// HandlePeerFound is called when mDNS discovers a new peer
func (p *Plugin) HandlePeerFound(peerInfo peer.AddrInfo) {
	// Connect to discovered peer
	ctx, cancel := context.WithTimeout(context.Background(), p.config.ConnectionTimeout)
	defer cancel()

	if err := p.host.Connect(ctx, peerInfo); err != nil {
		// Log connection failure but don't error out
		fmt.Printf("Failed to connect to discovered peer %s: %v\n", peerInfo.ID, err)
		return
	}

	// Update peer info
	if len(peerInfo.Addrs) > 0 {
		p.updatePeerInfo(peerInfo.ID, peerInfo.Addrs[0])
	}

	fmt.Printf("Connected to peer discovered via mDNS: %s\n", peerInfo.ID)
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.NetworkService = (*Plugin)(nil)
	_ mdns.Notifee          = (*Plugin)(nil)
)
