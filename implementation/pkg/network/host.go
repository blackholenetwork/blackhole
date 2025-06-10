package network

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	discrouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Host wraps a libp2p host with additional functionality
type Host struct {
	host.Host
	config      *Config
	metrics     *Metrics
	connManager *ConnectionManager
	dht         *dht.IpfsDHT
	mdns        mdns.Service
	discovery   discovery.Discovery
	logger      *zap.Logger
	
	// Lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	started    bool
	stopped    bool
	startMu    sync.Mutex
	
	// Performance tracking
	startTime  time.Time
	connEvents chan network.Conn
}

// NewHost creates a new libp2p host with the given configuration
func NewHost(ctx context.Context, config *Config) (*Host, error) {
	// Initialize metrics
	var metrics *Metrics
	var err error
	
	if config.Metrics.Enabled {
		metrics, err = NewMetrics()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize metrics: %w", err)
		}
	} else {
		// Use no-op metrics when disabled
		metrics = NewNoopMetrics()
	}

	// Load or generate identity
	identity, err := LoadOrCreateIdentity(config.Identity.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load identity: %w", err)
	}

	// Convert string addresses to multiaddrs
	listenAddrs := make([]multiaddr.Multiaddr, 0, len(config.Network.ListenAddresses))
	for _, addr := range config.Network.ListenAddresses {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid listen address %s: %w", addr, err)
		}
		listenAddrs = append(listenAddrs, maddr)
	}

	// Build libp2p options
	opts := []libp2p.Option{
		libp2p.Identity(identity),
		libp2p.ListenAddrs(listenAddrs...),
	}

	// Add transport options
	transportOpts, err := buildTransportOptions(config.Network.Transports)
	if err != nil {
		return nil, fmt.Errorf("failed to build transport options: %w", err)
	}
	opts = append(opts, transportOpts...)

	// Add security options
	securityOpts := buildSecurityOptions(config.Network.Security)
	opts = append(opts, securityOpts...)

	// Add connection manager
	var connManager *ConnectionManager
	if config.Network.ConnectionManager != nil {
		connManager = NewConnectionManager(
			config.Network.ConnectionManager.LowWater,
			config.Network.ConnectionManager.HighWater,
			config.Network.ConnectionManager.GracePeriod,
		)
		opts = append(opts, libp2p.ConnectionManager(connManager))
	}

	// Create the libp2p host
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create logger
	logger, err := createLogger(config.Logging)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	host := &Host{
		Host:       h,
		config:     config,
		metrics:    metrics,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		startTime:  time.Now(),
		connEvents: make(chan network.Conn, 100),
	}

	// Set up connection manager if it was created
	if connManager != nil {
		host.connManager = connManager
		connManager.SetMetrics(metrics)
		connManager.SetLogger(logger)
	}

	// Initialize DHT if enabled
	if config.Discovery.DHT != nil && config.Discovery.DHT.Enabled {
		if err := host.initializeDHT(ctx); err != nil {
			h.Close()
			return nil, fmt.Errorf("failed to initialize DHT: %w", err)
		}
	}

	return host, nil
}

// Bootstrap connects to the configured bootstrap peers
func (h *Host) Bootstrap(ctx context.Context) error {
	if len(h.config.Network.BootstrapPeers) == 0 {
		return nil
	}

	for _, peerAddr := range h.config.Network.BootstrapPeers {
		peerinfo, err := peer.AddrInfoFromString(peerAddr)
		if err != nil {
			return fmt.Errorf("invalid bootstrap peer address %s: %w", peerAddr, err)
		}

		if err := h.Connect(ctx, *peerinfo); err != nil {
			return fmt.Errorf("failed to connect to bootstrap peer %s: %w", peerAddr, err)
		}
	}

	return nil
}

// Shutdown gracefully shuts down the host
func (h *Host) Shutdown(ctx context.Context) error {
	return h.Close()
}

// Start initializes the host and begins all background services
func (h *Host) Start() error {
	h.startMu.Lock()
	defer h.startMu.Unlock()

	if h.started {
		return fmt.Errorf("host already started")
	}

	if h.stopped {
		return fmt.Errorf("host has been stopped and cannot be restarted")
	}

	h.logger.Info("Starting Blackhole host",
		zap.String("peer_id", h.ID().String()),
		zap.Strings("addresses", h.listenAddresses()),
	)

	// Set up network notifiee for connection events
	h.Network().Notify(h.connManager.Notifee())

	// Start metrics collection
	if h.config.Metrics.Enabled {
		go h.runMetricsCollection()
	}

	// Start connection event handler
	go h.handleConnectionEvents()

	// Initialize mDNS discovery if enabled
	if h.config.Discovery.MDNS != nil && h.config.Discovery.MDNS.Enabled {
		if err := h.initializeMDNS(); err != nil {
			h.logger.Error("Failed to initialize mDNS", zap.Error(err))
		}
	}

	// Start DHT if it was initialized
	if h.dht != nil {
		if err := h.dht.Bootstrap(h.ctx); err != nil {
			h.logger.Error("Failed to bootstrap DHT", zap.Error(err))
		}
	}

	// Connect to bootstrap peers
	if err := h.Bootstrap(h.ctx); err != nil {
		h.logger.Error("Failed to connect to bootstrap peers", zap.Error(err))
	}

	// Start periodic connection health checks
	go h.runConnectionHealthChecks()

	h.started = true
	h.logger.Info("Blackhole host started successfully")

	return nil
}

// Stop gracefully shuts down the host
func (h *Host) Stop() error {
	h.startMu.Lock()
	defer h.startMu.Unlock()

	if !h.started {
		return fmt.Errorf("host not started")
	}

	if h.stopped {
		return fmt.Errorf("host already stopped")
	}

	h.logger.Info("Stopping Blackhole host")

	// Cancel context to stop all background goroutines
	h.cancel()

	// Stop mDNS if running
	if h.mdns != nil {
		if err := h.mdns.Close(); err != nil {
			h.logger.Error("Error closing mDNS", zap.Error(err))
		}
	}

	// Close DHT if running
	if h.dht != nil {
		if err := h.dht.Close(); err != nil {
			h.logger.Error("Error closing DHT", zap.Error(err))
		}
	}

	// Close the host
	if err := h.Host.Close(); err != nil {
		h.logger.Error("Error closing host", zap.Error(err))
		return err
	}

	h.stopped = true
	h.logger.Info("Blackhole host stopped successfully")

	return nil
}

// initializeDHT sets up the Kademlia DHT
func (h *Host) initializeDHT(ctx context.Context) error {
	var mode dht.ModeOpt
	switch h.config.Discovery.DHT.Mode {
	case "client":
		mode = dht.ModeClient
	case "server":
		mode = dht.ModeServer
	default:
		mode = dht.ModeAuto
	}

	// Convert bootstrap peers to AddrInfo
	var bootstrapPeers []peer.AddrInfo
	for _, addr := range h.config.Network.BootstrapPeers {
		pi, err := peer.AddrInfoFromString(addr)
		if err != nil {
			h.logger.Warn("Invalid bootstrap peer address", zap.String("addr", addr), zap.Error(err))
			continue
		}
		bootstrapPeers = append(bootstrapPeers, *pi)
	}

	kadDHT, err := dht.New(ctx, h.Host,
		dht.Mode(mode),
		dht.BootstrapPeers(bootstrapPeers...),
	)
	if err != nil {
		return err
	}

	h.dht = kadDHT
	h.discovery = discrouting.NewRoutingDiscovery(kadDHT)
	return nil
}

// initializeMDNS sets up mDNS discovery
func (h *Host) initializeMDNS() error {
	mdnsService := mdns.NewMdnsService(h.Host, "blackhole", &mdnsNotifee{host: h})
	if err := mdnsService.Start(); err != nil {
		return err
	}
	h.mdns = mdnsService
	return nil
}

// mdnsNotifee handles mDNS peer discovery events
type mdnsNotifee struct {
	host *Host
}

func (n *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	n.host.logger.Debug("Discovered peer via mDNS", zap.String("peer_id", pi.ID.String()))
	n.host.metrics.DiscoveredPeers.Inc()
	
	ctx, cancel := context.WithTimeout(n.host.ctx, 10*time.Second)
	defer cancel()
	
	if err := n.host.Connect(ctx, pi); err != nil {
		n.host.logger.Debug("Failed to connect to discovered peer",
			zap.String("peer_id", pi.ID.String()),
			zap.Error(err),
		)
		n.host.metrics.RecordConnectionFailed()
	}
}

// runMetricsCollection periodically collects host metrics
func (h *Host) runMetricsCollection() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.collectMetrics()
		}
	}
}

// collectMetrics gathers current host metrics
func (h *Host) collectMetrics() {
	// Update connected peers gauge
	peers := h.Network().Peers()
	h.metrics.ConnectedPeers.Set(float64(len(peers)))
	
	// Update active connections
	conns := h.Network().Conns()
	h.metrics.ActiveConnections.Set(float64(len(conns)))
	
	// Collect bandwidth stats per connection
	for _, conn := range conns {
		stats := conn.Stat()
		h.metrics.RecordBytesTransferred(
			uint64(stats.Extra["bytesSent"].(int64)),
			uint64(stats.Extra["bytesRecvd"].(int64)),
		)
	}
}

// handleConnectionEvents processes connection lifecycle events
func (h *Host) handleConnectionEvents() {
	for {
		select {
		case <-h.ctx.Done():
			return
		case conn := <-h.connEvents:
			// Log connection latency for performance monitoring
			stats := conn.Stat()
			if !stats.Opened.IsZero() {
				latency := time.Since(stats.Opened)
				h.logger.Debug("Connection established",
					zap.String("peer_id", conn.RemotePeer().String()),
					zap.Duration("latency", latency),
					zap.String("direction", stats.Direction.String()),
				)
				
				// Check against performance targets
				if latency > 500*time.Millisecond {
					h.logger.Warn("Connection latency exceeds target",
						zap.String("peer_id", conn.RemotePeer().String()),
						zap.Duration("latency", latency),
					)
				}
			}
		}
	}
}

// runConnectionHealthChecks periodically checks connection health
func (h *Host) runConnectionHealthChecks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.checkConnectionHealth()
		}
	}
}

// checkConnectionHealth verifies all connections are healthy
func (h *Host) checkConnectionHealth() {
	conns := h.Network().Conns()
	for _, conn := range conns {
		// Check if connection is still alive by querying stats
		stats := conn.Stat()
		if stats.Direction == network.DirOutbound {
			// For outbound connections, check if we can still reach the peer
			ctx, cancel := context.WithTimeout(h.ctx, 5*time.Second)
			if err := h.Host.Connect(ctx, peer.AddrInfo{ID: conn.RemotePeer()}); err != nil {
				h.logger.Debug("Unhealthy connection detected",
					zap.String("peer_id", conn.RemotePeer().String()),
					zap.Error(err),
				)
			}
			cancel()
		}
	}
	
	// Trigger connection manager trimming if needed
	if h.connManager != nil && len(conns) > h.config.Network.ConnectionManager.HighWater {
		h.connManager.TrimConnections(h.ctx)
	}
}

// listenAddresses returns the addresses the host is listening on
func (h *Host) listenAddresses() []string {
	addrs := h.Addrs()
	strAddrs := make([]string, len(addrs))
	for i, addr := range addrs {
		strAddrs[i] = addr.String()
	}
	return strAddrs
}

// DiscoverPeers uses the configured discovery mechanisms to find peers
func (h *Host) DiscoverPeers(ctx context.Context, namespace string) (<-chan peer.AddrInfo, error) {
	if h.discovery == nil {
		return nil, fmt.Errorf("discovery not initialized")
	}
	
	return h.discovery.FindPeers(ctx, namespace)
}

// GetDHT returns the DHT instance if available
func (h *Host) GetDHT() routing.Routing {
	if h.dht == nil {
		return nil
	}
	return h.dht
}

// GetMetrics returns the host metrics
func (h *Host) GetMetrics() *Metrics {
	return h.metrics
}

// GetConnectionManager returns the connection manager
func (h *Host) GetConnectionManager() *ConnectionManager {
	return h.connManager
}

// createLogger creates a zap logger based on configuration
func createLogger(config LoggingConfig) (*zap.Logger, error) {
	var cfg zap.Config
	
	switch config.Level {
	case "debug":
		cfg = zap.NewDevelopmentConfig()
	default:
		cfg = zap.NewProductionConfig()
	}
	
	cfg.Level = zap.NewAtomicLevelAt(parseLogLevel(config.Level))
	cfg.OutputPaths = []string{config.Output}
	
	if config.Format == "console" {
		cfg.Encoding = "console"
	}
	
	return cfg.Build()
}

// parseLogLevel converts string log level to zap level
func parseLogLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}