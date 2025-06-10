# Unit U01: libp2p Core Setup - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U01 establishes the foundational libp2p networking layer for the Blackhole platform. This unit implements a robust, multi-transport P2P host capable of establishing secure connections across various network configurations, including NAT-restricted environments.

**Primary Goals:**
- Initialize a libp2p host with multiple transport protocols
- Configure security protocols for encrypted communications
- Implement connection management and lifecycle
- Establish metrics collection and monitoring
- Provide a stable foundation for all P2P services

### Dependencies

**None** - This is a foundational unit with no dependencies on other implementation units.

### Deliverables

1. **libp2p Host Implementation**
   - Multi-transport host initialization
   - Peer identity management
   - Connection lifecycle management

2. **Transport Layer**
   - TCP transport with port reuse
   - QUIC transport for improved performance
   - WebSocket transport for browser compatibility
   - WebRTC transport for NAT traversal

3. **Security Layer**
   - TLS 1.3 security transport
   - Noise protocol implementation
   - Peer authentication mechanisms

4. **Configuration System**
   - YAML-based configuration
   - Environment variable overrides
   - Sensible defaults for production use

### Integration Points

This unit provides the foundation for:
- U02: Kademlia DHT Implementation (peer discovery)
- U03: NAT Traversal & Connectivity (connection establishment)
- U05: GossipSub Messaging (pub/sub communications)
- U07: Network Security Layer (enhanced security)
- All other P2P-dependent services

## 2. Technical Specifications

### libp2p Version and Modules

```go
// go.mod dependencies
require (
    github.com/libp2p/go-libp2p v0.33.0
    github.com/libp2p/go-libp2p-core v0.20.1
    github.com/libp2p/go-libp2p-quic-transport v0.20.0
    github.com/libp2p/go-libp2p-tls v0.5.0
    github.com/libp2p/go-libp2p-noise v0.5.0
    github.com/libp2p/go-libp2p-mplex v0.8.0
    github.com/libp2p/go-libp2p-yamux v0.10.0
    github.com/libp2p/go-ws-transport v0.7.0
    github.com/libp2p/go-libp2p-webrtc-direct v0.2.0
    github.com/multiformats/go-multiaddr v0.12.0
    github.com/prometheus/client_golang v1.17.0
    github.com/ipfs/go-log/v2 v2.5.1
    github.com/spf13/viper v1.17.0
)
```

### Transport Protocols

#### TCP Transport
- Standard TCP/IP connections
- Port reuse for efficient resource utilization
- Support for IPv4 and IPv6
- Connection upgrade for security

#### QUIC Transport
- UDP-based multiplexed connections
- Built-in encryption and congestion control
- Reduced connection establishment latency
- Better performance over lossy networks

#### WebSocket Transport
- HTTP/HTTPS upgrade mechanism
- Browser compatibility
- Proxy and firewall traversal
- TLS support for secure WebSockets

#### WebRTC Transport
- Direct browser-to-browser connections
- STUN/TURN for NAT traversal
- DataChannel for application data
- Built-in encryption (DTLS-SRTP)

### Security Protocols

#### TLS 1.3
- Latest TLS protocol version
- Perfect forward secrecy
- Reduced handshake latency
- Strong cipher suites only

#### Noise Protocol
- Modern cryptographic framework
- Mutual authentication
- Forward secrecy
- Lightweight alternative to TLS

### Multiplexing

#### mplex
- Lightweight stream multiplexer
- Low overhead
- Simple implementation
- Good for resource-constrained environments

#### yamux
- Yet Another Multiplexer
- Flow control and backpressure
- Connection health monitoring
- Better for high-throughput scenarios

## 3. Implementation Details

### Project Structure

```
pkg/network/
├── host.go              # libp2p host initialization and management
├── transport.go         # Transport protocol configurations
├── security.go          # Security protocol setup
├── config.go            # Configuration structures and defaults
├── metrics.go           # Prometheus metrics collection
├── identity.go          # Peer identity management
├── connection.go        # Connection lifecycle management
├── errors.go            # Custom error types
├── tests/
│   ├── host_test.go
│   ├── transport_test.go
│   ├── security_test.go
│   ├── integration_test.go
│   └── benchmark_test.go
└── examples/
    ├── basic_host/      # Basic host example
    └── multi_transport/ # Multi-transport example
```

### Core libp2p Host Configuration

```go
// pkg/network/host.go
package network

import (
    "context"
    "crypto/rand"
    "fmt"
    "time"

    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/peerstore"
    "github.com/libp2p/go-libp2p/p2p/net/connmgr"
    "github.com/multiformats/go-multiaddr"
    "github.com/prometheus/client_golang/prometheus"
)

// Host represents a Blackhole P2P host
type Host struct {
    host.Host
    config     *Config
    metrics    *Metrics
    connMgr    *connmgr.BasicConnMgr
    ctx        context.Context
    cancel     context.CancelFunc
}

// NewHost creates a new libp2p host with the provided configuration
func NewHost(ctx context.Context, cfg *Config) (*Host, error) {
    // Generate or load peer identity
    privKey, err := loadOrGenerateKey(cfg.IdentityPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load/generate identity: %w", err)
    }

    // Create connection manager
    connMgr, err := connmgr.NewConnManager(
        cfg.ConnMgr.LowWater,
        cfg.ConnMgr.HighWater,
        connmgr.WithGracePeriod(cfg.ConnMgr.GracePeriod),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create connection manager: %w", err)
    }

    // Configure listen addresses
    listenAddrs := make([]multiaddr.Multiaddr, 0, len(cfg.ListenAddrs))
    for _, addr := range cfg.ListenAddrs {
        maddr, err := multiaddr.NewMultiaddr(addr)
        if err != nil {
            return nil, fmt.Errorf("invalid listen address %s: %w", addr, err)
        }
        listenAddrs = append(listenAddrs, maddr)
    }

    // Build host options
    hostOpts := []libp2p.Option{
        libp2p.Identity(privKey),
        libp2p.ListenAddrs(listenAddrs...),
        libp2p.ConnectionManager(connMgr),
        libp2p.EnableNATService(),
        libp2p.DefaultResourceManager,
    }

    // Configure transports
    transportOpts, err := configureTransports(cfg)
    if err != nil {
        return nil, fmt.Errorf("failed to configure transports: %w", err)
    }
    hostOpts = append(hostOpts, transportOpts...)

    // Configure security
    securityOpts := configureSecurity(cfg)
    hostOpts = append(hostOpts, securityOpts...)

    // Configure multiplexers
    muxOpts := configureMuxers(cfg)
    hostOpts = append(hostOpts, muxOpts...)

    // Create the host
    h, err := libp2p.New(hostOpts...)
    if err != nil {
        return nil, fmt.Errorf("failed to create host: %w", err)
    }

    // Create host context
    hostCtx, cancel := context.WithCancel(ctx)

    // Initialize metrics
    metrics := NewMetrics(h.ID().String())
    if err := metrics.Register(); err != nil {
        h.Close()
        cancel()
        return nil, fmt.Errorf("failed to register metrics: %w", err)
    }

    host := &Host{
        Host:    h,
        config:  cfg,
        metrics: metrics,
        connMgr: connMgr,
        ctx:     hostCtx,
        cancel:  cancel,
    }

    // Set up connection notifications
    host.setupConnectionNotifications()

    // Start background tasks
    go host.runMetricsCollection()
    go host.runConnectionPruning()

    return host, nil
}

// setupConnectionNotifications configures connection lifecycle notifications
func (h *Host) setupConnectionNotifications() {
    h.Network().Notify(&network.NotifyBundle{
        ConnectedF: func(n network.Network, c network.Conn) {
            h.metrics.ConnectionsTotal.Inc()
            h.metrics.ConnectionsActive.Inc()
            log.Debugf("Connected to peer %s", c.RemotePeer())
        },
        DisconnectedF: func(n network.Network, c network.Conn) {
            h.metrics.ConnectionsActive.Dec()
            log.Debugf("Disconnected from peer %s", c.RemotePeer())
        },
        OpenedStreamF: func(n network.Network, s network.Stream) {
            h.metrics.StreamsTotal.Inc()
            h.metrics.StreamsActive.Inc()
        },
        ClosedStreamF: func(n network.Network, s network.Stream) {
            h.metrics.StreamsActive.Dec()
        },
    })
}

// Start initializes the host and begins accepting connections
func (h *Host) Start() error {
    // Log listening addresses
    for _, addr := range h.Addrs() {
        log.Infof("Listening on %s/p2p/%s", addr, h.ID())
    }

    // Update metrics
    h.metrics.HostStatus.Set(1) // 1 = running

    return nil
}

// Stop gracefully shuts down the host
func (h *Host) Stop() error {
    log.Info("Shutting down host...")
    
    // Cancel context to stop background tasks
    h.cancel()

    // Update metrics
    h.metrics.HostStatus.Set(0) // 0 = stopped

    // Close all connections gracefully
    peers := h.Network().Peers()
    for _, p := range peers {
        if err := h.Network().ClosePeer(p); err != nil {
            log.Warnf("Error closing connection to peer %s: %v", p, err)
        }
    }

    // Close the host
    return h.Host.Close()
}

// GetMetrics returns current metrics snapshot
func (h *Host) GetMetrics() HostMetrics {
    return HostMetrics{
        ID:              h.ID().String(),
        Addresses:       h.Addrs(),
        ConnectedPeers:  len(h.Network().Peers()),
        OpenStreams:     h.metrics.StreamsActive.Get(),
        TotalBytesIn:    h.metrics.BytesIn.Get(),
        TotalBytesOut:   h.metrics.BytesOut.Get(),
    }
}

// loadOrGenerateKey loads an existing key or generates a new one
func loadOrGenerateKey(path string) (crypto.PrivKey, error) {
    // Try to load existing key
    if path != "" {
        key, err := loadKeyFromFile(path)
        if err == nil {
            log.Info("Loaded existing peer identity")
            return key, nil
        }
        if !os.IsNotExist(err) {
            return nil, err
        }
    }

    // Generate new key
    log.Info("Generating new peer identity")
    priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
    if err != nil {
        return nil, err
    }

    // Save key if path provided
    if path != "" {
        if err := saveKeyToFile(priv, path); err != nil {
            log.Warnf("Failed to save identity key: %v", err)
        }
    }

    return priv, nil
}
```

### Transport Setup Code

```go
// pkg/network/transport.go
package network

import (
    "fmt"

    "github.com/libp2p/go-libp2p"
    quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
    "github.com/libp2p/go-libp2p/p2p/transport/tcp"
    "github.com/libp2p/go-libp2p/p2p/transport/websocket"
    "github.com/libp2p/go-libp2p/p2p/transport/webrtcdirect"
    "github.com/multiformats/go-multiaddr"
)

// configureTransports sets up all enabled transport protocols
func configureTransports(cfg *Config) ([]libp2p.Option, error) {
    var opts []libp2p.Option

    // TCP Transport
    if cfg.Transports.TCP.Enabled {
        tcpOpts := []tcp.Option{}
        if cfg.Transports.TCP.ReusePort {
            tcpOpts = append(tcpOpts, tcp.WithReuseport())
        }
        opts = append(opts, libp2p.Transport(tcp.NewTCPTransport, tcpOpts...))
        log.Info("TCP transport enabled")
    }

    // QUIC Transport
    if cfg.Transports.QUIC.Enabled {
        quicOpts := []quic.Option{}
        if cfg.Transports.QUIC.DraftSupport {
            quicOpts = append(quicOpts, quic.WithDraftSupport())
        }
        opts = append(opts, libp2p.Transport(quic.NewTransport, quicOpts...))
        log.Info("QUIC transport enabled")
    }

    // WebSocket Transport
    if cfg.Transports.WebSocket.Enabled {
        opts = append(opts, libp2p.Transport(websocket.New))
        log.Info("WebSocket transport enabled")
    }

    // WebRTC Transport
    if cfg.Transports.WebRTC.Enabled {
        if cfg.Transports.WebRTC.STUNServers == nil {
            cfg.Transports.WebRTC.STUNServers = []string{
                "stun:stun.l.google.com:19302",
                "stun:stun1.l.google.com:19302",
            }
        }
        webrtcOpts := webrtcdirect.Option{
            STUNServers: cfg.Transports.WebRTC.STUNServers,
        }
        opts = append(opts, libp2p.Transport(
            webrtcdirect.NewTransport,
            webrtcdirect.WithWebRTCOptions(webrtcOpts),
        ))
        log.Info("WebRTC transport enabled")
    }

    if len(opts) == 0 {
        return nil, fmt.Errorf("no transports enabled")
    }

    return opts, nil
}

// TransportStats represents statistics for a transport protocol
type TransportStats struct {
    Protocol      string
    Connections   int
    BytesIn       uint64
    BytesOut      uint64
    AvgLatencyMs  float64
}

// GetTransportStats returns statistics for all active transports
func (h *Host) GetTransportStats() map[string]*TransportStats {
    stats := make(map[string]*TransportStats)
    
    for _, conn := range h.Network().Conns() {
        proto := conn.LocalMultiaddr().Protocols()[0].Name
        if _, ok := stats[proto]; !ok {
            stats[proto] = &TransportStats{Protocol: proto}
        }
        stats[proto].Connections++
        
        // Get connection stats (requires connection tracking)
        if connStats, ok := h.getConnectionStats(conn.ID()); ok {
            stats[proto].BytesIn += connStats.BytesIn
            stats[proto].BytesOut += connStats.BytesOut
        }
    }
    
    return stats
}

// PreferredTransport returns the preferred transport for a given peer
func (h *Host) PreferredTransport(peer peer.ID) string {
    // Check existing connections
    conns := h.Network().ConnsToPeer(peer)
    if len(conns) > 0 {
        // Return transport of best connection (lowest latency)
        bestConn := conns[0]
        for _, conn := range conns[1:] {
            if h.getConnectionLatency(conn) < h.getConnectionLatency(bestConn) {
                bestConn = conn
            }
        }
        return bestConn.LocalMultiaddr().Protocols()[0].Name
    }

    // Return default preference order
    if h.config.Transports.QUIC.Enabled {
        return "quic"
    }
    if h.config.Transports.TCP.Enabled {
        return "tcp"
    }
    if h.config.Transports.WebSocket.Enabled {
        return "ws"
    }
    return "webrtc"
}
```

### Security Configuration

```go
// pkg/network/security.go
package network

import (
    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/p2p/security/noise"
    "github.com/libp2p/go-libp2p/p2p/security/tls"
)

// configureSecurity sets up security protocols for the host
func configureSecurity(cfg *Config) []libp2p.Option {
    var opts []libp2p.Option

    // Always enable at least one security protocol
    if !cfg.Security.TLS.Enabled && !cfg.Security.Noise.Enabled {
        log.Warn("No security protocols enabled, enabling Noise by default")
        cfg.Security.Noise.Enabled = true
    }

    // Noise Protocol (preferred)
    if cfg.Security.Noise.Enabled {
        opts = append(opts, libp2p.Security(noise.ID, noise.New))
        log.Info("Noise security protocol enabled")
    }

    // TLS 1.3
    if cfg.Security.TLS.Enabled {
        opts = append(opts, libp2p.Security(tls.ID, tls.New))
        log.Info("TLS 1.3 security protocol enabled")
    }

    return opts
}

// configureMuxers sets up stream multiplexers
func configureMuxers(cfg *Config) []libp2p.Option {
    var opts []libp2p.Option

    // Yamux (preferred for performance)
    if cfg.Muxers.Yamux.Enabled {
        opts = append(opts, libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport))
        log.Info("Yamux multiplexer enabled")
    }

    // Mplex (lighter weight)
    if cfg.Muxers.Mplex.Enabled {
        opts = append(opts, libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport))
        log.Info("Mplex multiplexer enabled")
    }

    if len(opts) == 0 {
        // Default to yamux
        opts = append(opts, libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport))
        log.Info("Yamux multiplexer enabled (default)")
    }

    return opts
}

// SecurityInfo represents information about a secure connection
type SecurityInfo struct {
    Protocol     string
    CipherSuite  string
    PeerID       peer.ID
    Established  time.Time
    LocalPubKey  []byte
    RemotePubKey []byte
}

// GetSecurityInfo returns security information for a connection
func (h *Host) GetSecurityInfo(connID string) (*SecurityInfo, error) {
    conn := h.getConnectionByID(connID)
    if conn == nil {
        return nil, fmt.Errorf("connection not found")
    }

    secProto := conn.Security()
    if secProto == "" {
        return nil, fmt.Errorf("connection is not secure")
    }

    info := &SecurityInfo{
        Protocol:    string(secProto),
        PeerID:      conn.RemotePeer(),
        Established: conn.Stat().Opened,
    }

    // Get public keys
    localKey := conn.LocalPrivateKey().GetPublic()
    remoteKey := conn.RemotePublicKey()
    
    if localKey != nil {
        info.LocalPubKey, _ = localKey.Raw()
    }
    if remoteKey != nil {
        info.RemotePubKey, _ = remoteKey.Raw()
    }

    return info, nil
}
```

### Connection Management

```go
// pkg/network/connection.go
package network

import (
    "context"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
)

// ConnectionManager handles connection lifecycle and health monitoring
type ConnectionManager struct {
    host    *Host
    mu      sync.RWMutex
    connMap map[string]*ConnectionInfo
}

// ConnectionInfo tracks information about a connection
type ConnectionInfo struct {
    ID          string
    PeerID      peer.ID
    Transport   string
    Direction   network.Direction
    Opened      time.Time
    LastActive  time.Time
    BytesIn     uint64
    BytesOut    uint64
    Latency     time.Duration
    Streams     int
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(h *Host) *ConnectionManager {
    return &ConnectionManager{
        host:    h,
        connMap: make(map[string]*ConnectionInfo),
    }
}

// runConnectionPruning periodically removes stale connections
func (h *Host) runConnectionPruning() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            h.pruneConnections()
        case <-h.ctx.Done():
            return
        }
    }
}

// pruneConnections removes inactive or poor-performing connections
func (h *Host) pruneConnections() {
    conns := h.Network().Conns()
    
    for _, conn := range conns {
        // Skip if under low water mark
        if len(conns) <= h.config.ConnMgr.LowWater {
            break
        }

        // Check connection health
        if h.isConnectionUnhealthy(conn) {
            log.Debugf("Pruning unhealthy connection to %s", conn.RemotePeer())
            conn.Close()
        }
    }
}

// isConnectionUnhealthy determines if a connection should be pruned
func (h *Host) isConnectionUnhealthy(conn network.Conn) bool {
    stats := conn.Stat()
    
    // No streams and idle for > 5 minutes
    if stats.NumStreams == 0 {
        idleTime := time.Since(stats.Opened)
        if idleTime > 5*time.Minute {
            return true
        }
    }

    // High latency connections (> 1s)
    if latency := h.getConnectionLatency(conn); latency > time.Second {
        return true
    }

    return false
}

// DialPeer establishes a connection to a peer with retry logic
func (h *Host) DialPeer(ctx context.Context, p peer.ID) error {
    // Check if already connected
    if h.Network().Connectedness(p) == network.Connected {
        return nil
    }

    // Get peer addresses
    addrs := h.Peerstore().Addrs(p)
    if len(addrs) == 0 {
        return fmt.Errorf("no addresses for peer %s", p)
    }

    // Try connecting with exponential backoff
    backoff := 100 * time.Millisecond
    maxBackoff := 30 * time.Second
    
    for attempt := 0; attempt < 5; attempt++ {
        if err := h.Connect(ctx, peer.AddrInfo{ID: p, Addrs: addrs}); err == nil {
            h.metrics.ConnectionAttemptsSuccess.Inc()
            return nil
        }
        
        h.metrics.ConnectionAttemptsFailed.Inc()
        
        // Exponential backoff
        select {
        case <-time.After(backoff):
            backoff *= 2
            if backoff > maxBackoff {
                backoff = maxBackoff
            }
        case <-ctx.Done():
            return ctx.Err()
        }
    }

    return fmt.Errorf("failed to connect to peer %s after 5 attempts", p)
}

// GetConnectionInfo returns detailed information about a connection
func (h *Host) GetConnectionInfo(p peer.ID) (*ConnectionInfo, error) {
    conns := h.Network().ConnsToPeer(p)
    if len(conns) == 0 {
        return nil, fmt.Errorf("not connected to peer %s", p)
    }

    // Use the best connection (lowest latency)
    conn := conns[0]
    for _, c := range conns[1:] {
        if h.getConnectionLatency(c) < h.getConnectionLatency(conn) {
            conn = c
        }
    }

    stats := conn.Stat()
    return &ConnectionInfo{
        ID:         conn.ID(),
        PeerID:     p,
        Transport:  conn.LocalMultiaddr().Protocols()[0].Name,
        Direction:  stats.Direction,
        Opened:     stats.Opened,
        LastActive: time.Now(),
        Streams:    stats.NumStreams,
        Latency:    h.getConnectionLatency(conn),
    }, nil
}
```

## 4. Key Functions

### NewHost() - Initialize libp2p host

```go
// NewHost creates and configures a new Blackhole P2P host
// Parameters:
//   - ctx: Context for lifecycle management
//   - cfg: Host configuration
// Returns:
//   - *Host: Configured host instance
//   - error: Any initialization errors
func NewHost(ctx context.Context, cfg *Config) (*Host, error)
```

### ConfigureTransports() - Set up all transports

```go
// configureTransports enables and configures transport protocols
// Parameters:
//   - cfg: Transport configuration
// Returns:
//   - []libp2p.Option: Transport options for host construction
//   - error: Configuration errors
func configureTransports(cfg *Config) ([]libp2p.Option, error)
```

### ConfigureSecurity() - Set up security

```go
// configureSecurity enables security protocols (TLS, Noise)
// Parameters:
//   - cfg: Security configuration
// Returns:
//   - []libp2p.Option: Security options for host construction
func configureSecurity(cfg *Config) []libp2p.Option
```

### Start() / Stop() - Lifecycle management

```go
// Start initializes the host and begins accepting connections
// Returns:
//   - error: Any startup errors
func (h *Host) Start() error

// Stop gracefully shuts down the host
// Returns:
//   - error: Any shutdown errors
func (h *Host) Stop() error
```

## 5. Configuration

### Configuration Structure

```go
// pkg/network/config.go
package network

import (
    "time"
)

// Config represents the complete network configuration
type Config struct {
    // Identity configuration
    IdentityPath string `yaml:"identity_path" env:"BLACKHOLE_IDENTITY_PATH"`
    
    // Listen addresses
    ListenAddrs []string `yaml:"listen_addrs" env:"BLACKHOLE_LISTEN_ADDRS"`
    
    // Transport configuration
    Transports TransportConfig `yaml:"transports"`
    
    // Security configuration
    Security SecurityConfig `yaml:"security"`
    
    // Multiplexer configuration
    Muxers MuxerConfig `yaml:"muxers"`
    
    // Connection manager configuration
    ConnMgr ConnMgrConfig `yaml:"connection_manager"`
    
    // Metrics configuration
    Metrics MetricsConfig `yaml:"metrics"`
}

// TransportConfig configures available transports
type TransportConfig struct {
    TCP       TCPConfig       `yaml:"tcp"`
    QUIC      QUICConfig      `yaml:"quic"`
    WebSocket WebSocketConfig `yaml:"websocket"`
    WebRTC    WebRTCConfig    `yaml:"webrtc"`
}

// TCPConfig configures TCP transport
type TCPConfig struct {
    Enabled   bool `yaml:"enabled" env:"BLACKHOLE_TCP_ENABLED"`
    ReusePort bool `yaml:"reuse_port" env:"BLACKHOLE_TCP_REUSEPORT"`
}

// QUICConfig configures QUIC transport
type QUICConfig struct {
    Enabled      bool `yaml:"enabled" env:"BLACKHOLE_QUIC_ENABLED"`
    DraftSupport bool `yaml:"draft_support" env:"BLACKHOLE_QUIC_DRAFT"`
}

// WebSocketConfig configures WebSocket transport
type WebSocketConfig struct {
    Enabled bool `yaml:"enabled" env:"BLACKHOLE_WS_ENABLED"`
}

// WebRTCConfig configures WebRTC transport
type WebRTCConfig struct {
    Enabled     bool     `yaml:"enabled" env:"BLACKHOLE_WEBRTC_ENABLED"`
    STUNServers []string `yaml:"stun_servers" env:"BLACKHOLE_STUN_SERVERS"`
}

// SecurityConfig configures security protocols
type SecurityConfig struct {
    TLS   TLSConfig   `yaml:"tls"`
    Noise NoiseConfig `yaml:"noise"`
}

// TLSConfig configures TLS 1.3
type TLSConfig struct {
    Enabled bool `yaml:"enabled" env:"BLACKHOLE_TLS_ENABLED"`
}

// NoiseConfig configures Noise protocol
type NoiseConfig struct {
    Enabled bool `yaml:"enabled" env:"BLACKHOLE_NOISE_ENABLED"`
}

// MuxerConfig configures stream multiplexers
type MuxerConfig struct {
    Yamux YamuxConfig `yaml:"yamux"`
    Mplex MplexConfig `yaml:"mplex"`
}

// YamuxConfig configures Yamux multiplexer
type YamuxConfig struct {
    Enabled bool `yaml:"enabled" env:"BLACKHOLE_YAMUX_ENABLED"`
}

// MplexConfig configures Mplex multiplexer
type MplexConfig struct {
    Enabled bool `yaml:"enabled" env:"BLACKHOLE_MPLEX_ENABLED"`
}

// ConnMgrConfig configures connection management
type ConnMgrConfig struct {
    LowWater    int           `yaml:"low_water" env:"BLACKHOLE_CONN_LOW_WATER"`
    HighWater   int           `yaml:"high_water" env:"BLACKHOLE_CONN_HIGH_WATER"`
    GracePeriod time.Duration `yaml:"grace_period" env:"BLACKHOLE_CONN_GRACE_PERIOD"`
}

// MetricsConfig configures metrics collection
type MetricsConfig struct {
    Enabled  bool   `yaml:"enabled" env:"BLACKHOLE_METRICS_ENABLED"`
    Endpoint string `yaml:"endpoint" env:"BLACKHOLE_METRICS_ENDPOINT"`
    Interval time.Duration `yaml:"interval" env:"BLACKHOLE_METRICS_INTERVAL"`
}

// DefaultConfig returns a production-ready default configuration
func DefaultConfig() *Config {
    return &Config{
        ListenAddrs: []string{
            "/ip4/0.0.0.0/tcp/4001",
            "/ip4/0.0.0.0/udp/4001/quic",
            "/ip4/0.0.0.0/tcp/4002/ws",
        },
        Transports: TransportConfig{
            TCP: TCPConfig{
                Enabled:   true,
                ReusePort: true,
            },
            QUIC: QUICConfig{
                Enabled:      true,
                DraftSupport: false,
            },
            WebSocket: WebSocketConfig{
                Enabled: true,
            },
            WebRTC: WebRTCConfig{
                Enabled: false, // Disabled by default
            },
        },
        Security: SecurityConfig{
            TLS: TLSConfig{
                Enabled: true,
            },
            Noise: NoiseConfig{
                Enabled: true,
            },
        },
        Muxers: MuxerConfig{
            Yamux: YamuxConfig{
                Enabled: true,
            },
            Mplex: MplexConfig{
                Enabled: true,
            },
        },
        ConnMgr: ConnMgrConfig{
            LowWater:    100,
            HighWater:   400,
            GracePeriod: 20 * time.Second,
        },
        Metrics: MetricsConfig{
            Enabled:  true,
            Endpoint: "/metrics",
            Interval: 30 * time.Second,
        },
    }
}
```

### YAML Configuration Example

```yaml
# config/network.yaml
identity_path: "/var/lib/blackhole/identity"

listen_addrs:
  - "/ip4/0.0.0.0/tcp/4001"
  - "/ip4/0.0.0.0/udp/4001/quic"
  - "/ip4/0.0.0.0/tcp/4002/ws"
  - "/ip6/::/tcp/4001"
  - "/ip6/::/udp/4001/quic"

transports:
  tcp:
    enabled: true
    reuse_port: true
  quic:
    enabled: true
    draft_support: false
  websocket:
    enabled: true
  webrtc:
    enabled: true
    stun_servers:
      - "stun:stun.l.google.com:19302"
      - "stun:stun1.l.google.com:19302"

security:
  tls:
    enabled: true
  noise:
    enabled: true

muxers:
  yamux:
    enabled: true
  mplex:
    enabled: true

connection_manager:
  low_water: 100
  high_water: 400
  grace_period: 20s

metrics:
  enabled: true
  endpoint: "/metrics"
  interval: 30s
```

### Environment Variables

All configuration options can be overridden via environment variables:

```bash
# Core settings
export BLACKHOLE_IDENTITY_PATH="/var/lib/blackhole/identity"
export BLACKHOLE_LISTEN_ADDRS="/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/udp/4001/quic"

# Transport settings
export BLACKHOLE_TCP_ENABLED=true
export BLACKHOLE_TCP_REUSEPORT=true
export BLACKHOLE_QUIC_ENABLED=true
export BLACKHOLE_WS_ENABLED=true
export BLACKHOLE_WEBRTC_ENABLED=false

# Security settings
export BLACKHOLE_TLS_ENABLED=true
export BLACKHOLE_NOISE_ENABLED=true

# Connection management
export BLACKHOLE_CONN_LOW_WATER=100
export BLACKHOLE_CONN_HIGH_WATER=400
export BLACKHOLE_CONN_GRACE_PERIOD=20s

# Metrics
export BLACKHOLE_METRICS_ENABLED=true
export BLACKHOLE_METRICS_ENDPOINT="/metrics"
```

## 6. Testing Requirements

### Unit Tests

```go
// pkg/network/tests/host_test.go
package network_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/blackhole/pkg/network"
)

func TestHostCreation(t *testing.T) {
    ctx := context.Background()
    cfg := network.DefaultConfig()
    
    host, err := network.NewHost(ctx, cfg)
    require.NoError(t, err)
    defer host.Stop()
    
    // Verify host is created
    assert.NotNil(t, host)
    assert.NotEmpty(t, host.ID())
    assert.NotEmpty(t, host.Addrs())
}

func TestMultiTransport(t *testing.T) {
    ctx := context.Background()
    
    // Create two hosts with different transports
    cfg1 := network.DefaultConfig()
    cfg1.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}
    host1, err := network.NewHost(ctx, cfg1)
    require.NoError(t, err)
    defer host1.Stop()
    
    cfg2 := network.DefaultConfig()
    cfg2.ListenAddrs = []string{"/ip4/127.0.0.1/udp/0/quic"}
    host2, err := network.NewHost(ctx, cfg2)
    require.NoError(t, err)
    defer host2.Stop()
    
    // Connect hosts
    host2.Peerstore().AddAddrs(host1.ID(), host1.Addrs(), time.Hour)
    err = host2.Connect(ctx, host1.ID())
    require.NoError(t, err)
    
    // Verify connection
    assert.Eventually(t, func() bool {
        return host2.Network().Connectedness(host1.ID()) == network.Connected
    }, 5*time.Second, 100*time.Millisecond)
}

func TestSecurityProtocols(t *testing.T) {
    testCases := []struct {
        name     string
        tlsEnabled  bool
        noiseEnabled bool
    }{
        {"TLS only", true, false},
        {"Noise only", false, true},
        {"Both enabled", true, true},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            ctx := context.Background()
            cfg := network.DefaultConfig()
            cfg.Security.TLS.Enabled = tc.tlsEnabled
            cfg.Security.Noise.Enabled = tc.noiseEnabled
            
            host, err := network.NewHost(ctx, cfg)
            require.NoError(t, err)
            defer host.Stop()
            
            // Verify host can establish secure connections
            // (implementation depends on test infrastructure)
        })
    }
}

func TestConnectionManager(t *testing.T) {
    ctx := context.Background()
    cfg := network.DefaultConfig()
    cfg.ConnMgr.LowWater = 2
    cfg.ConnMgr.HighWater = 5
    cfg.ConnMgr.GracePeriod = 1 * time.Second
    
    host, err := network.NewHost(ctx, cfg)
    require.NoError(t, err)
    defer host.Stop()
    
    // Create multiple peers and connect
    peers := make([]*network.Host, 10)
    for i := range peers {
        peerCfg := network.DefaultConfig()
        peerCfg.ListenAddrs = []string{fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 5000+i)}
        peers[i], err = network.NewHost(ctx, peerCfg)
        require.NoError(t, err)
        defer peers[i].Stop()
        
        // Connect to main host
        host.Peerstore().AddAddrs(peers[i].ID(), peers[i].Addrs(), time.Hour)
        err = host.Connect(ctx, peers[i].ID())
        require.NoError(t, err)
    }
    
    // Wait for connection manager to prune
    time.Sleep(3 * time.Second)
    
    // Verify connections were pruned
    connCount := len(host.Network().Peers())
    assert.LessOrEqual(t, connCount, cfg.ConnMgr.HighWater)
    assert.GreaterOrEqual(t, connCount, cfg.ConnMgr.LowWater)
}
```

### Integration Tests

```go
// pkg/network/tests/integration_test.go
package network_test

import (
    "context"
    "io"
    "testing"
    "time"

    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/protocol"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

const testProtocol = protocol.ID("/blackhole/test/1.0.0")

func TestEndToEndCommunication(t *testing.T) {
    ctx := context.Background()
    
    // Create two hosts
    host1, err := network.NewHost(ctx, network.DefaultConfig())
    require.NoError(t, err)
    defer host1.Stop()
    
    host2, err := network.NewHost(ctx, network.DefaultConfig())
    require.NoError(t, err)
    defer host2.Stop()
    
    // Set up protocol handler on host1
    received := make(chan string, 1)
    host1.SetStreamHandler(testProtocol, func(s network.Stream) {
        defer s.Close()
        buf := make([]byte, 1024)
        n, err := s.Read(buf)
        if err != nil && err != io.EOF {
            t.Errorf("Failed to read: %v", err)
            return
        }
        received <- string(buf[:n])
    })
    
    // Connect hosts
    host2.Peerstore().AddAddrs(host1.ID(), host1.Addrs(), time.Hour)
    err = host2.Connect(ctx, host1.ID())
    require.NoError(t, err)
    
    // Open stream and send message
    stream, err := host2.NewStream(ctx, host1.ID(), testProtocol)
    require.NoError(t, err)
    defer stream.Close()
    
    testMsg := "Hello, Blackhole!"
    _, err = stream.Write([]byte(testMsg))
    require.NoError(t, err)
    stream.Close()
    
    // Verify message received
    select {
    case msg := <-received:
        assert.Equal(t, testMsg, msg)
    case <-time.After(5 * time.Second):
        t.Fatal("Timeout waiting for message")
    }
}

func TestNATTraversal(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping NAT traversal test in short mode")
    }
    
    ctx := context.Background()
    
    // Create host behind NAT (simulated)
    natCfg := network.DefaultConfig()
    natCfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}
    natHost, err := network.NewHost(ctx, natCfg)
    require.NoError(t, err)
    defer natHost.Stop()
    
    // Create public host
    publicCfg := network.DefaultConfig()
    publicHost, err := network.NewHost(ctx, publicCfg)
    require.NoError(t, err)
    defer publicHost.Stop()
    
    // Attempt connection through NAT
    publicHost.Peerstore().AddAddrs(natHost.ID(), natHost.Addrs(), time.Hour)
    err = publicHost.Connect(ctx, natHost.ID())
    require.NoError(t, err)
    
    // Verify bidirectional communication
    assert.Eventually(t, func() bool {
        return natHost.Network().Connectedness(publicHost.ID()) == network.Connected &&
               publicHost.Network().Connectedness(natHost.ID()) == network.Connected
    }, 10*time.Second, 100*time.Millisecond)
}
```

### Performance Benchmarks

```go
// pkg/network/tests/benchmark_test.go
package network_test

import (
    "context"
    "testing"
    "time"

    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/protocol"
)

func BenchmarkConnectionEstablishment(b *testing.B) {
    ctx := context.Background()
    
    // Create hosts
    host1, _ := network.NewHost(ctx, network.DefaultConfig())
    defer host1.Stop()
    
    host2, _ := network.NewHost(ctx, network.DefaultConfig())
    defer host2.Stop()
    
    host2.Peerstore().AddAddrs(host1.ID(), host1.Addrs(), time.Hour)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // Disconnect if connected
        if host2.Network().Connectedness(host1.ID()) == network.Connected {
            host2.Network().ClosePeer(host1.ID())
        }
        
        // Measure connection time
        err := host2.Connect(ctx, host1.ID())
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkStreamCreation(b *testing.B) {
    ctx := context.Background()
    testProto := protocol.ID("/bench/1.0.0")
    
    // Setup hosts and connection
    host1, _ := network.NewHost(ctx, network.DefaultConfig())
    defer host1.Stop()
    
    host2, _ := network.NewHost(ctx, network.DefaultConfig())
    defer host2.Stop()
    
    // Simple echo handler
    host1.SetStreamHandler(testProto, func(s network.Stream) {
        io.Copy(s, s)
    })
    
    host2.Peerstore().AddAddrs(host1.ID(), host1.Addrs(), time.Hour)
    host2.Connect(ctx, host1.ID())
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        stream, err := host2.NewStream(ctx, host1.ID(), testProto)
        if err != nil {
            b.Fatal(err)
        }
        stream.Close()
    }
}

func BenchmarkDataTransfer(b *testing.B) {
    sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB
    
    for _, size := range sizes {
        b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
            ctx := context.Background()
            data := make([]byte, size)
            rand.Read(data)
            
            // Setup hosts
            host1, _ := network.NewHost(ctx, network.DefaultConfig())
            defer host1.Stop()
            
            host2, _ := network.NewHost(ctx, network.DefaultConfig())
            defer host2.Stop()
            
            // Echo handler
            host1.SetStreamHandler("/bench/transfer/1.0.0", func(s network.Stream) {
                io.Copy(io.Discard, s)
                s.Close()
            })
            
            host2.Peerstore().AddAddrs(host1.ID(), host1.Addrs(), time.Hour)
            host2.Connect(ctx, host1.ID())
            
            b.SetBytes(int64(size))
            b.ResetTimer()
            
            for i := 0; i < b.N; i++ {
                stream, _ := host2.NewStream(ctx, host1.ID(), "/bench/transfer/1.0.0")
                stream.Write(data)
                stream.Close()
            }
        })
    }
}
```

## 7. Monitoring & Metrics

### Metrics Implementation

```go
// pkg/network/metrics.go
package network

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the network layer
type Metrics struct {
    // Host metrics
    HostStatus prometheus.Gauge
    PeerCount  prometheus.Gauge
    
    // Connection metrics
    ConnectionsTotal          prometheus.Counter
    ConnectionsActive         prometheus.Gauge
    ConnectionAttempts        prometheus.Counter
    ConnectionAttemptsSuccess prometheus.Counter
    ConnectionAttemptsFailed  prometheus.Counter
    ConnectionDuration        prometheus.Histogram
    
    // Stream metrics
    StreamsTotal  prometheus.Counter
    StreamsActive prometheus.Gauge
    
    // Bandwidth metrics
    BytesIn  prometheus.Counter
    BytesOut prometheus.Counter
    
    // Transport metrics
    TransportConnections *prometheus.GaugeVec
    TransportBytesIn     *prometheus.CounterVec
    TransportBytesOut    *prometheus.CounterVec
    
    // Security metrics
    SecureConnections   *prometheus.GaugeVec
    HandshakeDuration   prometheus.Histogram
    HandshakeFailures   prometheus.Counter
    
    // Error metrics
    NetworkErrors *prometheus.CounterVec
}

// NewMetrics creates a new metrics instance
func NewMetrics(hostID string) *Metrics {
    constLabels := prometheus.Labels{"host_id": hostID}
    
    return &Metrics{
        HostStatus: promauto.NewGauge(prometheus.GaugeOpts{
            Name:        "blackhole_host_status",
            Help:        "Host status (1=running, 0=stopped)",
            ConstLabels: constLabels,
        }),
        
        PeerCount: promauto.NewGauge(prometheus.GaugeOpts{
            Name:        "blackhole_peer_count",
            Help:        "Number of connected peers",
            ConstLabels: constLabels,
        }),
        
        ConnectionsTotal: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_connections_total",
            Help:        "Total number of connections established",
            ConstLabels: constLabels,
        }),
        
        ConnectionsActive: promauto.NewGauge(prometheus.GaugeOpts{
            Name:        "blackhole_connections_active",
            Help:        "Number of active connections",
            ConstLabels: constLabels,
        }),
        
        ConnectionAttempts: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_connection_attempts_total",
            Help:        "Total connection attempts",
            ConstLabels: constLabels,
        }),
        
        ConnectionAttemptsSuccess: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_connection_attempts_success_total",
            Help:        "Successful connection attempts",
            ConstLabels: constLabels,
        }),
        
        ConnectionAttemptsFailed: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_connection_attempts_failed_total",
            Help:        "Failed connection attempts",
            ConstLabels: constLabels,
        }),
        
        ConnectionDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:        "blackhole_connection_duration_seconds",
            Help:        "Connection duration in seconds",
            ConstLabels: constLabels,
            Buckets:     prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~9h
        }),
        
        StreamsTotal: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_streams_total",
            Help:        "Total number of streams created",
            ConstLabels: constLabels,
        }),
        
        StreamsActive: promauto.NewGauge(prometheus.GaugeOpts{
            Name:        "blackhole_streams_active",
            Help:        "Number of active streams",
            ConstLabels: constLabels,
        }),
        
        BytesIn: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_bytes_in_total",
            Help:        "Total bytes received",
            ConstLabels: constLabels,
        }),
        
        BytesOut: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_bytes_out_total",
            Help:        "Total bytes sent",
            ConstLabels: constLabels,
        }),
        
        TransportConnections: promauto.NewGaugeVec(prometheus.GaugeOpts{
            Name:        "blackhole_transport_connections",
            Help:        "Connections per transport protocol",
            ConstLabels: constLabels,
        }, []string{"transport"}),
        
        TransportBytesIn: promauto.NewCounterVec(prometheus.CounterOpts{
            Name:        "blackhole_transport_bytes_in_total",
            Help:        "Bytes received per transport",
            ConstLabels: constLabels,
        }, []string{"transport"}),
        
        TransportBytesOut: promauto.NewCounterVec(prometheus.CounterOpts{
            Name:        "blackhole_transport_bytes_out_total",
            Help:        "Bytes sent per transport",
            ConstLabels: constLabels,
        }, []string{"transport"}),
        
        SecureConnections: promauto.NewGaugeVec(prometheus.GaugeOpts{
            Name:        "blackhole_secure_connections",
            Help:        "Secure connections by protocol",
            ConstLabels: constLabels,
        }, []string{"protocol"}),
        
        HandshakeDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:        "blackhole_handshake_duration_seconds",
            Help:        "Security handshake duration",
            ConstLabels: constLabels,
            Buckets:     prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms to 4s
        }),
        
        HandshakeFailures: promauto.NewCounter(prometheus.CounterOpts{
            Name:        "blackhole_handshake_failures_total",
            Help:        "Total handshake failures",
            ConstLabels: constLabels,
        }),
        
        NetworkErrors: promauto.NewCounterVec(prometheus.CounterOpts{
            Name:        "blackhole_network_errors_total",
            Help:        "Network errors by type",
            ConstLabels: constLabels,
        }, []string{"error_type"}),
    }
}

// runMetricsCollection periodically updates metrics
func (h *Host) runMetricsCollection() {
    ticker := time.NewTicker(h.config.Metrics.Interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            h.updateMetrics()
        case <-h.ctx.Done():
            return
        }
    }
}

// updateMetrics updates all metrics with current values
func (h *Host) updateMetrics() {
    // Update peer count
    h.metrics.PeerCount.Set(float64(len(h.Network().Peers())))
    
    // Update transport metrics
    transportStats := h.GetTransportStats()
    for transport, stats := range transportStats {
        h.metrics.TransportConnections.WithLabelValues(transport).Set(float64(stats.Connections))
        h.metrics.TransportBytesIn.WithLabelValues(transport).Add(float64(stats.BytesIn))
        h.metrics.TransportBytesOut.WithLabelValues(transport).Add(float64(stats.BytesOut))
    }
    
    // Update security metrics
    securityStats := h.getSecurityStats()
    for protocol, count := range securityStats {
        h.metrics.SecureConnections.WithLabelValues(protocol).Set(float64(count))
    }
}
```

### Monitoring Dashboard Configuration

```yaml
# Grafana dashboard queries
panels:
  - title: "Host Status"
    query: "blackhole_host_status"
    
  - title: "Connected Peers"
    query: "blackhole_peer_count"
    
  - title: "Active Connections by Transport"
    query: "sum by (transport) (blackhole_transport_connections)"
    
  - title: "Bandwidth Usage"
    queries:
      - "rate(blackhole_bytes_in_total[5m])"
      - "rate(blackhole_bytes_out_total[5m])"
    
  - title: "Connection Success Rate"
    query: |
      rate(blackhole_connection_attempts_success_total[5m]) /
      rate(blackhole_connection_attempts_total[5m])
    
  - title: "Average Handshake Duration"
    query: |
      histogram_quantile(0.95, 
        rate(blackhole_handshake_duration_seconds_bucket[5m])
      )
```

## 8. Error Handling

### Error Types

```go
// pkg/network/errors.go
package network

import "errors"

var (
    // Configuration errors
    ErrInvalidConfig     = errors.New("invalid configuration")
    ErrNoTransports      = errors.New("no transports enabled")
    ErrNoSecurityProtos  = errors.New("no security protocols enabled")
    
    // Connection errors
    ErrConnectionFailed  = errors.New("connection failed")
    ErrConnectionTimeout = errors.New("connection timeout")
    ErrPeerNotFound      = errors.New("peer not found")
    ErrNoAddresses       = errors.New("no addresses for peer")
    
    // Transport errors
    ErrTransportFailed   = errors.New("transport failed")
    ErrListenFailed      = errors.New("failed to listen on address")
    
    // Security errors
    ErrHandshakeFailed   = errors.New("security handshake failed")
    ErrAuthenticationFailed = errors.New("peer authentication failed")
    
    // Resource errors
    ErrResourceExhausted = errors.New("resource exhausted")
    ErrConnectionLimit   = errors.New("connection limit reached")
)

// ErrorHandler provides centralized error handling
type ErrorHandler struct {
    metrics *Metrics
}

// HandleError processes and logs errors appropriately
func (eh *ErrorHandler) HandleError(err error, context string) {
    if err == nil {
        return
    }
    
    // Categorize error
    errorType := categorizeError(err)
    eh.metrics.NetworkErrors.WithLabelValues(errorType).Inc()
    
    // Log with appropriate level
    switch errorType {
    case "connection_failed", "timeout":
        log.Debugf("%s: %v", context, err)
    case "security_failed", "auth_failed":
        log.Warnf("%s: %v", context, err)
    default:
        log.Errorf("%s: %v", context, err)
    }
}

// categorizeError determines the error type for metrics
func categorizeError(err error) string {
    switch {
    case errors.Is(err, ErrConnectionFailed):
        return "connection_failed"
    case errors.Is(err, ErrConnectionTimeout):
        return "timeout"
    case errors.Is(err, ErrHandshakeFailed):
        return "security_failed"
    case errors.Is(err, ErrAuthenticationFailed):
        return "auth_failed"
    case errors.Is(err, ErrResourceExhausted):
        return "resource_exhausted"
    default:
        return "unknown"
    }
}
```

### Recovery Mechanisms

```go
// Connection retry with exponential backoff
func (h *Host) connectWithRetry(ctx context.Context, peer peer.AddrInfo) error {
    backoff := 100 * time.Millisecond
    maxBackoff := 30 * time.Second
    maxRetries := 5
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        err := h.Connect(ctx, peer)
        if err == nil {
            return nil
        }
        
        if !isRetryableError(err) {
            return err
        }
        
        select {
        case <-time.After(backoff):
            backoff = min(backoff*2, maxBackoff)
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    
    return ErrConnectionFailed
}

// Transport fallback mechanism
func (h *Host) dialWithFallback(ctx context.Context, p peer.ID) error {
    transports := []string{"quic", "tcp", "ws", "webrtc"}
    
    for _, transport := range transports {
        if !h.isTransportEnabled(transport) {
            continue
        }
        
        addrs := h.filterAddrsByTransport(h.Peerstore().Addrs(p), transport)
        if len(addrs) == 0 {
            continue
        }
        
        if err := h.Connect(ctx, peer.AddrInfo{ID: p, Addrs: addrs}); err == nil {
            log.Debugf("Connected to %s via %s", p, transport)
            return nil
        }
    }
    
    return ErrConnectionFailed
}
```

## 9. Acceptance Criteria

### Functional Requirements

1. **Multi-transport Connectivity**
   - [ ] TCP transport functional with port reuse
   - [ ] QUIC transport operational
   - [ ] WebSocket transport working
   - [ ] WebRTC transport available (optional)
   - [ ] Seamless fallback between transports

2. **Secure Connections**
   - [ ] TLS 1.3 handshake successful
   - [ ] Noise protocol operational
   - [ ] Mutual authentication working
   - [ ] No plaintext connections allowed

3. **NAT Traversal**
   - [ ] AutoNAT service running
   - [ ] Successful connections through NAT
   - [ ] Circuit relay as fallback
   - [ ] Hole punching attempted

4. **Metrics Exposed**
   - [ ] Prometheus endpoint available
   - [ ] All defined metrics collecting data
   - [ ] Grafana dashboard functional
   - [ ] Real-time monitoring possible

### Performance Requirements

1. **Connection Establishment**
   - Sub-100ms for local connections
   - Sub-500ms for internet connections
   - 95% success rate in good conditions

2. **Concurrent Connections**
   - Support 1000+ simultaneous connections
   - Graceful handling at connection limits
   - Efficient resource usage

3. **Data Transfer**
   - 10MB/s+ throughput on local network
   - 1MB/s+ on typical internet connection
   - Low CPU overhead

4. **Resource Usage**
   - Memory usage under 500MB for 1000 connections
   - CPU usage under 20% during normal operation
   - File descriptor management

### Security Requirements

1. **Encryption**
   - All connections encrypted
   - Strong cipher suites only
   - Perfect forward secrecy

2. **Authentication**
   - Peer identity verification
   - No man-in-the-middle vulnerabilities
   - Secure key storage

3. **Resource Protection**
   - Connection limits enforced
   - Rate limiting available
   - DDoS mitigation

## 10. Example Usage

### Basic Host Creation

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/blackhole/pkg/network"
)

func main() {
    ctx := context.Background()
    
    // Create host with default configuration
    host, err := network.NewHost(ctx, network.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    defer host.Stop()
    
    // Start accepting connections
    if err := host.Start(); err != nil {
        log.Fatal(err)
    }
    
    // Print host information
    fmt.Printf("Host ID: %s\n", host.ID())
    fmt.Println("Listening addresses:")
    for _, addr := range host.Addrs() {
        fmt.Printf("  %s\n", addr)
    }
    
    // Keep running
    select {}
}
```

### Custom Configuration

```go
package main

import (
    "context"
    "time"
    
    "github.com/blackhole/pkg/network"
)

func main() {
    ctx := context.Background()
    
    // Create custom configuration
    cfg := &network.Config{
        ListenAddrs: []string{
            "/ip4/0.0.0.0/tcp/4001",
            "/ip4/0.0.0.0/udp/4001/quic",
        },
        Transports: network.TransportConfig{
            TCP: network.TCPConfig{
                Enabled:   true,
                ReusePort: true,
            },
            QUIC: network.QUICConfig{
                Enabled: true,
            },
        },
        Security: network.SecurityConfig{
            Noise: network.NoiseConfig{
                Enabled: true,
            },
        },
        ConnMgr: network.ConnMgrConfig{
            LowWater:    50,
            HighWater:   200,
            GracePeriod: 30 * time.Second,
        },
    }
    
    host, err := network.NewHost(ctx, cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer host.Stop()
    
    host.Start()
    
    // Your application logic here
}
```

### Connecting to Peers

```go
package main

import (
    "context"
    "fmt"
    
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/multiformats/go-multiaddr"
)

func connectToPeer(host *network.Host, peerAddr string) error {
    // Parse multiaddr
    addr, err := multiaddr.NewMultiaddr(peerAddr)
    if err != nil {
        return err
    }
    
    // Extract peer ID
    info, err := peer.AddrInfoFromP2pAddr(addr)
    if err != nil {
        return err
    }
    
    // Add address to peerstore
    host.Peerstore().AddAddrs(info.ID, info.Addrs, time.Hour)
    
    // Connect
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := host.Connect(ctx, *info); err != nil {
        return err
    }
    
    fmt.Printf("Connected to %s\n", info.ID)
    return nil
}
```

## Summary

Unit U01 establishes the critical networking foundation for the Blackhole platform. By implementing a robust libp2p host with multiple transports, strong security, and comprehensive monitoring, this unit enables all subsequent P2P functionality. The modular design allows for easy extension and modification as the platform evolves.

Key achievements:
- Multi-transport support for maximum connectivity
- Strong security with TLS 1.3 and Noise
- Production-ready connection management
- Comprehensive metrics and monitoring
- Extensible architecture for future enhancements

This implementation provides a solid foundation for building the decentralized infrastructure that Blackhole requires.