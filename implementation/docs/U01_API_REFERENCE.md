# U01 API Reference

## Table of Contents

1. [Package Overview](#package-overview)
2. [Types](#types)
3. [Functions](#functions)
4. [Configuration](#configuration)
5. [Errors](#errors)
6. [Metrics](#metrics)
7. [Examples](#examples)

## Package Overview

```go
import "github.com/blackhole/implementation/pkg/network"
```

The network package provides a production-ready libp2p host implementation with enhanced features for the Blackhole decentralized platform.

## Types

### Host

```go
type Host struct {
    host.Host // Embedded libp2p host
    // Additional fields for enhanced functionality
}
```

The Host type wraps a standard libp2p host with additional functionality including lifecycle management, metrics collection, and health monitoring.

#### Methods

##### NewHost

```go
func NewHost(ctx context.Context, config *Config) (*Host, error)
```

Creates a new enhanced libp2p host with the provided configuration.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `config`: Host configuration

**Returns:**
- `*Host`: The created host instance
- `error`: Error if host creation fails

**Example:**
```go
config, err := network.LoadConfig("config/default.yaml")
if err != nil {
    return err
}

host, err := network.NewHost(context.Background(), config)
if err != nil {
    return err
}
```

##### Start

```go
func (h *Host) Start() error
```

Starts the host, including peer discovery, connection management, and health monitoring.

**Returns:**
- `error`: Error if start fails

**Errors:**
- `ErrHostAlreadyStarted`: Host is already running

##### Stop

```go
func (h *Host) Stop() error
```

Gracefully stops the host, closing all connections and releasing resources.

**Returns:**
- `error`: Error if stop fails

**Errors:**
- `ErrHostNotStarted`: Host was not started

##### Connect

```go
func (h *Host) Connect(ctx context.Context, pi peer.AddrInfo) error
```

Connects to a peer with the given address information.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `pi`: Peer address information

**Returns:**
- `error`: Error if connection fails

**Errors:**
- `ErrConnectionFailed`: Connection attempt failed
- `ErrTimeout`: Connection timed out

##### Disconnect

```go
func (h *Host) Disconnect(peerID peer.ID) error
```

Disconnects from a specific peer.

**Parameters:**
- `peerID`: ID of the peer to disconnect

**Returns:**
- `error`: Error if disconnection fails

**Errors:**
- `ErrPeerNotFound`: Peer not connected

##### Peers

```go
func (h *Host) Peers() []peer.ID
```

Returns a list of currently connected peer IDs.

**Returns:**
- `[]peer.ID`: List of connected peer IDs

##### PeerInfo

```go
func (h *Host) PeerInfo(peerID peer.ID) (*ConnectionInfo, error)
```

Returns detailed information about a connected peer.

**Parameters:**
- `peerID`: ID of the peer

**Returns:**
- `*ConnectionInfo`: Connection information
- `error`: Error if peer not found

##### SetProtocolHandler

```go
func (h *Host) SetProtocolHandler(proto protocol.ID, handler network.StreamHandler)
```

Registers a handler for a specific protocol.

**Parameters:**
- `proto`: Protocol identifier
- `handler`: Stream handler function

**Example:**
```go
host.SetProtocolHandler("/blackhole/1.0.0", func(stream network.Stream) {
    defer stream.Close()
    // Handle stream
})
```

##### NewStream

```go
func (h *Host) NewStream(ctx context.Context, p peer.ID, pids ...protocol.ID) (network.Stream, error)
```

Opens a new stream to a peer for the given protocols.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `p`: Target peer ID
- `pids`: Protocol IDs to negotiate

**Returns:**
- `network.Stream`: The opened stream
- `error`: Error if stream creation fails

**Errors:**
- `ErrStreamCreationFailed`: Failed to create stream
- `ErrPeerNotFound`: Target peer not connected
- `ErrProtocolNotSupported`: No matching protocol

### ConnectionManager

```go
type ConnectionManager struct {
    // Internal fields
}
```

Manages peer connections with intelligent resource management.

#### Methods

##### GetConnections

```go
func (cm *ConnectionManager) GetConnections() map[peer.ID]*ConnectionInfo
```

Returns a snapshot of all current connections.

**Returns:**
- `map[peer.ID]*ConnectionInfo`: Map of peer IDs to connection information

##### TrimConnections

```go
func (cm *ConnectionManager) TrimConnections()
```

Prunes connections to stay within configured limits.

##### TagPeer

```go
func (cm *ConnectionManager) TagPeer(p peer.ID, tag string, value int)
```

Tags a peer with a priority value for connection management.

**Parameters:**
- `p`: Peer ID to tag
- `tag`: Tag name
- `value`: Priority value (higher = more important)

### ConnectionInfo

```go
type ConnectionInfo struct {
    PeerID          peer.ID
    ConnectedAt     time.Time
    LastActivity    time.Time
    Direction       network.Direction
    Streams         int32
    BytesSent       uint64
    BytesReceived   uint64
    Latency         time.Duration
    Protocols       []protocol.ID
    RemoteAddr      multiaddr.Multiaddr
    UserAgent       string
    ProtocolVersion string
    Healthy         bool
    ReconnectCount  int
    LastError       error
}
```

Detailed information about a peer connection.

## Configuration

### Config

```go
type Config struct {
    Network   NetworkConfig
    Identity  IdentityConfig
    Metrics   MetricsConfig
    Logging   LoggingConfig
    Discovery DiscoveryConfig
    Resources ResourceConfig
}
```

Complete node configuration structure.

### NetworkConfig

```go
type NetworkConfig struct {
    ListenAddresses   []string
    BootstrapPeers    []string
    ConnectionManager *ConnectionManagerConf
    Transports        *TransportConfig
    Security          *SecurityConfig
    EnableRelay       bool
    EnableAutoRelay   bool
    StaticRelays      []string
}
```

Network-specific configuration.

### ConnectionManagerConf

```go
type ConnectionManagerConf struct {
    HighWater   int           // Max connections before pruning
    LowWater    int           // Target after pruning
    GracePeriod time.Duration // Grace period before closing
}
```

Connection manager configuration.

### TransportConfig

```go
type TransportConfig struct {
    TCP       *TCPConfig
    QUIC      *QUICConfig
    WebSocket *WebSocketConfig
    WebRTC    *WebRTCConfig
}
```

Transport-specific configurations.

### TCPConfig

```go
type TCPConfig struct {
    Enabled      bool
    PortReuse    bool
    KeepAlive    time.Duration
    TCPNoDelay   bool
    SocketBuffer int
}
```

TCP transport configuration.

### QUICConfig

```go
type QUICConfig struct {
    Enabled         bool
    MaxIdleTimeout  time.Duration
    KeepAlivePeriod time.Duration
    MaxStreams      int
    EnableDatagrams bool
}
```

QUIC transport configuration.

### SecurityConfig

```go
type SecurityConfig struct {
    TLS   *TLSConfig
    Noise *NoiseConfig
}
```

Security configuration.

### TLSConfig

```go
type TLSConfig struct {
    Enabled      bool
    MinVersion   string
    CertValidity time.Duration
}
```

TLS configuration options.

### Loading Configuration

```go
func LoadConfig(path string) (*Config, error)
```

Loads configuration from a YAML file.

**Parameters:**
- `path`: Path to configuration file

**Returns:**
- `*Config`: Loaded configuration
- `error`: Error if loading fails

```go
func DefaultConfig() *Config
```

Returns the default configuration.

**Returns:**
- `*Config`: Default configuration

```go
func ValidateConfig(config *Config) error
```

Validates a configuration for correctness.

**Parameters:**
- `config`: Configuration to validate

**Returns:**
- `error`: Validation errors

## Errors

### Error Variables

```go
var (
    // Configuration errors
    ErrInvalidConfig = errors.New("invalid configuration")
    
    // Lifecycle errors
    ErrHostNotStarted     = errors.New("host not started")
    ErrHostAlreadyStarted = errors.New("host already started")
    
    // Connection errors
    ErrConnectionFailed     = errors.New("connection failed")
    ErrPeerNotFound         = errors.New("peer not found")
    ErrNoBootstrapPeers     = errors.New("no bootstrap peers configured")
    
    // Stream errors
    ErrStreamCreationFailed = errors.New("stream creation failed")
    ErrProtocolNotSupported = errors.New("protocol not supported")
    
    // General errors
    ErrTimeout           = errors.New("operation timed out")
    ErrResourceExhausted = errors.New("resource exhausted")
)
```

### Error Types

#### ConfigError

```go
type ConfigError struct {
    Field   string
    Message string
}
```

Configuration validation error.

#### ConnectionError

```go
type ConnectionError struct {
    PeerID  string
    Address string
    Cause   error
}
```

Connection-specific error with context.

#### ProtocolError

```go
type ProtocolError struct {
    Protocol string
    Message  string
    Cause    error
}
```

Protocol-level error.

#### TransportError

```go
type TransportError struct {
    Transport string
    Message   string
    Cause     error
}
```

Transport-specific error.

### Error Checking Functions

```go
func IsConnectionError(err error) bool
func IsConfigError(err error) bool
func IsProtocolError(err error) bool
func IsTransportError(err error) bool
```

Check if an error is of a specific type.

## Metrics

### Metrics Structure

```go
type Metrics struct {
    // Connection metrics
    ActiveConnections   prometheus.Gauge
    TotalConnections    prometheus.Counter
    FailedConnections   prometheus.Counter
    ConnectionDuration  prometheus.Histogram
    ConnectionLatency   prometheus.Histogram
    
    // Peer metrics
    ConnectedPeers      prometheus.Gauge
    DiscoveredPeers     prometheus.Counter
    PeersByDirection    *prometheus.GaugeVec
    PeersByProtocol     *prometheus.GaugeVec
    
    // Stream metrics
    ActiveStreams       prometheus.Gauge
    TotalStreams        prometheus.Counter
    StreamDuration      prometheus.Histogram
    StreamsByProtocol   *prometheus.GaugeVec
    
    // Bandwidth metrics
    BytesSent           prometheus.Counter
    BytesReceived       prometheus.Counter
    BandwidthRate       *prometheus.GaugeVec
    MessageSize         *prometheus.HistogramVec
    
    // Protocol metrics
    ProtocolMessages    *prometheus.CounterVec
    ProtocolErrors      *prometheus.CounterVec
    ProtocolLatency     *prometheus.HistogramVec
    
    // Transport metrics
    TransportConnections *prometheus.GaugeVec
    TransportErrors      *prometheus.CounterVec
    TransportLatency     *prometheus.HistogramVec
    
    // DHT metrics
    DHTQueries          prometheus.Counter
    DHTQueryDuration    prometheus.Histogram
    DHTRoutingTableSize prometheus.Gauge
    
    // Resource metrics
    MemoryUsage         prometheus.Gauge
    GoroutineCount      prometheus.Gauge
    FileDescriptors     prometheus.Gauge
}
```

### Metric Names

All metrics are prefixed with `blackhole_`:

- `blackhole_active_connections`: Current active connections
- `blackhole_total_connections`: Total connections established
- `blackhole_failed_connections`: Failed connection attempts
- `blackhole_connection_duration_seconds`: Connection lifetime
- `blackhole_connection_latency_seconds`: Connection establishment time
- `blackhole_bytes_sent`: Total bytes sent
- `blackhole_bytes_received`: Total bytes received
- `blackhole_bandwidth_rate`: Current bandwidth rate
- `blackhole_protocol_messages`: Messages by protocol
- `blackhole_memory_usage_bytes`: Current memory usage
- `blackhole_goroutine_count`: Active goroutines

### Creating Metrics

```go
func NewMetrics() (*Metrics, error)
```

Creates and registers all metrics with Prometheus.

**Returns:**
- `*Metrics`: Metrics instance
- `error`: Error if registration fails

```go
func NewNoopMetrics() *Metrics
```

Creates no-op metrics for when monitoring is disabled.

**Returns:**
- `*Metrics`: No-op metrics instance

## Examples

### Basic Host Setup

```go
package main

import (
    "context"
    "log"
    "github.com/blackhole/implementation/pkg/network"
)

func main() {
    // Load configuration
    config, err := network.LoadConfig("config/default.yaml")
    if err != nil {
        log.Fatal(err)
    }
    
    // Create host
    ctx := context.Background()
    host, err := network.NewHost(ctx, config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Start host
    if err := host.Start(); err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Host started with ID: %s", host.ID())
    
    // Keep running
    select {}
}
```

### Protocol Handler

```go
// Define protocol
const ChatProtocol = "/blackhole/chat/1.0.0"

// Register handler
host.SetStreamHandler(ChatProtocol, func(stream network.Stream) {
    defer stream.Close()
    
    // Read message
    buf := make([]byte, 1024)
    n, err := stream.Read(buf)
    if err != nil {
        log.Printf("Read error: %v", err)
        return
    }
    
    log.Printf("Received: %s", string(buf[:n]))
    
    // Send response
    response := []byte("Hello from " + host.ID().String())
    if _, err := stream.Write(response); err != nil {
        log.Printf("Write error: %v", err)
    }
})
```

### Connecting to Peers

```go
// Parse peer address
peerAddr, err := multiaddr.NewMultiaddr(
    "/ip4/192.168.1.100/tcp/4001/p2p/QmPeerID...",
)
if err != nil {
    log.Fatal(err)
}

// Extract peer info
peerInfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
if err != nil {
    log.Fatal(err)
}

// Connect
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := host.Connect(ctx, *peerInfo); err != nil {
    log.Printf("Connection failed: %v", err)
    return
}

log.Printf("Connected to %s", peerInfo.ID)
```

### Opening Streams

```go
// Open stream to peer
stream, err := host.NewStream(
    context.Background(),
    peerID,
    ChatProtocol,
)
if err != nil {
    log.Printf("Failed to open stream: %v", err)
    return
}
defer stream.Close()

// Send message
message := []byte("Hello, peer!")
if _, err := stream.Write(message); err != nil {
    log.Printf("Failed to send: %v", err)
    return
}

// Read response
response := make([]byte, 1024)
n, err := stream.Read(response)
if err != nil {
    log.Printf("Failed to read: %v", err)
    return
}

log.Printf("Response: %s", string(response[:n]))
```

### Monitoring Connections

```go
// Get all connections
connections := host.ConnectionManager().GetConnections()

for peerID, info := range connections {
    log.Printf("Peer: %s", peerID)
    log.Printf("  Connected: %s", info.ConnectedAt)
    log.Printf("  Direction: %s", info.Direction)
    log.Printf("  Streams: %d", info.Streams)
    log.Printf("  Bytes Sent: %d", info.BytesSent)
    log.Printf("  Bytes Received: %d", info.BytesReceived)
    log.Printf("  Latency: %s", info.Latency)
    log.Printf("  Healthy: %v", info.Healthy)
}
```

### Custom Configuration

```go
// Create custom config
config := &network.Config{
    Network: network.NetworkConfig{
        ListenAddresses: []string{
            "/ip4/0.0.0.0/tcp/5001",
            "/ip4/0.0.0.0/udp/5001/quic-v1",
        },
        ConnectionManager: &network.ConnectionManagerConf{
            HighWater:   500,
            LowWater:    300,
            GracePeriod: 30 * time.Second,
        },
        Transports: &network.TransportConfig{
            TCP: &network.TCPConfig{
                Enabled:   true,
                PortReuse: true,
                KeepAlive: 30 * time.Second,
            },
            QUIC: &network.QUICConfig{
                Enabled:        true,
                MaxIdleTimeout: 60 * time.Second,
                MaxStreams:     500,
            },
        },
    },
    Metrics: network.MetricsConfig{
        Enabled: true,
        Address: ":9091",
        Path:    "/metrics",
    },
}

// Validate config
if err := network.ValidateConfig(config); err != nil {
    log.Fatal(err)
}

// Create host with custom config
host, err := network.NewHost(context.Background(), config)
```

### Graceful Shutdown

```go
// Setup signal handling
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

// Start host
if err := host.Start(); err != nil {
    log.Fatal(err)
}

// Wait for signal
<-sigChan

log.Println("Shutting down...")

// Graceful shutdown
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := host.Stop(); err != nil {
    log.Printf("Shutdown error: %v", err)
}

log.Println("Shutdown complete")
```