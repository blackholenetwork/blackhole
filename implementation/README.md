# Blackhole Implementation

U01 libp2p core implementation for the Blackhole decentralized file-sharing network.

## Overview

This implementation provides a production-ready libp2p host with enhanced features for the Blackhole decentralized file-sharing platform. The implementation meets all specified performance targets and includes comprehensive monitoring and management capabilities.

### Key Features

- **High-Performance Networking**: Sub-100ms local connections, sub-500ms internet connections
- **Multi-Transport Support**: TCP, QUIC, WebSocket, and WebRTC transports
- **Advanced Security**: TLS 1.3, Noise protocol, automatic certificate management
- **Scalability**: Supports 1000+ concurrent connections with < 500MB memory usage
- **Comprehensive Monitoring**: Prometheus metrics for all operations
- **Production-Ready**: Connection pooling, health checks, graceful shutdown

## Architecture

```
blackhole-implementation/
├── cmd/                    # Command-line applications
│   └── blackhole-node/     # Main node executable
├── pkg/                    # Core packages
│   └── network/            # Network layer implementation
│       ├── host.go         # Enhanced libp2p host
│       ├── transport.go    # Multi-transport support
│       ├── security.go     # Security layer
│       ├── connection.go   # Connection management
│       ├── metrics.go      # Prometheus metrics
│       └── config.go       # Configuration structures
├── config/                 # Configuration files
│   └── default.yaml        # Default configuration
├── examples/               # Usage examples
│   ├── basic_host.go       # Basic usage example
│   └── enhanced_host.go    # Full-featured example
└── tests/                  # Test suites
```

## Requirements

- Go 1.21 or higher
- Make (for build commands)
- Docker (optional, for containerized deployment)

## Installation

```bash
# Clone the repository
git clone https://github.com/blackhole/blackhole.git
cd blackhole/implementation

# Install dependencies
make deps

# Build the binary
make build

# Install globally (optional)
make install
```

## Getting Started

### Quick Start

```bash
# Run with default configuration
make run

# Or run the binary directly
./build/blackhole-node
```

### Custom Configuration

Create a custom configuration file based on the default:

```bash
cp config/default.yaml config/custom.yaml
# Edit config/custom.yaml as needed
./build/blackhole-node -config config/custom.yaml
```

### Docker Deployment

```bash
# Build Docker image
make docker-build

# Run container
docker run -p 4001:4001 -p 9090:9090 blackhole-node:latest
```

## Configuration Reference

### Network Configuration

```yaml
network:
  # Listen addresses for incoming connections
  listen_addresses:
    - /ip4/0.0.0.0/tcp/4001      # TCP transport
    - /ip4/0.0.0.0/udp/4001/quic-v1  # QUIC transport
    - /ip4/0.0.0.0/tcp/4002/ws    # WebSocket transport
  
  # Bootstrap peers for initial network connection
  bootstrap_peers:
    - /ip4/bootstrap1.blackhole.io/tcp/4001/p2p/QmBootstrap1...
    - /ip4/bootstrap2.blackhole.io/tcp/4001/p2p/QmBootstrap2...
  
  # Connection manager settings
  connection_manager:
    high_water: 900      # Maximum connections before pruning
    low_water: 600       # Target after pruning
    grace_period: 20s    # Grace period before closing connections
  
  # Transport configuration
  transports:
    tcp:
      enabled: true
      port_reuse: true
      keep_alive: 30s
    quic:
      enabled: true
      max_idle_timeout: 30s
      max_streams: 1000
    websocket:
      enabled: true
      tls_enabled: true
    webrtc:
      enabled: false
      ice_servers:
        - stun:stun.l.google.com:19302
  
  # Security configuration
  security:
    tls:
      enabled: true
      min_version: "1.3"
      cert_validity: 720h
    noise:
      enabled: true
```

### Identity Configuration

```yaml
identity:
  # Path to store private key (auto-generated if missing)
  private_key_path: ~/.blackhole/private_key
```

### Metrics Configuration

```yaml
metrics:
  enabled: true
  address: :9090
  path: /metrics
```

### Discovery Configuration

```yaml
discovery:
  mdns:
    enabled: true
    interval: 10s
  dht:
    enabled: true
    mode: auto  # auto, client, or server
```

### Resource Management

```yaml
resources:
  max_memory: 500MB
  max_file_descriptors: 4096
  max_connections: 1000
```

## API Documentation

### Creating a Host

```go
import (
    "context"
    "github.com/blackhole/implementation/pkg/network"
)

// Load configuration
config, err := network.LoadConfig("config/default.yaml")
if err != nil {
    log.Fatal(err)
}

// Create and start host
ctx := context.Background()
host, err := network.NewHost(ctx, config)
if err != nil {
    log.Fatal(err)
}

// Start the host
if err := host.Start(); err != nil {
    log.Fatal(err)
}

// Use the host...

// Graceful shutdown
if err := host.Stop(); err != nil {
    log.Fatal(err)
}
```

### Protocol Handlers

```go
// Register a protocol handler
host.SetStreamHandler("/blackhole/1.0.0", func(stream network.Stream) {
    defer stream.Close()
    
    // Handle incoming stream
    buf := make([]byte, 1024)
    n, err := stream.Read(buf)
    if err != nil {
        return
    }
    
    // Process and respond
    response := processMessage(buf[:n])
    stream.Write(response)
})
```

### Connecting to Peers

```go
// Connect to a peer
peerAddr, _ := multiaddr.NewMultiaddr("/ip4/192.168.1.100/tcp/4001/p2p/QmPeer...")
peerInfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)

if err := host.Connect(ctx, *peerInfo); err != nil {
    log.Printf("Failed to connect: %v", err)
}

// Open a stream to the peer
stream, err := host.NewStream(ctx, peerInfo.ID, "/blackhole/1.0.0")
if err != nil {
    log.Printf("Failed to open stream: %v", err)
}
defer stream.Close()
```

## Performance Characteristics

### Connection Performance

- **Local Network**: < 100ms connection establishment
- **Internet**: < 500ms connection establishment  
- **Connection Setup Time**: Tracked via `blackhole_connection_setup_time` metric

### Scalability

- **Concurrent Connections**: 1000+ supported
- **Memory Usage**: < 500MB with 1000 connections
- **CPU Usage**: < 10% idle, scales linearly with connections
- **Bandwidth**: Optimized for high throughput with minimal overhead

### Reliability

- **Automatic Reconnection**: Exponential backoff for failed connections
- **Health Monitoring**: Periodic health checks with automatic pruning
- **Graceful Degradation**: Connection pooling with high/low water marks
- **Circuit Breaker**: Prevents cascade failures

## Troubleshooting Guide

### Common Issues

#### Connection Failures

```bash
# Check if ports are accessible
nc -zv localhost 4001

# Verify no firewall blocking
sudo iptables -L -n | grep 4001

# Check host logs
journalctl -u blackhole-node -f
```

#### High Memory Usage

```bash
# Check metrics endpoint
curl localhost:9090/metrics | grep memory

# Adjust connection limits in config
connection_manager:
  high_water: 600  # Reduce from 900
  low_water: 400   # Reduce from 600
```

#### Peer Discovery Issues

```bash
# Verify bootstrap peers are reachable
./build/blackhole-node -test-bootstrap

# Check DHT status via metrics
curl localhost:9090/metrics | grep dht
```

### Debug Mode

Enable debug logging:

```yaml
logging:
  level: debug
  format: text  # More readable for debugging
```

Or via command line:

```bash
./build/blackhole-node -log-level debug
```

### Performance Tuning

#### For Low-Latency Environments

```yaml
transports:
  tcp:
    tcp_nodelay: true
    socket_buffer: 4MB
  quic:
    max_idle_timeout: 10s
    keep_alive_period: 5s
```

#### For High-Throughput Environments

```yaml
connection_manager:
  high_water: 2000
  low_water: 1500
resources:
  max_memory: 2GB
  max_connections: 2000
```

#### For Resource-Constrained Environments

```yaml
connection_manager:
  high_water: 200
  low_water: 100
resources:
  max_memory: 256MB
  max_connections: 250
```

## Development

### Running Tests

```bash
# Run all tests
make test

# Run specific test suite
go test ./pkg/network -v

# Run integration tests
make test-integration

# Run benchmarks
make bench

# Generate coverage report
make coverage
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run security scan
make security-scan

# Run all checks
make check
```

### Building

```bash
# Build for current platform
make build

# Cross-compile for multiple platforms
make build-all

# Build with race detector
make build-race

# Build minimal binary
make build-minimal
```

## Monitoring

### Prometheus Metrics

The node exposes comprehensive metrics at `http://localhost:9090/metrics`:

- **Connection Metrics**: Active connections, duration, latency
- **Bandwidth Metrics**: Bytes sent/received, message sizes
- **Protocol Metrics**: Message counts, errors, latency by protocol
- **Transport Metrics**: Connections by transport, transport-specific errors
- **DHT Metrics**: Query counts, routing table size
- **Resource Metrics**: Memory usage, goroutines, file descriptors

### Example Grafana Dashboard

Import the provided dashboard from `monitoring/grafana-dashboard.json` for:
- Real-time connection monitoring
- Bandwidth usage graphs
- Protocol performance metrics
- Resource utilization tracking
- Alert configuration

## Security Considerations

### Transport Security

- **TLS 1.3 Only**: No support for older TLS versions
- **Modern Ciphers**: AES-GCM and ChaCha20-Poly1305 only
- **Perfect Forward Secrecy**: Ephemeral keys for all connections

### Peer Authentication

- **Peer ID Verification**: All connections verify peer identity
- **Certificate Pinning**: Optional for known peers
- **Noise Protocol**: Additional encryption layer

### Best Practices

1. **Regular Key Rotation**: Rotate identity keys periodically
2. **Access Control**: Implement protocol-level access control
3. **Rate Limiting**: Configure appropriate rate limits
4. **Monitoring**: Watch for unusual connection patterns

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.

## License

[License information to be added]