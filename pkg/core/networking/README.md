# networking Plugin

P2P networking with libp2p for node communication

## Overview

The networking plugin provides the foundational P2P communication layer for the Blackhole Network using libp2p. It handles:

- Peer discovery and connection management
- Direct peer-to-peer messaging
- Broadcast messaging via pubsub
- Network health monitoring
- Automatic peer cleanup
- Multiple discovery mechanisms (DHT, mDNS, Bootstrap)

## Configuration

```yaml
networking:
  port: 4001  # P2P listen port (default: 4001)
  bootstrap_peers:  # List of bootstrap peer addresses
    - "/ip4/127.0.0.1/tcp/4001/p2p/QmPeerId1"
    - "/ip4/127.0.0.1/tcp/4002/p2p/QmPeerId2"
  max_connections: 50  # Maximum number of peer connections (default: 50)
  connection_timeout: 30s  # Connection timeout duration
  enable_auto_relay: true  # Enable AutoRelay for NAT traversal (default: true)
```

### AutoRelay Configuration

AutoRelay is **enabled by default** in production to ensure nodes behind NAT can participate fully in the network. It allows nodes to:

- Receive incoming connections even when behind NAT/firewall
- Use relay nodes to forward traffic
- Automatically discover relay nodes via DHT

For testing or nodes with public IPs, you can disable AutoRelay:
```yaml
networking:
  enable_auto_relay: false
```

### Peer Discovery

The plugin uses multiple mechanisms to discover peers:

1. **mDNS (Local Network Discovery)**
   - Automatically finds peers on the same network
   - No configuration needed
   - Works without bootstrap nodes
   - Ideal for development and local clusters

2. **Bootstrap Peers**
   - Configured list of known peers
   - Provides initial network entry points
   - Recommended for production

3. **DHT (Kademlia)**
   - Discovers peers after initial connection
   - Finds relay nodes for AutoRelay
   - Self-organizing and decentralized

This multi-pronged approach ensures nodes can join the network even without bootstrap peers (via mDNS), while still supporting global discovery (via DHT).

## Usage

The networking plugin is automatically loaded by the orchestrator.

## Development

### Running Tests

```bash
go test -v ./pkg/core/networking/
```

### Benchmarks

```bash
go test -bench=. ./pkg/core/networking/
```

## API

The networking plugin implements the `NetworkService` interface:

### Methods

```go
// Send sends data to a specific peer
Send(ctx context.Context, peerID string, data []byte) error

// Broadcast sends data to all connected peers  
Broadcast(ctx context.Context, data []byte) error

// GetPeers returns list of connected peers
GetPeers(ctx context.Context) ([]string, error)

// GetLatency returns latency to a specific peer
GetLatency(ctx context.Context, peerID string) (time.Duration, error)

// Subscribe to messages from peers
Subscribe(ctx context.Context, handler func(peerID string, data []byte)) error
```

### Events

The plugin publishes these events:

- `network.peer.connected` - When a new peer connects
- `network.peer.disconnected` - When a peer disconnects

## Metrics

- `peers_connected` (gauge) - Number of connected peers
- `messages_sent` (counter) - Total messages sent
- `messages_received` (counter) - Total messages received  
- `message_latency` (histogram) - Message latency distribution

## Performance

- Supports up to 50 concurrent peer connections by default
- 1MB maximum message size for direct messages
- Automatic peer cleanup every 30 seconds
- 5-minute peer timeout for inactive connections

## Dependencies

- libp2p - P2P networking stack
- libp2p-kad-dht - Distributed hash table for peer discovery
- libp2p-pubsub - Publish/subscribe for broadcasts
- multiformats - Multiaddress support

## License

MIT