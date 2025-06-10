# U01 libp2p Core Implementation - Requirements Summary

## Overview

This document summarizes the key requirements extracted from the technical design documents and research for implementing Unit U01: libp2p Core Setup. This unit forms the foundational networking layer for the Blackhole platform.

## 1. Technical Requirements

### 1.1 Core libp2p Configuration

**Version Requirements:**
- libp2p v0.33.0 or higher
- go-libp2p-core v0.20.1
- Compatible module versions for all transports and security protocols

**Host Requirements:**
- Multi-transport host initialization
- Peer identity management (Ed25519 keypairs)
- Connection lifecycle management
- Resource management with configurable limits
- Graceful shutdown capabilities

### 1.2 Transport Protocols

**TCP Transport (Required):**
- Standard TCP/IP connections
- Port reuse capability for efficient resource utilization
- Support for both IPv4 and IPv6
- Connection upgrade for security protocols
- Default port: 4001

**QUIC Transport (Required):**
- UDP-based multiplexed connections
- Built-in encryption and congestion control
- Reduced connection establishment latency (sub-100ms local)
- Better performance over lossy networks
- Default port: 4001/udp

**WebSocket Transport (Required):**
- HTTP/HTTPS upgrade mechanism
- Browser compatibility for web-based peers
- Proxy and firewall traversal capabilities
- TLS support for secure WebSockets (wss://)
- Default port: 4002

**WebRTC Transport (Optional but Recommended):**
- Direct browser-to-browser connections
- STUN/TURN for NAT traversal
- DataChannel for application data
- Built-in encryption (DTLS-SRTP)
- Default STUN servers: Google public STUN

### 1.3 Security Requirements

**TLS 1.3 (Required):**
- Latest TLS protocol version only
- Perfect forward secrecy
- Reduced handshake latency
- Strong cipher suites only (no legacy support)

**Noise Protocol (Required):**
- Modern cryptographic framework
- Mutual authentication
- Forward secrecy
- Lightweight alternative to TLS
- Preferred for performance-critical connections

**General Security:**
- No plaintext connections allowed
- Mandatory encryption for all transports
- Peer authentication via Ed25519 signatures
- Secure key storage with optional persistence

### 1.4 Multiplexing Requirements

**Yamux (Primary):**
- Flow control and backpressure
- Connection health monitoring
- Better for high-throughput scenarios
- Default choice for performance

**Mplex (Secondary):**
- Lightweight stream multiplexer
- Low overhead
- Good for resource-constrained environments
- Fallback option

## 2. Configuration Requirements

### 2.1 Configuration System

**Structure:**
- YAML-based configuration files
- Environment variable overrides
- Sensible production defaults
- Hot-reload capability (future enhancement)

**Key Configuration Areas:**
- Listen addresses (multiaddr format)
- Transport enable/disable flags
- Security protocol selection
- Connection manager limits
- Metrics collection settings

### 2.2 Connection Management

**Connection Manager Settings:**
- Low water mark: 100 connections (default)
- High water mark: 400 connections (default)
- Grace period: 20 seconds (default)
- Pruning interval: 30 seconds

**Connection Health Monitoring:**
- Idle connection timeout: 5 minutes
- High latency threshold: 1 second
- Automatic pruning of unhealthy connections
- Connection retry with exponential backoff

## 3. Performance Targets

### 3.1 Connection Establishment

**Local Network:**
- Sub-100ms connection establishment
- 99% success rate
- Minimal CPU overhead

**Internet Connections:**
- Sub-500ms connection establishment
- 95% success rate in good conditions
- Graceful degradation with network issues

### 3.2 Throughput

**Local Network:**
- Minimum 10MB/s data transfer
- Support for 1000+ concurrent connections
- Low latency (<10ms)

**Internet:**
- Minimum 1MB/s data transfer
- Adaptive to network conditions
- Efficient bandwidth utilization

### 3.3 Resource Usage

**Memory:**
- Under 500MB for 1000 connections
- Efficient buffer management
- Configurable limits

**CPU:**
- Under 20% usage during normal operation
- Efficient cryptographic operations
- Minimal protocol overhead

**File Descriptors:**
- Proper management and limits
- Graceful handling at limits
- Connection recycling

## 4. NAT Traversal Requirements

### 4.1 Methods

**AutoNAT:**
- Automatic NAT detection
- Public reachability testing
- ~75% success rate

**Circuit Relay:**
- Fallback for unreachable peers
- 100% connectivity guarantee
- Relay node discovery

**Hole Punching:**
- Direct connection upgrade
- DCUtR protocol support
- Reduced relay dependency

### 4.2 Success Metrics

- 70-80% direct connection success (IPFS baseline)
- 100% connectivity with relay fallback
- Automatic transport selection
- Minimal user configuration

## 5. Integration Points

### 5.1 Dependencies on U01

U01 provides the foundation for:
- **U02**: Kademlia DHT Implementation (peer discovery)
- **U03**: NAT Traversal & Connectivity (enhanced traversal)
- **U05**: GossipSub Messaging (pub/sub layer)
- **U07**: Network Security Layer (enhanced security)
- **All P2P Services**: Storage, compute, CDN, bandwidth pooling

### 5.2 API Requirements

**Host Interface:**
```go
- NewHost(ctx, config) (*Host, error)
- Start() error
- Stop() error
- Connect(ctx, peerInfo) error
- NewStream(ctx, peerID, protocol) (Stream, error)
- SetStreamHandler(protocol, handler)
```

**Metrics Interface:**
```go
- GetMetrics() HostMetrics
- GetTransportStats() map[string]*TransportStats
- GetConnectionInfo(peerID) (*ConnectionInfo, error)
```

## 6. Monitoring & Observability

### 6.1 Metrics Requirements

**Prometheus Metrics:**
- Host status (running/stopped)
- Peer count and connection metrics
- Bandwidth usage (in/out)
- Transport-specific statistics
- Security protocol usage
- Error rates and types

**Metric Collection:**
- 30-second default interval
- Prometheus-compatible format
- Grafana dashboard support
- Real-time monitoring capability

### 6.2 Logging Requirements

**Log Levels:**
- Debug: Connection attempts, protocol negotiations
- Info: Host startup, transport enablement
- Warn: Security issues, connection failures
- Error: Critical failures, resource exhaustion

**Structured Logging:**
- JSON format support
- Contextual information
- Correlation IDs
- Performance metrics

## 7. Testing Requirements

### 7.1 Unit Tests

**Coverage Areas:**
- Host creation and lifecycle
- Each transport protocol
- Security handshakes
- Connection management
- Error handling

**Coverage Target:**
- Minimum 80% code coverage
- All critical paths tested
- Edge case handling

### 7.2 Integration Tests

**Test Scenarios:**
- Multi-transport connectivity
- NAT traversal simulation
- Security protocol negotiation
- Load testing (1000+ connections)
- Network fault injection

### 7.3 Performance Benchmarks

**Benchmark Areas:**
- Connection establishment time
- Stream creation overhead
- Data transfer throughput
- Resource usage patterns
- Concurrent connection limits

## 8. Error Handling Requirements

### 8.1 Error Categories

**Configuration Errors:**
- Invalid addresses
- Missing transports
- Security misconfigurations

**Runtime Errors:**
- Connection failures
- Transport errors
- Resource exhaustion
- Security violations

### 8.2 Recovery Mechanisms

**Automatic Recovery:**
- Connection retry with backoff
- Transport fallback
- Graceful degradation
- Circuit breaker patterns

**Manual Intervention:**
- Clear error messages
- Actionable diagnostics
- Recovery procedures
- Configuration guidance

## 9. Security Considerations

### 9.1 Threat Model

**Protected Against:**
- Man-in-the-middle attacks
- Connection hijacking
- DDoS attacks
- Resource exhaustion

**Security Measures:**
- Mandatory encryption
- Peer authentication
- Rate limiting
- Connection limits

### 9.2 Key Management

**Requirements:**
- Secure key generation
- Optional key persistence
- Key rotation support
- Hardware security module compatibility

## 10. Future Enhancements

### 10.1 Planned Features

**Phase 2:**
- Additional transports (QUIC-v2, HTTP/3)
- Enhanced security protocols
- Connection pooling
- Advanced routing

**Phase 3:**
- Custom protocol support
- Performance optimizations
- Enhanced monitoring
- Cloud-native integrations

### 10.2 Extensibility

**Design Considerations:**
- Modular transport system
- Pluggable security protocols
- Custom metrics collectors
- Protocol negotiation framework

## Summary

Unit U01 must deliver a production-ready libp2p host that:
1. Supports multiple transport protocols for maximum connectivity
2. Implements strong security with modern protocols
3. Handles NAT traversal gracefully
4. Provides comprehensive monitoring and metrics
5. Manages resources efficiently
6. Integrates seamlessly with other Blackhole components

The implementation should prioritize stability, security, and performance while maintaining flexibility for future enhancements.