# Unit 33: WireGuard Tunnels

## Overview
WireGuard VPN implementation for secure peer-to-peer tunneling in the BlackHole network. Provides high-performance, cryptographically sound tunnels between nodes.

## Implementation

### Core WireGuard Manager

```go
package wireguard

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "net"
    "sync"
    "time"

    "golang.zx2c4.com/wireguard/wgctrl"
    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TunnelManager manages WireGuard tunnels
type TunnelManager struct {
    client      *wgctrl.Client
    device      string
    privateKey  wgtypes.Key
    listenPort  int
    peers       map[string]*Peer
    mu          sync.RWMutex
    routes      *RouteManager
    monitor     *TunnelMonitor
}

// Peer represents a WireGuard peer
type Peer struct {
    NodeID           string
    PublicKey        wgtypes.Key
    Endpoint         *net.UDPAddr
    AllowedIPs       []net.IPNet
    LastHandshake    time.Time
    BytesSent        uint64
    BytesReceived    uint64
    PersistentKeep   time.Duration
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(device string, listenPort int) (*TunnelManager, error) {
    client, err := wgctrl.New()
    if err != nil {
        return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
    }

    privateKey, err := generatePrivateKey()
    if err != nil {
        return nil, fmt.Errorf("failed to generate private key: %w", err)
    }

    tm := &TunnelManager{
        client:     client,
        device:     device,
        privateKey: privateKey,
        listenPort: listenPort,
        peers:      make(map[string]*Peer),
        routes:     NewRouteManager(),
        monitor:    NewTunnelMonitor(),
    }

    if err := tm.initialize(); err != nil {
        return nil, err
    }

    return tm, nil
}

// Initialize sets up the WireGuard interface
func (tm *TunnelManager) initialize() error {
    // Create or configure the interface
    config := wgtypes.Config{
        PrivateKey:   &tm.privateKey,
        ListenPort:   &tm.listenPort,
        ReplacePeers: true,
    }

    if err := tm.client.ConfigureDevice(tm.device, config); err != nil {
        return fmt.Errorf("failed to configure device: %w", err)
    }

    // Start monitoring
    go tm.monitor.Start(tm)

    return nil
}

// AddPeer adds a new peer to the tunnel
func (tm *TunnelManager) AddPeer(nodeID string, publicKey string, endpoint string, allowedIPs []string) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    // Parse public key
    key, err := wgtypes.ParseKey(publicKey)
    if err != nil {
        return fmt.Errorf("invalid public key: %w", err)
    }

    // Parse endpoint
    udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
    if err != nil {
        return fmt.Errorf("invalid endpoint: %w", err)
    }

    // Parse allowed IPs
    var ipNets []net.IPNet
    for _, ip := range allowedIPs {
        _, ipNet, err := net.ParseCIDR(ip)
        if err != nil {
            return fmt.Errorf("invalid allowed IP: %w", err)
        }
        ipNets = append(ipNets, *ipNet)
    }

    peer := &Peer{
        NodeID:         nodeID,
        PublicKey:      key,
        Endpoint:       udpAddr,
        AllowedIPs:     ipNets,
        PersistentKeep: 25 * time.Second,
    }

    // Configure peer
    peerConfig := wgtypes.PeerConfig{
        PublicKey:                   key,
        Endpoint:                    udpAddr,
        PersistentKeepaliveInterval: &peer.PersistentKeep,
        AllowedIPs:                  ipNets,
        ReplaceAllowedIPs:           true,
    }

    config := wgtypes.Config{
        Peers: []wgtypes.PeerConfig{peerConfig},
    }

    if err := tm.client.ConfigureDevice(tm.device, config); err != nil {
        return fmt.Errorf("failed to configure peer: %w", err)
    }

    tm.peers[nodeID] = peer

    // Update routing
    tm.routes.AddPeerRoutes(nodeID, ipNets)

    return nil
}

// RemovePeer removes a peer from the tunnel
func (tm *TunnelManager) RemovePeer(nodeID string) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    peer, exists := tm.peers[nodeID]
    if !exists {
        return fmt.Errorf("peer not found")
    }

    // Remove peer configuration
    config := wgtypes.Config{
        Peers: []wgtypes.PeerConfig{
            {
                PublicKey: peer.PublicKey,
                Remove:    true,
            },
        },
    }

    if err := tm.client.ConfigureDevice(tm.device, config); err != nil {
        return fmt.Errorf("failed to remove peer: %w", err)
    }

    delete(tm.peers, nodeID)

    // Update routing
    tm.routes.RemovePeerRoutes(nodeID)

    return nil
}

// GetPublicKey returns the public key for this node
func (tm *TunnelManager) GetPublicKey() string {
    publicKey := tm.privateKey.PublicKey()
    return publicKey.String()
}

// TunnelMonitor monitors tunnel health and performance
type TunnelMonitor struct {
    metrics     *TunnelMetrics
    alerts      chan TunnelAlert
    stopCh      chan struct{}
}

// TunnelMetrics tracks tunnel performance
type TunnelMetrics struct {
    mu              sync.RWMutex
    peerMetrics     map[string]*PeerMetrics
    totalBandwidth  BandwidthStats
    handshakeTimes  map[string]time.Duration
}

// PeerMetrics tracks per-peer performance
type PeerMetrics struct {
    Latency          time.Duration
    PacketLoss       float64
    Throughput       float64
    LastUpdate       time.Time
    HandshakeLatency time.Duration
}

// Monitor tunnel health
func (tm *TunnelMonitor) Start(manager *TunnelManager) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            tm.checkTunnelHealth(manager)
            tm.updateMetrics(manager)
        case <-tm.stopCh:
            return
        }
    }
}

// RouteManager manages routing for WireGuard tunnels
type RouteManager struct {
    routes map[string][]net.IPNet
    mu     sync.RWMutex
}

// NewRouteManager creates a new route manager
func NewRouteManager() *RouteManager {
    return &RouteManager{
        routes: make(map[string][]net.IPNet),
    }
}

// AddPeerRoutes adds routes for a peer
func (rm *RouteManager) AddPeerRoutes(nodeID string, routes []net.IPNet) {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    rm.routes[nodeID] = routes
}

// Performance optimizer for WireGuard tunnels
type TunnelOptimizer struct {
    manager    *TunnelManager
    config     *OptimizationConfig
    monitor    *TunnelMonitor
}

// OptimizationConfig contains optimization parameters
type OptimizationConfig struct {
    MTUSize              int
    SendBuffer           int
    ReceiveBuffer        int
    HandshakeRetries     int
    KeepaliveInterval    time.Duration
    RekeyAfterMessages   uint64
    RekeyAfterTime       time.Duration
    AdaptiveMTU          bool
    CongestionControl    bool
}

// OptimizeTunnel applies performance optimizations
func (to *TunnelOptimizer) OptimizeTunnel(nodeID string) error {
    peer, exists := to.manager.peers[nodeID]
    if !exists {
        return fmt.Errorf("peer not found")
    }

    // Get current metrics
    metrics := to.monitor.metrics.GetPeerMetrics(nodeID)
    
    // Adjust MTU based on packet loss
    if to.config.AdaptiveMTU && metrics.PacketLoss > 0.01 {
        to.adjustMTU(peer, metrics)
    }

    // Adjust keepalive based on handshake latency
    if metrics.HandshakeLatency > 5*time.Second {
        to.adjustKeepalive(peer)
    }

    // Apply congestion control
    if to.config.CongestionControl {
        to.applyCongestionControl(peer, metrics)
    }

    return nil
}

// Key exchange handler
type KeyExchange struct {
    manager    *TunnelManager
    dht        DHT
    crypto     *CryptoManager
}

// ExchangeKeys performs secure key exchange with a peer
func (ke *KeyExchange) ExchangeKeys(nodeID string) error {
    // Generate ephemeral keypair for exchange
    ephemeralPriv, ephemeralPub := generateKeyPair()
    
    // Create key exchange request
    request := &KeyExchangeRequest{
        NodeID:       ke.manager.GetNodeID(),
        PublicKey:    ke.manager.GetPublicKey(),
        EphemeralKey: ephemeralPub,
        Timestamp:    time.Now(),
        Signature:    ke.crypto.Sign(ephemeralPub),
    }

    // Send via DHT
    response, err := ke.dht.SendKeyExchange(nodeID, request)
    if err != nil {
        return fmt.Errorf("key exchange failed: %w", err)
    }

    // Verify response
    if !ke.crypto.Verify(response.PublicKey, response.Signature) {
        return fmt.Errorf("invalid key exchange response")
    }

    // Derive shared secret for additional security
    sharedSecret := ke.crypto.DeriveSharedSecret(ephemeralPriv, response.EphemeralKey)
    
    // Add peer with verified key
    return ke.manager.AddPeer(
        nodeID,
        response.PublicKey,
        response.Endpoint,
        response.AllowedIPs,
    )
}

// Helper functions
func generatePrivateKey() (wgtypes.Key, error) {
    key, err := wgtypes.GeneratePrivateKey()
    if err != nil {
        return wgtypes.Key{}, err
    }
    return key, nil
}

func generateKeyPair() (privateKey, publicKey []byte) {
    private := make([]byte, 32)
    rand.Read(private)
    
    // Curve25519 scalar multiplication
    public := scalarMultBase(private)
    
    return private, public
}

// MTU discovery for optimal performance
type MTUDiscovery struct {
    manager  *TunnelManager
    results  map[string]int
    mu       sync.RWMutex
}

// DiscoverMTU finds optimal MTU for a peer
func (md *MTUDiscovery) DiscoverMTU(nodeID string) (int, error) {
    md.mu.Lock()
    defer md.mu.Unlock()

    // Binary search for optimal MTU
    low, high := 1280, 1500
    optimal := low

    for low <= high {
        mid := (low + high) / 2
        
        if md.testMTU(nodeID, mid) {
            optimal = mid
            low = mid + 1
        } else {
            high = mid - 1
        }
    }

    md.results[nodeID] = optimal
    return optimal, nil
}

// Tunnel state machine
type TunnelState int

const (
    StateInit TunnelState = iota
    StateHandshaking
    StateConnected
    StateRekeying
    StateDisconnected
)

// TunnelStateMachine manages tunnel state transitions
type TunnelStateMachine struct {
    state      TunnelState
    nodeID     string
    manager    *TunnelManager
    transitions chan StateTransition
}

// StateTransition represents a state change
type StateTransition struct {
    From   TunnelState
    To     TunnelState
    Reason string
    Time   time.Time
}

// TransitionTo changes tunnel state
func (tsm *TunnelStateMachine) TransitionTo(newState TunnelState, reason string) error {
    tsm.transitions <- StateTransition{
        From:   tsm.state,
        To:     newState,
        Reason: reason,
        Time:   time.Now(),
    }
    
    tsm.state = newState
    
    // Handle state-specific actions
    switch newState {
    case StateHandshaking:
        return tsm.manager.initiateHandshake(tsm.nodeID)
    case StateRekeying:
        return tsm.manager.rekeyPeer(tsm.nodeID)
    case StateDisconnected:
        return tsm.manager.cleanupPeer(tsm.nodeID)
    }
    
    return nil
}
```

### Performance Optimization

```go
package wireguard

import (
    "context"
    "sync"
    "time"
)

// PerformanceOptimizer optimizes WireGuard tunnel performance
type PerformanceOptimizer struct {
    manager     *TunnelManager
    metrics     *MetricsCollector
    optimizer   *AdaptiveOptimizer
    scheduler   *OptimizationScheduler
}

// AdaptiveOptimizer adapts tunnel parameters based on conditions
type AdaptiveOptimizer struct {
    parameters  *TunnelParameters
    history     *PerformanceHistory
    ml          *MLOptimizer
}

// TunnelParameters contains tunable parameters
type TunnelParameters struct {
    MTU                 int
    SendBuffer          int
    ReceiveBuffer       int
    KeepaliveInterval   time.Duration
    HandshakeTimeout    time.Duration
    RekeyInterval       time.Duration
    QueueSize           int
    BatchSize           int
}

// OptimizeForLatency optimizes tunnel for low latency
func (ao *AdaptiveOptimizer) OptimizeForLatency(nodeID string) *TunnelParameters {
    params := &TunnelParameters{
        MTU:               1380,  // Smaller for lower latency
        SendBuffer:        65536,
        ReceiveBuffer:     65536,
        KeepaliveInterval: 10 * time.Second,
        HandshakeTimeout:  5 * time.Second,
        QueueSize:         64,
        BatchSize:         1,  // No batching for lowest latency
    }
    
    // Apply ML predictions if available
    if prediction := ao.ml.PredictOptimalParams(nodeID, "latency"); prediction != nil {
        params.merge(prediction)
    }
    
    return params
}

// OptimizeForThroughput optimizes tunnel for high throughput
func (ao *AdaptiveOptimizer) OptimizeForThroughput(nodeID string) *TunnelParameters {
    params := &TunnelParameters{
        MTU:               1500,  // Maximum for throughput
        SendBuffer:        262144,
        ReceiveBuffer:     262144,
        KeepaliveInterval: 25 * time.Second,
        HandshakeTimeout:  10 * time.Second,
        QueueSize:         256,
        BatchSize:         32,  // Batch for efficiency
    }
    
    // Adjust based on link characteristics
    if metrics := ao.history.GetLatestMetrics(nodeID); metrics != nil {
        params.adjustForLink(metrics)
    }
    
    return params
}

// CongestionController implements TCP-friendly congestion control
type CongestionController struct {
    cwnd        int     // Congestion window
    ssthresh    int     // Slow start threshold
    rtt         time.Duration
    rttVar      time.Duration
    inSlowStart bool
    losses      int
}

// UpdateWindow updates congestion window based on ACK/loss
func (cc *CongestionController) UpdateWindow(acked bool, rtt time.Duration) {
    if acked {
        cc.updateRTT(rtt)
        
        if cc.inSlowStart {
            cc.cwnd += 1  // Exponential growth
            if cc.cwnd >= cc.ssthresh {
                cc.inSlowStart = false
            }
        } else {
            cc.cwnd += 1 / cc.cwnd  // Linear growth (congestion avoidance)
        }
    } else {
        // Packet loss detected
        cc.losses++
        cc.ssthresh = cc.cwnd / 2
        cc.cwnd = cc.ssthresh
        cc.inSlowStart = false
    }
}

// BandwidthEstimator estimates available bandwidth
type BandwidthEstimator struct {
    samples     []BandwidthSample
    estimate    float64
    mu          sync.RWMutex
}

// BandwidthSample represents a bandwidth measurement
type BandwidthSample struct {
    Timestamp  time.Time
    Bytes      uint64
    Duration   time.Duration
    Bandwidth  float64
}

// EstimateBandwidth calculates current bandwidth estimate
func (be *BandwidthEstimator) EstimateBandwidth() float64 {
    be.mu.RLock()
    defer be.mu.RUnlock()
    
    if len(be.samples) < 3 {
        return 0
    }
    
    // Use exponential weighted moving average
    alpha := 0.125
    estimate := be.samples[0].Bandwidth
    
    for i := 1; i < len(be.samples); i++ {
        estimate = alpha*be.samples[i].Bandwidth + (1-alpha)*estimate
    }
    
    return estimate
}

// FastHandshake implements optimized handshake protocol
type FastHandshake struct {
    manager    *TunnelManager
    cache      *HandshakeCache
    predictor  *HandshakePredictor
}

// HandshakeCache caches handshake state
type HandshakeCache struct {
    entries map[string]*HandshakeEntry
    mu      sync.RWMutex
}

// HandshakeEntry contains cached handshake data
type HandshakeEntry struct {
    NodeID        string
    PublicKey     []byte
    PresharedKey  []byte
    LastEndpoint  string
    LastSuccess   time.Time
    SuccessRate   float64
}

// PerformHandshake performs optimized handshake
func (fh *FastHandshake) PerformHandshake(nodeID string) error {
    // Check cache first
    if entry := fh.cache.Get(nodeID); entry != nil {
        if time.Since(entry.LastSuccess) < 5*time.Minute {
            // Use cached data for fast handshake
            return fh.fastPath(entry)
        }
    }
    
    // Predict optimal parameters
    params := fh.predictor.PredictParameters(nodeID)
    
    // Perform parallel handshake attempts
    ctx, cancel := context.WithTimeout(context.Background(), params.Timeout)
    defer cancel()
    
    results := make(chan error, 3)
    
    // Try multiple strategies in parallel
    go func() { results <- fh.tryDirect(ctx, nodeID) }()
    go func() { results <- fh.tryRelay(ctx, nodeID) }()
    go func() { results <- fh.trySTUN(ctx, nodeID) }()
    
    // Return first success
    for i := 0; i < 3; i++ {
        if err := <-results; err == nil {
            fh.cache.Update(nodeID, true)
            return nil
        }
    }
    
    return fmt.Errorf("all handshake attempts failed")
}

// PacketScheduler optimizes packet scheduling
type PacketScheduler struct {
    queues      map[PriorityClass]*PacketQueue
    scheduler   SchedulingAlgorithm
    shaper      *TrafficShaper
}

// PriorityClass defines packet priority
type PriorityClass int

const (
    PriorityControl PriorityClass = iota
    PriorityRealtime
    PriorityInteractive
    PriorityBulk
)

// Schedule schedules packet for transmission
func (ps *PacketScheduler) Schedule(packet *Packet, class PriorityClass) {
    queue := ps.queues[class]
    queue.Enqueue(packet)
    
    // Apply traffic shaping if needed
    if ps.shaper.ShouldShape(class) {
        ps.shaper.ApplyShaping(packet)
    }
}

// CPUOptimizer optimizes CPU usage
type CPUOptimizer struct {
    affinity    *CPUAffinity
    vectorized  bool
    batchSize   int
}

// OptimizeCrypto optimizes cryptographic operations
func (co *CPUOptimizer) OptimizeCrypto() {
    if co.vectorized {
        // Use SIMD instructions for crypto
        enableAESNI()
        enableAVX2()
    }
    
    // Set CPU affinity for crypto threads
    co.affinity.SetCryptoThreads([]int{0, 1})
    
    // Optimize batch sizes
    co.batchSize = co.calculateOptimalBatchSize()
}
```

## Dependencies
- golang.zx2c4.com/wireguard/wgctrl
- WireGuard kernel module or wireguard-go
- Curve25519 for key exchange
- ChaCha20-Poly1305 for encryption

## Configuration
```yaml
wireguard:
  device: wg0
  listen_port: 51820
  private_key: "generated_on_first_run"
  mtu: 1420
  optimization:
    adaptive_mtu: true
    congestion_control: true
    cpu_affinity: true
    vectorized_crypto: true
  handshake:
    timeout: 5s
    retries: 3
    cache_duration: 5m
  performance:
    send_buffer: 262144
    receive_buffer: 262144
    queue_size: 256
```

## Security Considerations
1. **Key Management**: Secure storage of private keys
2. **Perfect Forward Secrecy**: Regular key rotation
3. **DDoS Protection**: Rate limiting on handshakes
4. **Replay Protection**: Built into WireGuard protocol
5. **Identity Verification**: Additional verification on top of WireGuard

## Performance Metrics
- Handshake latency < 100ms
- Throughput > 1 Gbps on modern hardware
- CPU usage < 10% for 1 Gbps traffic
- Memory usage < 50MB per 1000 peers
- Packet loss < 0.01% under normal conditions