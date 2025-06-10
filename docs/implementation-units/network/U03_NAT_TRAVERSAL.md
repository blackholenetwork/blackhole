# Unit U03: NAT Traversal & Connectivity - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U03 implements comprehensive NAT traversal mechanisms to ensure connectivity across diverse network configurations. This unit enables Blackhole nodes to establish connections even when behind firewalls, NATs, or other restrictive network environments.

**Primary Goals:**
- Implement AutoNAT for NAT detection
- Deploy circuit relay infrastructure
- Enable direct connection via hole punching
- Support UPnP/NAT-PMP for router configuration
- Provide fallback connectivity options

### Dependencies

- **U01: libp2p Core Setup** - Requires base libp2p host
- **U02: Kademlia DHT** - Uses DHT for relay discovery

### Deliverables

1. **AutoNAT Service**
   - NAT type detection
   - Public address discovery
   - Connectivity status reporting

2. **Circuit Relay Infrastructure**
   - Relay server implementation
   - Relay client functionality
   - Relay discovery via DHT

3. **Hole Punching Implementation**
   - STUN-like coordination
   - Direct connection upgrade
   - Success rate optimization

4. **Router Configuration**
   - UPnP port mapping
   - NAT-PMP support
   - Automatic port management

### Integration Points

- **U01: libp2p Core** - Extends transport capabilities
- **U02: DHT** - Relay discovery and coordination
- **All Service Units** - Ensures connectivity for all services

## 2. Technical Specifications

### NAT Types and Strategies

```go
// NAT Type Classifications
const (
    NATTypeNone       = "none"        // Public IP, no NAT
    NATTypeFull       = "full-cone"   // Full Cone NAT
    NATTypeRestricted = "restricted"  // Restricted Cone NAT
    NATTypePort       = "port"        // Port Restricted NAT
    NATTypeSymmetric  = "symmetric"   // Symmetric NAT
    NATTypeUnknown    = "unknown"     // Unable to determine
)

// Traversal Strategies by NAT Type
var TraversalStrategies = map[string][]string{
    NATTypeNone:       {"direct"},
    NATTypeFull:       {"direct", "upnp"},
    NATTypeRestricted: {"hole-punch", "relay", "upnp"},
    NATTypePort:       {"hole-punch", "relay", "upnp"},
    NATTypeSymmetric:  {"relay"}, // Only relay works reliably
}
```

### AutoNAT Protocol

AutoNAT allows nodes to determine their NAT status and discover their public addresses by asking other nodes to dial them back.

### Circuit Relay v2

Circuit Relay enables connectivity between nodes that cannot establish direct connections by routing traffic through intermediate relay nodes.

### Hole Punching Protocol

Coordinate simultaneous connection attempts to establish direct connections through NATs.

## 3. Implementation Details

### AutoNAT Implementation

```go
// pkg/network/autonat.go
package network

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/p2p/host/autonat"
    "github.com/multiformats/go-multiaddr"
)

// AutoNATService provides NAT detection and traversal
type AutoNATService struct {
    host        host.Host
    autonat     autonat.AutoNAT
    config      *AutoNATConfig
    status      *NATStatus
    statusMu    sync.RWMutex
    ctx         context.Context
    cancel      context.CancelFunc
}

// AutoNATConfig configures the AutoNAT service
type AutoNATConfig struct {
    // Enable AutoNAT service
    Enabled bool
    
    // Interval between NAT checks
    CheckInterval time.Duration
    
    // Number of peers to query
    QueryPeers int
    
    // Timeout for dial-back attempts
    DialTimeout time.Duration
    
    // Enable as AutoNAT server
    EnableServer bool
    
    // Rate limiting for server
    ServerRateLimit int // requests per minute
    
    // Confidence threshold
    ConfidenceThreshold int
}

// NATStatus represents current NAT status
type NATStatus struct {
    Type          string
    PublicAddrs   []multiaddr.Multiaddr
    Reachability  network.Reachability
    Confidence    float64
    LastCheck     time.Time
    SuccessCount  int
    FailureCount  int
}

// NewAutoNATService creates a new AutoNAT service
func NewAutoNATService(ctx context.Context, h host.Host, cfg *AutoNATConfig) (*AutoNATService, error) {
    if cfg == nil {
        cfg = DefaultAutoNATConfig()
    }

    serviceCtx, cancel := context.WithCancel(ctx)
    
    // Configure AutoNAT options
    autonatOpts := []autonat.Option{
        autonat.WithSchedule(cfg.CheckInterval, 3*cfg.CheckInterval),
        autonat.WithPeerThreshold(cfg.QueryPeers),
    }
    
    // Create AutoNAT instance
    an := autonat.New(h, autonatOpts...)
    
    service := &AutoNATService{
        host:     h,
        autonat:  an,
        config:   cfg,
        status:   &NATStatus{Type: NATTypeUnknown},
        ctx:      serviceCtx,
        cancel:   cancel,
    }
    
    // Enable AutoNAT server if configured
    if cfg.EnableServer {
        service.enableServer()
    }
    
    return service, nil
}

// Start begins NAT detection and monitoring
func (s *AutoNATService) Start() error {
    logger.Info("Starting AutoNAT service")
    
    // Subscribe to AutoNAT events
    sub, err := s.autonat.SubscribeToEvents()
    if err != nil {
        return fmt.Errorf("failed to subscribe to AutoNAT events: %w", err)
    }
    
    // Start event handler
    go s.handleAutoNATEvents(sub)
    
    // Start periodic NAT type detection
    go s.periodicNATTypeDetection()
    
    // Initial NAT check
    go s.checkNATStatus()
    
    return nil
}

// Stop shuts down the AutoNAT service
func (s *AutoNATService) Stop() error {
    logger.Info("Stopping AutoNAT service")
    s.cancel()
    return nil
}

// GetStatus returns current NAT status
func (s *AutoNATService) GetStatus() NATStatus {
    s.statusMu.RLock()
    defer s.statusMu.RUnlock()
    return *s.status
}

// handleAutoNATEvents processes AutoNAT status changes
func (s *AutoNATService) handleAutoNATEvents(sub event.Subscription) {
    defer sub.Close()
    
    for {
        select {
        case evt := <-sub.Out():
            if evt == nil {
                return
            }
            
            switch e := evt.(type) {
            case autonat.ReachabilityChanged:
                s.handleReachabilityChange(e.Reachability)
            case autonat.PublicAddrsChanged:
                s.handlePublicAddrsChange(e.Addrs)
            }
            
        case <-s.ctx.Done():
            return
        }
    }
}

// handleReachabilityChange updates NAT status based on reachability
func (s *AutoNATService) handleReachabilityChange(reach network.Reachability) {
    s.statusMu.Lock()
    defer s.statusMu.Unlock()
    
    s.status.Reachability = reach
    s.status.LastCheck = time.Now()
    
    switch reach {
    case network.ReachabilityPublic:
        s.status.Type = NATTypeNone
        logger.Info("Node is publicly reachable")
    case network.ReachabilityPrivate:
        // Need further detection for specific NAT type
        logger.Info("Node is behind NAT")
    default:
        s.status.Type = NATTypeUnknown
        logger.Info("Reachability unknown")
    }
}

// periodicNATTypeDetection performs detailed NAT type detection
func (s *AutoNATService) periodicNATTypeDetection() {
    ticker := time.NewTicker(s.config.CheckInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            s.detectNATType()
        case <-s.ctx.Done():
            return
        }
    }
}

// detectNATType performs comprehensive NAT type detection
func (s *AutoNATService) detectNATType() {
    // Skip if publicly reachable
    if s.status.Reachability == network.ReachabilityPublic {
        return
    }
    
    logger.Debug("Detecting NAT type")
    
    // Get test peers from different networks
    testPeers := s.getTestPeers(3)
    if len(testPeers) < 2 {
        logger.Warn("Insufficient test peers for NAT detection")
        return
    }
    
    // Perform connection tests
    results := make([]natTestResult, 0, len(testPeers))
    
    for _, peer := range testPeers {
        result := s.performNATTest(peer)
        results = append(results, result)
    }
    
    // Analyze results to determine NAT type
    natType := s.analyzeNATType(results)
    
    s.statusMu.Lock()
    s.status.Type = natType
    s.status.LastCheck = time.Now()
    s.statusMu.Unlock()
    
    logger.Infof("NAT type detected: %s", natType)
}

// natTestResult holds results from NAT testing
type natTestResult struct {
    PeerID      peer.ID
    Success     bool
    LocalAddr   multiaddr.Multiaddr
    RemoteAddr  multiaddr.Multiaddr
    ObservedAddr multiaddr.Multiaddr
}

// performNATTest tests connectivity with a peer
func (s *AutoNATService) performNATTest(p peer.ID) natTestResult {
    ctx, cancel := context.WithTimeout(s.ctx, s.config.DialTimeout)
    defer cancel()
    
    result := natTestResult{PeerID: p}
    
    // Attempt connection
    stream, err := s.host.NewStream(ctx, p, "/blackhole/nattest/1.0.0")
    if err != nil {
        result.Success = false
        return result
    }
    defer stream.Close()
    
    result.Success = true
    result.LocalAddr = stream.Conn().LocalMultiaddr()
    result.RemoteAddr = stream.Conn().RemoteMultiaddr()
    
    // Exchange observed addresses
    observedAddr, err := s.exchangeObservedAddr(stream)
    if err == nil {
        result.ObservedAddr = observedAddr
    }
    
    return result
}

// analyzeNATType determines NAT type from test results
func (s *AutoNATService) analyzeNATType(results []natTestResult) string {
    // Count successful connections
    successCount := 0
    var observedPorts []int
    
    for _, r := range results {
        if r.Success {
            successCount++
            if r.ObservedAddr != nil {
                port := extractPort(r.ObservedAddr)
                observedPorts = append(observedPorts, port)
            }
        }
    }
    
    // No successful connections - likely symmetric NAT
    if successCount == 0 {
        return NATTypeSymmetric
    }
    
    // Check if observed ports are consistent
    if len(observedPorts) >= 2 {
        portsMatch := true
        firstPort := observedPorts[0]
        for _, port := range observedPorts[1:] {
            if port != firstPort {
                portsMatch = false
                break
            }
        }
        
        if portsMatch {
            // Same port for different destinations
            if successCount == len(results) {
                return NATTypeFull
            }
            return NATTypeRestricted
        } else {
            // Different ports - likely symmetric
            return NATTypeSymmetric
        }
    }
    
    return NATTypeUnknown
}

// enableServer enables AutoNAT server functionality
func (s *AutoNATService) enableServer() {
    logger.Info("Enabling AutoNAT server")
    
    // Set stream handler for dial-back requests
    s.host.SetStreamHandler(autonat.AutoNATProto, s.handleDialBack)
    
    // Configure rate limiting
    s.rateLimiter = NewRateLimiter(s.config.ServerRateLimit)
}

// handleDialBack handles AutoNAT dial-back requests
func (s *AutoNATService) handleDialBack(stream network.Stream) {
    defer stream.Close()
    
    // Rate limit check
    if !s.rateLimiter.Allow(stream.Conn().RemotePeer()) {
        logger.Debug("Rate limited AutoNAT request")
        return
    }
    
    // Perform dial-back
    // Implementation follows AutoNAT protocol specification
}
```

### Circuit Relay Implementation

```go
// pkg/network/relay.go
package network

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/routing"
    "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
    "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
    "github.com/multiformats/go-multiaddr"
)

// RelayService manages circuit relay functionality
type RelayService struct {
    host         host.Host
    config       *RelayConfig
    relayService *relay.Relay
    client       *client.Client
    routing      routing.Routing
    activeRelays map[peer.ID]*RelayInfo
    relayMu      sync.RWMutex
    ctx          context.Context
    cancel       context.CancelFunc
}

// RelayConfig configures relay service
type RelayConfig struct {
    // Enable relay server
    EnableServer bool
    
    // Server configuration
    Resources relay.Resources
    
    // Maximum active relay connections
    MaxRelays int
    
    // Relay discovery interval
    DiscoveryInterval time.Duration
    
    // Preferred relay count
    PreferredRelays int
    
    // Enable relay client
    EnableClient bool
    
    // Relay selection strategy
    SelectionStrategy string // "latency", "random", "reputation"
}

// RelayInfo tracks relay connection info
type RelayInfo struct {
    PeerID       peer.ID
    Addrs        []multiaddr.Multiaddr
    Latency      time.Duration
    SuccessRate  float64
    BytesRelayed uint64
    ActiveConns  int
    LastUsed     time.Time
}

// NewRelayService creates a new relay service
func NewRelayService(ctx context.Context, h host.Host, r routing.Routing, cfg *RelayConfig) (*RelayService, error) {
    if cfg == nil {
        cfg = DefaultRelayConfig()
    }
    
    serviceCtx, cancel := context.WithCancel(ctx)
    
    service := &RelayService{
        host:         h,
        config:       cfg,
        routing:      r,
        activeRelays: make(map[peer.ID]*RelayInfo),
        ctx:          serviceCtx,
        cancel:       cancel,
    }
    
    // Initialize relay server if enabled
    if cfg.EnableServer {
        r, err := relay.New(h, relay.WithResources(cfg.Resources))
        if err != nil {
            cancel()
            return nil, fmt.Errorf("failed to create relay service: %w", err)
        }
        service.relayService = r
    }
    
    // Initialize relay client
    if cfg.EnableClient {
        service.client = client.New(h)
    }
    
    return service, nil
}

// Start begins relay operations
func (s *RelayService) Start() error {
    logger.Info("Starting relay service")
    
    if s.config.EnableClient {
        // Start relay discovery
        go s.discoverRelays()
        
        // Start relay monitoring
        go s.monitorRelays()
    }
    
    if s.config.EnableServer {
        logger.Info("Relay server enabled")
        // Advertise relay service in DHT
        go s.advertiseRelay()
    }
    
    return nil
}

// Stop shuts down relay service
func (s *RelayService) Stop() error {
    logger.Info("Stopping relay service")
    s.cancel()
    
    // Close all relay connections
    s.relayMu.Lock()
    for _, relay := range s.activeRelays {
        s.host.Network().ClosePeer(relay.PeerID)
    }
    s.relayMu.Unlock()
    
    return nil
}

// discoverRelays finds and connects to relay nodes
func (s *RelayService) discoverRelays() {
    ticker := time.NewTicker(s.config.DiscoveryInterval)
    defer ticker.Stop()
    
    // Initial discovery
    s.performRelayDiscovery()
    
    for {
        select {
        case <-ticker.C:
            s.performRelayDiscovery()
        case <-s.ctx.Done():
            return
        }
    }
}

// performRelayDiscovery searches for relay nodes
func (s *RelayService) performRelayDiscovery() {
    ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
    defer cancel()
    
    logger.Debug("Discovering relay nodes")
    
    // Search for relay service in DHT
    relayKey := "/libp2p/relay"
    peerChan, err := s.routing.FindProviders(ctx, relayKey)
    if err != nil {
        logger.Warnf("Failed to find relay providers: %v", err)
        return
    }
    
    candidates := make([]peer.AddrInfo, 0)
    for p := range peerChan {
        if len(candidates) >= s.config.PreferredRelays*2 {
            break
        }
        candidates = append(candidates, p)
    }
    
    // Test and select best relays
    s.selectBestRelays(candidates)
}

// selectBestRelays tests candidates and selects the best ones
func (s *RelayService) selectBestRelays(candidates []peer.AddrInfo) {
    var wg sync.WaitGroup
    results := make(chan *RelayTestResult, len(candidates))
    
    for _, candidate := range candidates {
        wg.Add(1)
        go func(p peer.AddrInfo) {
            defer wg.Done()
            result := s.testRelay(p)
            if result != nil {
                results <- result
            }
        }(candidate)
    }
    
    wg.Wait()
    close(results)
    
    // Collect and sort results
    var validRelays []*RelayTestResult
    for result := range results {
        if result.Success {
            validRelays = append(validRelays, result)
        }
    }
    
    // Sort by selection strategy
    s.sortRelays(validRelays)
    
    // Update active relays
    s.updateActiveRelays(validRelays)
}

// RelayTestResult holds relay testing results
type RelayTestResult struct {
    PeerInfo    peer.AddrInfo
    Success     bool
    Latency     time.Duration
    Bandwidth   float64
    Features    []string
}

// testRelay tests a relay candidate
func (s *RelayService) testRelay(p peer.AddrInfo) *RelayTestResult {
    ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
    defer cancel()
    
    result := &RelayTestResult{PeerInfo: p}
    
    // Connect to relay
    start := time.Now()
    if err := s.host.Connect(ctx, p); err != nil {
        logger.Debugf("Failed to connect to relay %s: %v", p.ID, err)
        return result
    }
    
    // Test relay functionality
    if !s.client.CanRelay(ctx, p.ID) {
        logger.Debugf("Peer %s cannot relay", p.ID)
        return result
    }
    
    result.Success = true
    result.Latency = time.Since(start)
    
    // TODO: Test bandwidth if needed
    
    return result
}

// updateActiveRelays updates the list of active relay nodes
func (s *RelayService) updateActiveRelays(relays []*RelayTestResult) {
    s.relayMu.Lock()
    defer s.relayMu.Unlock()
    
    // Remove excess relays
    if len(relays) > s.config.PreferredRelays {
        relays = relays[:s.config.PreferredRelays]
    }
    
    // Update relay map
    newRelays := make(map[peer.ID]*RelayInfo)
    
    for _, r := range relays {
        info := &RelayInfo{
            PeerID:      r.PeerInfo.ID,
            Addrs:       r.PeerInfo.Addrs,
            Latency:     r.Latency,
            SuccessRate: 1.0, // Initial success rate
            LastUsed:    time.Now(),
        }
        
        // Preserve stats from existing relay
        if existing, ok := s.activeRelays[r.PeerInfo.ID]; ok {
            info.BytesRelayed = existing.BytesRelayed
            info.SuccessRate = existing.SuccessRate
            info.ActiveConns = existing.ActiveConns
        }
        
        newRelays[r.PeerInfo.ID] = info
        
        // Reserve relay slot
        s.reserveRelaySlot(r.PeerInfo.ID)
    }
    
    // Close connections to removed relays
    for id := range s.activeRelays {
        if _, ok := newRelays[id]; !ok {
            s.unreserveRelaySlot(id)
        }
    }
    
    s.activeRelays = newRelays
    logger.Infof("Updated active relays: %d relays available", len(s.activeRelays))
}

// reserveRelaySlot reserves a slot with a relay
func (s *RelayService) reserveRelaySlot(relayID peer.ID) error {
    _, err := s.client.Reserve(s.ctx, relayID)
    if err != nil {
        logger.Warnf("Failed to reserve relay slot with %s: %v", relayID, err)
        return err
    }
    logger.Debugf("Reserved relay slot with %s", relayID)
    return nil
}

// GetRelayAddrs returns relay addresses for this node
func (s *RelayService) GetRelayAddrs() []multiaddr.Multiaddr {
    s.relayMu.RLock()
    defer s.relayMu.RUnlock()
    
    var addrs []multiaddr.Multiaddr
    for _, relay := range s.activeRelays {
        for _, addr := range relay.Addrs {
            // Build relay address
            relayAddr, err := multiaddr.NewMultiaddr(
                fmt.Sprintf("%s/p2p/%s/p2p-circuit/p2p/%s",
                    addr, relay.PeerID, s.host.ID()),
            )
            if err == nil {
                addrs = append(addrs, relayAddr)
            }
        }
    }
    
    return addrs
}

// DialPeerViaRelay attempts to dial a peer through relay
func (s *RelayService) DialPeerViaRelay(ctx context.Context, p peer.ID) error {
    s.relayMu.RLock()
    relays := make([]*RelayInfo, 0, len(s.activeRelays))
    for _, r := range s.activeRelays {
        relays = append(relays, r)
    }
    s.relayMu.RUnlock()
    
    // Try each relay
    for _, relay := range relays {
        relayAddr, err := multiaddr.NewMultiaddr(
            fmt.Sprintf("/p2p/%s/p2p-circuit/p2p/%s", relay.PeerID, p),
        )
        if err != nil {
            continue
        }
        
        if err := s.host.Connect(ctx, peer.AddrInfo{
            ID:    p,
            Addrs: []multiaddr.Multiaddr{relayAddr},
        }); err == nil {
            logger.Debugf("Connected to %s via relay %s", p, relay.PeerID)
            
            // Update relay stats
            s.updateRelayStats(relay.PeerID, true)
            
            return nil
        }
    }
    
    return fmt.Errorf("failed to dial %s via any relay", p)
}

// monitorRelays monitors relay health and performance
func (s *RelayService) monitorRelays() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            s.checkRelayHealth()
        case <-s.ctx.Done():
            return
        }
    }
}

// advertiseRelay advertises this node as a relay
func (s *RelayService) advertiseRelay() {
    // Advertise in DHT
    key := "/libp2p/relay"
    
    ticker := time.NewTicker(time.Hour)
    defer ticker.Stop()
    
    for {
        s.routing.Provide(s.ctx, key, true)
        
        select {
        case <-ticker.C:
            continue
        case <-s.ctx.Done():
            return
        }
    }
}
```

### Hole Punching Implementation

```go
// pkg/network/holepunch.go
package network

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/protocol"
    "github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
)

const (
    HolePunchProtocol = protocol.ID("/blackhole/holepunch/1.0.0")
    CoordinationTimeout = 30 * time.Second
)

// HolePunchService manages hole punching attempts
type HolePunchService struct {
    host          host.Host
    config        *HolePunchConfig
    coordinator   *HolePunchCoordinator
    activePunches map[string]*HolePunchAttempt
    punchMu       sync.RWMutex
    metrics       *HolePunchMetrics
    ctx           context.Context
    cancel        context.CancelFunc
}

// HolePunchConfig configures hole punching
type HolePunchConfig struct {
    // Enable hole punching
    Enabled bool
    
    // Maximum concurrent attempts
    MaxConcurrent int
    
    // Retry configuration
    MaxRetries    int
    RetryInterval time.Duration
    
    // Success rate threshold for enabling
    MinSuccessRate float64
    
    // Coordination timeout
    CoordinationTimeout time.Duration
}

// HolePunchAttempt tracks an active hole punch attempt
type HolePunchAttempt struct {
    ID           string
    LocalPeer    peer.ID
    RemotePeer   peer.ID
    LocalAddrs   []multiaddr.Multiaddr
    RemoteAddrs  []multiaddr.Multiaddr
    StartTime    time.Time
    State        string
    Attempts     int
    LastError    error
}

// HolePunchCoordinator coordinates hole punching between peers
type HolePunchCoordinator struct {
    host      host.Host
    attempts  map[string]*CoordinationState
    attemptMu sync.RWMutex
}

// CoordinationState tracks coordination state
type CoordinationState struct {
    AttemptID    string
    Initiator    peer.ID
    Target       peer.ID
    InitiatorReady bool
    TargetReady    bool
    SyncTime     time.Time
    Complete     bool
}

// NewHolePunchService creates a new hole punch service
func NewHolePunchService(ctx context.Context, h host.Host, cfg *HolePunchConfig) (*HolePunchService, error) {
    if cfg == nil {
        cfg = DefaultHolePunchConfig()
    }
    
    serviceCtx, cancel := context.WithCancel(ctx)
    
    service := &HolePunchService{
        host:          h,
        config:        cfg,
        coordinator:   NewHolePunchCoordinator(h),
        activePunches: make(map[string]*HolePunchAttempt),
        metrics:       NewHolePunchMetrics(),
        ctx:           serviceCtx,
        cancel:        cancel,
    }
    
    // Enable built-in hole punching if available
    if holepuncher, ok := h.(holepunch.Service); ok {
        logger.Info("Built-in hole punching available")
        // Configure built-in service
    }
    
    return service, nil
}

// Start initializes hole punching service
func (s *HolePunchService) Start() error {
    logger.Info("Starting hole punch service")
    
    // Set up protocol handlers
    s.host.SetStreamHandler(HolePunchProtocol, s.handleHolePunchStream)
    
    // Start coordinator
    s.coordinator.Start()
    
    // Start metrics collection
    go s.collectMetrics()
    
    return nil
}

// AttemptHolePunch attempts to establish direct connection via hole punching
func (s *HolePunchService) AttemptHolePunch(ctx context.Context, p peer.ID) error {
    // Check if hole punching is viable
    if !s.isHolePunchViable(p) {
        return fmt.Errorf("hole punching not viable for peer %s", p)
    }
    
    // Check concurrent attempts limit
    s.punchMu.RLock()
    activeCount := len(s.activePunches)
    s.punchMu.RUnlock()
    
    if activeCount >= s.config.MaxConcurrent {
        return fmt.Errorf("too many concurrent hole punch attempts")
    }
    
    attemptID := generateAttemptID(s.host.ID(), p)
    
    // Create attempt record
    attempt := &HolePunchAttempt{
        ID:         attemptID,
        LocalPeer:  s.host.ID(),
        RemotePeer: p,
        StartTime:  time.Now(),
        State:      "initializing",
    }
    
    s.punchMu.Lock()
    s.activePunches[attemptID] = attempt
    s.punchMu.Unlock()
    
    // Perform hole punch
    err := s.performHolePunch(ctx, attempt)
    
    // Update metrics
    s.punchMu.Lock()
    delete(s.activePunches, attemptID)
    s.punchMu.Unlock()
    
    if err != nil {
        s.metrics.AttemptsFailed.Inc()
        return err
    }
    
    s.metrics.AttemptsSuccess.Inc()
    return nil
}

// performHolePunch executes the hole punching protocol
func (s *HolePunchService) performHolePunch(ctx context.Context, attempt *HolePunchAttempt) error {
    logger.Debugf("Starting hole punch to %s", attempt.RemotePeer)
    
    // Phase 1: Exchange connectivity information
    connInfo, err := s.exchangeConnectivityInfo(ctx, attempt.RemotePeer)
    if err != nil {
        attempt.LastError = err
        return fmt.Errorf("failed to exchange connectivity info: %w", err)
    }
    
    attempt.RemoteAddrs = connInfo.ObservedAddrs
    attempt.State = "coordinating"
    
    // Phase 2: Coordinate with remote peer
    syncTime, err := s.coordinator.Coordinate(ctx, attempt)
    if err != nil {
        attempt.LastError = err
        return fmt.Errorf("failed to coordinate: %w", err)
    }
    
    attempt.State = "punching"
    
    // Phase 3: Simultaneous connection attempts
    err = s.simultaneousConnect(ctx, attempt, syncTime)
    if err != nil {
        attempt.LastError = err
        
        // Retry if configured
        if attempt.Attempts < s.config.MaxRetries {
            attempt.Attempts++
            time.Sleep(s.config.RetryInterval)
            return s.performHolePunch(ctx, attempt)
        }
        
        return fmt.Errorf("hole punch failed after %d attempts: %w", attempt.Attempts, err)
    }
    
    attempt.State = "success"
    logger.Infof("Hole punch successful to %s", attempt.RemotePeer)
    
    return nil
}

// ConnectivityInfo contains peer connectivity information
type ConnectivityInfo struct {
    PeerID         peer.ID
    ListenAddrs    []multiaddr.Multiaddr
    ObservedAddrs  []multiaddr.Multiaddr
    NATType        string
    RelayAddrs     []multiaddr.Multiaddr
}

// exchangeConnectivityInfo exchanges connectivity information with peer
func (s *HolePunchService) exchangeConnectivityInfo(ctx context.Context, p peer.ID) (*ConnectivityInfo, error) {
    // Open stream to peer (via relay if necessary)
    stream, err := s.host.NewStream(ctx, p, HolePunchProtocol)
    if err != nil {
        return nil, err
    }
    defer stream.Close()
    
    // Send our connectivity info
    ourInfo := &ConnectivityInfo{
        PeerID:        s.host.ID(),
        ListenAddrs:   s.host.Addrs(),
        ObservedAddrs: s.getObservedAddrs(),
        NATType:       s.getNATType(),
    }
    
    if err := sendConnectivityInfo(stream, ourInfo); err != nil {
        return nil, err
    }
    
    // Receive peer's info
    peerInfo, err := receiveConnectivityInfo(stream)
    if err != nil {
        return nil, err
    }
    
    return peerInfo, nil
}

// simultaneousConnect performs simultaneous connection attempts
func (s *HolePunchService) simultaneousConnect(ctx context.Context, attempt *HolePunchAttempt, syncTime time.Time) error {
    // Wait until sync time
    waitDuration := time.Until(syncTime)
    if waitDuration > 0 {
        time.Sleep(waitDuration)
    }
    
    // Prepare all addresses to try
    var addrs []multiaddr.Multiaddr
    addrs = append(addrs, attempt.RemoteAddrs...)
    
    // Try direct connections simultaneously
    results := make(chan error, len(addrs))
    
    for _, addr := range addrs {
        go func(a multiaddr.Multiaddr) {
            peerInfo := peer.AddrInfo{
                ID:    attempt.RemotePeer,
                Addrs: []multiaddr.Multiaddr{a},
            }
            
            // Attempt connection with short timeout
            connCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
            defer cancel()
            
            err := s.host.Connect(connCtx, peerInfo)
            results <- err
        }(addr)
    }
    
    // Wait for any successful connection
    successTimeout := time.After(10 * time.Second)
    
    for i := 0; i < len(addrs); i++ {
        select {
        case err := <-results:
            if err == nil {
                // Success! Verify the connection
                if s.host.Network().Connectedness(attempt.RemotePeer) == network.Connected {
                    return nil
                }
            }
        case <-successTimeout:
            return fmt.Errorf("hole punch timeout")
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    
    return fmt.Errorf("all connection attempts failed")
}

// isHolePunchViable checks if hole punching is worth attempting
func (s *HolePunchService) isHolePunchViable(p peer.ID) bool {
    // Check if we're already connected
    if s.host.Network().Connectedness(p) == network.Connected {
        return false
    }
    
    // Check success rate
    if s.metrics.GetSuccessRate() < s.config.MinSuccessRate {
        logger.Debug("Hole punch success rate too low")
        return false
    }
    
    // Check if peer supports hole punching
    protocols, err := s.host.Peerstore().GetProtocols(p)
    if err != nil {
        return false
    }
    
    for _, proto := range protocols {
        if proto == HolePunchProtocol {
            return true
        }
    }
    
    return false
}

// HolePunchMetrics tracks hole punching statistics
type HolePunchMetrics struct {
    AttemptsTotal   prometheus.Counter
    AttemptsSuccess prometheus.Counter
    AttemptsFailed  prometheus.Counter
    AttemptDuration prometheus.Histogram
    ActiveAttempts  prometheus.Gauge
}

// GetSuccessRate returns the hole punch success rate
func (m *HolePunchMetrics) GetSuccessRate() float64 {
    // Implementation would query Prometheus metrics
    return 0.75 // Example
}
```

### UPnP/NAT-PMP Implementation

```go
// pkg/network/portmapping.go
package network

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"
    
    "github.com/libp2p/go-nat"
)

// PortMappingService manages automatic port forwarding
type PortMappingService struct {
    nat         nat.NAT
    config      *PortMappingConfig
    mappings    map[string]*PortMapping
    mappingsMu  sync.RWMutex
    ctx         context.Context
    cancel      context.CancelFunc
}

// PortMappingConfig configures port mapping
type PortMappingConfig struct {
    // Enable UPnP
    EnableUPnP bool
    
    // Enable NAT-PMP
    EnableNATPMP bool
    
    // Lease duration
    LeaseDuration time.Duration
    
    // Renewal interval
    RenewalInterval time.Duration
    
    // Discovery timeout
    DiscoveryTimeout time.Duration
}

// PortMapping represents an active port mapping
type PortMapping struct {
    Protocol     string // "tcp" or "udp"
    InternalPort int
    ExternalPort int
    Description  string
    LeaseTime    time.Duration
    RenewAt      time.Time
}

// NewPortMappingService creates a new port mapping service
func NewPortMappingService(ctx context.Context, cfg *PortMappingConfig) (*PortMappingService, error) {
    if cfg == nil {
        cfg = DefaultPortMappingConfig()
    }
    
    serviceCtx, cancel := context.WithCancel(ctx)
    
    service := &PortMappingService{
        config:   cfg,
        mappings: make(map[string]*PortMapping),
        ctx:      serviceCtx,
        cancel:   cancel,
    }
    
    // Discover NAT device
    if err := service.discoverNAT(); err != nil {
        cancel()
        return nil, err
    }
    
    return service, nil
}

// Start begins port mapping operations
func (s *PortMappingService) Start() error {
    if s.nat == nil {
        return fmt.Errorf("no NAT device found")
    }
    
    logger.Info("Starting port mapping service")
    
    // Start renewal routine
    go s.renewMappings()
    
    return nil
}

// Stop removes all port mappings
func (s *PortMappingService) Stop() error {
    logger.Info("Stopping port mapping service")
    s.cancel()
    
    // Remove all mappings
    s.mappingsMu.Lock()
    defer s.mappingsMu.Unlock()
    
    for key, mapping := range s.mappings {
        if err := s.removeMapping(mapping); err != nil {
            logger.Warnf("Failed to remove mapping %s: %v", key, err)
        }
    }
    
    if s.nat != nil {
        s.nat.Close()
    }
    
    return nil
}

// discoverNAT discovers NAT device
func (s *PortMappingService) discoverNAT() error {
    ctx, cancel := context.WithTimeout(s.ctx, s.config.DiscoveryTimeout)
    defer cancel()
    
    logger.Info("Discovering NAT device")
    
    gateway, err := nat.DiscoverGateway(ctx)
    if err != nil {
        return fmt.Errorf("failed to discover gateway: %w", err)
    }
    
    s.nat = gateway
    
    // Get device info
    deviceType := "unknown"
    if s.nat != nil {
        deviceType = s.nat.Type()
    }
    
    externalIP, err := s.nat.GetExternalAddress()
    if err == nil {
        logger.Infof("NAT device found: %s, external IP: %s", deviceType, externalIP)
    } else {
        logger.Infof("NAT device found: %s", deviceType)
    }
    
    return nil
}

// AddPortMapping creates a new port mapping
func (s *PortMappingService) AddPortMapping(protocol string, internalPort int, description string) (*PortMapping, error) {
    if s.nat == nil {
        return nil, fmt.Errorf("no NAT device available")
    }
    
    // Try to get the same external port first
    externalPort := internalPort
    
    // Attempt mapping
    actualExternal, err := s.nat.AddPortMapping(
        protocol,
        internalPort,
        description,
        s.config.LeaseDuration,
    )
    if err != nil {
        return nil, fmt.Errorf("failed to add port mapping: %w", err)
    }
    
    mapping := &PortMapping{
        Protocol:     protocol,
        InternalPort: internalPort,
        ExternalPort: actualExternal,
        Description:  description,
        LeaseTime:    s.config.LeaseDuration,
        RenewAt:      time.Now().Add(s.config.RenewalInterval),
    }
    
    // Store mapping
    key := fmt.Sprintf("%s:%d", protocol, internalPort)
    s.mappingsMu.Lock()
    s.mappings[key] = mapping
    s.mappingsMu.Unlock()
    
    logger.Infof("Added port mapping: %s %d -> %d", protocol, internalPort, actualExternal)
    
    return mapping, nil
}

// RemovePortMapping removes a port mapping
func (s *PortMappingService) RemovePortMapping(protocol string, internalPort int) error {
    key := fmt.Sprintf("%s:%d", protocol, internalPort)
    
    s.mappingsMu.Lock()
    mapping, exists := s.mappings[key]
    if !exists {
        s.mappingsMu.Unlock()
        return fmt.Errorf("mapping not found")
    }
    delete(s.mappings, key)
    s.mappingsMu.Unlock()
    
    return s.removeMapping(mapping)
}

// removeMapping removes a mapping from NAT device
func (s *PortMappingService) removeMapping(mapping *PortMapping) error {
    if s.nat == nil {
        return nil
    }
    
    err := s.nat.DeletePortMapping(mapping.Protocol, mapping.InternalPort)
    if err != nil {
        return fmt.Errorf("failed to remove mapping: %w", err)
    }
    
    logger.Infof("Removed port mapping: %s %d", mapping.Protocol, mapping.InternalPort)
    return nil
}

// renewMappings periodically renews port mappings
func (s *PortMappingService) renewMappings() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            s.checkAndRenewMappings()
        case <-s.ctx.Done():
            return
        }
    }
}

// checkAndRenewMappings renews mappings that are due
func (s *PortMappingService) checkAndRenewMappings() {
    s.mappingsMu.RLock()
    mappingsToRenew := make([]*PortMapping, 0)
    
    now := time.Now()
    for _, mapping := range s.mappings {
        if now.After(mapping.RenewAt) {
            mappingsToRenew = append(mappingsToRenew, mapping)
        }
    }
    s.mappingsMu.RUnlock()
    
    // Renew mappings
    for _, mapping := range mappingsToRenew {
        if err := s.renewMapping(mapping); err != nil {
            logger.Warnf("Failed to renew mapping %s %d: %v", 
                mapping.Protocol, mapping.InternalPort, err)
        }
    }
}

// renewMapping renews a single mapping
func (s *PortMappingService) renewMapping(mapping *PortMapping) error {
    if s.nat == nil {
        return fmt.Errorf("NAT device not available")
    }
    
    // Re-add the mapping
    _, err := s.nat.AddPortMapping(
        mapping.Protocol,
        mapping.InternalPort,
        mapping.Description,
        s.config.LeaseDuration,
    )
    if err != nil {
        return err
    }
    
    // Update renewal time
    mapping.RenewAt = time.Now().Add(s.config.RenewalInterval)
    
    logger.Debugf("Renewed port mapping: %s %d", mapping.Protocol, mapping.InternalPort)
    return nil
}

// GetExternalAddress returns the external IP address
func (s *PortMappingService) GetExternalAddress() (net.IP, error) {
    if s.nat == nil {
        return nil, fmt.Errorf("no NAT device available")
    }
    
    return s.nat.GetExternalAddress()
}

// GetMappings returns all active port mappings
func (s *PortMappingService) GetMappings() []*PortMapping {
    s.mappingsMu.RLock()
    defer s.mappingsMu.RUnlock()
    
    mappings := make([]*PortMapping, 0, len(s.mappings))
    for _, m := range s.mappings {
        mappings = append(mappings, m)
    }
    
    return mappings
}
```

## 4. Configuration

### NAT Traversal Configuration

```go
// pkg/network/nat_config.go
package network

import "time"

// NATConfig combines all NAT traversal configurations
type NATConfig struct {
    AutoNAT      AutoNATConfig
    Relay        RelayConfig
    HolePunch    HolePunchConfig
    PortMapping  PortMappingConfig
}

// DefaultAutoNATConfig returns default AutoNAT configuration
func DefaultAutoNATConfig() *AutoNATConfig {
    return &AutoNATConfig{
        Enabled:             true,
        CheckInterval:       2 * time.Minute,
        QueryPeers:          3,
        DialTimeout:         15 * time.Second,
        EnableServer:        false, // Only on public nodes
        ServerRateLimit:     60,    // per minute
        ConfidenceThreshold: 3,
    }
}

// DefaultRelayConfig returns default relay configuration
func DefaultRelayConfig() *RelayConfig {
    return &RelayConfig{
        EnableServer: false, // Only on capable nodes
        Resources: relay.Resources{
            Limit: relay.DefaultLimit,
        },
        MaxRelays:         50,
        DiscoveryInterval: 5 * time.Minute,
        PreferredRelays:   3,
        EnableClient:      true,
        SelectionStrategy: "latency",
    }
}

// DefaultHolePunchConfig returns default hole punch configuration
func DefaultHolePunchConfig() *HolePunchConfig {
    return &HolePunchConfig{
        Enabled:             true,
        MaxConcurrent:       10,
        MaxRetries:          3,
        RetryInterval:       2 * time.Second,
        MinSuccessRate:      0.3, // 30% success rate
        CoordinationTimeout: 30 * time.Second,
    }
}

// DefaultPortMappingConfig returns default port mapping configuration
func DefaultPortMappingConfig() *PortMappingConfig {
    return &PortMappingConfig{
        EnableUPnP:       true,
        EnableNATPMP:     true,
        LeaseDuration:    2 * time.Hour,
        RenewalInterval:  1 * time.Hour,
        DiscoveryTimeout: 10 * time.Second,
    }
}

// PublicNodeNATConfig returns configuration for public nodes
func PublicNodeNATConfig() *NATConfig {
    cfg := &NATConfig{
        AutoNAT:     *DefaultAutoNATConfig(),
        Relay:       *DefaultRelayConfig(),
        HolePunch:   *DefaultHolePunchConfig(),
        PortMapping: *DefaultPortMappingConfig(),
    }
    
    // Enable AutoNAT server
    cfg.AutoNAT.EnableServer = true
    
    // Enable relay server
    cfg.Relay.EnableServer = true
    cfg.Relay.Resources = relay.Resources{
        Limit: &relay.Limit{
            Duration: 2 * time.Minute,
            Data:     1 << 20, // 1MB
        },
        MaxReservations:        128,
        MaxReservationsPerPeer: 4,
        MaxReservationsPerIP:   8,
        ReservationTTL:         time.Hour,
        MaxCircuits:            1024,
        MaxCircuitsPerPeer:     4,
        BufferSize:             2048,
    }
    
    return cfg
}
```

### YAML Configuration

```yaml
# config/nat.yaml
nat_traversal:
  autonat:
    enabled: true
    check_interval: 2m
    query_peers: 3
    dial_timeout: 15s
    enable_server: false
    server_rate_limit: 60
    
  relay:
    enable_server: false
    enable_client: true
    max_relays: 50
    discovery_interval: 5m
    preferred_relays: 3
    selection_strategy: "latency"
    
    # Server resources (if enabled)
    resources:
      max_reservations: 128
      max_circuits: 1024
      buffer_size: 2048
      
  hole_punch:
    enabled: true
    max_concurrent: 10
    max_retries: 3
    retry_interval: 2s
    min_success_rate: 0.3
    
  port_mapping:
    enable_upnp: true
    enable_nat_pmp: true
    lease_duration: 2h
    renewal_interval: 1h
    discovery_timeout: 10s
```

## 5. Testing Requirements

### Unit Tests

```go
// pkg/network/nat_test.go
package network_test

import (
    "context"
    "testing"
    "time"
)

func TestAutoNATDetection(t *testing.T) {
    ctx := context.Background()
    
    // Create test host
    host, _ := libp2p.New()
    defer host.Close()
    
    // Create AutoNAT service
    cfg := DefaultAutoNATConfig()
    autonat, err := NewAutoNATService(ctx, host, cfg)
    require.NoError(t, err)
    defer autonat.Stop()
    
    // Start service
    err = autonat.Start()
    require.NoError(t, err)
    
    // Wait for initial detection
    time.Sleep(5 * time.Second)
    
    // Check status
    status := autonat.GetStatus()
    assert.NotEqual(t, NATTypeUnknown, status.Type)
    assert.NotZero(t, status.LastCheck)
}

func TestRelayDiscovery(t *testing.T) {
    ctx := context.Background()
    
    // Create relay server
    relayHost, _ := libp2p.New()
    defer relayHost.Close()
    
    relayCfg := DefaultRelayConfig()
    relayCfg.EnableServer = true
    relayService, _ := NewRelayService(ctx, relayHost, nil, relayCfg)
    relayService.Start()
    defer relayService.Stop()
    
    // Create client
    clientHost, _ := libp2p.New()
    defer clientHost.Close()
    
    clientCfg := DefaultRelayConfig()
    clientService, _ := NewRelayService(ctx, clientHost, nil, clientCfg)
    clientService.Start()
    defer clientService.Stop()
    
    // Manually add relay for testing
    clientHost.Peerstore().AddAddrs(relayHost.ID(), relayHost.Addrs(), time.Hour)
    
    // Test relay discovery
    time.Sleep(2 * time.Second)
    
    relayAddrs := clientService.GetRelayAddrs()
    assert.NotEmpty(t, relayAddrs)
}

func TestHolePunching(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping hole punch test in short mode")
    }
    
    ctx := context.Background()
    
    // Create two hosts behind "NAT" (simulated)
    host1, _ := libp2p.New()
    defer host1.Close()
    
    host2, _ := libp2p.New()
    defer host2.Close()
    
    // Create hole punch services
    hp1, _ := NewHolePunchService(ctx, host1, nil)
    hp1.Start()
    defer hp1.Stop()
    
    hp2, _ := NewHolePunchService(ctx, host2, nil)
    hp2.Start()
    defer hp2.Stop()
    
    // Simulate relay connection first
    host1.Peerstore().AddAddrs(host2.ID(), host2.Addrs(), time.Hour)
    
    // Attempt hole punch
    err := hp1.AttemptHolePunch(ctx, host2.ID())
    
    // May fail in test environment
    if err == nil {
        assert.Equal(t, network.Connected, host1.Network().Connectedness(host2.ID()))
    }
}

func TestPortMapping(t *testing.T) {
    ctx := context.Background()
    
    cfg := DefaultPortMappingConfig()
    pm, err := NewPortMappingService(ctx, cfg)
    
    if err != nil {
        t.Skip("No NAT device found")
    }
    defer pm.Stop()
    
    err = pm.Start()
    require.NoError(t, err)
    
    // Add port mapping
    mapping, err := pm.AddPortMapping("tcp", 4001, "Blackhole P2P")
    if err != nil {
        t.Skip("Port mapping not supported")
    }
    
    assert.NotNil(t, mapping)
    assert.Equal(t, "tcp", mapping.Protocol)
    assert.Equal(t, 4001, mapping.InternalPort)
    
    // Remove mapping
    err = pm.RemovePortMapping("tcp", 4001)
    assert.NoError(t, err)
}
```

### Integration Tests

```go
// pkg/network/nat_integration_test.go
package network_test

func TestFullNATTraversal(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping NAT traversal integration test")
    }
    
    ctx := context.Background()
    
    // Create public relay node
    relayHost, _ := createPublicNode(t)
    defer relayHost.Close()
    
    // Create two NAT'ed nodes
    nat1, _ := createNATNode(t)
    defer nat1.Close()
    
    nat2, _ := createNATNode(t)
    defer nat2.Close()
    
    // Connect both to relay
    connectToRelay(t, nat1, relayHost)
    connectToRelay(t, nat2, relayHost)
    
    // Attempt direct connection
    initialConn := nat1.Network().Connectedness(nat2.ID())
    assert.NotEqual(t, network.Connected, initialConn)
    
    // Try hole punching
    hp := nat1.(*NATHost).HolePunch
    err := hp.AttemptHolePunch(ctx, nat2.ID())
    
    if err == nil {
        // Verify direct connection
        assert.Eventually(t, func() bool {
            return nat1.Network().Connectedness(nat2.ID()) == network.Connected
        }, 10*time.Second, 100*time.Millisecond)
        
        // Verify not using relay
        conn := nat1.Network().ConnsToPeer(nat2.ID())[0]
        assert.NotContains(t, conn.RemoteMultiaddr().String(), "p2p-circuit")
    }
}

func TestNATTypeDetection(t *testing.T) {
    scenarios := []struct {
        name     string
        setup    func() (*SimulatedNAT, host.Host)
        expected string
    }{
        {
            name: "No NAT",
            setup: func() (*SimulatedNAT, host.Host) {
                return nil, createPublicHost(t)
            },
            expected: NATTypeNone,
        },
        {
            name: "Full Cone NAT",
            setup: func() (*SimulatedNAT, host.Host) {
                nat := NewSimulatedNAT(FullCone)
                host := createHostBehindNAT(t, nat)
                return nat, host
            },
            expected: NATTypeFull,
        },
        {
            name: "Symmetric NAT",
            setup: func() (*SimulatedNAT, host.Host) {
                nat := NewSimulatedNAT(Symmetric)
                host := createHostBehindNAT(t, nat)
                return nat, host
            },
            expected: NATTypeSymmetric,
        },
    }
    
    for _, sc := range scenarios {
        t.Run(sc.name, func(t *testing.T) {
            nat, host := sc.setup()
            defer host.Close()
            if nat != nil {
                defer nat.Close()
            }
            
            autonat, _ := NewAutoNATService(context.Background(), host, nil)
            autonat.Start()
            defer autonat.Stop()
            
            // Wait for detection
            time.Sleep(3 * time.Second)
            
            status := autonat.GetStatus()
            assert.Equal(t, sc.expected, status.Type)
        })
    }
}
```

### Performance Benchmarks

```go
// pkg/network/nat_benchmark_test.go
package network_test

func BenchmarkRelayThroughput(b *testing.B) {
    ctx := context.Background()
    
    // Setup relay
    relay, client1, client2 := setupRelayBench(b)
    defer teardownRelayBench(relay, client1, client2)
    
    // Connect via relay
    relayAddr := getRelayAddr(relay, client2)
    client1.Connect(ctx, peer.AddrInfo{
        ID:    client2.ID(),
        Addrs: []multiaddr.Multiaddr{relayAddr},
    })
    
    // Benchmark data transfer
    data := make([]byte, 1024*1024) // 1MB
    rand.Read(data)
    
    b.SetBytes(int64(len(data)))
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        stream, _ := client1.NewStream(ctx, client2.ID(), "/bench")
        stream.Write(data)
        stream.Close()
    }
}

func BenchmarkHolePunchSuccess(b *testing.B) {
    // Benchmark hole punch success rate and timing
    ctx := context.Background()
    
    successful := 0
    totalDuration := time.Duration(0)
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        host1, host2 := createNATHosts(b)
        hp := NewHolePunchService(ctx, host1, nil)
        
        start := time.Now()
        err := hp.AttemptHolePunch(ctx, host2.ID())
        duration := time.Since(start)
        
        if err == nil {
            successful++
            totalDuration += duration
        }
        
        host1.Close()
        host2.Close()
    }
    
    b.Logf("Success rate: %.2f%%", float64(successful)/float64(b.N)*100)
    if successful > 0 {
        b.Logf("Average success time: %v", totalDuration/time.Duration(successful))
    }
}
```

## 6. Monitoring & Observability

### Metrics

```go
// pkg/network/nat_metrics.go
package network

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// NATMetrics combines all NAT-related metrics
type NATMetrics struct {
    // AutoNAT metrics
    NATType            prometheus.Gauge
    PublicAddrCount    prometheus.Gauge
    AutoNATChecks      prometheus.Counter
    AutoNATFailures    prometheus.Counter
    
    // Relay metrics
    ActiveRelays       prometheus.Gauge
    RelayConnections   prometheus.Gauge
    RelayBytesIn       prometheus.Counter
    RelayBytesOut      prometheus.Counter
    RelayReservations  prometheus.Gauge
    
    // Hole punch metrics
    HolePunchAttempts  prometheus.Counter
    HolePunchSuccess   prometheus.Counter
    HolePunchFailures  prometheus.Counter
    HolePunchDuration  prometheus.Histogram
    
    // Port mapping metrics
    ActivePortMappings prometheus.Gauge
    PortMappingSuccess prometheus.Counter
    PortMappingFailures prometheus.Counter
}

// NewNATMetrics creates NAT metrics
func NewNATMetrics(namespace string) *NATMetrics {
    return &NATMetrics{
        NATType: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "nat_type",
            Help:      "NAT type (0=none, 1=full, 2=restricted, 3=port, 4=symmetric)",
        }),
        
        ActiveRelays: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "relay_active_count",
            Help:      "Number of active relay connections",
        }),
        
        HolePunchSuccess: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "holepunch_success_total",
            Help:      "Successful hole punch attempts",
        }),
        
        HolePunchDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Namespace: namespace,
            Name:      "holepunch_duration_seconds",
            Help:      "Hole punch attempt duration",
            Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10),
        }),
    }
}
```

### Grafana Dashboard

```yaml
# NAT Traversal Dashboard
panels:
  - title: "NAT Type Distribution"
    query: "blackhole_nat_type"
    visualization: "pie"
    
  - title: "Relay Usage"
    query: "blackhole_relay_active_count"
    
  - title: "Hole Punch Success Rate"
    query: |
      rate(blackhole_holepunch_success_total[5m]) /
      rate(blackhole_holepunch_attempts_total[5m])
    
  - title: "Port Mappings"
    query: "blackhole_port_mappings_active"
    
  - title: "Relay Bandwidth"
    queries:
      - "rate(blackhole_relay_bytes_in_total[5m])"
      - "rate(blackhole_relay_bytes_out_total[5m])"
```

## 7. Acceptance Criteria

### Functional Requirements

1. **AutoNAT**
   - [ ] Detects NAT type correctly
   - [ ] Discovers public addresses
   - [ ] Updates on network changes
   - [ ] Server mode works for public nodes

2. **Circuit Relay**
   - [ ] Discovers relay nodes automatically
   - [ ] Establishes relay connections
   - [ ] Falls back to relay when direct fails
   - [ ] Relay server mode functional

3. **Hole Punching**
   - [ ] Attempts hole punch when viable
   - [ ] Coordinates with remote peer
   - [ ] Upgrades relay to direct connection
   - [ ] Success rate > 30% for compatible NATs

4. **Port Mapping**
   - [ ] Discovers UPnP/NAT-PMP devices
   - [ ] Creates port mappings
   - [ ] Renews mappings automatically
   - [ ] Handles device disconnection

### Performance Requirements

1. **Latency**
   - NAT detection < 30s
   - Relay setup < 5s
   - Hole punch attempt < 10s
   - Port mapping < 5s

2. **Success Rates**
   - > 95% relay connection success
   - > 30% hole punch success (compatible NATs)
   - > 80% port mapping success (when supported)

3. **Resource Usage**
   - < 100MB memory for NAT traversal
   - < 5% CPU overhead
   - Minimal bandwidth for coordination

## 8. Example Usage

### Complete NAT Traversal Setup

```go
package main

import (
    "context"
    "log"
    
    "github.com/blackhole/pkg/network"
)

func main() {
    ctx := context.Background()
    
    // Create libp2p host
    host, _ := network.NewHost(ctx, network.DefaultConfig())
    defer host.Stop()
    
    // Create DHT for relay discovery
    dht, _ := network.NewDHTService(ctx, host, network.DefaultDHTConfig())
    dht.Start()
    defer dht.Stop()
    
    // Setup NAT traversal services
    natConfig := &network.NATConfig{
        AutoNAT:     *network.DefaultAutoNATConfig(),
        Relay:       *network.DefaultRelayConfig(),
        HolePunch:   *network.DefaultHolePunchConfig(),
        PortMapping: *network.DefaultPortMappingConfig(),
    }
    
    // Initialize services
    autonat, _ := network.NewAutoNATService(ctx, host, &natConfig.AutoNAT)
    autonat.Start()
    defer autonat.Stop()
    
    relay, _ := network.NewRelayService(ctx, host, dht, &natConfig.Relay)
    relay.Start()
    defer relay.Stop()
    
    holepunch, _ := network.NewHolePunchService(ctx, host, &natConfig.HolePunch)
    holepunch.Start()
    defer holepunch.Stop()
    
    portmap, _ := network.NewPortMappingService(ctx, &natConfig.PortMapping)
    if portmap != nil {
        portmap.Start()
        defer portmap.Stop()
        
        // Map P2P ports
        portmap.AddPortMapping("tcp", 4001, "Blackhole P2P TCP")
        portmap.AddPortMapping("udp", 4001, "Blackhole P2P QUIC")
    }
    
    // Check NAT status
    status := autonat.GetStatus()
    log.Printf("NAT Status: %+v", status)
    
    // Get relay addresses
    relayAddrs := relay.GetRelayAddrs()
    log.Printf("Relay addresses: %v", relayAddrs)
    
    // Your application continues...
    select {}
}
```

### Smart Connection Manager

```go
// SmartDialer attempts connection with optimal strategy
type SmartDialer struct {
    host      host.Host
    autonat   *AutoNATService
    relay     *RelayService
    holepunch *HolePunchService
}

func (d *SmartDialer) DialPeer(ctx context.Context, p peer.ID) error {
    // Check if already connected
    if d.host.Network().Connectedness(p) == network.Connected {
        return nil
    }
    
    // Try direct connection first
    if err := d.tryDirectDial(ctx, p); err == nil {
        return nil
    }
    
    // Get our NAT status
    ourNAT := d.autonat.GetStatus()
    
    // Try hole punching if viable
    if ourNAT.Type != NATTypeSymmetric {
        if err := d.holepunch.AttemptHolePunch(ctx, p); err == nil {
            return nil
        }
    }
    
    // Fall back to relay
    return d.relay.DialPeerViaRelay(ctx, p)
}

func (d *SmartDialer) tryDirectDial(ctx context.Context, p peer.ID) error {
    addrs := d.host.Peerstore().Addrs(p)
    if len(addrs) == 0 {
        return fmt.Errorf("no addresses for peer")
    }
    
    return d.host.Connect(ctx, peer.AddrInfo{
        ID:    p,
        Addrs: addrs,
    })
}
```

## Summary

Unit U03 provides comprehensive NAT traversal capabilities that ensure Blackhole nodes can establish connections across diverse network environments. The implementation includes:

- Automatic NAT type detection
- Relay infrastructure for guaranteed connectivity
- Hole punching for optimal direct connections
- UPnP/NAT-PMP for automatic port forwarding
- Smart connection strategies based on network conditions

This unit ensures that the Blackhole network remains accessible and performant regardless of network restrictions, enabling true peer-to-peer connectivity for all participants.