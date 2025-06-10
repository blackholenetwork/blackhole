# Unit 36: VPN Gateway

## Overview
User-facing VPN service that leverages the BlackHole network's bandwidth pooling, providing secure internet access through decentralized exit nodes with load balancing and intelligent routing.

## Implementation

### Core VPN Gateway

```go
package vpngateway

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "net"
    "net/http"
    "sync"
    "time"
)

// VPNGateway manages the user-facing VPN service
type VPNGateway struct {
    config        *GatewayConfig
    exitNodes     *ExitNodeManager
    loadBalancer  *LoadBalancer
    authManager   *AuthenticationManager
    sessionMgr    *SessionManager
    tunnelMgr     *TunnelManager
    routingEngine *RoutingEngine
    monitoring    *GatewayMonitoring
    mu            sync.RWMutex
}

// GatewayConfig contains VPN gateway configuration
type GatewayConfig struct {
    ListenAddress    string
    Protocol         VPNProtocol
    MaxClients       int
    SessionTimeout   time.Duration
    DHCPPool         *DHCPPool
    DNSServers       []string
    AllowedNetworks  []net.IPNet
    BlockedNetworks  []net.IPNet
    RequireAuth      bool
    LogLevel         string
}

// VPNProtocol enum for supported protocols
type VPNProtocol int

const (
    ProtocolOpenVPN VPNProtocol = iota
    ProtocolWireGuard
    ProtocolIKEv2
    ProtocolL2TP
    ProtocolSSTP
)

// NewVPNGateway creates a new VPN gateway
func NewVPNGateway(config *GatewayConfig) (*VPNGateway, error) {
    gw := &VPNGateway{
        config:        config,
        exitNodes:     NewExitNodeManager(),
        loadBalancer:  NewLoadBalancer(),
        authManager:   NewAuthenticationManager(),
        sessionMgr:    NewSessionManager(),
        tunnelMgr:     NewTunnelManager(),
        routingEngine: NewRoutingEngine(),
        monitoring:    NewGatewayMonitoring(),
    }
    
    if err := gw.initialize(); err != nil {
        return nil, err
    }
    
    return gw, nil
}

// Start starts the VPN gateway
func (gw *VPNGateway) Start(ctx context.Context) error {
    // Start exit node discovery
    go gw.exitNodes.StartDiscovery(ctx)
    
    // Start load balancer
    go gw.loadBalancer.Start(ctx)
    
    // Start monitoring
    go gw.monitoring.Start(ctx)
    
    // Start protocol-specific listeners
    switch gw.config.Protocol {
    case ProtocolOpenVPN:
        return gw.startOpenVPN(ctx)
    case ProtocolWireGuard:
        return gw.startWireGuard(ctx)
    case ProtocolIKEv2:
        return gw.startIKEv2(ctx)
    default:
        return fmt.Errorf("unsupported protocol: %v", gw.config.Protocol)
    }
}

// Exit Node Management
type ExitNodeManager struct {
    nodes         map[string]*ExitNode
    discovery     *NodeDiscovery
    healthChecker *HealthChecker
    geolocator    *GeolocationService
    mu            sync.RWMutex
}

// ExitNode represents an exit node in the network
type ExitNode struct {
    ID              string
    Address         net.IP
    PublicKey       []byte
    Location        *GeoLocation
    Bandwidth       uint64
    Latency         time.Duration
    Reliability     float64
    Load            float64
    Policies        *ExitPolicy
    Reputation      float64
    LastSeen        time.Time
    Status          NodeStatus
}

// GeoLocation contains node geographic information
type GeoLocation struct {
    Country     string
    Region      string
    City        string
    Latitude    float64
    Longitude   float64
    ASNumber    int
    ISP         string
}

// ExitPolicy defines node's exit policy
type ExitPolicy struct {
    AllowedPorts    []uint16
    BlockedPorts    []uint16
    AllowedCountries []string
    BlockedCountries []string
    P2PAllowed      bool
    TorrentAllowed  bool
    MaxConnections  int
    RateLimit       uint64
}

// SelectExitNode selects optimal exit node for client
func (enm *ExitNodeManager) SelectExitNode(criteria *SelectionCriteria) (*ExitNode, error) {
    enm.mu.RLock()
    defer enm.mu.RUnlock()
    
    candidates := make([]*ExitNode, 0)
    
    // Filter nodes based on criteria
    for _, node := range enm.nodes {
        if enm.matchesCriteria(node, criteria) {
            candidates = append(candidates, node)
        }
    }
    
    if len(candidates) == 0 {
        return nil, errors.New("no suitable exit nodes available")
    }
    
    // Score and rank candidates
    scored := enm.scoreNodes(candidates, criteria)
    
    // Select best node with some randomization
    return enm.selectWithRandomization(scored, 0.2), nil
}

// SelectionCriteria defines exit node selection criteria
type SelectionCriteria struct {
    PreferredCountries  []string
    MinBandwidth       uint64
    MaxLatency         time.Duration
    MinReliability     float64
    RequiredPorts      []uint16
    AvoidOverloaded    bool
    PreferLowLatency   bool
    PreferHighBandwidth bool
    LoadBalanceStrategy LoadBalanceStrategy
}

// Load Balancer implementation
type LoadBalancer struct {
    strategy       LoadBalanceStrategy
    healthChecker  *HealthChecker
    metrics        *LoadBalancerMetrics
    nodeWeights    map[string]float64
    sessions       map[string]string  // sessionID -> nodeID
    mu             sync.RWMutex
}

// LoadBalanceStrategy enum
type LoadBalanceStrategy int

const (
    RoundRobin LoadBalanceStrategy = iota
    WeightedRoundRobin
    LeastConnections
    LeastLatency
    HighestBandwidth
    Geographic
    PowerOfTwoChoices
)

// BalanceLoad distributes client across exit nodes
func (lb *LoadBalancer) BalanceLoad(clientID string, nodes []*ExitNode) (*ExitNode, error) {
    if len(nodes) == 0 {
        return nil, errors.New("no nodes available")
    }
    
    switch lb.strategy {
    case RoundRobin:
        return lb.roundRobin(nodes)
    case WeightedRoundRobin:
        return lb.weightedRoundRobin(nodes)
    case LeastConnections:
        return lb.leastConnections(nodes)
    case LeastLatency:
        return lb.leastLatency(nodes)
    case HighestBandwidth:
        return lb.highestBandwidth(nodes)
    case PowerOfTwoChoices:
        return lb.powerOfTwoChoices(nodes)
    default:
        return nodes[0], nil
    }
}

// Client Authentication
type AuthenticationManager struct {
    methods      []AuthMethod
    userStore    UserStore
    tokenManager *TokenManager
    certificates *CertificateManager
}

// AuthMethod interface for different auth methods
type AuthMethod interface {
    Authenticate(credentials *Credentials) (*User, error)
    GetType() AuthMethodType
}

// AuthMethodType enum
type AuthMethodType int

const (
    AuthCertificate AuthMethodType = iota
    AuthToken
    AuthOAuth
    AuthLDAP
    AuthRadius
    AuthAnonymous
)

// CertificateAuth implements certificate-based authentication
type CertificateAuth struct {
    ca          *x509.Certificate
    crl         *x509.RevocationList
    validator   *CertificateValidator
}

// Authenticate using client certificate
func (ca *CertificateAuth) Authenticate(credentials *Credentials) (*User, error) {
    cert := credentials.Certificate
    if cert == nil {
        return nil, errors.New("no certificate provided")
    }
    
    // Validate certificate chain
    if err := ca.validator.ValidateChain(cert, ca.ca); err != nil {
        return nil, fmt.Errorf("certificate validation failed: %w", err)
    }
    
    // Check CRL
    if ca.crl != nil && ca.isRevoked(cert) {
        return nil, errors.New("certificate revoked")
    }
    
    // Extract user information
    user := &User{
        ID:          ca.extractUserID(cert),
        CommonName:  cert.Subject.CommonName,
        Groups:      ca.extractGroups(cert),
        Permissions: ca.extractPermissions(cert),
    }
    
    return user, nil
}

// Session Management
type SessionManager struct {
    sessions     map[string]*VPNSession
    dhcpPool     *DHCPPool
    ipAllocator  *IPAllocator
    timeouts     *SessionTimeouts
    mu           sync.RWMutex
}

// VPNSession represents an active VPN session
type VPNSession struct {
    ID           string
    UserID       string
    ClientIP     net.IP
    ExitNode     *ExitNode
    ConnectedAt  time.Time
    LastActivity time.Time
    BytesSent    uint64
    BytesReceived uint64
    Status       SessionStatus
    Tunnel       *VPNTunnel
}

// CreateSession creates new VPN session
func (sm *SessionManager) CreateSession(user *User, exitNode *ExitNode) (*VPNSession, error) {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    // Allocate IP address
    clientIP, err := sm.ipAllocator.AllocateIP(user.ID)
    if err != nil {
        return nil, fmt.Errorf("IP allocation failed: %w", err)
    }
    
    // Create session
    session := &VPNSession{
        ID:          generateSessionID(),
        UserID:      user.ID,
        ClientIP:    clientIP,
        ExitNode:    exitNode,
        ConnectedAt: time.Now(),
        Status:      SessionActive,
    }
    
    sm.sessions[session.ID] = session
    
    // Set timeout
    sm.timeouts.SetTimeout(session.ID, sm.getSessionTimeout(user))
    
    return session, nil
}

// VPN Tunnel Implementation
type VPNTunnel struct {
    session     *VPNSession
    conn        net.Conn
    exitConn    net.Conn
    router      *PacketRouter
    cryptor     *TunnelCrypto
    compressor  *DataCompressor
    mu          sync.RWMutex
}

// NewVPNTunnel creates a new VPN tunnel
func NewVPNTunnel(session *VPNSession, conn net.Conn) (*VPNTunnel, error) {
    tunnel := &VPNTunnel{
        session:    session,
        conn:       conn,
        router:     NewPacketRouter(),
        cryptor:    NewTunnelCrypto(),
        compressor: NewDataCompressor(),
    }
    
    // Establish connection to exit node
    exitConn, err := tunnel.connectToExitNode()
    if err != nil {
        return nil, err
    }
    tunnel.exitConn = exitConn
    
    return tunnel, nil
}

// StartTunnel starts packet forwarding
func (vt *VPNTunnel) StartTunnel(ctx context.Context) error {
    errChan := make(chan error, 2)
    
    // Forward client -> exit
    go func() {
        errChan <- vt.forwardClientToExit(ctx)
    }()
    
    // Forward exit -> client
    go func() {
        errChan <- vt.forwardExitToClient(ctx)
    }()
    
    // Wait for error or context cancellation
    select {
    case err := <-errChan:
        return err
    case <-ctx.Done():
        return ctx.Err()
    }
}

// Packet Router for intelligent routing
type PacketRouter struct {
    routes      map[string]*Route
    policies    *RoutingPolicy
    filters     *PacketFilters
    nat         *NATTable
    dns         *DNSHandler
}

// Route represents a routing rule
type Route struct {
    Destination net.IPNet
    Gateway     net.IP
    ExitNode    *ExitNode
    Metric      int
    Policy      RoutePolicy
}

// RoutePacket routes packet based on policies
func (pr *PacketRouter) RoutePacket(packet *Packet) (*RoutingDecision, error) {
    // Apply packet filters
    if action := pr.filters.FilterPacket(packet); action == FilterDrop {
        return &RoutingDecision{Action: ActionDrop}, nil
    }
    
    // Check for DNS queries
    if packet.IsDNS() {
        return pr.dns.HandleDNSQuery(packet)
    }
    
    // Find matching route
    route := pr.findBestRoute(packet.Destination)
    if route == nil {
        return &RoutingDecision{Action: ActionDrop}, errors.New("no route found")
    }
    
    // Apply NAT if needed
    if packet.RequiresNAT() {
        pr.nat.TranslatePacket(packet)
    }
    
    return &RoutingDecision{
        Action:   ActionForward,
        ExitNode: route.ExitNode,
        Gateway:  route.Gateway,
    }, nil
}

// DNS Handler for DNS-over-HTTPS/TLS
type DNSHandler struct {
    resolvers    []DNSResolver
    cache        *DNSCache
    filters      *DNSFilters
    analytics    *DNSAnalytics
}

// DNSResolver interface
type DNSResolver interface {
    Resolve(query *DNSQuery) (*DNSResponse, error)
    GetType() DNSResolverType
}

// HandleDNSQuery processes DNS queries
func (dh *DNSHandler) HandleDNSQuery(packet *Packet) (*RoutingDecision, error) {
    query, err := dh.parseDNSQuery(packet)
    if err != nil {
        return nil, err
    }
    
    // Check cache first
    if cached := dh.cache.Get(query.Name); cached != nil {
        response := dh.createResponse(query, cached)
        return dh.sendDNSResponse(packet.Source, response)
    }
    
    // Apply DNS filtering
    if dh.filters.ShouldBlock(query.Name) {
        return dh.createBlockedResponse(query)
    }
    
    // Resolve using DoH/DoT
    response, err := dh.resolveSecurely(query)
    if err != nil {
        return nil, err
    }
    
    // Cache result
    dh.cache.Set(query.Name, response)
    
    // Log for analytics
    dh.analytics.LogQuery(query, response)
    
    return dh.sendDNSResponse(packet.Source, response)
}

// Gateway Monitoring
type GatewayMonitoring struct {
    metrics      *GatewayMetrics
    healthCheck  *HealthMonitor
    alerting     *AlertManager
    analytics    *UsageAnalytics
}

// GatewayMetrics tracks gateway performance
type GatewayMetrics struct {
    ActiveSessions    uint64
    TotalBandwidth    uint64
    ConnectionRate    float64
    ErrorRate         float64
    AverageLatency    time.Duration
    NodeUtilization   map[string]float64
    mu                sync.RWMutex
}

// CollectMetrics gathers performance metrics
func (gm *GatewayMetrics) CollectMetrics() *MetricsSnapshot {
    gm.mu.RLock()
    defer gm.mu.RUnlock()
    
    return &MetricsSnapshot{
        Timestamp:        time.Now(),
        ActiveSessions:   gm.ActiveSessions,
        TotalBandwidth:   gm.TotalBandwidth,
        ConnectionRate:   gm.ConnectionRate,
        ErrorRate:        gm.ErrorRate,
        AverageLatency:   gm.AverageLatency,
        NodeUtilization:  copyMap(gm.NodeUtilization),
    }
}

// Client Configuration Generator
type ClientConfigGenerator struct {
    templates   map[VPNProtocol]*ConfigTemplate
    certMgr     *CertificateManager
    keyMgr      *KeyManager
}

// GenerateConfig generates client configuration
func (ccg *ClientConfigGenerator) GenerateConfig(user *User, protocol VPNProtocol) (*ClientConfig, error) {
    template := ccg.templates[protocol]
    if template == nil {
        return nil, fmt.Errorf("unsupported protocol: %v", protocol)
    }
    
    config := &ClientConfig{
        Protocol:     protocol,
        ServerHost:   ccg.getServerHost(),
        ServerPort:   ccg.getServerPort(protocol),
        UserID:       user.ID,
        GeneratedAt:  time.Now(),
    }
    
    switch protocol {
    case ProtocolOpenVPN:
        return ccg.generateOpenVPNConfig(config, user)
    case ProtocolWireGuard:
        return ccg.generateWireGuardConfig(config, user)
    case ProtocolIKEv2:
        return ccg.generateIKEv2Config(config, user)
    default:
        return nil, fmt.Errorf("unsupported protocol: %v", protocol)
    }
}

// Performance Optimization
type PerformanceOptimizer struct {
    bufferSizes    map[string]int
    compression    *CompressionOptimizer
    encryption     *EncryptionOptimizer
    routing        *RoutingOptimizer
}

// OptimizeConnection optimizes connection parameters
func (po *PerformanceOptimizer) OptimizeConnection(session *VPNSession) {
    // Optimize buffer sizes based on connection characteristics
    po.optimizeBuffers(session)
    
    // Enable appropriate compression
    po.compression.OptimizeForSession(session)
    
    // Select optimal encryption
    po.encryption.SelectOptimalCipher(session)
    
    // Optimize routing
    po.routing.OptimizeForLatency(session)
}

// Auto-failover system
type FailoverManager struct {
    primaryNodes   []*ExitNode
    backupNodes    []*ExitNode
    healthChecker  *HealthChecker
    switchover     *SwitchoverManager
    notifications  *NotificationService
}

// HandleNodeFailure handles exit node failures
func (fm *FailoverManager) HandleNodeFailure(nodeID string) error {
    // Find affected sessions
    sessions := fm.findSessionsUsingNode(nodeID)
    
    // Select backup nodes
    backupNodes, err := fm.selectBackupNodes(len(sessions))
    if err != nil {
        return fmt.Errorf("no backup nodes available: %w", err)
    }
    
    // Migrate sessions
    for i, session := range sessions {
        backup := backupNodes[i%len(backupNodes)]
        if err := fm.switchover.MigrateSession(session, backup); err != nil {
            fm.notifications.AlertFailedMigration(session.ID, err)
            continue
        }
    }
    
    // Notify operators
    fm.notifications.AlertNodeFailure(nodeID, len(sessions))
    
    return nil
}

// Traffic shaping and QoS
type TrafficShaper struct {
    buckets     map[string]*TokenBucket
    queues      map[QoSClass]*PacketQueue
    scheduler   *QoSScheduler
    policies    *ShapingPolicy
}

// ShapeTraffic applies traffic shaping
func (ts *TrafficShaper) ShapeTraffic(packet *Packet, sessionID string) error {
    // Get or create token bucket for session
    bucket := ts.getBucket(sessionID)
    
    // Check if packet is allowed
    if !bucket.TakeTokens(uint64(packet.Size)) {
        return errors.New("rate limit exceeded")
    }
    
    // Classify packet for QoS
    class := ts.classifyPacket(packet)
    
    // Enqueue packet
    queue := ts.queues[class]
    return queue.Enqueue(packet)
}
```

### Advanced Gateway Features

```go
package vpngateway

import (
    "crypto/x509"
    "database/sql"
    "encoding/json"
    "time"
)

// Multi-protocol Gateway Server
type MultiProtocolGateway struct {
    protocols     map[VPNProtocol]ProtocolHandler
    unifiedAuth   *UnifiedAuthenticator
    sessionStore  *UnifiedSessionStore
    loadBalancer  *GlobalLoadBalancer
}

// ProtocolHandler interface for different VPN protocols
type ProtocolHandler interface {
    Start(ctx context.Context, config *ProtocolConfig) error
    HandleConnection(conn net.Conn, auth *AuthResult) error
    GetMetrics() *ProtocolMetrics
    Shutdown() error
}

// OpenVPN Handler
type OpenVPNHandler struct {
    server      *openvpn.Server
    config      *OpenVPNConfig
    certAuth    *CertificateAuth
    sessionMgr  *SessionManager
}

// WireGuard Handler
type WireGuardHandler struct {
    device      *wireguard.Device
    config      *WireGuardConfig
    keyMgr      *WireGuardKeyManager
    peerMgr     *PeerManager
}

// Geographic Load Balancing
type GeographicLoadBalancer struct {
    regions      map[string]*Region
    geoIP        *GeoIPService
    latencyMap   *LatencyMatrix
    affinity     *ClientAffinity
}

// Region represents a geographic region
type Region struct {
    ID          string
    Name        string
    Country     string
    Nodes       []*ExitNode
    Capacity    uint64
    Load        float64
    Latency     time.Duration
}

// SelectRegion selects optimal region for client
func (glb *GeographicLoadBalancer) SelectRegion(clientIP net.IP, preferences *UserPreferences) (*Region, error) {
    clientLoc, err := glb.geoIP.Locate(clientIP)
    if err != nil {
        return nil, err
    }
    
    // Check user preferences first
    if preferences.PreferredRegion != "" {
        if region, exists := glb.regions[preferences.PreferredRegion]; exists {
            return region, nil
        }
    }
    
    // Find closest regions with capacity
    candidates := glb.findNearbyRegions(clientLoc, 5)
    
    // Score regions based on latency, load, and capacity
    scored := glb.scoreRegions(candidates, clientLoc)
    
    if len(scored) == 0 {
        return nil, errors.New("no suitable region found")
    }
    
    return scored[0], nil
}

// Smart Routing Engine
type SmartRoutingEngine struct {
    routingTable    *RoutingTable
    pathOptimizer   *PathOptimizer
    congestionMgr   *CongestionManager
    predictor       *TrafficPredictor
}

// OptimizeRoute finds optimal path for traffic
func (sre *SmartRoutingEngine) OptimizeRoute(destination net.IP, traffic *TrafficProfile) (*OptimalRoute, error) {
    // Predict traffic patterns
    prediction := sre.predictor.PredictTraffic(destination, traffic)
    
    // Find candidate paths
    paths := sre.pathOptimizer.FindPaths(destination, 3)
    
    // Score paths based on predicted performance
    bestPath := sre.scorePaths(paths, prediction)
    
    // Check for congestion
    if sre.congestionMgr.IsCongested(bestPath) {
        // Find alternative path
        alternative := sre.findAlternativePath(destination, bestPath)
        if alternative != nil {
            bestPath = alternative
        }
    }
    
    return &OptimalRoute{
        Path:            bestPath,
        ExpectedLatency: prediction.Latency,
        ExpectedThroughput: prediction.Throughput,
        CongestionLevel: sre.congestionMgr.GetCongestionLevel(bestPath),
    }, nil
}

// Deep Packet Inspection (DPI) Evasion
type DPIEvasion struct {
    techniques    []EvasionTechnique
    detector      *DPIDetector
    obfuscator    *TrafficObfuscator
}

// EvasionTechnique interface
type EvasionTechnique interface {
    Apply(packet *Packet) *Packet
    GetType() EvasionType
    IsEffective(context *NetworkContext) bool
}

// TrafficObfuscation obfuscates VPN traffic
type TrafficObfuscation struct {
    method        ObfuscationMethod
    key           []byte
    mimicProtocol string
}

// ApplyObfuscation obfuscates packet to evade DPI
func (to *TrafficObfuscation) ApplyObfuscation(packet *Packet) *Packet {
    switch to.method {
    case ObfuscationXOR:
        return to.applyXORObfuscation(packet)
    case ObfuscationMimic:
        return to.applyProtocolMimicking(packet)
    case ObfuscationSteganography:
        return to.applySteganography(packet)
    default:
        return packet
    }
}

// Kill Switch Implementation
type KillSwitch struct {
    enabled         bool
    rules           *FirewallRules
    leakDetector    *LeakDetector
    emergencyMode   bool
    allowedApps     []string
}

// ActivateKillSwitch blocks all non-VPN traffic
func (ks *KillSwitch) ActivateKillSwitch() error {
    if !ks.enabled {
        return nil
    }
    
    // Block all outgoing traffic except VPN
    if err := ks.rules.BlockAllExceptVPN(); err != nil {
        return err
    }
    
    // Start monitoring for leaks
    go ks.leakDetector.StartMonitoring()
    
    ks.emergencyMode = true
    return nil
}

// Split Tunneling
type SplitTunneling struct {
    rules        []*SplitRule
    appSelector  *ApplicationSelector
    domainRouter *DomainRouter
    ipRouter     *IPRouter
}

// SplitRule defines traffic routing rule
type SplitRule struct {
    ID          string
    Type        SplitRuleType
    Target      string
    Action      SplitAction
    Priority    int
}

// SplitRuleType enum
type SplitRuleType int

const (
    SplitByApp SplitRuleType = iota
    SplitByDomain
    SplitByIP
    SplitByPort
)

// ProcessTraffic routes traffic based on split tunneling rules
func (st *SplitTunneling) ProcessTraffic(packet *Packet) (*RoutingDecision, error) {
    // Apply rules in priority order
    for _, rule := range st.sortedRules() {
        if match, err := st.matchRule(packet, rule); err != nil {
            return nil, err
        } else if match {
            return st.applyRule(packet, rule)
        }
    }
    
    // Default action
    return &RoutingDecision{
        Action: ActionVPN,
        Reason: "No matching split tunnel rule",
    }, nil
}

// Bandwidth Management
type BandwidthManager struct {
    allocations  map[string]*BandwidthAllocation
    monitor      *BandwidthMonitor
    shaper       *AdaptiveShaper
    predictor    *BandwidthPredictor
}

// AdaptiveShaper adapts to network conditions
type AdaptiveShaper struct {
    currentRate    uint64
    targetRate     uint64
    rttHistory     []time.Duration
    lossHistory    []float64
    algorithm      ShapingAlgorithm
}

// AdaptRate adapts shaping rate based on conditions
func (as *AdaptiveShaper) AdaptRate(rtt time.Duration, loss float64) {
    as.rttHistory = append(as.rttHistory, rtt)
    as.lossHistory = append(as.lossHistory, loss)
    
    // Keep history bounded
    if len(as.rttHistory) > 10 {
        as.rttHistory = as.rttHistory[1:]
        as.lossHistory = as.lossHistory[1:]
    }
    
    // Calculate new rate based on algorithm
    newRate := as.algorithm.CalculateRate(as.rttHistory, as.lossHistory)
    
    // Apply smoothing
    as.currentRate = as.smoothTransition(as.currentRate, newRate)
}

// Analytics and Reporting
type GatewayAnalytics struct {
    collector     *DataCollector
    aggregator    *MetricsAggregator
    reporter      *ReportGenerator
    alerter       *AlertManager
    dashboard     *AnalyticsDashboard
}

// UsageReport contains gateway usage statistics
type UsageReport struct {
    Period          TimePeriod
    TotalSessions   int
    TotalBandwidth  uint64
    AverageLatency  time.Duration
    SuccessRate     float64
    TopCountries    []CountryUsage
    TopApplications []AppUsage
    PeakUsage       PeakUsageData
    Issues          []ReportedIssue
}

// GenerateReport creates comprehensive usage report
func (ga *GatewayAnalytics) GenerateReport(period TimePeriod) (*UsageReport, error) {
    // Collect raw data
    data, err := ga.collector.CollectForPeriod(period)
    if err != nil {
        return nil, err
    }
    
    // Aggregate metrics
    aggregated := ga.aggregator.Aggregate(data)
    
    // Generate insights
    insights := ga.generateInsights(aggregated)
    
    return &UsageReport{
        Period:          period,
        TotalSessions:   aggregated.SessionCount,
        TotalBandwidth:  aggregated.TotalBandwidth,
        AverageLatency:  aggregated.AverageLatency,
        SuccessRate:     aggregated.SuccessRate,
        TopCountries:    insights.TopCountries,
        TopApplications: insights.TopApplications,
        PeakUsage:       insights.PeakUsage,
        Issues:          insights.DetectedIssues,
    }, nil
}

// High Availability Setup
type HighAvailabilityManager struct {
    primary     *VPNGateway
    secondary   *VPNGateway
    healthCheck *HealthChecker
    switchover  *AutoSwitchover
    stateSync   *StateSync
}

// StateSync synchronizes state between gateways
type StateSync struct {
    sessions      *SessionReplicator
    routes        *RouteReplicator
    certificates  *CertReplicator
    syncInterval  time.Duration
}

// SyncState synchronizes critical state
func (ss *StateSync) SyncState(primary, secondary *VPNGateway) error {
    // Sync active sessions
    if err := ss.sessions.Sync(primary.sessionMgr, secondary.sessionMgr); err != nil {
        return fmt.Errorf("session sync failed: %w", err)
    }
    
    // Sync routing table
    if err := ss.routes.Sync(primary.routingEngine, secondary.routingEngine); err != nil {
        return fmt.Errorf("route sync failed: %w", err)
    }
    
    // Sync certificates
    if err := ss.certificates.Sync(primary.authManager, secondary.authManager); err != nil {
        return fmt.Errorf("certificate sync failed: %w", err)
    }
    
    return nil
}

// API Server for management
type GatewayAPIServer struct {
    gateway    *VPNGateway
    auth       *APIAuthentication
    rateLimit  *RateLimiter
    middleware []Middleware
}

// Management API endpoints
func (api *GatewayAPIServer) setupRoutes() {
    // Status endpoints
    api.GET("/api/v1/status", api.getStatus)
    api.GET("/api/v1/metrics", api.getMetrics)
    api.GET("/api/v1/health", api.getHealth)
    
    // Session management
    api.GET("/api/v1/sessions", api.listSessions)
    api.DELETE("/api/v1/sessions/:id", api.terminateSession)
    
    // Configuration
    api.GET("/api/v1/config", api.getConfig)
    api.PUT("/api/v1/config", api.updateConfig)
    
    // Exit nodes
    api.GET("/api/v1/nodes", api.listExitNodes)
    api.POST("/api/v1/nodes/:id/disable", api.disableNode)
    
    // Reports
    api.GET("/api/v1/reports/usage", api.getUsageReport)
    api.GET("/api/v1/reports/performance", api.getPerformanceReport)
}
```

## Dependencies
- OpenVPN library for OpenVPN support
- WireGuard Go implementation
- GeoIP database for location services
- Certificate management tools
- Firewall control libraries

## Configuration
```yaml
vpn_gateway:
  listen_address: "0.0.0.0:1194"
  protocol: "openvpn"
  max_clients: 1000
  
  authentication:
    methods:
      - certificate
      - token
    require_auth: true
    session_timeout: "24h"
  
  dhcp_pool:
    network: "10.8.0.0/24"
    start: "10.8.0.100"
    end: "10.8.0.200"
    dns_servers:
      - "1.1.1.1"
      - "8.8.8.8"
  
  exit_nodes:
    discovery_interval: "30s"
    health_check_interval: "10s"
    min_nodes: 5
    max_nodes: 50
  
  load_balancing:
    strategy: "least_latency"
    failover_enabled: true
    health_threshold: 0.8
  
  qos:
    enabled: true
    bandwidth_limit: "100mbps"
    burst_size: "10mb"
    classes:
      - name: "premium"
        bandwidth: "50mbps"
        priority: 1
      - name: "standard"
        bandwidth: "30mbps"
        priority: 2
  
  security:
    kill_switch: true
    dns_leak_protection: true
    dpi_evasion: true
    perfect_forward_secrecy: true
```

## Security Considerations
1. **Traffic Inspection**: DPI evasion techniques
2. **DNS Leaks**: Secure DNS resolution
3. **Kill Switch**: Emergency traffic blocking
4. **Perfect Forward Secrecy**: Regular key rotation
5. **Certificate Validation**: Strict certificate checking

## Performance Metrics
- Connection establishment < 2 seconds
- Throughput > 100 Mbps per client
- Latency overhead < 20ms
- 99.9% uptime availability
- Support for 1000+ concurrent connections