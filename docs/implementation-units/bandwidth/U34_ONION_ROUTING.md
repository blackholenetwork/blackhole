# Unit 34: Onion Routing

## Overview
Implementation of 2-3 hop onion routing for the BlackHole network, providing anonymity and traffic analysis resistance through layered encryption and circuit-based routing.

## Implementation

### Core Onion Router

```go
package onion

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/binary"
    "errors"
    "fmt"
    "sync"
    "time"
)

// OnionRouter manages onion routing functionality
type OnionRouter struct {
    nodeID       string
    privateKey   *rsa.PrivateKey
    circuits     map[CircuitID]*Circuit
    relayTable   map[CircuitID]RelayInfo
    nodeRegistry *NodeRegistry
    cryptoCore   *CryptoCore
    mu           sync.RWMutex
}

// Circuit represents an onion routing circuit
type Circuit struct {
    ID              CircuitID
    State           CircuitState
    Hops            []*CircuitHop
    CreatedAt       time.Time
    LastActivity    time.Time
    BytesSent       uint64
    BytesReceived   uint64
    StreamWindow    int
    PackageWindow   int
}

// CircuitHop represents a hop in the circuit
type CircuitHop struct {
    NodeID          string
    PublicKey       *rsa.PublicKey
    SharedSecret    []byte
    ForwardDigest   []byte
    BackwardDigest  []byte
    ForwardCipher   cipher.Stream
    BackwardCipher  cipher.Stream
}

// CircuitID uniquely identifies a circuit
type CircuitID [16]byte

// CircuitState represents circuit status
type CircuitState int

const (
    CircuitPending CircuitState = iota
    CircuitBuilding
    CircuitReady
    CircuitDestroying
    CircuitFailed
)

// CreateCircuit builds a new onion circuit
func (or *OnionRouter) CreateCircuit(path []string) (*Circuit, error) {
    if len(path) < 2 || len(path) > 3 {
        return nil, errors.New("circuit must have 2-3 hops")
    }

    // Generate circuit ID
    circuitID := or.generateCircuitID()
    
    circuit := &Circuit{
        ID:            circuitID,
        State:         CircuitPending,
        Hops:          make([]*CircuitHop, 0, len(path)),
        CreatedAt:     time.Now(),
        LastActivity:  time.Now(),
        StreamWindow:  1000,
        PackageWindow: 1000,
    }

    or.mu.Lock()
    or.circuits[circuitID] = circuit
    or.mu.Unlock()

    // Build circuit incrementally
    for i, nodeID := range path {
        hop, err := or.extendCircuit(circuit, nodeID, i)
        if err != nil {
            circuit.State = CircuitFailed
            return nil, fmt.Errorf("failed to extend circuit to %s: %w", nodeID, err)
        }
        circuit.Hops = append(circuit.Hops, hop)
    }

    circuit.State = CircuitReady
    return circuit, nil
}

// extendCircuit extends circuit by one hop
func (or *OnionRouter) extendCircuit(circuit *Circuit, nodeID string, hopNum int) (*CircuitHop, error) {
    // Get node information
    node, err := or.nodeRegistry.GetNode(nodeID)
    if err != nil {
        return nil, err
    }

    // Create extend cell
    extendCell := &ExtendCell{
        CircuitID: circuit.ID,
        NodeID:    nodeID,
        OnionSkin: or.createOnionSkin(node.PublicKey),
    }

    // Encrypt extend cell in layers
    payload := or.encryptForCircuit(circuit, extendCell.Serialize(), hopNum)
    
    // Send extend request
    response, err := or.sendCellAndWait(circuit, CellTypeExtend, payload)
    if err != nil {
        return nil, err
    }

    // Process extended response
    hop, err := or.processExtendedResponse(response, node.PublicKey)
    if err != nil {
        return nil, err
    }

    return hop, nil
}

// OnionSkin for key exchange
type OnionSkin struct {
    EphemeralPublic []byte
    EncryptedData   []byte
}

// createOnionSkin creates DH key exchange request
func (or *OnionRouter) createOnionSkin(peerPublicKey *rsa.PublicKey) *OnionSkin {
    // Generate ephemeral key pair
    ephemeralPriv, ephemeralPub := or.cryptoCore.GenerateEphemeralKeys()
    
    // Create handshake data
    handshake := &HandshakeData{
        NodeID:    or.nodeID,
        Timestamp: time.Now(),
        Nonce:     or.cryptoCore.GenerateNonce(),
    }
    
    // Encrypt with peer's public key
    encrypted, err := rsa.EncryptOAEP(
        sha256.New(),
        rand.Reader,
        peerPublicKey,
        handshake.Serialize(),
        nil,
    )
    if err != nil {
        return nil
    }
    
    // Store ephemeral private key for later
    or.storeEphemeralKey(ephemeralPriv)
    
    return &OnionSkin{
        EphemeralPublic: ephemeralPub,
        EncryptedData:   encrypted,
    }
}

// Layered encryption for onion routing
type LayeredEncryption struct {
    layers []EncryptionLayer
}

// EncryptionLayer represents one layer of encryption
type EncryptionLayer struct {
    NodeID    string
    Key       []byte
    IV        []byte
    Algorithm string
}

// EncryptData applies multiple layers of encryption
func (le *LayeredEncryption) EncryptData(data []byte) ([]byte, error) {
    encrypted := data
    
    // Apply encryption layers in reverse order
    for i := len(le.layers) - 1; i >= 0; i-- {
        layer := le.layers[i]
        
        block, err := aes.NewCipher(layer.Key)
        if err != nil {
            return nil, err
        }
        
        // Add padding
        encrypted = addPKCS7Padding(encrypted, block.BlockSize())
        
        // Encrypt
        mode := cipher.NewCBCEncrypter(block, layer.IV)
        mode.CryptBlocks(encrypted, encrypted)
    }
    
    return encrypted, nil
}

// DecryptLayer removes one layer of encryption
func (le *LayeredEncryption) DecryptLayer(data []byte, layerIndex int) ([]byte, error) {
    if layerIndex >= len(le.layers) {
        return nil, errors.New("invalid layer index")
    }
    
    layer := le.layers[layerIndex]
    
    block, err := aes.NewCipher(layer.Key)
    if err != nil {
        return nil, err
    }
    
    // Decrypt
    mode := cipher.NewCBCDecrypter(block, layer.IV)
    decrypted := make([]byte, len(data))
    mode.CryptBlocks(decrypted, data)
    
    // Remove padding
    decrypted, err = removePKCS7Padding(decrypted)
    if err != nil {
        return nil, err
    }
    
    return decrypted, nil
}

// Cell structure for onion routing protocol
type Cell struct {
    CircuitID CircuitID
    Command   CellCommand
    Payload   [509]byte // Fixed size for traffic analysis resistance
}

// CellCommand types
type CellCommand uint8

const (
    CellTypeCreate CellCommand = iota
    CellTypeCreated
    CellTypeRelay
    CellTypeDestroy
    CellTypeExtend
    CellTypeExtended
    CellTypePadding
)

// RelayCell for data transmission
type RelayCell struct {
    StreamID    uint16
    Digest      [6]byte  // Truncated SHA-1 for verification
    Length      uint16
    Command     RelayCommand
    Data        []byte
}

// RelayCommand types
type RelayCommand uint8

const (
    RelayData RelayCommand = iota
    RelayBegin
    RelayEnd
    RelayConnected
    RelayExtend
    RelayExtended
    RelayTruncate
    RelayTruncated
    RelayDrop
)

// ProcessRelayCell handles incoming relay cells
func (or *OnionRouter) ProcessRelayCell(cell *Cell) error {
    or.mu.RLock()
    circuit, exists := or.circuits[cell.CircuitID]
    or.mu.RUnlock()
    
    if !exists {
        return errors.New("circuit not found")
    }
    
    // Try to decrypt at each layer
    payload := cell.Payload[:]
    
    for i, hop := range circuit.Hops {
        // Decrypt one layer
        decrypted := make([]byte, len(payload))
        hop.BackwardCipher.XORKeyStream(decrypted, payload)
        
        // Check if this is our layer (verify digest)
        relayCell, err := or.parseRelayCell(decrypted)
        if err == nil && or.verifyRelayCell(relayCell, hop) {
            // This cell is for us or needs to be processed
            return or.handleRelayCommand(circuit, relayCell, i)
        }
        
        // Not our layer, continue with decrypted payload
        payload = decrypted
    }
    
    return errors.New("unable to decrypt relay cell")
}

// Route selection algorithm
type RouteSelector struct {
    nodeRegistry *NodeRegistry
    pathHistory  *PathHistory
    constraints  *RouteConstraints
}

// RouteConstraints defines path selection constraints
type RouteConstraints struct {
    MinBandwidth    uint64
    MaxLatency      time.Duration
    RequiredFlags   []string
    ExcludeNodes    []string
    ExcludeCountries []string
    EnforceDistinct bool  // No two nodes from same /16 subnet
}

// SelectPath chooses nodes for circuit
func (rs *RouteSelector) SelectPath(hopCount int) ([]string, error) {
    if hopCount < 2 || hopCount > 3 {
        return nil, errors.New("invalid hop count")
    }
    
    // Get candidate nodes
    candidates, err := rs.getCandidateNodes()
    if err != nil {
        return nil, err
    }
    
    // Apply constraints
    filtered := rs.applyConstraints(candidates)
    
    if len(filtered) < hopCount {
        return nil, errors.New("insufficient nodes meeting constraints")
    }
    
    // Select nodes with weighted probability
    path := make([]string, 0, hopCount)
    used := make(map[string]bool)
    usedSubnets := make(map[string]bool)
    
    for i := 0; i < hopCount; i++ {
        node := rs.selectNode(filtered, used, usedSubnets, i)
        if node == nil {
            return nil, errors.New("unable to select suitable node")
        }
        
        path = append(path, node.ID)
        used[node.ID] = true
        usedSubnets[node.Subnet] = true
    }
    
    // Record path for analysis
    rs.pathHistory.RecordPath(path)
    
    return path, nil
}

// Circuit construction protocol
type CircuitBuilder struct {
    router      *OnionRouter
    crypto      *CryptoCore
    handshaker  *Handshaker
}

// BuildCircuit constructs a circuit incrementally
func (cb *CircuitBuilder) BuildCircuit(path []string) (*Circuit, error) {
    if len(path) == 0 {
        return nil, errors.New("empty path")
    }
    
    // Phase 1: Create circuit with first hop
    circuit, err := cb.createFirstHop(path[0])
    if err != nil {
        return nil, fmt.Errorf("failed to create first hop: %w", err)
    }
    
    // Phase 2: Extend circuit for remaining hops
    for i := 1; i < len(path); i++ {
        if err := cb.extendToNode(circuit, path[i]); err != nil {
            cb.destroyCircuit(circuit)
            return nil, fmt.Errorf("failed to extend to hop %d: %w", i, err)
        }
    }
    
    // Phase 3: Verify circuit is functional
    if err := cb.verifyCircuit(circuit); err != nil {
        cb.destroyCircuit(circuit)
        return nil, fmt.Errorf("circuit verification failed: %w", err)
    }
    
    return circuit, nil
}

// Handshaker performs cryptographic handshakes
type Handshaker struct {
    nodeID     string
    privateKey *rsa.PrivateKey
    dhParams   *DHParameters
}

// PerformHandshake executes TAP or ntor handshake
func (h *Handshaker) PerformHandshake(nodeID string, publicKey *rsa.PublicKey) (*HandshakeResult, error) {
    // Use ntor handshake for better security
    return h.performNtorHandshake(nodeID, publicKey)
}

// performNtorHandshake implements the ntor handshake protocol
func (h *Handshaker) performNtorHandshake(nodeID string, publicKey *rsa.PublicKey) (*HandshakeResult, error) {
    // Generate ephemeral keypair
    ephemeralPriv, ephemeralPub := generateCurve25519KeyPair()
    
    // Create client handshake
    clientHandshake := &NtorClientHandshake{
        NodeID:          nodeID,
        IdentityKey:     publicKey,
        EphemeralKey:    ephemeralPub,
        ClientTimestamp: time.Now(),
    }
    
    // Send handshake and receive response
    response, err := h.sendHandshake(clientHandshake)
    if err != nil {
        return nil, err
    }
    
    // Derive shared secrets
    sharedSecret := h.deriveSharedSecret(
        ephemeralPriv,
        response.ServerEphemeral,
        response.ServerIdentity,
    )
    
    // Derive key material
    keyMaterial := h.kdf(sharedSecret, "ntor-curve25519-sha256", 92)
    
    return &HandshakeResult{
        ForwardDigest:  keyMaterial[0:20],
        BackwardDigest: keyMaterial[20:40],
        ForwardKey:     keyMaterial[40:56],
        BackwardKey:    keyMaterial[56:72],
        ForwardIV:      keyMaterial[72:82],
        BackwardIV:     keyMaterial[82:92],
    }, nil
}

// Traffic analysis resistance
type TrafficPadding struct {
    enabled    bool
    interval   time.Duration
    jitter     time.Duration
    dropRate   float64
}

// GeneratePadding creates cover traffic
func (tp *TrafficPadding) GeneratePadding(circuit *Circuit) *Cell {
    if !tp.enabled {
        return nil
    }
    
    // Probabilistic drop
    if rand.Float64() < tp.dropRate {
        return nil
    }
    
    // Create padding cell
    cell := &Cell{
        CircuitID: circuit.ID,
        Command:   CellTypePadding,
    }
    
    // Fill with random data
    rand.Read(cell.Payload[:])
    
    return cell
}

// Circuit performance monitor
type CircuitMonitor struct {
    circuits   map[CircuitID]*CircuitMetrics
    analyzer   *PerformanceAnalyzer
    mu         sync.RWMutex
}

// CircuitMetrics tracks circuit performance
type CircuitMetrics struct {
    Latency       time.Duration
    Throughput    float64
    PacketLoss    float64
    Jitter        time.Duration
    LastUpdated   time.Time
    HealthScore   float64
}

// MonitorCircuit tracks circuit health
func (cm *CircuitMonitor) MonitorCircuit(circuit *Circuit) {
    metrics := &CircuitMetrics{
        LastUpdated: time.Now(),
    }
    
    // Measure latency
    metrics.Latency = cm.measureCircuitLatency(circuit)
    
    // Calculate throughput
    metrics.Throughput = cm.calculateThroughput(circuit)
    
    // Estimate packet loss
    metrics.PacketLoss = cm.estimatePacketLoss(circuit)
    
    // Compute health score
    metrics.HealthScore = cm.computeHealthScore(metrics)
    
    cm.mu.Lock()
    cm.circuits[circuit.ID] = metrics
    cm.mu.Unlock()
    
    // Trigger actions based on health
    if metrics.HealthScore < 0.5 {
        cm.analyzer.SuggestCircuitRebuild(circuit.ID)
    }
}

// Stream multiplexing over circuits
type StreamManager struct {
    streams     map[uint16]*Stream
    circuits    map[CircuitID]*Circuit
    nextStream  uint16
    mu          sync.RWMutex
}

// Stream represents a TCP-like stream over a circuit
type Stream struct {
    ID           uint16
    CircuitID    CircuitID
    State        StreamState
    SendWindow   int
    RecvWindow   int
    SendBuffer   []byte
    RecvBuffer   []byte
    Connected    bool
}

// CreateStream creates new stream over circuit
func (sm *StreamManager) CreateStream(circuitID CircuitID, destination string) (*Stream, error) {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    circuit, exists := sm.circuits[circuitID]
    if !exists {
        return nil, errors.New("circuit not found")
    }
    
    if circuit.State != CircuitReady {
        return nil, errors.New("circuit not ready")
    }
    
    // Allocate stream ID
    streamID := sm.nextStream
    sm.nextStream++
    
    stream := &Stream{
        ID:         streamID,
        CircuitID:  circuitID,
        State:      StreamConnecting,
        SendWindow: 500,
        RecvWindow: 500,
    }
    
    sm.streams[streamID] = stream
    
    // Send BEGIN cell
    beginCell := &RelayCell{
        StreamID: streamID,
        Command:  RelayBegin,
        Data:     []byte(destination),
    }
    
    if err := sm.sendRelayCell(circuit, beginCell); err != nil {
        delete(sm.streams, streamID)
        return nil, err
    }
    
    return stream, nil
}
```

### Circuit Management and Optimization

```go
package onion

import (
    "container/heap"
    "context"
    "sync/atomic"
    "time"
)

// CircuitManager manages circuit lifecycle and optimization
type CircuitManager struct {
    router         *OnionRouter
    activeCircuits map[CircuitID]*ManagedCircuit
    circuitPool    *CircuitPool
    optimizer      *CircuitOptimizer
    scheduler      *CircuitScheduler
    mu             sync.RWMutex
}

// ManagedCircuit wraps circuit with management metadata
type ManagedCircuit struct {
    *Circuit
    Purpose        CircuitPurpose
    LastUsed       time.Time
    UseCount       uint64
    FailureCount   uint32
    Performance    *CircuitPerformance
}

// CircuitPurpose defines circuit usage type
type CircuitPurpose int

const (
    GeneralPurpose CircuitPurpose = iota
    StreamIsolation
    HiddenService
    DirectoryFetch
)

// CircuitPool maintains ready circuits
type CircuitPool struct {
    minSize      int
    maxSize      int
    circuits     []*ManagedCircuit
    building     int32
    purposeMap   map[CircuitPurpose][]*ManagedCircuit
}

// GetCircuit retrieves suitable circuit from pool
func (cp *CircuitPool) GetCircuit(purpose CircuitPurpose, constraints *SelectionConstraints) (*ManagedCircuit, error) {
    // Try to find existing suitable circuit
    if circuit := cp.findSuitableCircuit(purpose, constraints); circuit != nil {
        atomic.AddUint64(&circuit.UseCount, 1)
        circuit.LastUsed = time.Now()
        return circuit, nil
    }
    
    // Build new circuit if pool not full
    if len(cp.circuits) < cp.maxSize {
        return cp.buildNewCircuit(purpose, constraints)
    }
    
    // Wait for circuit to become available
    return cp.waitForCircuit(purpose, constraints)
}

// CircuitOptimizer optimizes circuit performance
type CircuitOptimizer struct {
    manager      *CircuitManager
    predictor    *PerformancePredictor
    strategies   []OptimizationStrategy
}

// OptimizationStrategy defines optimization approach
type OptimizationStrategy interface {
    ShouldOptimize(circuit *ManagedCircuit) bool
    Optimize(circuit *ManagedCircuit) error
    Priority() int
}

// LatencyOptimization reduces circuit latency
type LatencyOptimization struct {
    threshold time.Duration
}

func (lo *LatencyOptimization) ShouldOptimize(circuit *ManagedCircuit) bool {
    return circuit.Performance.AverageLatency > lo.threshold
}

func (lo *LatencyOptimization) Optimize(circuit *ManagedCircuit) error {
    // Rebuild circuit with lower latency path
    newPath := lo.selectLowLatencyPath(circuit)
    return circuit.manager.RebuildCircuit(circuit.ID, newPath)
}

// ThroughputOptimization improves bandwidth
type ThroughputOptimization struct {
    minThroughput float64
}

func (to *ThroughputOptimization) Optimize(circuit *ManagedCircuit) error {
    // Select high-bandwidth nodes
    nodes := to.selectHighBandwidthNodes()
    return circuit.manager.RebuildWithNodes(circuit.ID, nodes)
}

// CircuitScheduler schedules circuit operations
type CircuitScheduler struct {
    queue      PriorityQueue
    workers    int
    ctx        context.Context
    cancel     context.CancelFunc
}

// ScheduleOperation adds operation to queue
func (cs *CircuitScheduler) ScheduleOperation(op CircuitOperation) {
    cs.queue.Push(op)
}

// CircuitOperation represents a scheduled operation
type CircuitOperation interface {
    Execute() error
    Priority() int
    Deadline() time.Time
}

// BuildOperation builds new circuit
type BuildOperation struct {
    Path     []string
    Purpose  CircuitPurpose
    Callback func(*Circuit, error)
    priority int
    deadline time.Time
}

func (bo *BuildOperation) Execute() error {
    circuit, err := bo.buildCircuit()
    bo.Callback(circuit, err)
    return err
}

// Advanced route selection
type AdvancedRouteSelector struct {
    nodeDB       *NodeDatabase
    geoIP        *GeoIPDatabase
    asDB         *ASDatabase
    ml           *MLRoutePredictor
    constraints  *GlobalConstraints
}

// PathQuality measures path characteristics
type PathQuality struct {
    GeoDiversity     float64  // Geographic distribution
    ASIndependence   float64  // Autonomous system diversity
    Reliability      float64  // Historical reliability
    ExpectedLatency  time.Duration
    ExpectedBandwidth float64
}

// SelectOptimalPath uses ML to select best path
func (ars *AdvancedRouteSelector) SelectOptimalPath(requirements *PathRequirements) ([]string, *PathQuality, error) {
    // Get candidate nodes
    candidates := ars.nodeDB.GetActiveNodes()
    
    // Apply hard constraints
    filtered := ars.applyHardConstraints(candidates, requirements)
    
    // Generate candidate paths
    paths := ars.generateCandidatePaths(filtered, requirements.HopCount)
    
    // Score paths using ML model
    scoredPaths := make([]*ScoredPath, 0, len(paths))
    for _, path := range paths {
        quality := ars.evaluatePathQuality(path)
        score := ars.ml.PredictPathScore(path, quality, requirements)
        
        scoredPaths = append(scoredPaths, &ScoredPath{
            Path:    path,
            Quality: quality,
            Score:   score,
        })
    }
    
    // Select best path
    best := ars.selectBestPath(scoredPaths, requirements)
    
    return best.Path, best.Quality, nil
}

// Congestion control for circuits
type CircuitCongestionControl struct {
    circuit      *Circuit
    sendWindow   int32
    recvWindow   int32
    inFlight     int32
    rtt          time.Duration
    rttVar       time.Duration
    congestion   bool
}

// UpdateWindow adjusts congestion window
func (ccc *CircuitCongestionControl) UpdateWindow(acked bool, rtt time.Duration) {
    if acked {
        // Update RTT estimates
        ccc.updateRTT(rtt)
        
        // Increase window if not congested
        if !ccc.congestion && atomic.LoadInt32(&ccc.sendWindow) < 1000 {
            atomic.AddInt32(&ccc.sendWindow, 1)
        }
    } else {
        // Decrease window on loss
        current := atomic.LoadInt32(&ccc.sendWindow)
        atomic.StoreInt32(&ccc.sendWindow, current/2)
        ccc.congestion = true
    }
}

// Circuit failure detection and recovery
type CircuitHealthMonitor struct {
    circuits      map[CircuitID]*CircuitHealth
    detector      *FailureDetector
    recovery      *RecoveryManager
    mu            sync.RWMutex
}

// CircuitHealth tracks circuit health metrics
type CircuitHealth struct {
    Circuit           *Circuit
    ConsecutiveFails  int
    LastSuccess       time.Time
    FailureRate       float64
    RecoveryAttempts  int
    HealthStatus      HealthStatus
}

// HealthStatus represents circuit health state
type HealthStatus int

const (
    HealthyStatus HealthStatus = iota
    DegradedStatus
    FailingStatus
    DeadStatus
)

// MonitorHealth continuously monitors circuit health
func (chm *CircuitHealthMonitor) MonitorHealth(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            chm.checkAllCircuits()
        }
    }
}

// Circuit crypto optimization
type CryptoOptimizer struct {
    aesNI        bool
    parallelism  int
    batchSize    int
}

// OptimizedEncrypt performs optimized encryption
func (co *CryptoOptimizer) OptimizedEncrypt(layers []CryptoLayer, data []byte) ([]byte, error) {
    if co.aesNI {
        return co.encryptAESNI(layers, data)
    }
    
    // Parallel encryption for multiple layers
    if len(layers) > 1 && co.parallelism > 1 {
        return co.encryptParallel(layers, data)
    }
    
    return co.encryptSequential(layers, data)
}

// Circuit bandwidth allocation
type BandwidthAllocator struct {
    totalBandwidth uint64
    circuits       map[CircuitID]*BandwidthAllocation
    fairness       FairnessPolicy
    mu             sync.RWMutex
}

// BandwidthAllocation for a circuit
type BandwidthAllocation struct {
    Guaranteed  uint64
    Maximum     uint64
    Current     uint64
    Priority    int
    BurstCredit uint64
}

// AllocateBandwidth assigns bandwidth to circuit
func (ba *BandwidthAllocator) AllocateBandwidth(circuitID CircuitID, requested uint64) uint64 {
    ba.mu.Lock()
    defer ba.mu.Unlock()
    
    allocation, exists := ba.circuits[circuitID]
    if !exists {
        allocation = ba.createDefaultAllocation()
        ba.circuits[circuitID] = allocation
    }
    
    // Apply fairness policy
    allowed := ba.fairness.CalculateAllowance(allocation, requested, ba.getAvailable())
    
    // Update current usage
    allocation.Current = allowed
    
    // Update burst credit
    if allowed < allocation.Guaranteed {
        allocation.BurstCredit += allocation.Guaranteed - allowed
    }
    
    return allowed
}
```

## Dependencies
- Curve25519 for key exchange
- AES-CTR for stream cipher
- SHA-256 for digests
- PKCS7 padding
- Golang crypto libraries

## Configuration
```yaml
onion_routing:
  enabled: true
  default_hops: 3
  max_circuits: 100
  circuit_lifetime: 10m
  route_selection:
    min_bandwidth: 1000000  # 1 Mbps
    max_latency: 200ms
    enforce_geo_diversity: true
    enforce_as_diversity: true
  traffic_padding:
    enabled: true
    interval: 100ms
    jitter: 50ms
  optimization:
    latency_threshold: 150ms
    throughput_min: 500000  # 500 Kbps
    health_check_interval: 5s
  security:
    handshake_timeout: 10s
    key_rotation_interval: 1h
    enforce_perfect_forward_secrecy: true
```

## Security Considerations
1. **Traffic Analysis**: Padding and timing obfuscation
2. **Correlation Attacks**: Stream isolation and circuit rotation
3. **Compromise Recovery**: Perfect forward secrecy
4. **Node Selection**: Avoid correlated nodes
5. **Crypto Agility**: Support for algorithm upgrades

## Performance Metrics
- Circuit build time < 2 seconds
- Latency overhead < 50ms per hop
- Throughput > 10 Mbps per circuit
- Crypto operations < 5% CPU
- Memory < 10MB per circuit