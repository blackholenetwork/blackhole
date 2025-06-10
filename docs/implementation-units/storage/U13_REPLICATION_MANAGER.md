# U13: Replication Manager

## Overview

The Replication Manager ensures data durability and availability through intelligent 3x geographic replication across IPFS nodes. It handles pin management, health monitoring, automatic repair, and geographic distribution to maximize data resilience while minimizing latency.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Replication Manager                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │ Pin Coordinator  │  │ Health Monitor    │  │ Geo Distributor│ │
│  │                  │  │                  │  │                │ │
│  │ • Pin Management │  │ • Node Health    │  │ • Region Select│ │
│  │ • Pin Tracking   │  │ • Data Integrity │  │ • Latency Calc │ │
│  │ • Pin Rotation   │  │ • Auto Repair    │  │ • Load Balance │ │
│  └─────────────────┘  └──────────────────┘  └────────────────┘ │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    IPFS Integration Layer                    │ │
│  │  • Node Management  • Pin Operations  • Content Routing      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Pin Coordinator
- Manages pinning operations across multiple IPFS nodes
- Tracks pin status and replication count
- Handles pin rotation for load balancing
- Implements pin garbage collection

### 2. Health Monitor
- Monitors IPFS node availability and performance
- Verifies data integrity through periodic checks
- Detects failed replicas and triggers repairs
- Tracks node reputation and reliability

### 3. Geographic Distributor
- Selects optimal regions for replica placement
- Calculates network latency between regions
- Balances load across geographic locations
- Ensures replicas span multiple failure domains

### 4. IPFS Integration Layer
- Manages connections to IPFS nodes
- Handles pin/unpin operations
- Implements content routing
- Provides failover mechanisms

## Implementation

### Core Types and Interfaces

```go
package replication

import (
    "context"
    "errors"
    "fmt"
    "math"
    "sync"
    "time"

    "github.com/ipfs/go-cid"
    ipfsapi "github.com/ipfs/go-ipfs-api"
    "github.com/prometheus/client_golang/prometheus"
)

const (
    // Replication parameters
    TargetReplicas      = 3
    MinReplicas         = 2
    MaxReplicationTime  = 5 * time.Minute
    HealthCheckInterval = 1 * time.Minute
    RepairInterval      = 5 * time.Minute
    
    // Geographic regions
    RegionNorthAmerica = "na"
    RegionEurope       = "eu"
    RegionAsiaPacific  = "ap"
    RegionSouthAmerica = "sa"
    RegionAfrica       = "af"
    RegionMiddleEast   = "me"
)

// ReplicationManager manages data replication across IPFS nodes
type ReplicationManager struct {
    pinCoordinator  *PinCoordinator
    healthMonitor   *HealthMonitor
    geoDistributor  *GeographicDistributor
    ipfsLayer       *IPFSLayer
    
    mu              sync.RWMutex
    replicationMap  map[string]*ReplicationStatus
    
    // Metrics
    replicationGauge    prometheus.Gauge
    healthCheckCounter  prometheus.Counter
    repairCounter       prometheus.Counter
}

// ReplicationStatus tracks the replication status of content
type ReplicationStatus struct {
    CID             string
    Replicas        []*Replica
    TargetReplicas  int
    CreatedAt       time.Time
    LastChecked     time.Time
    LastRepaired    time.Time
    Status          string
}

// Replica represents a single replica of content
type Replica struct {
    NodeID       string
    Region       string
    PinnedAt     time.Time
    LastVerified time.Time
    Healthy      bool
    Latency      time.Duration
}

// PinCoordinator manages pinning operations
type PinCoordinator struct {
    mu          sync.RWMutex
    nodes       map[string]*IPFSNode
    pinQueue    chan *PinRequest
    pinTracking map[string]*PinStatus
}

// IPFSNode represents an IPFS node
type IPFSNode struct {
    ID          string
    API         *ipfsapi.Shell
    Region      string
    Endpoint    string
    Healthy     bool
    Capacity    int64
    Used        int64
    Reputation  float64
    LastSeen    time.Time
}

// HealthMonitor monitors node and data health
type HealthMonitor struct {
    checkQueue   chan *HealthCheck
    repairQueue  chan *RepairRequest
    nodeHealth   map[string]*NodeHealth
    mu           sync.RWMutex
}

// GeographicDistributor handles geographic distribution
type GeographicDistributor struct {
    regions      map[string]*Region
    latencyMap   map[string]map[string]time.Duration
    mu           sync.RWMutex
}

// Region represents a geographic region
type Region struct {
    ID          string
    Name        string
    Nodes       []string
    LoadFactor  float64
    Coordinates GeographicCoordinates
}

// GeographicCoordinates for distance calculations
type GeographicCoordinates struct {
    Latitude  float64
    Longitude float64
}
```

### Pin Coordinator Implementation

```go
// NewPinCoordinator creates a new pin coordinator
func NewPinCoordinator(nodes []*IPFSNode) *PinCoordinator {
    pc := &PinCoordinator{
        nodes:       make(map[string]*IPFSNode),
        pinQueue:    make(chan *PinRequest, 1000),
        pinTracking: make(map[string]*PinStatus),
    }
    
    for _, node := range nodes {
        pc.nodes[node.ID] = node
    }
    
    // Start pin workers
    for i := 0; i < 10; i++ {
        go pc.pinWorker()
    }
    
    return pc
}

// PinRequest represents a request to pin content
type PinRequest struct {
    CID        cid.Cid
    NodeID     string
    Priority   int
    ResultChan chan error
}

// PinStatus tracks the status of a pin operation
type PinStatus struct {
    CID       string
    NodeID    string
    Status    string
    StartedAt time.Time
    PinnedAt  time.Time
    Error     error
}

// PinContent pins content to a specific node
func (pc *PinCoordinator) PinContent(ctx context.Context, contentCID cid.Cid, nodeID string) error {
    pc.mu.RLock()
    node, exists := pc.nodes[nodeID]
    pc.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("node %s not found", nodeID)
    }
    
    if !node.Healthy {
        return fmt.Errorf("node %s is not healthy", nodeID)
    }
    
    // Check capacity
    if node.Used >= node.Capacity {
        return fmt.Errorf("node %s has reached capacity", nodeID)
    }
    
    // Create pin request
    resultChan := make(chan error, 1)
    req := &PinRequest{
        CID:        contentCID,
        NodeID:     nodeID,
        Priority:   0,
        ResultChan: resultChan,
    }
    
    // Submit to queue
    select {
    case pc.pinQueue <- req:
    case <-ctx.Done():
        return ctx.Err()
    }
    
    // Wait for result
    select {
    case err := <-resultChan:
        return err
    case <-ctx.Done():
        return ctx.Err()
    }
}

// pinWorker processes pin requests
func (pc *PinCoordinator) pinWorker() {
    for req := range pc.pinQueue {
        pc.processPinRequest(req)
    }
}

// processPinRequest handles a single pin request
func (pc *PinCoordinator) processPinRequest(req *PinRequest) {
    pc.mu.RLock()
    node, exists := pc.nodes[req.NodeID]
    pc.mu.RUnlock()
    
    if !exists {
        req.ResultChan <- fmt.Errorf("node not found")
        return
    }
    
    // Track pin status
    status := &PinStatus{
        CID:       req.CID.String(),
        NodeID:    req.NodeID,
        Status:    "pinning",
        StartedAt: time.Now(),
    }
    
    pc.mu.Lock()
    pc.pinTracking[req.CID.String()+":"+req.NodeID] = status
    pc.mu.Unlock()
    
    // Perform pin operation
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()
    
    err := node.API.Pin(req.CID.String())
    
    // Update status
    pc.mu.Lock()
    if err != nil {
        status.Status = "failed"
        status.Error = err
    } else {
        status.Status = "pinned"
        status.PinnedAt = time.Now()
        
        // Update node usage (estimated)
        node.Used += 1024 * 1024 // Placeholder - would get actual size
    }
    pc.mu.Unlock()
    
    req.ResultChan <- err
}

// UnpinContent removes a pin from a node
func (pc *PinCoordinator) UnpinContent(ctx context.Context, contentCID cid.Cid, nodeID string) error {
    pc.mu.RLock()
    node, exists := pc.nodes[nodeID]
    pc.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("node %s not found", nodeID)
    }
    
    // Unpin from node
    err := node.API.Unpin(contentCID.String())
    if err != nil {
        return fmt.Errorf("failed to unpin from node %s: %w", nodeID, err)
    }
    
    // Update tracking
    pc.mu.Lock()
    delete(pc.pinTracking, contentCID.String()+":"+nodeID)
    node.Used -= 1024 * 1024 // Placeholder
    pc.mu.Unlock()
    
    return nil
}

// GetPinStatus returns the pin status for content
func (pc *PinCoordinator) GetPinStatus(contentCID cid.Cid) ([]*PinStatus, error) {
    pc.mu.RLock()
    defer pc.mu.RUnlock()
    
    var statuses []*PinStatus
    cidStr := contentCID.String()
    
    for key, status := range pc.pinTracking {
        if len(key) > len(cidStr) && key[:len(cidStr)] == cidStr {
            statuses = append(statuses, status)
        }
    }
    
    return statuses, nil
}

// RotatePins rebalances pins across nodes
func (pc *PinCoordinator) RotatePins(ctx context.Context) error {
    pc.mu.RLock()
    
    // Calculate load factors
    loadFactors := make(map[string]float64)
    for nodeID, node := range pc.nodes {
        if node.Capacity > 0 {
            loadFactors[nodeID] = float64(node.Used) / float64(node.Capacity)
        }
    }
    pc.mu.RUnlock()
    
    // Find overloaded and underloaded nodes
    var overloaded, underloaded []string
    avgLoad := 0.0
    
    for nodeID, load := range loadFactors {
        avgLoad += load
        if load > 0.8 {
            overloaded = append(overloaded, nodeID)
        } else if load < 0.5 {
            underloaded = append(underloaded, nodeID)
        }
    }
    avgLoad /= float64(len(loadFactors))
    
    // Rebalance if needed
    if len(overloaded) > 0 && len(underloaded) > 0 {
        return pc.rebalancePins(ctx, overloaded, underloaded)
    }
    
    return nil
}

func (pc *PinCoordinator) rebalancePins(ctx context.Context, overloaded, underloaded []string) error {
    // Implementation would move pins from overloaded to underloaded nodes
    // This is a simplified version
    
    for _, fromNode := range overloaded {
        for _, toNode := range underloaded {
            // Get some pins from overloaded node
            pc.mu.RLock()
            var pinsToMove []string
            for key, status := range pc.pinTracking {
                if status.NodeID == fromNode && status.Status == "pinned" {
                    pinsToMove = append(pinsToMove, status.CID)
                    if len(pinsToMove) >= 10 {
                        break
                    }
                }
            }
            pc.mu.RUnlock()
            
            // Move pins
            for _, cidStr := range pinsToMove {
                c, err := cid.Parse(cidStr)
                if err != nil {
                    continue
                }
                
                // Pin to new node
                if err := pc.PinContent(ctx, c, toNode); err != nil {
                    continue
                }
                
                // Unpin from old node
                pc.UnpinContent(ctx, c, fromNode)
            }
        }
    }
    
    return nil
}
```

### Health Monitor Implementation

```go
// NewHealthMonitor creates a new health monitor
func NewHealthMonitor() *HealthMonitor {
    hm := &HealthMonitor{
        checkQueue:  make(chan *HealthCheck, 1000),
        repairQueue: make(chan *RepairRequest, 100),
        nodeHealth:  make(map[string]*NodeHealth),
    }
    
    // Start health check workers
    for i := 0; i < 5; i++ {
        go hm.healthCheckWorker()
    }
    
    // Start repair workers
    for i := 0; i < 3; i++ {
        go hm.repairWorker()
    }
    
    return hm
}

// HealthCheck represents a health check request
type HealthCheck struct {
    Type       string // "node" or "content"
    Target     string // NodeID or CID
    ResultChan chan *HealthCheckResult
}

// HealthCheckResult contains health check results
type HealthCheckResult struct {
    Healthy     bool
    Error       error
    Latency     time.Duration
    Details     map[string]interface{}
}

// NodeHealth tracks node health metrics
type NodeHealth struct {
    NodeID          string
    LastCheck       time.Time
    Healthy         bool
    ResponseTime    time.Duration
    SuccessRate     float64
    ConsecutiveFails int
}

// RepairRequest represents a repair request
type RepairRequest struct {
    CID         string
    FailedNodes []string
    Priority    int
}

// CheckNodeHealth checks the health of a specific node
func (hm *HealthMonitor) CheckNodeHealth(ctx context.Context, node *IPFSNode) (*HealthCheckResult, error) {
    resultChan := make(chan *HealthCheckResult, 1)
    
    check := &HealthCheck{
        Type:       "node",
        Target:     node.ID,
        ResultChan: resultChan,
    }
    
    select {
    case hm.checkQueue <- check:
    case <-ctx.Done():
        return nil, ctx.Err()
    }
    
    select {
    case result := <-resultChan:
        return result, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}

// CheckContentHealth verifies content is accessible
func (hm *HealthMonitor) CheckContentHealth(ctx context.Context, contentCID cid.Cid, nodeID string) (*HealthCheckResult, error) {
    resultChan := make(chan *HealthCheckResult, 1)
    
    check := &HealthCheck{
        Type:       "content",
        Target:     contentCID.String() + ":" + nodeID,
        ResultChan: resultChan,
    }
    
    select {
    case hm.checkQueue <- check:
    case <-ctx.Done():
        return nil, ctx.Err()
    }
    
    select {
    case result := <-resultChan:
        return result, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}

// healthCheckWorker processes health checks
func (hm *HealthMonitor) healthCheckWorker() {
    for check := range hm.checkQueue {
        hm.processHealthCheck(check)
    }
}

// processHealthCheck handles a single health check
func (hm *HealthMonitor) processHealthCheck(check *HealthCheck) {
    start := time.Now()
    result := &HealthCheckResult{
        Healthy: false,
        Details: make(map[string]interface{}),
    }
    
    switch check.Type {
    case "node":
        result = hm.checkNode(check.Target)
    case "content":
        result = hm.checkContent(check.Target)
    }
    
    result.Latency = time.Since(start)
    check.ResultChan <- result
}

// checkNode performs node health check
func (hm *HealthMonitor) checkNode(nodeID string) *HealthCheckResult {
    result := &HealthCheckResult{
        Details: make(map[string]interface{}),
    }
    
    // Get node from somewhere (simplified)
    // In real implementation, would get from node registry
    
    // Ping node
    // Check API responsiveness
    // Verify storage capacity
    
    // Update node health tracking
    hm.mu.Lock()
    health, exists := hm.nodeHealth[nodeID]
    if !exists {
        health = &NodeHealth{
            NodeID:      nodeID,
            SuccessRate: 1.0,
        }
        hm.nodeHealth[nodeID] = health
    }
    
    health.LastCheck = time.Now()
    
    // Simplified health check
    isHealthy := true // Would perform actual checks
    
    if isHealthy {
        health.Healthy = true
        health.ConsecutiveFails = 0
        health.SuccessRate = (health.SuccessRate*0.95 + 0.05)
        result.Healthy = true
    } else {
        health.Healthy = false
        health.ConsecutiveFails++
        health.SuccessRate = (health.SuccessRate * 0.95)
        result.Error = fmt.Errorf("node unhealthy")
    }
    hm.mu.Unlock()
    
    return result
}

// checkContent verifies content availability
func (hm *HealthMonitor) checkContent(target string) *HealthCheckResult {
    result := &HealthCheckResult{
        Details: make(map[string]interface{}),
    }
    
    // Parse target (CID:NodeID)
    // Verify content is pinned on node
    // Check content integrity
    
    // Simplified check
    result.Healthy = true
    
    return result
}

// TriggerRepair initiates repair for failed replicas
func (hm *HealthMonitor) TriggerRepair(cid string, failedNodes []string) error {
    repair := &RepairRequest{
        CID:         cid,
        FailedNodes: failedNodes,
        Priority:    1,
    }
    
    select {
    case hm.repairQueue <- repair:
        return nil
    default:
        return errors.New("repair queue full")
    }
}

// repairWorker processes repair requests
func (hm *HealthMonitor) repairWorker() {
    for repair := range hm.repairQueue {
        hm.processRepair(repair)
    }
}

// processRepair handles a single repair request
func (hm *HealthMonitor) processRepair(repair *RepairRequest) {
    // Find healthy nodes to replicate to
    // Ensure geographic distribution
    // Pin content to new nodes
    // Verify replication
    // Update replication status
    
    fmt.Printf("Processing repair for CID: %s\n", repair.CID)
}

// MonitorReplicationHealth continuously monitors all replications
func (hm *HealthMonitor) MonitorReplicationHealth(ctx context.Context, replications map[string]*ReplicationStatus) {
    ticker := time.NewTicker(HealthCheckInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            hm.performHealthChecks(ctx, replications)
        case <-ctx.Done():
            return
        }
    }
}

func (hm *HealthMonitor) performHealthChecks(ctx context.Context, replications map[string]*ReplicationStatus) {
    for cid, status := range replications {
        // Check each replica
        var failedReplicas []string
        
        for _, replica := range status.Replicas {
            // Skip if recently checked
            if time.Since(replica.LastVerified) < 30*time.Second {
                continue
            }
            
            c, _ := cid.Parse(cid)
            result, err := hm.CheckContentHealth(ctx, c, replica.NodeID)
            
            if err != nil || !result.Healthy {
                replica.Healthy = false
                failedReplicas = append(failedReplicas, replica.NodeID)
            } else {
                replica.Healthy = true
                replica.LastVerified = time.Now()
            }
        }
        
        // Trigger repair if needed
        healthyCount := len(status.Replicas) - len(failedReplicas)
        if healthyCount < MinReplicas {
            hm.TriggerRepair(cid, failedReplicas)
        }
        
        status.LastChecked = time.Now()
    }
}
```

### Geographic Distributor Implementation

```go
// NewGeographicDistributor creates a new geographic distributor
func NewGeographicDistributor() *GeographicDistributor {
    gd := &GeographicDistributor{
        regions:    make(map[string]*Region),
        latencyMap: make(map[string]map[string]time.Duration),
    }
    
    // Initialize regions
    gd.initializeRegions()
    
    // Initialize latency map
    gd.initializeLatencyMap()
    
    return gd
}

// initializeRegions sets up geographic regions
func (gd *GeographicDistributor) initializeRegions() {
    gd.regions[RegionNorthAmerica] = &Region{
        ID:   RegionNorthAmerica,
        Name: "North America",
        Coordinates: GeographicCoordinates{
            Latitude:  39.8283,
            Longitude: -98.5795,
        },
    }
    
    gd.regions[RegionEurope] = &Region{
        ID:   RegionEurope,
        Name: "Europe",
        Coordinates: GeographicCoordinates{
            Latitude:  54.5260,
            Longitude: 15.2551,
        },
    }
    
    gd.regions[RegionAsiaPacific] = &Region{
        ID:   RegionAsiaPacific,
        Name: "Asia Pacific",
        Coordinates: GeographicCoordinates{
            Latitude:  34.0479,
            Longitude: 100.6197,
        },
    }
    
    gd.regions[RegionSouthAmerica] = &Region{
        ID:   RegionSouthAmerica,
        Name: "South America",
        Coordinates: GeographicCoordinates{
            Latitude:  -8.7832,
            Longitude: -55.4915,
        },
    }
    
    gd.regions[RegionAfrica] = &Region{
        ID:   RegionAfrica,
        Name: "Africa",
        Coordinates: GeographicCoordinates{
            Latitude:  -8.7832,
            Longitude: 34.5085,
        },
    }
    
    gd.regions[RegionMiddleEast] = &Region{
        ID:   RegionMiddleEast,
        Name: "Middle East",
        Coordinates: GeographicCoordinates{
            Latitude:  29.2985,
            Longitude: 42.5510,
        },
    }
}

// initializeLatencyMap sets up inter-region latencies
func (gd *GeographicDistributor) initializeLatencyMap() {
    // Simplified latency matrix (ms)
    latencies := map[string]map[string]int{
        RegionNorthAmerica: {
            RegionNorthAmerica: 20,
            RegionEurope:       80,
            RegionAsiaPacific:  120,
            RegionSouthAmerica: 60,
            RegionAfrica:       100,
            RegionMiddleEast:   90,
        },
        RegionEurope: {
            RegionNorthAmerica: 80,
            RegionEurope:       15,
            RegionAsiaPacific:  150,
            RegionSouthAmerica: 110,
            RegionAfrica:       50,
            RegionMiddleEast:   40,
        },
        RegionAsiaPacific: {
            RegionNorthAmerica: 120,
            RegionEurope:       150,
            RegionAsiaPacific:  30,
            RegionSouthAmerica: 200,
            RegionAfrica:       130,
            RegionMiddleEast:   80,
        },
        // ... other regions
    }
    
    // Convert to time.Duration
    for from, destinations := range latencies {
        gd.latencyMap[from] = make(map[string]time.Duration)
        for to, ms := range destinations {
            gd.latencyMap[from][to] = time.Duration(ms) * time.Millisecond
        }
    }
}

// SelectReplicationNodes selects optimal nodes for replication
func (gd *GeographicDistributor) SelectReplicationNodes(
    existingNodes []string,
    availableNodes []*IPFSNode,
    count int,
) ([]string, error) {
    gd.mu.RLock()
    defer gd.mu.RUnlock()
    
    // Get regions of existing nodes
    existingRegions := make(map[string]bool)
    for _, nodeID := range existingNodes {
        // Get node region (simplified - would lookup from registry)
        for _, node := range availableNodes {
            if node.ID == nodeID {
                existingRegions[node.Region] = true
                break
            }
        }
    }
    
    // Score available nodes
    type scoredNode struct {
        node  *IPFSNode
        score float64
    }
    
    var candidates []scoredNode
    
    for _, node := range availableNodes {
        if !node.Healthy {
            continue
        }
        
        // Skip if already selected
        isExisting := false
        for _, existing := range existingNodes {
            if node.ID == existing {
                isExisting = true
                break
            }
        }
        if isExisting {
            continue
        }
        
        // Calculate score
        score := gd.calculateNodeScore(node, existingRegions)
        
        candidates = append(candidates, scoredNode{
            node:  node,
            score: score,
        })
    }
    
    // Sort by score (descending)
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].score > candidates[j].score
    })
    
    // Select top nodes
    selected := make([]string, 0, count)
    for i := 0; i < count && i < len(candidates); i++ {
        selected = append(selected, candidates[i].node.ID)
    }
    
    if len(selected) < count {
        return selected, fmt.Errorf("only %d nodes available, requested %d", len(selected), count)
    }
    
    return selected, nil
}

// calculateNodeScore calculates a score for node selection
func (gd *GeographicDistributor) calculateNodeScore(node *IPFSNode, existingRegions map[string]bool) float64 {
    score := 100.0
    
    // Geographic diversity bonus
    if !existingRegions[node.Region] {
        score += 50.0
    }
    
    // Node reputation
    score += node.Reputation * 20.0
    
    // Available capacity
    if node.Capacity > 0 {
        capacityRatio := float64(node.Capacity-node.Used) / float64(node.Capacity)
        score += capacityRatio * 30.0
    }
    
    // Region load factor (prefer less loaded regions)
    if region, exists := gd.regions[node.Region]; exists {
        score -= region.LoadFactor * 10.0
    }
    
    // Latency penalty (average to existing regions)
    if len(existingRegions) > 0 {
        totalLatency := 0.0
        for existingRegion := range existingRegions {
            if latency, exists := gd.latencyMap[node.Region][existingRegion]; exists {
                totalLatency += float64(latency.Milliseconds())
            }
        }
        avgLatency := totalLatency / float64(len(existingRegions))
        score -= avgLatency / 10.0 // Penalty for high latency
    }
    
    return score
}

// CalculateDistance calculates distance between two geographic points
func (gd *GeographicDistributor) CalculateDistance(coord1, coord2 GeographicCoordinates) float64 {
    // Haversine formula
    const earthRadius = 6371.0 // km
    
    lat1Rad := coord1.Latitude * math.Pi / 180
    lat2Rad := coord2.Latitude * math.Pi / 180
    deltaLat := (coord2.Latitude - coord1.Latitude) * math.Pi / 180
    deltaLon := (coord2.Longitude - coord1.Longitude) * math.Pi / 180
    
    a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
        math.Cos(lat1Rad)*math.Cos(lat2Rad)*
        math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
    
    c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
    
    return earthRadius * c
}

// GetOptimalRegions returns optimal regions for replication
func (gd *GeographicDistributor) GetOptimalRegions(userRegion string, count int) []string {
    gd.mu.RLock()
    defer gd.mu.RUnlock()
    
    if count <= 0 {
        return []string{}
    }
    
    // Always include user's region
    regions := []string{userRegion}
    count--
    
    if count == 0 {
        return regions
    }
    
    // Score other regions
    type scoredRegion struct {
        regionID string
        score    float64
    }
    
    var candidates []scoredRegion
    
    for regionID, region := range gd.regions {
        if regionID == userRegion {
            continue
        }
        
        // Calculate score based on distance and load
        userCoords := gd.regions[userRegion].Coordinates
        distance := gd.CalculateDistance(userCoords, region.Coordinates)
        
        // Prefer moderate distance (not too close, not too far)
        distanceScore := 100.0 - math.Abs(distance-3000)/100.0
        
        // Penalize high load
        loadScore := 100.0 - region.LoadFactor*100.0
        
        totalScore := distanceScore*0.6 + loadScore*0.4
        
        candidates = append(candidates, scoredRegion{
            regionID: regionID,
            score:    totalScore,
        })
    }
    
    // Sort by score
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].score > candidates[j].score
    })
    
    // Select top regions
    for i := 0; i < count && i < len(candidates); i++ {
        regions = append(regions, candidates[i].regionID)
    }
    
    return regions
}

// UpdateRegionLoad updates the load factor for a region
func (gd *GeographicDistributor) UpdateRegionLoad(regionID string, nodes []*IPFSNode) {
    gd.mu.Lock()
    defer gd.mu.Unlock()
    
    region, exists := gd.regions[regionID]
    if !exists {
        return
    }
    
    // Calculate average load
    totalLoad := 0.0
    nodeCount := 0
    
    for _, node := range nodes {
        if node.Region == regionID && node.Capacity > 0 {
            load := float64(node.Used) / float64(node.Capacity)
            totalLoad += load
            nodeCount++
        }
    }
    
    if nodeCount > 0 {
        region.LoadFactor = totalLoad / float64(nodeCount)
    }
}
```

### Main Replication Manager Implementation

```go
// NewReplicationManager creates a new replication manager
func NewReplicationManager(nodes []*IPFSNode) *ReplicationManager {
    rm := &ReplicationManager{
        pinCoordinator:  NewPinCoordinator(nodes),
        healthMonitor:   NewHealthMonitor(),
        geoDistributor:  NewGeographicDistributor(),
        ipfsLayer:       NewIPFSLayer(nodes),
        replicationMap:  make(map[string]*ReplicationStatus),
    }
    
    // Initialize metrics
    rm.initMetrics()
    
    // Start background tasks
    go rm.runHealthMonitor()
    go rm.runRepairService()
    go rm.runLoadBalancer()
    
    return rm
}

// initMetrics initializes Prometheus metrics
func (rm *ReplicationManager) initMetrics() {
    rm.replicationGauge = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "replication_total",
        Help: "Total number of replications",
    })
    
    rm.healthCheckCounter = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "health_checks_total",
        Help: "Total number of health checks performed",
    })
    
    rm.repairCounter = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "repairs_total",
        Help: "Total number of repairs performed",
    })
    
    prometheus.MustRegister(rm.replicationGauge)
    prometheus.MustRegister(rm.healthCheckCounter)
    prometheus.MustRegister(rm.repairCounter)
}

// ReplicateContent creates replicas across geographic regions
func (rm *ReplicationManager) ReplicateContent(ctx context.Context, contentCID cid.Cid, userRegion string) (*ReplicationStatus, error) {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Check if already replicated
    if status, exists := rm.replicationMap[contentCID.String()]; exists {
        return status, nil
    }
    
    // Create replication status
    status := &ReplicationStatus{
        CID:            contentCID.String(),
        TargetReplicas: TargetReplicas,
        CreatedAt:      time.Now(),
        Status:         "replicating",
        Replicas:       []*Replica{},
    }
    
    rm.replicationMap[contentCID.String()] = status
    
    // Get available nodes
    nodes := rm.ipfsLayer.GetHealthyNodes()
    
    // Select regions for replication
    regions := rm.geoDistributor.GetOptimalRegions(userRegion, TargetReplicas)
    
    // Select nodes from each region
    selectedNodes := []string{}
    for _, region := range regions {
        // Filter nodes by region
        regionNodes := filterNodesByRegion(nodes, region)
        
        // Select best node from region
        selected, err := rm.geoDistributor.SelectReplicationNodes(selectedNodes, regionNodes, 1)
        if err != nil {
            continue
        }
        
        if len(selected) > 0 {
            selectedNodes = append(selectedNodes, selected[0])
        }
    }
    
    // Create replicas
    var wg sync.WaitGroup
    successCount := 0
    
    for _, nodeID := range selectedNodes {
        wg.Add(1)
        go func(nID string) {
            defer wg.Done()
            
            err := rm.pinCoordinator.PinContent(ctx, contentCID, nID)
            if err != nil {
                fmt.Printf("Failed to pin to node %s: %v\n", nID, err)
                return
            }
            
            // Find node details
            var nodeRegion string
            for _, n := range nodes {
                if n.ID == nID {
                    nodeRegion = n.Region
                    break
                }
            }
            
            replica := &Replica{
                NodeID:       nID,
                Region:       nodeRegion,
                PinnedAt:     time.Now(),
                LastVerified: time.Now(),
                Healthy:      true,
            }
            
            rm.mu.Lock()
            status.Replicas = append(status.Replicas, replica)
            rm.mu.Unlock()
            
            successCount++
        }(nodeID)
    }
    
    wg.Wait()
    
    // Update status
    if successCount >= MinReplicas {
        status.Status = "replicated"
    } else {
        status.Status = "partial"
    }
    
    rm.replicationGauge.Set(float64(len(rm.replicationMap)))
    
    return status, nil
}

// GetReplicationStatus returns the replication status
func (rm *ReplicationManager) GetReplicationStatus(contentCID cid.Cid) (*ReplicationStatus, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    status, exists := rm.replicationMap[contentCID.String()]
    if !exists {
        return nil, errors.New("content not found")
    }
    
    return status, nil
}

// RemoveReplication removes all replicas of content
func (rm *ReplicationManager) RemoveReplication(ctx context.Context, contentCID cid.Cid) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    status, exists := rm.replicationMap[contentCID.String()]
    if !exists {
        return errors.New("content not found")
    }
    
    // Unpin from all nodes
    var wg sync.WaitGroup
    for _, replica := range status.Replicas {
        wg.Add(1)
        go func(r *Replica) {
            defer wg.Done()
            rm.pinCoordinator.UnpinContent(ctx, contentCID, r.NodeID)
        }(replica)
    }
    
    wg.Wait()
    
    // Remove from map
    delete(rm.replicationMap, contentCID.String())
    
    rm.replicationGauge.Set(float64(len(rm.replicationMap)))
    
    return nil
}

// runHealthMonitor runs the health monitoring service
func (rm *ReplicationManager) runHealthMonitor() {
    ctx := context.Background()
    rm.healthMonitor.MonitorReplicationHealth(ctx, rm.replicationMap)
}

// runRepairService runs the repair service
func (rm *ReplicationManager) runRepairService() {
    ticker := time.NewTicker(RepairInterval)
    defer ticker.Stop()
    
    for range ticker.C {
        rm.performRepairs()
    }
}

// performRepairs checks and repairs under-replicated content
func (rm *ReplicationManager) performRepairs() {
    rm.mu.RLock()
    repairNeeded := []*ReplicationStatus{}
    
    for _, status := range rm.replicationMap {
        healthyCount := 0
        for _, replica := range status.Replicas {
            if replica.Healthy {
                healthyCount++
            }
        }
        
        if healthyCount < TargetReplicas {
            repairNeeded = append(repairNeeded, status)
        }
    }
    rm.mu.RUnlock()
    
    // Perform repairs
    for _, status := range repairNeeded {
        rm.repairReplicas(status)
        rm.repairCounter.Inc()
    }
}

// repairReplicas repairs under-replicated content
func (rm *ReplicationManager) repairReplicas(status *ReplicationStatus) error {
    // Find healthy replicas
    var healthyNodes []string
    for _, replica := range status.Replicas {
        if replica.Healthy {
            healthyNodes = append(healthyNodes, replica.NodeID)
        }
    }
    
    // Calculate how many new replicas needed
    needed := TargetReplicas - len(healthyNodes)
    if needed <= 0 {
        return nil
    }
    
    // Get available nodes
    nodes := rm.ipfsLayer.GetHealthyNodes()
    
    // Select new nodes
    newNodes, err := rm.geoDistributor.SelectReplicationNodes(healthyNodes, nodes, needed)
    if err != nil {
        return err
    }
    
    // Create new replicas
    ctx := context.Background()
    cid, _ := cid.Parse(status.CID)
    
    for _, nodeID := range newNodes {
        err := rm.pinCoordinator.PinContent(ctx, cid, nodeID)
        if err != nil {
            continue
        }
        
        // Add to status
        replica := &Replica{
            NodeID:       nodeID,
            PinnedAt:     time.Now(),
            LastVerified: time.Now(),
            Healthy:      true,
        }
        
        rm.mu.Lock()
        status.Replicas = append(status.Replicas, replica)
        status.LastRepaired = time.Now()
        rm.mu.Unlock()
    }
    
    return nil
}

// runLoadBalancer runs the load balancing service
func (rm *ReplicationManager) runLoadBalancer() {
    ticker := time.NewTicker(30 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        ctx := context.Background()
        rm.pinCoordinator.RotatePins(ctx)
    }
}

// filterNodesByRegion filters nodes by region
func filterNodesByRegion(nodes []*IPFSNode, region string) []*IPFSNode {
    var filtered []*IPFSNode
    for _, node := range nodes {
        if node.Region == region {
            filtered = append(filtered, node)
        }
    }
    return filtered
}
```

### IPFS Integration Layer

```go
// IPFSLayer manages IPFS node connections
type IPFSLayer struct {
    mu    sync.RWMutex
    nodes map[string]*IPFSNode
}

// NewIPFSLayer creates a new IPFS integration layer
func NewIPFSLayer(nodes []*IPFSNode) *IPFSLayer {
    layer := &IPFSLayer{
        nodes: make(map[string]*IPFSNode),
    }
    
    for _, node := range nodes {
        layer.nodes[node.ID] = node
    }
    
    return layer
}

// GetHealthyNodes returns all healthy nodes
func (il *IPFSLayer) GetHealthyNodes() []*IPFSNode {
    il.mu.RLock()
    defer il.mu.RUnlock()
    
    var healthy []*IPFSNode
    for _, node := range il.nodes {
        if node.Healthy {
            healthy = append(healthy, node)
        }
    }
    
    return healthy
}

// AddNode adds a new IPFS node
func (il *IPFSLayer) AddNode(node *IPFSNode) error {
    il.mu.Lock()
    defer il.mu.Unlock()
    
    if _, exists := il.nodes[node.ID]; exists {
        return errors.New("node already exists")
    }
    
    il.nodes[node.ID] = node
    return nil
}

// RemoveNode removes an IPFS node
func (il *IPFSLayer) RemoveNode(nodeID string) error {
    il.mu.Lock()
    defer il.mu.Unlock()
    
    if _, exists := il.nodes[nodeID]; !exists {
        return errors.New("node not found")
    }
    
    delete(il.nodes, nodeID)
    return nil
}

// UpdateNodeHealth updates node health status
func (il *IPFSLayer) UpdateNodeHealth(nodeID string, healthy bool) error {
    il.mu.Lock()
    defer il.mu.Unlock()
    
    node, exists := il.nodes[nodeID]
    if !exists {
        return errors.New("node not found")
    }
    
    node.Healthy = healthy
    node.LastSeen = time.Now()
    
    return nil
}
```

## Testing

```go
package replication

import (
    "context"
    "testing"
    "time"

    "github.com/ipfs/go-cid"
)

func TestReplicationManager(t *testing.T) {
    // Create test nodes
    nodes := []*IPFSNode{
        {
            ID:       "node1",
            Region:   RegionNorthAmerica,
            Healthy:  true,
            Capacity: 1000000,
            Used:     0,
        },
        {
            ID:       "node2",
            Region:   RegionEurope,
            Healthy:  true,
            Capacity: 1000000,
            Used:     0,
        },
        {
            ID:       "node3",
            Region:   RegionAsiaPacific,
            Healthy:  true,
            Capacity: 1000000,
            Used:     0,
        },
    }
    
    rm := NewReplicationManager(nodes)
    
    // Test replication
    ctx := context.Background()
    testCID, _ := cid.Parse("QmTest123")
    
    status, err := rm.ReplicateContent(ctx, testCID, RegionNorthAmerica)
    if err != nil {
        t.Fatalf("Failed to replicate: %v", err)
    }
    
    if len(status.Replicas) != 3 {
        t.Errorf("Expected 3 replicas, got %d", len(status.Replicas))
    }
    
    // Verify geographic distribution
    regions := make(map[string]int)
    for _, replica := range status.Replicas {
        regions[replica.Region]++
    }
    
    if len(regions) < 2 {
        t.Error("Replicas not geographically distributed")
    }
}

func TestHealthMonitoring(t *testing.T) {
    hm := NewHealthMonitor()
    
    // Create test node
    node := &IPFSNode{
        ID:      "test-node",
        Healthy: true,
    }
    
    ctx := context.Background()
    result, err := hm.CheckNodeHealth(ctx, node)
    
    if err != nil {
        t.Fatalf("Health check failed: %v", err)
    }
    
    if !result.Healthy {
        t.Error("Expected node to be healthy")
    }
}

func TestGeographicDistribution(t *testing.T) {
    gd := NewGeographicDistributor()
    
    // Test optimal region selection
    regions := gd.GetOptimalRegions(RegionNorthAmerica, 3)
    
    if len(regions) != 3 {
        t.Errorf("Expected 3 regions, got %d", len(regions))
    }
    
    if regions[0] != RegionNorthAmerica {
        t.Error("User region should be first")
    }
}

func TestPinCoordinator(t *testing.T) {
    nodes := []*IPFSNode{
        {
            ID:       "node1",
            Healthy:  true,
            Capacity: 1000,
            Used:     0,
        },
    }
    
    pc := NewPinCoordinator(nodes)
    
    ctx := context.Background()
    testCID, _ := cid.Parse("QmTest456")
    
    err := pc.PinContent(ctx, testCID, "node1")
    if err != nil {
        t.Fatalf("Failed to pin content: %v", err)
    }
    
    // Check pin status
    statuses, err := pc.GetPinStatus(testCID)
    if err != nil {
        t.Fatalf("Failed to get pin status: %v", err)
    }
    
    if len(statuses) != 1 {
        t.Errorf("Expected 1 pin status, got %d", len(statuses))
    }
}

func BenchmarkReplication(b *testing.B) {
    nodes := make([]*IPFSNode, 10)
    for i := 0; i < 10; i++ {
        nodes[i] = &IPFSNode{
            ID:       fmt.Sprintf("node%d", i),
            Region:   []string{RegionNorthAmerica, RegionEurope, RegionAsiaPacific}[i%3],
            Healthy:  true,
            Capacity: 1000000,
            Used:     0,
        }
    }
    
    rm := NewReplicationManager(nodes)
    ctx := context.Background()
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        testCID, _ := cid.Parse(fmt.Sprintf("Qm%d", i))
        rm.ReplicateContent(ctx, testCID, RegionNorthAmerica)
    }
}
```

## Performance Optimizations

1. **Parallel Pinning**: Pin to multiple nodes concurrently
2. **Batch Operations**: Group multiple pin operations
3. **Connection Pooling**: Reuse IPFS API connections
4. **Caching**: Cache node health and latency information
5. **Async Repairs**: Perform repairs in background

## Monitoring and Metrics

1. **Replication Metrics**:
   - Total replications
   - Replication success rate
   - Geographic distribution
   - Repair frequency

2. **Health Metrics**:
   - Node availability
   - Content accessibility
   - Network latency
   - Storage utilization

3. **Performance Metrics**:
   - Pin operation latency
   - Repair completion time
   - Queue depths
   - Throughput rates

## Integration Points

1. **Encryption Gateway**: Receives encrypted content for replication
2. **Storage Service**: Coordinates with main storage operations
3. **Monitoring System**: Reports health and performance metrics
4. **Audit System**: Logs all replication operations