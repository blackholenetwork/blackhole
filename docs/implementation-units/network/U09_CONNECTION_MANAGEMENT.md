# Unit U09: Connection Management - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U09 implements comprehensive connection management for the Blackhole network, providing connection pooling, lifecycle management, and health monitoring. This unit ensures efficient resource utilization, maintains connection quality, and provides automatic recovery from network failures.

**Primary Goals:**
- Implement intelligent connection pooling with configurable limits
- Provide complete connection lifecycle management
- Enable proactive health monitoring and failure detection
- Implement automatic reconnection and recovery strategies
- Optimize connection resource usage and performance

### Dependencies

- **U01: libp2p Core Setup** - Base network connectivity
- **U02: Kademlia DHT Implementation** - Peer discovery for connections
- **U07: Network Security Layer** - Secure connection establishment
- **U08: Rate Limiting** - Connection rate control

### Deliverables

1. **Connection Pool Manager**
   - Per-peer connection pools
   - Global connection limits
   - Pool sizing strategies
   - Connection reuse optimization

2. **Lifecycle Management**
   - Connection state tracking
   - Graceful connection closure
   - Connection aging and rotation
   - Resource cleanup

3. **Health Monitoring System**
   - Heartbeat/keepalive mechanism
   - Latency tracking
   - Connection quality metrics
   - Failure detection

4. **Recovery Mechanisms**
   - Automatic reconnection
   - Exponential backoff
   - Circuit breaker pattern
   - Failover strategies

### Integration Points

This unit manages connections for:
- All P2P communications (U01-U09)
- Service connections (U06)
- Storage transfers (U10-U13)
- Compute job communications (U24-U28)
- Payment channel connections (U16)

## 2. Technical Specifications

### Connection Management Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Connection Manager                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │Pool Manager │  │Health Monitor│  │Recovery Manager │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Connection Pools                            │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Peer Pools  │  │Service Pools│  │ Priority Pools  │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                 Lifecycle Management                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │State Machine│  │   Timers     │  │  Cleanup        │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Health Monitoring                           │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Heartbeat   │  │Latency Track │  │Quality Metrics  │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Connection States

```
                    ┌─────────┐
                    │  IDLE   │
                    └────┬────┘
                         │ Connect
                    ┌────▼────┐
                    │CONNECTING│
                    └────┬────┘
                         │ Success
                    ┌────▼────┐
        ┌───────────┤ ACTIVE  │───────────┐
        │           └────┬────┘           │
        │ Error          │ Close          │ Timeout
   ┌────▼────┐     ┌────▼────┐      ┌────▼────┐
   │ FAILED  │     │ CLOSING │      │UNHEALTHY│
   └────┬────┘     └────┬────┘      └────┬────┘
        │                │                 │ Recover
        └────────────────┴─────────────────┘
                         │
                    ┌────▼────┐
                    │ CLOSED  │
                    └─────────┘
```

### Pool Sizing Strategies

1. **Fixed Size**: Constant number of connections
2. **Dynamic**: Scales based on demand
3. **Adaptive**: Learns optimal size over time
4. **Tiered**: Different sizes for different peer types

## 3. Implementation Details

### Project Structure

```
pkg/connection/
├── manager.go          # Main connection manager
├── pool.go             # Connection pool implementation
├── lifecycle.go        # Connection lifecycle management
├── health.go           # Health monitoring system
├── recovery.go         # Recovery and reconnection
├── metrics.go          # Connection metrics
├── config.go           # Configuration structures
├── errors.go           # Connection-specific errors
├── state.go            # Connection state machine
├── priority.go         # Priority queue for connections
├── tests/
│   ├── manager_test.go
│   ├── pool_test.go
│   ├── health_test.go
│   ├── recovery_test.go
│   └── integration_test.go
└── examples/
    ├── basic_pool/     # Basic connection pooling
    └── health_check/   # Health monitoring example
```

### Core Connection Manager

```go
// pkg/connection/manager.go
package connection

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/protocol"
    "github.com/prometheus/client_golang/prometheus"
)

const (
    // Default configuration values
    DefaultMaxConnections     = 1000
    DefaultMaxPerPeer        = 5
    DefaultMinPerPeer        = 1
    DefaultIdleTimeout       = 5 * time.Minute
    DefaultHealthCheckInterval = 30 * time.Second
    DefaultReconnectInterval  = 10 * time.Second
)

// ConnectionManager manages all network connections
type ConnectionManager struct {
    host       host.Host
    config     *Config
    
    // Connection pools
    pools      map[peer.ID]*ConnectionPool
    poolsMu    sync.RWMutex
    
    // Global connection tracking
    globalPool *GlobalPool
    
    // Health monitoring
    health     *HealthMonitor
    
    // Recovery management
    recovery   *RecoveryManager
    
    // Metrics
    metrics    *Metrics
    
    // Lifecycle
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

// Config holds connection manager configuration
type Config struct {
    // Pool configuration
    MaxConnections      int
    MaxConnectionsPerPeer int
    MinConnectionsPerPeer int
    PoolStrategy        PoolStrategy
    
    // Timeouts
    ConnectionTimeout   time.Duration
    IdleTimeout        time.Duration
    MaxConnectionAge   time.Duration
    
    // Health checks
    HealthCheckInterval time.Duration
    HealthCheckTimeout  time.Duration
    UnhealthyThreshold  int
    
    // Recovery
    EnableAutoReconnect bool
    ReconnectInterval   time.Duration
    MaxReconnectAttempts int
    BackoffMultiplier   float64
    
    // Priority settings
    EnablePriority      bool
    PriorityLevels      int
}

// Connection represents a managed connection
type Connection struct {
    ID           string
    Stream       network.Stream
    PeerID       peer.ID
    Protocol     protocol.ID
    State        ConnectionState
    Priority     int
    
    // Timestamps
    CreatedAt    time.Time
    LastUsedAt   time.Time
    LastHealthAt time.Time
    
    // Health metrics
    Latency      time.Duration
    ErrorCount   int
    SuccessCount int
    BytesSent    int64
    BytesReceived int64
    
    // Internal
    mu           sync.RWMutex
    ctx          context.Context
    cancel       context.CancelFunc
}

// ConnectionState represents the state of a connection
type ConnectionState int

const (
    StateIdle ConnectionState = iota
    StateConnecting
    StateActive
    StateUnhealthy
    StateClosing
    StateClosed
    StateFailed
)

// NewConnectionManager creates a new connection manager
func NewConnectionManager(h host.Host, cfg *Config) (*ConnectionManager, error) {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    cm := &ConnectionManager{
        host:     h,
        config:   cfg,
        pools:    make(map[peer.ID]*ConnectionPool),
        metrics:  NewMetrics(),
        ctx:      ctx,
        cancel:   cancel,
    }
    
    // Initialize global pool
    cm.globalPool = NewGlobalPool(cfg.MaxConnections)
    
    // Initialize health monitor
    cm.health = NewHealthMonitor(cm, cfg.HealthCheckInterval, cfg.HealthCheckTimeout)
    
    // Initialize recovery manager
    if cfg.EnableAutoReconnect {
        cm.recovery = NewRecoveryManager(cm, cfg.ReconnectInterval, cfg.MaxReconnectAttempts)
    }
    
    // Set up network notifications
    h.Network().Notify(&network.NotifyBundle{
        ConnectedF:    cm.onConnected,
        DisconnectedF: cm.onDisconnected,
        OpenedStreamF: cm.onStreamOpened,
        ClosedStreamF: cm.onStreamClosed,
    })
    
    // Start background workers
    cm.wg.Add(3)
    go cm.poolMaintenanceLoop()
    go cm.healthCheckLoop()
    go cm.metricsCollectionLoop()
    
    log.Info("Connection manager initialized")
    return cm, nil
}

// Connect establishes a connection to a peer
func (cm *ConnectionManager) Connect(ctx context.Context, p peer.ID, opts ...ConnectionOption) (*Connection, error) {
    // Apply options
    options := defaultConnectionOptions()
    for _, opt := range opts {
        opt(options)
    }
    
    // Check if we can create a new connection
    if err := cm.canConnect(p); err != nil {
        cm.metrics.ConnectionsRejected.Inc()
        return nil, err
    }
    
    // Get or create pool for peer
    pool := cm.getOrCreatePool(p)
    
    // Try to get existing connection from pool
    if !options.ForceNew {
        if conn := pool.Get(options.Protocol); conn != nil {
            cm.metrics.ConnectionReuse.Inc()
            return conn, nil
        }
    }
    
    // Create new connection
    cm.metrics.ConnectionAttempts.Inc()
    
    conn, err := cm.createConnection(ctx, p, options)
    if err != nil {
        cm.metrics.ConnectionFailures.Inc()
        cm.recovery.RecordFailure(p, err)
        return nil, fmt.Errorf("failed to create connection: %w", err)
    }
    
    // Add to pool
    if err := pool.Add(conn); err != nil {
        conn.Close()
        return nil, fmt.Errorf("failed to add to pool: %w", err)
    }
    
    // Update global pool
    cm.globalPool.AddConnection(p, conn.ID)
    
    cm.metrics.ConnectionsEstablished.Inc()
    cm.metrics.ActiveConnections.Inc()
    
    log.Debugf("Established connection to %s", p)
    return conn, nil
}

// GetConnection retrieves an existing connection
func (cm *ConnectionManager) GetConnection(p peer.ID, protocol protocol.ID) (*Connection, error) {
    pool := cm.getPool(p)
    if pool == nil {
        return nil, ErrNoConnectionPool
    }
    
    conn := pool.Get(protocol)
    if conn == nil {
        return nil, ErrNoConnection
    }
    
    // Check connection health
    if conn.State == StateUnhealthy {
        cm.metrics.UnhealthyConnectionsUsed.Inc()
    }
    
    return conn, nil
}

// CloseConnection closes a specific connection
func (cm *ConnectionManager) CloseConnection(connID string) error {
    cm.poolsMu.RLock()
    defer cm.poolsMu.RUnlock()
    
    // Find connection in pools
    for _, pool := range cm.pools {
        if conn := pool.GetByID(connID); conn != nil {
            return cm.closeConnection(conn)
        }
    }
    
    return ErrConnectionNotFound
}

// ClosePeer closes all connections to a peer
func (cm *ConnectionManager) ClosePeer(p peer.ID) error {
    pool := cm.getPool(p)
    if pool == nil {
        return nil
    }
    
    // Close all connections in pool
    connections := pool.GetAll()
    var lastErr error
    
    for _, conn := range connections {
        if err := cm.closeConnection(conn); err != nil {
            lastErr = err
        }
    }
    
    // Remove pool
    cm.poolsMu.Lock()
    delete(cm.pools, p)
    cm.poolsMu.Unlock()
    
    return lastErr
}

// createConnection creates a new connection to a peer
func (cm *ConnectionManager) createConnection(ctx context.Context, p peer.ID, opts *connectionOptions) (*Connection, error) {
    // Set connection timeout
    connCtx, cancel := context.WithTimeout(ctx, cm.config.ConnectionTimeout)
    defer cancel()
    
    // Open stream
    stream, err := cm.host.NewStream(connCtx, p, opts.Protocol)
    if err != nil {
        return nil, fmt.Errorf("failed to open stream: %w", err)
    }
    
    // Create connection context
    connCtx, connCancel := context.WithCancel(cm.ctx)
    
    // Create connection object
    conn := &Connection{
        ID:        generateConnectionID(),
        Stream:    stream,
        PeerID:    p,
        Protocol:  opts.Protocol,
        State:     StateActive,
        Priority:  opts.Priority,
        CreatedAt: time.Now(),
        LastUsedAt: time.Now(),
        ctx:       connCtx,
        cancel:    connCancel,
    }
    
    // Perform initial health check
    if err := cm.health.CheckConnection(conn); err != nil {
        conn.Close()
        return nil, fmt.Errorf("initial health check failed: %w", err)
    }
    
    return conn, nil
}

// closeConnection closes a connection
func (cm *ConnectionManager) closeConnection(conn *Connection) error {
    conn.mu.Lock()
    if conn.State == StateClosed || conn.State == StateClosing {
        conn.mu.Unlock()
        return nil
    }
    
    conn.State = StateClosing
    conn.mu.Unlock()
    
    // Cancel connection context
    conn.cancel()
    
    // Close stream
    if err := conn.Stream.Close(); err != nil {
        log.Warnf("Error closing stream: %v", err)
    }
    
    // Remove from pool
    if pool := cm.getPool(conn.PeerID); pool != nil {
        pool.Remove(conn.ID)
    }
    
    // Update global pool
    cm.globalPool.RemoveConnection(conn.PeerID, conn.ID)
    
    // Update state
    conn.mu.Lock()
    conn.State = StateClosed
    conn.mu.Unlock()
    
    cm.metrics.ActiveConnections.Dec()
    cm.metrics.ConnectionsClosed.Inc()
    
    log.Debugf("Closed connection %s to %s", conn.ID, conn.PeerID)
    return nil
}

// canConnect checks if a new connection can be created
func (cm *ConnectionManager) canConnect(p peer.ID) error {
    // Check global limit
    if cm.globalPool.Count() >= cm.config.MaxConnections {
        return ErrMaxConnectionsReached
    }
    
    // Check per-peer limit
    if pool := cm.getPool(p); pool != nil {
        if pool.Size() >= cm.config.MaxConnectionsPerPeer {
            return ErrMaxConnectionsPerPeer
        }
    }
    
    return nil
}

// getPool returns the connection pool for a peer
func (cm *ConnectionManager) getPool(p peer.ID) *ConnectionPool {
    cm.poolsMu.RLock()
    defer cm.poolsMu.RUnlock()
    return cm.pools[p]
}

// getOrCreatePool returns or creates a connection pool for a peer
func (cm *ConnectionManager) getOrCreatePool(p peer.ID) *ConnectionPool {
    cm.poolsMu.Lock()
    defer cm.poolsMu.Unlock()
    
    pool, exists := cm.pools[p]
    if !exists {
        pool = NewConnectionPool(p, cm.config)
        cm.pools[p] = pool
        cm.metrics.PoolsCreated.Inc()
    }
    
    return pool
}

// GetStats returns connection statistics
func (cm *ConnectionManager) GetStats() *ConnectionStats {
    cm.poolsMu.RLock()
    defer cm.poolsMu.RUnlock()
    
    stats := &ConnectionStats{
        TotalConnections: cm.globalPool.Count(),
        ActivePeers:     len(cm.pools),
        Pools:          make(map[peer.ID]*PoolStats),
    }
    
    // Collect per-pool stats
    for p, pool := range cm.pools {
        stats.Pools[p] = pool.GetStats()
    }
    
    // Add health stats
    if cm.health != nil {
        stats.HealthyConnections = cm.health.GetHealthyCount()
        stats.UnhealthyConnections = cm.health.GetUnhealthyCount()
    }
    
    return stats
}

// poolMaintenanceLoop performs periodic pool maintenance
func (cm *ConnectionManager) poolMaintenanceLoop() {
    defer cm.wg.Done()
    
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            cm.performMaintenance()
        case <-cm.ctx.Done():
            return
        }
    }
}

// performMaintenance cleans up idle connections and empty pools
func (cm *ConnectionManager) performMaintenance() {
    cm.poolsMu.Lock()
    defer cm.poolsMu.Unlock()
    
    now := time.Now()
    emptyPools := []peer.ID{}
    
    for p, pool := range cm.pools {
        // Clean idle connections
        idleConns := pool.GetIdleConnections(cm.config.IdleTimeout)
        for _, conn := range idleConns {
            if now.Sub(conn.LastUsedAt) > cm.config.IdleTimeout {
                cm.closeConnection(conn)
                cm.metrics.IdleConnectionsClosed.Inc()
            }
        }
        
        // Clean aged connections
        if cm.config.MaxConnectionAge > 0 {
            agedConns := pool.GetAgedConnections(cm.config.MaxConnectionAge)
            for _, conn := range agedConns {
                cm.closeConnection(conn)
                cm.metrics.AgedConnectionsClosed.Inc()
            }
        }
        
        // Mark empty pools for removal
        if pool.Size() == 0 {
            emptyPools = append(emptyPools, p)
        }
    }
    
    // Remove empty pools
    for _, p := range emptyPools {
        delete(cm.pools, p)
        cm.metrics.PoolsDestroyed.Inc()
    }
    
    log.Debugf("Maintenance: closed %d idle, %d aged connections, removed %d empty pools",
        len(idleConns), len(agedConns), len(emptyPools))
}

// Close shuts down the connection manager
func (cm *ConnectionManager) Close() error {
    log.Info("Shutting down connection manager")
    
    // Cancel context
    cm.cancel()
    
    // Close all connections
    cm.poolsMu.Lock()
    for _, pool := range cm.pools {
        for _, conn := range pool.GetAll() {
            conn.Close()
        }
    }
    cm.poolsMu.Unlock()
    
    // Wait for workers
    cm.wg.Wait()
    
    return nil
}
```

### Connection Pool Implementation

```go
// pkg/connection/pool.go
package connection

import (
    "container/list"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/protocol"
)

// PoolStrategy defines how the pool manages connections
type PoolStrategy int

const (
    StrategyFixed PoolStrategy = iota
    StrategyDynamic
    StrategyAdaptive
)

// ConnectionPool manages connections for a specific peer
type ConnectionPool struct {
    peerID    peer.ID
    config    *Config
    
    // Connection storage
    connections map[string]*Connection
    byProtocol  map[protocol.ID][]*Connection
    lru         *list.List
    lruMap      map[string]*list.Element
    
    // Pool state
    mu          sync.RWMutex
    strategy    PoolStrategy
    targetSize  int
    
    // Metrics
    hits        int64
    misses      int64
    evictions   int64
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(p peer.ID, cfg *Config) *ConnectionPool {
    return &ConnectionPool{
        peerID:      p,
        config:      cfg,
        connections: make(map[string]*Connection),
        byProtocol:  make(map[protocol.ID][]*Connection),
        lru:         list.New(),
        lruMap:      make(map[string]*list.Element),
        strategy:    cfg.PoolStrategy,
        targetSize:  cfg.MinConnectionsPerPeer,
    }
}

// Add adds a connection to the pool
func (cp *ConnectionPool) Add(conn *Connection) error {
    cp.mu.Lock()
    defer cp.mu.Unlock()
    
    // Check pool limits
    if len(cp.connections) >= cp.config.MaxConnectionsPerPeer {
        // Evict LRU connection if at capacity
        if cp.config.PoolStrategy != StrategyFixed {
            cp.evictLRU()
        } else {
            return ErrPoolFull
        }
    }
    
    // Add connection
    cp.connections[conn.ID] = conn
    
    // Update protocol index
    cp.byProtocol[conn.Protocol] = append(cp.byProtocol[conn.Protocol], conn)
    
    // Add to LRU
    elem := cp.lru.PushFront(conn.ID)
    cp.lruMap[conn.ID] = elem
    
    return nil
}

// Get retrieves a connection from the pool
func (cp *ConnectionPool) Get(protocol protocol.ID) *Connection {
    cp.mu.Lock()
    defer cp.mu.Unlock()
    
    // Find connections for protocol
    conns, exists := cp.byProtocol[protocol]
    if !exists || len(conns) == 0 {
        cp.misses++
        return nil
    }
    
    // Find best connection (healthiest, least loaded)
    var bestConn *Connection
    var bestScore float64
    
    for _, conn := range conns {
        if conn.State != StateActive && conn.State != StateUnhealthy {
            continue
        }
        
        score := cp.scoreConnection(conn)
        if bestConn == nil || score > bestScore {
            bestConn = conn
            bestScore = score
        }
    }
    
    if bestConn != nil {
        cp.hits++
        cp.updateLRU(bestConn.ID)
        bestConn.LastUsedAt = time.Now()
        return bestConn
    }
    
    cp.misses++
    return nil
}

// GetByID retrieves a connection by ID
func (cp *ConnectionPool) GetByID(connID string) *Connection {
    cp.mu.RLock()
    defer cp.mu.RUnlock()
    return cp.connections[connID]
}

// GetAll returns all connections in the pool
func (cp *ConnectionPool) GetAll() []*Connection {
    cp.mu.RLock()
    defer cp.mu.RUnlock()
    
    conns := make([]*Connection, 0, len(cp.connections))
    for _, conn := range cp.connections {
        conns = append(conns, conn)
    }
    return conns
}

// Remove removes a connection from the pool
func (cp *ConnectionPool) Remove(connID string) {
    cp.mu.Lock()
    defer cp.mu.Unlock()
    
    conn, exists := cp.connections[connID]
    if !exists {
        return
    }
    
    // Remove from connections map
    delete(cp.connections, connID)
    
    // Remove from protocol index
    if conns, exists := cp.byProtocol[conn.Protocol]; exists {
        for i, c := range conns {
            if c.ID == connID {
                cp.byProtocol[conn.Protocol] = append(conns[:i], conns[i+1:]...)
                break
            }
        }
    }
    
    // Remove from LRU
    if elem, exists := cp.lruMap[connID]; exists {
        cp.lru.Remove(elem)
        delete(cp.lruMap, connID)
    }
}

// Size returns the number of connections in the pool
func (cp *ConnectionPool) Size() int {
    cp.mu.RLock()
    defer cp.mu.RUnlock()
    return len(cp.connections)
}

// GetIdleConnections returns connections idle for longer than duration
func (cp *ConnectionPool) GetIdleConnections(idleTime time.Duration) []*Connection {
    cp.mu.RLock()
    defer cp.mu.RUnlock()
    
    now := time.Now()
    idle := []*Connection{}
    
    for _, conn := range cp.connections {
        if now.Sub(conn.LastUsedAt) > idleTime {
            idle = append(idle, conn)
        }
    }
    
    return idle
}

// GetAgedConnections returns connections older than maxAge
func (cp *ConnectionPool) GetAgedConnections(maxAge time.Duration) []*Connection {
    cp.mu.RLock()
    defer cp.mu.RUnlock()
    
    now := time.Now()
    aged := []*Connection{}
    
    for _, conn := range cp.connections {
        if now.Sub(conn.CreatedAt) > maxAge {
            aged = append(aged, conn)
        }
    }
    
    return aged
}

// scoreConnection calculates a score for connection selection
func (cp *ConnectionPool) scoreConnection(conn *Connection) float64 {
    score := 100.0
    
    // Penalize unhealthy connections
    if conn.State == StateUnhealthy {
        score -= 50.0
    }
    
    // Prefer lower latency
    if conn.Latency > 0 {
        latencyPenalty := float64(conn.Latency.Milliseconds()) / 10.0
        score -= min(latencyPenalty, 30.0)
    }
    
    // Prefer lower error rate
    if conn.SuccessCount > 0 {
        errorRate := float64(conn.ErrorCount) / float64(conn.SuccessCount + conn.ErrorCount)
        score -= errorRate * 20.0
    }
    
    // Prefer less loaded connections (bytes transferred)
    loadPenalty := float64(conn.BytesSent+conn.BytesReceived) / (1024 * 1024 * 100) // Per 100MB
    score -= min(loadPenalty, 10.0)
    
    return score
}

// updateLRU updates the LRU position of a connection
func (cp *ConnectionPool) updateLRU(connID string) {
    if elem, exists := cp.lruMap[connID]; exists {
        cp.lru.MoveToFront(elem)
    }
}

// evictLRU evicts the least recently used connection
func (cp *ConnectionPool) evictLRU() {
    if elem := cp.lru.Back(); elem != nil {
        connID := elem.Value.(string)
        if conn := cp.connections[connID]; conn != nil {
            conn.Close()
            cp.Remove(connID)
            cp.evictions++
        }
    }
}

// GetStats returns pool statistics
func (cp *ConnectionPool) GetStats() *PoolStats {
    cp.mu.RLock()
    defer cp.mu.RUnlock()
    
    stats := &PoolStats{
        PeerID:      cp.peerID,
        Connections: len(cp.connections),
        Hits:        cp.hits,
        Misses:      cp.misses,
        Evictions:   cp.evictions,
        Protocols:   make(map[protocol.ID]int),
    }
    
    // Count connections by protocol
    for proto, conns := range cp.byProtocol {
        stats.Protocols[proto] = len(conns)
    }
    
    // Calculate hit rate
    total := cp.hits + cp.misses
    if total > 0 {
        stats.HitRate = float64(cp.hits) / float64(total)
    }
    
    return stats
}

// Resize adjusts the pool size based on strategy
func (cp *ConnectionPool) Resize() {
    cp.mu.Lock()
    defer cp.mu.Unlock()
    
    switch cp.strategy {
    case StrategyDynamic:
        cp.resizeDynamic()
    case StrategyAdaptive:
        cp.resizeAdaptive()
    }
}

// resizeDynamic implements dynamic pool sizing
func (cp *ConnectionPool) resizeDynamic() {
    // Adjust based on hit rate
    hitRate := float64(cp.hits) / float64(cp.hits + cp.misses)
    
    if hitRate < 0.8 && cp.targetSize < cp.config.MaxConnectionsPerPeer {
        cp.targetSize++
    } else if hitRate > 0.95 && cp.targetSize > cp.config.MinConnectionsPerPeer {
        cp.targetSize--
    }
}

// resizeAdaptive implements adaptive pool sizing using historical data
func (cp *ConnectionPool) resizeAdaptive() {
    // More sophisticated sizing based on:
    // - Time of day patterns
    // - Historical usage
    // - Predicted demand
    // Implementation depends on requirements
}
```

### Health Monitoring System

```go
// pkg/connection/health.go
package connection

import (
    "context"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/network"
)

// HealthMonitor monitors connection health
type HealthMonitor struct {
    cm              *ConnectionManager
    checkInterval   time.Duration
    checkTimeout    time.Duration
    unhealthyThreshold int
    
    // Health tracking
    mu              sync.RWMutex
    healthScores    map[string]float64
    checkHistory    map[string][]HealthCheck
    
    // Lifecycle
    ctx             context.Context
    cancel          context.CancelFunc
}

// HealthCheck represents a single health check result
type HealthCheck struct {
    Timestamp   time.Time
    Success     bool
    Latency     time.Duration
    Error       error
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(cm *ConnectionManager, interval, timeout time.Duration) *HealthMonitor {
    ctx, cancel := context.WithCancel(cm.ctx)
    
    return &HealthMonitor{
        cm:            cm,
        checkInterval: interval,
        checkTimeout:  timeout,
        unhealthyThreshold: 3,
        healthScores:  make(map[string]float64),
        checkHistory:  make(map[string][]HealthCheck),
        ctx:           ctx,
        cancel:        cancel,
    }
}

// CheckConnection performs a health check on a connection
func (hm *HealthMonitor) CheckConnection(conn *Connection) error {
    start := time.Now()
    
    // Create health check context
    ctx, cancel := context.WithTimeout(hm.ctx, hm.checkTimeout)
    defer cancel()
    
    // Send ping
    if err := hm.sendPing(ctx, conn); err != nil {
        hm.recordCheck(conn, false, 0, err)
        return err
    }
    
    latency := time.Since(start)
    
    // Update connection metrics
    conn.mu.Lock()
    conn.Latency = latency
    conn.LastHealthAt = time.Now()
    conn.mu.Unlock()
    
    hm.recordCheck(conn, true, latency, nil)
    hm.updateHealthScore(conn)
    
    return nil
}

// sendPing sends a ping message to test connectivity
func (hm *HealthMonitor) sendPing(ctx context.Context, conn *Connection) error {
    // Implementation depends on protocol
    // This is a simplified example
    
    pingData := []byte("ping")
    if _, err := conn.Stream.Write(pingData); err != nil {
        return err
    }
    
    // Read pong response
    pongData := make([]byte, 4)
    if _, err := conn.Stream.Read(pongData); err != nil {
        return err
    }
    
    if string(pongData) != "pong" {
        return ErrInvalidPingResponse
    }
    
    return nil
}

// recordCheck records a health check result
func (hm *HealthMonitor) recordCheck(conn *Connection, success bool, latency time.Duration, err error) {
    hm.mu.Lock()
    defer hm.mu.Unlock()
    
    check := HealthCheck{
        Timestamp: time.Now(),
        Success:   success,
        Latency:   latency,
        Error:     err,
    }
    
    // Add to history
    history := hm.checkHistory[conn.ID]
    history = append(history, check)
    
    // Keep only recent history (last 100 checks)
    if len(history) > 100 {
        history = history[len(history)-100:]
    }
    
    hm.checkHistory[conn.ID] = history
    
    // Update connection state
    if success {
        conn.SuccessCount++
    } else {
        conn.ErrorCount++
        hm.checkUnhealthy(conn)
    }
}

// updateHealthScore calculates and updates health score
func (hm *HealthMonitor) updateHealthScore(conn *Connection) {
    hm.mu.Lock()
    defer hm.mu.Unlock()
    
    history := hm.checkHistory[conn.ID]
    if len(history) == 0 {
        return
    }
    
    // Calculate score based on recent checks
    var successCount, totalLatency float64
    recentChecks := history
    if len(history) > 10 {
        recentChecks = history[len(history)-10:]
    }
    
    for _, check := range recentChecks {
        if check.Success {
            successCount++
            totalLatency += float64(check.Latency.Milliseconds())
        }
    }
    
    successRate := successCount / float64(len(recentChecks))
    avgLatency := totalLatency / successCount
    
    // Calculate health score (0-100)
    score := successRate * 100.0
    
    // Penalize high latency
    if avgLatency > 100 {
        latencyPenalty := min((avgLatency-100)/10, 30)
        score -= latencyPenalty
    }
    
    hm.healthScores[conn.ID] = max(0, score)
    
    // Update connection state based on score
    conn.mu.Lock()
    if score < 50 {
        conn.State = StateUnhealthy
    } else if conn.State == StateUnhealthy && score > 70 {
        conn.State = StateActive
    }
    conn.mu.Unlock()
}

// checkUnhealthy checks if connection should be marked unhealthy
func (hm *HealthMonitor) checkUnhealthy(conn *Connection) {
    history := hm.checkHistory[conn.ID]
    if len(history) < hm.unhealthyThreshold {
        return
    }
    
    // Check recent failures
    recentFailures := 0
    for i := len(history) - hm.unhealthyThreshold; i < len(history); i++ {
        if !history[i].Success {
            recentFailures++
        }
    }
    
    if recentFailures >= hm.unhealthyThreshold {
        conn.mu.Lock()
        conn.State = StateUnhealthy
        conn.mu.Unlock()
        
        hm.cm.metrics.UnhealthyConnections.Inc()
        log.Warnf("Connection %s marked unhealthy after %d failures", conn.ID, recentFailures)
    }
}

// GetHealthScore returns the health score for a connection
func (hm *HealthMonitor) GetHealthScore(connID string) float64 {
    hm.mu.RLock()
    defer hm.mu.RUnlock()
    return hm.healthScores[connID]
}

// GetHealthyCount returns the number of healthy connections
func (hm *HealthMonitor) GetHealthyCount() int {
    hm.mu.RLock()
    defer hm.mu.RUnlock()
    
    count := 0
    for _, score := range hm.healthScores {
        if score >= 70 {
            count++
        }
    }
    return count
}

// GetUnhealthyCount returns the number of unhealthy connections
func (hm *HealthMonitor) GetUnhealthyCount() int {
    hm.mu.RLock()
    defer hm.mu.RUnlock()
    
    count := 0
    for _, score := range hm.healthScores {
        if score < 50 {
            count++
        }
    }
    return count
}

// RunHealthChecks performs health checks on all connections
func (hm *HealthMonitor) RunHealthChecks() {
    hm.cm.poolsMu.RLock()
    pools := make([]*ConnectionPool, 0, len(hm.cm.pools))
    for _, pool := range hm.cm.pools {
        pools = append(pools, pool)
    }
    hm.cm.poolsMu.RUnlock()
    
    // Check all connections in parallel
    var wg sync.WaitGroup
    for _, pool := range pools {
        for _, conn := range pool.GetAll() {
            if time.Since(conn.LastHealthAt) < hm.checkInterval/2 {
                continue // Skip recent checks
            }
            
            wg.Add(1)
            go func(c *Connection) {
                defer wg.Done()
                if err := hm.CheckConnection(c); err != nil {
                    log.Debugf("Health check failed for %s: %v", c.ID, err)
                }
            }(conn)
        }
    }
    
    wg.Wait()
}

// healthCheckLoop runs periodic health checks
func (cm *ConnectionManager) healthCheckLoop() {
    defer cm.wg.Done()
    
    ticker := time.NewTicker(cm.config.HealthCheckInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            cm.health.RunHealthChecks()
        case <-cm.ctx.Done():
            return
        }
    }
}
```

### Recovery Manager

```go
// pkg/connection/recovery.go
package connection

import (
    "context"
    "math"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/peer"
)

// RecoveryManager handles connection recovery and reconnection
type RecoveryManager struct {
    cm               *ConnectionManager
    reconnectInterval time.Duration
    maxAttempts      int
    backoffMultiplier float64
    
    // Failure tracking
    mu               sync.RWMutex
    failures         map[peer.ID]*FailureInfo
    recoveryQueue    *PriorityQueue
    
    // Circuit breaker
    circuitBreakers  map[peer.ID]*CircuitBreaker
    
    // Lifecycle
    ctx              context.Context
    cancel           context.CancelFunc
    wg               sync.WaitGroup
}

// FailureInfo tracks connection failures for a peer
type FailureInfo struct {
    PeerID          peer.ID
    FailureCount    int
    LastFailure     time.Time
    LastError       error
    NextRetry       time.Time
    BackoffDuration time.Duration
}

// CircuitBreaker prevents repeated connection attempts
type CircuitBreaker struct {
    State           CircuitState
    FailureCount    int
    SuccessCount    int
    LastStateChange time.Time
    HalfOpenTests   int
}

// CircuitState represents circuit breaker state
type CircuitState int

const (
    CircuitClosed CircuitState = iota
    CircuitOpen
    CircuitHalfOpen
)

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(cm *ConnectionManager, interval time.Duration, maxAttempts int) *RecoveryManager {
    ctx, cancel := context.WithCancel(cm.ctx)
    
    rm := &RecoveryManager{
        cm:                cm,
        reconnectInterval: interval,
        maxAttempts:       maxAttempts,
        backoffMultiplier: 2.0,
        failures:          make(map[peer.ID]*FailureInfo),
        recoveryQueue:     NewPriorityQueue(),
        circuitBreakers:   make(map[peer.ID]*CircuitBreaker),
        ctx:               ctx,
        cancel:            cancel,
    }
    
    // Start recovery worker
    rm.wg.Add(1)
    go rm.recoveryLoop()
    
    return rm
}

// RecordFailure records a connection failure
func (rm *RecoveryManager) RecordFailure(p peer.ID, err error) {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    info, exists := rm.failures[p]
    if !exists {
        info = &FailureInfo{
            PeerID:          p,
            BackoffDuration: rm.reconnectInterval,
        }
        rm.failures[p] = info
    }
    
    // Update failure info
    info.FailureCount++
    info.LastFailure = time.Now()
    info.LastError = err
    
    // Calculate next retry with exponential backoff
    backoff := time.Duration(float64(info.BackoffDuration) * math.Pow(rm.backoffMultiplier, float64(info.FailureCount-1)))
    maxBackoff := 5 * time.Minute
    if backoff > maxBackoff {
        backoff = maxBackoff
    }
    
    info.NextRetry = time.Now().Add(backoff)
    info.BackoffDuration = backoff
    
    // Update circuit breaker
    rm.updateCircuitBreaker(p, false)
    
    // Add to recovery queue if not at max attempts
    if info.FailureCount < rm.maxAttempts {
        rm.recoveryQueue.Push(&RecoveryItem{
            PeerID:   p,
            Priority: info.NextRetry.Unix(),
        })
    }
    
    rm.cm.metrics.ConnectionFailures.Inc()
    log.Debugf("Recorded failure for %s: %v (attempt %d/%d)", p, err, info.FailureCount, rm.maxAttempts)
}

// RecordSuccess records a successful connection
func (rm *RecoveryManager) RecordSuccess(p peer.ID) {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    // Clear failure info
    delete(rm.failures, p)
    
    // Update circuit breaker
    rm.updateCircuitBreaker(p, true)
    
    rm.cm.metrics.RecoverySuccesses.Inc()
}

// updateCircuitBreaker updates circuit breaker state
func (rm *RecoveryManager) updateCircuitBreaker(p peer.ID, success bool) {
    cb, exists := rm.circuitBreakers[p]
    if !exists {
        cb = &CircuitBreaker{
            State:           CircuitClosed,
            LastStateChange: time.Now(),
        }
        rm.circuitBreakers[p] = cb
    }
    
    switch cb.State {
    case CircuitClosed:
        if success {
            cb.SuccessCount++
            cb.FailureCount = 0
        } else {
            cb.FailureCount++
            if cb.FailureCount >= 5 {
                cb.State = CircuitOpen
                cb.LastStateChange = time.Now()
                log.Warnf("Circuit breaker opened for %s", p)
            }
        }
        
    case CircuitOpen:
        // Check if enough time has passed to try again
        if time.Since(cb.LastStateChange) > 30*time.Second {
            cb.State = CircuitHalfOpen
            cb.LastStateChange = time.Now()
            cb.HalfOpenTests = 0
        }
        
    case CircuitHalfOpen:
        cb.HalfOpenTests++
        if success {
            cb.SuccessCount++
            if cb.SuccessCount >= 3 {
                cb.State = CircuitClosed
                cb.FailureCount = 0
                cb.SuccessCount = 0
                cb.LastStateChange = time.Now()
                log.Infof("Circuit breaker closed for %s", p)
            }
        } else {
            cb.State = CircuitOpen
            cb.LastStateChange = time.Now()
            log.Warnf("Circuit breaker re-opened for %s", p)
        }
    }
}

// CanConnect checks if connection attempt is allowed
func (rm *RecoveryManager) CanConnect(p peer.ID) bool {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    // Check circuit breaker
    if cb, exists := rm.circuitBreakers[p]; exists {
        if cb.State == CircuitOpen {
            return false
        }
    }
    
    // Check failure count
    if info, exists := rm.failures[p]; exists {
        if info.FailureCount >= rm.maxAttempts {
            return false
        }
        if time.Now().Before(info.NextRetry) {
            return false
        }
    }
    
    return true
}

// recoveryLoop attempts to recover failed connections
func (rm *RecoveryManager) recoveryLoop() {
    defer rm.wg.Done()
    
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            rm.attemptRecoveries()
        case <-rm.ctx.Done():
            return
        }
    }
}

// attemptRecoveries tries to recover failed connections
func (rm *RecoveryManager) attemptRecoveries() {
    now := time.Now()
    
    for {
        rm.mu.Lock()
        item := rm.recoveryQueue.Peek()
        if item == nil || time.Unix(item.Priority, 0).After(now) {
            rm.mu.Unlock()
            break
        }
        
        // Pop from queue
        rm.recoveryQueue.Pop()
        p := item.PeerID
        
        // Check if we can attempt recovery
        if !rm.CanConnect(p) {
            rm.mu.Unlock()
            continue
        }
        
        info := rm.failures[p]
        rm.mu.Unlock()
        
        // Attempt recovery
        log.Debugf("Attempting recovery for %s (attempt %d/%d)", p, info.FailureCount, rm.maxAttempts)
        
        ctx, cancel := context.WithTimeout(rm.ctx, 30*time.Second)
        conn, err := rm.cm.Connect(ctx, p)
        cancel()
        
        if err != nil {
            rm.RecordFailure(p, err)
            rm.cm.metrics.RecoveryFailures.Inc()
        } else {
            rm.RecordSuccess(p)
            log.Infof("Successfully recovered connection to %s", p)
            conn.Close() // Let normal connection management take over
        }
    }
}

// GetFailureInfo returns failure information for a peer
func (rm *RecoveryManager) GetFailureInfo(p peer.ID) *FailureInfo {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    return rm.failures[p]
}

// GetCircuitBreakerState returns circuit breaker state
func (rm *RecoveryManager) GetCircuitBreakerState(p peer.ID) CircuitState {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    if cb, exists := rm.circuitBreakers[p]; exists {
        return cb.State
    }
    return CircuitClosed
}

// Close shuts down the recovery manager
func (rm *RecoveryManager) Close() error {
    rm.cancel()
    rm.wg.Wait()
    return nil
}
```

## 4. Key Functions

### Connect() - Establish managed connection

```go
// Connect establishes a connection to a peer
// Parameters:
//   - ctx: Context for cancellation
//   - p: Target peer ID
//   - opts: Connection options
// Returns:
//   - *Connection: Managed connection
//   - error: Connection errors
func (cm *ConnectionManager) Connect(ctx context.Context, p peer.ID, opts ...ConnectionOption) (*Connection, error)
```

### GetConnection() - Retrieve existing connection

```go
// GetConnection retrieves an existing connection
// Parameters:
//   - p: Peer ID
//   - protocol: Protocol ID
// Returns:
//   - *Connection: Existing connection
//   - error: If no connection exists
func (cm *ConnectionManager) GetConnection(p peer.ID, protocol protocol.ID) (*Connection, error)
```

### CloseConnection() - Close specific connection

```go
// CloseConnection closes a specific connection
// Parameters:
//   - connID: Connection ID to close
// Returns:
//   - error: Close errors
func (cm *ConnectionManager) CloseConnection(connID string) error
```

### GetStats() - Get connection statistics

```go
// GetStats returns connection statistics
// Returns:
//   - *ConnectionStats: Current statistics
func (cm *ConnectionManager) GetStats() *ConnectionStats
```

## 5. Configuration

### Configuration Structure

```go
// pkg/connection/config.go
package connection

import "time"

// DefaultConfig returns production-ready configuration
func DefaultConfig() *Config {
    return &Config{
        // Pool configuration
        MaxConnections:        1000,
        MaxConnectionsPerPeer: 5,
        MinConnectionsPerPeer: 1,
        PoolStrategy:          StrategyDynamic,
        
        // Timeouts
        ConnectionTimeout: 30 * time.Second,
        IdleTimeout:       5 * time.Minute,
        MaxConnectionAge:  1 * time.Hour,
        
        // Health checks
        HealthCheckInterval:  30 * time.Second,
        HealthCheckTimeout:   5 * time.Second,
        UnhealthyThreshold:   3,
        
        // Recovery
        EnableAutoReconnect:  true,
        ReconnectInterval:    10 * time.Second,
        MaxReconnectAttempts: 5,
        BackoffMultiplier:    2.0,
        
        // Priority
        EnablePriority: true,
        PriorityLevels: 3,
    }
}

// ConnectionOption configures a connection
type ConnectionOption func(*connectionOptions)

type connectionOptions struct {
    Protocol protocol.ID
    Priority int
    ForceNew bool
}

// WithProtocol sets the protocol for the connection
func WithProtocol(p protocol.ID) ConnectionOption {
    return func(opts *connectionOptions) {
        opts.Protocol = p
    }
}

// WithPriority sets the connection priority
func WithPriority(priority int) ConnectionOption {
    return func(opts *connectionOptions) {
        opts.Priority = priority
    }
}

// ForceNew forces creation of a new connection
func ForceNew() ConnectionOption {
    return func(opts *connectionOptions) {
        opts.ForceNew = true
    }
}
```

### YAML Configuration Example

```yaml
# config/connection.yaml
connection:
  # Pool settings
  pool:
    max_total: 1000
    max_per_peer: 5
    min_per_peer: 1
    strategy: "dynamic" # fixed, dynamic, adaptive
    
  # Timeouts
  timeouts:
    connection: 30s
    idle: 5m
    max_age: 1h
    
  # Health monitoring
  health:
    check_interval: 30s
    check_timeout: 5s
    unhealthy_threshold: 3
    ping_protocol: "/blackhole/ping/1.0.0"
    
  # Recovery settings
  recovery:
    enabled: true
    interval: 10s
    max_attempts: 5
    backoff_multiplier: 2.0
    circuit_breaker:
      failure_threshold: 5
      timeout: 30s
      
  # Priority settings
  priority:
    enabled: true
    levels: 3
    weights:
      high: 100
      medium: 50
      low: 10
```

### Environment Variables

```bash
# Connection limits
export BLACKHOLE_CONN_MAX_TOTAL=1000
export BLACKHOLE_CONN_MAX_PER_PEER=5
export BLACKHOLE_CONN_MIN_PER_PEER=1

# Timeouts
export BLACKHOLE_CONN_TIMEOUT=30s
export BLACKHOLE_CONN_IDLE_TIMEOUT=5m
export BLACKHOLE_CONN_MAX_AGE=1h

# Health checks
export BLACKHOLE_CONN_HEALTH_INTERVAL=30s
export BLACKHOLE_CONN_HEALTH_TIMEOUT=5s

# Recovery
export BLACKHOLE_CONN_RECOVERY_ENABLED=true
export BLACKHOLE_CONN_RECOVERY_INTERVAL=10s
export BLACKHOLE_CONN_RECOVERY_MAX_ATTEMPTS=5
```

## 6. Testing Requirements

### Unit Tests

```go
// pkg/connection/tests/manager_test.go
package connection_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/blackhole/pkg/connection"
)

func TestConnectionPooling(t *testing.T) {
    cm := setupTestConnectionManager(t)
    defer cm.Close()
    
    peer1 := generatePeerID("peer1")
    protocol := protocol.ID("/test/1.0.0")
    
    // Create first connection
    conn1, err := cm.Connect(context.Background(), peer1, 
        connection.WithProtocol(protocol))
    require.NoError(t, err)
    assert.NotNil(t, conn1)
    
    // Get same connection from pool
    conn2, err := cm.Connect(context.Background(), peer1,
        connection.WithProtocol(protocol))
    require.NoError(t, err)
    assert.Equal(t, conn1.ID, conn2.ID)
    
    // Force new connection
    conn3, err := cm.Connect(context.Background(), peer1,
        connection.WithProtocol(protocol),
        connection.ForceNew())
    require.NoError(t, err)
    assert.NotEqual(t, conn1.ID, conn3.ID)
}

func TestConnectionLimits(t *testing.T) {
    cfg := connection.DefaultConfig()
    cfg.MaxConnectionsPerPeer = 3
    
    cm := setupTestConnectionManagerWithConfig(t, cfg)
    defer cm.Close()
    
    peer1 := generatePeerID("peer1")
    
    // Create max connections
    for i := 0; i < 3; i++ {
        conn, err := cm.Connect(context.Background(), peer1,
            connection.ForceNew())
        require.NoError(t, err)
        assert.NotNil(t, conn)
    }
    
    // 4th connection should fail
    _, err := cm.Connect(context.Background(), peer1,
        connection.ForceNew())
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "max connections per peer")
}

func TestIdleConnectionCleanup(t *testing.T) {
    cfg := connection.DefaultConfig()
    cfg.IdleTimeout = 100 * time.Millisecond
    
    cm := setupTestConnectionManagerWithConfig(t, cfg)
    defer cm.Close()
    
    peer1 := generatePeerID("peer1")
    
    // Create connection
    conn, err := cm.Connect(context.Background(), peer1)
    require.NoError(t, err)
    
    connID := conn.ID
    
    // Verify connection exists
    stats := cm.GetStats()
    assert.Equal(t, 1, stats.TotalConnections)
    
    // Wait for idle timeout
    time.Sleep(200 * time.Millisecond)
    
    // Trigger maintenance
    cm.PerformMaintenance()
    
    // Verify connection was cleaned up
    stats = cm.GetStats()
    assert.Equal(t, 0, stats.TotalConnections)
    
    // Try to get cleaned connection
    _, err = cm.GetConnectionByID(connID)
    assert.Error(t, err)
}

func TestHealthMonitoring(t *testing.T) {
    cm := setupTestConnectionManager(t)
    defer cm.Close()
    
    peer1 := generatePeerID("peer1")
    
    // Create connection with mock health check
    conn, err := cm.Connect(context.Background(), peer1)
    require.NoError(t, err)
    
    // Simulate failed health checks
    for i := 0; i < 3; i++ {
        simulateHealthCheckFailure(conn)
    }
    
    // Wait for health check
    time.Sleep(100 * time.Millisecond)
    
    // Verify connection marked unhealthy
    assert.Equal(t, connection.StateUnhealthy, conn.State)
    
    // Simulate successful health checks
    for i := 0; i < 5; i++ {
        simulateHealthCheckSuccess(conn)
    }
    
    // Wait for recovery
    time.Sleep(100 * time.Millisecond)
    
    // Verify connection recovered
    assert.Equal(t, connection.StateActive, conn.State)
}

func TestConnectionRecovery(t *testing.T) {
    cfg := connection.DefaultConfig()
    cfg.EnableAutoReconnect = true
    cfg.ReconnectInterval = 100 * time.Millisecond
    
    cm := setupTestConnectionManagerWithConfig(t, cfg)
    defer cm.Close()
    
    peer1 := generatePeerID("peer1")
    
    // Simulate connection failure
    cm.RecordFailure(peer1, connection.ErrConnectionFailed)
    
    // Verify peer in recovery queue
    info := cm.GetFailureInfo(peer1)
    assert.NotNil(t, info)
    assert.Equal(t, 1, info.FailureCount)
    
    // Wait for recovery attempt
    time.Sleep(200 * time.Millisecond)
    
    // Simulate successful recovery
    mockSuccessfulConnection(cm, peer1)
    
    // Verify failure cleared
    info = cm.GetFailureInfo(peer1)
    assert.Nil(t, info)
}

func TestCircuitBreaker(t *testing.T) {
    cm := setupTestConnectionManager(t)
    defer cm.Close()
    
    peer1 := generatePeerID("peer1")
    
    // Simulate multiple failures
    for i := 0; i < 5; i++ {
        cm.RecordFailure(peer1, connection.ErrConnectionFailed)
    }
    
    // Circuit should be open
    state := cm.GetCircuitBreakerState(peer1)
    assert.Equal(t, connection.CircuitOpen, state)
    
    // Connection attempts should fail
    canConnect := cm.CanConnect(peer1)
    assert.False(t, canConnect)
    
    // Wait for circuit timeout
    time.Sleep(100 * time.Millisecond)
    
    // Simulate successful connection
    cm.RecordSuccess(peer1)
    
    // Circuit should move to half-open
    state = cm.GetCircuitBreakerState(peer1)
    assert.Equal(t, connection.CircuitHalfOpen, state)
}
```

### Integration Tests

```go
// pkg/connection/tests/integration_test.go
package connection_test

import (
    "context"
    "sync"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestConcurrentConnectionManagement(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    cm := setupTestConnectionManager(t)
    defer cm.Close()
    
    numPeers := 20
    connectionsPerPeer := 5
    
    var wg sync.WaitGroup
    errors := make(chan error, numPeers*connectionsPerPeer)
    
    // Concurrent connection creation
    for i := 0; i < numPeers; i++ {
        wg.Add(1)
        go func(peerNum int) {
            defer wg.Done()
            
            peer := generatePeerID(fmt.Sprintf("peer%d", peerNum))
            
            for j := 0; j < connectionsPerPeer; j++ {
                conn, err := cm.Connect(context.Background(), peer)
                if err != nil {
                    errors <- err
                    continue
                }
                
                // Simulate some work
                time.Sleep(10 * time.Millisecond)
                
                // Random close
                if j%2 == 0 {
                    conn.Close()
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Check errors
    errorCount := 0
    for err := range errors {
        if err != nil {
            errorCount++
            t.Logf("Connection error: %v", err)
        }
    }
    
    assert.Less(t, errorCount, 10) // Allow some failures
    
    // Verify stats
    stats := cm.GetStats()
    assert.Greater(t, stats.TotalConnections, 0)
    assert.LessOrEqual(t, stats.TotalConnections, cm.Config().MaxConnections)
}

func TestConnectionFailoverScenario(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    cm := setupTestConnectionManager(t)
    defer cm.Close()
    
    primaryPeer := generatePeerID("primary")
    backupPeer := generatePeerID("backup")
    
    // Establish primary connection
    primaryConn, err := cm.Connect(context.Background(), primaryPeer)
    require.NoError(t, err)
    
    // Establish backup connection
    backupConn, err := cm.Connect(context.Background(), backupPeer)
    require.NoError(t, err)
    
    // Simulate primary failure
    simulateConnectionFailure(primaryConn)
    
    // Wait for health check
    time.Sleep(100 * time.Millisecond)
    
    // Verify primary marked unhealthy
    assert.Equal(t, connection.StateUnhealthy, primaryConn.State)
    
    // Get connection should prefer backup
    conn, err := cm.GetBestConnection([]peer.ID{primaryPeer, backupPeer})
    require.NoError(t, err)
    assert.Equal(t, backupConn.ID, conn.ID)
}

func TestConnectionPoolPerformance(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping performance test")
    }
    
    cm := setupTestConnectionManager(t)
    defer cm.Close()
    
    // Pre-populate pools
    peers := make([]peer.ID, 100)
    for i := range peers {
        peers[i] = generatePeerID(fmt.Sprintf("peer%d", i))
        for j := 0; j < 3; j++ {
            cm.Connect(context.Background(), peers[i])
        }
    }
    
    // Measure pool performance
    start := time.Now()
    iterations := 10000
    
    for i := 0; i < iterations; i++ {
        peer := peers[i%len(peers)]
        conn, err := cm.GetConnection(peer, "/test/1.0.0")
        if err == nil {
            conn.LastUsedAt = time.Now()
        }
    }
    
    elapsed := time.Since(start)
    opsPerSecond := float64(iterations) / elapsed.Seconds()
    
    t.Logf("Pool operations: %.0f ops/sec", opsPerSecond)
    assert.Greater(t, opsPerSecond, 100000.0) // Should handle 100k+ ops/sec
}
```

### Performance Benchmarks

```go
// pkg/connection/tests/benchmark_test.go
package connection_test

import (
    "context"
    "testing"
)

func BenchmarkConnectionCreation(b *testing.B) {
    cm := setupBenchmarkConnectionManager(b)
    defer cm.Close()
    
    peer := generatePeerID("bench-peer")
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        conn, err := cm.Connect(context.Background(), peer,
            connection.ForceNew())
        if err != nil {
            b.Fatal(err)
        }
        conn.Close()
    }
}

func BenchmarkConnectionPooling(b *testing.B) {
    cm := setupBenchmarkConnectionManager(b)
    defer cm.Close()
    
    // Pre-create connections
    peers := make([]peer.ID, 100)
    for i := range peers {
        peers[i] = generatePeerID(fmt.Sprintf("peer%d", i))
        cm.Connect(context.Background(), peers[i])
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        peer := peers[i%len(peers)]
        conn, err := cm.GetConnection(peer, "/test/1.0.0")
        if err != nil {
            b.Fatal(err)
        }
        _ = conn
    }
}

func BenchmarkHealthCheck(b *testing.B) {
    cm := setupBenchmarkConnectionManager(b)
    defer cm.Close()
    
    peer := generatePeerID("bench-peer")
    conn, _ := cm.Connect(context.Background(), peer)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        cm.Health().CheckConnection(conn)
    }
}

func BenchmarkConcurrentPool(b *testing.B) {
    cm := setupBenchmarkConnectionManager(b)
    defer cm.Close()
    
    // Pre-create connections
    peers := make([]peer.ID, 10)
    for i := range peers {
        peers[i] = generatePeerID(fmt.Sprintf("peer%d", i))
        for j := 0; j < 5; j++ {
            cm.Connect(context.Background(), peers[i])
        }
    }
    
    b.RunParallel(func(pb *testing.PB) {
        i := 0
        for pb.Next() {
            peer := peers[i%len(peers)]
            conn, _ := cm.GetConnection(peer, "/test/1.0.0")
            if conn != nil {
                conn.LastUsedAt = time.Now()
            }
            i++
        }
    })
}
```

## 7. Monitoring & Metrics

### Metrics Implementation

```go
// pkg/connection/metrics.go
package connection

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics tracks connection management metrics
type Metrics struct {
    // Connection metrics
    ConnectionsEstablished   prometheus.Counter
    ConnectionsRejected      prometheus.Counter
    ConnectionsClosed        prometheus.Counter
    ConnectionFailures       prometheus.Counter
    ActiveConnections        prometheus.Gauge
    
    // Pool metrics
    PoolsCreated            prometheus.Counter
    PoolsDestroyed          prometheus.Counter
    ConnectionReuse         prometheus.Counter
    PoolHitRate             prometheus.Gauge
    
    // Health metrics
    HealthChecksPerformed   prometheus.Counter
    HealthCheckFailures     prometheus.Counter
    UnhealthyConnections    prometheus.Gauge
    UnhealthyConnectionsUsed prometheus.Counter
    
    // Recovery metrics
    RecoveryAttempts        prometheus.Counter
    RecoverySuccesses       prometheus.Counter
    RecoveryFailures        prometheus.Counter
    CircuitBreakerTrips     prometheus.Counter
    
    // Lifecycle metrics
    IdleConnectionsClosed   prometheus.Counter
    AgedConnectionsClosed   prometheus.Counter
    ConnectionAge           prometheus.Histogram
    ConnectionIdleTime      prometheus.Histogram
    
    // Performance metrics
    ConnectionLatency       prometheus.Histogram
    PoolLookupLatency       prometheus.Histogram
    HealthCheckDuration     prometheus.Histogram
}

// NewMetrics creates connection management metrics
func NewMetrics() *Metrics {
    return &Metrics{
        ConnectionsEstablished: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_established_total",
            Help: "Total connections established",
        }),
        
        ConnectionsRejected: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_rejected_total",
            Help: "Total connections rejected",
        }),
        
        ConnectionsClosed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_closed_total",
            Help: "Total connections closed",
        }),
        
        ConnectionFailures: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_failures_total",
            Help: "Total connection failures",
        }),
        
        ActiveConnections: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_connection_active",
            Help: "Current active connections",
        }),
        
        PoolsCreated: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_pools_created_total",
            Help: "Total connection pools created",
        }),
        
        PoolsDestroyed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_pools_destroyed_total",
            Help: "Total connection pools destroyed",
        }),
        
        ConnectionReuse: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_reuse_total",
            Help: "Total connection reuses from pool",
        }),
        
        PoolHitRate: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_connection_pool_hit_rate",
            Help: "Connection pool hit rate",
        }),
        
        HealthChecksPerformed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_health_checks_total",
            Help: "Total health checks performed",
        }),
        
        HealthCheckFailures: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_health_check_failures_total",
            Help: "Total health check failures",
        }),
        
        UnhealthyConnections: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_connection_unhealthy",
            Help: "Current unhealthy connections",
        }),
        
        UnhealthyConnectionsUsed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_unhealthy_used_total",
            Help: "Unhealthy connections used",
        }),
        
        RecoveryAttempts: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_recovery_attempts_total",
            Help: "Total recovery attempts",
        }),
        
        RecoverySuccesses: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_recovery_successes_total",
            Help: "Successful recoveries",
        }),
        
        RecoveryFailures: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_recovery_failures_total",
            Help: "Failed recoveries",
        }),
        
        CircuitBreakerTrips: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_circuit_breaker_trips_total",
            Help: "Circuit breaker trips",
        }),
        
        IdleConnectionsClosed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_idle_closed_total",
            Help: "Idle connections closed",
        }),
        
        AgedConnectionsClosed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_connection_aged_closed_total",
            Help: "Aged connections closed",
        }),
        
        ConnectionAge: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_connection_age_seconds",
            Help:    "Connection age at close",
            Buckets: prometheus.ExponentialBuckets(60, 2, 10),
        }),
        
        ConnectionIdleTime: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_connection_idle_seconds",
            Help:    "Connection idle time",
            Buckets: prometheus.ExponentialBuckets(1, 2, 10),
        }),
        
        ConnectionLatency: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_connection_latency_ms",
            Help:    "Connection latency in milliseconds",
            Buckets: prometheus.ExponentialBuckets(1, 2, 12),
        }),
        
        PoolLookupLatency: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_connection_pool_lookup_latency_us",
            Help:    "Pool lookup latency in microseconds",
            Buckets: prometheus.ExponentialBuckets(1, 2, 10),
        }),
        
        HealthCheckDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_connection_health_check_duration_ms",
            Help:    "Health check duration in milliseconds",
            Buckets: prometheus.ExponentialBuckets(1, 2, 10),
        }),
    }
}

// metricsCollectionLoop collects periodic metrics
func (cm *ConnectionManager) metricsCollectionLoop() {
    defer cm.wg.Done()
    
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            cm.collectMetrics()
        case <-cm.ctx.Done():
            return
        }
    }
}

// collectMetrics updates gauge metrics
func (cm *ConnectionManager) collectMetrics() {
    stats := cm.GetStats()
    
    // Update gauges
    cm.metrics.ActiveConnections.Set(float64(stats.TotalConnections))
    cm.metrics.UnhealthyConnections.Set(float64(stats.UnhealthyConnections))
    
    // Calculate pool hit rate
    totalHitRate := 0.0
    poolCount := 0
    
    for _, poolStats := range stats.Pools {
        if poolStats.HitRate > 0 {
            totalHitRate += poolStats.HitRate
            poolCount++
        }
    }
    
    if poolCount > 0 {
        cm.metrics.PoolHitRate.Set(totalHitRate / float64(poolCount))
    }
}
```

### Monitoring Dashboard

```yaml
# Grafana dashboard configuration
panels:
  - title: "Active Connections"
    query: "blackhole_connection_active"
    
  - title: "Connection Rate"
    queries:
      - "rate(blackhole_connection_established_total[5m])"
      - "rate(blackhole_connection_closed_total[5m])"
      
  - title: "Connection Pool Hit Rate"
    query: "blackhole_connection_pool_hit_rate"
    unit: "percentunit"
    
  - title: "Health Status"
    queries:
      - "blackhole_connection_active"
      - "blackhole_connection_unhealthy"
      
  - title: "Recovery Activity"
    queries:
      - "rate(blackhole_connection_recovery_attempts_total[5m])"
      - "rate(blackhole_connection_recovery_successes_total[5m])"
      
  - title: "Connection Latency"
    query: |
      histogram_quantile(0.95,
        rate(blackhole_connection_latency_ms_bucket[5m])
      )
      
  - title: "Connection Age Distribution"
    query: |
      histogram_quantile(0.95,
        rate(blackhole_connection_age_seconds_bucket[5m])
      )
      
  - title: "Circuit Breaker Activity"
    query: "increase(blackhole_connection_circuit_breaker_trips_total[5m])"
```

## 8. Error Handling

### Error Types

```go
// pkg/connection/errors.go
package connection

import "errors"

var (
    // Connection errors
    ErrConnectionFailed       = errors.New("connection failed")
    ErrConnectionTimeout      = errors.New("connection timeout")
    ErrConnectionClosed       = errors.New("connection closed")
    ErrNoConnection           = errors.New("no connection available")
    ErrConnectionNotFound     = errors.New("connection not found")
    
    // Pool errors
    ErrNoConnectionPool       = errors.New("no connection pool for peer")
    ErrPoolFull               = errors.New("connection pool is full")
    ErrMaxConnectionsReached  = errors.New("max total connections reached")
    ErrMaxConnectionsPerPeer  = errors.New("max connections per peer reached")
    
    // Health errors
    ErrHealthCheckFailed      = errors.New("health check failed")
    ErrConnectionUnhealthy    = errors.New("connection is unhealthy")
    ErrInvalidPingResponse    = errors.New("invalid ping response")
    
    // Recovery errors
    ErrRecoveryFailed         = errors.New("connection recovery failed")
    ErrMaxRetriesExceeded     = errors.New("max retry attempts exceeded")
    ErrCircuitBreakerOpen     = errors.New("circuit breaker is open")
    
    // Configuration errors
    ErrInvalidConfiguration   = errors.New("invalid configuration")
    ErrInvalidPoolStrategy    = errors.New("invalid pool strategy")
)
```

## 9. Acceptance Criteria

### Functional Requirements

1. **Connection Pooling**
   - [ ] Per-peer pools working
   - [ ] Global limits enforced
   - [ ] Connection reuse functional
   - [ ] LRU eviction working

2. **Lifecycle Management**
   - [ ] State machine functional
   - [ ] Idle timeout working
   - [ ] Age-based rotation
   - [ ] Graceful shutdown

3. **Health Monitoring**
   - [ ] Periodic health checks
   - [ ] Latency tracking accurate
   - [ ] Unhealthy detection working
   - [ ] Recovery detection functional

4. **Recovery Mechanisms**
   - [ ] Auto-reconnection working
   - [ ] Exponential backoff functional
   - [ ] Circuit breaker operational
   - [ ] Failure tracking accurate

### Performance Requirements

1. **Connection Operations**
   - Pool lookup: < 1μs
   - Connection creation: < 100ms
   - Health check: < 10ms

2. **Scalability**
   - Support 10k+ connections
   - 100k+ pool operations/sec
   - Minimal memory per connection

3. **Resource Efficiency**
   - Connection reuse > 80%
   - Idle cleanup effective
   - Memory usage bounded

## 10. Example Usage

### Basic Connection Management

```go
package main

import (
    "context"
    "log"
    
    "github.com/blackhole/pkg/connection"
    "github.com/blackhole/pkg/network"
)

func main() {
    // Create host
    host, err := network.NewHost(context.Background(), network.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    
    // Create connection manager
    cmConfig := connection.DefaultConfig()
    cmConfig.MaxConnectionsPerPeer = 3
    cmConfig.EnableAutoReconnect = true
    
    cm, err := connection.NewConnectionManager(host, cmConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer cm.Close()
    
    // Connect to peer
    peerID := "QmPeer123..."
    conn, err := cm.Connect(context.Background(), peerID,
        connection.WithProtocol("/blackhole/data/1.0.0"),
        connection.WithPriority(connection.PriorityHigh))
    
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    
    log.Printf("Connected to %s (ID: %s)", peerID, conn.ID)
    
    // Use connection
    if err := sendData(conn); err != nil {
        log.Printf("Send failed: %v", err)
    }
    
    // Get connection stats
    stats := cm.GetStats()
    log.Printf("Total connections: %d", stats.TotalConnections)
    log.Printf("Healthy connections: %d", stats.HealthyConnections)
    
    // Connection will be returned to pool automatically
}
```

### Advanced Pool Management

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/blackhole/pkg/connection"
)

func manageConnections(cm *connection.ConnectionManager) {
    // Monitor connection health
    go func() {
        ticker := time.NewTicker(1 * time.Minute)
        defer ticker.Stop()
        
        for range ticker.C {
            stats := cm.GetStats()
            
            for peerID, poolStats := range stats.Pools {
                if poolStats.HitRate < 0.5 {
                    log.Printf("Low hit rate for peer %s: %.2f", 
                        peerID, poolStats.HitRate)
                }
                
                if poolStats.Connections > 5 {
                    log.Printf("High connection count for peer %s: %d",
                        peerID, poolStats.Connections)
                }
            }
        }
    }()
    
    // Handle connection events
    cm.OnConnectionEvent(func(event connection.Event) {
        switch event.Type {
        case connection.EventConnected:
            log.Printf("New connection: %s to %s", 
                event.ConnectionID, event.PeerID)
                
        case connection.EventDisconnected:
            log.Printf("Connection closed: %s", event.ConnectionID)
            
        case connection.EventUnhealthy:
            log.Printf("Connection unhealthy: %s", event.ConnectionID)
            
        case connection.EventRecovered:
            log.Printf("Connection recovered: %s", event.ConnectionID)
        }
    })
}
```

## Summary

Unit U09 implements comprehensive connection management for the Blackhole network, providing intelligent pooling, lifecycle management, health monitoring, and automatic recovery. The implementation ensures efficient resource utilization while maintaining high availability and performance.

Key achievements:
- Intelligent connection pooling with multiple strategies
- Complete lifecycle management with state tracking
- Proactive health monitoring and quality metrics
- Automatic recovery with circuit breaker protection
- Comprehensive metrics and monitoring
- Production-ready scalability and performance
- Graceful degradation and error handling

This unit ensures that network connections are managed efficiently, failures are handled gracefully, and the system maintains optimal performance under various network conditions.