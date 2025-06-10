# Unit U08: Rate Limiting - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U08 implements comprehensive rate limiting and DDoS protection for the Blackhole network. This unit provides multi-layered defense mechanisms against various types of network attacks, resource exhaustion, and abuse scenarios while maintaining service quality for legitimate users.

**Primary Goals:**
- Implement network-level rate limiting for connections and bandwidth
- Provide application-level rate limiting for API calls and service requests
- Deploy DDoS detection and mitigation strategies
- Enable dynamic rate limit adjustment based on network conditions
- Implement fair resource allocation among users

### Dependencies

- **U01: libp2p Core Setup** - Network transport layer
- **U02: Kademlia DHT Implementation** - DHT operation rate limiting
- **U06: Service Discovery Protocol** - Service query rate limiting
- **U07: Network Security Layer** - Integration with security policies

### Deliverables

1. **Rate Limiter Engine**
   - Token bucket implementation
   - Sliding window rate limiter
   - Distributed rate limiting with Redis
   - Hierarchical rate limiting

2. **DDoS Protection System**
   - SYN flood protection
   - Amplification attack mitigation
   - Pattern-based attack detection
   - Automatic blacklisting

3. **Resource Management**
   - Connection pool limiting
   - Bandwidth throttling
   - Memory usage controls
   - CPU usage limiting

4. **Monitoring and Analytics**
   - Rate limit metrics
   - Attack detection alerts
   - Traffic analysis
   - Performance impact tracking

### Integration Points

This unit protects:
- All network connections (U01-U09)
- API endpoints (U41)
- Service discovery queries (U06)
- Storage operations (U10-U13)
- Payment transactions (U14-U19)

## 2. Technical Specifications

### Rate Limiting Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ API Limiter │  │Service Limiter│  │ Query Limiter    │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Rate Limiter Engine                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │Token Bucket │  │Sliding Window│  │ Leaky Bucket     │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    DDoS Protection                           │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ SYN Cookie  │  │Pattern Match │  │ Blacklist       │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Resource Management                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Connection  │  │  Bandwidth   │  │ Memory/CPU      │  │
│  │   Limits    │  │  Throttling  │  │   Limits        │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Network Layer                             │
│                  (TCP/UDP/QUIC)                              │
└─────────────────────────────────────────────────────────────┘
```

### Rate Limiting Algorithms

#### Token Bucket
- **Capacity**: Configurable per resource
- **Refill Rate**: Tokens per second
- **Burst Handling**: Allow temporary exceeding
- **Fair Queuing**: Priority-based token distribution

#### Sliding Window
- **Window Size**: 1 minute default
- **Precision**: 1-second buckets
- **Memory Efficient**: Ring buffer implementation
- **Accurate**: No boundary issues

#### Leaky Bucket
- **Fixed Rate**: Constant output rate
- **Queue Size**: Configurable buffer
- **Overflow Handling**: Drop or queue
- **Smooth Traffic**: No bursts

### DDoS Protection Strategies

1. **Layer 3/4 Protection**
   - SYN cookies for TCP
   - Rate limiting by IP
   - Geographic filtering
   - Protocol validation

2. **Layer 7 Protection**
   - Request pattern analysis
   - Behavioral analysis
   - CAPTCHA challenges
   - Proof of work

3. **Amplification Prevention**
   - Response size limiting
   - Reflection attack mitigation
   - DNS query filtering
   - NTP monlist blocking

## 3. Implementation Details

### Project Structure

```
pkg/ratelimit/
├── ratelimit.go        # Main rate limiter manager
├── tokenbucket.go      # Token bucket implementation
├── slidingwindow.go    # Sliding window implementation
├── leakybucket.go      # Leaky bucket implementation
├── distributed.go      # Distributed rate limiting
├── ddos.go             # DDoS protection system
├── throttle.go         # Bandwidth throttling
├── monitor.go          # Rate limit monitoring
├── policy.go           # Rate limit policies
├── metrics.go          # Rate limiting metrics
├── errors.go           # Rate limit errors
├── tests/
│   ├── ratelimit_test.go
│   ├── tokenbucket_test.go
│   ├── ddos_test.go
│   ├── throttle_test.go
│   └── integration_test.go
└── examples/
    ├── api_limiter/    # API rate limiting example
    └── ddos_protection/ # DDoS protection example
```

### Core Rate Limiter Implementation

```go
// pkg/ratelimit/ratelimit.go
package ratelimit

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/redis/go-redis/v9"
)

const (
    // Default rate limits
    DefaultConnectionsPerSecond = 10
    DefaultBytesPerSecond      = 10 * 1024 * 1024 // 10MB/s
    DefaultRequestsPerMinute   = 600
    DefaultBurstSize          = 20
    
    // DDoS thresholds
    SYNFloodThreshold = 100
    PacketFloodThreshold = 10000
    BandwidthFloodThreshold = 100 * 1024 * 1024 // 100MB/s
)

// RateLimiter manages all rate limiting functionality
type RateLimiter struct {
    host       host.Host
    config     *Config
    
    // Rate limiters by type
    connLimiter    *ConnectionLimiter
    bwLimiter      *BandwidthLimiter
    apiLimiter     *APILimiter
    queryLimiter   *QueryLimiter
    
    // DDoS protection
    ddos          *DDoSProtection
    
    // Distributed coordination
    redis         *redis.Client
    
    // Resource tracking
    mu            sync.RWMutex
    peerLimits    map[peer.ID]*PeerLimits
    ipLimits      map[string]*IPLimits
    
    // Monitoring
    monitor       *RateLimitMonitor
    metrics       *Metrics
    
    // Lifecycle
    ctx           context.Context
    cancel        context.CancelFunc
    wg            sync.WaitGroup
}

// Config holds rate limiter configuration
type Config struct {
    // Connection limits
    MaxConnectionsPerPeer    int
    MaxConnectionsPerIP      int
    ConnectionsPerSecond     int
    ConnectionBurstSize      int
    
    // Bandwidth limits
    MaxBytesPerSecond       int64
    MaxBytesPerPeer         int64
    BandwidthBurstSize      int64
    
    // API limits
    RequestsPerMinute       int
    RequestsPerHour         int
    RequestBurstSize        int
    
    // Query limits
    QueriesPerSecond        int
    QueriesPerMinute        int
    QueryComplexityLimit    int
    
    // DDoS protection
    EnableDDoSProtection    bool
    DDoSThresholds         DDoSThresholds
    
    // Distributed settings
    RedisURL               string
    EnableDistributed      bool
    
    // Policy settings
    PolicyUpdateInterval   time.Duration
    DynamicAdjustment     bool
}

// PeerLimits tracks limits for a specific peer
type PeerLimits struct {
    PeerID              peer.ID
    ConnectionCount     int
    BytesPerSecond      int64
    RequestsPerMinute   int
    LastActivity        time.Time
    Violations          int
    Blocked             bool
}

// IPLimits tracks limits for an IP address
type IPLimits struct {
    IP                  net.IP
    ConnectionCount     int
    PacketsPerSecond    int
    BytesPerSecond      int64
    SuspiciousActivity  int
    LastSeen           time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(h host.Host, cfg *Config) (*RateLimiter, error) {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    rl := &RateLimiter{
        host:       h,
        config:     cfg,
        peerLimits: make(map[peer.ID]*PeerLimits),
        ipLimits:   make(map[string]*IPLimits),
        metrics:    NewMetrics(),
        ctx:        ctx,
        cancel:     cancel,
    }
    
    // Initialize Redis if distributed mode
    if cfg.EnableDistributed && cfg.RedisURL != "" {
        opt, err := redis.ParseURL(cfg.RedisURL)
        if err != nil {
            cancel()
            return nil, fmt.Errorf("invalid redis URL: %w", err)
        }
        rl.redis = redis.NewClient(opt)
        
        // Test connection
        if err := rl.redis.Ping(ctx).Err(); err != nil {
            cancel()
            return nil, fmt.Errorf("redis connection failed: %w", err)
        }
    }
    
    // Initialize rate limiters
    rl.connLimiter = NewConnectionLimiter(rl)
    rl.bwLimiter = NewBandwidthLimiter(rl)
    rl.apiLimiter = NewAPILimiter(rl)
    rl.queryLimiter = NewQueryLimiter(rl)
    
    // Initialize DDoS protection
    if cfg.EnableDDoSProtection {
        rl.ddos = NewDDoSProtection(rl)
    }
    
    // Initialize monitor
    rl.monitor = NewRateLimitMonitor(rl)
    
    // Set up network notifications
    h.Network().Notify(&network.NotifyBundle{
        ConnectedF:    rl.onConnect,
        DisconnectedF: rl.onDisconnect,
    })
    
    // Start background workers
    rl.wg.Add(3)
    go rl.cleanupLoop()
    go rl.monitorLoop()
    go rl.policyUpdateLoop()
    
    return rl, nil
}

// AllowConnection checks if a new connection is allowed
func (rl *RateLimiter) AllowConnection(p peer.ID, addr net.Addr) error {
    // Check peer connection limit
    if err := rl.checkPeerConnectionLimit(p); err != nil {
        rl.metrics.ConnectionsRejected.Inc()
        rl.metrics.RejectionReason.WithLabelValues("peer_limit").Inc()
        return err
    }
    
    // Check IP connection limit
    if tcpAddr, ok := addr.(*net.TCPAddr); ok {
        if err := rl.checkIPConnectionLimit(tcpAddr.IP); err != nil {
            rl.metrics.ConnectionsRejected.Inc()
            rl.metrics.RejectionReason.WithLabelValues("ip_limit").Inc()
            return err
        }
    }
    
    // Check connection rate limit
    if err := rl.connLimiter.Allow(p); err != nil {
        rl.metrics.ConnectionsRejected.Inc()
        rl.metrics.RejectionReason.WithLabelValues("rate_limit").Inc()
        return err
    }
    
    // Check DDoS protection
    if rl.ddos != nil {
        if err := rl.ddos.CheckConnection(p, addr); err != nil {
            rl.metrics.ConnectionsRejected.Inc()
            rl.metrics.RejectionReason.WithLabelValues("ddos").Inc()
            return err
        }
    }
    
    rl.metrics.ConnectionsAccepted.Inc()
    return nil
}

// AllowBandwidth checks if bandwidth usage is allowed
func (rl *RateLimiter) AllowBandwidth(p peer.ID, bytes int64) error {
    return rl.bwLimiter.Allow(p, bytes)
}

// AllowRequest checks if an API request is allowed
func (rl *RateLimiter) AllowRequest(p peer.ID, endpoint string) error {
    return rl.apiLimiter.Allow(p, endpoint)
}

// AllowQuery checks if a query is allowed
func (rl *RateLimiter) AllowQuery(p peer.ID, queryType string, complexity int) error {
    return rl.queryLimiter.Allow(p, queryType, complexity)
}

// checkPeerConnectionLimit verifies peer connection count
func (rl *RateLimiter) checkPeerConnectionLimit(p peer.ID) error {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    limits, exists := rl.peerLimits[p]
    if !exists {
        limits = &PeerLimits{
            PeerID: p,
        }
        rl.peerLimits[p] = limits
    }
    
    if limits.Blocked {
        return ErrPeerBlocked
    }
    
    if limits.ConnectionCount >= rl.config.MaxConnectionsPerPeer {
        return ErrTooManyConnections
    }
    
    return nil
}

// checkIPConnectionLimit verifies IP connection count
func (rl *RateLimiter) checkIPConnectionLimit(ip net.IP) error {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    ipStr := ip.String()
    limits, exists := rl.ipLimits[ipStr]
    if !exists {
        limits = &IPLimits{
            IP: ip,
        }
        rl.ipLimits[ipStr] = limits
    }
    
    if limits.ConnectionCount >= rl.config.MaxConnectionsPerIP {
        // Check for suspicious activity
        limits.SuspiciousActivity++
        if limits.SuspiciousActivity > 10 {
            rl.blockIP(ip, 1*time.Hour)
        }
        return ErrTooManyConnectionsFromIP
    }
    
    return nil
}

// onConnect handles new connections
func (rl *RateLimiter) onConnect(n network.Network, c network.Conn) {
    p := c.RemotePeer()
    
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    // Update peer limits
    if limits, exists := rl.peerLimits[p]; exists {
        limits.ConnectionCount++
        limits.LastActivity = time.Now()
    } else {
        rl.peerLimits[p] = &PeerLimits{
            PeerID:          p,
            ConnectionCount: 1,
            LastActivity:    time.Now(),
        }
    }
    
    // Update IP limits
    if addr := c.RemoteMultiaddr(); addr != nil {
        if ip, err := getIPFromMultiaddr(addr); err == nil {
            ipStr := ip.String()
            if limits, exists := rl.ipLimits[ipStr]; exists {
                limits.ConnectionCount++
                limits.LastSeen = time.Now()
            } else {
                rl.ipLimits[ipStr] = &IPLimits{
                    IP:              ip,
                    ConnectionCount: 1,
                    LastSeen:        time.Now(),
                }
            }
        }
    }
}

// onDisconnect handles disconnections
func (rl *RateLimiter) onDisconnect(n network.Network, c network.Conn) {
    p := c.RemotePeer()
    
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    // Update peer limits
    if limits, exists := rl.peerLimits[p]; exists {
        limits.ConnectionCount--
        if limits.ConnectionCount <= 0 {
            delete(rl.peerLimits, p)
        }
    }
    
    // Update IP limits
    if addr := c.RemoteMultiaddr(); addr != nil {
        if ip, err := getIPFromMultiaddr(addr); err == nil {
            ipStr := ip.String()
            if limits, exists := rl.ipLimits[ipStr]; exists {
                limits.ConnectionCount--
                if limits.ConnectionCount <= 0 {
                    delete(rl.ipLimits, ipStr)
                }
            }
        }
    }
}

// BlockPeer blocks a peer for a duration
func (rl *RateLimiter) BlockPeer(p peer.ID, duration time.Duration, reason string) {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    limits, exists := rl.peerLimits[p]
    if !exists {
        limits = &PeerLimits{PeerID: p}
        rl.peerLimits[p] = limits
    }
    
    limits.Blocked = true
    
    // Schedule unblock
    time.AfterFunc(duration, func() {
        rl.mu.Lock()
        defer rl.mu.Unlock()
        if l, exists := rl.peerLimits[p]; exists {
            l.Blocked = false
        }
    })
    
    rl.metrics.PeersBlocked.Inc()
    log.Infof("Blocked peer %s for %v: %s", p, duration, reason)
}

// GetPeerStatus returns current status for a peer
func (rl *RateLimiter) GetPeerStatus(p peer.ID) (*PeerStatus, error) {
    rl.mu.RLock()
    defer rl.mu.RUnlock()
    
    limits, exists := rl.peerLimits[p]
    if !exists {
        return &PeerStatus{
            PeerID: p,
            Status: "unknown",
        }, nil
    }
    
    status := &PeerStatus{
        PeerID:           p,
        ConnectionCount:  limits.ConnectionCount,
        BytesPerSecond:   limits.BytesPerSecond,
        RequestsPerMinute: limits.RequestsPerMinute,
        Violations:       limits.Violations,
        LastActivity:     limits.LastActivity,
    }
    
    if limits.Blocked {
        status.Status = "blocked"
    } else if limits.Violations > 0 {
        status.Status = "warned"
    } else {
        status.Status = "ok"
    }
    
    return status, nil
}

// cleanupLoop removes stale entries
func (rl *RateLimiter) cleanupLoop() {
    defer rl.wg.Done()
    
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            rl.cleanup()
        case <-rl.ctx.Done():
            return
        }
    }
}

// cleanup removes inactive limits
func (rl *RateLimiter) cleanup() {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    now := time.Now()
    inactiveThreshold := 30 * time.Minute
    
    // Clean peer limits
    for p, limits := range rl.peerLimits {
        if limits.ConnectionCount == 0 && 
           now.Sub(limits.LastActivity) > inactiveThreshold {
            delete(rl.peerLimits, p)
        }
    }
    
    // Clean IP limits
    for ip, limits := range rl.ipLimits {
        if limits.ConnectionCount == 0 && 
           now.Sub(limits.LastSeen) > inactiveThreshold {
            delete(rl.ipLimits, ip)
        }
    }
}

// Close shuts down the rate limiter
func (rl *RateLimiter) Close() error {
    rl.cancel()
    rl.wg.Wait()
    
    if rl.redis != nil {
        return rl.redis.Close()
    }
    
    return nil
}
```

### Token Bucket Implementation

```go
// pkg/ratelimit/tokenbucket.go
package ratelimit

import (
    "sync"
    "time"
)

// TokenBucket implements the token bucket algorithm
type TokenBucket struct {
    capacity    int64
    tokens      int64
    refillRate  int64
    lastRefill  time.Time
    mu          sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
    return &TokenBucket{
        capacity:   capacity,
        tokens:     capacity,
        refillRate: refillRate,
        lastRefill: time.Now(),
    }
}

// Allow checks if n tokens are available
func (tb *TokenBucket) Allow(n int64) bool {
    tb.mu.Lock()
    defer tb.mu.Unlock()
    
    tb.refill()
    
    if tb.tokens >= n {
        tb.tokens -= n
        return true
    }
    
    return false
}

// AllowWait waits for n tokens to be available
func (tb *TokenBucket) AllowWait(n int64, timeout time.Duration) bool {
    deadline := time.Now().Add(timeout)
    
    for time.Now().Before(deadline) {
        if tb.Allow(n) {
            return true
        }
        
        // Calculate wait time
        tb.mu.Lock()
        needed := n - tb.tokens
        waitTime := time.Duration(needed/tb.refillRate) * time.Second
        tb.mu.Unlock()
        
        if waitTime > timeout {
            return false
        }
        
        time.Sleep(waitTime)
    }
    
    return false
}

// refill adds tokens based on elapsed time
func (tb *TokenBucket) refill() {
    now := time.Now()
    elapsed := now.Sub(tb.lastRefill)
    
    tokensToAdd := int64(elapsed.Seconds()) * tb.refillRate
    if tokensToAdd > 0 {
        tb.tokens = min(tb.tokens+tokensToAdd, tb.capacity)
        tb.lastRefill = now
    }
}

// Reset resets the bucket to full capacity
func (tb *TokenBucket) Reset() {
    tb.mu.Lock()
    defer tb.mu.Unlock()
    
    tb.tokens = tb.capacity
    tb.lastRefill = time.Now()
}

// GetAvailable returns current available tokens
func (tb *TokenBucket) GetAvailable() int64 {
    tb.mu.Lock()
    defer tb.mu.Unlock()
    
    tb.refill()
    return tb.tokens
}

// TokenBucketLimiter manages multiple token buckets
type TokenBucketLimiter struct {
    buckets map[string]*TokenBucket
    mu      sync.RWMutex
    config  TokenBucketConfig
}

// TokenBucketConfig configures token bucket parameters
type TokenBucketConfig struct {
    DefaultCapacity   int64
    DefaultRefillRate int64
    BucketTTL         time.Duration
}

// NewTokenBucketLimiter creates a new limiter
func NewTokenBucketLimiter(config TokenBucketConfig) *TokenBucketLimiter {
    return &TokenBucketLimiter{
        buckets: make(map[string]*TokenBucket),
        config:  config,
    }
}

// Allow checks if request is allowed for key
func (tbl *TokenBucketLimiter) Allow(key string, tokens int64) bool {
    tbl.mu.Lock()
    bucket, exists := tbl.buckets[key]
    if !exists {
        bucket = NewTokenBucket(
            tbl.config.DefaultCapacity,
            tbl.config.DefaultRefillRate,
        )
        tbl.buckets[key] = bucket
    }
    tbl.mu.Unlock()
    
    return bucket.Allow(tokens)
}

// SetLimit sets custom limits for a key
func (tbl *TokenBucketLimiter) SetLimit(key string, capacity, refillRate int64) {
    tbl.mu.Lock()
    defer tbl.mu.Unlock()
    
    tbl.buckets[key] = NewTokenBucket(capacity, refillRate)
}

// Reset resets limits for a key
func (tbl *TokenBucketLimiter) Reset(key string) {
    tbl.mu.Lock()
    defer tbl.mu.Unlock()
    
    if bucket, exists := tbl.buckets[key]; exists {
        bucket.Reset()
    }
}

// Cleanup removes expired buckets
func (tbl *TokenBucketLimiter) Cleanup() {
    tbl.mu.Lock()
    defer tbl.mu.Unlock()
    
    // Implementation would track last access time
    // and remove buckets not used for TTL duration
}
```

### DDoS Protection System

```go
// pkg/ratelimit/ddos.go
package ratelimit

import (
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/peer"
)

// DDoSProtection implements DDoS detection and mitigation
type DDoSProtection struct {
    rl         *RateLimiter
    
    // Attack detection
    synTracker *SYNTracker
    patterns   *PatternDetector
    anomaly    *AnomalyDetector
    
    // Mitigation
    synCookies bool
    challenges *ChallengeSystem
    
    // Metrics
    attacks    map[string]*AttackInfo
    mu         sync.RWMutex
}

// AttackInfo tracks information about detected attacks
type AttackInfo struct {
    Type       string
    Source     string
    StartTime  time.Time
    EndTime    time.Time
    Severity   int
    Mitigated  bool
}

// DDoSThresholds configures DDoS detection thresholds
type DDoSThresholds struct {
    SYNPerSecond        int
    PacketsPerSecond    int
    BytesPerSecond      int64
    ConnectionsPerIP    int
    QueryComplexity     int
}

// NewDDoSProtection creates a new DDoS protection system
func NewDDoSProtection(rl *RateLimiter) *DDoSProtection {
    return &DDoSProtection{
        rl:         rl,
        synTracker: NewSYNTracker(),
        patterns:   NewPatternDetector(),
        anomaly:    NewAnomalyDetector(),
        challenges: NewChallengeSystem(),
        attacks:    make(map[string]*AttackInfo),
        synCookies: true,
    }
}

// CheckConnection checks for connection-based attacks
func (dp *DDoSProtection) CheckConnection(p peer.ID, addr net.Addr) error {
    // Extract IP
    var ip net.IP
    if tcpAddr, ok := addr.(*net.TCPAddr); ok {
        ip = tcpAddr.IP
    } else {
        return nil
    }
    
    // Check SYN flood
    if dp.synTracker.IsSYNFlood(ip) {
        dp.recordAttack("syn_flood", ip.String())
        if dp.synCookies {
            // SYN cookies are handled at kernel level
            return nil
        }
        return ErrSYNFlood
    }
    
    // Check connection rate
    connRate := dp.getConnectionRate(ip)
    if connRate > dp.rl.config.DDoSThresholds.ConnectionsPerIP {
        dp.recordAttack("connection_flood", ip.String())
        return ErrConnectionFlood
    }
    
    // Check for amplification attacks
    if dp.isAmplificationSource(ip) {
        dp.recordAttack("amplification", ip.String())
        return ErrAmplificationAttack
    }
    
    return nil
}

// CheckTraffic analyzes traffic patterns for attacks
func (dp *DDoSProtection) CheckTraffic(source string, packets, bytes int64) error {
    // Check packet rate
    if packets > int64(dp.rl.config.DDoSThresholds.PacketsPerSecond) {
        dp.recordAttack("packet_flood", source)
        return ErrPacketFlood
    }
    
    // Check bandwidth
    if bytes > dp.rl.config.DDoSThresholds.BytesPerSecond {
        dp.recordAttack("bandwidth_flood", source)
        return ErrBandwidthFlood
    }
    
    // Pattern detection
    if dp.patterns.DetectAttackPattern(source, packets, bytes) {
        dp.recordAttack("pattern_attack", source)
        return ErrPatternAttack
    }
    
    // Anomaly detection
    if dp.anomaly.IsAnomalous(source, packets, bytes) {
        dp.recordAttack("anomaly", source)
        return ErrAnomalousTraffic
    }
    
    return nil
}

// MitigateAttack applies mitigation for detected attacks
func (dp *DDoSProtection) MitigateAttack(attackID string) error {
    dp.mu.Lock()
    attack, exists := dp.attacks[attackID]
    if !exists {
        dp.mu.Unlock()
        return fmt.Errorf("attack not found: %s", attackID)
    }
    dp.mu.Unlock()
    
    switch attack.Type {
    case "syn_flood":
        return dp.mitigateSYNFlood(attack)
    case "bandwidth_flood":
        return dp.mitigateBandwidthFlood(attack)
    case "amplification":
        return dp.mitigateAmplification(attack)
    default:
        return dp.mitigateGeneric(attack)
    }
}

// mitigateSYNFlood applies SYN flood mitigation
func (dp *DDoSProtection) mitigateSYNFlood(attack *AttackInfo) error {
    // Enable SYN cookies (usually kernel level)
    dp.synCookies = true
    
    // Rate limit SYN packets from source
    if err := dp.rl.BlockIP(net.ParseIP(attack.Source), 1*time.Hour); err != nil {
        return err
    }
    
    // Add to firewall rules if available
    if err := dp.addFirewallRule(attack.Source, "DROP"); err != nil {
        log.Warnf("Failed to add firewall rule: %v", err)
    }
    
    attack.Mitigated = true
    dp.rl.metrics.AttacksMitigated.Inc()
    
    return nil
}

// recordAttack records detected attack
func (dp *DDoSProtection) recordAttack(attackType, source string) {
    dp.mu.Lock()
    defer dp.mu.Unlock()
    
    key := fmt.Sprintf("%s:%s", attackType, source)
    if attack, exists := dp.attacks[key]; exists {
        attack.EndTime = time.Now()
        attack.Severity++
    } else {
        dp.attacks[key] = &AttackInfo{
            Type:      attackType,
            Source:    source,
            StartTime: time.Now(),
            Severity:  1,
        }
    }
    
    dp.rl.metrics.AttacksDetected.WithLabelValues(attackType).Inc()
}

// SYNTracker tracks SYN packets for flood detection
type SYNTracker struct {
    mu       sync.RWMutex
    counters map[string]*SYNCounter
}

// SYNCounter tracks SYN packets from an IP
type SYNCounter struct {
    Count      int
    WindowStart time.Time
}

// NewSYNTracker creates a new SYN tracker
func NewSYNTracker() *SYNTracker {
    return &SYNTracker{
        counters: make(map[string]*SYNCounter),
    }
}

// RecordSYN records a SYN packet
func (st *SYNTracker) RecordSYN(ip net.IP) {
    st.mu.Lock()
    defer st.mu.Unlock()
    
    key := ip.String()
    now := time.Now()
    
    counter, exists := st.counters[key]
    if !exists || now.Sub(counter.WindowStart) > time.Second {
        st.counters[key] = &SYNCounter{
            Count:       1,
            WindowStart: now,
        }
    } else {
        counter.Count++
    }
}

// IsSYNFlood checks if IP is flooding with SYN packets
func (st *SYNTracker) IsSYNFlood(ip net.IP) bool {
    st.mu.RLock()
    defer st.mu.RUnlock()
    
    counter, exists := st.counters[ip.String()]
    if !exists {
        return false
    }
    
    // Check if within time window
    if time.Since(counter.WindowStart) > time.Second {
        return false
    }
    
    return counter.Count > SYNFloodThreshold
}

// PatternDetector detects attack patterns
type PatternDetector struct {
    patterns []AttackPattern
    history  *TrafficHistory
}

// AttackPattern defines a traffic pattern indicating attack
type AttackPattern struct {
    Name        string
    PacketSize  []int
    Interval    time.Duration
    Repetitions int
}

// NewPatternDetector creates a pattern detector
func NewPatternDetector() *PatternDetector {
    return &PatternDetector{
        patterns: loadAttackPatterns(),
        history:  NewTrafficHistory(1000),
    }
}

// DetectAttackPattern checks for known attack patterns
func (pd *PatternDetector) DetectAttackPattern(source string, packets, bytes int64) bool {
    // Record traffic
    pd.history.Record(source, packets, bytes)
    
    // Check against known patterns
    for _, pattern := range pd.patterns {
        if pd.matchesPattern(source, pattern) {
            return true
        }
    }
    
    return false
}

// ChallengeSystem implements proof-of-work challenges
type ChallengeSystem struct {
    challenges map[string]*Challenge
    mu         sync.RWMutex
}

// Challenge represents a proof-of-work challenge
type Challenge struct {
    ID         string
    Difficulty int
    Nonce      []byte
    Issued     time.Time
    Solved     bool
}

// NewChallengeSystem creates a challenge system
func NewChallengeSystem() *ChallengeSystem {
    return &ChallengeSystem{
        challenges: make(map[string]*Challenge),
    }
}

// IssueChallenge creates a new challenge
func (cs *ChallengeSystem) IssueChallenge(clientID string, difficulty int) *Challenge {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    
    nonce := make([]byte, 32)
    rand.Read(nonce)
    
    challenge := &Challenge{
        ID:         generateChallengeID(),
        Difficulty: difficulty,
        Nonce:      nonce,
        Issued:     time.Now(),
    }
    
    cs.challenges[clientID] = challenge
    return challenge
}

// VerifyChallenge verifies a challenge solution
func (cs *ChallengeSystem) VerifyChallenge(clientID string, solution []byte) bool {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    
    challenge, exists := cs.challenges[clientID]
    if !exists {
        return false
    }
    
    // Check expiration
    if time.Since(challenge.Issued) > 5*time.Minute {
        delete(cs.challenges, clientID)
        return false
    }
    
    // Verify solution
    if verifySolution(challenge.Nonce, solution, challenge.Difficulty) {
        challenge.Solved = true
        return true
    }
    
    return false
}
```

### Bandwidth Throttling

```go
// pkg/ratelimit/throttle.go
package ratelimit

import (
    "io"
    "sync"
    "time"
    
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
)

// BandwidthLimiter limits bandwidth usage
type BandwidthLimiter struct {
    rl            *RateLimiter
    peerLimiters  map[peer.ID]*ThrottledPeer
    globalLimiter *TokenBucket
    mu            sync.RWMutex
}

// ThrottledPeer tracks bandwidth for a peer
type ThrottledPeer struct {
    PeerID       peer.ID
    ReadLimiter  *TokenBucket
    WriteLimiter *TokenBucket
    BytesRead    int64
    BytesWritten int64
    LastActive   time.Time
}

// NewBandwidthLimiter creates a bandwidth limiter
func NewBandwidthLimiter(rl *RateLimiter) *BandwidthLimiter {
    return &BandwidthLimiter{
        rl:            rl,
        peerLimiters:  make(map[peer.ID]*ThrottledPeer),
        globalLimiter: NewTokenBucket(
            rl.config.MaxBytesPerSecond,
            rl.config.MaxBytesPerSecond,
        ),
    }
}

// Allow checks if bandwidth is available
func (bl *BandwidthLimiter) Allow(p peer.ID, bytes int64) error {
    // Check global limit
    if !bl.globalLimiter.Allow(bytes) {
        bl.rl.metrics.BandwidthExceeded.Inc()
        return ErrGlobalBandwidthExceeded
    }
    
    // Check peer limit
    bl.mu.Lock()
    limiter, exists := bl.peerLimiters[p]
    if !exists {
        limiter = &ThrottledPeer{
            PeerID: p,
            ReadLimiter: NewTokenBucket(
                bl.rl.config.MaxBytesPerPeer,
                bl.rl.config.MaxBytesPerPeer,
            ),
            WriteLimiter: NewTokenBucket(
                bl.rl.config.MaxBytesPerPeer,
                bl.rl.config.MaxBytesPerPeer,
            ),
        }
        bl.peerLimiters[p] = limiter
    }
    bl.mu.Unlock()
    
    if !limiter.ReadLimiter.Allow(bytes) {
        bl.rl.metrics.PeerBandwidthExceeded.Inc()
        return ErrPeerBandwidthExceeded
    }
    
    limiter.BytesRead += bytes
    limiter.LastActive = time.Now()
    
    return nil
}

// WrapStream wraps a stream with bandwidth limiting
func (bl *BandwidthLimiter) WrapStream(s network.Stream) network.Stream {
    p := s.Conn().RemotePeer()
    
    bl.mu.Lock()
    limiter, exists := bl.peerLimiters[p]
    if !exists {
        limiter = &ThrottledPeer{
            PeerID: p,
            ReadLimiter: NewTokenBucket(
                bl.rl.config.MaxBytesPerPeer,
                bl.rl.config.MaxBytesPerPeer,
            ),
            WriteLimiter: NewTokenBucket(
                bl.rl.config.MaxBytesPerPeer,
                bl.rl.config.MaxBytesPerPeer,
            ),
        }
        bl.peerLimiters[p] = limiter
    }
    bl.mu.Unlock()
    
    return &ThrottledStream{
        Stream:       s,
        readLimiter:  limiter.ReadLimiter,
        writeLimiter: limiter.WriteLimiter,
        bl:           bl,
        peer:         p,
    }
}

// ThrottledStream implements bandwidth-limited stream
type ThrottledStream struct {
    network.Stream
    readLimiter  *TokenBucket
    writeLimiter *TokenBucket
    bl           *BandwidthLimiter
    peer         peer.ID
}

// Read implements throttled reading
func (ts *ThrottledStream) Read(b []byte) (int, error) {
    // Wait for tokens
    if !ts.readLimiter.AllowWait(int64(len(b)), 30*time.Second) {
        return 0, ErrBandwidthExceeded
    }
    
    // Read data
    n, err := ts.Stream.Read(b)
    
    // Update metrics
    if n > 0 {
        ts.bl.updateBytesRead(ts.peer, int64(n))
    }
    
    return n, err
}

// Write implements throttled writing
func (ts *ThrottledStream) Write(b []byte) (int, error) {
    // Wait for tokens
    if !ts.writeLimiter.AllowWait(int64(len(b)), 30*time.Second) {
        return 0, ErrBandwidthExceeded
    }
    
    // Write data
    n, err := ts.Stream.Write(b)
    
    // Update metrics
    if n > 0 {
        ts.bl.updateBytesWritten(ts.peer, int64(n))
    }
    
    return n, err
}

// updateBytesRead updates read metrics
func (bl *BandwidthLimiter) updateBytesRead(p peer.ID, bytes int64) {
    bl.mu.Lock()
    defer bl.mu.Unlock()
    
    if limiter, exists := bl.peerLimiters[p]; exists {
        limiter.BytesRead += bytes
        bl.rl.metrics.BytesReceived.Add(float64(bytes))
    }
}

// updateBytesWritten updates write metrics
func (bl *BandwidthLimiter) updateBytesWritten(p peer.ID, bytes int64) {
    bl.mu.Lock()
    defer bl.mu.Unlock()
    
    if limiter, exists := bl.peerLimiters[p]; exists {
        limiter.BytesWritten += bytes
        bl.rl.metrics.BytesSent.Add(float64(bytes))
    }
}

// GetPeerBandwidth returns bandwidth usage for a peer
func (bl *BandwidthLimiter) GetPeerBandwidth(p peer.ID) *BandwidthStats {
    bl.mu.RLock()
    defer bl.mu.RUnlock()
    
    limiter, exists := bl.peerLimiters[p]
    if !exists {
        return &BandwidthStats{PeerID: p}
    }
    
    return &BandwidthStats{
        PeerID:         p,
        BytesRead:      limiter.BytesRead,
        BytesWritten:   limiter.BytesWritten,
        ReadRate:       limiter.ReadLimiter.refillRate,
        WriteRate:      limiter.WriteLimiter.refillRate,
        LastActive:     limiter.LastActive,
    }
}
```

## 4. Key Functions

### AllowConnection() - Check connection limit

```go
// AllowConnection checks if a new connection is allowed
// Parameters:
//   - p: Peer ID attempting to connect
//   - addr: Network address of connection
// Returns:
//   - error: Rate limit error if exceeded
func (rl *RateLimiter) AllowConnection(p peer.ID, addr net.Addr) error
```

### AllowBandwidth() - Check bandwidth limit

```go
// AllowBandwidth checks if bandwidth usage is allowed
// Parameters:
//   - p: Peer ID using bandwidth
//   - bytes: Number of bytes to transfer
// Returns:
//   - error: Bandwidth limit error if exceeded
func (rl *RateLimiter) AllowBandwidth(p peer.ID, bytes int64) error
```

### AllowRequest() - Check API rate limit

```go
// AllowRequest checks if an API request is allowed
// Parameters:
//   - p: Peer ID making request
//   - endpoint: API endpoint being called
// Returns:
//   - error: Rate limit error if exceeded
func (rl *RateLimiter) AllowRequest(p peer.ID, endpoint string) error
```

### BlockPeer() - Block a peer

```go
// BlockPeer blocks a peer for a duration
// Parameters:
//   - p: Peer ID to block
//   - duration: How long to block
//   - reason: Reason for blocking
func (rl *RateLimiter) BlockPeer(p peer.ID, duration time.Duration, reason string)
```

## 5. Configuration

### Configuration Structure

```go
// pkg/ratelimit/config.go
package ratelimit

import "time"

// DefaultConfig returns production-ready configuration
func DefaultConfig() *Config {
    return &Config{
        // Connection limits
        MaxConnectionsPerPeer: 10,
        MaxConnectionsPerIP:   50,
        ConnectionsPerSecond:  10,
        ConnectionBurstSize:   20,
        
        // Bandwidth limits (10MB/s global, 1MB/s per peer)
        MaxBytesPerSecond:  10 * 1024 * 1024,
        MaxBytesPerPeer:    1 * 1024 * 1024,
        BandwidthBurstSize: 5 * 1024 * 1024,
        
        // API limits
        RequestsPerMinute: 600,
        RequestsPerHour:   10000,
        RequestBurstSize:  100,
        
        // Query limits
        QueriesPerSecond:     10,
        QueriesPerMinute:     300,
        QueryComplexityLimit: 1000,
        
        // DDoS protection
        EnableDDoSProtection: true,
        DDoSThresholds: DDoSThresholds{
            SYNPerSecond:     100,
            PacketsPerSecond: 10000,
            BytesPerSecond:   100 * 1024 * 1024,
            ConnectionsPerIP: 100,
            QueryComplexity:  10000,
        },
        
        // Distributed settings
        EnableDistributed: false,
        RedisURL:         "",
        
        // Policy settings
        PolicyUpdateInterval: 5 * time.Minute,
        DynamicAdjustment:   true,
    }
}
```

### YAML Configuration Example

```yaml
# config/ratelimit.yaml
ratelimit:
  # Connection limits
  connections:
    max_per_peer: 10
    max_per_ip: 50
    per_second: 10
    burst_size: 20
    
  # Bandwidth limits
  bandwidth:
    max_global_mbps: 100
    max_peer_mbps: 10
    burst_mb: 50
    
  # API rate limits
  api:
    requests_per_minute: 600
    requests_per_hour: 10000
    burst_size: 100
    endpoints:
      - path: "/api/v1/storage/*"
        rpm: 300
      - path: "/api/v1/compute/*"
        rpm: 100
        
  # Query limits
  queries:
    per_second: 10
    per_minute: 300
    complexity_limit: 1000
    
  # DDoS protection
  ddos:
    enabled: true
    thresholds:
      syn_per_second: 100
      packets_per_second: 10000
      bandwidth_mbps: 100
      connections_per_ip: 100
      
  # Distributed mode
  distributed:
    enabled: true
    redis_url: "redis://localhost:6379/0"
    sync_interval: 1s
    
  # Dynamic adjustment
  dynamic:
    enabled: true
    adjustment_interval: 5m
    metrics_window: 1h
```

### Environment Variables

```bash
# Connection limits
export BLACKHOLE_RATELIMIT_MAX_CONN_PEER=10
export BLACKHOLE_RATELIMIT_MAX_CONN_IP=50
export BLACKHOLE_RATELIMIT_CONN_PER_SEC=10

# Bandwidth limits
export BLACKHOLE_RATELIMIT_MAX_BW_GLOBAL=104857600  # 100MB/s
export BLACKHOLE_RATELIMIT_MAX_BW_PEER=10485760     # 10MB/s

# API limits
export BLACKHOLE_RATELIMIT_API_RPM=600
export BLACKHOLE_RATELIMIT_API_RPH=10000

# DDoS protection
export BLACKHOLE_RATELIMIT_DDOS_ENABLED=true
export BLACKHOLE_RATELIMIT_DDOS_SYN_THRESHOLD=100

# Redis for distributed mode
export BLACKHOLE_RATELIMIT_REDIS_URL="redis://localhost:6379/0"
```

## 6. Testing Requirements

### Unit Tests

```go
// pkg/ratelimit/tests/ratelimit_test.go
package ratelimit_test

import (
    "context"
    "net"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/blackhole/pkg/ratelimit"
)

func TestConnectionRateLimit(t *testing.T) {
    // Create rate limiter
    cfg := ratelimit.DefaultConfig()
    cfg.ConnectionsPerSecond = 5
    cfg.MaxConnectionsPerPeer = 3
    
    rl := setupTestRateLimiter(t, cfg)
    defer rl.Close()
    
    peer1 := generatePeerID("peer1")
    addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
    
    // First 3 connections should succeed
    for i := 0; i < 3; i++ {
        err := rl.AllowConnection(peer1, addr)
        assert.NoError(t, err)
    }
    
    // 4th connection should fail (max per peer)
    err := rl.AllowConnection(peer1, addr)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "too many connections")
}

func TestBandwidthLimit(t *testing.T) {
    cfg := ratelimit.DefaultConfig()
    cfg.MaxBytesPerSecond = 1000
    cfg.MaxBytesPerPeer = 500
    
    rl := setupTestRateLimiter(t, cfg)
    defer rl.Close()
    
    peer1 := generatePeerID("peer1")
    peer2 := generatePeerID("peer2")
    
    // Peer 1 uses 400 bytes - should succeed
    err := rl.AllowBandwidth(peer1, 400)
    assert.NoError(t, err)
    
    // Peer 1 tries 200 more - should fail (exceeds peer limit)
    err = rl.AllowBandwidth(peer1, 200)
    assert.Error(t, err)
    
    // Peer 2 uses 400 bytes - should succeed
    err = rl.AllowBandwidth(peer2, 400)
    assert.NoError(t, err)
    
    // Peer 2 tries 300 more - should fail (exceeds global limit)
    err = rl.AllowBandwidth(peer2, 300)
    assert.Error(t, err)
}

func TestTokenBucket(t *testing.T) {
    // Create bucket with 10 tokens, 5 tokens/sec refill
    bucket := ratelimit.NewTokenBucket(10, 5)
    
    // Use 8 tokens
    assert.True(t, bucket.Allow(8))
    assert.Equal(t, int64(2), bucket.GetAvailable())
    
    // Try to use 5 more - should fail
    assert.False(t, bucket.Allow(5))
    
    // Wait for refill
    time.Sleep(1 * time.Second)
    
    // Should have ~7 tokens now (2 + 5 refilled)
    available := bucket.GetAvailable()
    assert.Greater(t, available, int64(6))
    assert.LessOrEqual(t, available, int64(8))
}

func TestDDoSDetection(t *testing.T) {
    cfg := ratelimit.DefaultConfig()
    cfg.EnableDDoSProtection = true
    cfg.DDoSThresholds.ConnectionsPerIP = 5
    
    rl := setupTestRateLimiter(t, cfg)
    defer rl.Close()
    
    // Simulate connections from same IP
    ip := net.ParseIP("10.0.0.1")
    
    for i := 0; i < 5; i++ {
        peer := generatePeerID(fmt.Sprintf("peer%d", i))
        addr := &net.TCPAddr{IP: ip, Port: 1234 + i}
        err := rl.AllowConnection(peer, addr)
        assert.NoError(t, err)
    }
    
    // 6th connection from same IP should trigger DDoS protection
    peer6 := generatePeerID("peer6")
    addr6 := &net.TCPAddr{IP: ip, Port: 1240}
    err := rl.AllowConnection(peer6, addr6)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "too many connections from IP")
}

func TestPeerBlocking(t *testing.T) {
    rl := setupTestRateLimiter(t, ratelimit.DefaultConfig())
    defer rl.Close()
    
    peer1 := generatePeerID("peer1")
    addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
    
    // Block peer
    rl.BlockPeer(peer1, 100*time.Millisecond, "test")
    
    // Connection should fail
    err := rl.AllowConnection(peer1, addr)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "blocked")
    
    // Wait for unblock
    time.Sleep(150 * time.Millisecond)
    
    // Connection should succeed now
    err = rl.AllowConnection(peer1, addr)
    assert.NoError(t, err)
}

func TestAPIRateLimit(t *testing.T) {
    cfg := ratelimit.DefaultConfig()
    cfg.RequestsPerMinute = 60
    
    rl := setupTestRateLimiter(t, cfg)
    defer rl.Close()
    
    peer1 := generatePeerID("peer1")
    
    // Make 60 requests rapidly
    for i := 0; i < 60; i++ {
        err := rl.AllowRequest(peer1, "/api/v1/test")
        assert.NoError(t, err)
    }
    
    // 61st request should fail
    err := rl.AllowRequest(peer1, "/api/v1/test")
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "rate limit exceeded")
}
```

### Integration Tests

```go
// pkg/ratelimit/tests/integration_test.go
package ratelimit_test

import (
    "context"
    "sync"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestConcurrentRateLimiting(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    cfg := ratelimit.DefaultConfig()
    cfg.ConnectionsPerSecond = 100
    cfg.MaxConnectionsPerPeer = 10
    
    rl := setupTestRateLimiter(t, cfg)
    defer rl.Close()
    
    // Simulate concurrent connections from multiple peers
    numPeers := 20
    connectionsPerPeer := 15
    
    var wg sync.WaitGroup
    errors := make(chan error, numPeers*connectionsPerPeer)
    
    for i := 0; i < numPeers; i++ {
        wg.Add(1)
        go func(peerNum int) {
            defer wg.Done()
            
            peer := generatePeerID(fmt.Sprintf("peer%d", peerNum))
            addr := &net.TCPAddr{
                IP:   net.ParseIP(fmt.Sprintf("10.0.0.%d", peerNum)),
                Port: 1234,
            }
            
            for j := 0; j < connectionsPerPeer; j++ {
                err := rl.AllowConnection(peer, addr)
                if err != nil {
                    errors <- err
                }
                time.Sleep(10 * time.Millisecond)
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Count errors
    errorCount := 0
    for err := range errors {
        if err != nil {
            errorCount++
        }
    }
    
    // Each peer should have ~5 connections rejected
    expectedErrors := numPeers * (connectionsPerPeer - cfg.MaxConnectionsPerPeer)
    assert.InDelta(t, expectedErrors, errorCount, float64(numPeers))
}

func TestDDoSMitigation(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping DDoS test")
    }
    
    cfg := ratelimit.DefaultConfig()
    cfg.EnableDDoSProtection = true
    cfg.DDoSThresholds.PacketsPerSecond = 1000
    
    rl := setupTestRateLimiter(t, cfg)
    defer rl.Close()
    
    // Simulate normal traffic
    normalSource := "normal-client"
    for i := 0; i < 100; i++ {
        err := rl.GetDDoS().CheckTraffic(normalSource, 10, 1024)
        assert.NoError(t, err)
        time.Sleep(10 * time.Millisecond)
    }
    
    // Simulate attack traffic
    attackSource := "attacker"
    attackDetected := false
    
    for i := 0; i < 200; i++ {
        err := rl.GetDDoS().CheckTraffic(attackSource, 2000, 1024*1024)
        if err != nil {
            attackDetected = true
            break
        }
    }
    
    assert.True(t, attackDetected, "DDoS attack should be detected")
    
    // Verify mitigation
    attacks := rl.GetDDoS().GetActiveAttacks()
    assert.Greater(t, len(attacks), 0)
    
    // Mitigate attack
    for _, attack := range attacks {
        err := rl.GetDDoS().MitigateAttack(attack.ID)
        assert.NoError(t, err)
    }
}

func TestDistributedRateLimit(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping distributed test")
    }
    
    // Requires Redis
    cfg := ratelimit.DefaultConfig()
    cfg.EnableDistributed = true
    cfg.RedisURL = "redis://localhost:6379/0"
    cfg.RequestsPerMinute = 100
    
    // Create two rate limiters (simulating two nodes)
    rl1 := setupTestRateLimiter(t, cfg)
    defer rl1.Close()
    
    rl2 := setupTestRateLimiter(t, cfg)
    defer rl2.Close()
    
    peer := generatePeerID("shared-peer")
    
    // Make requests from both nodes
    totalRequests := 0
    
    // Node 1 makes 60 requests
    for i := 0; i < 60; i++ {
        err := rl1.AllowRequest(peer, "/api/test")
        if err == nil {
            totalRequests++
        }
    }
    
    // Node 2 makes 60 requests
    for i := 0; i < 60; i++ {
        err := rl2.AllowRequest(peer, "/api/test")
        if err == nil {
            totalRequests++
        }
    }
    
    // Total should be limited to 100 (not 120)
    assert.LessOrEqual(t, totalRequests, 100)
    assert.Greater(t, totalRequests, 95) // Allow some margin
}
```

### Performance Benchmarks

```go
// pkg/ratelimit/tests/benchmark_test.go
package ratelimit_test

import (
    "fmt"
    "net"
    "testing"
)

func BenchmarkTokenBucket(b *testing.B) {
    bucket := ratelimit.NewTokenBucket(1000, 1000)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        bucket.Allow(1)
    }
}

func BenchmarkConnectionCheck(b *testing.B) {
    rl := setupBenchmarkRateLimiter(b)
    defer rl.Close()
    
    peer := generatePeerID("bench-peer")
    addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        rl.AllowConnection(peer, addr)
    }
}

func BenchmarkConcurrentRateLimit(b *testing.B) {
    rl := setupBenchmarkRateLimiter(b)
    defer rl.Close()
    
    b.RunParallel(func(pb *testing.PB) {
        peer := generatePeerID(fmt.Sprintf("peer-%d", rand.Int()))
        addr := &net.TCPAddr{
            IP:   net.ParseIP(fmt.Sprintf("10.0.%d.%d", rand.Intn(255), rand.Intn(255))),
            Port: 1234,
        }
        
        for pb.Next() {
            rl.AllowConnection(peer, addr)
        }
    })
}

func BenchmarkDDoSDetection(b *testing.B) {
    cfg := ratelimit.DefaultConfig()
    cfg.EnableDDoSProtection = true
    
    rl := setupBenchmarkRateLimiterWithConfig(b, cfg)
    defer rl.Close()
    
    sources := make([]string, 100)
    for i := range sources {
        sources[i] = fmt.Sprintf("source-%d", i)
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        source := sources[i%len(sources)]
        rl.GetDDoS().CheckTraffic(source, 100, 10240)
    }
}
```

## 7. Monitoring & Metrics

### Metrics Implementation

```go
// pkg/ratelimit/metrics.go
package ratelimit

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics tracks rate limiting metrics
type Metrics struct {
    // Connection metrics
    ConnectionsAccepted  prometheus.Counter
    ConnectionsRejected  prometheus.Counter
    RejectionReason      *prometheus.CounterVec
    ActiveConnections    prometheus.Gauge
    
    // Bandwidth metrics
    BytesSent            prometheus.Counter
    BytesReceived        prometheus.Counter
    BandwidthExceeded    prometheus.Counter
    PeerBandwidthExceeded prometheus.Counter
    
    // API metrics
    RequestsAllowed      prometheus.Counter
    RequestsRejected     prometheus.Counter
    RequestsPerEndpoint  *prometheus.CounterVec
    
    // DDoS metrics
    AttacksDetected      *prometheus.CounterVec
    AttacksMitigated     prometheus.Counter
    SuspiciousActivity   prometheus.Counter
    
    // Blocking metrics
    PeersBlocked         prometheus.Counter
    IPsBlocked           prometheus.Counter
    BlockDuration        prometheus.Histogram
    
    // Resource metrics
    LimiterCount         prometheus.Gauge
    MemoryUsage          prometheus.Gauge
}

// NewMetrics creates rate limiting metrics
func NewMetrics() *Metrics {
    return &Metrics{
        ConnectionsAccepted: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_connections_accepted_total",
            Help: "Total connections accepted",
        }),
        
        ConnectionsRejected: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_connections_rejected_total",
            Help: "Total connections rejected",
        }),
        
        RejectionReason: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_rejections_by_reason",
            Help: "Rejections by reason",
        }, []string{"reason"}),
        
        ActiveConnections: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_ratelimit_active_connections",
            Help: "Current active connections",
        }),
        
        BytesSent: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_bytes_sent_total",
            Help: "Total bytes sent",
        }),
        
        BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_bytes_received_total",
            Help: "Total bytes received",
        }),
        
        BandwidthExceeded: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_bandwidth_exceeded_total",
            Help: "Global bandwidth limit exceeded",
        }),
        
        PeerBandwidthExceeded: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_peer_bandwidth_exceeded_total",
            Help: "Peer bandwidth limit exceeded",
        }),
        
        RequestsAllowed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_requests_allowed_total",
            Help: "API requests allowed",
        }),
        
        RequestsRejected: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_requests_rejected_total",
            Help: "API requests rejected",
        }),
        
        RequestsPerEndpoint: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_requests_by_endpoint",
            Help: "Requests by endpoint",
        }, []string{"endpoint"}),
        
        AttacksDetected: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_attacks_detected_total",
            Help: "Attacks detected by type",
        }, []string{"type"}),
        
        AttacksMitigated: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_attacks_mitigated_total",
            Help: "Attacks successfully mitigated",
        }),
        
        SuspiciousActivity: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_suspicious_activity_total",
            Help: "Suspicious activity detected",
        }),
        
        PeersBlocked: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_peers_blocked_total",
            Help: "Peers blocked",
        }),
        
        IPsBlocked: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_ratelimit_ips_blocked_total",
            Help: "IPs blocked",
        }),
        
        BlockDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_ratelimit_block_duration_seconds",
            Help:    "Block duration in seconds",
            Buckets: prometheus.ExponentialBuckets(60, 2, 10),
        }),
        
        LimiterCount: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_ratelimit_active_limiters",
            Help: "Number of active rate limiters",
        }),
        
        MemoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_ratelimit_memory_bytes",
            Help: "Memory usage in bytes",
        }),
    }
}
```

### Monitoring Dashboard

```yaml
# Grafana dashboard configuration
panels:
  - title: "Connection Rate"
    queries:
      - "rate(blackhole_ratelimit_connections_accepted_total[5m])"
      - "rate(blackhole_ratelimit_connections_rejected_total[5m])"
      
  - title: "Rejection Reasons"
    query: "rate(blackhole_ratelimit_rejections_by_reason[5m])"
    legend: "{{reason}}"
    
  - title: "Bandwidth Usage"
    queries:
      - "rate(blackhole_ratelimit_bytes_sent_total[5m])"
      - "rate(blackhole_ratelimit_bytes_received_total[5m])"
      
  - title: "API Request Rate"
    queries:
      - "rate(blackhole_ratelimit_requests_allowed_total[5m])"
      - "rate(blackhole_ratelimit_requests_rejected_total[5m])"
      
  - title: "DDoS Detection"
    query: "rate(blackhole_ratelimit_attacks_detected_total[5m])"
    legend: "{{type}}"
    
  - title: "Active Blocks"
    queries:
      - "increase(blackhole_ratelimit_peers_blocked_total[5m])"
      - "increase(blackhole_ratelimit_ips_blocked_total[5m])"
      
  - title: "Resource Usage"
    queries:
      - "blackhole_ratelimit_active_limiters"
      - "blackhole_ratelimit_memory_bytes"
```

## 8. Error Handling

### Error Types

```go
// pkg/ratelimit/errors.go
package ratelimit

import "errors"

var (
    // Connection errors
    ErrTooManyConnections       = errors.New("too many connections")
    ErrTooManyConnectionsFromIP = errors.New("too many connections from IP")
    ErrConnectionRateLimited    = errors.New("connection rate limit exceeded")
    
    // Bandwidth errors
    ErrBandwidthExceeded        = errors.New("bandwidth limit exceeded")
    ErrGlobalBandwidthExceeded  = errors.New("global bandwidth limit exceeded")
    ErrPeerBandwidthExceeded    = errors.New("peer bandwidth limit exceeded")
    
    // API errors
    ErrRateLimitExceeded        = errors.New("rate limit exceeded")
    ErrEndpointRateLimited      = errors.New("endpoint rate limit exceeded")
    ErrQueryComplexityExceeded  = errors.New("query complexity limit exceeded")
    
    // DDoS errors
    ErrSYNFlood                 = errors.New("SYN flood detected")
    ErrPacketFlood              = errors.New("packet flood detected")
    ErrBandwidthFlood           = errors.New("bandwidth flood detected")
    ErrAmplificationAttack      = errors.New("amplification attack detected")
    ErrPatternAttack            = errors.New("attack pattern detected")
    ErrAnomalousTraffic         = errors.New("anomalous traffic detected")
    ErrConnectionFlood          = errors.New("connection flood detected")
    
    // Blocking errors
    ErrPeerBlocked              = errors.New("peer is blocked")
    ErrIPBlocked                = errors.New("IP is blocked")
    
    // Configuration errors
    ErrInvalidConfiguration     = errors.New("invalid rate limit configuration")
    ErrRedisConnectionFailed    = errors.New("redis connection failed")
)
```

## 9. Acceptance Criteria

### Functional Requirements

1. **Rate Limiting**
   - [ ] Connection rate limiting working
   - [ ] Bandwidth throttling functional
   - [ ] API rate limiting operational
   - [ ] Query complexity limiting working

2. **DDoS Protection**
   - [ ] SYN flood detection functional
   - [ ] Pattern-based detection working
   - [ ] Automatic mitigation triggered
   - [ ] Attack metrics recorded

3. **Resource Management**
   - [ ] Per-peer limits enforced
   - [ ] Per-IP limits enforced
   - [ ] Global limits respected
   - [ ] Fair resource allocation

4. **Monitoring**
   - [ ] All metrics exposed
   - [ ] Real-time monitoring possible
   - [ ] Attack alerts generated
   - [ ] Performance impact tracked

### Performance Requirements

1. **Latency Impact**
   - Rate limit check: < 1ms
   - Token bucket operation: < 100μs
   - DDoS detection: < 5ms

2. **Throughput**
   - Handle 100k+ checks/second
   - Support 10k+ concurrent limiters
   - Minimal memory overhead

3. **Scalability**
   - Distributed mode functional
   - Redis sync efficient
   - Horizontal scaling supported

## 10. Example Usage

### Basic Rate Limiting

```go
package main

import (
    "context"
    "log"
    "net"
    
    "github.com/blackhole/pkg/network"
    "github.com/blackhole/pkg/ratelimit"
)

func main() {
    // Create libp2p host
    host, err := network.NewHost(context.Background(), network.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    
    // Create rate limiter
    rlConfig := ratelimit.DefaultConfig()
    rlConfig.MaxConnectionsPerPeer = 5
    rlConfig.MaxBytesPerSecond = 10 * 1024 * 1024 // 10MB/s
    
    rl, err := ratelimit.NewRateLimiter(host, rlConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer rl.Close()
    
    // Use in connection handler
    host.SetStreamHandler("/blackhole/data/1.0.0", func(stream network.Stream) {
        defer stream.Close()
        
        peer := stream.Conn().RemotePeer()
        addr := stream.Conn().RemoteMultiaddr()
        
        // Check connection limit
        if err := rl.AllowConnection(peer, addr); err != nil {
            log.Printf("Connection rejected: %v", err)
            return
        }
        
        // Wrap stream with bandwidth limiting
        throttledStream := rl.WrapStream(stream)
        
        // Handle data transfer
        handleDataTransfer(throttledStream)
    })
    
    log.Printf("Rate-limited host running: %s", host.ID())
    select {}
}
```

### API Rate Limiting

```go
package main

import (
    "net/http"
    
    "github.com/blackhole/pkg/ratelimit"
    "github.com/gorilla/mux"
)

func rateLimitMiddleware(rl *ratelimit.RateLimiter) mux.MiddlewareFunc {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract peer ID from request
            peerID := extractPeerID(r)
            
            // Check rate limit
            endpoint := r.URL.Path
            if err := rl.AllowRequest(peerID, endpoint); err != nil {
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                
                // Add retry header
                w.Header().Set("Retry-After", "60")
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

func main() {
    // Create rate limiter
    rl, err := ratelimit.NewRateLimiter(nil, ratelimit.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    
    // Create router with rate limiting
    router := mux.NewRouter()
    router.Use(rateLimitMiddleware(rl))
    
    // Add routes
    router.HandleFunc("/api/v1/storage", handleStorage).Methods("POST")
    router.HandleFunc("/api/v1/compute", handleCompute).Methods("POST")
    
    log.Fatal(http.ListenAndServe(":8080", router))
}
```

## Summary

Unit U08 implements comprehensive rate limiting and DDoS protection for the Blackhole network. The implementation provides multiple layers of defense including connection limiting, bandwidth throttling, API rate limiting, and sophisticated DDoS detection and mitigation strategies.

Key achievements:
- Multiple rate limiting algorithms (token bucket, sliding window, leaky bucket)
- Comprehensive DDoS protection with automatic mitigation
- Distributed rate limiting support via Redis
- Fine-grained control over resources
- Real-time monitoring and alerting
- Minimal performance impact
- Production-ready scalability

This unit ensures the Blackhole network remains stable and available even under adverse conditions, protecting legitimate users while preventing abuse and attacks.