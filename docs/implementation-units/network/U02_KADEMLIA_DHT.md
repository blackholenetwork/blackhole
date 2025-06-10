# Unit U02: Kademlia DHT Implementation - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U02 implements the Kademlia Distributed Hash Table (DHT) for peer and service discovery in the Blackhole network. This unit provides a decentralized discovery mechanism that enables nodes to find peers and services without relying on centralized infrastructure.

**Primary Goals:**
- Implement Kademlia DHT for peer discovery
- Enable service advertisement and discovery
- Provide content routing capabilities
- Support bootstrap node configuration
- Implement DHT security measures

### Dependencies

- **U01: libp2p Core Setup** - Requires the base libp2p host for network operations

### Deliverables

1. **DHT Configuration and Bootstrap**
   - Kademlia DHT initialization
   - Bootstrap node management
   - Network bootstrapping process

2. **Service Discovery Protocol**
   - Service record format and schema
   - Service registration mechanism
   - Service lookup and resolution

3. **Content Routing**
   - Content provider registration
   - Provider discovery
   - DHT key management

4. **DHT Security**
   - Record validation
   - Signature verification
   - Sybil attack mitigation

### Integration Points

- **U03: NAT Traversal** - DHT assists in peer discovery for NAT traversal
- **U06: Service Discovery Protocol** - Extends DHT for service-specific discovery
- **All Service Units** - Use DHT for service advertisement and discovery

## 2. Technical Specifications

### Kademlia Parameters

```go
// DHT Configuration Parameters
const (
    // K-bucket size (number of peers per bucket)
    KBucketSize = 20
    
    // Alpha - parallel query parameter
    AlphaValue = 3
    
    // Number of closer peers to return
    BetaValue = 20
    
    // DHT query timeout
    QueryTimeout = 60 * time.Second
    
    // Record expiration time
    RecordTTL = 48 * time.Hour
    
    // Provider record expiration
    ProviderTTL = 24 * time.Hour
    
    // Republish interval
    RepublishInterval = 12 * time.Hour
)
```

### DHT Modes

1. **Server Mode** (Full DHT Node)
   - Stores records for other peers
   - Participates in DHT queries
   - Suitable for stable, well-connected nodes

2. **Client Mode** (Light Node)
   - Only stores own records
   - Queries DHT but doesn't serve others
   - Suitable for mobile or resource-constrained nodes

3. **Auto Mode**
   - Dynamically switches between client/server
   - Based on connectivity and resources

### Key Formats

```
# Peer routing keys
/pk/<peer-id>                    # Public key records
/ipns/<peer-id>                  # IPNS records

# Content routing keys
/providers/<content-hash>         # Content providers

# Service discovery keys (Blackhole-specific)
/blackhole/service/<service-type>/<provider-id>
/blackhole/service/<service-type>/all
/blackhole/node/<node-id>/services
/blackhole/node/<node-id>/capacity
```

## 3. Implementation Details

### DHT Initialization

```go
// pkg/network/dht.go
package network

import (
    "context"
    "fmt"
    "time"

    dht "github.com/libp2p/go-libp2p-kad-dht"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/routing"
    "github.com/multiformats/go-multiaddr"
    "github.com/ipfs/go-datastore"
    "github.com/ipfs/go-log/v2"
)

var logger = log.Logger("blackhole:dht")

// DHTService manages the Kademlia DHT
type DHTService struct {
    host       host.Host
    dht        *dht.IpfsDHT
    config     *DHTConfig
    ctx        context.Context
    cancel     context.CancelFunc
    validators map[string]routing.Validator
}

// DHTConfig configures the DHT service
type DHTConfig struct {
    // DHT mode: "server", "client", or "auto"
    Mode string
    
    // Bootstrap nodes
    BootstrapPeers []multiaddr.Multiaddr
    
    // Enable bootstrap on start
    AutoBootstrap bool
    
    // Bootstrap retry configuration
    BootstrapRetries   int
    BootstrapInterval  time.Duration
    
    // DHT parameters
    BucketSize         int
    Concurrency        int
    RefreshInterval    time.Duration
    
    // Datastore for DHT records
    Datastore datastore.Batching
    
    // Custom namespace for service discovery
    ServiceNamespace string
}

// NewDHTService creates a new DHT service
func NewDHTService(ctx context.Context, h host.Host, cfg *DHTConfig) (*DHTService, error) {
    if cfg == nil {
        cfg = DefaultDHTConfig()
    }

    serviceCtx, cancel := context.WithCancel(ctx)
    
    // Configure DHT options
    opts := []dht.Option{
        dht.BucketSize(cfg.BucketSize),
        dht.Concurrency(cfg.Concurrency),
        dht.Datastore(cfg.Datastore),
        dht.ProtocolPrefix("/blackhole"),
    }

    // Set DHT mode
    switch cfg.Mode {
    case "server":
        opts = append(opts, dht.Mode(dht.ModeServer))
    case "client":
        opts = append(opts, dht.Mode(dht.ModeClient))
    default:
        opts = append(opts, dht.Mode(dht.ModeAuto))
    }

    // Create DHT instance
    kadDHT, err := dht.New(serviceCtx, h, opts...)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("failed to create DHT: %w", err)
    }

    service := &DHTService{
        host:       h,
        dht:        kadDHT,
        config:     cfg,
        ctx:        serviceCtx,
        cancel:     cancel,
        validators: make(map[string]routing.Validator),
    }

    // Register validators
    service.registerValidators()

    return service, nil
}

// Start initializes and bootstraps the DHT
func (s *DHTService) Start() error {
    logger.Info("Starting DHT service")

    // Bootstrap the DHT
    if err := s.dht.Bootstrap(s.ctx); err != nil {
        return fmt.Errorf("failed to bootstrap DHT: %w", err)
    }

    // Connect to bootstrap peers
    if s.config.AutoBootstrap {
        go s.bootstrapConnect()
    }

    // Start periodic refresh
    go s.periodicRefresh()

    logger.Info("DHT service started successfully")
    return nil
}

// Stop gracefully shuts down the DHT service
func (s *DHTService) Stop() error {
    logger.Info("Stopping DHT service")
    s.cancel()
    return s.dht.Close()
}

// bootstrapConnect connects to bootstrap peers with retry logic
func (s *DHTService) bootstrapConnect() {
    logger.Info("Connecting to bootstrap peers")
    
    connected := 0
    for attempt := 0; attempt < s.config.BootstrapRetries; attempt++ {
        for _, addr := range s.config.BootstrapPeers {
            peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
            if err != nil {
                logger.Warnf("Invalid bootstrap peer address %s: %v", addr, err)
                continue
            }

            if err := s.connectPeer(peerInfo); err != nil {
                logger.Debugf("Failed to connect to bootstrap peer %s: %v", peerInfo.ID, err)
            } else {
                connected++
                logger.Infof("Connected to bootstrap peer %s", peerInfo.ID)
            }
        }

        if connected >= 3 { // Minimum bootstrap peers
            logger.Info("Successfully connected to bootstrap peers")
            return
        }

        time.Sleep(s.config.BootstrapInterval)
    }

    logger.Warn("Failed to connect to sufficient bootstrap peers")
}

// connectPeer establishes a connection to a peer
func (s *DHTService) connectPeer(peerInfo *peer.AddrInfo) error {
    ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
    defer cancel()

    // Add addresses to peerstore
    s.host.Peerstore().AddAddrs(peerInfo.ID, peerInfo.Addrs, time.Hour)

    // Connect to peer
    if err := s.host.Connect(ctx, *peerInfo); err != nil {
        return err
    }

    // Protect the connection (prevent pruning)
    s.host.ConnManager().Protect(peerInfo.ID, "bootstrap")

    return nil
}

// periodicRefresh performs periodic DHT refresh
func (s *DHTService) periodicRefresh() {
    ticker := time.NewTicker(s.config.RefreshInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := s.dht.RefreshRoutingTable(); err != nil {
                logger.Warnf("Failed to refresh routing table: %v", err)
            }
        case <-s.ctx.Done():
            return
        }
    }
}
```

### Service Discovery Implementation

```go
// pkg/network/service_discovery.go
package network

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/routing"
    "github.com/multiformats/go-multiaddr"
)

// ServiceRecord represents a service advertised in the DHT
type ServiceRecord struct {
    // Service identification
    ServiceID   string    `json:"service_id"`   // e.g., "/blackhole/compute/v1"
    ServiceType string    `json:"service_type"` // e.g., "compute", "storage", "bandwidth"
    Version     string    `json:"version"`      // Service version
    
    // Provider information
    ProviderID  peer.ID              `json:"provider_id"`
    Endpoints   []multiaddr.Multiaddr `json:"endpoints"`
    
    // Service capabilities
    Capacity    ResourceCapacity     `json:"capacity"`
    Available   bool                 `json:"available"`
    
    // Pricing information
    PriceModel  PricingModel        `json:"price_model"`
    
    // Metadata
    Region      string              `json:"region"`
    Reputation  float64             `json:"reputation"`
    Uptime      float64             `json:"uptime"`
    
    // Record metadata
    Timestamp   time.Time           `json:"timestamp"`
    TTL         time.Duration       `json:"ttl"`
    Signature   []byte              `json:"signature"`
}

// ResourceCapacity defines available resources
type ResourceCapacity struct {
    // Compute resources
    CPUCores    int     `json:"cpu_cores"`
    CPUSpeed    float64 `json:"cpu_speed_ghz"`
    GPUs        int     `json:"gpus"`
    GPUModel    string  `json:"gpu_model"`
    MemoryGB    float64 `json:"memory_gb"`
    
    // Storage resources
    StorageGB   float64 `json:"storage_gb"`
    StorageType string  `json:"storage_type"` // "ssd", "hdd"
    IOPS        int     `json:"iops"`
    
    // Network resources
    BandwidthMbps float64 `json:"bandwidth_mbps"`
    MonthlyGB     float64 `json:"monthly_gb"`
}

// PricingModel defines service pricing
type PricingModel struct {
    Currency    string  `json:"currency"`     // "USDC"
    
    // Compute pricing
    CPUHourly   float64 `json:"cpu_hourly"`   // Per core hour
    GPUHourly   float64 `json:"gpu_hourly"`   // Per GPU hour
    MemoryHourly float64 `json:"memory_hourly"` // Per GB hour
    
    // Storage pricing
    StorageMonthly float64 `json:"storage_monthly"` // Per GB month
    
    // Bandwidth pricing
    BandwidthGB float64 `json:"bandwidth_gb"`   // Per GB transferred
    
    // Minimum commitment
    MinimumHours int `json:"minimum_hours"`
}

// RegisterService advertises a service in the DHT
func (s *DHTService) RegisterService(ctx context.Context, record *ServiceRecord) error {
    // Validate record
    if err := s.validateServiceRecord(record); err != nil {
        return fmt.Errorf("invalid service record: %w", err)
    }

    // Sign the record
    if err := s.signServiceRecord(record); err != nil {
        return fmt.Errorf("failed to sign record: %w", err)
    }

    // Marshal record
    data, err := json.Marshal(record)
    if err != nil {
        return fmt.Errorf("failed to marshal record: %w", err)
    }

    // Generate DHT keys
    keys := s.generateServiceKeys(record)

    // Store in DHT
    for _, key := range keys {
        if err := s.dht.PutValue(ctx, key, data); err != nil {
            logger.Warnf("Failed to store service record at key %s: %v", key, err)
        } else {
            logger.Infof("Registered service %s at key %s", record.ServiceID, key)
        }
    }

    // Schedule periodic republishing
    go s.scheduleRepublish(record)

    return nil
}

// FindServices discovers services of a specific type
func (s *DHTService) FindServices(ctx context.Context, serviceType string) ([]*ServiceRecord, error) {
    key := fmt.Sprintf("/blackhole/service/%s/all", serviceType)
    
    // Search DHT
    value, err := s.dht.GetValue(ctx, key)
    if err != nil {
        return nil, fmt.Errorf("failed to find services: %w", err)
    }

    // Parse service list
    var serviceIDs []string
    if err := json.Unmarshal(value, &serviceIDs); err != nil {
        return nil, fmt.Errorf("failed to parse service list: %w", err)
    }

    // Fetch individual service records
    var services []*ServiceRecord
    for _, id := range serviceIDs {
        record, err := s.GetServiceRecord(ctx, id)
        if err != nil {
            logger.Warnf("Failed to fetch service %s: %v", id, err)
            continue
        }
        services = append(services, record)
    }

    return services, nil
}

// GetServiceRecord retrieves a specific service record
func (s *DHTService) GetServiceRecord(ctx context.Context, serviceID string) (*ServiceRecord, error) {
    key := fmt.Sprintf("/blackhole/service/%s", serviceID)
    
    value, err := s.dht.GetValue(ctx, key)
    if err != nil {
        return nil, fmt.Errorf("service not found: %w", err)
    }

    var record ServiceRecord
    if err := json.Unmarshal(value, &record); err != nil {
        return nil, fmt.Errorf("failed to parse service record: %w", err)
    }

    // Verify signature
    if err := s.verifyServiceRecord(&record); err != nil {
        return nil, fmt.Errorf("invalid service record signature: %w", err)
    }

    return &record, nil
}

// generateServiceKeys creates DHT keys for service discovery
func (s *DHTService) generateServiceKeys(record *ServiceRecord) []string {
    return []string{
        // Primary service key
        fmt.Sprintf("/blackhole/service/%s/%s", record.ServiceType, record.ProviderID),
        
        // Service type index
        fmt.Sprintf("/blackhole/service/%s/all", record.ServiceType),
        
        // Provider services index
        fmt.Sprintf("/blackhole/node/%s/services", record.ProviderID),
        
        // Regional index
        fmt.Sprintf("/blackhole/service/%s/region/%s", record.ServiceType, record.Region),
    }
}

// validateServiceRecord ensures the record is valid
func (s *DHTService) validateServiceRecord(record *ServiceRecord) error {
    if record.ServiceID == "" {
        return fmt.Errorf("service ID required")
    }
    if record.ServiceType == "" {
        return fmt.Errorf("service type required")
    }
    if record.ProviderID == "" {
        return fmt.Errorf("provider ID required")
    }
    if len(record.Endpoints) == 0 {
        return fmt.Errorf("at least one endpoint required")
    }
    if record.TTL == 0 {
        record.TTL = RecordTTL
    }
    record.Timestamp = time.Now()
    return nil
}

// signServiceRecord signs the record with the provider's private key
func (s *DHTService) signServiceRecord(record *ServiceRecord) error {
    // Prepare record for signing (exclude signature field)
    record.Signature = nil
    data, err := json.Marshal(record)
    if err != nil {
        return err
    }

    // Sign with host's private key
    sig, err := s.host.Peerstore().PrivKey(s.host.ID()).Sign(data)
    if err != nil {
        return err
    }

    record.Signature = sig
    return nil
}

// verifyServiceRecord verifies the record signature
func (s *DHTService) verifyServiceRecord(record *ServiceRecord) error {
    // Get provider's public key
    pubKey, err := record.ProviderID.ExtractPublicKey()
    if err != nil {
        // Try to fetch from DHT
        pubKey, err = s.getPublicKey(record.ProviderID)
        if err != nil {
            return fmt.Errorf("failed to get provider public key: %w", err)
        }
    }

    // Prepare record for verification
    sig := record.Signature
    record.Signature = nil
    data, err := json.Marshal(record)
    if err != nil {
        return err
    }
    record.Signature = sig

    // Verify signature
    valid, err := pubKey.Verify(data, sig)
    if err != nil {
        return err
    }
    if !valid {
        return fmt.Errorf("invalid signature")
    }

    return nil
}

// scheduleRepublish periodically republishes the service record
func (s *DHTService) scheduleRepublish(record *ServiceRecord) {
    ticker := time.NewTicker(RepublishInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
            if err := s.RegisterService(ctx, record); err != nil {
                logger.Warnf("Failed to republish service %s: %v", record.ServiceID, err)
            }
            cancel()
        case <-s.ctx.Done():
            return
        }
    }
}
```

### Content Routing

```go
// pkg/network/content_routing.go
package network

import (
    "context"
    "fmt"
    
    "github.com/ipfs/go-cid"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/routing"
)

// ContentRouter provides content routing functionality
type ContentRouter struct {
    dht *DHTService
}

// Provide announces that this node can provide the given content
func (cr *ContentRouter) Provide(ctx context.Context, c cid.Cid, announce bool) error {
    if !announce {
        return nil
    }

    logger.Infof("Announcing content %s", c)
    return cr.dht.dht.Provide(ctx, c, true)
}

// FindProvidersAsync searches for peers who can provide the content
func (cr *ContentRouter) FindProvidersAsync(ctx context.Context, c cid.Cid, limit int) <-chan peer.AddrInfo {
    logger.Infof("Finding providers for %s", c)
    return cr.dht.dht.FindProvidersAsync(ctx, c, limit)
}

// ProvideMany announces multiple content items efficiently
func (cr *ContentRouter) ProvideMany(ctx context.Context, cids []cid.Cid) error {
    for _, c := range cids {
        if err := cr.Provide(ctx, c, true); err != nil {
            logger.Warnf("Failed to provide %s: %v", c, err)
        }
    }
    return nil
}

// FindPeer searches for a specific peer's addresses
func (cr *ContentRouter) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {
    logger.Debugf("Finding peer %s", p)
    return cr.dht.dht.FindPeer(ctx, p)
}
```

### DHT Security and Validation

```go
// pkg/network/dht_security.go
package network

import (
    "bytes"
    "fmt"
    
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/routing"
    record "github.com/libp2p/go-libp2p-record"
)

// registerValidators sets up record validators for security
func (s *DHTService) registerValidators() {
    // Service record validator
    s.dht.Validator.RegisterValidator("/blackhole/service/", &serviceValidator{dht: s})
    
    // Node capacity validator
    s.dht.Validator.RegisterValidator("/blackhole/node/", &nodeValidator{dht: s})
    
    // Custom namespace validator
    if s.config.ServiceNamespace != "" {
        namespace := fmt.Sprintf("/%s/", s.config.ServiceNamespace)
        s.dht.Validator.RegisterValidator(namespace, &namespaceValidator{
            namespace: namespace,
            dht: s,
        })
    }
}

// serviceValidator validates service records
type serviceValidator struct {
    dht *DHTService
}

func (v *serviceValidator) Validate(key string, value []byte) error {
    var record ServiceRecord
    if err := json.Unmarshal(value, &record); err != nil {
        return fmt.Errorf("invalid service record format: %w", err)
    }

    // Verify signature
    if err := v.dht.verifyServiceRecord(&record); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }

    // Check TTL
    if time.Since(record.Timestamp) > record.TTL {
        return fmt.Errorf("record expired")
    }

    // Validate capacity claims
    if err := v.validateCapacity(&record.Capacity); err != nil {
        return fmt.Errorf("invalid capacity claims: %w", err)
    }

    return nil
}

func (v *serviceValidator) Select(key string, values [][]byte) (int, error) {
    // Select the most recent valid record
    var bestIdx int
    var bestTime time.Time

    for i, val := range values {
        var record ServiceRecord
        if err := json.Unmarshal(val, &record); err != nil {
            continue
        }

        if err := v.Validate(key, val); err != nil {
            continue
        }

        if record.Timestamp.After(bestTime) {
            bestIdx = i
            bestTime = record.Timestamp
        }
    }

    return bestIdx, nil
}

// validateCapacity ensures capacity claims are reasonable
func (v *serviceValidator) validateCapacity(cap *ResourceCapacity) error {
    // Sanity checks
    if cap.CPUCores < 0 || cap.CPUCores > 1000 {
        return fmt.Errorf("unreasonable CPU core count")
    }
    if cap.MemoryGB < 0 || cap.MemoryGB > 10000 {
        return fmt.Errorf("unreasonable memory size")
    }
    if cap.StorageGB < 0 || cap.StorageGB > 1000000 {
        return fmt.Errorf("unreasonable storage size")
    }
    if cap.BandwidthMbps < 0 || cap.BandwidthMbps > 100000 {
        return fmt.Errorf("unreasonable bandwidth")
    }
    return nil
}

// RateLimiter implements per-peer rate limiting
type RateLimiter struct {
    requests map[peer.ID]*rateLimitInfo
    mu       sync.RWMutex
}

type rateLimitInfo struct {
    count     int
    resetTime time.Time
}

func (rl *RateLimiter) Allow(p peer.ID) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    now := time.Now()
    info, exists := rl.requests[p]
    
    if !exists || now.After(info.resetTime) {
        rl.requests[p] = &rateLimitInfo{
            count:     1,
            resetTime: now.Add(time.Minute),
        }
        return true
    }

    if info.count >= 100 { // 100 requests per minute
        return false
    }

    info.count++
    return true
}

// SybilDetector detects potential Sybil attacks
type SybilDetector struct {
    dht      *DHTService
    suspects map[peer.ID]int
    mu       sync.RWMutex
}

func (sd *SybilDetector) CheckPeer(p peer.ID) bool {
    sd.mu.RLock()
    suspicionLevel := sd.suspects[p]
    sd.mu.RUnlock()

    if suspicionLevel > 5 {
        logger.Warnf("Peer %s suspected of Sybil attack", p)
        return false
    }

    // Check for suspicious patterns
    if sd.isSuspicious(p) {
        sd.mu.Lock()
        sd.suspects[p]++
        sd.mu.Unlock()
    }

    return true
}

func (sd *SybilDetector) isSuspicious(p peer.ID) bool {
    // Check for rapid ID generation
    // Check for similar ID patterns
    // Check for coordinated behavior
    // Implementation depends on specific attack patterns
    return false
}
```

### Metrics and Monitoring

```go
// pkg/network/dht_metrics.go
package network

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// DHTMetrics tracks DHT performance
type DHTMetrics struct {
    // Routing table metrics
    RoutingTableSize    prometheus.Gauge
    BucketCount         prometheus.Gauge
    
    // Query metrics
    QueriesTotal        prometheus.Counter
    QueriesSuccess      prometheus.Counter
    QueriesFailed       prometheus.Counter
    QueryDuration       prometheus.Histogram
    
    // Service discovery metrics
    ServicesRegistered  prometheus.Gauge
    ServiceLookups      prometheus.Counter
    ServiceHits         prometheus.Counter
    ServiceMisses       prometheus.Counter
    
    // Content routing metrics
    ProvidesAnnounced   prometheus.Counter
    ProviderSearches    prometheus.Counter
    
    // Network metrics
    MessagesReceived    *prometheus.CounterVec
    MessagesSent        *prometheus.CounterVec
    
    // Security metrics
    ValidationFailures  prometheus.Counter
    RateLimitHits       prometheus.Counter
    SuspiciousPeers     prometheus.Gauge
}

// NewDHTMetrics creates DHT metrics
func NewDHTMetrics(namespace string) *DHTMetrics {
    return &DHTMetrics{
        RoutingTableSize: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "dht_routing_table_size",
            Help:      "Number of peers in routing table",
        }),
        
        BucketCount: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "dht_bucket_count",
            Help:      "Number of k-buckets",
        }),
        
        QueriesTotal: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_queries_total",
            Help:      "Total DHT queries",
        }),
        
        QueriesSuccess: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_queries_success_total",
            Help:      "Successful DHT queries",
        }),
        
        QueriesFailed: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_queries_failed_total",
            Help:      "Failed DHT queries",
        }),
        
        QueryDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Namespace: namespace,
            Name:      "dht_query_duration_seconds",
            Help:      "DHT query duration",
            Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
        }),
        
        ServicesRegistered: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "dht_services_registered",
            Help:      "Number of services registered",
        }),
        
        ServiceLookups: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_service_lookups_total",
            Help:      "Total service lookups",
        }),
        
        ServiceHits: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_service_hits_total",
            Help:      "Service lookup hits",
        }),
        
        ServiceMisses: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_service_misses_total",
            Help:      "Service lookup misses",
        }),
        
        MessagesReceived: promauto.NewCounterVec(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_messages_received_total",
            Help:      "DHT messages received by type",
        }, []string{"message_type"}),
        
        MessagesSent: promauto.NewCounterVec(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "dht_messages_sent_total",
            Help:      "DHT messages sent by type",
        }, []string{"message_type"}),
    }
}
```

## 4. Configuration

### DHT Configuration Structure

```go
// pkg/network/dht_config.go
package network

import (
    "time"
    "github.com/ipfs/go-datastore"
    ds_sync "github.com/ipfs/go-datastore/sync"
)

// DefaultDHTConfig returns default DHT configuration
func DefaultDHTConfig() *DHTConfig {
    return &DHTConfig{
        Mode:          "auto",
        AutoBootstrap: true,
        
        BootstrapPeers: []multiaddr.Multiaddr{
            // Blackhole bootstrap nodes
            multiaddr.StringCast("/dnsaddr/bootstrap1.blackhole.network/p2p/QmBootstrap1..."),
            multiaddr.StringCast("/dnsaddr/bootstrap2.blackhole.network/p2p/QmBootstrap2..."),
            multiaddr.StringCast("/dnsaddr/bootstrap3.blackhole.network/p2p/QmBootstrap3..."),
            
            // IPFS bootstrap nodes as fallback
            multiaddr.StringCast("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
            multiaddr.StringCast("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
        },
        
        BootstrapRetries:  5,
        BootstrapInterval: 30 * time.Second,
        
        BucketSize:      20,
        Concurrency:     10,
        RefreshInterval: 1 * time.Hour,
        
        Datastore: ds_sync.MutexWrap(datastore.NewMapDatastore()),
        
        ServiceNamespace: "blackhole",
    }
}

// ProductionDHTConfig returns production-optimized configuration
func ProductionDHTConfig() *DHTConfig {
    cfg := DefaultDHTConfig()
    cfg.Mode = "server" // Full DHT node in production
    cfg.BucketSize = 20
    cfg.Concurrency = 50 // Higher concurrency for production
    cfg.RefreshInterval = 30 * time.Minute
    return cfg
}

// MobileDHTConfig returns mobile-optimized configuration
func MobileDHTConfig() *DHTConfig {
    cfg := DefaultDHTConfig()
    cfg.Mode = "client" // Light client mode
    cfg.BucketSize = 10 // Smaller routing table
    cfg.Concurrency = 3  // Lower concurrency
    cfg.RefreshInterval = 2 * time.Hour
    return cfg
}
```

### YAML Configuration

```yaml
# config/dht.yaml
dht:
  # DHT mode: server, client, or auto
  mode: auto
  
  # Bootstrap configuration
  bootstrap:
    enabled: true
    retries: 5
    interval: 30s
    peers:
      - "/dnsaddr/bootstrap1.blackhole.network/p2p/QmBootstrap1..."
      - "/dnsaddr/bootstrap2.blackhole.network/p2p/QmBootstrap2..."
      - "/dnsaddr/bootstrap3.blackhole.network/p2p/QmBootstrap3..."
  
  # DHT parameters
  parameters:
    bucket_size: 20
    concurrency: 10
    refresh_interval: 1h
    query_timeout: 60s
  
  # Record TTL settings
  ttl:
    record: 48h
    provider: 24h
    republish: 12h
  
  # Service discovery
  service_discovery:
    namespace: "blackhole"
    max_services_per_peer: 10
    service_timeout: 5m
  
  # Security settings
  security:
    validate_records: true
    rate_limit_per_minute: 100
    sybil_detection: true
```

## 5. Testing Requirements

### Unit Tests

```go
// pkg/network/dht_test.go
package network_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/libp2p/go-libp2p"
    "github.com/libp2p/go-libp2p/core/peer"
)

func TestDHTBootstrap(t *testing.T) {
    ctx := context.Background()
    
    // Create test hosts
    h1, _ := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
    defer h1.Close()
    
    h2, _ := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
    defer h2.Close()
    
    // Create DHT instances
    cfg1 := DefaultDHTConfig()
    cfg1.Mode = "server"
    dht1, err := NewDHTService(ctx, h1, cfg1)
    require.NoError(t, err)
    defer dht1.Stop()
    
    cfg2 := DefaultDHTConfig()
    cfg2.BootstrapPeers = []multiaddr.Multiaddr{
        h1.Addrs()[0].Encapsulate(multiaddr.StringCast("/p2p/" + h1.ID().String())),
    }
    dht2, err := NewDHTService(ctx, h2, cfg2)
    require.NoError(t, err)
    defer dht2.Stop()
    
    // Start DHTs
    require.NoError(t, dht1.Start())
    require.NoError(t, dht2.Start())
    
    // Wait for bootstrap
    time.Sleep(2 * time.Second)
    
    // Verify connection
    assert.Eventually(t, func() bool {
        return h2.Network().Connectedness(h1.ID()) == network.Connected
    }, 5*time.Second, 100*time.Millisecond)
}

func TestServiceDiscovery(t *testing.T) {
    ctx := context.Background()
    
    // Setup test network
    hosts, dhts := createTestNetwork(t, 3)
    defer cleanupTestNetwork(hosts, dhts)
    
    // Create service record
    record := &ServiceRecord{
        ServiceID:   "/blackhole/compute/v1",
        ServiceType: "compute",
        Version:     "1.0.0",
        ProviderID:  hosts[0].ID(),
        Endpoints:   hosts[0].Addrs(),
        Capacity: ResourceCapacity{
            CPUCores:  8,
            MemoryGB:  16,
            StorageGB: 100,
        },
        Available: true,
        PriceModel: PricingModel{
            Currency:  "USDC",
            CPUHourly: 0.10,
        },
        Region:     "us-east",
        Reputation: 0.95,
        Uptime:     0.99,
    }
    
    // Register service
    err := dhts[0].RegisterService(ctx, record)
    require.NoError(t, err)
    
    // Wait for propagation
    time.Sleep(2 * time.Second)
    
    // Find service from another node
    services, err := dhts[1].FindServices(ctx, "compute")
    require.NoError(t, err)
    assert.Len(t, services, 1)
    assert.Equal(t, record.ServiceID, services[0].ServiceID)
}

func TestContentRouting(t *testing.T) {
    ctx := context.Background()
    
    // Setup test network
    hosts, dhts := createTestNetwork(t, 3)
    defer cleanupTestNetwork(hosts, dhts)
    
    // Create content router
    router := &ContentRouter{dht: dhts[0]}
    
    // Announce content
    testCID := generateTestCID(t, []byte("test content"))
    err := router.Provide(ctx, testCID, true)
    require.NoError(t, err)
    
    // Find providers from another node
    router2 := &ContentRouter{dht: dhts[1]}
    providers := router2.FindProvidersAsync(ctx, testCID, 10)
    
    // Verify provider found
    var found bool
    for p := range providers {
        if p.ID == hosts[0].ID() {
            found = true
            break
        }
    }
    assert.True(t, found, "Provider not found")
}

func TestDHTSecurity(t *testing.T) {
    ctx := context.Background()
    
    // Create malicious service record
    h, _ := libp2p.New()
    defer h.Close()
    
    cfg := DefaultDHTConfig()
    dht, _ := NewDHTService(ctx, h, cfg)
    defer dht.Stop()
    
    // Invalid record (wrong signature)
    record := &ServiceRecord{
        ServiceID:   "malicious",
        ServiceType: "compute",
        ProviderID:  peer.ID("invalid"),
        Signature:   []byte("invalid signature"),
    }
    
    // Should fail validation
    err := dht.RegisterService(ctx, record)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "invalid")
}

// Helper functions
func createTestNetwork(t *testing.T, n int) ([]host.Host, []*DHTService) {
    ctx := context.Background()
    hosts := make([]host.Host, n)
    dhts := make([]*DHTService, n)
    
    // Create bootstrap node
    hosts[0], _ = libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
    cfg0 := DefaultDHTConfig()
    cfg0.Mode = "server"
    dhts[0], _ = NewDHTService(ctx, hosts[0], cfg0)
    dhts[0].Start()
    
    // Create other nodes
    for i := 1; i < n; i++ {
        hosts[i], _ = libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
        
        cfg := DefaultDHTConfig()
        cfg.BootstrapPeers = []multiaddr.Multiaddr{
            hosts[0].Addrs()[0].Encapsulate(
                multiaddr.StringCast("/p2p/" + hosts[0].ID().String()),
            ),
        }
        
        dhts[i], _ = NewDHTService(ctx, hosts[i], cfg)
        dhts[i].Start()
    }
    
    // Wait for network to stabilize
    time.Sleep(3 * time.Second)
    
    return hosts, dhts
}

func cleanupTestNetwork(hosts []host.Host, dhts []*DHTService) {
    for _, dht := range dhts {
        dht.Stop()
    }
    for _, h := range hosts {
        h.Close()
    }
}
```

### Integration Tests

```go
// pkg/network/dht_integration_test.go
package network_test

import (
    "context"
    "sync"
    "testing"
    "time"
)

func TestDHTScalability(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping scalability test in short mode")
    }
    
    ctx := context.Background()
    nodeCount := 50
    
    // Create network
    hosts, dhts := createTestNetwork(t, nodeCount)
    defer cleanupTestNetwork(hosts, dhts)
    
    // Register services concurrently
    var wg sync.WaitGroup
    for i := 0; i < nodeCount; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            
            record := &ServiceRecord{
                ServiceID:   fmt.Sprintf("/blackhole/compute/node%d", idx),
                ServiceType: "compute",
                ProviderID:  hosts[idx].ID(),
                Endpoints:   hosts[idx].Addrs(),
                Available:   true,
            }
            
            err := dhts[idx].RegisterService(ctx, record)
            assert.NoError(t, err)
        }(i)
    }
    
    wg.Wait()
    time.Sleep(5 * time.Second)
    
    // Query from random nodes
    for i := 0; i < 10; i++ {
        services, err := dhts[rand.Intn(nodeCount)].FindServices(ctx, "compute")
        require.NoError(t, err)
        assert.GreaterOrEqual(t, len(services), nodeCount/2) // At least half visible
    }
}

func TestDHTChurn(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping churn test in short mode")
    }
    
    ctx := context.Background()
    
    // Start with stable network
    hosts, dhts := createTestNetwork(t, 10)
    
    // Register initial services
    for i := 0; i < 5; i++ {
        record := &ServiceRecord{
            ServiceID:   fmt.Sprintf("service-%d", i),
            ServiceType: "storage",
            ProviderID:  hosts[i].ID(),
            Endpoints:   hosts[i].Addrs(),
        }
        dhts[i].RegisterService(ctx, record)
    }
    
    // Simulate node churn
    for round := 0; round < 5; round++ {
        // Stop random node
        idx := rand.Intn(len(dhts))
        dhts[idx].Stop()
        hosts[idx].Close()
        
        // Start new node
        h, _ := libp2p.New()
        cfg := DefaultDHTConfig()
        cfg.BootstrapPeers = []multiaddr.Multiaddr{
            hosts[(idx+1)%len(hosts)].Addrs()[0],
        }
        dht, _ := NewDHTService(ctx, h, cfg)
        dht.Start()
        
        hosts[idx] = h
        dhts[idx] = dht
        
        time.Sleep(2 * time.Second)
        
        // Verify services still discoverable
        services, err := dhts[(idx+2)%len(dhts)].FindServices(ctx, "storage")
        require.NoError(t, err)
        assert.NotEmpty(t, services)
    }
    
    cleanupTestNetwork(hosts, dhts)
}
```

### Performance Benchmarks

```go
// pkg/network/dht_benchmark_test.go
package network_test

func BenchmarkDHTLookup(b *testing.B) {
    ctx := context.Background()
    hosts, dhts := createTestNetwork(b, 20)
    defer cleanupTestNetwork(hosts, dhts)
    
    // Populate DHT
    for i := 0; i < 100; i++ {
        record := &ServiceRecord{
            ServiceID:   fmt.Sprintf("service-%d", i),
            ServiceType: "compute",
            ProviderID:  hosts[i%len(hosts)].ID(),
        }
        dhts[i%len(dhts)].RegisterService(ctx, record)
    }
    
    time.Sleep(3 * time.Second)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        serviceID := fmt.Sprintf("service-%d", i%100)
        dhts[i%len(dhts)].GetServiceRecord(ctx, serviceID)
    }
}

func BenchmarkDHTProvide(b *testing.B) {
    ctx := context.Background()
    hosts, dhts := createTestNetwork(b, 10)
    defer cleanupTestNetwork(hosts, dhts)
    
    router := &ContentRouter{dht: dhts[0]}
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        cid := generateTestCID(b, []byte(fmt.Sprintf("content-%d", i)))
        router.Provide(ctx, cid, true)
    }
}
```

## 6. Monitoring & Observability

### Grafana Dashboard Queries

```yaml
# DHT Health Dashboard
panels:
  - title: "Routing Table Size"
    query: "blackhole_dht_routing_table_size"
    
  - title: "DHT Query Success Rate"
    query: |
      rate(blackhole_dht_queries_success_total[5m]) /
      rate(blackhole_dht_queries_total[5m])
    
  - title: "Query Latency (p95)"
    query: |
      histogram_quantile(0.95,
        rate(blackhole_dht_query_duration_seconds_bucket[5m])
      )
    
  - title: "Service Discovery Hit Rate"
    query: |
      rate(blackhole_dht_service_hits_total[5m]) /
      (rate(blackhole_dht_service_hits_total[5m]) + 
       rate(blackhole_dht_service_misses_total[5m]))
    
  - title: "Active Services by Type"
    query: "blackhole_dht_services_registered"
    
  - title: "DHT Message Rate"
    query: "sum by (message_type) (rate(blackhole_dht_messages_received_total[5m]))"
```

## 7. Acceptance Criteria

### Functional Requirements

1. **DHT Operations**
   - [ ] Successful bootstrap to network
   - [ ] Peer discovery functional
   - [ ] Content routing operational
   - [ ] Service discovery working

2. **Service Discovery**
   - [ ] Service registration successful
   - [ ] Service lookup returns results
   - [ ] Regional discovery functional
   - [ ] Service updates propagate

3. **Security**
   - [ ] Record signatures verified
   - [ ] Invalid records rejected
   - [ ] Rate limiting enforced
   - [ ] Sybil detection active

4. **Performance**
   - [ ] < 1s average lookup time
   - [ ] > 95% query success rate
   - [ ] Handles 100+ services per node
   - [ ] Scales to 1000+ nodes

### Non-Functional Requirements

1. **Reliability**
   - Survives 20% node churn
   - Automatic republishing works
   - Bootstrap recovery functional

2. **Efficiency**
   - Low bandwidth overhead
   - Efficient routing table management
   - Minimal redundant queries

## 8. Example Usage

### Starting DHT Service

```go
package main

import (
    "context"
    "log"
    
    "github.com/blackhole/pkg/network"
)

func main() {
    ctx := context.Background()
    
    // Create libp2p host (from U01)
    host, err := network.NewHost(ctx, network.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    defer host.Stop()
    
    // Create DHT service
    dhtConfig := network.DefaultDHTConfig()
    dht, err := network.NewDHTService(ctx, host, dhtConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer dht.Stop()
    
    // Start DHT
    if err := dht.Start(); err != nil {
        log.Fatal(err)
    }
    
    log.Println("DHT service started successfully")
    
    // Keep running
    select {}
}
```

### Registering a Service

```go
func registerComputeService(dht *network.DHTService) error {
    ctx := context.Background()
    
    record := &network.ServiceRecord{
        ServiceID:   "/blackhole/compute/v1",
        ServiceType: "compute",
        Version:     "1.0.0",
        ProviderID:  dht.host.ID(),
        Endpoints:   dht.host.Addrs(),
        
        Capacity: network.ResourceCapacity{
            CPUCores:  16,
            CPUSpeed:  3.5,
            MemoryGB:  32,
            GPUs:      2,
            GPUModel:  "NVIDIA RTX 3080",
        },
        
        Available: true,
        
        PriceModel: network.PricingModel{
            Currency:     "USDC",
            CPUHourly:    0.10,
            GPUHourly:    0.50,
            MemoryHourly: 0.01,
            MinimumHours: 1,
        },
        
        Region:     "us-west-2",
        Reputation: 0.0, // New provider
        Uptime:     1.0,
    }
    
    return dht.RegisterService(ctx, record)
}
```

### Finding Services

```go
func findComputeProviders(dht *network.DHTService) {
    ctx := context.Background()
    
    // Find all compute services
    services, err := dht.FindServices(ctx, "compute")
    if err != nil {
        log.Printf("Failed to find services: %v", err)
        return
    }
    
    // Filter by requirements
    for _, service := range services {
        if service.Capacity.GPUs >= 1 && 
           service.PriceModel.GPUHourly <= 1.00 &&
           service.Available {
            
            log.Printf("Found suitable provider: %s", service.ProviderID)
            log.Printf("  GPUs: %d x %s", service.Capacity.GPUs, service.Capacity.GPUModel)
            log.Printf("  Price: $%.2f/hour", service.PriceModel.GPUHourly)
            log.Printf("  Region: %s", service.Region)
        }
    }
}
```

## Summary

Unit U02 implements a robust Kademlia DHT that serves as the discovery backbone for the Blackhole network. The implementation provides:

- Decentralized peer and service discovery
- Secure record validation and storage
- Efficient content routing
- Scalable service marketplace
- Protection against common attacks

This DHT implementation enables the Blackhole platform to operate without central coordination servers while maintaining high performance and security.