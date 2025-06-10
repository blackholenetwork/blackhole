# Unit U06: Service Discovery Protocol - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U06 implements a distributed service discovery protocol that enables providers to advertise their services and consumers to discover available resources across the Blackhole network. This unit leverages the Kademlia DHT for decentralized service registration and lookup, providing a scalable alternative to centralized service registries.

**Primary Goals:**
- Implement service advertisement with structured metadata
- Enable efficient service discovery via DHT queries
- Support multi-criteria service filtering
- Provide service health monitoring and TTL management
- Enable geographic and capability-based service routing

### Dependencies

- **U02: Kademlia DHT Implementation** - Provides distributed key-value storage
- **U01: libp2p Core Setup** - Network communication foundation
- **U05: GossipSub Messaging** - Real-time service updates

### Deliverables

1. **Service Record Format**
   - Structured service metadata schema
   - Versioned record format for upgrades
   - Signature verification for authenticity

2. **DHT Key Schema**
   - Hierarchical namespace design
   - Service type categorization
   - Geographic sharding support

3. **Service Registration API**
   - Provider service advertisement
   - Periodic refresh mechanism
   - Batch registration support

4. **Service Discovery API**
   - Multi-criteria search capabilities
   - Result ranking and filtering
   - Caching for performance

### Integration Points

This unit enables:
- U10: Storage API Service (storage provider discovery)
- U24: Job Submission API (compute provider discovery)
- U29: CDN Request Router (edge node discovery)
- U33: WireGuard Integration (bandwidth provider discovery)
- U45: Pricing Engine (service pricing queries)

## 2. Technical Specifications

### Service Record Schema

```protobuf
// proto/service.proto
syntax = "proto3";
package blackhole.discovery;

import "google/protobuf/timestamp.proto";

// ServiceRecord represents a service advertisement in the DHT
message ServiceRecord {
    // Unique service instance ID
    string id = 1;
    
    // Provider peer ID
    string provider_id = 2;
    
    // Service metadata
    ServiceMetadata metadata = 3;
    
    // Service capabilities
    ServiceCapabilities capabilities = 4;
    
    // Geographic information
    GeoLocation location = 5;
    
    // Pricing information
    PricingInfo pricing = 6;
    
    // Service health status
    HealthStatus health = 7;
    
    // Record timestamps
    google.protobuf.Timestamp created_at = 8;
    google.protobuf.Timestamp updated_at = 9;
    google.protobuf.Timestamp expires_at = 10;
    
    // Cryptographic signature
    bytes signature = 11;
}

message ServiceMetadata {
    // Service type (storage, compute, cdn, bandwidth)
    string type = 1;
    
    // Service subtype (e.g., gpu-compute, ssd-storage)
    string subtype = 2;
    
    // Human-readable name
    string name = 3;
    
    // Service description
    string description = 4;
    
    // Service version
    string version = 5;
    
    // API endpoints
    repeated string endpoints = 6;
    
    // Supported protocols
    repeated string protocols = 7;
    
    // Custom attributes
    map<string, string> attributes = 8;
}

message ServiceCapabilities {
    // For storage services
    StorageCapabilities storage = 1;
    
    // For compute services
    ComputeCapabilities compute = 2;
    
    // For CDN services
    CDNCapabilities cdn = 3;
    
    // For bandwidth services
    BandwidthCapabilities bandwidth = 4;
}

message StorageCapabilities {
    uint64 total_space = 1;      // Total space in bytes
    uint64 available_space = 2;   // Available space in bytes
    uint32 max_object_size = 3;   // Max object size in MB
    repeated string storage_classes = 4; // hot, cold, archive
    bool encryption_supported = 5;
    bool versioning_supported = 6;
}

message ComputeCapabilities {
    uint32 cpu_cores = 1;
    uint64 memory_mb = 2;
    repeated GPUInfo gpus = 3;
    repeated string runtime_engines = 4; // wasm, docker, native
    uint32 max_job_duration = 5; // seconds
}

message CDNCapabilities {
    uint64 bandwidth_mbps = 1;
    repeated string regions = 2;
    repeated string cache_types = 3; // static, dynamic, streaming
    bool ssl_supported = 4;
    bool http2_supported = 5;
}

message BandwidthCapabilities {
    uint64 upload_mbps = 1;
    uint64 download_mbps = 2;
    repeated string protocols = 3; // wireguard, openvpn, socks5
    repeated string exit_countries = 4;
}

message GeoLocation {
    double latitude = 1;
    double longitude = 2;
    string country = 3;
    string region = 4;
    string city = 5;
    string isp = 6;
}

message PricingInfo {
    string currency = 1; // USDC
    double base_price = 2;
    string price_unit = 3; // per-gb, per-hour, per-request
    map<string, double> tier_pricing = 4;
    double minimum_commitment = 5;
}

message HealthStatus {
    enum Status {
        UNKNOWN = 0;
        HEALTHY = 1;
        DEGRADED = 2;
        UNHEALTHY = 3;
    }
    
    Status status = 1;
    double uptime_percent = 2;
    uint64 response_time_ms = 3;
    uint32 error_rate = 4; // per 10000 requests
    google.protobuf.Timestamp last_check = 5;
}

message GPUInfo {
    string model = 1;
    uint32 memory_mb = 2;
    uint32 compute_capability = 3;
}
```

### DHT Key Design

```go
// Service discovery uses a hierarchical key structure:
// /blackhole/services/{type}/{subtype}/{geohash}/{provider_id}/{service_id}
//
// Examples:
// /blackhole/services/storage/ssd/u4pruydq/QmProvider1/service-123
// /blackhole/services/compute/gpu/9q8yyx8/QmProvider2/service-456
// /blackhole/services/cdn/static/dqcjq/QmProvider3/service-789
// /blackhole/services/bandwidth/wireguard/u4pruy/QmProvider4/service-012

// Key components:
// - type: Primary service category (storage, compute, cdn, bandwidth)
// - subtype: Service specialization (ssd, gpu, static, wireguard)
// - geohash: Geographic location (4-6 character precision)
// - provider_id: Peer ID of the service provider
// - service_id: Unique service instance identifier
```

## 3. Implementation Details

### Project Structure

```
pkg/discovery/
├── service.go          # Core service discovery implementation
├── record.go           # Service record management
├── registry.go         # Local service registry
├── query.go            # Service query engine
├── cache.go            # Discovery cache layer
├── health.go           # Health monitoring
├── geo.go              # Geographic utilities
├── metrics.go          # Discovery metrics
├── proto/
│   ├── service.proto
│   └── service.pb.go
├── tests/
│   ├── service_test.go
│   ├── registry_test.go
│   ├── query_test.go
│   └── integration_test.go
└── examples/
    ├── provider/       # Service provider example
    └── consumer/       # Service consumer example
```

### Core Service Discovery Implementation

```go
// pkg/discovery/service.go
package discovery

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "time"

    "github.com/ipfs/go-cid"
    ds "github.com/ipfs/go-datastore"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/routing"
    kaddht "github.com/libp2p/go-libp2p-kad-dht"
    "github.com/mmcloughlin/geohash"
    "google.golang.org/protobuf/proto"
    
    pb "github.com/blackhole/pkg/discovery/proto"
)

const (
    // Service namespace in DHT
    ServiceNamespace = "/blackhole/services"
    
    // Default TTL for service records
    DefaultTTL = 24 * time.Hour
    
    // Refresh interval (should be < TTL/2)
    RefreshInterval = 6 * time.Hour
    
    // Maximum records per query
    MaxQueryResults = 100
)

// ServiceDiscovery provides service registration and discovery
type ServiceDiscovery struct {
    host     host.Host
    dht      *kaddht.IpfsDHT
    registry *ServiceRegistry
    cache    *DiscoveryCache
    health   *HealthMonitor
    
    ctx      context.Context
    cancel   context.CancelFunc
    wg       sync.WaitGroup
    
    config   *Config
    metrics  *Metrics
}

// Config holds discovery configuration
type Config struct {
    // Service record TTL
    RecordTTL time.Duration
    
    // Refresh interval for owned services
    RefreshInterval time.Duration
    
    // Cache configuration
    CacheSize       int
    CacheTTL        time.Duration
    
    // Health check configuration
    HealthCheckInterval time.Duration
    HealthCheckTimeout  time.Duration
    
    // Geographic precision (geohash length)
    GeoPrecision int
    
    // Maximum services per provider
    MaxServicesPerProvider int
}

// NewServiceDiscovery creates a new service discovery instance
func NewServiceDiscovery(h host.Host, dht *kaddht.IpfsDHT, cfg *Config) (*ServiceDiscovery, error) {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    sd := &ServiceDiscovery{
        host:     h,
        dht:      dht,
        registry: NewServiceRegistry(cfg.MaxServicesPerProvider),
        cache:    NewDiscoveryCache(cfg.CacheSize, cfg.CacheTTL),
        config:   cfg,
        ctx:      ctx,
        cancel:   cancel,
        metrics:  NewMetrics(),
    }
    
    // Initialize health monitor
    sd.health = NewHealthMonitor(sd, cfg.HealthCheckInterval, cfg.HealthCheckTimeout)
    
    // Start background workers
    sd.wg.Add(2)
    go sd.refreshLoop()
    go sd.cleanupLoop()
    
    return sd, nil
}

// RegisterService advertises a service in the DHT
func (sd *ServiceDiscovery) RegisterService(ctx context.Context, service *pb.ServiceRecord) error {
    // Validate service record
    if err := sd.validateServiceRecord(service); err != nil {
        return fmt.Errorf("invalid service record: %w", err)
    }
    
    // Set timestamps
    now := time.Now()
    service.CreatedAt = timestamppb.New(now)
    service.UpdatedAt = timestamppb.New(now)
    service.ExpiresAt = timestamppb.New(now.Add(sd.config.RecordTTL))
    
    // Sign the record
    if err := sd.signServiceRecord(service); err != nil {
        return fmt.Errorf("failed to sign record: %w", err)
    }
    
    // Generate DHT keys for the service
    keys, err := sd.generateServiceKeys(service)
    if err != nil {
        return fmt.Errorf("failed to generate keys: %w", err)
    }
    
    // Serialize the record
    data, err := proto.Marshal(service)
    if err != nil {
        return fmt.Errorf("failed to marshal record: %w", err)
    }
    
    // Store in DHT with all keys
    for _, key := range keys {
        if err := sd.dht.PutValue(ctx, key, data); err != nil {
            log.Warnf("Failed to store under key %s: %v", key, err)
            // Continue with other keys
        }
    }
    
    // Add to local registry
    sd.registry.AddService(service)
    
    // Update metrics
    sd.metrics.ServicesRegistered.Inc()
    sd.metrics.ServicesByType.WithLabelValues(service.Metadata.Type).Inc()
    
    log.Infof("Registered service %s of type %s", service.Id, service.Metadata.Type)
    return nil
}

// DiscoverServices finds services matching the query
func (sd *ServiceDiscovery) DiscoverServices(ctx context.Context, query *ServiceQuery) ([]*pb.ServiceRecord, error) {
    // Check cache first
    if cached := sd.cache.Get(query.CacheKey()); cached != nil {
        sd.metrics.CacheHits.Inc()
        return cached, nil
    }
    sd.metrics.CacheMisses.Inc()
    
    // Build DHT query keys
    queryKeys := sd.buildQueryKeys(query)
    
    // Collect results
    results := make([]*pb.ServiceRecord, 0)
    seen := make(map[string]bool)
    
    for _, key := range queryKeys {
        // Query DHT
        records, err := sd.queryDHT(ctx, key)
        if err != nil {
            log.Warnf("DHT query failed for key %s: %v", key, err)
            continue
        }
        
        // Deduplicate and filter results
        for _, record := range records {
            if seen[record.Id] {
                continue
            }
            seen[record.Id] = true
            
            if sd.matchesQuery(record, query) {
                results = append(results, record)
                if len(results) >= MaxQueryResults {
                    break
                }
            }
        }
        
        if len(results) >= MaxQueryResults {
            break
        }
    }
    
    // Rank results
    results = sd.rankResults(results, query)
    
    // Cache results
    sd.cache.Set(query.CacheKey(), results)
    
    // Update metrics
    sd.metrics.QueriesTotal.Inc()
    sd.metrics.ResultsReturned.Add(float64(len(results)))
    
    return results, nil
}

// UnregisterService removes a service from the DHT
func (sd *ServiceDiscovery) UnregisterService(ctx context.Context, serviceID string) error {
    // Get service from registry
    service := sd.registry.GetService(serviceID)
    if service == nil {
        return fmt.Errorf("service not found: %s", serviceID)
    }
    
    // Generate DHT keys
    keys, err := sd.generateServiceKeys(service)
    if err != nil {
        return fmt.Errorf("failed to generate keys: %w", err)
    }
    
    // Remove from DHT
    for _, key := range keys {
        // DHT doesn't support explicit delete, so we put empty value
        if err := sd.dht.PutValue(ctx, key, []byte{}); err != nil {
            log.Warnf("Failed to remove key %s: %v", key, err)
        }
    }
    
    // Remove from local registry
    sd.registry.RemoveService(serviceID)
    
    // Update metrics
    sd.metrics.ServicesUnregistered.Inc()
    sd.metrics.ServicesByType.WithLabelValues(service.Metadata.Type).Dec()
    
    log.Infof("Unregistered service %s", serviceID)
    return nil
}

// generateServiceKeys creates all DHT keys for a service
func (sd *ServiceDiscovery) generateServiceKeys(service *pb.ServiceRecord) ([]string, error) {
    keys := make([]string, 0)
    
    // Base path
    basePath := fmt.Sprintf("%s/%s", ServiceNamespace, service.Metadata.Type)
    
    // Add subtype if present
    if service.Metadata.Subtype != "" {
        basePath = fmt.Sprintf("%s/%s", basePath, service.Metadata.Subtype)
    }
    
    // Add geographic keys
    if service.Location != nil && service.Location.Latitude != 0 && service.Location.Longitude != 0 {
        geoHash := geohash.EncodeWithPrecision(
            service.Location.Latitude,
            service.Location.Longitude,
            sd.config.GeoPrecision,
        )
        
        // Add keys for different geo precisions
        for i := 2; i <= sd.config.GeoPrecision; i++ {
            geoKey := fmt.Sprintf("%s/%s/%s/%s",
                basePath,
                geoHash[:i],
                service.ProviderId,
                service.Id,
            )
            keys = append(keys, geoKey)
        }
    }
    
    // Add non-geographic key
    globalKey := fmt.Sprintf("%s/global/%s/%s",
        basePath,
        service.ProviderId,
        service.Id,
    )
    keys = append(keys, globalKey)
    
    return keys, nil
}

// queryDHT performs a DHT query for a specific key pattern
func (sd *ServiceDiscovery) queryDHT(ctx context.Context, keyPrefix string) ([]*pb.ServiceRecord, error) {
    // Create a CID from the key for DHT routing
    hash := sha256.Sum256([]byte(keyPrefix))
    mh, err := multihash.EncodeName(hash[:], "sha2-256")
    if err != nil {
        return nil, err
    }
    
    c := cid.NewCidV1(cid.Raw, mh)
    
    // Find providers for this CID
    providers := sd.dht.FindProvidersAsync(ctx, c, 20)
    
    results := make([]*pb.ServiceRecord, 0)
    
    for provider := range providers {
        // Get value from provider
        stream, err := sd.host.NewStream(ctx, provider.ID, "/blackhole/discovery/1.0.0")
        if err != nil {
            continue
        }
        defer stream.Close()
        
        // Request records matching prefix
        req := &QueryRequest{KeyPrefix: keyPrefix}
        if err := writeMessage(stream, req); err != nil {
            continue
        }
        
        // Read response
        var resp QueryResponse
        if err := readMessage(stream, &resp); err != nil {
            continue
        }
        
        // Parse records
        for _, data := range resp.Records {
            var record pb.ServiceRecord
            if err := proto.Unmarshal(data, &record); err != nil {
                continue
            }
            
            // Verify signature
            if err := sd.verifyServiceRecord(&record); err != nil {
                log.Warnf("Invalid signature for service %s: %v", record.Id, err)
                continue
            }
            
            // Check expiration
            if record.ExpiresAt.AsTime().Before(time.Now()) {
                continue
            }
            
            results = append(results, &record)
        }
    }
    
    return results, nil
}

// refreshLoop periodically refreshes registered services
func (sd *ServiceDiscovery) refreshLoop() {
    defer sd.wg.Done()
    
    ticker := time.NewTicker(sd.config.RefreshInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            sd.refreshServices()
        case <-sd.ctx.Done():
            return
        }
    }
}

// refreshServices updates TTL for all registered services
func (sd *ServiceDiscovery) refreshServices() {
    services := sd.registry.GetAllServices()
    
    for _, service := range services {
        // Update timestamps
        service.UpdatedAt = timestamppb.New(time.Now())
        service.ExpiresAt = timestamppb.New(time.Now().Add(sd.config.RecordTTL))
        
        // Re-sign
        if err := sd.signServiceRecord(service); err != nil {
            log.Warnf("Failed to re-sign service %s: %v", service.Id, err)
            continue
        }
        
        // Re-register
        ctx, cancel := context.WithTimeout(sd.ctx, 30*time.Second)
        if err := sd.RegisterService(ctx, service); err != nil {
            log.Warnf("Failed to refresh service %s: %v", service.Id, err)
        }
        cancel()
        
        sd.metrics.ServicesRefreshed.Inc()
    }
}

// Close shuts down the service discovery
func (sd *ServiceDiscovery) Close() error {
    sd.cancel()
    sd.wg.Wait()
    
    // Unregister all services
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    for _, service := range sd.registry.GetAllServices() {
        sd.UnregisterService(ctx, service.Id)
    }
    
    return nil
}
```

### Service Query Engine

```go
// pkg/discovery/query.go
package discovery

import (
    "fmt"
    "sort"
    "strings"
    
    pb "github.com/blackhole/pkg/discovery/proto"
)

// ServiceQuery represents a service discovery query
type ServiceQuery struct {
    // Service type filter
    Type    string
    Subtype string
    
    // Geographic filter
    Location *GeoFilter
    
    // Capability filters
    MinCPUCores     uint32
    MinMemoryMB     uint64
    MinStorageGB    uint64
    MinBandwidthMbps uint64
    RequiredGPU     bool
    
    // Price filter
    MaxPrice float64
    Currency string
    
    // Quality filters
    MinUptime    float64
    MaxErrorRate uint32
    
    // Provider filter
    ProviderID string
    
    // Attribute filters
    Attributes map[string]string
    
    // Result options
    MaxResults int
    SortBy     SortCriteria
}

// GeoFilter represents geographic filtering criteria
type GeoFilter struct {
    Latitude  float64
    Longitude float64
    RadiusKm  float64
    Countries []string
    Regions   []string
}

// SortCriteria defines how results should be sorted
type SortCriteria int

const (
    SortByDistance SortCriteria = iota
    SortByPrice
    SortByUptime
    SortByResponseTime
    SortByRandom
)

// CacheKey generates a cache key for the query
func (q *ServiceQuery) CacheKey() string {
    parts := []string{
        q.Type,
        q.Subtype,
    }
    
    if q.Location != nil {
        parts = append(parts, fmt.Sprintf("geo:%.4f,%.4f,%.0f",
            q.Location.Latitude,
            q.Location.Longitude,
            q.Location.RadiusKm,
        ))
    }
    
    if q.MinCPUCores > 0 {
        parts = append(parts, fmt.Sprintf("cpu:%d", q.MinCPUCores))
    }
    
    if q.MaxPrice > 0 {
        parts = append(parts, fmt.Sprintf("price:%.2f", q.MaxPrice))
    }
    
    return strings.Join(parts, "/")
}

// buildQueryKeys generates DHT keys for the query
func (sd *ServiceDiscovery) buildQueryKeys(query *ServiceQuery) []string {
    keys := make([]string, 0)
    
    // Base path
    basePath := fmt.Sprintf("%s/%s", ServiceNamespace, query.Type)
    
    if query.Subtype != "" {
        basePath = fmt.Sprintf("%s/%s", basePath, query.Subtype)
    }
    
    // Geographic queries
    if query.Location != nil && query.Location.RadiusKm > 0 {
        // Calculate geohash precision based on radius
        precision := sd.calculateGeoPrecision(query.Location.RadiusKm)
        centerHash := geohash.EncodeWithPrecision(
            query.Location.Latitude,
            query.Location.Longitude,
            precision,
        )
        
        // Get neighboring geohashes
        neighbors := geohash.Neighbors(centerHash)
        neighbors = append(neighbors, centerHash)
        
        for _, gh := range neighbors {
            keys = append(keys, fmt.Sprintf("%s/%s", basePath, gh))
        }
    } else {
        // Global query
        keys = append(keys, fmt.Sprintf("%s/global", basePath))
    }
    
    return keys
}

// matchesQuery checks if a service record matches the query criteria
func (sd *ServiceDiscovery) matchesQuery(record *pb.ServiceRecord, query *ServiceQuery) bool {
    // Type matching
    if query.Type != "" && record.Metadata.Type != query.Type {
        return false
    }
    
    if query.Subtype != "" && record.Metadata.Subtype != query.Subtype {
        return false
    }
    
    // Geographic filtering
    if query.Location != nil && !sd.matchesGeoFilter(record, query.Location) {
        return false
    }
    
    // Capability filtering
    if !sd.matchesCapabilities(record, query) {
        return false
    }
    
    // Price filtering
    if query.MaxPrice > 0 && record.Pricing != nil {
        if record.Pricing.BasePrice > query.MaxPrice {
            return false
        }
    }
    
    // Quality filtering
    if query.MinUptime > 0 && record.Health != nil {
        if record.Health.UptimePercent < query.MinUptime {
            return false
        }
    }
    
    if query.MaxErrorRate > 0 && record.Health != nil {
        if record.Health.ErrorRate > query.MaxErrorRate {
            return false
        }
    }
    
    // Provider filtering
    if query.ProviderID != "" && record.ProviderId != query.ProviderID {
        return false
    }
    
    // Attribute filtering
    for key, value := range query.Attributes {
        if record.Metadata.Attributes[key] != value {
            return false
        }
    }
    
    return true
}

// matchesCapabilities checks capability requirements
func (sd *ServiceDiscovery) matchesCapabilities(record *pb.ServiceRecord, query *ServiceQuery) bool {
    caps := record.Capabilities
    if caps == nil {
        return false
    }
    
    switch record.Metadata.Type {
    case "compute":
        if caps.Compute == nil {
            return false
        }
        if query.MinCPUCores > 0 && caps.Compute.CpuCores < query.MinCPUCores {
            return false
        }
        if query.MinMemoryMB > 0 && caps.Compute.MemoryMb < query.MinMemoryMB {
            return false
        }
        if query.RequiredGPU && len(caps.Compute.Gpus) == 0 {
            return false
        }
        
    case "storage":
        if caps.Storage == nil {
            return false
        }
        if query.MinStorageGB > 0 {
            availableGB := caps.Storage.AvailableSpace / (1024 * 1024 * 1024)
            if availableGB < query.MinStorageGB {
                return false
            }
        }
        
    case "cdn":
        if caps.Cdn == nil {
            return false
        }
        if query.MinBandwidthMbps > 0 && caps.Cdn.BandwidthMbps < query.MinBandwidthMbps {
            return false
        }
        
    case "bandwidth":
        if caps.Bandwidth == nil {
            return false
        }
        if query.MinBandwidthMbps > 0 {
            minBandwidth := min(caps.Bandwidth.UploadMbps, caps.Bandwidth.DownloadMbps)
            if minBandwidth < query.MinBandwidthMbps {
                return false
            }
        }
    }
    
    return true
}

// rankResults sorts results based on query preferences
func (sd *ServiceDiscovery) rankResults(results []*pb.ServiceRecord, query *ServiceQuery) []*pb.ServiceRecord {
    // Calculate scores for each result
    type scoredResult struct {
        record *pb.ServiceRecord
        score  float64
    }
    
    scored := make([]scoredResult, len(results))
    for i, record := range results {
        scored[i] = scoredResult{
            record: record,
            score:  sd.calculateScore(record, query),
        }
    }
    
    // Sort by criteria
    switch query.SortBy {
    case SortByDistance:
        if query.Location != nil {
            sort.Slice(scored, func(i, j int) bool {
                di := sd.calculateDistance(scored[i].record, query.Location)
                dj := sd.calculateDistance(scored[j].record, query.Location)
                return di < dj
            })
        }
        
    case SortByPrice:
        sort.Slice(scored, func(i, j int) bool {
            pi := scored[i].record.Pricing.BasePrice
            pj := scored[j].record.Pricing.BasePrice
            return pi < pj
        })
        
    case SortByUptime:
        sort.Slice(scored, func(i, j int) bool {
            ui := scored[i].record.Health.UptimePercent
            uj := scored[j].record.Health.UptimePercent
            return ui > uj
        })
        
    case SortByResponseTime:
        sort.Slice(scored, func(i, j int) bool {
            ri := scored[i].record.Health.ResponseTimeMs
            rj := scored[j].record.Health.ResponseTimeMs
            return ri < rj
        })
        
    default:
        // Sort by composite score
        sort.Slice(scored, func(i, j int) bool {
            return scored[i].score > scored[j].score
        })
    }
    
    // Extract sorted records
    sorted := make([]*pb.ServiceRecord, len(results))
    for i, s := range scored {
        sorted[i] = s.record
    }
    
    // Apply result limit
    if query.MaxResults > 0 && len(sorted) > query.MaxResults {
        sorted = sorted[:query.MaxResults]
    }
    
    return sorted
}

// calculateScore computes a composite score for ranking
func (sd *ServiceDiscovery) calculateScore(record *pb.ServiceRecord, query *ServiceQuery) float64 {
    score := 100.0
    
    // Health score (0-40 points)
    if record.Health != nil {
        healthScore := record.Health.UptimePercent * 0.3
        if record.Health.ErrorRate > 0 {
            healthScore -= float64(record.Health.ErrorRate) / 100
        }
        score += healthScore
    }
    
    // Price score (0-30 points)
    if query.MaxPrice > 0 && record.Pricing != nil {
        priceRatio := record.Pricing.BasePrice / query.MaxPrice
        priceScore := (1.0 - priceRatio) * 30
        score += priceScore
    }
    
    // Performance score (0-20 points)
    if record.Health != nil && record.Health.ResponseTimeMs > 0 {
        // Lower response time is better
        perfScore := 20.0 * (1.0 - float64(record.Health.ResponseTimeMs)/1000.0)
        if perfScore > 0 {
            score += perfScore
        }
    }
    
    // Location score (0-10 points)
    if query.Location != nil && record.Location != nil {
        distance := sd.calculateDistance(record, query.Location)
        if distance < query.Location.RadiusKm {
            locScore := 10.0 * (1.0 - distance/query.Location.RadiusKm)
            score += locScore
        }
    }
    
    return score
}
```

### Service Registry

```go
// pkg/discovery/registry.go
package discovery

import (
    "sync"
    "time"
    
    pb "github.com/blackhole/pkg/discovery/proto"
)

// ServiceRegistry manages local service registrations
type ServiceRegistry struct {
    mu              sync.RWMutex
    services        map[string]*pb.ServiceRecord
    byProvider      map[string][]string
    maxPerProvider  int
}

// NewServiceRegistry creates a new registry
func NewServiceRegistry(maxPerProvider int) *ServiceRegistry {
    return &ServiceRegistry{
        services:       make(map[string]*pb.ServiceRecord),
        byProvider:     make(map[string][]string),
        maxPerProvider: maxPerProvider,
    }
}

// AddService registers a service
func (r *ServiceRegistry) AddService(service *pb.ServiceRecord) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    // Check provider limit
    providerServices := r.byProvider[service.ProviderId]
    if len(providerServices) >= r.maxPerProvider {
        return fmt.Errorf("provider %s has reached service limit", service.ProviderId)
    }
    
    // Add service
    r.services[service.Id] = service
    
    // Update provider index
    r.byProvider[service.ProviderId] = append(providerServices, service.Id)
    
    return nil
}

// RemoveService unregisters a service
func (r *ServiceRegistry) RemoveService(serviceID string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    service, exists := r.services[serviceID]
    if !exists {
        return
    }
    
    // Remove from services map
    delete(r.services, serviceID)
    
    // Update provider index
    providerServices := r.byProvider[service.ProviderId]
    for i, id := range providerServices {
        if id == serviceID {
            r.byProvider[service.ProviderId] = append(
                providerServices[:i],
                providerServices[i+1:]...,
            )
            break
        }
    }
}

// GetService returns a service by ID
func (r *ServiceRegistry) GetService(serviceID string) *pb.ServiceRecord {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    return r.services[serviceID]
}

// GetAllServices returns all registered services
func (r *ServiceRegistry) GetAllServices() []*pb.ServiceRecord {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    services := make([]*pb.ServiceRecord, 0, len(r.services))
    for _, service := range r.services {
        services = append(services, service)
    }
    
    return services
}

// GetProviderServices returns all services for a provider
func (r *ServiceRegistry) GetProviderServices(providerID string) []*pb.ServiceRecord {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    serviceIDs := r.byProvider[providerID]
    services := make([]*pb.ServiceRecord, 0, len(serviceIDs))
    
    for _, id := range serviceIDs {
        if service := r.services[id]; service != nil {
            services = append(services, service)
        }
    }
    
    return services
}

// CleanExpired removes expired services
func (r *ServiceRegistry) CleanExpired() int {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    now := time.Now()
    removed := 0
    
    for id, service := range r.services {
        if service.ExpiresAt.AsTime().Before(now) {
            delete(r.services, id)
            removed++
            
            // Update provider index
            providerServices := r.byProvider[service.ProviderId]
            for i, sid := range providerServices {
                if sid == id {
                    r.byProvider[service.ProviderId] = append(
                        providerServices[:i],
                        providerServices[i+1:]...,
                    )
                    break
                }
            }
        }
    }
    
    return removed
}
```

## 4. Key Functions

### RegisterService() - Advertise a service

```go
// RegisterService advertises a service in the DHT
// Parameters:
//   - ctx: Context for cancellation
//   - service: Service record to advertise
// Returns:
//   - error: Registration errors
func (sd *ServiceDiscovery) RegisterService(ctx context.Context, service *pb.ServiceRecord) error
```

### DiscoverServices() - Find services

```go
// DiscoverServices finds services matching the query
// Parameters:
//   - ctx: Context for cancellation
//   - query: Search criteria
// Returns:
//   - []*pb.ServiceRecord: Matching services
//   - error: Query errors
func (sd *ServiceDiscovery) DiscoverServices(ctx context.Context, query *ServiceQuery) ([]*pb.ServiceRecord, error)
```

### UnregisterService() - Remove a service

```go
// UnregisterService removes a service from the DHT
// Parameters:
//   - ctx: Context for cancellation
//   - serviceID: ID of service to remove
// Returns:
//   - error: Unregistration errors
func (sd *ServiceDiscovery) UnregisterService(ctx context.Context, serviceID string) error
```

### RefreshService() - Update service TTL

```go
// RefreshService updates the TTL of a service
// Parameters:
//   - ctx: Context for cancellation
//   - serviceID: ID of service to refresh
// Returns:
//   - error: Refresh errors
func (sd *ServiceDiscovery) RefreshService(ctx context.Context, serviceID string) error
```

## 5. Configuration

### Configuration Structure

```go
// pkg/discovery/config.go
package discovery

import "time"

// DefaultConfig returns production-ready configuration
func DefaultConfig() *Config {
    return &Config{
        // Record TTL (24 hours)
        RecordTTL: 24 * time.Hour,
        
        // Refresh every 6 hours
        RefreshInterval: 6 * time.Hour,
        
        // Cache configuration
        CacheSize: 1000,
        CacheTTL:  5 * time.Minute,
        
        // Health monitoring
        HealthCheckInterval: 1 * time.Minute,
        HealthCheckTimeout:  10 * time.Second,
        
        // Geographic precision (approx 1km)
        GeoPrecision: 6,
        
        // Service limits
        MaxServicesPerProvider: 100,
    }
}

// ValidateConfig ensures configuration is valid
func ValidateConfig(cfg *Config) error {
    if cfg.RecordTTL < 1*time.Hour {
        return fmt.Errorf("RecordTTL must be at least 1 hour")
    }
    
    if cfg.RefreshInterval >= cfg.RecordTTL/2 {
        return fmt.Errorf("RefreshInterval must be less than RecordTTL/2")
    }
    
    if cfg.CacheSize < 100 {
        return fmt.Errorf("CacheSize must be at least 100")
    }
    
    if cfg.GeoPrecision < 4 || cfg.GeoPrecision > 12 {
        return fmt.Errorf("GeoPrecision must be between 4 and 12")
    }
    
    return nil
}
```

### YAML Configuration Example

```yaml
# config/discovery.yaml
discovery:
  # Service record lifetime
  record_ttl: 24h
  
  # How often to refresh records
  refresh_interval: 6h
  
  # Discovery cache
  cache:
    size: 1000
    ttl: 5m
  
  # Health monitoring
  health:
    check_interval: 1m
    check_timeout: 10s
    
  # Geographic settings
  geo:
    precision: 6  # ~1.2km x 0.6km
    
  # Provider limits
  limits:
    services_per_provider: 100
    
  # Query defaults
  query:
    max_results: 100
    default_radius_km: 50
```

### Environment Variables

```bash
# Discovery configuration
export BLACKHOLE_DISCOVERY_RECORD_TTL=24h
export BLACKHOLE_DISCOVERY_REFRESH_INTERVAL=6h
export BLACKHOLE_DISCOVERY_CACHE_SIZE=1000
export BLACKHOLE_DISCOVERY_CACHE_TTL=5m
export BLACKHOLE_DISCOVERY_GEO_PRECISION=6
export BLACKHOLE_DISCOVERY_MAX_SERVICES=100
```

## 6. Testing Requirements

### Unit Tests

```go
// pkg/discovery/tests/service_test.go
package discovery_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/blackhole/pkg/discovery"
    pb "github.com/blackhole/pkg/discovery/proto"
)

func TestServiceRegistration(t *testing.T) {
    ctx := context.Background()
    sd := setupTestDiscovery(t)
    defer sd.Close()
    
    // Create test service
    service := &pb.ServiceRecord{
        Id:         "test-service-1",
        ProviderId: "provider-1",
        Metadata: &pb.ServiceMetadata{
            Type:    "storage",
            Subtype: "ssd",
            Name:    "Test Storage Service",
        },
        Capabilities: &pb.ServiceCapabilities{
            Storage: &pb.StorageCapabilities{
                TotalSpace:     1000000000000, // 1TB
                AvailableSpace: 800000000000,  // 800GB
            },
        },
        Location: &pb.GeoLocation{
            Latitude:  37.7749,
            Longitude: -122.4194,
            City:      "San Francisco",
            Country:   "US",
        },
        Pricing: &pb.PricingInfo{
            Currency:  "USDC",
            BasePrice: 0.05,
            PriceUnit: "per-gb-month",
        },
    }
    
    // Register service
    err := sd.RegisterService(ctx, service)
    require.NoError(t, err)
    
    // Verify registration
    registered := sd.GetRegistry().GetService(service.Id)
    assert.NotNil(t, registered)
    assert.Equal(t, service.Id, registered.Id)
    assert.NotNil(t, registered.Signature)
}

func TestServiceDiscovery(t *testing.T) {
    ctx := context.Background()
    sd := setupTestDiscovery(t)
    defer sd.Close()
    
    // Register multiple services
    services := createTestServices(10)
    for _, svc := range services {
        err := sd.RegisterService(ctx, svc)
        require.NoError(t, err)
    }
    
    // Query for storage services
    query := &discovery.ServiceQuery{
        Type:         "storage",
        MinStorageGB: 100,
        MaxPrice:     0.10,
    }
    
    results, err := sd.DiscoverServices(ctx, query)
    require.NoError(t, err)
    assert.NotEmpty(t, results)
    
    // Verify results match criteria
    for _, result := range results {
        assert.Equal(t, "storage", result.Metadata.Type)
        assert.True(t, result.Pricing.BasePrice <= 0.10)
        
        availableGB := result.Capabilities.Storage.AvailableSpace / (1024 * 1024 * 1024)
        assert.True(t, availableGB >= 100)
    }
}

func TestGeoQuery(t *testing.T) {
    ctx := context.Background()
    sd := setupTestDiscovery(t)
    defer sd.Close()
    
    // Register services in different locations
    locations := []struct {
        lat, lon float64
        city     string
    }{
        {37.7749, -122.4194, "San Francisco"},
        {40.7128, -74.0060, "New York"},
        {51.5074, -0.1278, "London"},
        {35.6762, 139.6503, "Tokyo"},
    }
    
    for i, loc := range locations {
        service := &pb.ServiceRecord{
            Id:         fmt.Sprintf("cdn-service-%d", i),
            ProviderId: fmt.Sprintf("provider-%d", i),
            Metadata: &pb.ServiceMetadata{
                Type: "cdn",
                Name: fmt.Sprintf("CDN %s", loc.city),
            },
            Location: &pb.GeoLocation{
                Latitude:  loc.lat,
                Longitude: loc.lon,
                City:      loc.city,
            },
        }
        
        err := sd.RegisterService(ctx, service)
        require.NoError(t, err)
    }
    
    // Query for services near San Francisco
    query := &discovery.ServiceQuery{
        Type: "cdn",
        Location: &discovery.GeoFilter{
            Latitude:  37.7749,
            Longitude: -122.4194,
            RadiusKm:  100,
        },
        SortBy: discovery.SortByDistance,
    }
    
    results, err := sd.DiscoverServices(ctx, query)
    require.NoError(t, err)
    assert.NotEmpty(t, results)
    
    // Verify closest service is first
    assert.Equal(t, "San Francisco", results[0].Location.City)
}

func TestServiceExpiration(t *testing.T) {
    ctx := context.Background()
    
    // Create discovery with short TTL
    cfg := discovery.DefaultConfig()
    cfg.RecordTTL = 2 * time.Second
    sd := setupTestDiscoveryWithConfig(t, cfg)
    defer sd.Close()
    
    // Register service
    service := createTestService("expiring-service")
    err := sd.RegisterService(ctx, service)
    require.NoError(t, err)
    
    // Verify service exists
    results, err := sd.DiscoverServices(ctx, &discovery.ServiceQuery{
        Type: service.Metadata.Type,
    })
    require.NoError(t, err)
    assert.Len(t, results, 1)
    
    // Wait for expiration
    time.Sleep(3 * time.Second)
    
    // Verify service is gone
    results, err = sd.DiscoverServices(ctx, &discovery.ServiceQuery{
        Type: service.Metadata.Type,
    })
    require.NoError(t, err)
    assert.Empty(t, results)
}
```

### Integration Tests

```go
// pkg/discovery/tests/integration_test.go
package discovery_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestMultiProviderDiscovery(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create multiple discovery nodes
    nodes := make([]*discovery.ServiceDiscovery, 3)
    for i := range nodes {
        nodes[i] = setupTestDiscoveryNode(t, i)
        defer nodes[i].Close()
    }
    
    // Wait for DHT to stabilize
    time.Sleep(2 * time.Second)
    
    // Register services on different nodes
    for i, node := range nodes {
        service := &pb.ServiceRecord{
            Id:         fmt.Sprintf("service-%d", i),
            ProviderId: fmt.Sprintf("provider-%d", i),
            Metadata: &pb.ServiceMetadata{
                Type:    "compute",
                Subtype: "gpu",
                Name:    fmt.Sprintf("GPU Compute %d", i),
            },
            Capabilities: &pb.ServiceCapabilities{
                Compute: &pb.ComputeCapabilities{
                    CpuCores: 16,
                    MemoryMb: 32768,
                    Gpus: []*pb.GPUInfo{{
                        Model:    "NVIDIA RTX 3090",
                        MemoryMb: 24576,
                    }},
                },
            },
        }
        
        err := node.RegisterService(ctx, service)
        require.NoError(t, err)
    }
    
    // Wait for propagation
    time.Sleep(1 * time.Second)
    
    // Query from each node
    for _, node := range nodes {
        query := &discovery.ServiceQuery{
            Type:        "compute",
            Subtype:     "gpu",
            RequiredGPU: true,
        }
        
        results, err := node.DiscoverServices(ctx, query)
        require.NoError(t, err)
        assert.Len(t, results, 3, "Should discover all services from any node")
    }
}

func TestServiceUpdatePropagation(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create two nodes
    node1 := setupTestDiscoveryNode(t, 1)
    defer node1.Close()
    
    node2 := setupTestDiscoveryNode(t, 2)
    defer node2.Close()
    
    // Wait for connection
    time.Sleep(2 * time.Second)
    
    // Register service on node1
    service := createTestService("update-test")
    service.Pricing.BasePrice = 0.10
    
    err := node1.RegisterService(ctx, service)
    require.NoError(t, err)
    
    // Query from node2
    time.Sleep(1 * time.Second)
    results, err := node2.DiscoverServices(ctx, &discovery.ServiceQuery{
        Type: service.Metadata.Type,
    })
    require.NoError(t, err)
    assert.Len(t, results, 1)
    assert.Equal(t, 0.10, results[0].Pricing.BasePrice)
    
    // Update service on node1
    service.Pricing.BasePrice = 0.08
    err = node1.RegisterService(ctx, service)
    require.NoError(t, err)
    
    // Query updated service from node2
    time.Sleep(1 * time.Second)
    results, err = node2.DiscoverServices(ctx, &discovery.ServiceQuery{
        Type: service.Metadata.Type,
    })
    require.NoError(t, err)
    assert.Len(t, results, 1)
    assert.Equal(t, 0.08, results[0].Pricing.BasePrice)
}
```

### Performance Benchmarks

```go
// pkg/discovery/tests/benchmark_test.go
package discovery_test

import (
    "context"
    "fmt"
    "testing"
)

func BenchmarkServiceRegistration(b *testing.B) {
    ctx := context.Background()
    sd := setupTestDiscovery(b)
    defer sd.Close()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        service := createTestService(fmt.Sprintf("bench-service-%d", i))
        if err := sd.RegisterService(ctx, service); err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkServiceDiscovery(b *testing.B) {
    ctx := context.Background()
    sd := setupTestDiscovery(b)
    defer sd.Close()
    
    // Pre-register services
    for i := 0; i < 1000; i++ {
        service := createTestService(fmt.Sprintf("bench-service-%d", i))
        sd.RegisterService(ctx, service)
    }
    
    query := &discovery.ServiceQuery{
        Type:       "storage",
        MaxResults: 10,
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        results, err := sd.DiscoverServices(ctx, query)
        if err != nil {
            b.Fatal(err)
        }
        if len(results) == 0 {
            b.Fatal("No results found")
        }
    }
}

func BenchmarkGeoQuery(b *testing.B) {
    ctx := context.Background()
    sd := setupTestDiscovery(b)
    defer sd.Close()
    
    // Register services across geographic grid
    for lat := -90.0; lat <= 90.0; lat += 10 {
        for lon := -180.0; lon <= 180.0; lon += 10 {
            service := &pb.ServiceRecord{
                Id:         fmt.Sprintf("geo-%f-%f", lat, lon),
                ProviderId: "geo-provider",
                Metadata: &pb.ServiceMetadata{
                    Type: "cdn",
                },
                Location: &pb.GeoLocation{
                    Latitude:  lat,
                    Longitude: lon,
                },
            }
            sd.RegisterService(ctx, service)
        }
    }
    
    query := &discovery.ServiceQuery{
        Type: "cdn",
        Location: &discovery.GeoFilter{
            Latitude:  37.7749,
            Longitude: -122.4194,
            RadiusKm:  100,
        },
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        results, err := sd.DiscoverServices(ctx, query)
        if err != nil {
            b.Fatal(err)
        }
        if len(results) == 0 {
            b.Fatal("No results found")
        }
    }
}
```

## 7. Monitoring & Metrics

### Metrics Implementation

```go
// pkg/discovery/metrics.go
package discovery

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics tracks discovery performance
type Metrics struct {
    // Registration metrics
    ServicesRegistered   prometheus.Counter
    ServicesUnregistered prometheus.Counter
    ServicesRefreshed    prometheus.Counter
    ServicesByType       *prometheus.GaugeVec
    
    // Query metrics
    QueriesTotal     prometheus.Counter
    QueryDuration    prometheus.Histogram
    ResultsReturned  prometheus.Histogram
    CacheHits        prometheus.Counter
    CacheMisses      prometheus.Counter
    
    // DHT metrics
    DHTOperations    *prometheus.CounterVec
    DHTLatency       *prometheus.HistogramVec
    
    // Health metrics
    HealthChecks     prometheus.Counter
    HealthyServices  prometheus.Gauge
    UnhealthyServices prometheus.Gauge
    
    // Error metrics
    Errors           *prometheus.CounterVec
}

// NewMetrics creates discovery metrics
func NewMetrics() *Metrics {
    return &Metrics{
        ServicesRegistered: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_services_registered_total",
            Help: "Total services registered",
        }),
        
        ServicesUnregistered: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_services_unregistered_total",
            Help: "Total services unregistered",
        }),
        
        ServicesRefreshed: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_services_refreshed_total",
            Help: "Total service refreshes",
        }),
        
        ServicesByType: promauto.NewGaugeVec(prometheus.GaugeOpts{
            Name: "blackhole_discovery_services_active",
            Help: "Active services by type",
        }, []string{"type"}),
        
        QueriesTotal: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_queries_total",
            Help: "Total discovery queries",
        }),
        
        QueryDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_discovery_query_duration_seconds",
            Help:    "Discovery query duration",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
        }),
        
        ResultsReturned: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_discovery_results_returned",
            Help:    "Number of results per query",
            Buckets: prometheus.LinearBuckets(0, 10, 11),
        }),
        
        CacheHits: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_cache_hits_total",
            Help: "Discovery cache hits",
        }),
        
        CacheMisses: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_cache_misses_total",
            Help: "Discovery cache misses",
        }),
        
        DHTOperations: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_discovery_dht_operations_total",
            Help: "DHT operations by type",
        }, []string{"operation"}),
        
        DHTLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
            Name:    "blackhole_discovery_dht_latency_seconds",
            Help:    "DHT operation latency",
            Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
        }, []string{"operation"}),
        
        HealthChecks: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_discovery_health_checks_total",
            Help: "Total health checks performed",
        }),
        
        HealthyServices: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_discovery_healthy_services",
            Help: "Number of healthy services",
        }),
        
        UnhealthyServices: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_discovery_unhealthy_services",
            Help: "Number of unhealthy services",
        }),
        
        Errors: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_discovery_errors_total",
            Help: "Discovery errors by type",
        }, []string{"error_type"}),
    }
}
```

### Monitoring Dashboard

```yaml
# Grafana dashboard configuration
panels:
  - title: "Active Services by Type"
    query: "blackhole_discovery_services_active"
    legend: "{{type}}"
    
  - title: "Registration Rate"
    query: "rate(blackhole_discovery_services_registered_total[5m])"
    
  - title: "Query Performance"
    queries:
      - "histogram_quantile(0.95, rate(blackhole_discovery_query_duration_seconds_bucket[5m]))"
      - "histogram_quantile(0.99, rate(blackhole_discovery_query_duration_seconds_bucket[5m]))"
    
  - title: "Cache Hit Rate"
    query: |
      rate(blackhole_discovery_cache_hits_total[5m]) /
      (rate(blackhole_discovery_cache_hits_total[5m]) + 
       rate(blackhole_discovery_cache_misses_total[5m]))
    
  - title: "Service Health"
    queries:
      - "blackhole_discovery_healthy_services"
      - "blackhole_discovery_unhealthy_services"
    
  - title: "DHT Operation Latency"
    query: |
      histogram_quantile(0.95,
        rate(blackhole_discovery_dht_latency_seconds_bucket[5m])
      )
```

## 8. Error Handling

### Error Types

```go
// pkg/discovery/errors.go
package discovery

import "errors"

var (
    // Registration errors
    ErrInvalidService      = errors.New("invalid service record")
    ErrServiceExists       = errors.New("service already exists")
    ErrProviderLimitReached = errors.New("provider service limit reached")
    ErrSignatureFailed     = errors.New("failed to sign service record")
    
    // Query errors
    ErrInvalidQuery        = errors.New("invalid query parameters")
    ErrNoServicesFound     = errors.New("no services found")
    ErrQueryTimeout        = errors.New("query timeout")
    
    // DHT errors
    ErrDHTOperation        = errors.New("DHT operation failed")
    ErrDHTNotReady         = errors.New("DHT not ready")
    
    // Validation errors
    ErrMissingMetadata     = errors.New("missing service metadata")
    ErrInvalidCapabilities = errors.New("invalid service capabilities")
    ErrInvalidLocation     = errors.New("invalid geographic location")
    ErrInvalidPricing      = errors.New("invalid pricing information")
)
```

### Recovery Mechanisms

```go
// Retry logic for DHT operations
func (sd *ServiceDiscovery) retryDHTOperation(
    ctx context.Context,
    operation func() error,
    maxRetries int,
) error {
    backoff := 100 * time.Millisecond
    
    for i := 0; i < maxRetries; i++ {
        err := operation()
        if err == nil {
            return nil
        }
        
        if !isRetryableError(err) {
            return err
        }
        
        select {
        case <-time.After(backoff):
            backoff *= 2
            if backoff > 5*time.Second {
                backoff = 5 * time.Second
            }
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    
    return ErrDHTOperation
}
```

## 9. Acceptance Criteria

### Functional Requirements

1. **Service Registration**
   - [ ] Register services with full metadata
   - [ ] Generate appropriate DHT keys
   - [ ] Sign records cryptographically
   - [ ] Handle TTL and expiration
   - [ ] Support batch registration

2. **Service Discovery**
   - [ ] Query by type and subtype
   - [ ] Filter by capabilities
   - [ ] Geographic queries work correctly
   - [ ] Price filtering functional
   - [ ] Results properly ranked

3. **Data Integrity**
   - [ ] All records signed and verified
   - [ ] Expired records filtered out
   - [ ] Duplicate detection working
   - [ ] Provider limits enforced

4. **Performance**
   - [ ] Sub-second query response time
   - [ ] Efficient caching layer
   - [ ] Minimal DHT operations
   - [ ] Scale to 10k+ services

### Performance Benchmarks

1. **Registration Performance**
   - Register service: < 100ms
   - Batch registration: < 10ms per service
   - DHT propagation: < 5 seconds

2. **Query Performance**
   - Simple query: < 50ms (cached)
   - Complex query: < 500ms
   - Geographic query: < 200ms
   - First query: < 2 seconds

3. **Scalability**
   - 10,000+ active services
   - 1,000+ queries per second
   - 100+ providers
   - Geographic distribution

## 10. Example Usage

### Service Provider Example

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/blackhole/pkg/discovery"
    pb "github.com/blackhole/pkg/discovery/proto"
)

func main() {
    // Initialize discovery
    sd, err := setupDiscovery()
    if err != nil {
        log.Fatal(err)
    }
    defer sd.Close()
    
    // Create storage service
    service := &pb.ServiceRecord{
        Id:         generateServiceID(),
        ProviderId: getProviderID(),
        Metadata: &pb.ServiceMetadata{
            Type:        "storage",
            Subtype:     "ssd",
            Name:        "Fast SSD Storage",
            Description: "High-performance SSD storage with encryption",
            Version:     "1.0.0",
            Endpoints:   []string{"https://storage.example.com/api/v1"},
            Protocols:   []string{"s3", "ipfs"},
            Attributes: map[string]string{
                "datacenter": "us-west-1",
                "tier":       "premium",
            },
        },
        Capabilities: &pb.ServiceCapabilities{
            Storage: &pb.StorageCapabilities{
                TotalSpace:        5000000000000,  // 5TB
                AvailableSpace:    4500000000000,  // 4.5TB
                MaxObjectSize:     5000,           // 5GB
                StorageClasses:    []string{"hot", "cold"},
                EncryptionSupported: true,
                VersioningSupported: true,
            },
        },
        Location: &pb.GeoLocation{
            Latitude:  37.7749,
            Longitude: -122.4194,
            Country:   "US",
            Region:    "California",
            City:      "San Francisco",
        },
        Pricing: &pb.PricingInfo{
            Currency:  "USDC",
            BasePrice: 0.05,
            PriceUnit: "per-gb-month",
            TierPricing: map[string]float64{
                "0-100":    0.05,
                "100-1000": 0.04,
                "1000+":    0.03,
            },
        },
        Health: &pb.HealthStatus{
            Status:         pb.HealthStatus_HEALTHY,
            UptimePercent:  99.99,
            ResponseTimeMs: 50,
            ErrorRate:      1, // per 10k requests
        },
    }
    
    // Register service
    ctx := context.Background()
    if err := sd.RegisterService(ctx, service); err != nil {
        log.Fatalf("Failed to register service: %v", err)
    }
    
    log.Printf("Service %s registered successfully", service.Id)
    
    // Keep service registered
    select {}
}
```

### Service Consumer Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/blackhole/pkg/discovery"
)

func main() {
    // Initialize discovery
    sd, err := setupDiscovery()
    if err != nil {
        log.Fatal(err)
    }
    defer sd.Close()
    
    // Find storage services near me
    ctx := context.Background()
    query := &discovery.ServiceQuery{
        Type:         "storage",
        Subtype:      "ssd",
        MinStorageGB: 1000, // 1TB minimum
        MaxPrice:     0.06, // $0.06 per GB/month max
        Location: &discovery.GeoFilter{
            Latitude:  37.7749,
            Longitude: -122.4194,
            RadiusKm:  50,
        },
        MinUptime: 99.0,
        SortBy:    discovery.SortByPrice,
        MaxResults: 10,
    }
    
    // Discover services
    services, err := sd.DiscoverServices(ctx, query)
    if err != nil {
        log.Fatalf("Discovery failed: %v", err)
    }
    
    fmt.Printf("Found %d storage services:\n", len(services))
    
    for i, svc := range services {
        fmt.Printf("\n%d. %s (ID: %s)\n", i+1, svc.Metadata.Name, svc.Id)
        fmt.Printf("   Type: %s/%s\n", svc.Metadata.Type, svc.Metadata.Subtype)
        fmt.Printf("   Provider: %s\n", svc.ProviderId)
        fmt.Printf("   Location: %s, %s\n", svc.Location.City, svc.Location.Country)
        fmt.Printf("   Available: %.2f TB\n", 
            float64(svc.Capabilities.Storage.AvailableSpace)/(1024*1024*1024*1024))
        fmt.Printf("   Price: $%.3f per GB/month\n", svc.Pricing.BasePrice)
        fmt.Printf("   Uptime: %.2f%%\n", svc.Health.UptimePercent)
        fmt.Printf("   Response: %dms\n", svc.Health.ResponseTimeMs)
        fmt.Printf("   Endpoints: %v\n", svc.Metadata.Endpoints)
    }
    
    // Select best service
    if len(services) > 0 {
        selected := services[0]
        fmt.Printf("\nSelected service: %s\n", selected.Id)
        
        // Connect to service endpoint
        endpoint := selected.Metadata.Endpoints[0]
        fmt.Printf("Connecting to %s...\n", endpoint)
        // ... establish connection
    }
}
```

## Summary

Unit U06 implements a comprehensive service discovery protocol that enables the Blackhole network to function as a decentralized marketplace for computational resources. The implementation leverages the Kademlia DHT for distributed storage while providing rich querying capabilities including geographic filtering, capability matching, and multi-criteria ranking.

Key achievements:
- Structured service records with versioning and signatures
- Hierarchical DHT key design for efficient queries
- Geographic-aware service discovery
- Multi-criteria filtering and ranking
- Automatic TTL management and refresh
- Comprehensive health monitoring
- Production-ready caching layer

This unit provides the foundation for all service-based interactions in the Blackhole network, enabling providers to advertise their resources and consumers to discover the best available options.