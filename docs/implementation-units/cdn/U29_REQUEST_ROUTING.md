# U29: Request Routing

## Overview
GeoDNS-based request routing with latency-based selection, load distribution, and failover handling for optimal content delivery.

## Implementation

```go
package requestrouting

import (
    "context"
    "fmt"
    "math"
    "net"
    "sort"
    "sync"
    "time"
)

// NodeInfo represents a CDN node with its characteristics
type NodeInfo struct {
    ID          string
    IP          net.IP
    Location    GeoLocation
    Capacity    int
    CurrentLoad int
    Latency     time.Duration
    Healthy     bool
    LastCheck   time.Time
}

// GeoLocation represents geographical coordinates
type GeoLocation struct {
    Latitude  float64
    Longitude float64
    Country   string
    Region    string
}

// RequestRouter handles intelligent request routing
type RequestRouter struct {
    nodes       map[string]*NodeInfo
    nodesMutex  sync.RWMutex
    geoResolver *GeoResolver
    healthCheck *HealthChecker
    metrics     *RoutingMetrics
}

// GeoResolver resolves IP addresses to geographical locations
type GeoResolver struct {
    db *maxminddb.Reader
}

// HealthChecker monitors node health
type HealthChecker struct {
    interval time.Duration
    timeout  time.Duration
}

// RoutingMetrics tracks routing performance
type RoutingMetrics struct {
    requests     uint64
    routingTime  time.Duration
    failovers    uint64
    mutex        sync.Mutex
}

// NewRequestRouter creates a new request router
func NewRequestRouter(geoDBPath string) (*RequestRouter, error) {
    geoResolver, err := NewGeoResolver(geoDBPath)
    if err != nil {
        return nil, fmt.Errorf("failed to create geo resolver: %w", err)
    }

    return &RequestRouter{
        nodes:       make(map[string]*NodeInfo),
        geoResolver: geoResolver,
        healthCheck: &HealthChecker{
            interval: 30 * time.Second,
            timeout:  5 * time.Second,
        },
        metrics: &RoutingMetrics{},
    }, nil
}

// RouteRequest selects the best node for a client request
func (rr *RequestRouter) RouteRequest(ctx context.Context, clientIP net.IP) (*NodeInfo, error) {
    start := time.Now()
    defer func() {
        rr.metrics.mutex.Lock()
        rr.metrics.requests++
        rr.metrics.routingTime += time.Since(start)
        rr.metrics.mutex.Unlock()
    }()

    // Get client location
    clientLoc, err := rr.geoResolver.Resolve(clientIP)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve client location: %w", err)
    }

    // Get available nodes
    nodes := rr.getHealthyNodes()
    if len(nodes) == 0 {
        return nil, fmt.Errorf("no healthy nodes available")
    }

    // Score and rank nodes
    candidates := rr.rankNodes(nodes, clientLoc, clientIP)
    
    // Select best node
    return rr.selectBestNode(candidates)
}

// rankNodes scores and ranks nodes based on multiple factors
func (rr *RequestRouter) rankNodes(nodes []*NodeInfo, clientLoc GeoLocation, clientIP net.IP) []*scoredNode {
    var candidates []*scoredNode

    for _, node := range nodes {
        score := rr.calculateNodeScore(node, clientLoc, clientIP)
        candidates = append(candidates, &scoredNode{
            node:  node,
            score: score,
        })
    }

    // Sort by score (higher is better)
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].score > candidates[j].score
    })

    return candidates
}

// calculateNodeScore computes a composite score for node selection
func (rr *RequestRouter) calculateNodeScore(node *NodeInfo, clientLoc GeoLocation, clientIP net.IP) float64 {
    // Distance score (closer is better)
    distance := calculateDistance(clientLoc, node.Location)
    distanceScore := 1.0 / (1.0 + distance/1000.0) // Normalize to 0-1

    // Load score (less loaded is better)
    loadScore := 1.0 - float64(node.CurrentLoad)/float64(node.Capacity)

    // Latency score (lower is better)
    latencyScore := 1.0 / (1.0 + float64(node.Latency.Milliseconds())/100.0)

    // Combine scores with weights
    return distanceScore*0.4 + loadScore*0.3 + latencyScore*0.3
}

// calculateDistance computes the haversine distance between two locations
func calculateDistance(loc1, loc2 GeoLocation) float64 {
    const earthRadius = 6371.0 // km

    lat1Rad := loc1.Latitude * math.Pi / 180.0
    lat2Rad := loc2.Latitude * math.Pi / 180.0
    deltaLat := (loc2.Latitude - loc1.Latitude) * math.Pi / 180.0
    deltaLon := (loc2.Longitude - loc1.Longitude) * math.Pi / 180.0

    a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
        math.Cos(lat1Rad)*math.Cos(lat2Rad)*
            math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
    c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

    return earthRadius * c
}

// selectBestNode applies final selection logic with failover
func (rr *RequestRouter) selectBestNode(candidates []*scoredNode) (*NodeInfo, error) {
    if len(candidates) == 0 {
        return nil, fmt.Errorf("no candidates available")
    }

    // Try candidates in order
    for _, candidate := range candidates {
        if candidate.node.CurrentLoad < candidate.node.Capacity {
            return candidate.node, nil
        }
    }

    // All nodes at capacity - return best scored anyway
    return candidates[0].node, nil
}

// getHealthyNodes returns all healthy nodes
func (rr *RequestRouter) getHealthyNodes() []*NodeInfo {
    rr.nodesMutex.RLock()
    defer rr.nodesMutex.RUnlock()

    var healthy []*NodeInfo
    for _, node := range rr.nodes {
        if node.Healthy {
            healthy = append(healthy, node)
        }
    }

    return healthy
}

// UpdateNodeHealth updates the health status of a node
func (rr *RequestRouter) UpdateNodeHealth(nodeID string, healthy bool) {
    rr.nodesMutex.Lock()
    defer rr.nodesMutex.Unlock()

    if node, exists := rr.nodes[nodeID]; exists {
        node.Healthy = healthy
        node.LastCheck = time.Now()
        
        if !healthy {
            rr.metrics.mutex.Lock()
            rr.metrics.failovers++
            rr.metrics.mutex.Unlock()
        }
    }
}

// LoadBalancer implements various load balancing algorithms
type LoadBalancer struct {
    algorithm string
    nodes     []*NodeInfo
    counter   uint64
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(algorithm string) *LoadBalancer {
    return &LoadBalancer{
        algorithm: algorithm,
    }
}

// SelectNode selects a node based on the configured algorithm
func (lb *LoadBalancer) SelectNode(nodes []*NodeInfo) (*NodeInfo, error) {
    if len(nodes) == 0 {
        return nil, fmt.Errorf("no nodes available")
    }

    switch lb.algorithm {
    case "round-robin":
        return lb.roundRobin(nodes)
    case "least-connections":
        return lb.leastConnections(nodes)
    case "weighted":
        return lb.weighted(nodes)
    default:
        return lb.random(nodes)
    }
}

// roundRobin implements round-robin selection
func (lb *LoadBalancer) roundRobin(nodes []*NodeInfo) (*NodeInfo, error) {
    index := atomic.AddUint64(&lb.counter, 1) % uint64(len(nodes))
    return nodes[index], nil
}

// leastConnections selects the node with the least current load
func (lb *LoadBalancer) leastConnections(nodes []*NodeInfo) (*NodeInfo, error) {
    var selected *NodeInfo
    minLoad := math.MaxInt32

    for _, node := range nodes {
        if node.CurrentLoad < minLoad {
            minLoad = node.CurrentLoad
            selected = node
        }
    }

    return selected, nil
}

// weighted implements weighted selection based on capacity
func (lb *LoadBalancer) weighted(nodes []*NodeInfo) (*NodeInfo, error) {
    totalCapacity := 0
    for _, node := range nodes {
        totalCapacity += node.Capacity
    }

    r := rand.Intn(totalCapacity)
    cumulative := 0

    for _, node := range nodes {
        cumulative += node.Capacity
        if r < cumulative {
            return node, nil
        }
    }

    return nodes[len(nodes)-1], nil
}

// FailoverManager handles node failures and recovery
type FailoverManager struct {
    router      *RequestRouter
    retryPolicy *RetryPolicy
    circuit     *CircuitBreaker
}

// RetryPolicy defines retry behavior
type RetryPolicy struct {
    MaxRetries int
    Backoff    time.Duration
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
    failures    map[string]int
    threshold   int
    timeout     time.Duration
    halfOpen    map[string]time.Time
    mutex       sync.Mutex
}

// HandleFailover manages failover for a failed node
func (fm *FailoverManager) HandleFailover(ctx context.Context, failedNode *NodeInfo, clientIP net.IP) (*NodeInfo, error) {
    // Mark node as unhealthy
    fm.router.UpdateNodeHealth(failedNode.ID, false)

    // Open circuit breaker
    fm.circuit.Open(failedNode.ID)

    // Find alternative node
    for retry := 0; retry < fm.retryPolicy.MaxRetries; retry++ {
        alternative, err := fm.router.RouteRequest(ctx, clientIP)
        if err == nil && alternative.ID != failedNode.ID {
            return alternative, nil
        }

        // Exponential backoff
        time.Sleep(fm.retryPolicy.Backoff * time.Duration(1<<retry))
    }

    return nil, fmt.Errorf("failover exhausted all retries")
}

// DNSResolver implements GeoDNS resolution
type DNSResolver struct {
    router *RequestRouter
    cache  *DNSCache
}

// DNSCache caches DNS resolutions
type DNSCache struct {
    entries map[string]*DNSEntry
    mutex   sync.RWMutex
    ttl     time.Duration
}

// DNSEntry represents a cached DNS entry
type DNSEntry struct {
    IPs       []net.IP
    ExpiresAt time.Time
}

// Resolve performs GeoDNS resolution
func (dr *DNSResolver) Resolve(ctx context.Context, hostname string, clientIP net.IP) ([]net.IP, error) {
    // Check cache
    if cached := dr.cache.Get(hostname); cached != nil {
        return cached.IPs, nil
    }

    // Route request to best node
    node, err := dr.router.RouteRequest(ctx, clientIP)
    if err != nil {
        return nil, fmt.Errorf("failed to route DNS request: %w", err)
    }

    // Cache result
    dr.cache.Set(hostname, []net.IP{node.IP})

    return []net.IP{node.IP}, nil
}

// Get retrieves a cached DNS entry
func (dc *DNSCache) Get(hostname string) *DNSEntry {
    dc.mutex.RLock()
    defer dc.mutex.RUnlock()

    entry, exists := dc.entries[hostname]
    if !exists || time.Now().After(entry.ExpiresAt) {
        return nil
    }

    return entry
}

// Set caches a DNS resolution
func (dc *DNSCache) Set(hostname string, ips []net.IP) {
    dc.mutex.Lock()
    defer dc.mutex.Unlock()

    dc.entries[hostname] = &DNSEntry{
        IPs:       ips,
        ExpiresAt: time.Now().Add(dc.ttl),
    }
}

// Types
type scoredNode struct {
    node  *NodeInfo
    score float64
}
```

## Testing

```go
package requestrouting

import (
    "context"
    "net"
    "testing"
    "time"
)

func TestRequestRouter(t *testing.T) {
    router, err := NewRequestRouter("testdata/GeoLite2-City.mmdb")
    if err != nil {
        t.Fatalf("Failed to create router: %v", err)
    }

    // Add test nodes
    nodes := []*NodeInfo{
        {
            ID:       "node1",
            IP:       net.ParseIP("192.168.1.1"),
            Location: GeoLocation{Latitude: 40.7128, Longitude: -74.0060}, // NYC
            Capacity: 100,
            Healthy:  true,
        },
        {
            ID:       "node2",
            IP:       net.ParseIP("192.168.1.2"),
            Location: GeoLocation{Latitude: 34.0522, Longitude: -118.2437}, // LA
            Capacity: 100,
            Healthy:  true,
        },
    }

    for _, node := range nodes {
        router.nodes[node.ID] = node
    }

    // Test routing
    clientIP := net.ParseIP("8.8.8.8")
    selected, err := router.RouteRequest(context.Background(), clientIP)
    if err != nil {
        t.Fatalf("Failed to route request: %v", err)
    }

    if selected == nil {
        t.Fatal("No node selected")
    }
}

func TestLoadBalancer(t *testing.T) {
    lb := NewLoadBalancer("round-robin")
    
    nodes := []*NodeInfo{
        {ID: "node1", CurrentLoad: 10},
        {ID: "node2", CurrentLoad: 20},
        {ID: "node3", CurrentLoad: 5},
    }

    // Test round-robin
    seen := make(map[string]int)
    for i := 0; i < 9; i++ {
        node, err := lb.SelectNode(nodes)
        if err != nil {
            t.Fatalf("Failed to select node: %v", err)
        }
        seen[node.ID]++
    }

    // Each node should be selected 3 times
    for _, count := range seen {
        if count != 3 {
            t.Errorf("Expected 3 selections, got %d", count)
        }
    }
}

func TestFailover(t *testing.T) {
    router, _ := NewRequestRouter("testdata/GeoLite2-City.mmdb")
    fm := &FailoverManager{
        router: router,
        retryPolicy: &RetryPolicy{
            MaxRetries: 3,
            Backoff:    100 * time.Millisecond,
        },
        circuit: &CircuitBreaker{
            failures:  make(map[string]int),
            threshold: 5,
            timeout:   30 * time.Second,
            halfOpen:  make(map[string]time.Time),
        },
    }

    failedNode := &NodeInfo{ID: "failed", Healthy: false}
    
    // Test failover
    _, err := fm.HandleFailover(context.Background(), failedNode, net.ParseIP("8.8.8.8"))
    if err == nil {
        t.Error("Expected failover to fail with no healthy nodes")
    }
}

func BenchmarkRouting(b *testing.B) {
    router, _ := NewRequestRouter("testdata/GeoLite2-City.mmdb")
    
    // Add many nodes
    for i := 0; i < 100; i++ {
        router.nodes[fmt.Sprintf("node%d", i)] = &NodeInfo{
            ID:       fmt.Sprintf("node%d", i),
            IP:       net.ParseIP(fmt.Sprintf("192.168.1.%d", i)),
            Location: GeoLocation{Latitude: float64(i), Longitude: float64(i)},
            Capacity: 100,
            Healthy:  true,
        }
    }

    clientIP := net.ParseIP("8.8.8.8")
    ctx := context.Background()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        router.RouteRequest(ctx, clientIP)
    }
}
```

## Configuration

```yaml
request_routing:
  geo_database: "/data/GeoLite2-City.mmdb"
  
  algorithms:
    primary: "geo-proximity"
    secondary: "least-connections"
    
  health_check:
    interval: 30s
    timeout: 5s
    threshold: 3
    
  load_balancing:
    algorithm: "weighted"
    sticky_sessions: true
    session_timeout: 5m
    
  failover:
    max_retries: 3
    backoff: 100ms
    circuit_breaker:
      threshold: 5
      timeout: 30s
      
  dns:
    ttl: 300s
    cache_size: 10000
```

## Deployment

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o request-router cmd/router/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/request-router .
COPY --from=builder /app/config.yaml .
COPY --from=builder /app/GeoLite2-City.mmdb /data/

EXPOSE 53/udp
EXPOSE 8080/tcp

CMD ["./request-router"]
```