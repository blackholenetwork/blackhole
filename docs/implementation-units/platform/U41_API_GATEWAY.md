# Unit U41: API Gateway Implementation

## 1. Unit Overview

### Purpose
Implement a unified API gateway that provides a single entry point for all Blackhole platform services. The gateway handles request routing, authentication, rate limiting, load balancing, and service discovery, offering REST, gRPC, and WebSocket interfaces for maximum compatibility.

### Dependencies
- **U10**: Storage API Service (storage operations)
- **U24**: Compute Job Submission API (compute operations)
- **U29**: CDN Request Router (CDN operations)
- **U33**: WireGuard Integration (bandwidth operations)
- **U20-U23**: Identity & Access System (authentication/authorization)
- **U06**: Service Discovery Protocol (service registration/discovery)
- **U19**: Payment Gateway API (billing integration)

### Deliverables
- High-performance API gateway with multi-protocol support
- Service discovery and health checking
- Rate limiting and quota management
- Authentication/authorization middleware
- Request routing and load balancing
- WebSocket connection management
- Distributed tracing and monitoring
- Service mesh integration

### Service Mesh Integration
- **Consul**: Service discovery and health checking
- **Envoy**: Sidecar proxy for advanced traffic management
- **Jaeger**: Distributed tracing
- **Prometheus**: Metrics collection

## 2. Technical Specifications

### Gateway Architecture
- **Core Framework**: Custom Go implementation with plugin architecture
- **Protocols**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), gRPC, WebSocket
- **Load Balancing**: Round-robin, least connections, weighted, consistent hashing
- **Circuit Breaker**: Hystrix-style with configurable thresholds
- **Rate Limiting**: Token bucket algorithm with Redis backend

### Rate Limiting Strategies
```yaml
default_limits:
  anonymous:
    requests_per_second: 10
    burst: 20
    quota_per_hour: 1000
  
  authenticated:
    requests_per_second: 100
    burst: 200
    quota_per_hour: 100000
  
  premium:
    requests_per_second: 1000
    burst: 2000
    quota_per_hour: unlimited

service_limits:
  storage:
    upload_mb_per_second: 100
    download_mb_per_second: 200
  
  compute:
    jobs_per_minute: 10
    concurrent_jobs: 5
```

### Authentication/Authorization
- **JWT Tokens**: RS256 signed, 15-minute expiry
- **API Keys**: HMAC-SHA256 for service-to-service
- **DID Auth**: W3C DID-based authentication
- **OAuth 2.0**: For third-party integrations
- **RBAC**: Role-based access control per service

### Request Routing Rules
```yaml
routes:
  - pattern: /api/v1/storage/*
    service: storage-service
    methods: [GET, POST, PUT, DELETE, HEAD]
    auth: required
    
  - pattern: /api/v1/compute/*
    service: compute-service
    methods: [GET, POST]
    auth: required
    rate_limit: compute
    
  - pattern: /api/v1/cdn/*
    service: cdn-service
    methods: [GET, HEAD]
    auth: optional
    cache: true
    
  - pattern: /api/v1/bandwidth/*
    service: bandwidth-service
    methods: [GET, POST]
    auth: required
    
  - pattern: /api/v1/identity/*
    service: identity-service
    methods: [GET, POST, PUT]
    auth: public
```

## 3. Implementation Details

### Gateway Architecture

```go
// pkg/gateway/server.go
package gateway

import (
    "context"
    "net/http"
    "sync"
    "time"
    
    "github.com/blackhole/pkg/gateway/middleware"
    "github.com/blackhole/pkg/gateway/router"
    "github.com/blackhole/pkg/gateway/discovery"
    "github.com/blackhole/pkg/gateway/loadbalancer"
    "github.com/blackhole/pkg/gateway/ratelimit"
    "github.com/gorilla/mux"
    "github.com/prometheus/client_golang/prometheus"
    "go.uber.org/zap"
)

type Config struct {
    ListenAddr       string
    TLSConfig        *TLSConfig
    ServiceDiscovery discovery.Config
    RateLimit        ratelimit.Config
    Metrics          MetricsConfig
    Tracing          TracingConfig
}

type Gateway struct {
    config          Config
    router          *router.Router
    discovery       discovery.Client
    loadBalancer    loadbalancer.LoadBalancer
    rateLimiter     ratelimit.RateLimiter
    middleware      *middleware.Stack
    server          *http.Server
    grpcServer      *grpc.Server
    wsUpgrader      *websocket.Upgrader
    metrics         *Metrics
    logger          *zap.Logger
    shutdownCh      chan struct{}
    wg              sync.WaitGroup
}

func New(config Config) (*Gateway, error) {
    logger, _ := zap.NewProduction()
    
    // Initialize service discovery
    discoveryClient, err := discovery.NewConsulClient(config.ServiceDiscovery)
    if err != nil {
        return nil, fmt.Errorf("failed to create discovery client: %w", err)
    }
    
    // Initialize rate limiter
    rateLimiter, err := ratelimit.NewRedisLimiter(config.RateLimit)
    if err != nil {
        return nil, fmt.Errorf("failed to create rate limiter: %w", err)
    }
    
    // Initialize load balancer
    lb := loadbalancer.New(loadbalancer.Config{
        Algorithm: loadbalancer.LeastConnections,
        HealthCheck: loadbalancer.HealthCheckConfig{
            Interval: 10 * time.Second,
            Timeout:  3 * time.Second,
        },
    })
    
    gw := &Gateway{
        config:       config,
        discovery:    discoveryClient,
        loadBalancer: lb,
        rateLimiter:  rateLimiter,
        logger:       logger,
        shutdownCh:   make(chan struct{}),
        metrics:      NewMetrics(),
        wsUpgrader: &websocket.Upgrader{
            CheckOrigin: func(r *http.Request) bool {
                return true // Configure based on CORS policy
            },
        },
    }
    
    // Initialize middleware stack
    gw.middleware = middleware.NewStack(
        middleware.RequestID(),
        middleware.Logger(logger),
        middleware.Recovery(),
        middleware.CORS(config.CORS),
        middleware.RateLimit(rateLimiter),
        middleware.Authentication(config.Auth),
        middleware.Authorization(),
        middleware.Compression(),
        middleware.CircuitBreaker(config.CircuitBreaker),
        middleware.Tracing(config.Tracing),
        middleware.Metrics(gw.metrics),
    )
    
    // Initialize router
    gw.router = router.New(router.Config{
        ServiceDiscovery: discoveryClient,
        LoadBalancer:     lb,
        Middleware:       gw.middleware,
    })
    
    return gw, nil
}

func (g *Gateway) Start(ctx context.Context) error {
    // Start service discovery
    g.wg.Add(1)
    go g.watchServices(ctx)
    
    // Start health checker
    g.wg.Add(1)
    go g.healthChecker(ctx)
    
    // Configure HTTP server
    mux := g.setupRoutes()
    
    g.server = &http.Server{
        Addr:         g.config.ListenAddr,
        Handler:      mux,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }
    
    // Start gRPC server
    if g.config.GRPCEnabled {
        g.wg.Add(1)
        go g.startGRPCServer(ctx)
    }
    
    // Start HTTP server
    g.logger.Info("Starting API Gateway", zap.String("addr", g.config.ListenAddr))
    
    if g.config.TLSConfig != nil {
        return g.server.ListenAndServeTLS(g.config.TLSConfig.CertFile, g.config.TLSConfig.KeyFile)
    }
    
    return g.server.ListenAndServe()
}

func (g *Gateway) setupRoutes() *mux.Router {
    r := mux.NewRouter()
    
    // Health check endpoint
    r.HandleFunc("/health", g.handleHealth).Methods("GET")
    
    // Metrics endpoint
    r.Handle("/metrics", promhttp.Handler())
    
    // API routes
    apiRouter := r.PathPrefix("/api/v1").Subrouter()
    
    // Storage routes
    apiRouter.PathPrefix("/storage/").Handler(
        g.middleware.Apply(g.proxyHandler("storage-service")),
    )
    
    // Compute routes
    apiRouter.PathPrefix("/compute/").Handler(
        g.middleware.Apply(g.proxyHandler("compute-service")),
    )
    
    // CDN routes
    apiRouter.PathPrefix("/cdn/").Handler(
        g.middleware.Apply(g.proxyHandler("cdn-service")),
    )
    
    // Bandwidth routes
    apiRouter.PathPrefix("/bandwidth/").Handler(
        g.middleware.Apply(g.proxyHandler("bandwidth-service")),
    )
    
    // Identity routes
    apiRouter.PathPrefix("/identity/").Handler(
        g.middleware.Apply(g.proxyHandler("identity-service")),
    )
    
    // WebSocket upgrade endpoint
    r.HandleFunc("/ws", g.handleWebSocket)
    
    return r
}
```

### Service Discovery Integration

```go
// pkg/gateway/discovery.go
package gateway

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    consulapi "github.com/hashicorp/consul/api"
    "go.uber.org/zap"
)

type ServiceInstance struct {
    ID          string
    Name        string
    Address     string
    Port        int
    Version     string
    Tags        []string
    Metadata    map[string]string
    HealthCheck HealthStatus
}

type HealthStatus struct {
    Status       string
    LastChecked  time.Time
    ResponseTime time.Duration
}

type DiscoveryClient interface {
    Register(service ServiceInstance) error
    Deregister(serviceID string) error
    Discover(serviceName string) ([]ServiceInstance, error)
    Watch(serviceName string, callback func([]ServiceInstance)) error
    HealthCheck(instance ServiceInstance) (HealthStatus, error)
}

type ConsulDiscoveryClient struct {
    client      *consulapi.Client
    logger      *zap.Logger
    services    map[string][]ServiceInstance
    watchers    map[string][]func([]ServiceInstance)
    mu          sync.RWMutex
    stopCh      chan struct{}
}

func NewConsulClient(config Config) (*ConsulDiscoveryClient, error) {
    consulConfig := consulapi.DefaultConfig()
    consulConfig.Address = config.ConsulAddress
    
    client, err := consulapi.NewClient(consulConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create consul client: %w", err)
    }
    
    logger, _ := zap.NewProduction()
    
    return &ConsulDiscoveryClient{
        client:   client,
        logger:   logger,
        services: make(map[string][]ServiceInstance),
        watchers: make(map[string][]func([]ServiceInstance)),
        stopCh:   make(chan struct{}),
    }, nil
}

func (c *ConsulDiscoveryClient) Discover(serviceName string) ([]ServiceInstance, error) {
    // Check cache first
    c.mu.RLock()
    if instances, ok := c.services[serviceName]; ok {
        c.mu.RUnlock()
        return instances, nil
    }
    c.mu.RUnlock()
    
    // Query Consul
    services, _, err := c.client.Health().Service(serviceName, "", true, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to discover service %s: %w", serviceName, err)
    }
    
    instances := make([]ServiceInstance, 0, len(services))
    for _, entry := range services {
        instance := ServiceInstance{
            ID:      entry.Service.ID,
            Name:    entry.Service.Service,
            Address: entry.Service.Address,
            Port:    entry.Service.Port,
            Tags:    entry.Service.Tags,
            Metadata: entry.Service.Meta,
            HealthCheck: HealthStatus{
                Status:      "passing",
                LastChecked: time.Now(),
            },
        }
        instances = append(instances, instance)
    }
    
    // Update cache
    c.mu.Lock()
    c.services[serviceName] = instances
    c.mu.Unlock()
    
    return instances, nil
}

func (c *ConsulDiscoveryClient) Watch(serviceName string, callback func([]ServiceInstance)) error {
    c.mu.Lock()
    c.watchers[serviceName] = append(c.watchers[serviceName], callback)
    c.mu.Unlock()
    
    // Start watching if not already
    go c.watchService(serviceName)
    
    return nil
}

func (c *ConsulDiscoveryClient) watchService(serviceName string) {
    var lastIndex uint64
    
    for {
        select {
        case <-c.stopCh:
            return
        default:
            services, meta, err := c.client.Health().Service(
                serviceName, 
                "", 
                true,
                &consulapi.QueryOptions{
                    WaitIndex: lastIndex,
                    WaitTime:  30 * time.Second,
                },
            )
            
            if err != nil {
                c.logger.Error("Failed to watch service", 
                    zap.String("service", serviceName),
                    zap.Error(err))
                time.Sleep(5 * time.Second)
                continue
            }
            
            lastIndex = meta.LastIndex
            
            // Convert to ServiceInstance
            instances := make([]ServiceInstance, 0, len(services))
            for _, entry := range services {
                instances = append(instances, ServiceInstance{
                    ID:      entry.Service.ID,
                    Name:    entry.Service.Service,
                    Address: entry.Service.Address,
                    Port:    entry.Service.Port,
                    Tags:    entry.Service.Tags,
                    Metadata: entry.Service.Meta,
                })
            }
            
            // Update cache
            c.mu.Lock()
            c.services[serviceName] = instances
            callbacks := c.watchers[serviceName]
            c.mu.Unlock()
            
            // Notify watchers
            for _, callback := range callbacks {
                go callback(instances)
            }
        }
    }
}

func (c *ConsulDiscoveryClient) HealthCheck(instance ServiceInstance) (HealthStatus, error) {
    start := time.Now()
    
    // Perform HTTP health check
    url := fmt.Sprintf("http://%s:%d/health", instance.Address, instance.Port)
    resp, err := http.Get(url)
    if err != nil {
        return HealthStatus{
            Status:       "failing",
            LastChecked:  time.Now(),
            ResponseTime: time.Since(start),
        }, nil
    }
    defer resp.Body.Close()
    
    status := "passing"
    if resp.StatusCode != http.StatusOK {
        status = "warning"
    }
    
    return HealthStatus{
        Status:       status,
        LastChecked:  time.Now(),
        ResponseTime: time.Since(start),
    }, nil
}
```

### Load Balancing

```go
// pkg/gateway/loadbalancer.go
package gateway

import (
    "context"
    "fmt"
    "hash/fnv"
    "math/rand"
    "sync"
    "sync/atomic"
    "time"
)

type Algorithm string

const (
    RoundRobin       Algorithm = "round-robin"
    LeastConnections Algorithm = "least-connections"
    Weighted         Algorithm = "weighted"
    ConsistentHash   Algorithm = "consistent-hash"
    Random           Algorithm = "random"
)

type LoadBalancer interface {
    Select(serviceName string, key string) (*ServiceInstance, error)
    UpdateInstances(serviceName string, instances []ServiceInstance)
    MarkHealthy(instance *ServiceInstance)
    MarkUnhealthy(instance *ServiceInstance)
}

type BaseLoadBalancer struct {
    algorithm    Algorithm
    instances    map[string][]*ServiceInstance
    healthyMap   map[string]map[string]bool
    connections  map[string]int64
    weights      map[string]int
    roundRobin   map[string]*uint64
    mu           sync.RWMutex
}

func New(config Config) LoadBalancer {
    return &BaseLoadBalancer{
        algorithm:   config.Algorithm,
        instances:   make(map[string][]*ServiceInstance),
        healthyMap:  make(map[string]map[string]bool),
        connections: make(map[string]int64),
        weights:     make(map[string]int),
        roundRobin:  make(map[string]*uint64),
    }
}

func (lb *BaseLoadBalancer) Select(serviceName string, key string) (*ServiceInstance, error) {
    lb.mu.RLock()
    defer lb.mu.RUnlock()
    
    instances := lb.getHealthyInstances(serviceName)
    if len(instances) == 0 {
        return nil, fmt.Errorf("no healthy instances for service %s", serviceName)
    }
    
    switch lb.algorithm {
    case RoundRobin:
        return lb.roundRobinSelect(serviceName, instances), nil
    case LeastConnections:
        return lb.leastConnectionsSelect(instances), nil
    case Weighted:
        return lb.weightedSelect(instances), nil
    case ConsistentHash:
        return lb.consistentHashSelect(instances, key), nil
    case Random:
        return instances[rand.Intn(len(instances))], nil
    default:
        return lb.roundRobinSelect(serviceName, instances), nil
    }
}

func (lb *BaseLoadBalancer) roundRobinSelect(serviceName string, instances []*ServiceInstance) *ServiceInstance {
    if _, ok := lb.roundRobin[serviceName]; !ok {
        var counter uint64
        lb.roundRobin[serviceName] = &counter
    }
    
    counter := atomic.AddUint64(lb.roundRobin[serviceName], 1)
    return instances[int(counter)%len(instances)]
}

func (lb *BaseLoadBalancer) leastConnectionsSelect(instances []*ServiceInstance) *ServiceInstance {
    var selected *ServiceInstance
    minConnections := int64(^uint64(0) >> 1) // Max int64
    
    for _, instance := range instances {
        connections := atomic.LoadInt64(&lb.connections[instance.ID])
        if connections < minConnections {
            minConnections = connections
            selected = instance
        }
    }
    
    if selected != nil {
        atomic.AddInt64(&lb.connections[selected.ID], 1)
    }
    
    return selected
}

func (lb *BaseLoadBalancer) weightedSelect(instances []*ServiceInstance) *ServiceInstance {
    totalWeight := 0
    for _, instance := range instances {
        weight := lb.weights[instance.ID]
        if weight == 0 {
            weight = 1
        }
        totalWeight += weight
    }
    
    if totalWeight == 0 {
        return instances[0]
    }
    
    random := rand.Intn(totalWeight)
    for _, instance := range instances {
        weight := lb.weights[instance.ID]
        if weight == 0 {
            weight = 1
        }
        random -= weight
        if random < 0 {
            return instance
        }
    }
    
    return instances[0]
}

func (lb *BaseLoadBalancer) consistentHashSelect(instances []*ServiceInstance, key string) *ServiceInstance {
    if key == "" {
        return instances[0]
    }
    
    h := fnv.New32a()
    h.Write([]byte(key))
    hash := h.Sum32()
    
    return instances[int(hash)%len(instances)]
}

func (lb *BaseLoadBalancer) getHealthyInstances(serviceName string) []*ServiceInstance {
    allInstances := lb.instances[serviceName]
    healthyInstances := make([]*ServiceInstance, 0, len(allInstances))
    
    healthMap, ok := lb.healthyMap[serviceName]
    if !ok {
        return allInstances // If no health info, assume all healthy
    }
    
    for _, instance := range allInstances {
        if healthy, exists := healthMap[instance.ID]; exists && healthy {
            healthyInstances = append(healthyInstances, instance)
        }
    }
    
    return healthyInstances
}

func (lb *BaseLoadBalancer) UpdateInstances(serviceName string, instances []ServiceInstance) {
    lb.mu.Lock()
    defer lb.mu.Unlock()
    
    // Convert to pointers
    instancePtrs := make([]*ServiceInstance, len(instances))
    for i := range instances {
        instancePtrs[i] = &instances[i]
    }
    
    lb.instances[serviceName] = instancePtrs
    
    // Initialize health map if needed
    if _, ok := lb.healthyMap[serviceName]; !ok {
        lb.healthyMap[serviceName] = make(map[string]bool)
    }
    
    // Mark all as healthy by default
    for _, instance := range instances {
        if _, exists := lb.healthyMap[serviceName][instance.ID]; !exists {
            lb.healthyMap[serviceName][instance.ID] = true
        }
    }
}

func (lb *BaseLoadBalancer) MarkHealthy(instance *ServiceInstance) {
    lb.mu.Lock()
    defer lb.mu.Unlock()
    
    if _, ok := lb.healthyMap[instance.Name]; !ok {
        lb.healthyMap[instance.Name] = make(map[string]bool)
    }
    
    lb.healthyMap[instance.Name][instance.ID] = true
}

func (lb *BaseLoadBalancer) MarkUnhealthy(instance *ServiceInstance) {
    lb.mu.Lock()
    defer lb.mu.Unlock()
    
    if _, ok := lb.healthyMap[instance.Name]; !ok {
        lb.healthyMap[instance.Name] = make(map[string]bool)
    }
    
    lb.healthyMap[instance.Name][instance.ID] = false
}

// Connection tracking for least connections
func (lb *BaseLoadBalancer) OnRequestComplete(instanceID string) {
    if lb.algorithm == LeastConnections {
        atomic.AddInt64(&lb.connections[instanceID], -1)
    }
}
```

## 4. Code Structure

```
pkg/gateway/
├── server.go              # Main gateway server
├── router.go              # Request routing logic
├── middleware/
│   ├── auth.go           # Authentication middleware
│   ├── ratelimit.go      # Rate limiting middleware
│   ├── cors.go           # CORS handling
│   ├── logging.go        # Request/response logging
│   ├── metrics.go        # Prometheus metrics
│   ├── tracing.go        # Distributed tracing
│   ├── compression.go    # Response compression
│   ├── circuit.go        # Circuit breaker
│   └── recovery.go       # Panic recovery
├── auth.go               # Authentication handlers
├── ratelimit.go          # Rate limiting implementation
├── loadbalancer.go       # Load balancing algorithms
├── discovery.go          # Service discovery client
├── proxy.go              # HTTP/gRPC proxy logic
├── websocket.go          # WebSocket handling
├── cache.go              # Response caching
├── health.go             # Health check endpoints
└── config.go             # Configuration structures
```

## 5. API Routes

### Storage Service Routes
```yaml
/api/v1/storage/buckets:
  GET: List all buckets
  POST: Create new bucket

/api/v1/storage/buckets/{bucket}:
  GET: Get bucket info
  DELETE: Delete bucket
  HEAD: Check bucket exists

/api/v1/storage/buckets/{bucket}/objects:
  GET: List objects
  POST: Upload object

/api/v1/storage/buckets/{bucket}/objects/{key}:
  GET: Download object
  PUT: Update object
  DELETE: Delete object
  HEAD: Get object metadata
```

### Compute Service Routes
```yaml
/api/v1/compute/jobs:
  GET: List jobs
  POST: Submit new job

/api/v1/compute/jobs/{jobId}:
  GET: Get job details
  DELETE: Cancel job

/api/v1/compute/jobs/{jobId}/results:
  GET: Get job results

/api/v1/compute/workers:
  GET: List available workers
```

### CDN Service Routes
```yaml
/api/v1/cdn/content/{hash}:
  GET: Retrieve content
  HEAD: Check content exists

/api/v1/cdn/cache:
  POST: Warm cache
  DELETE: Purge cache

/api/v1/cdn/stats:
  GET: CDN statistics
```

### Bandwidth Service Routes
```yaml
/api/v1/bandwidth/tunnels:
  GET: List tunnels
  POST: Create tunnel

/api/v1/bandwidth/tunnels/{tunnelId}:
  GET: Get tunnel info
  DELETE: Close tunnel

/api/v1/bandwidth/usage:
  GET: Get bandwidth usage
```

### Identity Service Routes
```yaml
/api/v1/identity/dids:
  POST: Create DID

/api/v1/identity/dids/{did}:
  GET: Resolve DID
  PUT: Update DID document

/api/v1/identity/auth:
  POST: Authenticate
  
/api/v1/identity/credentials:
  POST: Issue credential
  GET: List credentials
```

## 6. Middleware Stack

### Authentication Middleware

```go
// pkg/gateway/middleware/auth.go
package middleware

import (
    "context"
    "net/http"
    "strings"
    
    "github.com/blackhole/pkg/auth"
    "github.com/dgrijalva/jwt-go"
)

type AuthMiddleware struct {
    jwtSecret   []byte
    didResolver auth.DIDResolver
    optional    bool
}

func Authentication(config AuthConfig) Middleware {
    return &AuthMiddleware{
        jwtSecret:   config.JWTSecret,
        didResolver: config.DIDResolver,
        optional:    config.Optional,
    }
}

func (m *AuthMiddleware) Handle(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            if m.optional {
                next.ServeHTTP(w, r)
                return
            }
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }
        
        // Parse Bearer token
        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
            return
        }
        
        token := parts[1]
        
        // Validate JWT token
        claims, err := m.validateJWT(token)
        if err != nil {
            // Try DID authentication
            if didClaims, err := m.validateDID(token); err == nil {
                claims = didClaims
            } else {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }
        }
        
        // Add claims to context
        ctx := context.WithValue(r.Context(), "user", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (m *AuthMiddleware) validateJWT(tokenString string) (*auth.Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &auth.Claims{}, func(token *jwt.Token) (interface{}, error) {
        return m.jwtSecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*auth.Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, fmt.Errorf("invalid token claims")
}

func (m *AuthMiddleware) validateDID(token string) (*auth.Claims, error) {
    // Validate DID-based authentication
    did, err := m.didResolver.Resolve(token)
    if err != nil {
        return nil, err
    }
    
    return &auth.Claims{
        Subject: did.ID,
        Type:    "did",
    }, nil
}
```

### Rate Limiting Middleware

```go
// pkg/gateway/middleware/ratelimit.go
package middleware

import (
    "fmt"
    "net/http"
    "time"
    
    "github.com/blackhole/pkg/gateway/ratelimit"
    "github.com/go-redis/redis/v8"
)

type RateLimitMiddleware struct {
    limiter ratelimit.RateLimiter
    config  RateLimitConfig
}

func RateLimit(limiter ratelimit.RateLimiter) Middleware {
    return &RateLimitMiddleware{
        limiter: limiter,
    }
}

func (m *RateLimitMiddleware) Handle(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get user from context
        userClaims := getUserFromContext(r.Context())
        
        // Determine rate limit key
        key := m.getRateLimitKey(r, userClaims)
        
        // Check rate limit
        allowed, remaining, resetAt, err := m.limiter.Allow(key)
        if err != nil {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }
        
        // Set rate limit headers
        w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", m.getLimit(userClaims)))
        w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
        w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))
        
        if !allowed {
            w.Header().Set("Retry-After", fmt.Sprintf("%d", resetAt.Unix()-time.Now().Unix()))
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (m *RateLimitMiddleware) getRateLimitKey(r *http.Request, user *auth.Claims) string {
    if user != nil {
        return fmt.Sprintf("user:%s:%s", user.Subject, r.URL.Path)
    }
    
    // Use IP address for anonymous users
    ip := getClientIP(r)
    return fmt.Sprintf("ip:%s:%s", ip, r.URL.Path)
}

func (m *RateLimitMiddleware) getLimit(user *auth.Claims) int {
    if user == nil {
        return m.config.AnonymousLimit
    }
    
    switch user.Tier {
    case "premium":
        return m.config.PremiumLimit
    case "authenticated":
        return m.config.AuthenticatedLimit
    default:
        return m.config.AnonymousLimit
    }
}
```

### Circuit Breaker Middleware

```go
// pkg/gateway/middleware/circuit.go
package middleware

import (
    "net/http"
    "time"
    
    "github.com/sony/gobreaker"
)

type CircuitBreakerMiddleware struct {
    breakers map[string]*gobreaker.CircuitBreaker
    config   CircuitBreakerConfig
}

func CircuitBreaker(config CircuitBreakerConfig) Middleware {
    return &CircuitBreakerMiddleware{
        breakers: make(map[string]*gobreaker.CircuitBreaker),
        config:   config,
    }
}

func (m *CircuitBreakerMiddleware) Handle(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        service := getServiceFromPath(r.URL.Path)
        
        breaker := m.getBreaker(service)
        
        _, err := breaker.Execute(func() (interface{}, error) {
            // Create response writer wrapper to capture status
            wrapper := &responseWriterWrapper{
                ResponseWriter: w,
                statusCode:     http.StatusOK,
            }
            
            next.ServeHTTP(wrapper, r)
            
            // Check if request was successful
            if wrapper.statusCode >= 500 {
                return nil, fmt.Errorf("service error: %d", wrapper.statusCode)
            }
            
            return nil, nil
        })
        
        if err != nil {
            if err == gobreaker.ErrOpenState {
                http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
                return
            }
            
            if err == gobreaker.ErrTooManyRequests {
                http.Error(w, "Too many requests", http.StatusTooManyRequests)
                return
            }
        }
    })
}

func (m *CircuitBreakerMiddleware) getBreaker(service string) *gobreaker.CircuitBreaker {
    if breaker, ok := m.breakers[service]; ok {
        return breaker
    }
    
    settings := gobreaker.Settings{
        Name:        service,
        MaxRequests: uint32(m.config.MaxRequests),
        Interval:    m.config.Interval,
        Timeout:     m.config.Timeout,
        ReadyToTrip: func(counts gobreaker.Counts) bool {
            failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
            return counts.Requests >= 3 && failureRatio >= m.config.FailureRatio
        },
    }
    
    breaker := gobreaker.NewCircuitBreaker(settings)
    m.breakers[service] = breaker
    
    return breaker
}
```

## 7. Service Integration

### Service Discovery Integration

```go
// pkg/gateway/integration.go
package gateway

import (
    "context"
    "fmt"
    "time"
)

func (g *Gateway) watchServices(ctx context.Context) {
    defer g.wg.Done()
    
    services := []string{
        "storage-service",
        "compute-service",
        "cdn-service",
        "bandwidth-service",
        "identity-service",
    }
    
    for _, service := range services {
        err := g.discovery.Watch(service, func(instances []ServiceInstance) {
            g.logger.Info("Service instances updated",
                zap.String("service", service),
                zap.Int("count", len(instances)))
            
            g.loadBalancer.UpdateInstances(service, instances)
        })
        
        if err != nil {
            g.logger.Error("Failed to watch service",
                zap.String("service", service),
                zap.Error(err))
        }
    }
    
    <-ctx.Done()
}

func (g *Gateway) healthChecker(ctx context.Context) {
    defer g.wg.Done()
    
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            g.checkAllServices()
        }
    }
}

func (g *Gateway) checkAllServices() {
    services := []string{
        "storage-service",
        "compute-service",
        "cdn-service",
        "bandwidth-service",
        "identity-service",
    }
    
    for _, service := range services {
        instances, err := g.discovery.Discover(service)
        if err != nil {
            g.logger.Error("Failed to discover service",
                zap.String("service", service),
                zap.Error(err))
            continue
        }
        
        for _, instance := range instances {
            go g.checkInstance(instance)
        }
    }
}

func (g *Gateway) checkInstance(instance ServiceInstance) {
    health, err := g.discovery.HealthCheck(instance)
    if err != nil {
        g.logger.Error("Health check failed",
            zap.String("instance", instance.ID),
            zap.Error(err))
        g.loadBalancer.MarkUnhealthy(&instance)
        return
    }
    
    if health.Status == "passing" {
        g.loadBalancer.MarkHealthy(&instance)
    } else {
        g.loadBalancer.MarkUnhealthy(&instance)
    }
    
    // Record metrics
    g.metrics.healthCheckDuration.WithLabelValues(
        instance.Name,
        instance.ID,
    ).Observe(health.ResponseTime.Seconds())
}
```

### Request Routing

```go
// pkg/gateway/router.go
package gateway

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "time"
)

type Router struct {
    config       RouterConfig
    discovery    DiscoveryClient
    loadBalancer LoadBalancer
    middleware   *middleware.Stack
    proxies      map[string]*httputil.ReverseProxy
}

func NewRouter(config RouterConfig) *Router {
    return &Router{
        config:       config,
        discovery:    config.ServiceDiscovery,
        loadBalancer: config.LoadBalancer,
        middleware:   config.Middleware,
        proxies:      make(map[string]*httputil.ReverseProxy),
    }
}

func (r *Router) Route(serviceName string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        // Select backend instance
        instance, err := r.loadBalancer.Select(serviceName, getRouteKey(req))
        if err != nil {
            http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
            return
        }
        
        // Get or create proxy
        proxy := r.getProxy(instance)
        
        // Add tracing headers
        span := opentracing.SpanFromContext(req.Context())
        if span != nil {
            carrier := opentracing.HTTPHeadersCarrier(req.Header)
            span.Tracer().Inject(span.Context(), opentracing.HTTPHeaders, carrier)
        }
        
        // Proxy the request
        proxy.ServeHTTP(w, req)
        
        // Update connection count for least connections
        if lb, ok := r.loadBalancer.(*BaseLoadBalancer); ok {
            defer lb.OnRequestComplete(instance.ID)
        }
    })
}

func (r *Router) getProxy(instance *ServiceInstance) *httputil.ReverseProxy {
    key := fmt.Sprintf("%s:%d", instance.Address, instance.Port)
    
    if proxy, ok := r.proxies[key]; ok {
        return proxy
    }
    
    target := &url.URL{
        Scheme: "http",
        Host:   key,
    }
    
    proxy := httputil.NewSingleHostReverseProxy(target)
    
    // Customize proxy behavior
    proxy.Director = func(req *http.Request) {
        req.URL.Scheme = target.Scheme
        req.URL.Host = target.Host
        req.Host = target.Host
        
        // Add forwarding headers
        if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
            req.Header.Set("X-Forwarded-For", clientIP)
        }
        req.Header.Set("X-Forwarded-Proto", "https")
        req.Header.Set("X-Forwarded-Host", req.Host)
        
        // Add service headers
        req.Header.Set("X-Service-Name", instance.Name)
        req.Header.Set("X-Service-Version", instance.Version)
    }
    
    proxy.ModifyResponse = func(resp *http.Response) error {
        // Add response headers
        resp.Header.Set("X-Served-By", instance.ID)
        resp.Header.Set("X-Service-Version", instance.Version)
        
        return nil
    }
    
    proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
        r.logger.Error("Proxy error",
            zap.String("service", instance.Name),
            zap.String("instance", instance.ID),
            zap.Error(err))
        
        // Mark instance as unhealthy
        r.loadBalancer.MarkUnhealthy(instance)
        
        // Return error response
        http.Error(w, "Bad gateway", http.StatusBadGateway)
    }
    
    r.proxies[key] = proxy
    return proxy
}
```

## 8. Performance Features

### Response Caching

```go
// pkg/gateway/cache.go
package gateway

import (
    "bytes"
    "crypto/md5"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"
    
    "github.com/go-redis/redis/v8"
)

type CacheMiddleware struct {
    client     *redis.Client
    ttl        time.Duration
    maxSize    int64
    skipAuth   bool
}

func NewCacheMiddleware(config CacheConfig) *CacheMiddleware {
    return &CacheMiddleware{
        client:   config.RedisClient,
        ttl:      config.TTL,
        maxSize:  config.MaxSize,
        skipAuth: config.SkipAuth,
    }
}

func (c *CacheMiddleware) Handle(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Only cache GET requests
        if r.Method != http.MethodGet {
            next.ServeHTTP(w, r)
            return
        }
        
        // Skip caching for authenticated requests if configured
        if c.skipAuth && r.Header.Get("Authorization") != "" {
            next.ServeHTTP(w, r)
            return
        }
        
        // Generate cache key
        key := c.generateKey(r)
        
        // Try to get from cache
        cached, err := c.client.Get(r.Context(), key).Result()
        if err == nil {
            // Parse cached response
            resp, err := parseCachedResponse([]byte(cached))
            if err == nil {
                // Write cached response
                for k, v := range resp.Headers {
                    w.Header()[k] = v
                }
                w.Header().Set("X-Cache", "HIT")
                w.WriteHeader(resp.StatusCode)
                w.Write(resp.Body)
                return
            }
        }
        
        // Cache miss - capture response
        recorder := &responseRecorder{
            ResponseWriter: w,
            statusCode:     http.StatusOK,
            body:           &bytes.Buffer{},
        }
        
        next.ServeHTTP(recorder, r)
        
        // Cache successful responses
        if recorder.statusCode >= 200 && recorder.statusCode < 300 {
            if int64(recorder.body.Len()) <= c.maxSize {
                cached := &cachedResponse{
                    StatusCode: recorder.statusCode,
                    Headers:    recorder.Header(),
                    Body:       recorder.body.Bytes(),
                }
                
                data, _ := cached.Marshal()
                c.client.Set(r.Context(), key, data, c.ttl)
            }
        }
    })
}

func (c *CacheMiddleware) generateKey(r *http.Request) string {
    h := md5.New()
    io.WriteString(h, r.Method)
    io.WriteString(h, r.URL.String())
    
    // Include important headers
    for _, header := range []string{"Accept", "Accept-Encoding", "Accept-Language"} {
        if value := r.Header.Get(header); value != "" {
            io.WriteString(h, header)
            io.WriteString(h, value)
        }
    }
    
    return fmt.Sprintf("cache:%x", h.Sum(nil))
}
```

### Request Coalescing

```go
// pkg/gateway/coalesce.go
package gateway

import (
    "context"
    "sync"
    "time"
)

type RequestCoalescer struct {
    requests map[string]*coalescedRequest
    mu       sync.Mutex
}

type coalescedRequest struct {
    key       string
    waiters   []chan *coalescedResponse
    executing bool
    response  *coalescedResponse
}

type coalescedResponse struct {
    statusCode int
    headers    http.Header
    body       []byte
    err        error
}

func NewRequestCoalescer() *RequestCoalescer {
    return &RequestCoalescer{
        requests: make(map[string]*coalescedRequest),
    }
}

func (rc *RequestCoalescer) Do(key string, fn func() (*http.Response, error)) (*coalescedResponse, error) {
    rc.mu.Lock()
    
    if req, ok := rc.requests[key]; ok {
        // Request already in flight
        ch := make(chan *coalescedResponse, 1)
        req.waiters = append(req.waiters, ch)
        rc.mu.Unlock()
        
        // Wait for response
        select {
        case resp := <-ch:
            return resp, resp.err
        case <-time.After(30 * time.Second):
            return nil, fmt.Errorf("request timeout")
        }
    }
    
    // New request
    req := &coalescedRequest{
        key:       key,
        waiters:   make([]chan *coalescedResponse, 0),
        executing: true,
    }
    rc.requests[key] = req
    rc.mu.Unlock()
    
    // Execute request
    resp, err := fn()
    
    coalescedResp := &coalescedResponse{
        err: err,
    }
    
    if err == nil && resp != nil {
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        
        coalescedResp.statusCode = resp.StatusCode
        coalescedResp.headers = resp.Header.Clone()
        coalescedResp.body = body
    }
    
    // Notify waiters
    rc.mu.Lock()
    req.response = coalescedResp
    for _, ch := range req.waiters {
        ch <- coalescedResp
        close(ch)
    }
    delete(rc.requests, key)
    rc.mu.Unlock()
    
    return coalescedResp, err
}
```

### Connection Pooling

```go
// pkg/gateway/pool.go
package gateway

import (
    "net"
    "net/http"
    "time"
)

func NewHTTPClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            Proxy: http.ProxyFromEnvironment,
            DialContext: (&net.Dialer{
                Timeout:   30 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            ForceAttemptHTTP2:     true,
            MaxIdleConns:          100,
            MaxIdleConnsPerHost:   10,
            MaxConnsPerHost:       100,
            IdleConnTimeout:       90 * time.Second,
            TLSHandshakeTimeout:   10 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
            DisableCompression:    false,
        },
        Timeout: 30 * time.Second,
    }
}

// HTTP/3 support
func NewHTTP3Client() *http.Client {
    return &http.Client{
        Transport: &http3.RoundTripper{
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS13,
            },
            QuicConfig: &quic.Config{
                MaxIdleTimeout:  30 * time.Second,
                KeepAlivePeriod: 10 * time.Second,
            },
        },
    }
}
```

## 9. Monitoring & Observability

### Distributed Tracing

```go
// pkg/gateway/tracing.go
package gateway

import (
    "io"
    
    "github.com/opentracing/opentracing-go"
    "github.com/uber/jaeger-client-go"
    jaegercfg "github.com/uber/jaeger-client-go/config"
)

func InitTracing(serviceName string) (opentracing.Tracer, io.Closer, error) {
    cfg := jaegercfg.Configuration{
        ServiceName: serviceName,
        Sampler: &jaegercfg.SamplerConfig{
            Type:  jaeger.SamplerTypeConst,
            Param: 1,
        },
        Reporter: &jaegercfg.ReporterConfig{
            LogSpans:            true,
            BufferFlushInterval: 1 * time.Second,
        },
    }
    
    tracer, closer, err := cfg.NewTracer(
        jaegercfg.Logger(jaeger.StdLogger),
        jaegercfg.Metrics(metrics.NullFactory),
    )
    
    if err != nil {
        return nil, nil, err
    }
    
    opentracing.SetGlobalTracer(tracer)
    return tracer, closer, nil
}

// Tracing middleware
func TracingMiddleware(tracer opentracing.Tracer) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract span context from headers
            wireContext, _ := tracer.Extract(
                opentracing.HTTPHeaders,
                opentracing.HTTPHeadersCarrier(r.Header),
            )
            
            // Start new span
            span := tracer.StartSpan(
                fmt.Sprintf("%s %s", r.Method, r.URL.Path),
                ext.RPCServerOption(wireContext),
            )
            defer span.Finish()
            
            // Set span tags
            ext.HTTPMethod.Set(span, r.Method)
            ext.HTTPUrl.Set(span, r.URL.String())
            ext.Component.Set(span, "api-gateway")
            
            // Add span to context
            ctx := opentracing.ContextWithSpan(r.Context(), span)
            
            // Wrap response writer to capture status code
            wrapped := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
            
            // Continue with request
            next.ServeHTTP(wrapped, r.WithContext(ctx))
            
            // Set response status
            ext.HTTPStatusCode.Set(span, uint16(wrapped.statusCode))
            if wrapped.statusCode >= 400 {
                ext.Error.Set(span, true)
            }
        })
    }
}
```

### Metrics Collection

```go
// pkg/gateway/metrics.go
package gateway

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
    requestsTotal       *prometheus.CounterVec
    requestDuration     *prometheus.HistogramVec
    requestSize         *prometheus.HistogramVec
    responseSize        *prometheus.HistogramVec
    activeConnections   prometheus.Gauge
    healthCheckDuration *prometheus.HistogramVec
    cacheHits           *prometheus.CounterVec
    rateLimitHits       *prometheus.CounterVec
}

func NewMetrics() *Metrics {
    return &Metrics{
        requestsTotal: promauto.NewCounterVec(
            prometheus.CounterOpts{
                Name: "gateway_requests_total",
                Help: "Total number of requests processed",
            },
            []string{"method", "path", "service", "status"},
        ),
        
        requestDuration: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "gateway_request_duration_seconds",
                Help:    "Request duration in seconds",
                Buckets: prometheus.DefBuckets,
            },
            []string{"method", "path", "service"},
        ),
        
        requestSize: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "gateway_request_size_bytes",
                Help:    "Request size in bytes",
                Buckets: prometheus.ExponentialBuckets(100, 10, 7),
            },
            []string{"method", "path", "service"},
        ),
        
        responseSize: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "gateway_response_size_bytes",
                Help:    "Response size in bytes",
                Buckets: prometheus.ExponentialBuckets(100, 10, 7),
            },
            []string{"method", "path", "service"},
        ),
        
        activeConnections: promauto.NewGauge(
            prometheus.GaugeOpts{
                Name: "gateway_active_connections",
                Help: "Number of active connections",
            },
        ),
        
        healthCheckDuration: promauto.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "gateway_health_check_duration_seconds",
                Help:    "Health check duration in seconds",
                Buckets: prometheus.DefBuckets,
            },
            []string{"service", "instance"},
        ),
        
        cacheHits: promauto.NewCounterVec(
            prometheus.CounterOpts{
                Name: "gateway_cache_hits_total",
                Help: "Total number of cache hits",
            },
            []string{"path", "status"},
        ),
        
        rateLimitHits: promauto.NewCounterVec(
            prometheus.CounterOpts{
                Name: "gateway_rate_limit_hits_total",
                Help: "Total number of rate limit hits",
            },
            []string{"path", "user_type"},
        ),
    }
}

// Metrics middleware
func MetricsMiddleware(metrics *Metrics) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            
            // Track active connections
            metrics.activeConnections.Inc()
            defer metrics.activeConnections.Dec()
            
            // Wrap response writer
            wrapped := &metricsResponseWriter{
                ResponseWriter: w,
                statusCode:     http.StatusOK,
                bytesWritten:   0,
            }
            
            // Get service name from path
            service := getServiceFromPath(r.URL.Path)
            
            // Continue with request
            next.ServeHTTP(wrapped, r)
            
            // Record metrics
            duration := time.Since(start).Seconds()
            
            metrics.requestsTotal.WithLabelValues(
                r.Method,
                r.URL.Path,
                service,
                fmt.Sprintf("%d", wrapped.statusCode),
            ).Inc()
            
            metrics.requestDuration.WithLabelValues(
                r.Method,
                r.URL.Path,
                service,
            ).Observe(duration)
            
            if r.ContentLength > 0 {
                metrics.requestSize.WithLabelValues(
                    r.Method,
                    r.URL.Path,
                    service,
                ).Observe(float64(r.ContentLength))
            }
            
            metrics.responseSize.WithLabelValues(
                r.Method,
                r.URL.Path,
                service,
            ).Observe(float64(wrapped.bytesWritten))
        })
    }
}
```

### Structured Logging

```go
// pkg/gateway/logging.go
package gateway

import (
    "time"
    
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
)

func LoggingMiddleware(logger *zap.Logger) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            
            // Get request ID
            requestID := r.Header.Get("X-Request-ID")
            if requestID == "" {
                requestID = generateRequestID()
            }
            
            // Create request logger
            reqLogger := logger.With(
                zap.String("request_id", requestID),
                zap.String("method", r.Method),
                zap.String("path", r.URL.Path),
                zap.String("remote_addr", r.RemoteAddr),
                zap.String("user_agent", r.UserAgent()),
            )
            
            // Log request
            reqLogger.Info("Request started")
            
            // Wrap response writer
            wrapped := &loggingResponseWriter{
                ResponseWriter: w,
                statusCode:     http.StatusOK,
                bytesWritten:   0,
            }
            
            // Add request ID to response
            w.Header().Set("X-Request-ID", requestID)
            
            // Continue with request
            next.ServeHTTP(wrapped, r)
            
            // Log response
            duration := time.Since(start)
            
            fields := []zapcore.Field{
                zap.Int("status", wrapped.statusCode),
                zap.Int64("bytes", wrapped.bytesWritten),
                zap.Duration("duration", duration),
            }
            
            if wrapped.statusCode >= 400 {
                reqLogger.Error("Request failed", fields...)
            } else {
                reqLogger.Info("Request completed", fields...)
            }
        })
    }
}
```

## 10. Acceptance Criteria

### Performance Criteria
- **Latency**: Sub-50ms P99 latency overhead for request routing
- **Throughput**: Handle 100,000 requests per second per gateway instance
- **Connection Handling**: Support 50,000 concurrent connections
- **Memory Usage**: Less than 1GB RAM under normal load
- **CPU Usage**: Less than 80% CPU utilization under peak load

### Reliability Criteria
- **Availability**: 99.99% uptime (less than 4.38 minutes downtime per month)
- **Zero-downtime Deployments**: Support rolling updates without service interruption
- **Graceful Degradation**: Continue operating with degraded functionality if backend services fail
- **Circuit Breaking**: Automatically isolate failing services
- **Request Retries**: Automatic retry with exponential backoff for transient failures

### Integration Criteria
- **All Services Integrated**: Successfully route to all 5 core services
- **Protocol Support**: Full support for REST, gRPC, and WebSocket
- **Authentication**: Support JWT, API keys, and DID authentication
- **Service Discovery**: Automatic discovery and routing to new service instances
- **Health Checking**: Continuous health monitoring of all backend services

### Security Criteria
- **TLS Support**: TLS 1.3 for all external connections
- **Authentication**: Validate all requests with proper authentication
- **Rate Limiting**: Enforce rate limits per user and IP
- **DDoS Protection**: Implement request filtering and rate limiting
- **Security Headers**: Add appropriate security headers to all responses

### Operational Criteria
- **Monitoring**: Export metrics to Prometheus
- **Tracing**: Full distributed tracing with Jaeger
- **Logging**: Structured logging with request correlation
- **Configuration**: Hot-reloadable configuration
- **Debugging**: Request tracing and debug endpoints

## Testing Strategy

### Unit Tests
```bash
go test ./pkg/gateway/... -v -cover
```

### Integration Tests
```go
// Test service discovery integration
func TestServiceDiscovery(t *testing.T) {
    // Test service registration
    // Test service discovery
    // Test health checking
    // Test watch functionality
}

// Test load balancing algorithms
func TestLoadBalancing(t *testing.T) {
    // Test round-robin
    // Test least connections
    // Test consistent hashing
    // Test weighted distribution
}
```

### Load Tests
```bash
# Using k6 for load testing
k6 run --vus 1000 --duration 5m loadtest.js
```

### Chaos Testing
- Randomly kill backend services
- Introduce network latency
- Simulate service overload
- Test circuit breaker activation

This completes the comprehensive implementation design for the API Gateway unit, providing a production-ready gateway that unifies access to all Blackhole platform services with high performance, reliability, and security.