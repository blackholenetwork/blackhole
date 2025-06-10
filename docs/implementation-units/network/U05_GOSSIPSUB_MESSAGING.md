# Unit U05: GossipSub Messaging Implementation

## 1. Unit Overview

### Purpose
Implement GossipSub v1.1 protocol for efficient publish-subscribe messaging across the Blackhole network, enabling real-time updates for service discovery, state synchronization, and event propagation.

### Dependencies
- **U01**: libp2p Core Setup (peer connections, transport layer)
- **U02**: Kademlia DHT Implementation (peer discovery, routing)

### Deliverables
- GossipSub v1.1 protocol implementation with custom parameters
- Topic management system with namespaced topics
- Message validation and signing framework
- Rate limiting and spam prevention
- Integration hooks for service-specific handlers

### Integration Points
- Service discovery announcements via DHT
- State synchronization for distributed services
- Real-time event notifications
- Health monitoring and metrics propagation

## 2. Technical Specifications

### GossipSub v1.1 Protocol Parameters

```go
// pkg/pubsub/config.go
package pubsub

import (
    "time"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// GossipSubParams defines our custom GossipSub parameters
var GossipSubParams = pubsub.GossipSubParams{
    // Network size parameters
    D:   6,  // Target degree (number of peers in mesh)
    Dlo: 4,  // Lower bound for mesh degree
    Dhi: 12, // Upper bound for mesh degree
    
    // Gossip parameters
    Dlazy:             6,    // Gossip degree
    GossipFactor:      0.25, // Gossip emission factor
    Gossip:            3,    // Number of history windows to gossip
    
    // Heartbeat parameters
    HeartbeatInterval: 700 * time.Millisecond,
    HeartbeatInitialDelay: 100 * time.Millisecond,
    
    // History parameters
    HistoryLength:  6,  // Number of heartbeat intervals to retain messages
    HistoryGossip:  3,  // Number of windows to gossip about
    
    // Flood publishing parameters
    FloodPublish:       true,  // Enable flood publishing for low latency
    
    // Peer scoring thresholds
    GossipThreshold:       -100,
    PublishThreshold:      -500,
    GraylistThreshold:     -1000,
    AcceptPXThreshold:     0,
    OpportunisticGraftThreshold: 5,
}

// TopicScoreParams defines scoring parameters for topics
func GetTopicScoreParams(topicName string) *pubsub.TopicScoreParams {
    return &pubsub.TopicScoreParams{
        // Time in mesh parameters
        TimeInMeshWeight:  0.01,
        TimeInMeshQuantum: time.Second,
        TimeInMeshCap:     36000, // 10 hours
        
        // First message deliveries
        FirstMessageDeliveriesWeight: 1,
        FirstMessageDeliveriesDecay:  0.5,
        FirstMessageDeliveriesCap:    100,
        
        // Mesh message deliveries
        MeshMessageDeliveriesWeight:     -0.1,
        MeshMessageDeliveriesDecay:      0.5,
        MeshMessageDeliveriesThreshold:  5,
        MeshMessageDeliveriesCap:        100,
        MeshMessageDeliveriesActivation: 30 * time.Second,
        MeshMessageDeliveriesWindow:     5 * time.Minute,
        
        // Invalid messages
        InvalidMessageDeliveriesWeight: -100,
        InvalidMessageDeliveriesDecay:  0.9,
        
        // Topic weight based on importance
        TopicWeight: getTopicWeight(topicName),
    }
}

func getTopicWeight(topic string) float64 {
    weights := map[string]float64{
        "/blackhole/compute/jobs":      1.0,
        "/blackhole/storage/updates":   0.8,
        "/blackhole/cdn/cache":         0.7,
        "/blackhole/bandwidth/routes":  0.6,
        "/blackhole/system/health":     0.5,
    }
    
    if weight, ok := weights[topic]; ok {
        return weight
    }
    return 0.1 // Default weight for unknown topics
}
```

### Topic Structure

```go
// pkg/pubsub/topics.go
package pubsub

import (
    "fmt"
    "strings"
)

// Topic represents a pubsub topic
type Topic struct {
    Namespace string
    Service   string
    Event     string
}

// String returns the full topic path
func (t Topic) String() string {
    return fmt.Sprintf("/%s/%s/%s", t.Namespace, t.Service, t.Event)
}

// ParseTopic parses a topic string into components
func ParseTopic(topic string) (*Topic, error) {
    parts := strings.Split(strings.TrimPrefix(topic, "/"), "/")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid topic format: %s", topic)
    }
    
    return &Topic{
        Namespace: parts[0],
        Service:   parts[1],
        Event:     parts[2],
    }, nil
}

// Predefined topics
var (
    // Compute service topics
    TopicComputeJobs = Topic{"blackhole", "compute", "jobs"}
    TopicComputeResults = Topic{"blackhole", "compute", "results"}
    TopicComputeStatus = Topic{"blackhole", "compute", "status"}
    
    // Storage service topics
    TopicStorageUpdates = Topic{"blackhole", "storage", "updates"}
    TopicStorageReplication = Topic{"blackhole", "storage", "replication"}
    TopicStorageHealth = Topic{"blackhole", "storage", "health"}
    
    // CDN service topics
    TopicCDNCache = Topic{"blackhole", "cdn", "cache"}
    TopicCDNInvalidation = Topic{"blackhole", "cdn", "invalidation"}
    TopicCDNMetrics = Topic{"blackhole", "cdn", "metrics"}
    
    // Bandwidth service topics
    TopicBandwidthRoutes = Topic{"blackhole", "bandwidth", "routes"}
    TopicBandwidthUsage = Topic{"blackhole", "bandwidth", "usage"}
    TopicBandwidthHealth = Topic{"blackhole", "bandwidth", "health"}
    
    // System topics
    TopicSystemHealth = Topic{"blackhole", "system", "health"}
    TopicSystemAlerts = Topic{"blackhole", "system", "alerts"}
    TopicSystemMetrics = Topic{"blackhole", "system", "metrics"}
)

// TopicAccessPolicy defines access control for topics
type TopicAccessPolicy struct {
    RequireAuthentication bool
    RequirePermission     string
    RateLimit            int // messages per minute
    MaxMessageSize       int // bytes
}

// GetTopicPolicy returns the access policy for a topic
func GetTopicPolicy(topic string) TopicAccessPolicy {
    policies := map[string]TopicAccessPolicy{
        TopicComputeJobs.String(): {
            RequireAuthentication: true,
            RequirePermission:     "compute.submit",
            RateLimit:            60,
            MaxMessageSize:       1024 * 1024, // 1MB
        },
        TopicStorageUpdates.String(): {
            RequireAuthentication: true,
            RequirePermission:     "storage.provider",
            RateLimit:            120,
            MaxMessageSize:       64 * 1024, // 64KB
        },
        TopicSystemHealth.String(): {
            RequireAuthentication: false,
            RequirePermission:     "",
            RateLimit:            10,
            MaxMessageSize:       4 * 1024, // 4KB
        },
    }
    
    if policy, ok := policies[topic]; ok {
        return policy
    }
    
    // Default policy
    return TopicAccessPolicy{
        RequireAuthentication: true,
        RequirePermission:     "",
        RateLimit:            30,
        MaxMessageSize:       32 * 1024, // 32KB
    }
}
```

### Message Validation and Signing

```go
// pkg/pubsub/validation.go
package pubsub

import (
    "context"
    "crypto/sha256"
    "fmt"
    "time"
    
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "github.com/libp2p/go-libp2p/core/peer"
    "google.golang.org/protobuf/proto"
)

// MessageValidator handles message validation
type MessageValidator struct {
    host         Host
    authService  AuthService
    rateLimiter  *RateLimiter
    messageCache *MessageCache
}

// NewMessageValidator creates a new message validator
func NewMessageValidator(host Host, auth AuthService) *MessageValidator {
    return &MessageValidator{
        host:         host,
        authService:  auth,
        rateLimiter:  NewRateLimiter(),
        messageCache: NewMessageCache(10000, 5*time.Minute),
    }
}

// Validate implements the pubsub validator interface
func (v *MessageValidator) Validate(ctx context.Context, pid peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
    // Check message size
    policy := GetTopicPolicy(msg.GetTopic())
    if len(msg.Data) > policy.MaxMessageSize {
        return pubsub.ValidationReject
    }
    
    // Check rate limit
    if !v.rateLimiter.Allow(pid, msg.GetTopic(), policy.RateLimit) {
        return pubsub.ValidationIgnore
    }
    
    // Check for duplicate messages
    msgID := v.calculateMessageID(msg)
    if v.messageCache.Has(msgID) {
        return pubsub.ValidationIgnore
    }
    v.messageCache.Add(msgID)
    
    // Parse and validate message
    var envelope MessageEnvelope
    if err := proto.Unmarshal(msg.Data, &envelope); err != nil {
        return pubsub.ValidationReject
    }
    
    // Verify timestamp
    if err := v.validateTimestamp(envelope.Timestamp); err != nil {
        return pubsub.ValidationReject
    }
    
    // Verify signature if required
    if policy.RequireAuthentication {
        if err := v.verifySignature(&envelope, pid); err != nil {
            return pubsub.ValidationReject
        }
        
        // Check permissions
        if policy.RequirePermission != "" {
            if !v.authService.HasPermission(envelope.SenderId, policy.RequirePermission) {
                return pubsub.ValidationReject
            }
        }
    }
    
    // Topic-specific validation
    if err := v.validateTopicMessage(msg.GetTopic(), &envelope); err != nil {
        return pubsub.ValidationReject
    }
    
    return pubsub.ValidationAccept
}

func (v *MessageValidator) calculateMessageID(msg *pubsub.Message) string {
    h := sha256.New()
    h.Write([]byte(msg.GetFrom().String()))
    h.Write(msg.Data)
    return fmt.Sprintf("%x", h.Sum(nil))
}

func (v *MessageValidator) validateTimestamp(timestamp int64) error {
    msgTime := time.Unix(timestamp, 0)
    now := time.Now()
    
    // Reject messages from the future
    if msgTime.After(now.Add(30 * time.Second)) {
        return fmt.Errorf("message timestamp in future")
    }
    
    // Reject old messages
    if msgTime.Before(now.Add(-5 * time.Minute)) {
        return fmt.Errorf("message timestamp too old")
    }
    
    return nil
}

func (v *MessageValidator) verifySignature(envelope *MessageEnvelope, pid peer.ID) error {
    // Reconstruct the message for verification
    msg := &BaseMessage{
        Type:      envelope.Type,
        Payload:   envelope.Payload,
        Timestamp: envelope.Timestamp,
        SenderId:  envelope.SenderId,
    }
    
    data, err := proto.Marshal(msg)
    if err != nil {
        return err
    }
    
    // Get peer's public key
    pubKey, err := pid.ExtractPublicKey()
    if err != nil {
        return err
    }
    
    // Verify signature
    ok, err := pubKey.Verify(data, envelope.Signature)
    if err != nil {
        return err
    }
    if !ok {
        return fmt.Errorf("invalid signature")
    }
    
    return nil
}

func (v *MessageValidator) validateTopicMessage(topic string, envelope *MessageEnvelope) error {
    parsedTopic, err := ParseTopic(topic)
    if err != nil {
        return err
    }
    
    switch parsedTopic.Service {
    case "compute":
        return v.validateComputeMessage(parsedTopic.Event, envelope)
    case "storage":
        return v.validateStorageMessage(parsedTopic.Event, envelope)
    case "cdn":
        return v.validateCDNMessage(parsedTopic.Event, envelope)
    case "bandwidth":
        return v.validateBandwidthMessage(parsedTopic.Event, envelope)
    case "system":
        return v.validateSystemMessage(parsedTopic.Event, envelope)
    default:
        return fmt.Errorf("unknown service: %s", parsedTopic.Service)
    }
}
```

### Flood Control and Rate Limiting

```go
// pkg/pubsub/ratelimit.go
package pubsub

import (
    "sync"
    "time"
    
    "github.com/libp2p/go-libp2p/core/peer"
    "golang.org/x/time/rate"
)

// RateLimiter manages rate limiting for peers and topics
type RateLimiter struct {
    mu       sync.RWMutex
    limiters map[string]*rate.Limiter
    cleanup  *time.Ticker
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
    rl := &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        cleanup:  time.NewTicker(5 * time.Minute),
    }
    
    go rl.cleanupLoop()
    return rl
}

// Allow checks if a message is allowed
func (rl *RateLimiter) Allow(pid peer.ID, topic string, limit int) bool {
    key := fmt.Sprintf("%s:%s", pid.String(), topic)
    
    rl.mu.Lock()
    limiter, exists := rl.limiters[key]
    if !exists {
        // Create new limiter with burst of 10
        limiter = rate.NewLimiter(rate.Limit(float64(limit)/60.0), 10)
        rl.limiters[key] = limiter
    }
    rl.mu.Unlock()
    
    return limiter.Allow()
}

// cleanupLoop removes inactive limiters
func (rl *RateLimiter) cleanupLoop() {
    for range rl.cleanup.C {
        rl.mu.Lock()
        // Remove limiters that haven't been used recently
        // Implementation details omitted for brevity
        rl.mu.Unlock()
    }
}

// FloodController manages flood control across topics
type FloodController struct {
    mu              sync.RWMutex
    messageCount    map[string]int
    windowStart     time.Time
    windowDuration  time.Duration
    maxMessagesPerWindow int
}

// NewFloodController creates a new flood controller
func NewFloodController(windowDuration time.Duration, maxMessages int) *FloodController {
    return &FloodController{
        messageCount:         make(map[string]int),
        windowStart:          time.Now(),
        windowDuration:       windowDuration,
        maxMessagesPerWindow: maxMessages,
    }
}

// CheckFlood checks if network is experiencing message flood
func (fc *FloodController) CheckFlood(topic string) bool {
    fc.mu.Lock()
    defer fc.mu.Unlock()
    
    // Reset window if needed
    if time.Since(fc.windowStart) > fc.windowDuration {
        fc.messageCount = make(map[string]int)
        fc.windowStart = time.Now()
    }
    
    fc.messageCount[topic]++
    return fc.messageCount[topic] > fc.maxMessagesPerWindow
}
```

## 3. Implementation Details

### Topic Naming Conventions

Topics follow a hierarchical naming structure:
```
/{namespace}/{service}/{event}
```

Examples:
- `/blackhole/compute/jobs` - New compute job announcements
- `/blackhole/storage/updates` - Storage availability updates
- `/blackhole/cdn/cache` - CDN cache invalidation events
- `/blackhole/bandwidth/routes` - Bandwidth routing updates
- `/blackhole/system/health` - Node health status updates

### Message Formats (Protobuf)

```protobuf
// pkg/pubsub/messages.proto
syntax = "proto3";
package blackhole.pubsub;
option go_package = "github.com/blackhole/pkg/pubsub";

// Base message structure
message BaseMessage {
    string type = 1;
    bytes payload = 2;
    int64 timestamp = 3;
    string sender_id = 4;
}

// Message envelope with signature
message MessageEnvelope {
    string type = 1;
    bytes payload = 2;
    int64 timestamp = 3;
    string sender_id = 4;
    bytes signature = 5;
}

// Compute job announcement
message JobAnnouncement {
    string job_id = 1;
    string job_type = 2;
    int64 cpu_requirements = 3;
    int64 memory_requirements = 4;
    int64 gpu_requirements = 5;
    int64 duration_estimate = 6;
    double payment_amount = 7;
    string payment_token = 8;
    repeated string preferred_regions = 9;
    map<string, string> metadata = 10;
}

// Storage availability update
message StorageUpdate {
    string provider_id = 1;
    int64 available_space = 2;
    int64 used_space = 3;
    double price_per_gb_month = 4;
    repeated string supported_protocols = 5;
    repeated string regions = 6;
    int32 replication_factor = 7;
    map<string, string> capabilities = 8;
}

// CDN cache invalidation
message CacheInvalidation {
    string content_id = 1;
    repeated string affected_paths = 2;
    int64 invalidation_time = 3;
    string reason = 4;
    bool recursive = 5;
}

// Bandwidth route update
message RouteUpdate {
    string node_id = 1;
    repeated Route routes = 2;
    int64 bandwidth_available = 3;
    double price_per_gb = 4;
    repeated string supported_protocols = 5;
}

message Route {
    string destination = 1;
    int32 hop_count = 2;
    int64 latency_ms = 3;
    double packet_loss = 4;
}

// Health check message
message HealthCheck {
    string node_id = 1;
    int64 timestamp = 2;
    double cpu_usage = 3;
    double memory_usage = 4;
    double disk_usage = 5;
    int64 network_in = 6;
    int64 network_out = 7;
    map<string, ServiceHealth> services = 8;
}

message ServiceHealth {
    bool healthy = 1;
    int64 uptime = 2;
    map<string, string> metrics = 3;
}
```

### Subscription Management

```go
// pkg/pubsub/subscription.go
package pubsub

import (
    "context"
    "sync"
    
    pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// SubscriptionManager manages topic subscriptions
type SubscriptionManager struct {
    mu            sync.RWMutex
    pubsub        *pubsub.PubSub
    subscriptions map[string]*Subscription
    handlers      map[string][]MessageHandler
}

// Subscription represents an active topic subscription
type Subscription struct {
    Topic        string
    subscription *pubsub.Subscription
    cancel       context.CancelFunc
    handlers     []MessageHandler
}

// MessageHandler processes incoming messages
type MessageHandler func(ctx context.Context, msg *Message) error

// Message represents a decoded pubsub message
type Message struct {
    Topic     string
    Type      string
    Payload   []byte
    Timestamp time.Time
    SenderID  string
    Envelope  *MessageEnvelope
}

// NewSubscriptionManager creates a new subscription manager
func NewSubscriptionManager(ps *pubsub.PubSub) *SubscriptionManager {
    return &SubscriptionManager{
        pubsub:        ps,
        subscriptions: make(map[string]*Subscription),
        handlers:      make(map[string][]MessageHandler),
    }
}

// Subscribe to a topic with handlers
func (sm *SubscriptionManager) Subscribe(ctx context.Context, topic string, handlers ...MessageHandler) error {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    // Check if already subscribed
    if _, exists := sm.subscriptions[topic]; exists {
        // Add new handlers
        sm.handlers[topic] = append(sm.handlers[topic], handlers...)
        return nil
    }
    
    // Join topic
    topicHandle, err := sm.pubsub.Join(topic)
    if err != nil {
        return fmt.Errorf("failed to join topic %s: %w", topic, err)
    }
    
    // Subscribe to topic
    sub, err := topicHandle.Subscribe()
    if err != nil {
        return fmt.Errorf("failed to subscribe to topic %s: %w", topic, err)
    }
    
    // Create subscription context
    subCtx, cancel := context.WithCancel(ctx)
    
    subscription := &Subscription{
        Topic:        topic,
        subscription: sub,
        cancel:       cancel,
        handlers:     handlers,
    }
    
    sm.subscriptions[topic] = subscription
    sm.handlers[topic] = handlers
    
    // Start message processing
    go sm.processMessages(subCtx, subscription)
    
    return nil
}

// Unsubscribe from a topic
func (sm *SubscriptionManager) Unsubscribe(topic string) error {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    
    sub, exists := sm.subscriptions[topic]
    if !exists {
        return fmt.Errorf("not subscribed to topic %s", topic)
    }
    
    // Cancel subscription context
    sub.cancel()
    
    // Close subscription
    sub.subscription.Cancel()
    
    // Remove from maps
    delete(sm.subscriptions, topic)
    delete(sm.handlers, topic)
    
    return nil
}

// processMessages handles incoming messages for a subscription
func (sm *SubscriptionManager) processMessages(ctx context.Context, sub *Subscription) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            msg, err := sub.subscription.Next(ctx)
            if err != nil {
                if err == context.Canceled {
                    return
                }
                // Log error and continue
                continue
            }
            
            // Decode message
            decoded, err := sm.decodeMessage(msg)
            if err != nil {
                // Log error and continue
                continue
            }
            
            // Execute handlers
            sm.executeHandlers(ctx, sub.Topic, decoded)
        }
    }
}

// decodeMessage decodes a pubsub message
func (sm *SubscriptionManager) decodeMessage(msg *pubsub.Message) (*Message, error) {
    var envelope MessageEnvelope
    if err := proto.Unmarshal(msg.Data, &envelope); err != nil {
        return nil, err
    }
    
    return &Message{
        Topic:     msg.GetTopic(),
        Type:      envelope.Type,
        Payload:   envelope.Payload,
        Timestamp: time.Unix(envelope.Timestamp, 0),
        SenderID:  envelope.SenderId,
        Envelope:  &envelope,
    }, nil
}

// executeHandlers runs all handlers for a message
func (sm *SubscriptionManager) executeHandlers(ctx context.Context, topic string, msg *Message) {
    sm.mu.RLock()
    handlers := sm.handlers[topic]
    sm.mu.RUnlock()
    
    for _, handler := range handlers {
        go func(h MessageHandler) {
            if err := h(ctx, msg); err != nil {
                // Log error
            }
        }(handler)
    }
}
```

### Message Validation Functions

```go
// pkg/pubsub/validators.go
package pubsub

import (
    "fmt"
    "google.golang.org/protobuf/proto"
)

// validateComputeMessage validates compute service messages
func (v *MessageValidator) validateComputeMessage(event string, envelope *MessageEnvelope) error {
    switch event {
    case "jobs":
        var job JobAnnouncement
        if err := proto.Unmarshal(envelope.Payload, &job); err != nil {
            return err
        }
        return v.validateJobAnnouncement(&job)
        
    case "results":
        // Validate result messages
        return nil
        
    case "status":
        // Validate status messages
        return nil
        
    default:
        return fmt.Errorf("unknown compute event: %s", event)
    }
}

func (v *MessageValidator) validateJobAnnouncement(job *JobAnnouncement) error {
    // Validate job ID
    if job.JobId == "" {
        return fmt.Errorf("job ID required")
    }
    
    // Validate resource requirements
    if job.CpuRequirements <= 0 {
        return fmt.Errorf("invalid CPU requirements")
    }
    if job.MemoryRequirements <= 0 {
        return fmt.Errorf("invalid memory requirements")
    }
    
    // Validate payment
    if job.PaymentAmount <= 0 {
        return fmt.Errorf("invalid payment amount")
    }
    if job.PaymentToken == "" {
        return fmt.Errorf("payment token required")
    }
    
    return nil
}

// validateStorageMessage validates storage service messages
func (v *MessageValidator) validateStorageMessage(event string, envelope *MessageEnvelope) error {
    switch event {
    case "updates":
        var update StorageUpdate
        if err := proto.Unmarshal(envelope.Payload, &update); err != nil {
            return err
        }
        return v.validateStorageUpdate(&update)
        
    case "replication":
        // Validate replication messages
        return nil
        
    case "health":
        // Validate health messages
        return nil
        
    default:
        return fmt.Errorf("unknown storage event: %s", event)
    }
}

func (v *MessageValidator) validateStorageUpdate(update *StorageUpdate) error {
    // Validate provider ID
    if update.ProviderId == "" {
        return fmt.Errorf("provider ID required")
    }
    
    // Validate space values
    if update.AvailableSpace < 0 || update.UsedSpace < 0 {
        return fmt.Errorf("invalid space values")
    }
    
    // Validate pricing
    if update.PricePerGbMonth < 0 {
        return fmt.Errorf("invalid price")
    }
    
    // Validate replication factor
    if update.ReplicationFactor < 1 || update.ReplicationFactor > 10 {
        return fmt.Errorf("invalid replication factor")
    }
    
    return nil
}
```

## 4. Code Structure

```
pkg/pubsub/
├── gossipsub.go          # Main GossipSub implementation
├── topics.go             # Topic management and naming
├── messages.go           # Message type definitions
├── messages.proto        # Protobuf message definitions
├── validation.go         # Message validation logic
├── validators.go         # Service-specific validators
├── subscription.go       # Subscription management
├── handlers.go           # Default message handlers
├── ratelimit.go         # Rate limiting implementation
├── config.go            # Configuration parameters
├── metrics.go           # Metrics collection
└── tests/
    ├── gossipsub_test.go
    ├── validation_test.go
    └── integration_test.go
```

### Main GossipSub Implementation

```go
// pkg/pubsub/gossipsub.go
package pubsub

import (
    "context"
    "fmt"
    "time"
    
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "google.golang.org/protobuf/proto"
)

// GossipSub manages the GossipSub protocol
type GossipSub struct {
    host       host.Host
    pubsub     *pubsub.PubSub
    validator  *MessageValidator
    subManager *SubscriptionManager
    metrics    *Metrics
}

// NewGossipSub creates a new GossipSub instance
func NewGossipSub(ctx context.Context, h host.Host, auth AuthService) (*GossipSub, error) {
    // Create peer score params
    peerScoreParams := &pubsub.PeerScoreParams{
        Topics:        make(map[string]*pubsub.TopicScoreParams),
        AppSpecificScore: func(p peer.ID) float64 {
            // Custom peer scoring based on reputation
            return 0
        },
        DecayInterval: time.Minute,
        DecayToZero:   0.01,
    }
    
    // Create peer score thresholds
    peerScoreThresholds := &pubsub.PeerScoreThresholds{
        GossipThreshold:             -100,
        PublishThreshold:            -500,
        GraylistThreshold:           -1000,
        AcceptPXThreshold:           0,
        OpportunisticGraftThreshold: 5,
    }
    
    // Create GossipSub with custom parameters
    ps, err := pubsub.NewGossipSub(
        ctx,
        h,
        pubsub.WithPeerScore(peerScoreParams, peerScoreThresholds),
        pubsub.WithGossipSubParams(GossipSubParams),
        pubsub.WithMessageSigning(true),
        pubsub.WithStrictSignatureVerification(true),
        pubsub.WithFloodPublish(true),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create gossipsub: %w", err)
    }
    
    // Create components
    validator := NewMessageValidator(h, auth)
    subManager := NewSubscriptionManager(ps)
    metrics := NewMetrics()
    
    gs := &GossipSub{
        host:       h,
        pubsub:     ps,
        validator:  validator,
        subManager: subManager,
        metrics:    metrics,
    }
    
    // Register validators for all topics
    gs.registerValidators()
    
    return gs, nil
}

// registerValidators registers message validators for topics
func (gs *GossipSub) registerValidators() {
    topics := []string{
        TopicComputeJobs.String(),
        TopicComputeResults.String(),
        TopicComputeStatus.String(),
        TopicStorageUpdates.String(),
        TopicStorageReplication.String(),
        TopicStorageHealth.String(),
        TopicCDNCache.String(),
        TopicCDNInvalidation.String(),
        TopicCDNMetrics.String(),
        TopicBandwidthRoutes.String(),
        TopicBandwidthUsage.String(),
        TopicBandwidthHealth.String(),
        TopicSystemHealth.String(),
        TopicSystemAlerts.String(),
        TopicSystemMetrics.String(),
    }
    
    for _, topic := range topics {
        gs.pubsub.RegisterTopicValidator(topic, gs.validator.Validate)
    }
}

// Publish publishes a message to a topic
func (gs *GossipSub) Publish(ctx context.Context, topic Topic, msgType string, payload interface{}) error {
    // Marshal payload
    data, err := proto.Marshal(payload.(proto.Message))
    if err != nil {
        return fmt.Errorf("failed to marshal payload: %w", err)
    }
    
    // Create base message
    baseMsg := &BaseMessage{
        Type:      msgType,
        Payload:   data,
        Timestamp: time.Now().Unix(),
        SenderId:  gs.host.ID().String(),
    }
    
    // Marshal base message
    msgData, err := proto.Marshal(baseMsg)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }
    
    // Sign message
    privKey := gs.host.Peerstore().PrivKey(gs.host.ID())
    signature, err := privKey.Sign(msgData)
    if err != nil {
        return fmt.Errorf("failed to sign message: %w", err)
    }
    
    // Create envelope
    envelope := &MessageEnvelope{
        Type:      msgType,
        Payload:   data,
        Timestamp: baseMsg.Timestamp,
        SenderId:  baseMsg.SenderId,
        Signature: signature,
    }
    
    // Marshal envelope
    envelopeData, err := proto.Marshal(envelope)
    if err != nil {
        return fmt.Errorf("failed to marshal envelope: %w", err)
    }
    
    // Get or create topic handle
    topicHandle, err := gs.pubsub.Join(topic.String())
    if err != nil {
        return fmt.Errorf("failed to join topic: %w", err)
    }
    
    // Publish message
    err = topicHandle.Publish(ctx, envelopeData)
    if err != nil {
        return fmt.Errorf("failed to publish message: %w", err)
    }
    
    // Update metrics
    gs.metrics.MessagePublished(topic.String())
    
    return nil
}

// Subscribe subscribes to a topic with handlers
func (gs *GossipSub) Subscribe(ctx context.Context, topic Topic, handlers ...MessageHandler) error {
    return gs.subManager.Subscribe(ctx, topic.String(), handlers...)
}

// Unsubscribe unsubscribes from a topic
func (gs *GossipSub) Unsubscribe(topic Topic) error {
    return gs.subManager.Unsubscribe(topic.String())
}

// GetPeers returns peers subscribed to a topic
func (gs *GossipSub) GetPeers(topic Topic) []peer.ID {
    return gs.pubsub.ListPeers(topic.String())
}

// GetTopics returns all topics we're subscribed to
func (gs *GossipSub) GetTopics() []string {
    return gs.pubsub.GetTopics()
}

// Close shuts down the GossipSub system
func (gs *GossipSub) Close() error {
    // Unsubscribe from all topics
    for _, topic := range gs.GetTopics() {
        if err := gs.subManager.Unsubscribe(topic); err != nil {
            // Log error
        }
    }
    
    return nil
}
```

## 5. Key Topics

The following topics are predefined for core services:

### Compute Service Topics
- `/blackhole/compute/jobs` - New compute job announcements
- `/blackhole/compute/results` - Job completion results
- `/blackhole/compute/status` - Job status updates

### Storage Service Topics
- `/blackhole/storage/updates` - Storage availability and pricing
- `/blackhole/storage/replication` - Replication requests and confirmations
- `/blackhole/storage/health` - Storage node health status

### CDN Service Topics
- `/blackhole/cdn/cache` - Cache warming requests
- `/blackhole/cdn/invalidation` - Cache invalidation events
- `/blackhole/cdn/metrics` - CDN performance metrics

### Bandwidth Service Topics
- `/blackhole/bandwidth/routes` - Available routes and pricing
- `/blackhole/bandwidth/usage` - Bandwidth usage reports
- `/blackhole/bandwidth/health` - Bandwidth node health

### System Topics
- `/blackhole/system/health` - General node health updates
- `/blackhole/system/alerts` - System-wide alerts
- `/blackhole/system/metrics` - Aggregated system metrics

## 6. Message Types

### JobAnnouncement
Announces new compute jobs available for execution:
- Job ID and type
- Resource requirements (CPU, memory, GPU)
- Duration estimate
- Payment details
- Preferred regions

### StorageUpdate
Updates storage availability and pricing:
- Provider ID
- Available/used space
- Pricing per GB/month
- Supported protocols
- Geographic regions
- Replication factor

### CacheInvalidation
Invalidates CDN cache entries:
- Content ID
- Affected paths
- Invalidation timestamp
- Reason for invalidation
- Recursive flag

### RouteUpdate
Updates bandwidth routing information:
- Node ID
- Available routes with metrics
- Bandwidth capacity
- Pricing information
- Supported protocols

### HealthCheck
Node health status updates:
- Node ID and timestamp
- Resource usage (CPU, memory, disk)
- Network I/O statistics
- Per-service health status

## 7. Security

### Message Signing
All messages are signed using the sender's libp2p private key:
1. Create base message with type, payload, timestamp, and sender ID
2. Marshal message to bytes
3. Sign with private key
4. Include signature in message envelope

### Topic Access Control
Topics enforce access policies:
- Authentication requirement
- Permission checks
- Rate limiting per peer
- Message size limits

### Spam Prevention
Multiple layers of spam protection:
1. **Peer scoring** - Tracks peer behavior and penalizes bad actors
2. **Rate limiting** - Per-peer, per-topic message limits
3. **Message validation** - Rejects malformed or invalid messages
4. **Flood control** - Network-wide message rate monitoring

### Sybil Resistance
Protection against Sybil attacks:
- Peer reputation system
- Proof of stake requirements for certain topics
- Connection limits per IP
- Behavioral analysis

## 8. Performance Optimization

### Message Batching
Messages can be batched for efficiency:
```go
type MessageBatch struct {
    messages []*MessageEnvelope
    topic    string
}

func (gs *GossipSub) PublishBatch(ctx context.Context, batch *MessageBatch) error {
    // Implementation for batched publishing
}
```

### Compression
Optional message compression for large payloads:
```go
func compressPayload(data []byte) ([]byte, error) {
    // Use zstd compression for payloads > 1KB
    if len(data) > 1024 {
        return zstd.Compress(nil, data)
    }
    return data, nil
}
```

### Topic Sharding
Large topics can be sharded for scalability:
```go
func getShardedTopic(base Topic, shardKey string) Topic {
    shard := hashToShard(shardKey, numShards)
    return Topic{
        Namespace: base.Namespace,
        Service:   base.Service,
        Event:     fmt.Sprintf("%s.shard%d", base.Event, shard),
    }
}
```

### Fanout Control
Adaptive fanout based on network conditions:
- Monitor message delivery rates
- Adjust D parameter dynamically
- Prioritize reliable peers

## 9. Testing Requirements

### Message Propagation Tests
```go
func TestMessagePropagation(t *testing.T) {
    // Create test network with 100 nodes
    // Publish message from one node
    // Verify 95% receive within 500ms
}
```

### Security Validation Tests
```go
func TestMessageValidation(t *testing.T) {
    // Test invalid signatures
    // Test expired timestamps
    // Test unauthorized access
    // Test rate limit enforcement
}
```

### Performance Under Load
```go
func TestHighThroughput(t *testing.T) {
    // Generate 10,000 msg/sec
    // Measure latency distribution
    // Verify no message loss
    // Check resource usage
}
```

### Network Partition Handling
```go
func TestNetworkPartition(t *testing.T) {
    // Create network partition
    // Verify message delivery after heal
    // Check duplicate handling
    // Measure recovery time
}
```

## 10. Acceptance Criteria

### Performance Metrics
- **Message delivery**: 95% of nodes receive messages within 500ms
- **Throughput**: Handle 10,000 messages/second network-wide
- **Latency**: P99 latency < 1 second under normal load
- **Reliability**: < 0.1% message loss rate

### Security Requirements
- **Spam resistance**: Effectively limit message rates per peer
- **Authentication**: All authenticated topics properly validated
- **Integrity**: 100% of messages pass signature verification
- **Access control**: Unauthorized messages rejected

### Functionality
- **Topic isolation**: Messages only delivered to subscribed peers
- **Multi-topic support**: Nodes can subscribe to multiple topics
- **Dynamic subscription**: Can subscribe/unsubscribe at runtime
- **Peer discovery**: Find peers interested in same topics

### Integration
- **Service discovery**: Integrates with DHT for peer finding
- **State sync**: Supports reliable state propagation
- **Event delivery**: Real-time event notification working
- **Monitoring**: Metrics exposed for all operations

## Conclusion

This implementation provides a robust, secure, and scalable pub/sub messaging system using GossipSub v1.1. It supports the real-time communication needs of all Blackhole services while maintaining security through message signing, access control, and spam prevention. The system is designed to scale to thousands of nodes while maintaining sub-second message delivery latency.