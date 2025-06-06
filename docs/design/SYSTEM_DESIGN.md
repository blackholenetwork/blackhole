# Blackhole Network - Complete System Design

## 1. Core Architecture Decisions

### Data Flow Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  API Layer  │────▶│    Core     │
└─────────────┘     └─────────────┘     └─────────────┘
                            │                    │
                            ▼                    ▼
                    ┌─────────────┐     ┌─────────────┐
                    │   Storage   │     │   Network   │
                    └─────────────┘     └─────────────┘
```

### State Management Strategy

**Decision: Hybrid Approach**
- **Local State**: BoltDB for node-specific data
- **Global State**: DHT for network-wide discovery
- **Consistency**: Strong for metadata, eventual for data

```go
type StateManager struct {
    local  *bolt.DB          // My data, my state
    dht    *kaddht.DHT       // Network discovery
    events *EventStore       // Audit trail
}
```

### Identity Model

**Decision: Crypto-based Identity**
```go
type NodeIdentity struct {
    ID         NodeID         // Hash of public key
    PublicKey  ed25519.PublicKey
    PrivateKey ed25519.PrivateKey
    DID        string         // did:key:xyz...
}

// Every node generates on first run
func GenerateIdentity() (*NodeIdentity, error) {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    id := sha256.Sum256(pub)
    did := fmt.Sprintf("did:key:%s", base58.Encode(pub))
    return &NodeIdentity{
        ID:         NodeID(id[:]),
        PublicKey:  pub,
        PrivateKey: priv,
        DID:        did,
    }, nil
}
```

## 2. Component Detailed Design

### Storage Component

```go
package storage

// Clear separation of concerns
type Storage struct {
    // Interfaces
    chunks   ChunkStore      // Low-level chunk storage
    metadata MetadataStore   // File metadata
    erasure  ErasureCoder    // Reed-Solomon coding

    // State
    state    StorageState
    metrics  *StorageMetrics

    // Configuration
    config   StorageConfig
}

type StorageConfig struct {
    DataPath      string
    MaxSize       int64
    DataShards    int  // 10
    ParityShards  int  // 4
    ChunkSize     int  // 1MB
}

// File upload flow
func (s *Storage) StoreFile(ctx context.Context, reader io.Reader, metadata FileMetadata) (*FileID, error) {
    // 1. Chunk the file
    chunks := s.chunkFile(reader)

    // 2. Erasure code each chunk
    encoded := make([]EncodedChunk, len(chunks))
    for i, chunk := range chunks {
        encoded[i] = s.erasure.Encode(chunk)
    }

    // 3. Store chunks
    stored := make([]StoredChunk, 0)
    for _, chunk := range encoded {
        sc, err := s.chunks.Store(chunk)
        if err != nil {
            // Rollback on failure
            s.rollback(stored)
            return nil, err
        }
        stored = append(stored, sc)
    }

    // 4. Create manifest
    manifest := &FileManifest{
        ID:       generateFileID(),
        Metadata: metadata,
        Chunks:   stored,
        Created:  time.Now(),
    }

    // 5. Store manifest
    err := s.metadata.StoreManifest(manifest)
    if err != nil {
        s.rollback(stored)
        return nil, err
    }

    // 6. Publish to DHT
    s.publishToDHT(manifest)

    return &manifest.ID, nil
}
```

### Network Component

```go
package network

type Network struct {
    host      host.Host
    dht       *dht.IpfsDHT
    pubsub    *pubsub.PubSub

    peers     *PeerManager
    nat       *NATManager

    handlers  map[Protocol]Handler
    state     NetworkState
}

// Connection lifecycle
type PeerManager struct {
    mu          sync.RWMutex
    peers       map[peer.ID]*PeerInfo
    maxPeers    int
    minPeers    int

    connecting  map[peer.ID]chan error
    scores      *PeerScorer
}

type PeerInfo struct {
    ID          peer.ID
    Addresses   []multiaddr.Multiaddr
    Connected   time.Time
    LastSeen    time.Time

    // Performance tracking
    Latency     time.Duration
    Bandwidth   BandwidthStats
    Reliability float64  // 0.0 to 1.0

    // Economic info
    Tier        UserTier
    Balance     int64
}

// Smart peer selection
func (pm *PeerManager) SelectPeersForStorage(count int, exclude []peer.ID) []peer.ID {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    // Score peers by multiple factors
    candidates := make([]*ScoredPeer, 0)
    for id, info := range pm.peers {
        if contains(exclude, id) {
            continue
        }

        score := pm.scores.Score(info)
        candidates = append(candidates, &ScoredPeer{id, score})
    }

    // Sort by score
    sort.Sort(ByScore(candidates))

    // Select top N
    selected := make([]peer.ID, 0, count)
    for i := 0; i < count && i < len(candidates); i++ {
        selected = append(selected, candidates[i].ID)
    }

    return selected
}
```

### API Component

```go
package api

type APIServer struct {
    app      *fiber.App
    storage  storage.Interface
    network  network.Interface
    auth     *Authenticator
    limiter  *RateLimiter

    // WebSocket
    hub      *Hub
    upgrader websocket.Upgrader

    // Metrics
    metrics  *APIMetrics
}

// Structured error handling
type APIError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details any    `json:"details,omitempty"`
}

// Request context
type RequestContext struct {
    RequestID string
    UserID    string
    Tier      UserTier
    StartTime time.Time
}

// Example endpoint with full error handling
func (s *APIServer) handleFileUpload(c *fiber.Ctx) error {
    ctx := c.Context()
    rc := getRequestContext(c)

    // 1. Validate request
    var req UploadRequest
    if err := c.BodyParser(&req); err != nil {
        return s.error(c, InvalidRequest, "Invalid request body", err)
    }

    // 2. Check rate limits
    if limited := s.limiter.Check(rc.UserID, "upload"); limited {
        return s.error(c, RateLimited, "Rate limit exceeded", nil)
    }

    // 3. Check quotas
    quota, err := s.checkQuota(rc.UserID, req.Size)
    if err != nil {
        return s.error(c, QuotaExceeded, "Storage quota exceeded", err)
    }

    // 4. Process upload
    fileID, err := s.storage.StoreFile(ctx, req.Data, req.Metadata)
    if err != nil {
        return s.error(c, StorageError, "Failed to store file", err)
    }

    // 5. Update metrics
    s.metrics.RecordUpload(rc.UserID, req.Size, time.Since(rc.StartTime))

    // 6. Return response
    return c.JSON(UploadResponse{
        FileID:    fileID,
        Timestamp: time.Now(),
        ExpiresAt: quota.ExpiresAt,
    })
}
```

### Resource Manager

```go
package resource

type ResourceManager struct {
    mu        sync.RWMutex

    // Resource tracking
    cpu       *CPUManager
    memory    *MemoryManager
    storage   *StorageManager
    bandwidth *BandwidthManager

    // Job scheduling
    queues    map[UserTier]*PriorityQueue
    scheduler *Scheduler

    // Policies
    policies  *ResourcePolicies
}

type Job struct {
    ID        JobID
    UserID    string
    Tier      UserTier
    Type      JobType

    // Resource requirements
    CPU       float64  // cores
    Memory    int64    // bytes
    Bandwidth int64    // bytes/sec
    Duration  time.Duration

    // Scheduling
    Priority  int
    Submitted time.Time
    Started   *time.Time
    Completed *time.Time

    // Execution
    Handler   JobHandler
    Context   context.Context
    Result    chan JobResult
}

// Smart scheduling with economic priorities
func (rm *ResourceManager) ScheduleJob(job *Job) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    // 1. Validate resources available
    if !rm.canAllocate(job) {
        return ErrInsufficientResources
    }

    // 2. Add to appropriate queue
    queue := rm.queues[job.Tier]
    queue.Push(job)

    // 3. Try immediate execution
    if rm.tryExecute(job) {
        return nil
    }

    // 4. Will execute when resources available
    go rm.scheduler.Schedule(job)

    return nil
}

func (rm *ResourceManager) tryExecute(job *Job) bool {
    // Check current load
    load := rm.currentLoad()

    // Tier-based execution thresholds
    var threshold float64
    switch job.Tier {
    case TierUltimate:
        threshold = 0.95  // Can run up to 95% load
    case TierAdvance:
        threshold = 0.85
    case TierNormal:
        threshold = 0.70
    case TierFree:
        threshold = 0.50
    }

    if load >= threshold {
        return false
    }

    // Try to allocate resources
    alloc, err := rm.allocate(job)
    if err != nil {
        return false
    }

    // Execute job
    go rm.executeJob(job, alloc)
    return true
}
```

## 3. Critical Design Patterns

### Event-Driven Architecture

```go
// Central event bus for loose coupling
type EventBus struct {
    subscribers map[EventType][]EventHandler
    mu          sync.RWMutex
    buffer      chan Event
}

// Example events
type Events struct {
    // Storage events
    FileStored      FileStoredEvent
    ChunkMissing    ChunkMissingEvent
    StorageFull     StorageFullEvent

    // Network events
    PeerConnected   PeerConnectedEvent
    PeerDisconnect  PeerDisconnectEvent

    // Economic events
    PaymentReceived PaymentEvent
    BalanceUpdated  BalanceEvent
}

// Components subscribe to relevant events
func (s *Storage) Subscribe(bus *EventBus) {
    bus.Subscribe(ChunkMissing, s.handleChunkMissing)
    bus.Subscribe(PeerDisconnect, s.handlePeerDisconnect)
}
```

### State Machine Pattern

```go
// Every component has explicit states
type StateMachine struct {
    current     State
    transitions map[StateTransition]State
    handlers    map[State]StateHandler
    mu          sync.Mutex
}

type StateTransition struct {
    From  State
    Event Event
}

// Example: Storage component states
const (
    StorageInitializing = iota
    StorageReady
    StorageDegraded
    StorageRebuilding
    StorageFull
    StorageFailed
)

// Explicit state transitions
func (s *Storage) setupStateMachine() {
    s.fsm = NewStateMachine(StorageInitializing)

    // Define valid transitions
    s.fsm.AddTransition(StorageInitializing, EventInitComplete, StorageReady)
    s.fsm.AddTransition(StorageReady, EventChunkLost, StorageDegraded)
    s.fsm.AddTransition(StorageDegraded, EventRebuildStart, StorageRebuilding)
    s.fsm.AddTransition(StorageRebuilding, EventRebuildComplete, StorageReady)
    s.fsm.AddTransition(StorageReady, EventStorageFull, StorageFull)

    // State handlers
    s.fsm.OnEnter(StorageDegraded, s.startRecovery)
    s.fsm.OnEnter(StorageFull, s.rejectNewFiles)
}
```

### Circuit Breaker Pattern

```go
// Prevent cascading failures
type CircuitBreaker struct {
    failures    int
    lastFailure time.Time
    state       CBState
    timeout     time.Duration
    threshold   int
}

func (cb *CircuitBreaker) Call(fn func() error) error {
    if cb.state == Open {
        if time.Since(cb.lastFailure) > cb.timeout {
            cb.state = HalfOpen
        } else {
            return ErrCircuitOpen
        }
    }

    err := fn()

    if err != nil {
        cb.recordFailure()
        if cb.failures >= cb.threshold {
            cb.state = Open
        }
        return err
    }

    if cb.state == HalfOpen {
        cb.state = Closed
    }
    cb.failures = 0
    return nil
}
```

## 4. Data Structures

### Core Data Models

```go
// File representation
type File struct {
    ID          FileID
    Name        string
    Size        int64
    ContentType string

    // Ownership
    Owner       NodeID
    Permissions Permissions

    // Storage
    Chunks      []ChunkRef
    Erasure     ErasureInfo

    // Metadata
    Created     time.Time
    Modified    time.Time
    AccessCount int64
}

// Chunk representation
type Chunk struct {
    ID      ChunkID  // SHA256 of content
    FileID  FileID   // Parent file
    Index   int      // Position in file
    Size    int64

    // Erasure coding
    DataShard   int  // Which data shard (0-9)
    ParityShard int  // Which parity shard (0-3)

    // Storage location
    Nodes   []NodeID // Where it's stored
    Primary NodeID   // Primary replica
}

// Network message types
type Message interface {
    Type() MessageType
    Validate() error
}

type StoreChunkRequest struct {
    ChunkID ChunkID
    Data    []byte
    Tier    UserTier
    TTL     time.Duration
}

type RetrieveChunkRequest struct {
    ChunkID ChunkID
    Urgent  bool  // For rebuild operations
}
```

### Performance-Critical Structures

```go
// Lock-free ring buffer for metrics
type MetricsBuffer struct {
    buffer [1024]Metric
    head   uint64  // atomic
    tail   uint64  // atomic
}

// Efficient peer scoring
type PeerScore struct {
    Latency     ewma.MovingAverage
    Bandwidth   ewma.MovingAverage
    Reliability ewma.MovingAverage

    LastUpdated time.Time
}

// Memory-mapped chunk storage
type ChunkStore struct {
    file   *os.File
    mmap   mmap.MMap
    index  *ChunkIndex

    // Free space management
    freeList *FreeList
}
```

## 5. Error Handling Strategy

```go
// Structured errors with context
type Error struct {
    Code      ErrorCode
    Message   string
    Cause     error
    Context   map[string]any
    Timestamp time.Time
}

// Error categories
const (
    // Network errors (retryable)
    ErrPeerUnreachable
    ErrTimeout
    ErrBandwidthExceeded

    // Storage errors (some retryable)
    ErrChunkNotFound
    ErrStorageFull
    ErrCorruptData

    // Fatal errors (not retryable)
    ErrInvalidConfiguration
    ErrCryptoFailure
)

// Retry logic with backoff
func withRetry(fn func() error, opts RetryOptions) error {
    var err error
    backoff := opts.InitialDelay

    for i := 0; i < opts.MaxAttempts; i++ {
        err = fn()
        if err == nil {
            return nil
        }

        if !isRetryable(err) {
            return err
        }

        time.Sleep(backoff)
        backoff = time.Duration(float64(backoff) * opts.Multiplier)
    }

    return fmt.Errorf("failed after %d attempts: %w", opts.MaxAttempts, err)
}
```

## 6. Testing Strategy

### Unit Test Structure
```go
// Table-driven tests for all edge cases
func TestChunkStorage(t *testing.T) {
    tests := []struct {
        name    string
        chunk   Chunk
        setup   func(*ChunkStore)
        wantErr error
    }{
        {
            name:  "store normal chunk",
            chunk: testChunk(1*MB),
        },
        {
            name:  "store when full",
            setup: fillStorage,
            chunk: testChunk(1*MB),
            wantErr: ErrStorageFull,
        },
        // ... 20 more cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            store := NewTestStore()
            if tt.setup != nil {
                tt.setup(store)
            }

            err := store.Store(tt.chunk)
            assert.Equal(t, tt.wantErr, err)
        })
    }
}
```

### Integration Test Harness
```go
// Full network simulation
type TestNetwork struct {
    nodes   []*Node
    latency LatencyModel
    loss    float64
}

func TestDataRecovery(t *testing.T) {
    // Create network with 20 nodes
    net := NewTestNetwork(20)

    // Store file
    file := generateFile(10*MB)
    id, err := net.nodes[0].Store(file)
    require.NoError(t, err)

    // Kill 4 nodes (maximum we can lose)
    net.KillNodes(4)

    // Should still retrieve
    retrieved, err := net.nodes[5].Retrieve(id)
    require.NoError(t, err)
    assert.Equal(t, file, retrieved)
}
```

## 7. Deployment Configuration

```yaml
# config.yaml
node:
  identity:
    path: ~/.blackhole/identity

  network:
    listen: /ip4/0.0.0.0/tcp/4001
    bootstrap:
      - /dnsaddr/bootstrap.blackhole.network
    max_peers: 50
    min_peers: 10

  storage:
    path: ~/.blackhole/storage
    max_size: 500GB
    cache_size: 1GB

  resources:
    cpu:
      max_percent: 80
      reserved_cores: 1
    memory:
      max_gb: 8
      reserved_gb: 2
    bandwidth:
      up_mbps: 100
      down_mbps: 500

  api:
    listen: localhost:8080
    max_request_size: 100MB
    rate_limit:
      requests_per_min: 60
      burst: 10
```

## 8. Monitoring & Observability

```go
// Comprehensive metrics
type Metrics struct {
    // Resource usage
    CPUUsage      prometheus.Gauge
    MemoryUsage   prometheus.Gauge
    StorageUsage  prometheus.Gauge
    BandwidthIn   prometheus.Counter
    BandwidthOut  prometheus.Counter

    // Operations
    FilesStored   prometheus.Counter
    FilesRetrieved prometheus.Counter
    ChunksServed  prometheus.Counter

    // Network health
    PeerCount     prometheus.Gauge
    PeerLatency   prometheus.Histogram

    // Economic
    EarningsTotal prometheus.Counter
    JobsCompleted prometheus.Counter
}

// Structured logging
type Logger struct {
    *zap.Logger
}

func (l *Logger) ChunkStored(chunk ChunkID, size int64, duration time.Duration) {
    l.Info("chunk stored",
        zap.String("chunk_id", chunk.String()),
        zap.Int64("size", size),
        zap.Duration("duration", duration),
    )
}
```

## 9. Migration Strategy

When we need to update:

```go
// Version-aware upgrades
type Migrator struct {
    current   Version
    target    Version
    migrations []Migration
}

type Migration interface {
    Version() Version
    Up(ctx context.Context) error
    Down(ctx context.Context) error
}

// Example: Adding new index
type AddChunkIndexMigration struct{}

func (m *AddChunkIndexMigration) Up(ctx context.Context) error {
    // Build index from existing data
    // Update metadata version
    // No downtime required
}
```

## 10. Cross-Resource Communication Flow

Example: User uploads a video for transcoding

```go
// 1. API receives upload request
func (api *APIServer) HandleVideoUpload(c *fiber.Ctx) error {
    // Validate and get file
    video := c.FormFile("video")

    // 2. Storage stores the file
    storageRef, err := api.storage.StoreFile(ctx, video.Reader, metadata)

    // 3. Storage triggers compute job through coordinator
    coordinator := api.resourceCoordinator
    job := ComputeJob{
        Type:     "transcode",
        Input:    storageRef,
        Output:   OutputSpec{Format: "mp4", Quality: "1080p"},
        Priority: UserTier(c.Locals("tier")),
    }

    jobHandle, err := coordinator.ScheduleCompute(ctx, storageRef, job)

    // 4. ResourceCoordinator orchestrates:
    //    - Finds compute node with capacity
    //    - Reserves memory for transcoding
    //    - Allocates bandwidth for data transfer
    //    - Notifies compute to start job
}

// 5. Compute node processes the job
func (compute *ComputeNode) ProcessJob(job ComputeJob) error {
    // Reserve memory first
    memHandle, err := compute.coordinator.ReserveMemoryForJob(ctx, job.ID, job.EstimatedMemory)
    defer memHandle.Release()

    // Stream data from storage
    bridge := compute.storageBridge
    dataHandle, err := bridge.PrepareDataForCompute(ctx, job.Input.Chunks)
    defer bridge.ReleaseComputeData(ctx, dataHandle)

    // Allocate bandwidth for streaming
    bwHandle, err := compute.coordinator.AllocateBandwidthForTransfer(ctx, job.Input.Size, job.Priority)
    defer bwHandle.Release()

    // Process with memory and bandwidth limits
    reader := bridge.StreamToCompute(ctx, dataHandle, bwHandle.LimitedWriter())
    result := compute.transcode(reader, job.Output)

    // Store results back
    resultRef, err := compute.coordinator.StoreResult(ctx, job.ID, result)

    // Notify completion
    compute.eventBus.Publish(JobComplete{ID: job.ID, Result: resultRef})
}

// 6. Resource pressure handling
func (memory *MemoryManager) HandlePressure() {
    // Notify compute to pause low-priority jobs
    memory.eventBus.Publish(MemoryPressure{
        Available: memory.Available(),
        Action:    PauseLowPriorityJobs,
    })
}

// 7. Bandwidth congestion handling
func (bandwidth *BandwidthManager) HandleCongestion() {
    // Reduce transfer rates for free tier
    for _, transfer := range bandwidth.activeTransfers {
        if transfer.Tier == TierFree {
            bandwidth.coordinator.AdjustAllocation(transfer.ID, transfer.Rate * 0.5)
        }
    }
}
```

### Resource Communication Patterns

1. **Direct Communication**: Storage ↔ Compute via bridges
2. **Coordinated Allocation**: Through ResourceCoordinator
3. **Event-Driven Updates**: Via ResourceEventBus
4. **Priority-Based Scheduling**: Economic tiers respected

This ensures resources work together efficiently while respecting priorities and limits.

## 11. Security Considerations

```go
// Defense in depth
type Security struct {
    // Encryption at rest
    cipher cipher.AEAD

    // Rate limiting
    limiter *rate.Limiter

    // Input validation
    validator *Validator

    // Audit logging
    audit *AuditLogger
}

// Example: Validate all inputs
func (s *Security) ValidateChunk(data []byte) error {
    if len(data) > MaxChunkSize {
        return ErrChunkTooLarge
    }

    if !isValidContent(data) {
        return ErrInvalidContent
    }

    return nil
}
```

This design addresses:
- Every component interaction
- All error scenarios
- State management
- Performance considerations
- Testing approach
- Security concerns
- Future evolution

No surprises during implementation!
