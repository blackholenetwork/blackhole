# Blackhole Network - Core Interfaces

This document defines ALL interfaces that components will implement. These are contracts that should rarely change.

## Storage Interfaces

```go
package storage

import (
    "context"
    "io"
    "time"
)

// Primary storage interface
type Storage interface {
    // File operations
    StoreFile(ctx context.Context, reader io.Reader, metadata FileMetadata) (*FileID, error)
    RetrieveFile(ctx context.Context, id FileID) (io.ReadCloser, error)
    DeleteFile(ctx context.Context, id FileID) error
    
    // Metadata operations
    GetFileInfo(ctx context.Context, id FileID) (*FileInfo, error)
    ListFiles(ctx context.Context, owner NodeID, opts ListOptions) ([]*FileInfo, error)
    
    // Health and metrics
    Health() StorageHealth
    Metrics() StorageMetrics
}

// Chunk-level operations
type ChunkStore interface {
    Store(chunk *Chunk) error
    Retrieve(id ChunkID) (*Chunk, error)
    Delete(id ChunkID) error
    Has(id ChunkID) bool
    
    // Batch operations
    StoreBatch(chunks []*Chunk) error
    RetrieveBatch(ids []ChunkID) ([]*Chunk, error)
    
    // Maintenance
    GarbageCollect() error
    Verify() error
}

// Erasure coding operations
type ErasureCoder interface {
    Encode(data []byte) ([][]byte, error)
    Decode(shards [][]byte) ([]byte, error)
    Verify(shards [][]byte) error
    
    // Config
    DataShards() int
    ParityShards() int
    TotalShards() int
}

// Metadata operations
type MetadataStore interface {
    StoreManifest(manifest *FileManifest) error
    GetManifest(id FileID) (*FileManifest, error)
    UpdateManifest(id FileID, update ManifestUpdate) error
    DeleteManifest(id FileID) error
    
    // Queries
    FindByOwner(owner NodeID) ([]*FileManifest, error)
    FindByTag(tag string) ([]*FileManifest, error)
}
```

## Network Interfaces

```go
package network

import (
    "context"
    "time"
    
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/protocol"
)

// Primary network interface
type Network interface {
    // Lifecycle
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    
    // Peer operations
    Connect(ctx context.Context, addr peer.AddrInfo) error
    Disconnect(ctx context.Context, id peer.ID) error
    Peers() []peer.ID
    
    // Messaging
    Send(ctx context.Context, id peer.ID, msg Message) error
    Request(ctx context.Context, id peer.ID, req Request) (Response, error)
    
    // Protocols
    RegisterHandler(proto protocol.ID, handler Handler) error
    
    // Discovery
    FindPeers(ctx context.Context, count int) ([]peer.AddrInfo, error)
    Advertise(ctx context.Context, ns string) error
    
    // Metrics
    Bandwidth() BandwidthStats
    Latency(id peer.ID) time.Duration
}

// Peer management
type PeerManager interface {
    AddPeer(info peer.AddrInfo) error
    RemovePeer(id peer.ID) error
    GetPeer(id peer.ID) (*PeerInfo, error)
    
    // Selection
    SelectPeers(count int, filter PeerFilter) []peer.ID
    SelectPeersByScore(count int, scorer PeerScorer) []peer.ID
    
    // Scoring
    UpdateScore(id peer.ID, delta ScoreDelta) error
    GetScore(id peer.ID) float64
    
    // Maintenance
    PrunePeers() error
    BlacklistPeer(id peer.ID, reason string) error
}

// Protocol handlers
type Handler interface {
    Handle(ctx context.Context, stream Stream) error
}

type Stream interface {
    Read([]byte) (int, error)
    Write([]byte) (int, error)
    Close() error
    
    Protocol() protocol.ID
    RemotePeer() peer.ID
}

// DHT operations
type DHT interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    
    Provide(ctx context.Context, key string) error
    FindProviders(ctx context.Context, key string) ([]peer.AddrInfo, error)
}

// NAT management
type NATManager interface {
    DiscoverNAT(ctx context.Context) (*NATInfo, error)
    MapPort(ctx context.Context, port int) error
    GetExternalAddr() (string, error)
    
    // Relay fallback
    EnableRelay() error
    DisableRelay() error
}
```

## API Interfaces

```go
package api

import (
    "context"
    "net/http"
    
    "github.com/gofiber/fiber/v2"
)

// HTTP API server
type Server interface {
    Start(addr string) error
    Stop(ctx context.Context) error
    
    // Routes
    RegisterRoute(method, path string, handler Handler) error
    RegisterMiddleware(middleware ...fiber.Handler) error
    
    // WebSocket
    RegisterWebSocket(path string, handler WSHandler) error
}

// Authentication
type Authenticator interface {
    // Token operations
    CreateToken(claims Claims) (string, error)
    ValidateToken(token string) (*Claims, error)
    RevokeToken(token string) error
    
    // API keys
    CreateAPIKey(owner NodeID, name string) (*APIKey, error)
    ValidateAPIKey(key string) (*APIKey, error)
    RevokeAPIKey(key string) error
}

// Rate limiting
type RateLimiter interface {
    Check(identifier string, action string) bool
    Reset(identifier string) error
    
    // Configuration
    SetLimit(action string, limit Limit) error
    GetLimit(action string) Limit
}

// WebSocket hub
type Hub interface {
    Register(client *Client) error
    Unregister(client *Client) error
    Broadcast(message []byte) error
    Send(clientID string, message []byte) error
    
    // Rooms
    JoinRoom(clientID, room string) error
    LeaveRoom(clientID, room string) error
    BroadcastRoom(room string, message []byte) error
}
```

## Resource Manager Interfaces

```go
package resource

import (
    "context"
    "time"
)

// Resource management
type ResourceManager interface {
    // Job scheduling
    SubmitJob(job *Job) error
    CancelJob(id JobID) error
    GetJob(id JobID) (*Job, error)
    
    // Resource allocation
    Allocate(req ResourceRequest) (*Allocation, error)
    Release(id AllocationID) error
    
    // Monitoring
    CurrentLoad() Load
    AvailableResources() Resources
    
    // Policies
    SetPolicy(tier UserTier, policy Policy) error
    GetPolicy(tier UserTier) Policy
}

// CPU management
type CPUManager interface {
    AllocateCores(count float64) (*CPUAllocation, error)
    ReleaseCores(id AllocationID) error
    
    Usage() float64
    Available() float64
}

// Memory management
type MemoryManager interface {
    Allocate(bytes int64) (*MemAllocation, error)
    Release(id AllocationID) error
    
    Usage() int64
    Available() int64
}

// Bandwidth management
type BandwidthManager interface {
    AllocateUpload(bps int64) (*BWAllocation, error)
    AllocateDownload(bps int64) (*BWAllocation, error)
    Release(id AllocationID) error
    
    CurrentUpload() int64
    CurrentDownload() int64
}

// Job execution
type Executor interface {
    Execute(ctx context.Context, job *Job) (*JobResult, error)
    
    // Lifecycle
    Pause() error
    Resume() error
    
    // Monitoring
    RunningJobs() []*Job
    QueuedJobs() []*Job
}
```

## Data Layer Interfaces

```go
package data

import (
    "context"
)

// Schema management
type SchemaRegistry interface {
    Register(schema *Schema) error
    Get(name string, version int) (*Schema, error)
    Latest(name string) (*Schema, error)
    
    // Evolution
    Evolve(name string, changes SchemaChange) (*Schema, error)
    Validate(data []byte, schema *Schema) error
    
    // Migration
    Migrate(data []byte, from, to *Schema) ([]byte, error)
}

// Indexing
type Indexer interface {
    Index(doc Document) error
    Update(id string, updates map[string]any) error
    Delete(id string) error
    
    // Batch operations
    BulkIndex(docs []Document) error
    
    // Maintenance
    Optimize() error
    Stats() IndexStats
}

// Querying
type QueryEngine interface {
    Execute(query Query) (*ResultSet, error)
    Explain(query Query) (*QueryPlan, error)
    
    // Prepared statements
    Prepare(query string) (*PreparedQuery, error)
}

// Search
type SearchEngine interface {
    Search(ctx context.Context, query string, opts SearchOptions) (*SearchResults, error)
    
    // Advanced search
    SearchSimilar(ctx context.Context, vector []float32, opts SimilarOptions) (*SearchResults, error)
    SearchFaceted(ctx context.Context, query string, facets []Facet) (*FacetedResults, error)
    
    // ML features
    Embed(text string) ([]float32, error)
    Train(dataset []TrainingDoc) error
}
```

## Economic Layer Interfaces

```go
package economic

import (
    "context"
    "time"
)

// Incentive system
type IncentiveEngine interface {
    // Pricing
    CalculatePrice(resource ResourceType, amount int64) Price
    UpdatePrices() error
    
    // Rewards
    RecordWork(node NodeID, work Work) error
    CalculateRewards(period Period) ([]Reward, error)
    DistributeRewards(rewards []Reward) error
    
    // Market dynamics
    GetSupply(resource ResourceType) int64
    GetDemand(resource ResourceType) int64
}

// Contract management
type ContractManager interface {
    // Subscriptions
    CreateSubscription(user UserID, tier Tier) (*Subscription, error)
    UpdateSubscription(id SubscriptionID, update SubscriptionUpdate) error
    CancelSubscription(id SubscriptionID) error
    
    // Usage tracking
    RecordUsage(user UserID, usage Usage) error
    GetUsage(user UserID, period Period) (*UsageSummary, error)
    
    // Billing
    GenerateInvoice(user UserID) (*Invoice, error)
    ProcessPayment(payment Payment) error
}

// Balance management
type BalanceManager interface {
    GetBalance(account AccountID) (Balance, error)
    Credit(account AccountID, amount int64, reason string) error
    Debit(account AccountID, amount int64, reason string) error
    
    // Transactions
    Transfer(from, to AccountID, amount int64) (*Transaction, error)
    GetTransactions(account AccountID, opts TxOptions) ([]*Transaction, error)
    
    // Holds
    PlaceHold(account AccountID, amount int64) (*Hold, error)
    ReleaseHold(holdID HoldID) error
    CaptureHold(holdID HoldID) error
}
```

## Cross-Resource Communication Interfaces

```go
package resource

import (
    "context"
    "io"
)

// Resource coordination - how resources talk to each other
type ResourceCoordinator interface {
    // Storage → Compute: Process stored data
    ScheduleCompute(ctx context.Context, data StorageRef, job ComputeJob) (*JobHandle, error)
    
    // Compute → Storage: Store results
    StoreResult(ctx context.Context, jobID JobID, result io.Reader) (*StorageRef, error)
    
    // Storage → Bandwidth: Serve data
    AllocateBandwidthForTransfer(ctx context.Context, size int64, priority Priority) (*BWHandle, error)
    
    // Compute → Memory: Reserve for job
    ReserveMemoryForJob(ctx context.Context, jobID JobID, size int64) (*MemHandle, error)
    
    // Bandwidth → Storage: Track transfer
    RecordTransfer(ctx context.Context, storageRef StorageRef, bytes int64, direction Direction) error
}

// Storage to Compute communication
type StorageComputeBridge interface {
    // Make data available for compute
    PrepareDataForCompute(ctx context.Context, chunks []ChunkID) (*ComputeDataHandle, error)
    
    // Stream data to compute job
    StreamToCompute(ctx context.Context, handle *ComputeDataHandle, writer io.Writer) error
    
    // Clean up after compute
    ReleaseComputeData(ctx context.Context, handle *ComputeDataHandle) error
}

// Compute to Storage communication  
type ComputeStorageBridge interface {
    // Request data chunks for processing
    RequestChunks(ctx context.Context, chunks []ChunkID) (<-chan *Chunk, error)
    
    // Stream results back to storage
    StreamResults(ctx context.Context, jobID JobID) (io.WriteCloser, error)
    
    // Atomic result commit
    CommitResults(ctx context.Context, jobID JobID, manifest ResultManifest) error
}

// Memory coordination for jobs
type MemoryCoordinator interface {
    // Pre-allocate memory for incoming job
    ReserveForJob(jobID JobID, estimate MemoryEstimate) (*Reservation, error)
    
    // Adjust reservation based on actual usage
    AdjustReservation(jobID JobID, newSize int64) error
    
    // Memory pressure handling
    OnMemoryPressure(handler PressureHandler) error
    
    // Get memory stats for scheduling
    GetAvailableForTier(tier UserTier) int64
}

// Bandwidth allocation for transfers
type BandwidthCoordinator interface {
    // Reserve bandwidth for data transfer
    ReserveForTransfer(transferID TransferID, estimate BWEstimate) (*BWReservation, error)
    
    // Dynamic bandwidth adjustment
    AdjustAllocation(transferID TransferID, newRate int64) error
    
    // Priority-based scheduling
    ScheduleTransfer(transfer Transfer) error
    
    // Congestion control
    OnCongestion(handler CongestionHandler) error
}

// Inter-resource events
type ResourceEventBus interface {
    // Storage events that compute cares about
    OnDataAvailable(handler func(StorageRef) error) error
    OnStorageFull(handler func() error) error
    
    // Compute events that storage cares about  
    OnJobComplete(handler func(JobID, ResultRef) error) error
    OnJobFailed(handler func(JobID, error) error) error
    
    // Memory events
    OnMemoryLow(handler func(Available int64) error) error
    OnOOM(handler func() error) error
    
    // Bandwidth events
    OnBandwidthSaturated(handler func() error) error
    OnTransferComplete(handler func(TransferID) error) error
}

// Resource allocation requests between components
type CrossResourceRequest interface {
    // Storage requesting compute
    RequestCompute(ctx context.Context, req ComputeRequest) (*ComputeAllocation, error)
    
    // Compute requesting storage
    RequestStorage(ctx context.Context, req StorageRequest) (*StorageAllocation, error)
    
    // Anyone requesting bandwidth
    RequestBandwidth(ctx context.Context, req BandwidthRequest) (*BandwidthAllocation, error)
    
    // Compute requesting memory
    RequestMemory(ctx context.Context, req MemoryRequest) (*MemoryAllocation, error)
    
    // Multi-resource request (atomic)
    RequestMultiple(ctx context.Context, reqs ...ResourceRequest) (*MultiAllocation, error)
}

// Data locality optimization
type LocalityManager interface {
    // Find compute near storage
    FindComputeNearData(dataRefs []StorageRef) ([]ComputeNode, error)
    
    // Find storage near compute  
    FindStorageNearCompute(computeID ComputeID) ([]StorageNode, error)
    
    // Co-locate related resources
    OptimizePlacement(job Job) (*PlacementPlan, error)
    
    // Migration for better locality
    MigrateForLocality(resource ResourceRef, target NodeID) error
}
```

## Component Lifecycle Interface

```go
package core

import (
    "context"
)

// Every component must implement this
type Component interface {
    // Metadata
    Name() string
    Version() string
    Dependencies() []string
    
    // Lifecycle
    Initialize(ctx context.Context, config Config) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    
    // Health
    Health() ComponentHealth
    Metrics() ComponentMetrics
    
    // Configuration
    ValidateConfig(config Config) error
    ReloadConfig(config Config) error
}

// Component health
type ComponentHealth struct {
    Status      HealthStatus
    Message     string
    LastChecked time.Time
    Details     map[string]any
}

type HealthStatus int

const (
    HealthUnknown HealthStatus = iota
    HealthStarting
    HealthHealthy
    HealthDegraded
    HealthUnhealthy
    HealthStopping
    HealthStopped
)
```

## Event System Interfaces

```go
package events

import (
    "context"
)

// Event bus
type EventBus interface {
    // Publishing
    Publish(ctx context.Context, event Event) error
    PublishAsync(event Event) error
    
    // Subscribing
    Subscribe(eventType EventType, handler Handler) (Subscription, error)
    SubscribeOnce(eventType EventType, handler Handler) (Subscription, error)
    
    // Management
    Unsubscribe(sub Subscription) error
    Clear(eventType EventType) error
}

// Event interface
type Event interface {
    Type() EventType
    Timestamp() time.Time
    Source() string
    Data() any
    
    // Serialization
    Marshal() ([]byte, error)
}

// Event handler
type Handler interface {
    Handle(ctx context.Context, event Event) error
}

// Subscription
type Subscription interface {
    ID() string
    EventType() EventType
    Active() bool
    
    Pause() error
    Resume() error
    Cancel() error
}
```

These interfaces define the complete contract between all components. Any implementation must satisfy these interfaces, ensuring we can:
1. Test components in isolation
2. Swap implementations
3. Maintain clean boundaries
4. Avoid the spaghetti nightmare

The key is: these interfaces should almost NEVER change once we start implementing!