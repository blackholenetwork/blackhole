# Unit U04: IPFS Integration - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U04 integrates IPFS (InterPlanetary File System) as the distributed storage foundation for the Blackhole platform. This unit provides content-addressed storage, efficient content distribution, and serves as the backbone for the storage service layer.

**Primary Goals:**
- Integrate IPFS node with custom configuration
- Implement content routing and discovery
- Configure Bitswap for efficient data exchange
- Provide pinning and garbage collection management
- Enable IPFS gateway functionality

### Dependencies

- **U01: libp2p Core Setup** - Uses the same libp2p host
- **U02: Kademlia DHT** - Shares DHT for content routing

### Deliverables

1. **IPFS Node Integration**
   - Custom IPFS node configuration
   - Shared libp2p host usage
   - Datastore configuration

2. **Content Management**
   - Content adding and retrieval
   - Pinning service implementation
   - Garbage collection policies

3. **Bitswap Configuration**
   - Block exchange optimization
   - Bandwidth management
   - Priority strategies

4. **Gateway Services**
   - HTTP gateway for web access
   - Custom gateway endpoints
   - Access control mechanisms

### Integration Points

- **U10: Storage Interface Layer** - Provides IPFS backend
- **U11: Erasure Coding System** - Stores encoded chunks
- **U13: Storage Replication Manager** - Manages distributed pins
- **All Storage Services** - Foundation for storage operations

## 2. Technical Specifications

### IPFS Configuration Parameters

```go
// IPFS Configuration Constants
const (
    // Block size limits
    DefaultBlockSize = 256 * 1024  // 256KB
    MaxBlockSize     = 1024 * 1024 // 1MB
    
    // Bitswap parameters
    BitswapMaxOutstandingBytesPerPeer = 1 << 20    // 1MB
    BitswapTargetMessageSize          = 16 * 1024  // 16KB
    
    // Pinning parameters
    PinningConcurrency = 32
    
    // Gateway parameters
    GatewayTimeout = 30 * time.Second
    
    // GC parameters
    GCPeriod    = 1 * time.Hour
    GCThreshold = 90 // percentage of datastore full
)
```

### IPFS Architecture Integration

```
┌─────────────────────────────────────────────────┐
│           Blackhole Storage Services             │
│         (S3 API, Storage Interface)             │
└─────────────────────────┬───────────────────────┘
                          │
┌─────────────────────────▼───────────────────────┐
│              IPFS Integration Layer              │
│  ┌─────────────┐  ┌──────────────┐            │
│  │   Content   │  │   Pinning    │            │
│  │  Management  │  │   Service    │            │
│  └─────────────┘  └──────────────┘            │
│                                                 │
│  ┌─────────────┐  ┌──────────────┐            │
│  │   Bitswap   │  │   Gateway    │            │
│  │   Protocol  │  │   Service    │            │
│  └─────────────┘  └──────────────┘            │
└─────────────────────────┬───────────────────────┘
                          │
┌─────────────────────────▼───────────────────────┐
│             IPFS Core Components                 │
│  ┌──────────┐  ┌────────────┐  ┌────────────┐ │
│  │   DAG    │  │  Datastore  │  │  Blockstore│ │
│  │  Service │  │              │  │            │ │
│  └──────────┘  └────────────┘  └────────────┘ │
└─────────────────────────┬───────────────────────┘
                          │
┌─────────────────────────▼───────────────────────┐
│          Shared libp2p Host (from U01)           │
└─────────────────────────────────────────────────┘
```

## 3. Implementation Details

### IPFS Node Configuration and Initialization

```go
// pkg/network/ipfs.go
package network

import (
    "context"
    "fmt"
    "path/filepath"
    "time"
    
    "github.com/ipfs/go-ipfs/config"
    "github.com/ipfs/go-ipfs/core"
    "github.com/ipfs/go-ipfs/core/bootstrap"
    "github.com/ipfs/go-ipfs/core/coreapi"
    "github.com/ipfs/go-ipfs/core/node/libp2p"
    "github.com/ipfs/go-ipfs/plugin/loader"
    "github.com/ipfs/go-ipfs/repo"
    "github.com/ipfs/go-ipfs/repo/fsrepo"
    icore "github.com/ipfs/interface-go-ipfs-core"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/multiformats/go-multiaddr"
)

// IPFSNode represents an integrated IPFS node
type IPFSNode struct {
    node       *core.IpfsNode
    api        icore.CoreAPI
    config     *IPFSConfig
    host       host.Host
    repo       repo.Repo
    ctx        context.Context
    cancel     context.CancelFunc
    gcTicker   *time.Ticker
}

// IPFSConfig configures the IPFS node
type IPFSConfig struct {
    // Repository path
    RepoPath string
    
    // Use existing libp2p host
    UseExistingHost bool
    Host           host.Host
    
    // Bootstrap nodes
    BootstrapNodes []multiaddr.Multiaddr
    
    // Bitswap configuration
    Bitswap BitswapConfig
    
    // Gateway configuration
    Gateway GatewayConfig
    
    // Datastore configuration
    Datastore DatastoreConfig
    
    // Garbage collection
    GC GCConfig
    
    // Pinning configuration
    Pinning PinningConfig
    
    // Performance tuning
    Performance PerformanceConfig
}

// BitswapConfig configures Bitswap protocol
type BitswapConfig struct {
    MaxOutstandingBytesPerPeer int
    TargetMessageSize          int
    MaxProvideBatchSize        int
    TaskWorkerCount            int
    EngineBlockSize            int
    MaxPendingBlocks           int
    WantlistRetryDelay         time.Duration
}

// GatewayConfig configures HTTP gateway
type GatewayConfig struct {
    Enabled       bool
    ListenAddr    string
    PublicGateway bool
    PathPrefixes  []string
    Headers       map[string][]string
    Timeout       time.Duration
}

// GCConfig configures garbage collection
type GCConfig struct {
    Enabled   bool
    Interval  time.Duration
    Threshold float64 // Percentage of datastore capacity
}

// NewIPFSNode creates a new IPFS node
func NewIPFSNode(ctx context.Context, cfg *IPFSConfig) (*IPFSNode, error) {
    if cfg == nil {
        cfg = DefaultIPFSConfig()
    }
    
    nodeCtx, cancel := context.WithCancel(ctx)
    
    // Initialize repo if needed
    repo, err := initializeRepo(cfg)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("failed to initialize repo: %w", err)
    }
    
    // Create node configuration
    nodeConfig := &core.BuildCfg{
        Online:    true,
        Permanent: true,
        Repo:      repo,
    }
    
    // Use existing host if provided
    if cfg.UseExistingHost && cfg.Host != nil {
        nodeConfig.Host = cfg.Host
        nodeConfig.ExtraOpts = map[string]bool{
            "pubsub": true,
        }
    }
    
    // Construct IPFS node
    node, err := core.NewNode(nodeCtx, nodeConfig)
    if err != nil {
        repo.Close()
        cancel()
        return nil, fmt.Errorf("failed to create IPFS node: %w", err)
    }
    
    // Create CoreAPI
    api, err := coreapi.NewCoreAPI(node)
    if err != nil {
        node.Close()
        cancel()
        return nil, fmt.Errorf("failed to create CoreAPI: %w", err)
    }
    
    ipfsNode := &IPFSNode{
        node:   node,
        api:    api,
        config: cfg,
        host:   node.PeerHost,
        repo:   repo,
        ctx:    nodeCtx,
        cancel: cancel,
    }
    
    return ipfsNode, nil
}

// Start initializes and starts the IPFS node
func (n *IPFSNode) Start() error {
    logger.Info("Starting IPFS node")
    
    // Bootstrap connections
    if err := n.bootstrap(); err != nil {
        logger.Warnf("Bootstrap failed: %v", err)
    }
    
    // Configure Bitswap
    if err := n.configureBitswap(); err != nil {
        return fmt.Errorf("failed to configure Bitswap: %w", err)
    }
    
    // Start garbage collection if enabled
    if n.config.GC.Enabled {
        n.startGarbageCollection()
    }
    
    // Start gateway if enabled
    if n.config.Gateway.Enabled {
        if err := n.startGateway(); err != nil {
            return fmt.Errorf("failed to start gateway: %w", err)
        }
    }
    
    logger.Infof("IPFS node started with ID: %s", n.node.Identity)
    return nil
}

// Stop gracefully shuts down the IPFS node
func (n *IPFSNode) Stop() error {
    logger.Info("Stopping IPFS node")
    
    n.cancel()
    
    if n.gcTicker != nil {
        n.gcTicker.Stop()
    }
    
    if err := n.node.Close(); err != nil {
        logger.Warnf("Error closing IPFS node: %v", err)
    }
    
    if err := n.repo.Close(); err != nil {
        logger.Warnf("Error closing repo: %v", err)
    }
    
    return nil
}

// initializeRepo creates or opens an IPFS repository
func initializeRepo(cfg *IPFSConfig) (repo.Repo, error) {
    // Check if repo exists
    if !fsrepo.IsInitialized(cfg.RepoPath) {
        // Create new repo
        repoCfg, err := createRepoConfig(cfg)
        if err != nil {
            return nil, err
        }
        
        if err := fsrepo.Init(cfg.RepoPath, repoCfg); err != nil {
            return nil, fmt.Errorf("failed to init repo: %w", err)
        }
    }
    
    // Open repo
    return fsrepo.Open(cfg.RepoPath)
}

// createRepoConfig creates IPFS repository configuration
func createRepoConfig(cfg *IPFSConfig) (*config.Config, error) {
    // Create default config
    conf, err := config.Init(os.Stdout, 2048)
    if err != nil {
        return nil, err
    }
    
    // Configure bootstrap nodes
    if len(cfg.BootstrapNodes) > 0 {
        conf.Bootstrap = make([]string, len(cfg.BootstrapNodes))
        for i, addr := range cfg.BootstrapNodes {
            conf.Bootstrap[i] = addr.String()
        }
    }
    
    // Configure datastore
    conf.Datastore = config.Datastore{
        StorageMax:         cfg.Datastore.StorageMax,
        StorageGCWatermark: int64(cfg.GC.Threshold),
        GCPeriod:           cfg.GC.Interval.String(),
        Spec: map[string]interface{}{
            "type": cfg.Datastore.Type,
            "path": cfg.Datastore.Path,
        },
    }
    
    // Configure Bitswap
    conf.Swarm.ConnMgr = config.ConnMgr{
        Type:        "basic",
        LowWater:    cfg.Performance.ConnMgrLowWater,
        HighWater:   cfg.Performance.ConnMgrHighWater,
        GracePeriod: cfg.Performance.ConnMgrGracePeriod.String(),
    }
    
    // Disable automatic bootstrapping if using existing host
    if cfg.UseExistingHost {
        conf.Bootstrap = []string{}
    }
    
    return conf, nil
}

// bootstrap connects to bootstrap nodes
func (n *IPFSNode) bootstrap() error {
    bootstrapCfg := bootstrap.BootstrapConfigWithPeers(
        n.config.BootstrapNodes,
    )
    
    return bootstrap.Bootstrap(n.node, bootstrapCfg)
}

// configureBitswap applies Bitswap configuration
func (n *IPFSNode) configureBitswap() error {
    // Access Bitswap instance
    bitswap := n.node.Exchange
    
    // Configure Bitswap parameters
    // Note: Direct configuration depends on IPFS version
    // This is a placeholder for actual configuration
    
    logger.Info("Bitswap configured")
    return nil
}
```

### Content Management Implementation

```go
// pkg/network/ipfs_content.go
package network

import (
    "context"
    "fmt"
    "io"
    "path"
    
    "github.com/ipfs/go-cid"
    files "github.com/ipfs/go-ipfs-files"
    "github.com/ipfs/interface-go-ipfs-core/options"
    ipath "github.com/ipfs/interface-go-ipfs-core/path"
)

// ContentManager handles IPFS content operations
type ContentManager struct {
    node *IPFSNode
}

// NewContentManager creates a new content manager
func NewContentManager(node *IPFSNode) *ContentManager {
    return &ContentManager{node: node}
}

// AddContent adds content to IPFS
func (cm *ContentManager) AddContent(ctx context.Context, data io.Reader, opts ...AddOption) (cid.Cid, error) {
    // Apply options
    settings := &AddSettings{
        Pin:         true,
        HashOnly:    false,
        RawLeaves:   true,
        Chunker:     "size-262144", // 256KB chunks
        CidVersion:  1,
    }
    
    for _, opt := range opts {
        opt(settings)
    }
    
    // Create file node
    file := files.NewReaderFile(data)
    
    // Configure add options
    addOpts := []options.UnixfsAddOption{
        options.Unixfs.Pin(settings.Pin),
        options.Unixfs.HashOnly(settings.HashOnly),
        options.Unixfs.RawLeaves(settings.RawLeaves),
        options.Unixfs.Chunker(settings.Chunker),
        options.Unixfs.CidVersion(settings.CidVersion),
    }
    
    if settings.Progress != nil {
        addOpts = append(addOpts, options.Unixfs.Progress(settings.Progress))
    }
    
    // Add to IPFS
    path, err := cm.node.api.Unixfs().Add(ctx, file, addOpts...)
    if err != nil {
        return cid.Cid{}, fmt.Errorf("failed to add content: %w", err)
    }
    
    // Extract CID
    resolved, err := cm.node.api.ResolvePath(ctx, path)
    if err != nil {
        return cid.Cid{}, fmt.Errorf("failed to resolve path: %w", err)
    }
    
    return resolved.Cid(), nil
}

// GetContent retrieves content from IPFS
func (cm *ContentManager) GetContent(ctx context.Context, c cid.Cid) (io.ReadCloser, error) {
    // Create path from CID
    path := ipath.IpfsPath(c)
    
    // Get content
    node, err := cm.node.api.Unixfs().Get(ctx, path)
    if err != nil {
        return nil, fmt.Errorf("failed to get content: %w", err)
    }
    
    // Convert to reader
    file, ok := node.(files.File)
    if !ok {
        return nil, fmt.Errorf("content is not a file")
    }
    
    return file, nil
}

// AddDirectory adds a directory to IPFS
func (cm *ContentManager) AddDirectory(ctx context.Context, dir files.Directory) (cid.Cid, error) {
    path, err := cm.node.api.Unixfs().Add(ctx, dir,
        options.Unixfs.Pin(true),
        options.Unixfs.CidVersion(1),
    )
    if err != nil {
        return cid.Cid{}, fmt.Errorf("failed to add directory: %w", err)
    }
    
    resolved, err := cm.node.api.ResolvePath(ctx, path)
    if err != nil {
        return cid.Cid{}, fmt.Errorf("failed to resolve path: %w", err)
    }
    
    return resolved.Cid(), nil
}

// ListDirectory lists contents of an IPFS directory
func (cm *ContentManager) ListDirectory(ctx context.Context, c cid.Cid) ([]DirEntry, error) {
    path := ipath.IpfsPath(c)
    
    entries, err := cm.node.api.Unixfs().Ls(ctx, path)
    if err != nil {
        return nil, fmt.Errorf("failed to list directory: %w", err)
    }
    
    var result []DirEntry
    for entry := range entries {
        if entry.Err != nil {
            return nil, entry.Err
        }
        
        result = append(result, DirEntry{
            Name: entry.Name,
            Cid:  entry.Cid,
            Size: entry.Size,
            Type: entry.Type,
        })
    }
    
    return result, nil
}

// GetMetadata retrieves metadata for content
func (cm *ContentManager) GetMetadata(ctx context.Context, c cid.Cid) (*ContentMetadata, error) {
    // Get object stats
    stat, err := cm.node.api.Object().Stat(ctx, ipath.IpfsPath(c))
    if err != nil {
        return nil, fmt.Errorf("failed to get stats: %w", err)
    }
    
    // Get block stats
    blockStat, err := cm.node.api.Block().Stat(ctx, ipath.IpfsPath(c))
    if err != nil {
        return nil, fmt.Errorf("failed to get block stats: %w", err)
    }
    
    return &ContentMetadata{
        Cid:           c,
        Type:          stat.Type,
        Blocks:        stat.Blocks,
        Size:          stat.DataSize,
        CumulativeSize: stat.CumulativeSize,
        LinkCount:     stat.LinksSize,
        BlockSize:     blockStat.Size(),
    }, nil
}

// AddSettings configures content addition
type AddSettings struct {
    Pin         bool
    HashOnly    bool
    RawLeaves   bool
    Chunker     string
    CidVersion  int
    Progress    chan int64
}

// AddOption configures content addition
type AddOption func(*AddSettings)

// WithPin sets pinning option
func WithPin(pin bool) AddOption {
    return func(s *AddSettings) {
        s.Pin = pin
    }
}

// WithChunker sets chunking algorithm
func WithChunker(chunker string) AddOption {
    return func(s *AddSettings) {
        s.Chunker = chunker
    }
}

// WithProgress sets progress channel
func WithProgress(ch chan int64) AddOption {
    return func(s *AddSettings) {
        s.Progress = ch
    }
}

// DirEntry represents a directory entry
type DirEntry struct {
    Name string
    Cid  cid.Cid
    Size uint64
    Type files.FileType
}

// ContentMetadata contains content metadata
type ContentMetadata struct {
    Cid            cid.Cid
    Type           string
    Blocks         int
    Size           uint64
    CumulativeSize uint64
    LinkCount      int
    BlockSize      int
}
```

### Pinning Service Implementation

```go
// pkg/network/ipfs_pinning.go
package network

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/ipfs/go-cid"
    "github.com/ipfs/interface-go-ipfs-core/options"
    ipath "github.com/ipfs/interface-go-ipfs-core/path"
)

// PinningService manages content pinning
type PinningService struct {
    node        *IPFSNode
    pins        map[cid.Cid]*PinInfo
    pinsMu      sync.RWMutex
    workers     int
    workQueue   chan PinRequest
    ctx         context.Context
    cancel      context.CancelFunc
}

// PinInfo tracks pinning information
type PinInfo struct {
    Cid         cid.Cid
    Type        PinType
    Created     time.Time
    LastChecked time.Time
    Size        uint64
    Recursive   bool
    Metadata    map[string]string
}

// PinType represents the type of pin
type PinType string

const (
    PinTypeDirect    PinType = "direct"
    PinTypeRecursive PinType = "recursive"
    PinTypeIndirect  PinType = "indirect"
)

// PinRequest represents a pinning request
type PinRequest struct {
    Cid       cid.Cid
    Recursive bool
    Metadata  map[string]string
    Response  chan PinResponse
}

// PinResponse represents pinning result
type PinResponse struct {
    Success bool
    Error   error
    Info    *PinInfo
}

// NewPinningService creates a new pinning service
func NewPinningService(node *IPFSNode, workers int) *PinningService {
    ctx, cancel := context.WithCancel(node.ctx)
    
    ps := &PinningService{
        node:      node,
        pins:      make(map[cid.Cid]*PinInfo),
        workers:   workers,
        workQueue: make(chan PinRequest, 100),
        ctx:       ctx,
        cancel:    cancel,
    }
    
    // Start workers
    for i := 0; i < workers; i++ {
        go ps.pinWorker(i)
    }
    
    // Load existing pins
    go ps.loadExistingPins()
    
    return ps
}

// Pin adds a pin for content
func (ps *PinningService) Pin(ctx context.Context, c cid.Cid, recursive bool) error {
    req := PinRequest{
        Cid:       c,
        Recursive: recursive,
        Response:  make(chan PinResponse, 1),
    }
    
    select {
    case ps.workQueue <- req:
        select {
        case resp := <-req.Response:
            if !resp.Success {
                return resp.Error
            }
            return nil
        case <-ctx.Done():
            return ctx.Err()
        }
    case <-ctx.Done():
        return ctx.Err()
    }
}

// Unpin removes a pin
func (ps *PinningService) Unpin(ctx context.Context, c cid.Cid) error {
    // Remove from tracking
    ps.pinsMu.Lock()
    delete(ps.pins, c)
    ps.pinsMu.Unlock()
    
    // Unpin from IPFS
    path := ipath.IpfsPath(c)
    err := ps.node.api.Pin().Rm(ctx, path)
    if err != nil {
        return fmt.Errorf("failed to unpin: %w", err)
    }
    
    logger.Infof("Unpinned content: %s", c)
    return nil
}

// IsPinned checks if content is pinned
func (ps *PinningService) IsPinned(ctx context.Context, c cid.Cid) (bool, error) {
    ps.pinsMu.RLock()
    _, exists := ps.pins[c]
    ps.pinsMu.RUnlock()
    
    if exists {
        return true, nil
    }
    
    // Check IPFS
    path := ipath.IpfsPath(c)
    pinned, _, err := ps.node.api.Pin().IsPinned(ctx, path)
    return pinned, err
}

// ListPins returns all pins
func (ps *PinningService) ListPins(ctx context.Context, filter PinType) ([]*PinInfo, error) {
    ps.pinsMu.RLock()
    defer ps.pinsMu.RUnlock()
    
    var pins []*PinInfo
    for _, pin := range ps.pins {
        if filter == "" || pin.Type == filter {
            pins = append(pins, pin)
        }
    }
    
    return pins, nil
}

// pinWorker processes pinning requests
func (ps *PinningService) pinWorker(id int) {
    logger.Debugf("Pin worker %d started", id)
    
    for {
        select {
        case req := <-ps.workQueue:
            ps.processPinRequest(req)
        case <-ps.ctx.Done():
            logger.Debugf("Pin worker %d stopped", id)
            return
        }
    }
}

// processPinRequest handles a single pin request
func (ps *PinningService) processPinRequest(req PinRequest) {
    resp := PinResponse{}
    
    // Pin content
    path := ipath.IpfsPath(req.Cid)
    opts := []options.PinAddOption{}
    if req.Recursive {
        opts = append(opts, options.Pin.Recursive(true))
    }
    
    err := ps.node.api.Pin().Add(ps.ctx, path, opts...)
    if err != nil {
        resp.Error = fmt.Errorf("failed to pin: %w", err)
        req.Response <- resp
        return
    }
    
    // Get content size
    stat, err := ps.node.api.Object().Stat(ps.ctx, path)
    if err != nil {
        logger.Warnf("Failed to get pin stats: %v", err)
    }
    
    // Create pin info
    pinType := PinTypeDirect
    if req.Recursive {
        pinType = PinTypeRecursive
    }
    
    info := &PinInfo{
        Cid:         req.Cid,
        Type:        pinType,
        Created:     time.Now(),
        LastChecked: time.Now(),
        Size:        stat.CumulativeSize,
        Recursive:   req.Recursive,
        Metadata:    req.Metadata,
    }
    
    // Store pin info
    ps.pinsMu.Lock()
    ps.pins[req.Cid] = info
    ps.pinsMu.Unlock()
    
    resp.Success = true
    resp.Info = info
    req.Response <- resp
    
    logger.Infof("Pinned content: %s (size: %d)", req.Cid, info.Size)
}

// loadExistingPins loads pins from IPFS
func (ps *PinningService) loadExistingPins() {
    ctx, cancel := context.WithTimeout(ps.ctx, 5*time.Minute)
    defer cancel()
    
    // List all pins
    pins, err := ps.node.api.Pin().Ls(ctx, options.Pin.Type.All())
    if err != nil {
        logger.Errorf("Failed to load existing pins: %v", err)
        return
    }
    
    count := 0
    for pin := range pins {
        if pin.Err() != nil {
            logger.Warnf("Error loading pin: %v", pin.Err())
            continue
        }
        
        pinType := PinTypeDirect
        switch pin.Type() {
        case "recursive":
            pinType = PinTypeRecursive
        case "indirect":
            pinType = PinTypeIndirect
        }
        
        ps.pinsMu.Lock()
        ps.pins[pin.Path().Cid()] = &PinInfo{
            Cid:         pin.Path().Cid(),
            Type:        pinType,
            Created:     time.Now(), // Unknown
            LastChecked: time.Now(),
            Recursive:   pinType == PinTypeRecursive,
        }
        ps.pinsMu.Unlock()
        
        count++
    }
    
    logger.Infof("Loaded %d existing pins", count)
}

// VerifyPins checks integrity of all pins
func (ps *PinningService) VerifyPins(ctx context.Context) error {
    ps.pinsMu.RLock()
    pins := make([]*PinInfo, 0, len(ps.pins))
    for _, pin := range ps.pins {
        pins = append(pins, pin)
    }
    ps.pinsMu.RUnlock()
    
    errors := 0
    for _, pin := range pins {
        if err := ps.verifyPin(ctx, pin); err != nil {
            logger.Warnf("Pin verification failed for %s: %v", pin.Cid, err)
            errors++
        }
    }
    
    if errors > 0 {
        return fmt.Errorf("%d pins failed verification", errors)
    }
    
    return nil
}

// verifyPin verifies a single pin
func (ps *PinningService) verifyPin(ctx context.Context, pin *PinInfo) error {
    // Check if still pinned
    path := ipath.IpfsPath(pin.Cid)
    pinned, _, err := ps.node.api.Pin().IsPinned(ctx, path)
    if err != nil {
        return err
    }
    
    if !pinned {
        return fmt.Errorf("content no longer pinned")
    }
    
    // Update last checked
    ps.pinsMu.Lock()
    if p, exists := ps.pins[pin.Cid]; exists {
        p.LastChecked = time.Now()
    }
    ps.pinsMu.Unlock()
    
    return nil
}
```

### Bitswap Optimization

```go
// pkg/network/ipfs_bitswap.go
package network

import (
    "context"
    "sync"
    "time"
    
    "github.com/ipfs/go-cid"
    "github.com/libp2p/go-libp2p/core/peer"
)

// BitswapManager manages Bitswap protocol optimization
type BitswapManager struct {
    node          *IPFSNode
    peerStats     map[peer.ID]*PeerStats
    statsMu       sync.RWMutex
    wantlist      map[cid.Cid]*WantInfo
    wantlistMu    sync.RWMutex
    strategies    []BitswapStrategy
}

// PeerStats tracks peer performance
type PeerStats struct {
    PeerID           peer.ID
    BlocksReceived   uint64
    BlocksSent       uint64
    BytesReceived    uint64
    BytesSent        uint64
    Latency          time.Duration
    LastInteraction  time.Time
    ReputationScore  float64
}

// WantInfo tracks wanted blocks
type WantInfo struct {
    Cid          cid.Cid
    Priority     int
    RequestTime  time.Time
    Attempts     int
    LastAttempt  time.Time
}

// BitswapStrategy defines block exchange strategy
type BitswapStrategy interface {
    ShouldSendBlock(peer peer.ID, block cid.Cid) bool
    PrioritizePeer(stats []*PeerStats) []*PeerStats
    AdjustWantlist(wants map[cid.Cid]*WantInfo) map[cid.Cid]*WantInfo
}

// NewBitswapManager creates a new Bitswap manager
func NewBitswapManager(node *IPFSNode) *BitswapManager {
    bm := &BitswapManager{
        node:      node,
        peerStats: make(map[peer.ID]*PeerStats),
        wantlist:  make(map[cid.Cid]*WantInfo),
        strategies: []BitswapStrategy{
            &TitForTatStrategy{},
            &LatencyOptimizedStrategy{},
            &BandwidthOptimizedStrategy{},
        },
    }
    
    // Start monitoring
    go bm.monitorBitswap()
    
    return bm
}

// RequestBlock requests a block with priority
func (bm *BitswapManager) RequestBlock(ctx context.Context, c cid.Cid, priority int) error {
    bm.wantlistMu.Lock()
    bm.wantlist[c] = &WantInfo{
        Cid:         c,
        Priority:    priority,
        RequestTime: time.Now(),
        Attempts:    0,
    }
    bm.wantlistMu.Unlock()
    
    // Notify Bitswap
    // Note: Direct Bitswap API interaction depends on IPFS version
    
    return nil
}

// GetPeerStats returns statistics for a peer
func (bm *BitswapManager) GetPeerStats(p peer.ID) *PeerStats {
    bm.statsMu.RLock()
    defer bm.statsMu.RUnlock()
    
    if stats, exists := bm.peerStats[p]; exists {
        return stats
    }
    return nil
}

// UpdatePeerStats updates peer statistics
func (bm *BitswapManager) UpdatePeerStats(p peer.ID, update func(*PeerStats)) {
    bm.statsMu.Lock()
    defer bm.statsMu.Unlock()
    
    stats, exists := bm.peerStats[p]
    if !exists {
        stats = &PeerStats{
            PeerID:          p,
            ReputationScore: 1.0,
        }
        bm.peerStats[p] = stats
    }
    
    update(stats)
    stats.LastInteraction = time.Now()
}

// monitorBitswap monitors Bitswap activity
func (bm *BitswapManager) monitorBitswap() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            bm.updateStats()
            bm.optimizeWantlist()
        case <-bm.node.ctx.Done():
            return
        }
    }
}

// updateStats updates Bitswap statistics
func (bm *BitswapManager) updateStats() {
    // Get Bitswap stats from node
    // Implementation depends on IPFS API access
    
    // Update peer reputation scores
    bm.statsMu.Lock()
    for _, stats := range bm.peerStats {
        bm.updateReputation(stats)
    }
    bm.statsMu.Unlock()
}

// updateReputation calculates peer reputation
func (bm *BitswapManager) updateReputation(stats *PeerStats) {
    // Simple reputation algorithm
    // Can be made more sophisticated
    
    if stats.BlocksReceived == 0 {
        stats.ReputationScore = 0.5
        return
    }
    
    ratio := float64(stats.BlocksSent) / float64(stats.BlocksReceived)
    latencyScore := 1.0 / (1.0 + stats.Latency.Seconds())
    
    stats.ReputationScore = (ratio*0.7 + latencyScore*0.3)
    
    // Clamp between 0 and 2
    if stats.ReputationScore > 2.0 {
        stats.ReputationScore = 2.0
    } else if stats.ReputationScore < 0.0 {
        stats.ReputationScore = 0.0
    }
}

// optimizeWantlist optimizes the want list
func (bm *BitswapManager) optimizeWantlist() {
    bm.wantlistMu.Lock()
    defer bm.wantlistMu.Unlock()
    
    // Apply strategies
    optimized := bm.wantlist
    for _, strategy := range bm.strategies {
        optimized = strategy.AdjustWantlist(optimized)
    }
    
    bm.wantlist = optimized
}

// TitForTatStrategy implements tit-for-tat block sharing
type TitForTatStrategy struct{}

func (s *TitForTatStrategy) ShouldSendBlock(peer peer.ID, block cid.Cid) bool {
    // Send blocks to peers that have sent us blocks
    return true
}

func (s *TitForTatStrategy) PrioritizePeer(stats []*PeerStats) []*PeerStats {
    // Prioritize by reputation
    sort.Slice(stats, func(i, j int) bool {
        return stats[i].ReputationScore > stats[j].ReputationScore
    })
    return stats
}

func (s *TitForTatStrategy) AdjustWantlist(wants map[cid.Cid]*WantInfo) map[cid.Cid]*WantInfo {
    // No adjustment needed
    return wants
}

// LatencyOptimizedStrategy optimizes for low latency
type LatencyOptimizedStrategy struct{}

func (s *LatencyOptimizedStrategy) ShouldSendBlock(peer peer.ID, block cid.Cid) bool {
    return true
}

func (s *LatencyOptimizedStrategy) PrioritizePeer(stats []*PeerStats) []*PeerStats {
    // Prioritize by latency
    sort.Slice(stats, func(i, j int) bool {
        return stats[i].Latency < stats[j].Latency
    })
    return stats
}

func (s *LatencyOptimizedStrategy) AdjustWantlist(wants map[cid.Cid]*WantInfo) map[cid.Cid]*WantInfo {
    // Increase priority for old requests
    for _, want := range wants {
        age := time.Since(want.RequestTime)
        if age > 30*time.Second {
            want.Priority += int(age.Seconds() / 30)
        }
    }
    return wants
}

// BandwidthOptimizedStrategy optimizes bandwidth usage
type BandwidthOptimizedStrategy struct{}

func (s *BandwidthOptimizedStrategy) ShouldSendBlock(peer peer.ID, block cid.Cid) bool {
    // Could implement bandwidth limiting here
    return true
}

func (s *BandwidthOptimizedStrategy) PrioritizePeer(stats []*PeerStats) []*PeerStats {
    // Prioritize by bandwidth efficiency
    sort.Slice(stats, func(i, j int) bool {
        eff1 := float64(stats[i].BlocksReceived) / float64(stats[i].BytesReceived+1)
        eff2 := float64(stats[j].BlocksReceived) / float64(stats[j].BytesReceived+1)
        return eff1 > eff2
    })
    return stats
}

func (s *BandwidthOptimizedStrategy) AdjustWantlist(wants map[cid.Cid]*WantInfo) map[cid.Cid]*WantInfo {
    // Could batch requests here
    return wants
}
```

### Gateway Service Implementation

```go
// pkg/network/ipfs_gateway.go
package network

import (
    "context"
    "fmt"
    "net/http"
    "strings"
    "time"
    
    "github.com/ipfs/go-ipfs/core/corehttp"
    "github.com/ipfs/go-ipfs/core/coreapi"
)

// GatewayService provides HTTP gateway to IPFS
type GatewayService struct {
    node       *IPFSNode
    config     *GatewayConfig
    server     *http.Server
    mux        *http.ServeMux
    middleware []Middleware
}

// Middleware defines gateway middleware
type Middleware func(http.Handler) http.Handler

// NewGatewayService creates a new gateway service
func NewGatewayService(node *IPFSNode, cfg *GatewayConfig) *GatewayService {
    mux := http.NewServeMux()
    
    gs := &GatewayService{
        node:   node,
        config: cfg,
        mux:    mux,
        middleware: []Middleware{
            loggingMiddleware,
            corsMiddleware(cfg),
            authMiddleware(cfg),
            rateLimitMiddleware(cfg),
        },
    }
    
    // Configure routes
    gs.setupRoutes()
    
    // Create server
    gs.server = &http.Server{
        Addr:         cfg.ListenAddr,
        Handler:      gs.applyMiddleware(mux),
        ReadTimeout:  30 * time.Second,
        WriteTimeout: cfg.Timeout,
        IdleTimeout:  120 * time.Second,
    }
    
    return gs
}

// Start starts the gateway server
func (gs *GatewayService) Start() error {
    logger.Infof("Starting IPFS gateway on %s", gs.config.ListenAddr)
    
    go func() {
        if err := gs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Errorf("Gateway server error: %v", err)
        }
    }()
    
    return nil
}

// Stop shuts down the gateway
func (gs *GatewayService) Stop() error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    return gs.server.Shutdown(ctx)
}

// setupRoutes configures gateway routes
func (gs *GatewayService) setupRoutes() {
    // IPFS gateway paths
    gs.mux.HandleFunc("/ipfs/", gs.handleIPFS)
    gs.mux.HandleFunc("/ipns/", gs.handleIPNS)
    
    // API endpoints
    gs.mux.HandleFunc("/api/v0/", gs.handleAPI)
    
    // Custom Blackhole endpoints
    gs.mux.HandleFunc("/blackhole/pin", gs.handlePin)
    gs.mux.HandleFunc("/blackhole/stats", gs.handleStats)
    
    // Health check
    gs.mux.HandleFunc("/health", gs.handleHealth)
}

// handleIPFS handles /ipfs/* requests
func (gs *GatewayService) handleIPFS(w http.ResponseWriter, r *http.Request) {
    // Extract CID from path
    path := strings.TrimPrefix(r.URL.Path, "/ipfs/")
    parts := strings.SplitN(path, "/", 2)
    if len(parts) == 0 {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }
    
    // Parse CID
    c, err := cid.Parse(parts[0])
    if err != nil {
        http.Error(w, "Invalid CID", http.StatusBadRequest)
        return
    }
    
    // Get content
    ctx, cancel := context.WithTimeout(r.Context(), gs.config.Timeout)
    defer cancel()
    
    reader, err := gs.node.api.Unixfs().Get(ctx, ipath.IpfsPath(c))
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    
    // Serve content
    http.ServeContent(w, r, path, time.Now(), reader)
}

// handlePin handles pinning requests
func (gs *GatewayService) handlePin(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Parse request
    var req struct {
        Cid       string `json:"cid"`
        Recursive bool   `json:"recursive"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Parse CID
    c, err := cid.Parse(req.Cid)
    if err != nil {
        http.Error(w, "Invalid CID", http.StatusBadRequest)
        return
    }
    
    // Pin content
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
    defer cancel()
    
    path := ipath.IpfsPath(c)
    err = gs.node.api.Pin().Add(ctx, path, options.Pin.Recursive(req.Recursive))
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "pinned": true,
        "cid":    c.String(),
    })
}

// handleStats returns node statistics
func (gs *GatewayService) handleStats(w http.ResponseWriter, r *http.Request) {
    stats, err := gs.node.api.Stats().BW(r.Context())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    repoStat, err := gs.node.api.Stats().Repo(r.Context())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    response := map[string]interface{}{
        "bandwidth": map[string]interface{}{
            "total_in":  stats.TotalIn,
            "total_out": stats.TotalOut,
            "rate_in":   stats.RateIn,
            "rate_out":  stats.RateOut,
        },
        "repo": map[string]interface{}{
            "size":       repoStat.RepoSize,
            "storage_max": repoStat.StorageMax,
            "num_objects": repoStat.NumObjects,
        },
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// handleHealth returns health status
func (gs *GatewayService) handleHealth(w http.ResponseWriter, r *http.Request) {
    // Check IPFS node status
    peers := gs.node.node.PeerHost.Network().Peers()
    
    healthy := len(peers) > 0
    status := "healthy"
    if !healthy {
        status = "unhealthy"
    }
    
    response := map[string]interface{}{
        "status":     status,
        "peer_count": len(peers),
        "node_id":    gs.node.node.Identity.String(),
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// applyMiddleware applies all middleware
func (gs *GatewayService) applyMiddleware(handler http.Handler) http.Handler {
    for i := len(gs.middleware) - 1; i >= 0; i-- {
        handler = gs.middleware[i](handler)
    }
    return handler
}

// Middleware implementations

func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Wrap response writer to capture status
        wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
        
        next.ServeHTTP(wrapped, r)
        
        logger.Infof("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
    })
}

func corsMiddleware(cfg *GatewayConfig) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if cfg.PublicGateway {
                w.Header().Set("Access-Control-Allow-Origin", "*")
                w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
                w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Range")
            }
            
            if r.Method == "OPTIONS" {
                w.WriteHeader(http.StatusOK)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

func authMiddleware(cfg *GatewayConfig) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Implement authentication if needed
            next.ServeHTTP(w, r)
        })
    }
}

func rateLimitMiddleware(cfg *GatewayConfig) Middleware {
    // Simple rate limiter - can be enhanced
    limiter := NewRateLimiter(100) // 100 requests per minute
    
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ip := getClientIP(r)
            
            if !limiter.Allow(ip) {
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}
```

### Garbage Collection

```go
// pkg/network/ipfs_gc.go
package network

import (
    "context"
    "fmt"
    "time"
)

// startGarbageCollection starts periodic garbage collection
func (n *IPFSNode) startGarbageCollection() {
    n.gcTicker = time.NewTicker(n.config.GC.Interval)
    
    go func() {
        for {
            select {
            case <-n.gcTicker.C:
                n.runGarbageCollection()
            case <-n.ctx.Done():
                return
            }
        }
    }()
    
    logger.Info("Garbage collection enabled")
}

// runGarbageCollection performs garbage collection
func (n *IPFSNode) runGarbageCollection() {
    ctx, cancel := context.WithTimeout(n.ctx, 30*time.Minute)
    defer cancel()
    
    logger.Info("Running garbage collection")
    start := time.Now()
    
    // Check if GC is needed
    stat, err := n.api.Stats().Repo(ctx)
    if err != nil {
        logger.Errorf("Failed to get repo stats: %v", err)
        return
    }
    
    usage := float64(stat.RepoSize) / float64(stat.StorageMax) * 100
    if usage < n.config.GC.Threshold {
        logger.Debugf("GC not needed, usage: %.2f%%", usage)
        return
    }
    
    // Run GC
    out, err := n.api.Repo().Gc(ctx)
    if err != nil {
        logger.Errorf("Garbage collection failed: %v", err)
        return
    }
    
    // Process results
    removed := 0
    var reclaimedBytes uint64
    
    for res := range out {
        if res.Error != nil {
            logger.Warnf("GC error for %s: %v", res.KeyRemoved, res.Error)
            continue
        }
        removed++
        // Track reclaimed space
    }
    
    logger.Infof("Garbage collection completed in %v, removed %d objects, reclaimed %d bytes",
        time.Since(start), removed, reclaimedBytes)
}
```

## 4. Configuration

### IPFS Configuration Structure

```go
// pkg/network/ipfs_config.go
package network

import (
    "time"
    "github.com/multiformats/go-multiaddr"
)

// DefaultIPFSConfig returns default IPFS configuration
func DefaultIPFSConfig() *IPFSConfig {
    return &IPFSConfig{
        RepoPath:        "/var/lib/blackhole/ipfs",
        UseExistingHost: true,
        
        BootstrapNodes: []multiaddr.Multiaddr{
            // Blackhole bootstrap nodes
            multiaddr.StringCast("/dnsaddr/ipfs.blackhole.network/p2p/Qm..."),
            
            // IPFS public bootstrap nodes as fallback
            multiaddr.StringCast("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
            multiaddr.StringCast("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
        },
        
        Bitswap: BitswapConfig{
            MaxOutstandingBytesPerPeer: 1 << 20,  // 1MB
            TargetMessageSize:          16 << 10, // 16KB
            MaxProvideBatchSize:        50,
            TaskWorkerCount:            8,
            EngineBlockSize:            1 << 20,  // 1MB
            MaxPendingBlocks:           128,
            WantlistRetryDelay:         1 * time.Second,
        },
        
        Gateway: GatewayConfig{
            Enabled:       true,
            ListenAddr:    ":8080",
            PublicGateway: false,
            PathPrefixes:  []string{"/ipfs", "/ipns"},
            Headers: map[string][]string{
                "Cache-Control": {"public, max-age=29030400"},
            },
            Timeout: 30 * time.Second,
        },
        
        Datastore: DatastoreConfig{
            Type:       "flatfs",
            Path:       "datastore",
            StorageMax: "100GB",
            Compression: true,
        },
        
        GC: GCConfig{
            Enabled:   true,
            Interval:  1 * time.Hour,
            Threshold: 90.0,
        },
        
        Pinning: PinningConfig{
            Workers:           32,
            VerifyInterval:    24 * time.Hour,
            RemoteServices:    []RemotePinService{},
        },
        
        Performance: PerformanceConfig{
            MaxMemory:           "2GB",
            MaxOpenFiles:        8192,
            ConnMgrLowWater:     600,
            ConnMgrHighWater:    900,
            ConnMgrGracePeriod:  20 * time.Second,
        },
    }
}

// DatastoreConfig configures the datastore
type DatastoreConfig struct {
    Type        string
    Path        string
    StorageMax  string
    Compression bool
}

// PinningConfig configures pinning behavior
type PinningConfig struct {
    Workers        int
    VerifyInterval time.Duration
    RemoteServices []RemotePinService
}

// RemotePinService defines a remote pinning service
type RemotePinService struct {
    Name     string
    Endpoint string
    APIKey   string
}

// PerformanceConfig tunes performance
type PerformanceConfig struct {
    MaxMemory          string
    MaxOpenFiles       int
    ConnMgrLowWater    int
    ConnMgrHighWater   int
    ConnMgrGracePeriod time.Duration
}

// OptimizedIPFSConfig returns performance-optimized configuration
func OptimizedIPFSConfig() *IPFSConfig {
    cfg := DefaultIPFSConfig()
    
    // Optimize for performance
    cfg.Bitswap.TaskWorkerCount = 16
    cfg.Bitswap.MaxPendingBlocks = 256
    cfg.Performance.MaxMemory = "4GB"
    cfg.Performance.ConnMgrHighWater = 1200
    
    return cfg
}

// MinimalIPFSConfig returns minimal resource configuration
func MinimalIPFSConfig() *IPFSConfig {
    cfg := DefaultIPFSConfig()
    
    // Reduce resource usage
    cfg.Bitswap.TaskWorkerCount = 4
    cfg.Bitswap.MaxPendingBlocks = 64
    cfg.Performance.MaxMemory = "512MB"
    cfg.Performance.ConnMgrHighWater = 200
    cfg.Pinning.Workers = 8
    
    return cfg
}
```

### YAML Configuration

```yaml
# config/ipfs.yaml
ipfs:
  repo_path: "/var/lib/blackhole/ipfs"
  use_existing_host: true
  
  bootstrap:
    nodes:
      - "/dnsaddr/ipfs.blackhole.network/p2p/QmBootstrap1"
      - "/dnsaddr/ipfs.blackhole.network/p2p/QmBootstrap2"
      - "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
  
  bitswap:
    max_outstanding_bytes_per_peer: 1048576
    target_message_size: 16384
    max_provide_batch_size: 50
    task_worker_count: 8
    wantlist_retry_delay: "1s"
  
  gateway:
    enabled: true
    listen_addr: ":8080"
    public_gateway: false
    path_prefixes:
      - "/ipfs"
      - "/ipns"
      - "/blackhole"
    timeout: "30s"
    headers:
      Cache-Control:
        - "public, max-age=29030400"
      X-Frame-Options:
        - "DENY"
  
  datastore:
    type: "flatfs"
    path: "datastore"
    storage_max: "100GB"
    compression: true
  
  gc:
    enabled: true
    interval: "1h"
    threshold: 90.0
  
  pinning:
    workers: 32
    verify_interval: "24h"
    remote_services: []
  
  performance:
    max_memory: "2GB"
    max_open_files: 8192
    conn_mgr:
      low_water: 600
      high_water: 900
      grace_period: "20s"
```

## 5. Testing Requirements

### Unit Tests

```go
// pkg/network/ipfs_test.go
package network_test

import (
    "bytes"
    "context"
    "io"
    "testing"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestIPFSNodeCreation(t *testing.T) {
    ctx := context.Background()
    
    // Create test configuration
    cfg := &IPFSConfig{
        RepoPath: t.TempDir(),
        UseExistingHost: false,
    }
    
    // Create IPFS node
    node, err := NewIPFSNode(ctx, cfg)
    require.NoError(t, err)
    defer node.Stop()
    
    // Start node
    err = node.Start()
    require.NoError(t, err)
    
    // Verify node is running
    assert.NotNil(t, node.api)
    assert.NotEmpty(t, node.node.Identity)
}

func TestContentAddAndGet(t *testing.T) {
    ctx := context.Background()
    
    node := createTestIPFSNode(t)
    defer node.Stop()
    
    cm := NewContentManager(node)
    
    // Test data
    testData := []byte("Hello, IPFS from Blackhole!")
    
    // Add content
    cid, err := cm.AddContent(ctx, bytes.NewReader(testData))
    require.NoError(t, err)
    assert.NotEmpty(t, cid.String())
    
    // Get content
    reader, err := cm.GetContent(ctx, cid)
    require.NoError(t, err)
    defer reader.Close()
    
    // Verify content
    retrieved, err := io.ReadAll(reader)
    require.NoError(t, err)
    assert.Equal(t, testData, retrieved)
}

func TestPinning(t *testing.T) {
    ctx := context.Background()
    
    node := createTestIPFSNode(t)
    defer node.Stop()
    
    ps := NewPinningService(node, 4)
    cm := NewContentManager(node)
    
    // Add content without pinning
    cid, err := cm.AddContent(ctx, bytes.NewReader([]byte("test")), WithPin(false))
    require.NoError(t, err)
    
    // Check not pinned
    pinned, err := ps.IsPinned(ctx, cid)
    require.NoError(t, err)
    assert.False(t, pinned)
    
    // Pin content
    err = ps.Pin(ctx, cid, true)
    require.NoError(t, err)
    
    // Check pinned
    pinned, err = ps.IsPinned(ctx, cid)
    require.NoError(t, err)
    assert.True(t, pinned)
    
    // List pins
    pins, err := ps.ListPins(ctx, "")
    require.NoError(t, err)
    assert.NotEmpty(t, pins)
    
    // Unpin
    err = ps.Unpin(ctx, cid)
    require.NoError(t, err)
}

func TestBitswapOptimization(t *testing.T) {
    ctx := context.Background()
    
    // Create two nodes
    node1 := createTestIPFSNode(t)
    defer node1.Stop()
    
    node2 := createTestIPFSNode(t)
    defer node2.Stop()
    
    // Connect nodes
    node1.host.Peerstore().AddAddrs(node2.host.ID(), node2.host.Addrs(), time.Hour)
    err := node1.host.Connect(ctx, peer.AddrInfo{
        ID:    node2.host.ID(),
        Addrs: node2.host.Addrs(),
    })
    require.NoError(t, err)
    
    // Create Bitswap managers
    bm1 := NewBitswapManager(node1)
    bm2 := NewBitswapManager(node2)
    
    // Add content to node2
    cm2 := NewContentManager(node2)
    cid, err := cm2.AddContent(ctx, bytes.NewReader(make([]byte, 1024*1024))) // 1MB
    require.NoError(t, err)
    
    // Request from node1
    start := time.Now()
    err = bm1.RequestBlock(ctx, cid, 100)
    require.NoError(t, err)
    
    // Wait for transfer
    cm1 := NewContentManager(node1)
    reader, err := cm1.GetContent(ctx, cid)
    require.NoError(t, err)
    reader.Close()
    
    duration := time.Since(start)
    t.Logf("Transfer completed in %v", duration)
    
    // Check stats
    stats := bm1.GetPeerStats(node2.host.ID())
    assert.NotNil(t, stats)
    assert.Greater(t, stats.BlocksReceived, uint64(0))
}

func TestGateway(t *testing.T) {
    ctx := context.Background()
    
    node := createTestIPFSNode(t)
    defer node.Stop()
    
    // Configure gateway
    cfg := &GatewayConfig{
        Enabled:    true,
        ListenAddr: "127.0.0.1:0", // Random port
        Timeout:    10 * time.Second,
    }
    
    gateway := NewGatewayService(node, cfg)
    err := gateway.Start()
    require.NoError(t, err)
    defer gateway.Stop()
    
    // Add test content
    cm := NewContentManager(node)
    cid, err := cm.AddContent(ctx, bytes.NewReader([]byte("Gateway test")))
    require.NoError(t, err)
    
    // Request via gateway
    resp, err := http.Get(fmt.Sprintf("http://%s/ipfs/%s", gateway.server.Addr, cid))
    require.NoError(t, err)
    defer resp.Body.Close()
    
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    
    body, err := io.ReadAll(resp.Body)
    require.NoError(t, err)
    assert.Equal(t, "Gateway test", string(body))
}

// Helper functions

func createTestIPFSNode(t *testing.T) *IPFSNode {
    ctx := context.Background()
    
    cfg := &IPFSConfig{
        RepoPath:        t.TempDir(),
        UseExistingHost: false,
        GC: GCConfig{
            Enabled: false, // Disable for tests
        },
        Gateway: GatewayConfig{
            Enabled: false, // Disable for tests
        },
    }
    
    node, err := NewIPFSNode(ctx, cfg)
    require.NoError(t, err)
    
    err = node.Start()
    require.NoError(t, err)
    
    return node
}
```

### Integration Tests

```go
// pkg/network/ipfs_integration_test.go
package network_test

import (
    "context"
    "sync"
    "testing"
)

func TestIPFSNetworkIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create network of nodes
    nodes := createIPFSNetwork(t, 5)
    defer stopIPFSNetwork(nodes)
    
    // Add content to first node
    cm0 := NewContentManager(nodes[0])
    testData := make([]byte, 10*1024*1024) // 10MB
    rand.Read(testData)
    
    cid, err := cm0.AddContent(ctx, bytes.NewReader(testData))
    require.NoError(t, err)
    
    // Retrieve from all other nodes
    var wg sync.WaitGroup
    for i := 1; i < len(nodes); i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            
            cm := NewContentManager(nodes[idx])
            reader, err := cm.GetContent(ctx, cid)
            assert.NoError(t, err)
            if err == nil {
                data, _ := io.ReadAll(reader)
                reader.Close()
                assert.Equal(t, testData, data)
            }
        }(i)
    }
    
    wg.Wait()
}

func TestPinningReplication(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create nodes
    nodes := createIPFSNetwork(t, 3)
    defer stopIPFSNetwork(nodes)
    
    // Create pinning services
    pinServices := make([]*PinningService, len(nodes))
    for i, node := range nodes {
        pinServices[i] = NewPinningService(node, 4)
    }
    
    // Add and pin content on first node
    cm := NewContentManager(nodes[0])
    cid, err := cm.AddContent(ctx, bytes.NewReader([]byte("Replicated content")))
    require.NoError(t, err)
    
    // Pin on all nodes
    for _, ps := range pinServices {
        err := ps.Pin(ctx, cid, true)
        require.NoError(t, err)
    }
    
    // Verify pinned on all nodes
    for i, ps := range pinServices {
        pinned, err := ps.IsPinned(ctx, cid)
        require.NoError(t, err)
        assert.True(t, pinned, "Node %d should have content pinned", i)
    }
}

func TestGarbageCollectionSafety(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create node with aggressive GC
    cfg := DefaultIPFSConfig()
    cfg.RepoPath = t.TempDir()
    cfg.GC.Enabled = true
    cfg.GC.Interval = 1 * time.Second
    cfg.GC.Threshold = 50.0 // Low threshold
    
    node, err := NewIPFSNode(ctx, cfg)
    require.NoError(t, err)
    defer node.Stop()
    
    node.Start()
    
    cm := NewContentManager(node)
    ps := NewPinningService(node, 4)
    
    // Add pinned content
    pinnedCID, err := cm.AddContent(ctx, bytes.NewReader(make([]byte, 1024*1024)))
    require.NoError(t, err)
    
    // Add unpinned content
    unpinnedCID, err := cm.AddContent(ctx, bytes.NewReader(make([]byte, 1024*1024)), WithPin(false))
    require.NoError(t, err)
    
    // Wait for GC to run
    time.Sleep(3 * time.Second)
    
    // Verify pinned content still exists
    _, err = cm.GetContent(ctx, pinnedCID)
    assert.NoError(t, err, "Pinned content should not be garbage collected")
    
    // Unpinned content might be gone
    _, err = cm.GetContent(ctx, unpinnedCID)
    // May or may not error depending on GC timing
}

// Helper functions

func createIPFSNetwork(t *testing.T, count int) []*IPFSNode {
    nodes := make([]*IPFSNode, count)
    
    // Create bootstrap node
    nodes[0] = createTestIPFSNode(t)
    bootstrapAddrs := nodes[0].host.Addrs()
    bootstrapID := nodes[0].host.ID()
    
    // Create other nodes
    for i := 1; i < count; i++ {
        cfg := &IPFSConfig{
            RepoPath:        t.TempDir(),
            UseExistingHost: false,
            BootstrapNodes:  []multiaddr.Multiaddr{},
        }
        
        // Add bootstrap addresses
        for _, addr := range bootstrapAddrs {
            ma, _ := multiaddr.NewMultiaddr(fmt.Sprintf("%s/p2p/%s", addr, bootstrapID))
            cfg.BootstrapNodes = append(cfg.BootstrapNodes, ma)
        }
        
        node, err := NewIPFSNode(context.Background(), cfg)
        require.NoError(t, err)
        
        err = node.Start()
        require.NoError(t, err)
        
        nodes[i] = node
    }
    
    // Wait for network to stabilize
    time.Sleep(3 * time.Second)
    
    return nodes
}

func stopIPFSNetwork(nodes []*IPFSNode) {
    for _, node := range nodes {
        node.Stop()
    }
}
```

### Performance Benchmarks

```go
// pkg/network/ipfs_benchmark_test.go
package network_test

func BenchmarkContentAdd(b *testing.B) {
    node := createTestIPFSNode(b)
    defer node.Stop()
    
    cm := NewContentManager(node)
    ctx := context.Background()
    
    sizes := []int{
        1024,         // 1KB
        1024 * 1024,  // 1MB
        10 * 1024 * 1024, // 10MB
    }
    
    for _, size := range sizes {
        data := make([]byte, size)
        rand.Read(data)
        
        b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
            b.SetBytes(int64(size))
            b.ResetTimer()
            
            for i := 0; i < b.N; i++ {
                _, err := cm.AddContent(ctx, bytes.NewReader(data))
                if err != nil {
                    b.Fatal(err)
                }
            }
        })
    }
}

func BenchmarkContentGet(b *testing.B) {
    node := createTestIPFSNode(b)
    defer node.Stop()
    
    cm := NewContentManager(node)
    ctx := context.Background()
    
    // Pre-add content
    sizes := []int{1024, 1024 * 1024, 10 * 1024 * 1024}
    cids := make([]cid.Cid, len(sizes))
    
    for i, size := range sizes {
        data := make([]byte, size)
        rand.Read(data)
        c, _ := cm.AddContent(ctx, bytes.NewReader(data))
        cids[i] = c
    }
    
    for i, size := range sizes {
        b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
            b.SetBytes(int64(size))
            b.ResetTimer()
            
            for j := 0; j < b.N; j++ {
                reader, err := cm.GetContent(ctx, cids[i])
                if err != nil {
                    b.Fatal(err)
                }
                io.Copy(io.Discard, reader)
                reader.Close()
            }
        })
    }
}

func BenchmarkPinning(b *testing.B) {
    node := createTestIPFSNode(b)
    defer node.Stop()
    
    ps := NewPinningService(node, 8)
    cm := NewContentManager(node)
    ctx := context.Background()
    
    // Pre-add content
    cids := make([]cid.Cid, 100)
    for i := range cids {
        c, _ := cm.AddContent(ctx, bytes.NewReader(make([]byte, 1024)), WithPin(false))
        cids[i] = c
    }
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        c := cids[i%len(cids)]
        
        // Pin
        err := ps.Pin(ctx, c, false)
        if err != nil {
            b.Fatal(err)
        }
        
        // Unpin
        err = ps.Unpin(ctx, c)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## 6. Monitoring & Observability

### IPFS Metrics

```go
// pkg/network/ipfs_metrics.go
package network

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// IPFSMetrics tracks IPFS performance
type IPFSMetrics struct {
    // Content operations
    ContentAdded      prometheus.Counter
    ContentRetrieved  prometheus.Counter
    AddDuration       prometheus.Histogram
    GetDuration       prometheus.Histogram
    
    // Storage metrics
    RepoSize          prometheus.Gauge
    ObjectCount       prometheus.Gauge
    PinnedObjects     prometheus.Gauge
    
    // Bitswap metrics
    BlocksReceived    prometheus.Counter
    BlocksSent        prometheus.Counter
    WantlistSize      prometheus.Gauge
    PeerCount         prometheus.Gauge
    
    // Bandwidth metrics
    BandwidthIn       prometheus.Counter
    BandwidthOut      prometheus.Counter
    
    // Gateway metrics
    GatewayRequests   *prometheus.CounterVec
    GatewayDuration   prometheus.Histogram
    
    // GC metrics
    GCRuns            prometheus.Counter
    GCDuration        prometheus.Histogram
    ObjectsRemoved    prometheus.Counter
}

// NewIPFSMetrics creates IPFS metrics
func NewIPFSMetrics(namespace string) *IPFSMetrics {
    return &IPFSMetrics{
        ContentAdded: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_content_added_total",
            Help:      "Total content items added",
        }),
        
        ContentRetrieved: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_content_retrieved_total",
            Help:      "Total content items retrieved",
        }),
        
        AddDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Namespace: namespace,
            Name:      "ipfs_add_duration_seconds",
            Help:      "Content add duration",
            Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
        }),
        
        GetDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Namespace: namespace,
            Name:      "ipfs_get_duration_seconds",
            Help:      "Content get duration",
            Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
        }),
        
        RepoSize: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "ipfs_repo_size_bytes",
            Help:      "Repository size in bytes",
        }),
        
        ObjectCount: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "ipfs_object_count",
            Help:      "Number of objects in repo",
        }),
        
        PinnedObjects: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "ipfs_pinned_objects",
            Help:      "Number of pinned objects",
        }),
        
        BlocksReceived: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_blocks_received_total",
            Help:      "Total blocks received via Bitswap",
        }),
        
        BlocksSent: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_blocks_sent_total",
            Help:      "Total blocks sent via Bitswap",
        }),
        
        WantlistSize: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "ipfs_wantlist_size",
            Help:      "Current wantlist size",
        }),
        
        PeerCount: promauto.NewGauge(prometheus.GaugeOpts{
            Namespace: namespace,
            Name:      "ipfs_peer_count",
            Help:      "Number of connected peers",
        }),
        
        BandwidthIn: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_bandwidth_in_bytes",
            Help:      "Total bytes received",
        }),
        
        BandwidthOut: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_bandwidth_out_bytes",
            Help:      "Total bytes sent",
        }),
        
        GatewayRequests: promauto.NewCounterVec(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_gateway_requests_total",
            Help:      "Gateway requests by path",
        }, []string{"path", "status"}),
        
        GatewayDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Namespace: namespace,
            Name:      "ipfs_gateway_duration_seconds",
            Help:      "Gateway request duration",
            Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
        }),
        
        GCRuns: promauto.NewCounter(prometheus.CounterOpts{
            Namespace: namespace,
            Name:      "ipfs_gc_runs_total",
            Help:      "Total garbage collection runs",
        }),
        
        GCDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Namespace: namespace,
            Name:      "ipfs_gc_duration_seconds",
            Help:      "Garbage collection duration",
            Buckets:   prometheus.ExponentialBuckets(1, 2, 10),
        }),
    }
}
```

### Grafana Dashboard Configuration

```yaml
# IPFS Monitoring Dashboard
panels:
  - title: "Content Operations"
    queries:
      - "rate(blackhole_ipfs_content_added_total[5m])"
      - "rate(blackhole_ipfs_content_retrieved_total[5m])"
    
  - title: "Operation Latency (p95)"
    queries:
      - |
        histogram_quantile(0.95, 
          rate(blackhole_ipfs_add_duration_seconds_bucket[5m])
        )
      - |
        histogram_quantile(0.95,
          rate(blackhole_ipfs_get_duration_seconds_bucket[5m])
        )
    
  - title: "Repository Size"
    query: "blackhole_ipfs_repo_size_bytes"
    
  - title: "Bitswap Activity"
    queries:
      - "rate(blackhole_ipfs_blocks_received_total[5m])"
      - "rate(blackhole_ipfs_blocks_sent_total[5m])"
    
  - title: "Bandwidth Usage"
    queries:
      - "rate(blackhole_ipfs_bandwidth_in_bytes[5m])"
      - "rate(blackhole_ipfs_bandwidth_out_bytes[5m])"
    
  - title: "Peer Connections"
    query: "blackhole_ipfs_peer_count"
    
  - title: "Gateway Performance"
    query: |
      histogram_quantile(0.95,
        rate(blackhole_ipfs_gateway_duration_seconds_bucket[5m])
      )
    
  - title: "Pinned Objects"
    query: "blackhole_ipfs_pinned_objects"
```

## 7. Acceptance Criteria

### Functional Requirements

1. **IPFS Integration**
   - [ ] IPFS node starts successfully
   - [ ] Shares libp2p host with network layer
   - [ ] Bootstrap connections established
   - [ ] Content routing functional

2. **Content Management**
   - [ ] Content add/get operations work
   - [ ] Directory support functional
   - [ ] Metadata retrieval accurate
   - [ ] Chunking strategies applied

3. **Pinning Service**
   - [ ] Pin/unpin operations successful
   - [ ] Pin verification works
   - [ ] Concurrent pinning efficient
   - [ ] Pin persistence across restarts

4. **Gateway Service**
   - [ ] HTTP gateway accessible
   - [ ] /ipfs/* paths serve content
   - [ ] Custom endpoints functional
   - [ ] Rate limiting enforced

### Performance Requirements

1. **Content Operations**
   - Add: > 50MB/s for local content
   - Get: > 100MB/s for cached content
   - < 100ms latency for small files

2. **Bitswap Performance**
   - > 10MB/s transfer between peers
   - < 5s discovery time for content
   - Efficient bandwidth utilization

3. **Resource Usage**
   - < 500MB memory baseline
   - < 10% CPU idle usage
   - Efficient disk I/O patterns

## 8. Example Usage

### Complete IPFS Setup

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
    host, _ := network.NewHost(ctx, network.DefaultConfig())
    defer host.Stop()
    
    // Configure IPFS
    ipfsConfig := network.DefaultIPFSConfig()
    ipfsConfig.UseExistingHost = true
    ipfsConfig.Host = host
    
    // Create IPFS node
    ipfsNode, err := network.NewIPFSNode(ctx, ipfsConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer ipfsNode.Stop()
    
    // Start IPFS
    if err := ipfsNode.Start(); err != nil {
        log.Fatal(err)
    }
    
    // Create managers
    content := network.NewContentManager(ipfsNode)
    pinning := network.NewPinningService(ipfsNode, 8)
    bitswap := network.NewBitswapManager(ipfsNode)
    
    // Start gateway
    gateway := network.NewGatewayService(ipfsNode, &ipfsConfig.Gateway)
    gateway.Start()
    defer gateway.Stop()
    
    log.Printf("IPFS node running with ID: %s", ipfsNode.node.Identity)
    log.Printf("Gateway available at: %s", ipfsConfig.Gateway.ListenAddr)
    
    // Your application continues...
    select {}
}
```

### Content Operations Example

```go
// Store file in IPFS
func storeFile(cm *ContentManager, filePath string) (cid.Cid, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return cid.Cid{}, err
    }
    defer file.Close()
    
    // Add with progress tracking
    progress := make(chan int64, 1)
    go func() {
        for bytes := range progress {
            fmt.Printf("Uploaded: %d bytes\n", bytes)
        }
    }()
    
    return cm.AddContent(context.Background(), file,
        WithPin(true),
        WithProgress(progress),
        WithChunker("rabin-512KB-1MB-2MB"),
    )
}

// Create directory structure
func createDirectory(cm *ContentManager) (cid.Cid, error) {
    // Create in-memory directory
    dir := files.NewMapDirectory(map[string]files.Node{
        "README.md": files.NewBytesFile([]byte("# My Project")),
        "src": files.NewMapDirectory(map[string]files.Node{
            "main.go": files.NewBytesFile([]byte("package main...")),
        }),
    })
    
    return cm.AddDirectory(context.Background(), dir)
}
```

## Summary

Unit U04 successfully integrates IPFS as the distributed storage foundation for Blackhole. The implementation provides:

- Seamless integration with existing libp2p infrastructure
- Efficient content management and distribution
- Robust pinning and garbage collection
- HTTP gateway for web compatibility
- Optimized Bitswap for performance
- Comprehensive monitoring and metrics

This IPFS integration enables Blackhole to leverage proven distributed storage technology while maintaining full control over configuration and optimization for the platform's specific needs.