# U40: Filesystem Cache Implementation

## Overview
Multi-level caching system for the distributed filesystem. Provides block-level caching, metadata caching, prefetching strategies, write coalescing, and cache coherence across the distributed cluster.

## Architecture

```
Filesystem Cache
├── Block Cache Layer
├── Metadata Cache Layer
├── Prefetch Engine
├── Write Coalescing
└── Coherence Protocol
```

## Complete Implementation

### 1. Core Cache Structures

```go
package cache

import (
    "container/list"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "sync"
    "sync/atomic"
    "time"
)

type CacheEntry struct {
    Key       string
    Value     []byte
    Size      int64
    Timestamp time.Time
    AccessCount uint64
    Dirty     bool
    Version   uint64
    TTL       time.Duration
    element   *list.Element // For LRU
}

type CacheStats struct {
    Hits             uint64 `json:"hits"`
    Misses           uint64 `json:"misses"`
    Evictions        uint64 `json:"evictions"`
    TotalSize        int64  `json:"total_size"`
    MaxSize          int64  `json:"max_size"`
    EntryCount       int    `json:"entry_count"`
    HitRatio         float64 `json:"hit_ratio"`
    PrefetchHits     uint64 `json:"prefetch_hits"`
    WriteCoalescing  uint64 `json:"write_coalescing"`
    CoherenceUpdates uint64 `json:"coherence_updates"`
}

type CacheType int

const (
    CacheTypeBlock CacheType = iota
    CacheTypeMetadata
    CacheTypeDirectory
    CacheTypeInode
    CacheTypeExtendedAttrs
)

type CacheLevel int

const (
    CacheLevelL1 CacheLevel = iota // Memory cache
    CacheLevelL2                   // SSD cache
    CacheLevelL3                   // Network cache
)

type EvictionPolicy int

const (
    EvictionLRU EvictionPolicy = iota
    EvictionLFU
    EvictionTTL
    EvictionAdaptive
)
```

### 2. Multi-Level Cache Manager

```go
type FilesystemCache struct {
    levels     []*CacheLevel
    config     *CacheConfig
    stats      *CacheStats
    prefetcher *Prefetcher
    coalescer  *WriteCoalescer
    coherence  *CoherenceManager
    mu         sync.RWMutex
    
    // Cache invalidation
    invalidationCh chan InvalidationEvent
    subscribers    map[string]chan InvalidationEvent
    
    // Background workers
    ctx       context.Context
    cancel    context.CancelFunc
    wg        sync.WaitGroup
}

type CacheConfig struct {
    L1Config *LevelConfig `yaml:"l1"`
    L2Config *LevelConfig `yaml:"l2"`
    L3Config *LevelConfig `yaml:"l3"`
    
    // Global settings
    EnablePrefetch     bool          `yaml:"enable_prefetch"`
    EnableCoalescing   bool          `yaml:"enable_coalescing"`
    EnableCoherence    bool          `yaml:"enable_coherence"`
    SyncInterval       time.Duration `yaml:"sync_interval"`
    CleanupInterval    time.Duration `yaml:"cleanup_interval"`
    CompressionEnabled bool          `yaml:"compression_enabled"`
    EncryptionEnabled  bool          `yaml:"encryption_enabled"`
}

type LevelConfig struct {
    MaxSize        int64           `yaml:"max_size"`
    MaxEntries     int             `yaml:"max_entries"`
    TTL            time.Duration   `yaml:"ttl"`
    EvictionPolicy EvictionPolicy  `yaml:"eviction_policy"`
    WriteBehind    bool            `yaml:"write_behind"`
    WriteThrough   bool            `yaml:"write_through"`
    Persistent     bool            `yaml:"persistent"`
    StoragePath    string          `yaml:"storage_path"`
    BlockSize      int             `yaml:"block_size"`
}

func NewFilesystemCache(config *CacheConfig) (*FilesystemCache, error) {
    if config == nil {
        config = DefaultCacheConfig()
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    fc := &FilesystemCache{
        config:         config,
        stats:          &CacheStats{},
        invalidationCh: make(chan InvalidationEvent, 1000),
        subscribers:    make(map[string]chan InvalidationEvent),
        ctx:           ctx,
        cancel:        cancel,
    }
    
    // Initialize cache levels
    if err := fc.initializeLevels(); err != nil {
        return nil, err
    }
    
    // Initialize components
    fc.prefetcher = NewPrefetcher(fc, config)
    fc.coalescer = NewWriteCoalescer(fc, config)
    fc.coherence = NewCoherenceManager(fc, config)
    
    // Start background workers
    fc.startWorkers()
    
    return fc, nil
}

func DefaultCacheConfig() *CacheConfig {
    return &CacheConfig{
        L1Config: &LevelConfig{
            MaxSize:        1024 * 1024 * 1024, // 1GB
            MaxEntries:     100000,
            TTL:            5 * time.Minute,
            EvictionPolicy: EvictionLRU,
            WriteBehind:    false,
            WriteThrough:   true,
            Persistent:     false,
            BlockSize:      4096,
        },
        L2Config: &LevelConfig{
            MaxSize:        10 * 1024 * 1024 * 1024, // 10GB
            MaxEntries:     1000000,
            TTL:            30 * time.Minute,
            EvictionPolicy: EvictionLFU,
            WriteBehind:    true,
            WriteThrough:   false,
            Persistent:     true,
            StoragePath:    "/var/cache/blackhole/l2",
            BlockSize:      65536,
        },
        L3Config: &LevelConfig{
            MaxSize:        100 * 1024 * 1024 * 1024, // 100GB
            MaxEntries:     10000000,
            TTL:            2 * time.Hour,
            EvictionPolicy: EvictionTTL,
            WriteBehind:    true,
            WriteThrough:   false,
            Persistent:     true,
            StoragePath:    "/var/cache/blackhole/l3",
            BlockSize:      1048576,
        },
        EnablePrefetch:     true,
        EnableCoalescing:   true,
        EnableCoherence:    true,
        SyncInterval:       30 * time.Second,
        CleanupInterval:    5 * time.Minute,
        CompressionEnabled: true,
        EncryptionEnabled:  false,
    }
}

func (fc *FilesystemCache) initializeLevels() error {
    configs := []*LevelConfig{fc.config.L1Config, fc.config.L2Config, fc.config.L3Config}
    
    for i, config := range configs {
        if config == nil {
            continue
        }
        
        level, err := NewCacheLevel(CacheLevel(i), config)
        if err != nil {
            return fmt.Errorf("failed to initialize cache level %d: %v", i, err)
        }
        
        fc.levels = append(fc.levels, level)
    }
    
    return nil
}

func (fc *FilesystemCache) startWorkers() {
    // Prefetcher worker
    if fc.config.EnablePrefetch {
        fc.wg.Add(1)
        go func() {
            defer fc.wg.Done()
            fc.prefetcher.Run(fc.ctx)
        }()
    }
    
    // Write coalescer worker
    if fc.config.EnableCoalescing {
        fc.wg.Add(1)
        go func() {
            defer fc.wg.Done()
            fc.coalescer.Run(fc.ctx)
        }()
    }
    
    // Coherence manager worker
    if fc.config.EnableCoherence {
        fc.wg.Add(1)
        go func() {
            defer fc.wg.Done()
            fc.coherence.Run(fc.ctx)
        }()
    }
    
    // Cache cleanup worker
    fc.wg.Add(1)
    go func() {
        defer fc.wg.Done()
        fc.runCleanup()
    }()
    
    // Statistics worker
    fc.wg.Add(1)
    go func() {
        defer fc.wg.Done()
        fc.runStatsUpdater()
    }()
}
```

### 3. Cache Level Implementation

```go
type CacheLevel struct {
    level    CacheLevel
    config   *LevelConfig
    entries  map[string]*CacheEntry
    lruList  *list.List
    lfuHeap  *LFUHeap
    mu       sync.RWMutex
    
    // Statistics
    hits      uint64
    misses    uint64
    evictions uint64
    totalSize int64
    
    // Persistent storage
    storage PersistentStorage
}

type PersistentStorage interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte) error
    Delete(key string) error
    Exists(key string) bool
    Sync() error
    Close() error
}

func NewCacheLevel(level CacheLevel, config *LevelConfig) (*CacheLevel, error) {
    cl := &CacheLevel{
        level:   level,
        config:  config,
        entries: make(map[string]*CacheEntry),
        lruList: list.New(),
    }
    
    if config.EvictionPolicy == EvictionLFU {
        cl.lfuHeap = NewLFUHeap()
    }
    
    if config.Persistent {
        storage, err := NewBoltStorage(config.StoragePath)
        if err != nil {
            return nil, err
        }
        cl.storage = storage
        
        // Load existing entries
        if err := cl.loadPersistedEntries(); err != nil {
            return nil, err
        }
    }
    
    return cl, nil
}

func (cl *CacheLevel) Get(key string) (*CacheEntry, bool) {
    cl.mu.RLock()
    defer cl.mu.RUnlock()
    
    entry, exists := cl.entries[key]
    if !exists {
        atomic.AddUint64(&cl.misses, 1)
        return nil, false
    }
    
    // Check TTL
    if cl.config.TTL > 0 && time.Since(entry.Timestamp) > cl.config.TTL {
        // Entry expired
        cl.mu.RUnlock()
        cl.mu.Lock()
        cl.evictEntry(key)
        cl.mu.Unlock()
        cl.mu.RLock()
        atomic.AddUint64(&cl.misses, 1)
        return nil, false
    }
    
    // Update access statistics
    atomic.AddUint64(&entry.AccessCount, 1)
    atomic.AddUint64(&cl.hits, 1)
    entry.Timestamp = time.Now()
    
    // Update LRU position
    if cl.config.EvictionPolicy == EvictionLRU && entry.element != nil {
        cl.lruList.MoveToFront(entry.element)
    }
    
    // Update LFU heap
    if cl.config.EvictionPolicy == EvictionLFU {
        cl.lfuHeap.Update(entry)
    }
    
    return entry, true
}

func (cl *CacheLevel) Put(key string, data []byte, cacheType CacheType) error {
    cl.mu.Lock()
    defer cl.mu.Unlock()
    
    // Check if entry already exists
    if existing, exists := cl.entries[key]; exists {
        // Update existing entry
        existing.Value = data
        existing.Size = int64(len(data))
        existing.Timestamp = time.Now()
        existing.Version++
        atomic.AddUint64(&existing.AccessCount, 1)
        
        if cl.config.EvictionPolicy == EvictionLRU && existing.element != nil {
            cl.lruList.MoveToFront(existing.element)
        }
        
        return cl.persistEntry(key, existing)
    }
    
    // Create new entry
    entry := &CacheEntry{
        Key:       key,
        Value:     make([]byte, len(data)),
        Size:      int64(len(data)),
        Timestamp: time.Now(),
        AccessCount: 1,
        Version:   1,
        TTL:       cl.config.TTL,
    }
    copy(entry.Value, data)
    
    // Check capacity
    if err := cl.ensureCapacity(entry.Size); err != nil {
        return err
    }
    
    // Add to cache
    cl.entries[key] = entry
    cl.totalSize += entry.Size
    
    // Add to eviction data structure
    switch cl.config.EvictionPolicy {
    case EvictionLRU:
        entry.element = cl.lruList.PushFront(key)
    case EvictionLFU:
        cl.lfuHeap.Add(entry)
    }
    
    return cl.persistEntry(key, entry)
}

func (cl *CacheLevel) Delete(key string) error {
    cl.mu.Lock()
    defer cl.mu.Unlock()
    
    return cl.evictEntry(key)
}

func (cl *CacheLevel) evictEntry(key string) error {
    entry, exists := cl.entries[key]
    if !exists {
        return nil
    }
    
    delete(cl.entries, key)
    cl.totalSize -= entry.Size
    atomic.AddUint64(&cl.evictions, 1)
    
    // Remove from eviction data structure
    switch cl.config.EvictionPolicy {
    case EvictionLRU:
        if entry.element != nil {
            cl.lruList.Remove(entry.element)
        }
    case EvictionLFU:
        cl.lfuHeap.Remove(entry)
    }
    
    // Remove from persistent storage
    if cl.storage != nil {
        return cl.storage.Delete(key)
    }
    
    return nil
}

func (cl *CacheLevel) ensureCapacity(newSize int64) error {
    for cl.totalSize+newSize > cl.config.MaxSize || len(cl.entries) >= cl.config.MaxEntries {
        if err := cl.evictOneEntry(); err != nil {
            return err
        }
    }
    return nil
}

func (cl *CacheLevel) evictOneEntry() error {
    var victimKey string
    
    switch cl.config.EvictionPolicy {
    case EvictionLRU:
        if cl.lruList.Len() == 0 {
            return fmt.Errorf("no entries to evict")
        }
        elem := cl.lruList.Back()
        victimKey = elem.Value.(string)
        
    case EvictionLFU:
        victim := cl.lfuHeap.ExtractMin()
        if victim == nil {
            return fmt.Errorf("no entries to evict")
        }
        victimKey = victim.Key
        
    case EvictionTTL:
        // Find oldest entry
        var oldestKey string
        var oldestTime time.Time
        
        for key, entry := range cl.entries {
            if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
                oldestKey = key
                oldestTime = entry.Timestamp
            }
        }
        
        if oldestKey == "" {
            return fmt.Errorf("no entries to evict")
        }
        victimKey = oldestKey
        
    case EvictionAdaptive:
        // Adaptive replacement based on access patterns
        victimKey = cl.selectAdaptiveVictim()
    }
    
    return cl.evictEntry(victimKey)
}

func (cl *CacheLevel) selectAdaptiveVictim() string {
    // Simple adaptive algorithm: combine LRU and LFU
    if len(cl.entries) == 0 {
        return ""
    }
    
    var minScore float64 = -1
    var victimKey string
    
    now := time.Now()
    
    for key, entry := range cl.entries {
        // Score based on recency and frequency
        timeSinceAccess := now.Sub(entry.Timestamp).Seconds()
        accessFreq := float64(entry.AccessCount)
        
        score := accessFreq / (1.0 + timeSinceAccess)
        
        if minScore < 0 || score < minScore {
            minScore = score
            victimKey = key
        }
    }
    
    return victimKey
}

func (cl *CacheLevel) persistEntry(key string, entry *CacheEntry) error {
    if cl.storage == nil || !cl.config.Persistent {
        return nil
    }
    
    data := entry.Value
    if cl.config.WriteThrough {
        return cl.storage.Put(key, data)
    }
    
    if cl.config.WriteBehind {
        entry.Dirty = true
        // Actual write happens in background
    }
    
    return nil
}

func (cl *CacheLevel) loadPersistedEntries() error {
    // This would load entries from persistent storage
    // Implementation depends on the storage backend
    return nil
}
```

### 4. Prefetch Engine

```go
type Prefetcher struct {
    cache       *FilesystemCache
    config      *CacheConfig
    patterns    *AccessPatternDetector
    requests    chan PrefetchRequest
    mu          sync.RWMutex
    
    // Statistics
    prefetchHits   uint64
    prefetchMisses uint64
    totalPrefetched uint64
}

type PrefetchRequest struct {
    Key        string
    Priority   int
    Pattern    AccessPattern
    Context    map[string]interface{}
}

type AccessPattern int

const (
    PatternSequential AccessPattern = iota
    PatternRandom
    PatternSpatial
    PatternTemporal
)

type AccessPatternDetector struct {
    recentAccesses *list.List
    sequentialRuns map[string]*SequentialRun
    spatialGroups  map[string]*SpatialGroup
    mu             sync.RWMutex
}

type SequentialRun struct {
    BaseKey   string
    Count     int
    Direction int // 1 for forward, -1 for backward
    LastAccess time.Time
}

type SpatialGroup struct {
    Members    map[string]bool
    Center     string
    LastAccess time.Time
}

func NewPrefetcher(cache *FilesystemCache, config *CacheConfig) *Prefetcher {
    return &Prefetcher{
        cache:    cache,
        config:   config,
        patterns: NewAccessPatternDetector(),
        requests: make(chan PrefetchRequest, 10000),
    }
}

func (p *Prefetcher) Run(ctx context.Context) {
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case req := <-p.requests:
            p.processPrefetchRequest(req)
        case <-ticker.C:
            p.analyzePatternsAndPrefetch()
        }
    }
}

func (p *Prefetcher) OnAccess(key string, cacheType CacheType) {
    p.patterns.RecordAccess(key, cacheType)
    
    // Detect pattern and trigger prefetch
    pattern := p.patterns.DetectPattern(key)
    
    switch pattern {
    case PatternSequential:
        p.prefetchSequential(key)
    case PatternSpatial:
        p.prefetchSpatial(key)
    case PatternTemporal:
        p.prefetchTemporal(key)
    }
}

func (p *Prefetcher) prefetchSequential(key string) {
    // Extract base path and sequence number
    basePath, seqNum, err := parseSequentialKey(key)
    if err != nil {
        return
    }
    
    // Prefetch next few blocks
    for i := 1; i <= 5; i++ {
        nextKey := fmt.Sprintf("%s_%d", basePath, seqNum+i)
        p.requests <- PrefetchRequest{
            Key:      nextKey,
            Priority: 10 - i,
            Pattern:  PatternSequential,
            Context:  map[string]interface{}{"base": basePath, "offset": i},
        }
    }
}

func (p *Prefetcher) prefetchSpatial(key string) {
    // Prefetch related files in the same directory
    dir := getDirectoryFromKey(key)
    
    // Get sibling files
    siblings := p.getSiblingFiles(dir)
    
    for _, sibling := range siblings {
        if sibling != key {
            p.requests <- PrefetchRequest{
                Key:      sibling,
                Priority: 5,
                Pattern:  PatternSpatial,
                Context:  map[string]interface{}{"directory": dir},
            }
        }
    }
}

func (p *Prefetcher) prefetchTemporal(key string) {
    // Prefetch files that are often accessed together with this file
    related := p.patterns.GetTemporallyRelated(key)
    
    for _, relatedKey := range related {
        p.requests <- PrefetchRequest{
            Key:      relatedKey,
            Priority: 3,
            Pattern:  PatternTemporal,
            Context:  map[string]interface{}{"trigger": key},
        }
    }
}

func (p *Prefetcher) processPrefetchRequest(req PrefetchRequest) {
    // Check if already in cache
    if p.cache.Exists(req.Key) {
        atomic.AddUint64(&p.prefetchHits, 1)
        return
    }
    
    // Fetch data from storage
    data, err := p.fetchFromStorage(req.Key)
    if err != nil {
        atomic.AddUint64(&p.prefetchMisses, 1)
        return
    }
    
    // Add to cache with low priority
    p.cache.PutWithPriority(req.Key, data, CacheTypeBlock, req.Priority)
    atomic.AddUint64(&p.totalPrefetched, 1)
}

func (p *Prefetcher) analyzePatternsAndPrefetch() {
    // Analyze access patterns and trigger prefetch
    patterns := p.patterns.GetActivePatterns()
    
    for _, pattern := range patterns {
        switch pattern.Type {
        case PatternSequential:
            p.prefetchSequentialPattern(pattern)
        case PatternSpatial:
            p.prefetchSpatialPattern(pattern)
        }
    }
}

func NewAccessPatternDetector() *AccessPatternDetector {
    return &AccessPatternDetector{
        recentAccesses: list.New(),
        sequentialRuns: make(map[string]*SequentialRun),
        spatialGroups:  make(map[string]*SpatialGroup),
    }
}

func (apd *AccessPatternDetector) RecordAccess(key string, cacheType CacheType) {
    apd.mu.Lock()
    defer apd.mu.Unlock()
    
    access := &AccessRecord{
        Key:       key,
        Type:      cacheType,
        Timestamp: time.Now(),
    }
    
    apd.recentAccesses.PushFront(access)
    
    // Keep only recent accesses (last 1000)
    if apd.recentAccesses.Len() > 1000 {
        apd.recentAccesses.Remove(apd.recentAccesses.Back())
    }
    
    // Update pattern detection
    apd.updateSequentialRuns(key)
    apd.updateSpatialGroups(key)
}

func (apd *AccessPatternDetector) DetectPattern(key string) AccessPattern {
    apd.mu.RLock()
    defer apd.mu.RUnlock()
    
    // Check for sequential pattern
    if run, exists := apd.sequentialRuns[getBaseKey(key)]; exists {
        if run.Count >= 3 && time.Since(run.LastAccess) < 5*time.Second {
            return PatternSequential
        }
    }
    
    // Check for spatial pattern
    dir := getDirectoryFromKey(key)
    if group, exists := apd.spatialGroups[dir]; exists {
        if len(group.Members) >= 3 && time.Since(group.LastAccess) < 10*time.Second {
            return PatternSpatial
        }
    }
    
    // Check for temporal pattern
    if apd.hasTemporalPattern(key) {
        return PatternTemporal
    }
    
    return PatternRandom
}

type AccessRecord struct {
    Key       string
    Type      CacheType
    Timestamp time.Time
}
```

### 5. Write Coalescing

```go
type WriteCoalescer struct {
    cache       *FilesystemCache
    config      *CacheConfig
    pendingWrites map[string]*CoalescedWrite
    flushQueue    chan string
    mu            sync.RWMutex
    
    // Statistics
    coalesced     uint64
    flushes       uint64
    bytesReduced  uint64
}

type CoalescedWrite struct {
    Key         string
    Data        []byte
    Regions     []*WriteRegion
    FirstWrite  time.Time
    LastWrite   time.Time
    WriteCount  int
    Dirty       bool
}

type WriteRegion struct {
    Offset int64
    Length int64
    Data   []byte
}

func NewWriteCoalescer(cache *FilesystemCache, config *CacheConfig) *WriteCoalescer {
    return &WriteCoalescer{
        cache:         cache,
        config:        config,
        pendingWrites: make(map[string]*CoalescedWrite),
        flushQueue:    make(chan string, 1000),
    }
}

func (wc *WriteCoalescer) Run(ctx context.Context) {
    flushTicker := time.NewTicker(5 * time.Second)
    defer flushTicker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            wc.flushAll()
            return
        case key := <-wc.flushQueue:
            wc.flushWrite(key)
        case <-flushTicker.C:
            wc.flushExpiredWrites()
        }
    }
}

func (wc *WriteCoalescer) CoalesceWrite(key string, offset int64, data []byte) error {
    wc.mu.Lock()
    defer wc.mu.Unlock()
    
    write, exists := wc.pendingWrites[key]
    if !exists {
        write = &CoalescedWrite{
            Key:        key,
            Data:       make([]byte, 0),
            Regions:    make([]*WriteRegion, 0),
            FirstWrite: time.Now(),
            LastWrite:  time.Now(),
            WriteCount: 1,
            Dirty:      true,
        }
        wc.pendingWrites[key] = write
    } else {
        write.LastWrite = time.Now()
        write.WriteCount++
        atomic.AddUint64(&wc.coalesced, 1)
    }
    
    // Add write region
    region := &WriteRegion{
        Offset: offset,
        Length: int64(len(data)),
        Data:   make([]byte, len(data)),
    }
    copy(region.Data, data)
    
    write.Regions = append(write.Regions, region)
    
    // Merge overlapping regions
    wc.mergeRegions(write)
    
    // Check if we should flush immediately
    if wc.shouldFlushImmediate(write) {
        wc.flushQueue <- key
    }
    
    return nil
}

func (wc *WriteCoalescer) mergeRegions(write *CoalescedWrite) {
    if len(write.Regions) <= 1 {
        return
    }
    
    // Sort regions by offset
    sort.Slice(write.Regions, func(i, j int) bool {
        return write.Regions[i].Offset < write.Regions[j].Offset
    })
    
    merged := make([]*WriteRegion, 0, len(write.Regions))
    current := write.Regions[0]
    
    for i := 1; i < len(write.Regions); i++ {
        next := write.Regions[i]
        
        // Check if regions overlap or are adjacent
        if current.Offset+current.Length >= next.Offset {
            // Merge regions
            endOffset := max(current.Offset+current.Length, next.Offset+next.Length)
            newLength := endOffset - current.Offset
            
            newData := make([]byte, newLength)
            copy(newData, current.Data)
            
            // Copy non-overlapping part of next region
            nextStart := max(0, next.Offset-current.Offset)
            if nextStart < int64(len(newData)) {
                copy(newData[nextStart:], next.Data)
            }
            
            current = &WriteRegion{
                Offset: current.Offset,
                Length: newLength,
                Data:   newData,
            }
            
            atomic.AddUint64(&wc.bytesReduced, uint64(next.Length))
        } else {
            merged = append(merged, current)
            current = next
        }
    }
    
    merged = append(merged, current)
    write.Regions = merged
}

func (wc *WriteCoalescer) shouldFlushImmediate(write *CoalescedWrite) bool {
    // Flush conditions
    if time.Since(write.FirstWrite) > 30*time.Second {
        return true
    }
    
    if write.WriteCount > 10 {
        return true
    }
    
    totalSize := int64(0)
    for _, region := range write.Regions {
        totalSize += region.Length
    }
    
    if totalSize > 1024*1024 { // 1MB
        return true
    }
    
    return false
}

func (wc *WriteCoalescer) flushWrite(key string) error {
    wc.mu.Lock()
    write, exists := wc.pendingWrites[key]
    if !exists {
        wc.mu.Unlock()
        return nil
    }
    delete(wc.pendingWrites, key)
    wc.mu.Unlock()
    
    // Reconstruct full data from regions
    data, err := wc.reconstructData(write)
    if err != nil {
        return err
    }
    
    // Write to cache and storage
    if err := wc.cache.Put(key, data); err != nil {
        return err
    }
    
    atomic.AddUint64(&wc.flushes, 1)
    return nil
}

func (wc *WriteCoalescer) reconstructData(write *CoalescedWrite) ([]byte, error) {
    if len(write.Regions) == 0 {
        return []byte{}, nil
    }
    
    // Find total size needed
    maxEnd := int64(0)
    for _, region := range write.Regions {
        end := region.Offset + region.Length
        if end > maxEnd {
            maxEnd = end
        }
    }
    
    // Get existing data from cache
    existing := wc.cache.Get(write.Key, 0, maxEnd)
    
    result := make([]byte, maxEnd)
    if existing != nil && len(existing) > 0 {
        copy(result, existing)
    }
    
    // Apply all regions
    for _, region := range write.Regions {
        if region.Offset+region.Length <= int64(len(result)) {
            copy(result[region.Offset:region.Offset+region.Length], region.Data)
        }
    }
    
    return result, nil
}

func (wc *WriteCoalescer) flushExpiredWrites() {
    wc.mu.RLock()
    var expiredKeys []string
    
    for key, write := range wc.pendingWrites {
        if time.Since(write.FirstWrite) > 10*time.Second {
            expiredKeys = append(expiredKeys, key)
        }
    }
    wc.mu.RUnlock()
    
    for _, key := range expiredKeys {
        wc.flushQueue <- key
    }
}

func (wc *WriteCoalescer) flushAll() {
    wc.mu.RLock()
    keys := make([]string, 0, len(wc.pendingWrites))
    for key := range wc.pendingWrites {
        keys = append(keys, key)
    }
    wc.mu.RUnlock()
    
    for _, key := range keys {
        wc.flushWrite(key)
    }
}

func max(a, b int64) int64 {
    if a > b {
        return a
    }
    return b
}
```

### 6. Cache Coherence Protocol

```go
type CoherenceManager struct {
    cache       *FilesystemCache
    config      *CacheConfig
    nodeID      string
    peers       map[string]*PeerConnection
    protocol    CoherenceProtocol
    messages    chan CoherenceMessage
    mu          sync.RWMutex
    
    // Statistics
    invalidations uint64
    updates       uint64
    conflicts     uint64
}

type CoherenceProtocol int

const (
    ProtocolMSI CoherenceProtocol = iota // Modified, Shared, Invalid
    ProtocolMESI                        // Modified, Exclusive, Shared, Invalid
    ProtocolMOESI                       // Modified, Owned, Exclusive, Shared, Invalid
)

type CoherenceState int

const (
    StateInvalid CoherenceState = iota
    StateShared
    StateExclusive
    StateModified
    StateOwned
)

type CoherenceMessage struct {
    Type      MessageType              `json:"type"`
    NodeID    string                   `json:"node_id"`
    Key       string                   `json:"key"`
    Version   uint64                   `json:"version"`
    Data      []byte                   `json:"data,omitempty"`
    State     CoherenceState           `json:"state"`
    Timestamp time.Time                `json:"timestamp"`
    Context   map[string]interface{}   `json:"context,omitempty"`
}

type MessageType int

const (
    MsgInvalidate MessageType = iota
    MsgUpdate
    MsgRead
    MsgWrite
    MsgAck
    MsgNack
    MsgEvict
)

type PeerConnection struct {
    NodeID   string
    Address  string
    Conn     net.Conn
    Encoder  *json.Encoder
    Decoder  *json.Decoder
    LastSeen time.Time
    mu       sync.Mutex
}

type InvalidationEvent struct {
    Key     string
    Version uint64
    Source  string
}

func NewCoherenceManager(cache *FilesystemCache, config *CacheConfig) *CoherenceManager {
    return &CoherenceManager{
        cache:    cache,
        config:   config,
        nodeID:   generateNodeID(),
        peers:    make(map[string]*PeerConnection),
        protocol: ProtocolMESI,
        messages: make(chan CoherenceMessage, 10000),
    }
}

func (cm *CoherenceManager) Run(ctx context.Context) {
    // Start message handler
    go cm.handleMessages(ctx)
    
    // Start peer discovery
    go cm.discoverPeers(ctx)
    
    // Start periodic cleanup
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            cm.cleanupPeers()
        }
    }
}

func (cm *CoherenceManager) OnRead(key string) CoherenceState {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    // Send read request to peers
    msg := CoherenceMessage{
        Type:      MsgRead,
        NodeID:    cm.nodeID,
        Key:       key,
        Timestamp: time.Now(),
    }
    
    cm.broadcastMessage(msg)
    
    // Return current state
    return cm.getKeyState(key)
}

func (cm *CoherenceManager) OnWrite(key string, data []byte) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    // Get exclusive access
    if err := cm.acquireExclusive(key); err != nil {
        return err
    }
    
    // Invalidate copies on other nodes
    msg := CoherenceMessage{
        Type:      MsgInvalidate,
        NodeID:    cm.nodeID,
        Key:       key,
        Timestamp: time.Now(),
    }
    
    cm.broadcastMessage(msg)
    
    // Set local state to modified
    cm.setKeyState(key, StateModified)
    
    return nil
}

func (cm *CoherenceManager) OnEvict(key string) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    // Notify peers of eviction
    msg := CoherenceMessage{
        Type:      MsgEvict,
        NodeID:    cm.nodeID,
        Key:       key,
        Timestamp: time.Now(),
    }
    
    cm.broadcastMessage(msg)
    
    // Remove local state
    cm.setKeyState(key, StateInvalid)
}

func (cm *CoherenceManager) handleMessages(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case msg := <-cm.messages:
            cm.processMessage(msg)
        }
    }
}

func (cm *CoherenceManager) processMessage(msg CoherenceMessage) {
    switch msg.Type {
    case MsgInvalidate:
        cm.handleInvalidate(msg)
    case MsgUpdate:
        cm.handleUpdate(msg)
    case MsgRead:
        cm.handleRead(msg)
    case MsgWrite:
        cm.handleWrite(msg)
    case MsgEvict:
        cm.handleEvict(msg)
    }
}

func (cm *CoherenceManager) handleInvalidate(msg CoherenceMessage) {
    // Invalidate local copy
    cm.cache.InvalidateKey(msg.Key)
    cm.setKeyState(msg.Key, StateInvalid)
    
    atomic.AddUint64(&cm.invalidations, 1)
    
    // Send acknowledgment
    ack := CoherenceMessage{
        Type:      MsgAck,
        NodeID:    cm.nodeID,
        Key:       msg.Key,
        Timestamp: time.Now(),
    }
    
    cm.sendToPeer(msg.NodeID, ack)
}

func (cm *CoherenceManager) handleUpdate(msg CoherenceMessage) {
    // Update local copy with new data
    if len(msg.Data) > 0 {
        cm.cache.Put(msg.Key, msg.Data)
        cm.setKeyState(msg.Key, StateShared)
        
        atomic.AddUint64(&cm.updates, 1)
    }
}

func (cm *CoherenceManager) handleRead(msg CoherenceMessage) {
    // Check if we have the data
    entry, exists := cm.cache.GetEntry(msg.Key)
    if !exists {
        return
    }
    
    state := cm.getKeyState(msg.Key)
    
    switch state {
    case StateModified, StateExclusive:
        // Send data and downgrade to shared
        response := CoherenceMessage{
            Type:      MsgUpdate,
            NodeID:    cm.nodeID,
            Key:       msg.Key,
            Data:      entry.Value,
            Version:   entry.Version,
            State:     StateShared,
            Timestamp: time.Now(),
        }
        
        cm.sendToPeer(msg.NodeID, response)
        cm.setKeyState(msg.Key, StateShared)
        
    case StateShared:
        // Send data, keep shared
        response := CoherenceMessage{
            Type:      MsgUpdate,
            NodeID:    cm.nodeID,
            Key:       msg.Key,
            Data:      entry.Value,
            Version:   entry.Version,
            State:     StateShared,
            Timestamp: time.Now(),
        }
        
        cm.sendToPeer(msg.NodeID, response)
    }
}

func (cm *CoherenceManager) handleWrite(msg CoherenceMessage) {
    // Someone else wants to write - invalidate our copy
    cm.cache.InvalidateKey(msg.Key)
    cm.setKeyState(msg.Key, StateInvalid)
    
    // Send acknowledgment
    ack := CoherenceMessage{
        Type:      MsgAck,
        NodeID:    cm.nodeID,
        Key:       msg.Key,
        Timestamp: time.Now(),
    }
    
    cm.sendToPeer(msg.NodeID, ack)
}

func (cm *CoherenceManager) handleEvict(msg CoherenceMessage) {
    // Peer evicted entry - update our state if needed
    state := cm.getKeyState(msg.Key)
    
    if state == StateShared {
        // Check if we're the only one left with the data
        if cm.countSharedCopies(msg.Key) == 1 {
            cm.setKeyState(msg.Key, StateExclusive)
        }
    }
}

func (cm *CoherenceManager) acquireExclusive(key string) error {
    state := cm.getKeyState(key)
    
    switch state {
    case StateExclusive, StateModified:
        return nil // Already have exclusive access
        
    case StateShared:
        // Send invalidation to all peers
        msg := CoherenceMessage{
            Type:      MsgInvalidate,
            NodeID:    cm.nodeID,
            Key:       key,
            Timestamp: time.Now(),
        }
        
        return cm.waitForAcks(msg)
        
    case StateInvalid:
        // Need to acquire data first
        return cm.acquireData(key)
    }
    
    return nil
}

func (cm *CoherenceManager) waitForAcks(msg CoherenceMessage) error {
    // Broadcast message and wait for acknowledgments
    ackChan := make(chan bool, len(cm.peers))
    timeout := time.After(5 * time.Second)
    
    cm.broadcastMessage(msg)
    
    expectedAcks := len(cm.peers)
    receivedAcks := 0
    
    for receivedAcks < expectedAcks {
        select {
        case <-ackChan:
            receivedAcks++
        case <-timeout:
            return fmt.Errorf("timeout waiting for acknowledgments")
        }
    }
    
    return nil
}

func (cm *CoherenceManager) broadcastMessage(msg CoherenceMessage) {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    for _, peer := range cm.peers {
        go cm.sendToPeer(peer.NodeID, msg)
    }
}

func (cm *CoherenceManager) sendToPeer(peerID string, msg CoherenceMessage) error {
    cm.mu.RLock()
    peer, exists := cm.peers[peerID]
    cm.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("peer %s not found", peerID)
    }
    
    peer.mu.Lock()
    defer peer.mu.Unlock()
    
    return peer.Encoder.Encode(msg)
}

// State management
var keyStates = make(map[string]CoherenceState)
var keyStatesMu sync.RWMutex

func (cm *CoherenceManager) getKeyState(key string) CoherenceState {
    keyStatesMu.RLock()
    defer keyStatesMu.RUnlock()
    
    state, exists := keyStates[key]
    if !exists {
        return StateInvalid
    }
    return state
}

func (cm *CoherenceManager) setKeyState(key string, state CoherenceState) {
    keyStatesMu.Lock()
    defer keyStatesMu.Unlock()
    
    keyStates[key] = state
}

func (cm *CoherenceManager) countSharedCopies(key string) int {
    // This would query peers for their state
    // Simplified implementation
    return 1
}

func (cm *CoherenceManager) acquireData(key string) error {
    // Request data from peers
    msg := CoherenceMessage{
        Type:      MsgRead,
        NodeID:    cm.nodeID,
        Key:       key,
        Timestamp: time.Now(),
    }
    
    cm.broadcastMessage(msg)
    
    // Wait for response
    timeout := time.After(5 * time.Second)
    select {
    case <-timeout:
        return fmt.Errorf("timeout acquiring data for key %s", key)
    default:
        // Data will be received via handleUpdate
        return nil
    }
}

func generateNodeID() string {
    hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
    return hex.EncodeToString(hash[:8])
}

func (cm *CoherenceManager) discoverPeers(ctx context.Context) {
    // Peer discovery implementation
    // This would use mDNS, consul, or other service discovery
}

func (cm *CoherenceManager) cleanupPeers() {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    now := time.Now()
    for id, peer := range cm.peers {
        if now.Sub(peer.LastSeen) > 60*time.Second {
            peer.Conn.Close()
            delete(cm.peers, id)
        }
    }
}
```

### 7. Public Cache Interface

```go
// Main cache interface methods
func (fc *FilesystemCache) Get(key string, offset, length int64) []byte {
    // Try each cache level
    for _, level := range fc.levels {
        if entry, exists := level.Get(key); exists {
            atomic.AddUint64(&fc.stats.Hits, 1)
            
            // Trigger prefetch
            if fc.config.EnablePrefetch {
                fc.prefetcher.OnAccess(key, CacheTypeBlock)
            }
            
            // Extract requested range
            if offset == 0 && length == 0 {
                return entry.Value
            }
            
            if offset >= int64(len(entry.Value)) {
                return nil
            }
            
            end := offset + length
            if end > int64(len(entry.Value)) {
                end = int64(len(entry.Value))
            }
            
            return entry.Value[offset:end]
        }
    }
    
    atomic.AddUint64(&fc.stats.Misses, 1)
    return nil
}

func (fc *FilesystemCache) Put(key string, data []byte) error {
    return fc.PutWithPriority(key, data, CacheTypeBlock, 5)
}

func (fc *FilesystemCache) PutWithPriority(key string, data []byte, cacheType CacheType, priority int) error {
    // Determine which level to use based on data size and priority
    level := fc.selectLevel(len(data), priority)
    
    if err := fc.levels[level].Put(key, data, cacheType); err != nil {
        return err
    }
    
    // Notify coherence manager if enabled
    if fc.config.EnableCoherence {
        fc.coherence.OnWrite(key, data)
    }
    
    return nil
}

func (fc *FilesystemCache) WriteAt(key string, data []byte, offset int64) error {
    if fc.config.EnableCoalescing {
        return fc.coalescer.CoalesceWrite(key, offset, data)
    }
    
    // Direct write
    existing := fc.Get(key, 0, 0)
    
    // Extend if necessary
    needed := offset + int64(len(data))
    if int64(len(existing)) < needed {
        newData := make([]byte, needed)
        if len(existing) > 0 {
            copy(newData, existing)
        }
        existing = newData
    }
    
    // Update data
    copy(existing[offset:], data)
    
    return fc.Put(key, existing)
}

func (fc *FilesystemCache) Delete(key string) error {
    // Remove from all levels
    for _, level := range fc.levels {
        level.Delete(key)
    }
    
    // Notify coherence manager
    if fc.config.EnableCoherence {
        fc.coherence.OnEvict(key)
    }
    
    return nil
}

func (fc *FilesystemCache) Exists(key string) bool {
    for _, level := range fc.levels {
        if _, exists := level.Get(key); exists {
            return true
        }
    }
    return false
}

func (fc *FilesystemCache) InvalidateKey(key string) {
    for _, level := range fc.levels {
        level.Delete(key)
    }
}

func (fc *FilesystemCache) Flush() error {
    if fc.config.EnableCoalescing {
        fc.coalescer.flushAll()
    }
    
    // Sync all persistent levels
    for _, level := range fc.levels {
        if level.storage != nil {
            if err := level.storage.Sync(); err != nil {
                return err
            }
        }
    }
    
    return nil
}

func (fc *FilesystemCache) GetStats() *CacheStats {
    fc.mu.RLock()
    defer fc.mu.RUnlock()
    
    stats := &CacheStats{
        Hits:       atomic.LoadUint64(&fc.stats.Hits),
        Misses:     atomic.LoadUint64(&fc.stats.Misses),
        TotalSize:  fc.getTotalSize(),
        MaxSize:    fc.getMaxSize(),
        EntryCount: fc.getEntryCount(),
    }
    
    if stats.Hits+stats.Misses > 0 {
        stats.HitRatio = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
    }
    
    if fc.prefetcher != nil {
        stats.PrefetchHits = atomic.LoadUint64(&fc.prefetcher.prefetchHits)
    }
    
    if fc.coalescer != nil {
        stats.WriteCoalescing = atomic.LoadUint64(&fc.coalescer.coalesced)
    }
    
    if fc.coherence != nil {
        stats.CoherenceUpdates = atomic.LoadUint64(&fc.coherence.updates)
    }
    
    return stats
}

func (fc *FilesystemCache) selectLevel(dataSize, priority int) int {
    // L1 for small, high-priority data
    if dataSize <= 64*1024 && priority >= 8 {
        return 0
    }
    
    // L2 for medium data
    if dataSize <= 1024*1024 && priority >= 5 {
        if len(fc.levels) > 1 {
            return 1
        }
    }
    
    // L3 for large or low-priority data
    if len(fc.levels) > 2 {
        return 2
    }
    
    // Default to L1
    return 0
}

func (fc *FilesystemCache) getTotalSize() int64 {
    var total int64
    for _, level := range fc.levels {
        total += level.totalSize
    }
    return total
}

func (fc *FilesystemCache) getMaxSize() int64 {
    var total int64
    for _, level := range fc.levels {
        total += level.config.MaxSize
    }
    return total
}

func (fc *FilesystemCache) getEntryCount() int {
    var total int
    for _, level := range fc.levels {
        total += len(level.entries)
    }
    return total
}

func (fc *FilesystemCache) runCleanup() {
    ticker := time.NewTicker(fc.config.CleanupInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-fc.ctx.Done():
            return
        case <-ticker.C:
            fc.performCleanup()
        }
    }
}

func (fc *FilesystemCache) performCleanup() {
    for _, level := range fc.levels {
        level.mu.Lock()
        
        // Remove expired entries
        var expiredKeys []string
        for key, entry := range level.entries {
            if level.config.TTL > 0 && time.Since(entry.Timestamp) > level.config.TTL {
                expiredKeys = append(expiredKeys, key)
            }
        }
        
        for _, key := range expiredKeys {
            level.evictEntry(key)
        }
        
        level.mu.Unlock()
    }
}

func (fc *FilesystemCache) runStatsUpdater() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-fc.ctx.Done():
            return
        case <-ticker.C:
            fc.updateStats()
        }
    }
}

func (fc *FilesystemCache) updateStats() {
    // Update cache statistics
    fc.stats.TotalSize = fc.getTotalSize()
    fc.stats.MaxSize = fc.getMaxSize()
    fc.stats.EntryCount = fc.getEntryCount()
    
    if fc.stats.Hits+fc.stats.Misses > 0 {
        fc.stats.HitRatio = float64(fc.stats.Hits) / float64(fc.stats.Hits+fc.stats.Misses)
    }
}

func (fc *FilesystemCache) Shutdown() error {
    fc.cancel()
    fc.wg.Wait()
    
    // Close all storage backends
    for _, level := range fc.levels {
        if level.storage != nil {
            level.storage.Close()
        }
    }
    
    return nil
}
```

### 8. LFU Heap Implementation

```go
type LFUHeap struct {
    entries []*CacheEntry
    indices map[string]int
    mu      sync.RWMutex
}

func NewLFUHeap() *LFUHeap {
    return &LFUHeap{
        entries: make([]*CacheEntry, 0),
        indices: make(map[string]int),
    }
}

func (h *LFUHeap) Add(entry *CacheEntry) {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    h.entries = append(h.entries, entry)
    h.indices[entry.Key] = len(h.entries) - 1
    h.heapifyUp(len(h.entries) - 1)
}

func (h *LFUHeap) Remove(entry *CacheEntry) {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    idx, exists := h.indices[entry.Key]
    if !exists {
        return
    }
    
    last := len(h.entries) - 1
    if idx != last {
        h.entries[idx] = h.entries[last]
        h.indices[h.entries[idx].Key] = idx
    }
    
    h.entries = h.entries[:last]
    delete(h.indices, entry.Key)
    
    if idx < len(h.entries) {
        h.heapifyDown(idx)
    }
}

func (h *LFUHeap) Update(entry *CacheEntry) {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    idx, exists := h.indices[entry.Key]
    if !exists {
        return
    }
    
    h.heapifyDown(idx)
    h.heapifyUp(idx)
}

func (h *LFUHeap) ExtractMin() *CacheEntry {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    if len(h.entries) == 0 {
        return nil
    }
    
    min := h.entries[0]
    last := len(h.entries) - 1
    
    if last > 0 {
        h.entries[0] = h.entries[last]
        h.indices[h.entries[0].Key] = 0
    }
    
    h.entries = h.entries[:last]
    delete(h.indices, min.Key)
    
    if len(h.entries) > 0 {
        h.heapifyDown(0)
    }
    
    return min
}

func (h *LFUHeap) heapifyUp(idx int) {
    for idx > 0 {
        parent := (idx - 1) / 2
        if h.entries[idx].AccessCount >= h.entries[parent].AccessCount {
            break
        }
        
        h.swap(idx, parent)
        idx = parent
    }
}

func (h *LFUHeap) heapifyDown(idx int) {
    for {
        left := 2*idx + 1
        right := 2*idx + 2
        smallest := idx
        
        if left < len(h.entries) && h.entries[left].AccessCount < h.entries[smallest].AccessCount {
            smallest = left
        }
        
        if right < len(h.entries) && h.entries[right].AccessCount < h.entries[smallest].AccessCount {
            smallest = right
        }
        
        if smallest == idx {
            break
        }
        
        h.swap(idx, smallest)
        idx = smallest
    }
}

func (h *LFUHeap) swap(i, j int) {
    h.entries[i], h.entries[j] = h.entries[j], h.entries[i]
    h.indices[h.entries[i].Key] = i
    h.indices[h.entries[j].Key] = j
}
```

This comprehensive filesystem cache implementation provides multi-level caching with sophisticated prefetching, write coalescing, and cache coherence protocols optimized for distributed filesystem workloads.