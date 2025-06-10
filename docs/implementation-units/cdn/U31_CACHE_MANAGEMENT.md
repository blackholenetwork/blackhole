# U31: Cache Management

## Overview
LRU cache implementation with cache invalidation, content preloading, and storage optimization for efficient CDN content management.

## Implementation

```go
package cachemanagement

import (
    "container/list"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sync"
    "sync/atomic"
    "time"
)

// CacheManager manages the CDN cache with LRU eviction
type CacheManager struct {
    config      *CacheConfig
    storage     StorageBackend
    lru         *LRUCache
    invalidator *CacheInvalidator
    preloader   *ContentPreloader
    optimizer   *StorageOptimizer
    metrics     *CacheMetrics
}

// CacheConfig holds cache configuration
type CacheConfig struct {
    MaxSize          int64
    MaxItems         int
    TTL              time.Duration
    EvictionPolicy   string
    StoragePath      string
    PreloadStrategy  string
    CompressionLevel int
}

// LRUCache implements an LRU cache with size constraints
type LRUCache struct {
    capacity   int64
    size       int64
    items      map[string]*list.Element
    evictList  *list.List
    mutex      sync.Mutex
    onEvict    func(key string, value *CacheEntry)
}

// CacheEntry represents a cached item
type CacheEntry struct {
    Key          string
    Value        []byte
    Size         int64
    ContentType  string
    Hash         string
    AccessCount  uint64
    CreatedAt    time.Time
    LastAccessed time.Time
    TTL          time.Duration
    Metadata     map[string]string
}

// StorageBackend defines the storage interface
type StorageBackend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte) error
    Delete(key string) error
    Exists(key string) bool
    Size() int64
}

// NewCacheManager creates a new cache manager
func NewCacheManager(config *CacheConfig) (*CacheManager, error) {
    storage, err := NewFileStorage(config.StoragePath)
    if err != nil {
        return nil, fmt.Errorf("failed to create storage: %w", err)
    }

    lru := NewLRUCache(config.MaxSize, func(key string, value *CacheEntry) {
        storage.Delete(key)
    })

    cm := &CacheManager{
        config:      config,
        storage:     storage,
        lru:         lru,
        invalidator: NewCacheInvalidator(),
        preloader:   NewContentPreloader(config.PreloadStrategy),
        optimizer:   NewStorageOptimizer(config.CompressionLevel),
        metrics:     NewCacheMetrics(),
    }

    return cm, nil
}

// NewLRUCache creates a new LRU cache
func NewLRUCache(capacity int64, onEvict func(string, *CacheEntry)) *LRUCache {
    return &LRUCache{
        capacity:  capacity,
        items:     make(map[string]*list.Element),
        evictList: list.New(),
        onEvict:   onEvict,
    }
}

// Get retrieves an item from the cache
func (c *LRUCache) Get(key string) (*CacheEntry, bool) {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    if elem, exists := c.items[key]; exists {
        c.evictList.MoveToFront(elem)
        entry := elem.Value.(*CacheEntry)
        entry.LastAccessed = time.Now()
        atomic.AddUint64(&entry.AccessCount, 1)
        return entry, true
    }

    return nil, false
}

// Put adds an item to the cache
func (c *LRUCache) Put(key string, entry *CacheEntry) error {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    // Check if key already exists
    if elem, exists := c.items[key]; exists {
        c.evictList.MoveToFront(elem)
        oldEntry := elem.Value.(*CacheEntry)
        c.size -= oldEntry.Size
        elem.Value = entry
        c.size += entry.Size
        return nil
    }

    // Add new item
    elem := c.evictList.PushFront(entry)
    c.items[key] = elem
    c.size += entry.Size

    // Evict items if over capacity
    for c.size > c.capacity && c.evictList.Len() > 0 {
        c.evictOldest()
    }

    return nil
}

// evictOldest removes the least recently used item
func (c *LRUCache) evictOldest() {
    elem := c.evictList.Back()
    if elem != nil {
        c.removeElement(elem)
    }
}

// removeElement removes an element from the cache
func (c *LRUCache) removeElement(elem *list.Element) {
    c.evictList.Remove(elem)
    entry := elem.Value.(*CacheEntry)
    delete(c.items, entry.Key)
    c.size -= entry.Size

    if c.onEvict != nil {
        c.onEvict(entry.Key, entry)
    }
}

// Delete removes an item from the cache
func (c *LRUCache) Delete(key string) bool {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    if elem, exists := c.items[key]; exists {
        c.removeElement(elem)
        return true
    }

    return false
}

// CacheInvalidator handles cache invalidation
type CacheInvalidator struct {
    rules          []InvalidationRule
    subscriptions  map[string][]chan string
    mutex          sync.RWMutex
}

// InvalidationRule defines when to invalidate cache entries
type InvalidationRule struct {
    Pattern     string
    MaxAge      time.Duration
    Dependency  string
    Condition   func(*CacheEntry) bool
}

// NewCacheInvalidator creates a new cache invalidator
func NewCacheInvalidator() *CacheInvalidator {
    return &CacheInvalidator{
        rules:         []InvalidationRule{},
        subscriptions: make(map[string][]chan string),
    }
}

// AddRule adds an invalidation rule
func (ci *CacheInvalidator) AddRule(rule InvalidationRule) {
    ci.mutex.Lock()
    defer ci.mutex.Unlock()
    ci.rules = append(ci.rules, rule)
}

// Invalidate invalidates cache entries matching the pattern
func (ci *CacheInvalidator) Invalidate(pattern string) {
    ci.mutex.RLock()
    channels := ci.subscriptions[pattern]
    ci.mutex.RUnlock()

    for _, ch := range channels {
        select {
        case ch <- pattern:
        default:
        }
    }
}

// Subscribe subscribes to invalidation events
func (ci *CacheInvalidator) Subscribe(pattern string) <-chan string {
    ci.mutex.Lock()
    defer ci.mutex.Unlock()

    ch := make(chan string, 10)
    ci.subscriptions[pattern] = append(ci.subscriptions[pattern], ch)
    return ch
}

// ContentPreloader handles intelligent content preloading
type ContentPreloader struct {
    strategy   string
    predictor  *AccessPredictor
    queue      *PreloadQueue
    workers    int
    maxPreload int64
}

// AccessPredictor predicts future content access
type AccessPredictor struct {
    history    *AccessHistory
    patterns   map[string]*AccessPattern
    mutex      sync.RWMutex
}

// AccessHistory tracks content access history
type AccessHistory struct {
    entries    *list.List
    index      map[string]*list.Element
    maxEntries int
    mutex      sync.Mutex
}

// AccessPattern represents an access pattern
type AccessPattern struct {
    ContentID   string
    Frequency   int
    LastAccess  time.Time
    Predictions []string
}

// PreloadQueue manages the preload queue
type PreloadQueue struct {
    items    []*PreloadItem
    mutex    sync.Mutex
    notEmpty *sync.Cond
}

// PreloadItem represents an item to preload
type PreloadItem struct {
    Key      string
    URL      string
    Priority int
    Size     int64
}

// NewContentPreloader creates a new content preloader
func NewContentPreloader(strategy string) *ContentPreloader {
    queue := &PreloadQueue{
        items: make([]*PreloadItem, 0),
    }
    queue.notEmpty = sync.NewCond(&queue.mutex)

    return &ContentPreloader{
        strategy:   strategy,
        predictor:  NewAccessPredictor(),
        queue:      queue,
        workers:    4,
        maxPreload: 100 * 1024 * 1024, // 100MB
    }
}

// Start starts the preloader workers
func (cp *ContentPreloader) Start(ctx context.Context, cache *CacheManager) {
    for i := 0; i < cp.workers; i++ {
        go cp.worker(ctx, cache)
    }

    // Start prediction engine
    go cp.runPredictionEngine(ctx)
}

// worker processes preload items
func (cp *ContentPreloader) worker(ctx context.Context, cache *CacheManager) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            item := cp.queue.Pop()
            if item != nil {
                cp.preloadContent(cache, item)
            }
        }
    }
}

// preloadContent preloads a content item
func (cp *ContentPreloader) preloadContent(cache *CacheManager, item *PreloadItem) error {
    // Fetch content
    data, err := fetchContent(item.URL)
    if err != nil {
        return fmt.Errorf("failed to fetch content: %w", err)
    }

    // Store in cache
    entry := &CacheEntry{
        Key:         item.Key,
        Value:       data,
        Size:        int64(len(data)),
        CreatedAt:   time.Now(),
        TTL:         cache.config.TTL,
    }

    return cache.Put(item.Key, entry)
}

// StorageOptimizer optimizes cache storage
type StorageOptimizer struct {
    compressionLevel int
    deduplicator     *Deduplicator
    compactor        *Compactor
}

// Deduplicator handles content deduplication
type Deduplicator struct {
    hashes map[string][]string
    mutex  sync.RWMutex
}

// Compactor handles storage compaction
type Compactor struct {
    threshold float64
    running   atomic.Bool
}

// NewStorageOptimizer creates a new storage optimizer
func NewStorageOptimizer(compressionLevel int) *StorageOptimizer {
    return &StorageOptimizer{
        compressionLevel: compressionLevel,
        deduplicator:     NewDeduplicator(),
        compactor:        NewCompactor(0.8), // 80% threshold
    }
}

// Optimize optimizes storage for an entry
func (so *StorageOptimizer) Optimize(entry *CacheEntry) (*CacheEntry, error) {
    // Calculate content hash
    hash := so.calculateHash(entry.Value)
    entry.Hash = hash

    // Check for duplicates
    if existing := so.deduplicator.FindDuplicate(hash); existing != "" {
        // Return reference to existing content
        entry.Value = nil
        entry.Metadata = map[string]string{
            "dedupe_ref": existing,
        }
        return entry, nil
    }

    // Compress content if beneficial
    if so.shouldCompress(entry) {
        compressed, err := so.compress(entry.Value)
        if err == nil && len(compressed) < len(entry.Value) {
            entry.Value = compressed
            entry.Size = int64(len(compressed))
            entry.Metadata = map[string]string{
                "compressed": "true",
                "original_size": fmt.Sprintf("%d", len(entry.Value)),
            }
        }
    }

    // Register with deduplicator
    so.deduplicator.Register(hash, entry.Key)

    return entry, nil
}

// calculateHash calculates content hash
func (so *StorageOptimizer) calculateHash(data []byte) string {
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}

// FileStorage implements file-based storage backend
type FileStorage struct {
    basePath string
    size     atomic.Int64
    mutex    sync.RWMutex
}

// NewFileStorage creates a new file storage backend
func NewFileStorage(basePath string) (*FileStorage, error) {
    if err := os.MkdirAll(basePath, 0755); err != nil {
        return nil, fmt.Errorf("failed to create storage directory: %w", err)
    }

    fs := &FileStorage{
        basePath: basePath,
    }

    // Calculate initial size
    if err := fs.calculateSize(); err != nil {
        return nil, err
    }

    return fs, nil
}

// Get retrieves data from file storage
func (fs *FileStorage) Get(key string) ([]byte, error) {
    fs.mutex.RLock()
    defer fs.mutex.RUnlock()

    path := fs.getPath(key)
    return os.ReadFile(path)
}

// Put stores data in file storage
func (fs *FileStorage) Put(key string, data []byte) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    path := fs.getPath(key)
    dir := filepath.Dir(path)

    if err := os.MkdirAll(dir, 0755); err != nil {
        return err
    }

    if err := os.WriteFile(path, data, 0644); err != nil {
        return err
    }

    fs.size.Add(int64(len(data)))
    return nil
}

// Delete removes data from file storage
func (fs *FileStorage) Delete(key string) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()

    path := fs.getPath(key)
    info, err := os.Stat(path)
    if err != nil {
        return err
    }

    if err := os.Remove(path); err != nil {
        return err
    }

    fs.size.Add(-info.Size())
    return nil
}

// CacheMetrics tracks cache performance metrics
type CacheMetrics struct {
    hits         atomic.Uint64
    misses       atomic.Uint64
    evictions    atomic.Uint64
    bytesServed  atomic.Uint64
    bytesCached  atomic.Uint64
}

// NewCacheMetrics creates new cache metrics
func NewCacheMetrics() *CacheMetrics {
    return &CacheMetrics{}
}

// RecordHit records a cache hit
func (cm *CacheMetrics) RecordHit(size int64) {
    cm.hits.Add(1)
    cm.bytesServed.Add(uint64(size))
}

// RecordMiss records a cache miss
func (cm *CacheMetrics) RecordMiss() {
    cm.misses.Add(1)
}

// GetStats returns cache statistics
func (cm *CacheMetrics) GetStats() map[string]interface{} {
    total := cm.hits.Load() + cm.misses.Load()
    hitRate := float64(0)
    if total > 0 {
        hitRate = float64(cm.hits.Load()) / float64(total)
    }

    return map[string]interface{}{
        "hits":          cm.hits.Load(),
        "misses":        cm.misses.Load(),
        "hit_rate":      hitRate,
        "evictions":     cm.evictions.Load(),
        "bytes_served":  cm.bytesServed.Load(),
        "bytes_cached":  cm.bytesCached.Load(),
    }
}

// CacheManager methods

// Get retrieves content from cache
func (cm *CacheManager) Get(key string) ([]byte, error) {
    // Check LRU cache first
    if entry, exists := cm.lru.Get(key); exists {
        if !cm.isExpired(entry) {
            cm.metrics.RecordHit(entry.Size)
            return entry.Value, nil
        }
        // Remove expired entry
        cm.lru.Delete(key)
    }

    cm.metrics.RecordMiss()
    return nil, fmt.Errorf("cache miss")
}

// Put stores content in cache
func (cm *CacheManager) Put(key string, data []byte) error {
    entry := &CacheEntry{
        Key:       key,
        Value:     data,
        Size:      int64(len(data)),
        CreatedAt: time.Now(),
        TTL:       cm.config.TTL,
    }

    // Optimize storage
    optimized, err := cm.optimizer.Optimize(entry)
    if err != nil {
        return fmt.Errorf("failed to optimize entry: %w", err)
    }

    // Store in LRU cache
    if err := cm.lru.Put(key, optimized); err != nil {
        return err
    }

    // Store in backend
    if err := cm.storage.Put(key, optimized.Value); err != nil {
        cm.lru.Delete(key)
        return err
    }

    cm.metrics.bytesCached.Add(uint64(optimized.Size))
    return nil
}

// isExpired checks if an entry is expired
func (cm *CacheManager) isExpired(entry *CacheEntry) bool {
    if entry.TTL == 0 {
        return false
    }
    return time.Since(entry.CreatedAt) > entry.TTL
}

// Invalidate invalidates cache entries
func (cm *CacheManager) Invalidate(pattern string) {
    cm.invalidator.Invalidate(pattern)
    // TODO: Implement pattern matching and removal
}

// Preload schedules content for preloading
func (cm *CacheManager) Preload(items []*PreloadItem) {
    for _, item := range items {
        cm.preloader.queue.Push(item)
    }
}
```

## Testing

```go
package cachemanagement

import (
    "bytes"
    "testing"
    "time"
)

func TestLRUCache(t *testing.T) {
    cache := NewLRUCache(100, nil)

    // Test basic operations
    entry1 := &CacheEntry{
        Key:   "key1",
        Value: []byte("value1"),
        Size:  6,
    }

    err := cache.Put("key1", entry1)
    if err != nil {
        t.Fatalf("Failed to put entry: %v", err)
    }

    retrieved, exists := cache.Get("key1")
    if !exists {
        t.Fatal("Entry not found")
    }

    if !bytes.Equal(retrieved.Value, entry1.Value) {
        t.Error("Retrieved value doesn't match")
    }

    // Test eviction
    cache = NewLRUCache(10, nil)
    
    for i := 0; i < 5; i++ {
        entry := &CacheEntry{
            Key:   fmt.Sprintf("key%d", i),
            Value: []byte("123"),
            Size:  3,
        }
        cache.Put(entry.Key, entry)
    }

    // This should trigger eviction
    entry := &CacheEntry{
        Key:   "key5",
        Value: []byte("123"),
        Size:  3,
    }
    cache.Put("key5", entry)

    // First entries should be evicted
    _, exists = cache.Get("key0")
    if exists {
        t.Error("Expected key0 to be evicted")
    }
}

func TestCacheInvalidator(t *testing.T) {
    invalidator := NewCacheInvalidator()
    
    // Add rule
    rule := InvalidationRule{
        Pattern: "user:*",
        MaxAge:  time.Hour,
    }
    invalidator.AddRule(rule)

    // Subscribe to invalidations
    ch := invalidator.Subscribe("user:*")
    
    // Trigger invalidation
    go invalidator.Invalidate("user:*")

    select {
    case pattern := <-ch:
        if pattern != "user:*" {
            t.Errorf("Expected pattern 'user:*', got %s", pattern)
        }
    case <-time.After(time.Second):
        t.Error("Timeout waiting for invalidation")
    }
}

func TestStorageOptimizer(t *testing.T) {
    optimizer := NewStorageOptimizer(6)

    entry := &CacheEntry{
        Key:   "test",
        Value: []byte("test content that should be compressed"),
        Size:  38,
    }

    optimized, err := optimizer.Optimize(entry)
    if err != nil {
        t.Fatalf("Failed to optimize: %v", err)
    }

    if optimized.Hash == "" {
        t.Error("Hash not calculated")
    }

    // For small content, compression might not be beneficial
    // Just verify the process completes
}

func TestFileStorage(t *testing.T) {
    storage, err := NewFileStorage("/tmp/cache-test")
    if err != nil {
        t.Fatalf("Failed to create storage: %v", err)
    }

    key := "test-key"
    data := []byte("test data")

    // Test Put
    err = storage.Put(key, data)
    if err != nil {
        t.Fatalf("Failed to put data: %v", err)
    }

    // Test Get
    retrieved, err := storage.Get(key)
    if err != nil {
        t.Fatalf("Failed to get data: %v", err)
    }

    if !bytes.Equal(retrieved, data) {
        t.Error("Retrieved data doesn't match")
    }

    // Test Delete
    err = storage.Delete(key)
    if err != nil {
        t.Fatalf("Failed to delete data: %v", err)
    }

    // Verify deletion
    _, err = storage.Get(key)
    if err == nil {
        t.Error("Expected error after deletion")
    }
}

func TestCacheMetrics(t *testing.T) {
    metrics := NewCacheMetrics()

    metrics.RecordHit(1024)
    metrics.RecordHit(2048)
    metrics.RecordMiss()

    stats := metrics.GetStats()

    if stats["hits"].(uint64) != 2 {
        t.Errorf("Expected 2 hits, got %v", stats["hits"])
    }

    if stats["misses"].(uint64) != 1 {
        t.Errorf("Expected 1 miss, got %v", stats["misses"])
    }

    hitRate := stats["hit_rate"].(float64)
    expectedRate := 2.0 / 3.0
    if hitRate != expectedRate {
        t.Errorf("Expected hit rate %f, got %f", expectedRate, hitRate)
    }
}

func BenchmarkLRUCache(b *testing.B) {
    cache := NewLRUCache(1024*1024, nil) // 1MB cache

    // Prepare entries
    entries := make([]*CacheEntry, 1000)
    for i := 0; i < 1000; i++ {
        entries[i] = &CacheEntry{
            Key:   fmt.Sprintf("key%d", i),
            Value: make([]byte, 1024), // 1KB each
            Size:  1024,
        }
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        entry := entries[i%1000]
        cache.Put(entry.Key, entry)
        cache.Get(entry.Key)
    }
}
```

## Configuration

```yaml
cache_management:
  lru_cache:
    max_size: "10GB"
    max_items: 1000000
    ttl: "24h"
    eviction_policy: "lru"
    
  storage:
    type: "file"
    path: "/var/cache/cdn"
    compression:
      enabled: true
      level: 6
      min_size: 1024
      
  invalidation:
    rules:
      - pattern: "static/*"
        max_age: "7d"
      - pattern: "api/*"
        max_age: "5m"
      - pattern: "user/*"
        dependency: "user-data"
        
  preloading:
    strategy: "predictive"
    workers: 4
    max_preload_size: "100MB"
    algorithms:
      - "access-pattern"
      - "time-based"
      - "popularity"
      
  optimization:
    deduplication: true
    compaction:
      enabled: true
      threshold: 0.8
      schedule: "0 2 * * *"
      
  metrics:
    export_interval: "1m"
    retention: "7d"
```

## Deployment

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: cache-manager
spec:
  serviceName: cache-manager
  replicas: 3
  selector:
    matchLabels:
      app: cache-manager
  template:
    metadata:
      labels:
        app: cache-manager
    spec:
      containers:
      - name: cache
        image: blackhole/cache-manager:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090  # Metrics
        env:
        - name: CACHE_SIZE
          value: "10GB"
        - name: STORAGE_PATH
          value: "/cache"
        volumeMounts:
        - name: cache-storage
          mountPath: /cache
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
  volumeClaimTemplates:
  - metadata:
      name: cache-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
```