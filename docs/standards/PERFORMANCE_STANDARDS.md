# Performance Standards

This document defines performance requirements, optimization techniques, and monitoring standards for the Blackhole Network.

## 1. Performance Requirements

### Response Time SLAs
```go
// API Response Time Targets (p99)
const (
    SLA_SingleResourceRead  = 100 * time.Millisecond  // GET /files/{id}
    SLA_ListResources      = 200 * time.Millisecond  // GET /files
    SLA_ResourceWrite      = 500 * time.Millisecond  // POST/PUT/DELETE
    SLA_SearchOperation    = 1 * time.Second         // Search queries
    SLA_FileUpload1MB      = 2 * time.Second         // Small file upload
    SLA_FileDownload1MB    = 1 * time.Second         // Small file download
)

// Internal Service SLAs
const (
    SLA_StorageRead        = 50 * time.Millisecond
    SLA_StorageWrite       = 100 * time.Millisecond
    SLA_NetworkDiscovery   = 200 * time.Millisecond
    SLA_IndexQuery         = 100 * time.Millisecond
)
```

### Throughput Requirements
```go
// Minimum throughput requirements
type ThroughputRequirements struct {
    // API layer
    APIRequestsPerSecond    int // 1000 RPS per node
    ConcurrentConnections   int // 10,000 concurrent
    
    // Storage layer
    StorageReadMBps         int // 100 MB/s
    StorageWriteMBps        int // 50 MB/s
    ConcurrentFileOps       int // 100 concurrent
    
    // Network layer  
    P2PConnectionsPerNode   int // 50 peers
    NetworkBandwidthMbps    int // 100 Mbps
}
```

### Resource Limits
```go
// Maximum resource usage
type ResourceLimits struct {
    MaxCPUPercent          float64 // 80%
    MaxMemoryGB            int     // 8 GB
    MaxGoroutines          int     // 10,000
    MaxOpenFiles           int     // 5,000
    MaxDiskIOPercent       float64 // 70%
}
```

## 2. Optimization Techniques

### Memory Optimization

#### Object Pooling
```go
// Pool frequently allocated objects
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 4096)
    },
}

func ProcessData(r io.Reader) error {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    
    _, err := r.Read(buf)
    return err
}

// Pool for structured objects
var chunkPool = sync.Pool{
    New: func() interface{} {
        return &Chunk{
            Data: make([]byte, 0, ChunkSize),
        }
    },
}
```

#### Preallocation
```go
// ✅ Preallocate slices when size is known
func ProcessFiles(count int) []Result {
    results := make([]Result, 0, count)
    for i := 0; i < count; i++ {
        results = append(results, processFile(i))
    }
    return results
}

// ✅ Preallocate maps
func IndexFiles(files []File) map[string]File {
    index := make(map[string]File, len(files))
    for _, f := range files {
        index[f.ID] = f
    }
    return index
}
```

#### String Optimization
```go
// Use strings.Builder for concatenation
func BuildPath(parts ...string) string {
    var b strings.Builder
    b.Grow(64) // Preallocate
    
    for i, part := range parts {
        if i > 0 {
            b.WriteByte('/')
        }
        b.WriteString(part)
    }
    return b.String()
}

// Avoid string allocations in hot paths
type FileCache struct {
    mu    sync.RWMutex
    files map[string]*File
    
    // Intern strings to save memory
    paths *StringInterner
}
```

### CPU Optimization

#### Batch Processing
```go
// Process in batches to improve cache locality
const BatchSize = 1000

func ProcessManyItems(items []Item) error {
    for i := 0; i < len(items); i += BatchSize {
        end := i + BatchSize
        if end > len(items) {
            end = len(items)
        }
        
        if err := processBatch(items[i:end]); err != nil {
            return err
        }
    }
    return nil
}
```

#### Parallel Processing
```go
// Use all CPU cores efficiently
func ParallelProcess(items []Item) error {
    numCPU := runtime.NumCPU()
    ch := make(chan Item, numCPU*2)
    errCh := make(chan error, 1)
    
    // Worker pool
    var wg sync.WaitGroup
    for i := 0; i < numCPU; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for item := range ch {
                if err := processItem(item); err != nil {
                    select {
                    case errCh <- err:
                    default:
                    }
                    return
                }
            }
        }()
    }
    
    // Feed work
    for _, item := range items {
        ch <- item
    }
    close(ch)
    
    wg.Wait()
    
    select {
    case err := <-errCh:
        return err
    default:
        return nil
    }
}
```

#### Lock-Free Operations
```go
// Use atomic operations instead of mutexes
type Counter struct {
    value int64
}

func (c *Counter) Inc() int64 {
    return atomic.AddInt64(&c.value, 1)
}

func (c *Counter) Get() int64 {
    return atomic.LoadInt64(&c.value)
}

// Lock-free queue for high throughput
type LockFreeQueue struct {
    head unsafe.Pointer
    tail unsafe.Pointer
}
```

### I/O Optimization

#### Buffered I/O
```go
// Always use buffered I/O for files
func ReadFile(path string) ([]byte, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()
    
    // Use buffered reader
    reader := bufio.NewReaderSize(file, 64*1024) // 64KB buffer
    return io.ReadAll(reader)
}

// Buffered writing
func WriteFile(path string, data []byte) error {
    file, err := os.Create(path)
    if err != nil {
        return err
    }
    defer file.Close()
    
    writer := bufio.NewWriterSize(file, 64*1024)
    defer writer.Flush()
    
    _, err = writer.Write(data)
    return err
}
```

#### Streaming Processing
```go
// Stream large files instead of loading into memory
func ProcessLargeFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    scanner.Buffer(make([]byte, 4096), 1024*1024) // 1MB max line
    
    for scanner.Scan() {
        if err := processLine(scanner.Bytes()); err != nil {
            return err
        }
    }
    
    return scanner.Err()
}
```

### Network Optimization

#### Connection Pooling
```go
// HTTP client with connection pooling
var httpClient = &http.Client{
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        MaxConnsPerHost:     20,
        IdleConnTimeout:     90 * time.Second,
        DisableCompression:  false,
        DisableKeepAlives:   false,
    },
    Timeout: 30 * time.Second,
}

// Database connection pool
type DBPool struct {
    maxConns     int
    maxIdleConns int
    maxLifetime  time.Duration
}
```

#### Batch Network Operations
```go
// Batch multiple operations into single request
type BatchRequest struct {
    Operations []Operation `json:"operations"`
}

func (c *Client) BatchExecute(ops []Operation) ([]Result, error) {
    // Single network round trip
    req := BatchRequest{Operations: ops}
    resp, err := c.post("/batch", req)
    if err != nil {
        return nil, err
    }
    
    return resp.Results, nil
}
```

## 3. Caching Strategy

### Multi-Level Caching
```go
// L1: In-memory cache (hot data)
type L1Cache struct {
    mu    sync.RWMutex
    data  map[string]*CacheEntry
    size  int64
    limit int64 // 100MB
}

// L2: Disk cache (warm data)
type L2Cache struct {
    path     string
    index    map[string]int64 // offset in file
    dataFile *os.File
    limit    int64 // 10GB
}

// Cache hierarchy
type CacheHierarchy struct {
    l1 *L1Cache
    l2 *L2Cache
}

func (c *CacheHierarchy) Get(key string) ([]byte, error) {
    // Try L1 first
    if data, ok := c.l1.Get(key); ok {
        return data, nil
    }
    
    // Try L2
    if data, ok := c.l2.Get(key); ok {
        // Promote to L1
        c.l1.Set(key, data)
        return data, nil
    }
    
    return nil, ErrNotFound
}
```

### Cache Invalidation
```go
// Time-based expiration
type TTLCache struct {
    data map[string]*TTLEntry
    mu   sync.RWMutex
}

type TTLEntry struct {
    Value     interface{}
    ExpiresAt time.Time
}

// Event-based invalidation
type EventCache struct {
    cache    *Cache
    eventBus *EventBus
}

func (e *EventCache) Init() {
    e.eventBus.Subscribe("file.updated", func(event Event) {
        fileID := event.Data.(string)
        e.cache.Delete("file:" + fileID)
    })
}
```

## 4. Database Optimization

### Query Optimization
```go
// Use prepared statements
var stmtCache = map[string]*sql.Stmt{}

func GetPreparedStmt(db *sql.DB, query string) (*sql.Stmt, error) {
    if stmt, ok := stmtCache[query]; ok {
        return stmt, nil
    }
    
    stmt, err := db.Prepare(query)
    if err != nil {
        return nil, err
    }
    
    stmtCache[query] = stmt
    return stmt, nil
}

// Batch inserts
func BulkInsert(db *sql.DB, records []Record) error {
    tx, err := db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    stmt, err := tx.Prepare("INSERT INTO records (id, data) VALUES (?, ?)")
    if err != nil {
        return err
    }
    defer stmt.Close()
    
    for _, record := range records {
        _, err := stmt.Exec(record.ID, record.Data)
        if err != nil {
            return err
        }
    }
    
    return tx.Commit()
}
```

### Index Design
```sql
-- Composite indexes for common queries
CREATE INDEX idx_files_owner_created ON files(owner_id, created_at DESC);
CREATE INDEX idx_files_type_size ON files(file_type, size);

-- Partial indexes for filtered queries
CREATE INDEX idx_active_files ON files(id) WHERE deleted_at IS NULL;

-- Covering indexes to avoid table lookups
CREATE INDEX idx_files_metadata ON files(id, name, size, created_at);
```

## 5. Profiling and Benchmarking

### CPU Profiling
```go
// Enable CPU profiling in production
import _ "net/http/pprof"

func EnableProfiling() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}

// Benchmark critical functions
func BenchmarkChunkProcessing(b *testing.B) {
    data := generateTestData(1 * MB)
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        _ = processChunk(data)
    }
    
    b.SetBytes(int64(len(data)))
}
```

### Memory Profiling
```go
// Track memory allocations
func TrackMemory() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    log.Printf("Alloc = %v MB", m.Alloc / 1024 / 1024)
    log.Printf("TotalAlloc = %v MB", m.TotalAlloc / 1024 / 1024)
    log.Printf("Sys = %v MB", m.Sys / 1024 / 1024)
    log.Printf("NumGC = %v", m.NumGC)
}

// Force garbage collection in tests
func TestMemoryUsage(t *testing.T) {
    runtime.GC()
    var before runtime.MemStats
    runtime.ReadMemStats(&before)
    
    // Run test
    allocateMemory()
    
    runtime.GC()
    var after runtime.MemStats
    runtime.ReadMemStats(&after)
    
    leak := after.Alloc - before.Alloc
    if leak > 1*MB {
        t.Errorf("Memory leak detected: %d bytes", leak)
    }
}
```

## 6. Performance Monitoring

### Metrics Collection
```go
// Define performance metrics
var (
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request latencies",
            Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
        },
        []string{"method", "endpoint", "status"},
    )
    
    activeGoroutines = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "active_goroutines",
            Help: "Number of active goroutines",
        },
    )
    
    memoryUsage = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "memory_usage_bytes",
            Help: "Current memory usage",
        },
    )
)

// Collect metrics
func CollectMetrics() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        activeGoroutines.Set(float64(runtime.NumGoroutine()))
        
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        memoryUsage.Set(float64(m.Alloc))
    }
}
```

### Performance Alerts
```go
// Alert on performance degradation
type PerformanceMonitor struct {
    thresholds map[string]time.Duration
    alerting   AlertManager
}

func (pm *PerformanceMonitor) CheckPerformance(operation string, duration time.Duration) {
    threshold, ok := pm.thresholds[operation]
    if !ok {
        return
    }
    
    if duration > threshold {
        pm.alerting.Send(Alert{
            Severity: "warning",
            Title:    fmt.Sprintf("Performance degradation: %s", operation),
            Message:  fmt.Sprintf("Operation took %v, threshold is %v", duration, threshold),
        })
    }
}
```

## 7. Load Testing

### Load Test Scenarios
```go
// Define load test scenarios
type LoadTestScenario struct {
    Name            string
    Duration        time.Duration
    RampUpTime      time.Duration
    TargetRPS       int
    MaxConcurrency  int
}

var scenarios = []LoadTestScenario{
    {
        Name:           "normal_load",
        Duration:       10 * time.Minute,
        TargetRPS:      100,
        MaxConcurrency: 50,
    },
    {
        Name:           "peak_load",
        Duration:       5 * time.Minute,
        TargetRPS:      1000,
        MaxConcurrency: 200,
    },
    {
        Name:           "stress_test",
        Duration:       30 * time.Minute,
        TargetRPS:      2000,
        MaxConcurrency: 500,
    },
}
```

### Performance Regression Tests
```go
// Ensure performance doesn't degrade
func TestPerformanceRegression(t *testing.T) {
    benchmarks := map[string]time.Duration{
        "FileUpload1MB":   2 * time.Second,
        "FileDownload1MB": 1 * time.Second,
        "SearchQuery":     500 * time.Millisecond,
    }
    
    for name, maxDuration := range benchmarks {
        t.Run(name, func(t *testing.T) {
            start := time.Now()
            
            // Run operation
            err := runOperation(name)
            
            duration := time.Since(start)
            
            if err != nil {
                t.Fatalf("Operation failed: %v", err)
            }
            
            if duration > maxDuration {
                t.Errorf("Performance regression: %s took %v, max is %v",
                    name, duration, maxDuration)
            }
        })
    }
}
```

## 8. Optimization Checklist

Before deploying:
- [ ] CPU profiling shows no obvious bottlenecks
- [ ] Memory profiling shows no leaks
- [ ] All benchmarks meet targets
- [ ] Load tests pass at 2x expected traffic
- [ ] Database queries use indexes
- [ ] Caching strategy implemented
- [ ] Connection pooling configured
- [ ] Batch operations where possible
- [ ] Streaming for large data
- [ ] Monitoring and alerts configured

Remember: Measure first, optimize second. Never optimize without data.