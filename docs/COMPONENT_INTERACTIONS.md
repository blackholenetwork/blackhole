# Blackhole Network - Component Interaction Map

This document maps out the actual communication paths between components based on real user operations.

## Component Communication Matrix

```
From ↓ / To →   API  Storage  Network  Search  Index  Query  Compute  ResMan  Monitor  Security
API              -      ✓        -        ✓      -      ✓       -        ✓        -        ✓
Storage          -      -        ✓        -      ✓      -       -        ✓        ✓        -
Network          -      ✓        -        -      -      -       -        -        ✓        ✓
Search           -      ✓        -        -      ✓      -       -        -        -        -
Indexer          -      ✓        -        -      -      -       -        -        -        -
Query            -      ✓        -        ✓      ✓      -       -        -        -        -
Compute          -      ✓        -        -      -      -       -        ✓        ✓        -
ResourceMgr      -      -        -        -      -      -       ✓        -        ✓        -
Monitoring       -      -        -        -      -      -       -        -        -        -
Security         ✓      -        ✓        -      -      -       -        -        -        -
```

## Real User Operations

### 1. File Upload
```
User uploads file → API
```

**Communication Flow:**
```go
// 1. API validates request with Security
api.security.ValidateToken(token) 
api.security.CheckQuota(userID, fileSize)

// 2. API requests storage allocation from ResourceManager
allocation := api.resourceManager.AllocateStorage(userID, fileSize, tier)

// 3. API stores file in Storage
fileID := api.storage.StoreFile(reader, metadata)

// 4. Storage chunks and stores locally
chunks := storage.chunkFile(reader)
storage.storeChunksLocal(chunks)

// 5. Storage updates Indexer with metadata
storage.indexer.IndexFile(FileMetadata{
    ID: fileID,
    Name: filename,
    Size: fileSize,
    Owner: userID,
    Tags: tags,
})

// 6. Storage announces to Network (DHT)
storage.network.Announce(fileID, chunks)

// 7. Storage reports metrics to Monitoring
storage.monitor.RecordUpload(fileID, fileSize, duration)
```

**Required Interfaces:**
```go
// API needs
type APIStorageInterface interface {
    StoreFile(reader io.Reader, metadata Metadata) (FileID, error)
}

type APIResourceInterface interface {
    AllocateStorage(userID string, size int64, tier Tier) (*Allocation, error)
}

type APISecurityInterface interface {
    ValidateToken(token string) (*Claims, error)
    CheckQuota(userID string, size int64) error
}

// Storage needs
type StorageIndexInterface interface {
    IndexFile(metadata FileMetadata) error
    RemoveIndex(fileID FileID) error
}

type StorageNetworkInterface interface {
    Announce(fileID FileID, chunks []ChunkID) error
    FindProviders(chunkID ChunkID) ([]PeerID, error)
}

type StorageMonitorInterface interface {
    RecordUpload(fileID FileID, size int64, duration time.Duration)
    RecordDownload(fileID FileID, size int64, duration time.Duration)
}
```

### 2. File Search and Download
```
User searches "cooking videos" → API
User downloads result → API
```

**Communication Flow:**
```go
// SEARCH PHASE
// 1. API forwards search to Search service
results := api.search.Search(SearchRequest{
    Query: "cooking videos",
    Filters: filters,
    UserTier: tier,
})

// 2. Search queries Indexer
docs := search.indexer.Query(IndexQuery{
    Text: "cooking videos",
    Type: "video",
})

// 3. Search enriches results with Storage metadata
for _, doc := range docs {
    metadata := search.storage.GetMetadata(doc.FileID)
    results = append(results, enrichedResult(doc, metadata))
}

// DOWNLOAD PHASE
// 4. API requests file from Storage
reader := api.storage.GetFile(fileID)

// 5. Storage checks local chunks
missingChunks := storage.findMissingChunks(fileID)

// 6. Storage asks Network for missing chunks
for _, chunkID := range missingChunks {
    providers := storage.network.FindProviders(chunkID)
    chunk := storage.network.FetchChunk(chunkID, providers[0])
    storage.storeChunkLocal(chunk)
}

// 7. ResourceManager allocates bandwidth
bwAllocation := storage.resourceManager.AllocateBandwidth(userID, tier)

// 8. Storage streams to API with bandwidth limits
limitedReader := storage.createRateLimitedReader(reader, bwAllocation)
return limitedReader
```

**Required Interfaces:**
```go
// API needs
type APISearchInterface interface {
    Search(req SearchRequest) ([]SearchResult, error)
}

// Search needs  
type SearchIndexInterface interface {
    Query(query IndexQuery) ([]Document, error)
}

type SearchStorageInterface interface {
    GetMetadata(fileID FileID) (*FileMetadata, error)
}

// Storage needs
type StorageResourceInterface interface {
    AllocateBandwidth(userID string, tier Tier) (*BWAllocation, error)
    ReleaseAllocation(id AllocationID) error
}
```

### 3. Compute Job (Video Transcoding)
```
User requests video transcoding → API
```

**Communication Flow:**
```go
// 1. API validates and creates job request
job := api.resourceManager.SubmitJob(JobRequest{
    Type: "transcode",
    Input: fileID,
    Output: outputSpec,
    UserID: userID,
    Tier: tier,
})

// 2. ResourceManager schedules job
resourceManager.checkResources(job)
resourceManager.allocateCompute(job)
resourceManager.compute.ExecuteJob(job)

// 3. Compute reads input from Storage
input := compute.storage.GetFile(job.InputID)

// 4. Compute processes (monitoring resources)
compute.monitor.RecordJobStart(job.ID)
output := compute.process(input)
compute.monitor.RecordJobComplete(job.ID)

// 5. Compute stores result
resultID := compute.storage.StoreFile(output, metadata)

// 6. Compute notifies ResourceManager
compute.resourceManager.JobComplete(job.ID, resultID)
```

**Required Interfaces:**
```go
// ResourceManager needs
type ResourceComputeInterface interface {
    ExecuteJob(job Job) error
    CancelJob(jobID JobID) error
    GetJobStatus(jobID JobID) JobStatus
}

// Compute needs
type ComputeStorageInterface interface {
    GetFile(fileID FileID) (io.ReadCloser, error)
    StoreFile(reader io.Reader, metadata Metadata) (FileID, error)
}

type ComputeMonitorInterface interface {
    RecordJobStart(jobID JobID)
    RecordJobComplete(jobID JobID)
    RecordResourceUsage(jobID JobID, usage ResourceUsage)
}

type ComputeResourceInterface interface {
    JobComplete(jobID JobID, resultID FileID) error
    JobFailed(jobID JobID, err error) error
}
```

### 4. Complex Query (SQL-like Analytics)
```
User runs: "SELECT * FROM files WHERE size > 1GB AND type = 'video'"
```

**Communication Flow:**
```go
// 1. API forwards to Query engine
results := api.query.Execute(QueryRequest{
    SQL: "SELECT * FROM files WHERE size > 1GB AND type = 'video'",
    UserID: userID,
})

// 2. Query parses and plans
plan := query.parseSQLToPlan(sql)

// 3. Query uses Search for text conditions
if plan.hasTextSearch() {
    searchResults := query.search.Search(plan.textQuery)
    plan.addFilter(searchResults)
}

// 4. Query uses Indexer for structured conditions  
indexResults := query.indexer.Query(IndexQuery{
    Filters: []Filter{
        {Field: "size", Op: ">", Value: 1*GB},
        {Field: "type", Op: "=", Value: "video"},
    },
})

// 5. Query fetches additional data from Storage
for _, result := range indexResults {
    metadata := query.storage.GetMetadata(result.FileID)
    enrichedResults = append(enrichedResults, metadata)
}
```

**Required Interfaces:**
```go
// Query needs
type QuerySearchInterface interface {
    Search(req SearchRequest) ([]SearchResult, error)
}

type QueryIndexInterface interface {
    Query(query IndexQuery) ([]Document, error)
    GetSchema(collection string) (*Schema, error)
}

type QueryStorageInterface interface {
    GetMetadata(fileID FileID) (*FileMetadata, error)
    ScanMetadata(filter Filter, limit int) ([]*FileMetadata, error)
}
```

## Actual Component Dependencies

Based on real operations, here are the actual dependencies:

### API Layer Dependencies
```go
type API struct {
    storage  StorageInterface  // Store/retrieve files
    search   SearchInterface   // Search functionality
    query    QueryInterface    // SQL queries
    resource ResourceInterface // Job submission
    security SecurityInterface // Auth & validation
}
```

### Storage Layer Dependencies  
```go
type Storage struct {
    network  NetworkInterface  // Find/fetch chunks from peers
    indexer  IndexInterface    // Update search index
    resource ResourceInterface // Bandwidth allocation
    monitor  MonitorInterface  // Metrics
}
```

### Search Layer Dependencies
```go
type Search struct {
    indexer IndexInterface   // Query index
    storage StorageInterface // Get metadata
}
```

### Query Layer Dependencies
```go
type Query struct {
    search  SearchInterface  // Text search
    indexer IndexInterface   // Structured queries
    storage StorageInterface // Metadata access
}
```

### Compute Layer Dependencies
```go
type Compute struct {
    storage  StorageInterface  // Read input, write output
    resource ResourceInterface // Report completion
    monitor  MonitorInterface  // Metrics
}
```

### ResourceManager Dependencies
```go
type ResourceManager struct {
    compute ComputeInterface // Execute jobs
    monitor MonitorInterface // Resource metrics
}
```

### Network Layer Dependencies
```go
type Network struct {
    storage  StorageInterface  // Chunk verification
    security SecurityInterface // Peer authentication
    monitor  MonitorInterface  // Network metrics
}
```

## Design Principles

1. **Minimal Dependencies**: Each component only depends on what it actually needs
2. **Unidirectional Where Possible**: Avoid circular dependencies
3. **Interface Segregation**: Components only see the methods they need
4. **Clear Boundaries**: Storage doesn't know about Search, Search doesn't know about Compute

## What This Means for Implementation

1. **Start with Core Interfaces**: Define the exact methods each component needs from others
2. **Mock Dependencies for Testing**: Each component can be tested in isolation
3. **Clear Initialization Order**: Based on dependency graph
4. **No Surprises**: We know exactly who talks to whom and how