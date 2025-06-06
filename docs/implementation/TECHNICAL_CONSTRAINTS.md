# Technical Constraints and Non-Negotiables

## Architectural Constraints

### 1. Single Binary Distribution
**Constraint**: Everything must compile into one executable

**Requirements**:
- Pure Go implementation (no CGO)
- Embed all assets (web UI, configs)
- Static linking for all dependencies
- No external runtime requirements

**Implications**:
```go
// Acceptable
//go:embed web/dist/*
var webAssets embed.FS

// NOT Acceptable
exec.Command("node", "server.js")
```

**Size Limits**:
- Binary size: <50MB uncompressed
- Memory footprint: <500MB running
- Startup time: <2 seconds

---

### 2. Zero External Dependencies
**Constraint**: Node must run without any external services

**Requirements**:
- No database server (use embedded)
- No Redis/Memcached (local cache)
- No message queue (in-process)
- No external authentication

**Implementation**:
```go
// Use embedded databases
badgerDB    // For metadata
boltDB      // For configuration
bleve       // For search index

// NOT allowed
postgresql  // External database
mongodb     // External database
rabbitmq    // External queue
```

---

### 3. Cross-Platform Compatibility
**Constraint**: Must run identically on Linux, macOS, Windows

**Requirements**:
- No platform-specific system calls
- Handle path separators correctly
- Respect platform conventions
- Test on all platforms

**Code Standards**:
```go
// Correct
filepath.Join(home, "blackhole", "data")

// Incorrect
home + "/blackhole/data"

// Use build tags for platform code
// +build windows
```

---

## Performance Constraints

### 1. Resource Limits
**Constraint**: Must run on modest hardware

**Minimum Requirements**:
- CPU: 2 cores
- RAM: 2GB
- Disk: 10GB free
- Network: 10 Mbps

**Resource Caps**:
```yaml
limits:
  cpu_percent: 50      # Max 50% CPU
  memory_mb: 1024      # Max 1GB RAM
  disk_io_mbps: 50     # Max 50MB/s disk
  network_mbps: 100    # Max 100Mbps
  connections: 100     # Max 100 peers
```

---

### 2. Latency Requirements
**Constraint**: Responsive user experience

**Targets**:
- API response: <100ms (p95)
- File chunk lookup: <500ms
- DHT query: <2 seconds
- Storage operation: <5 seconds

**Implementation**:
```go
// All operations must have timeouts
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

// Background work in goroutines
go func() {
    processInBackground()
}()
```

---

### 3. Scalability Limits (MVP)
**Constraint**: Design for modest scale initially

**Limits**:
- Network size: 1,000 nodes
- Files per node: 10,000
- Total storage: 100TB network-wide
- Concurrent operations: 1,000

**Data Structures**:
```go
// Efficient for MVP scale
map[string]*File      // 10K entries OK
[]peer.ID             // 1K entries OK

// Avoid for MVP
*btree.BTree          // Over-engineered
*skiplist.SkipList    // Unnecessary
```

---

## Security Constraints

### 1. Cryptographic Standards
**Constraint**: Use only proven, standard algorithms

**Required Algorithms**:
- Identity: Ed25519 keys
- Transport: TLS 1.3
- Storage: AES-256-GCM
- Hashing: SHA-256
- Key Derivation: Argon2id

**Forbidden**:
- Custom crypto algorithms
- Deprecated algorithms (MD5, SHA1)
- Experimental features
- Weak key sizes

---

### 2. Trust Model
**Constraint**: Zero-trust architecture

**Principles**:
- Don't trust any single node
- Verify everything cryptographically
- Assume network is hostile
- Encrypt all communications

**Implementation**:
```go
// Always verify
if !VerifySignature(data, signature, peerKey) {
    return ErrInvalidSignature
}

// Never trust
// DON'T: if peer.IsTrusted() { skip verification }
```

---

### 3. Privacy Requirements
**Constraint**: Metadata privacy by default

**Requirements**:
- No tracking of user behavior
- No correlation of transactions
- Optional anonymous mode
- No telemetry without consent

**Data Collection**:
```go
// Allowed
logrus.Info("File stored", "size", fileSize)

// NOT Allowed
analytics.Track("FileUploaded", userID, fileName)
```

---

## Protocol Constraints

### 1. Standards Compliance
**Constraint**: Use existing standards where possible

**Required Standards**:
- Networking: libp2p protocols
- API: REST with JSON
- Addressing: IPFS CIDs
- Encoding: Protocol Buffers

**Extensions Allowed**:
- Custom protocols on top of libp2p
- Additional API endpoints
- Extended metadata formats

---

### 2. Backwards Compatibility
**Constraint**: Never break existing clients

**Rules**:
- Versioned APIs (/api/v1/)
- Optional new fields only
- Graceful degradation
- Clear upgrade paths

**API Evolution**:
```go
// Adding fields - OK
type FileInfo struct {
    CID      string    `json:"cid"`
    Size     int64     `json:"size"`
    Created  time.Time `json:"created"`
    MimeType string    `json:"mime_type,omitempty"` // New field
}

// Changing fields - NOT OK
// DON'T: Rename 'cid' to 'content_id'
```

---

### 3. Network Behavior
**Constraint**: Be a good network citizen

**Requirements**:
- Respect rate limits
- Implement backoff strategies
- Don't flood the network
- Clean up resources

**Patterns**:
```go
// Exponential backoff
backoff := 100 * time.Millisecond
for retries := 0; retries < 5; retries++ {
    if err := attempt(); err == nil {
        break
    }
    time.Sleep(backoff)
    backoff *= 2
}
```

---

## Development Constraints

### 1. Code Simplicity
**Constraint**: Optimize for readability

**Principles**:
- Obvious over clever
- Explicit over implicit
- Simple over sophisticated
- Tested over assumed

**Examples**:
```go
// Preferred
if err != nil {
    return fmt.Errorf("failed to store file: %w", err)
}

// Avoid
if err := store(); err != nil {
    return errors.Wrap(errors.WithStack(err), "storage failed")
}
```

---

### 2. Testing Requirements
**Constraint**: Comprehensive test coverage

**Requirements**:
- Unit tests: >80% coverage
- Integration tests: All APIs
- Stress tests: Load scenarios
- Chaos tests: Failure modes

**Test Patterns**:
```go
// Table-driven tests
func TestStorage(t *testing.T) {
    tests := []struct{
        name string
        file File
        want error
    }{
        {"empty file", File{}, ErrEmptyFile},
        {"large file", largeFile, nil},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := Store(tt.file)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

---

### 3. Operational Constraints
**Constraint**: Easy to operate and debug

**Requirements**:
- Structured logging
- Prometheus metrics
- Health endpoints
- Graceful shutdown
- Config hot-reload

**Observability**:
```go
// Structured logs
log.WithFields(log.Fields{
    "node_id": nodeID,
    "peer_count": len(peers),
    "operation": "store_file",
    "duration_ms": duration.Milliseconds(),
}).Info("File stored successfully")

// Metrics
filesStored.Inc()
storageLatency.Observe(duration.Seconds())
```

---

## Non-Negotiable Decisions

### Things We Will NOT Do

1. **No Blockchain**
   - No proof-of-work
   - No mining
   - No consensus algorithms
   - No smart contracts

2. **No External Services**
   - No cloud APIs
   - No third-party authentication
   - No external databases
   - No SaaS dependencies

3. **No Complex Features (MVP)**
   - No machine learning
   - No advanced analytics
   - No complex queries
   - No real-time streaming

4. **No Premature Optimization**
   - No micro-optimizations
   - No assembly code
   - No custom memory allocators
   - No exotic data structures

### Things We MUST Do

1. **User Privacy**
   - Encrypt user data
   - No tracking
   - No data sales
   - Anonymous option

2. **Network Health**
   - Graceful degradation
   - Self-healing
   - Automatic recovery
   - No single points of failure

3. **Developer Experience**
   - Clear documentation
   - Simple APIs
   - Good error messages
   - Example code

4. **Sustainable Economics**
   - Fair pricing
   - No speculation
   - Transparent costs
   - Predictable earnings
