# Storage Replication Architecture

## Overview

The Blackhole Network storage system supports both erasure coding and P2P replication to provide redundancy and availability. These two mechanisms work together to create an efficient, resilient distributed storage system.

## Erasure Coding vs P2P Replication

### Erasure Coding (Local Operation)
- **What**: Mathematical redundancy technique that splits files into chunks
- **Where**: Happens locally on the storage node before distribution
- **Why**: Reduces storage overhead while maintaining reliability
- **Example**: Reed-Solomon (10,4) encoding
  - Original file: 1MB
  - Output: 14 chunks of ~100KB each (10 data + 4 parity)
  - Storage overhead: 40% (vs 200% for 3x replication)
  - Can recover from any 10 of the 14 chunks

### P2P Replication (Network Operation)
- **What**: Distributes chunks to other nodes in the network
- **Where**: Uses network plugin's libp2p connections
- **Why**: Ensures data availability across the network
- **Example**: Each chunk replicated to 3 different nodes
  - Total network storage: 14 chunks × 3 replicas = 42 chunks
  - But each node only stores a few chunks

## Architecture Design

```
┌─────────────────────────────────────────────────────────┐
│                   Storage Plugin                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. File Upload                                         │
│     ↓                                                   │
│  2. Erasure Encoding (Reed-Solomon)                    │
│     ├── Split into k data chunks                       │
│     └── Generate m parity chunks                       │
│     ↓                                                   │
│  3. Chunk Storage                                       │
│     ├── Store locally (some chunks)                    │
│     └── Queue for replication                          │
│     ↓                                                   │
│  4. Replication Request → Network Plugin               │
│                                                         │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                   Network Plugin                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  5. Peer Discovery                                      │
│     ├── Find nodes with available storage              │
│     └── Check node reputation/reliability              │
│     ↓                                                   │
│  6. Chunk Distribution                                  │
│     ├── Establish libp2p streams                       │
│     ├── Transfer chunks to selected peers              │
│     └── Verify successful storage                      │
│     ↓                                                   │
│  7. Metadata Update                                     │
│     ├── Update DHT with chunk locations                │
│     └── Notify storage plugin of completion            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Implementation Approach

### Phase 1: Erasure Coding (Storage Plugin Only)
1. Implement Reed-Solomon encoding/decoding
2. Add chunk management system
3. Store chunk metadata in local database
4. Test with local storage only

### Phase 2: Basic Replication (Network Integration)
1. Add inter-plugin messaging for replication requests
2. Implement chunk transfer protocol
3. Add peer selection logic
4. Store chunk location metadata

### Phase 3: Advanced Features
1. Dynamic replication based on demand
2. Repair mechanisms for lost chunks
3. Bandwidth-aware chunk distribution
4. Economic incentives for storage

## Data Structures

### File Metadata
```go
type FileMetadata struct {
    Hash         string              // SHA256 of original file
    Size         int64               // Original file size
    Encoding     EncodingParams      // Erasure coding parameters
    Chunks       []ChunkInfo         // Information about each chunk
    Replicas     map[string][]string // ChunkID -> [NodeIDs]
    CreatedAt    time.Time
    LastAccessed time.Time
}

type EncodingParams struct {
    Type         string // "reed-solomon"
    DataChunks   int    // k value (e.g., 10)
    ParityChunks int    // m value (e.g., 4)
    ChunkSize    int    // Size of each chunk
}

type ChunkInfo struct {
    ID       string // Unique chunk identifier
    Index    int    // Position in sequence (0 to k+m-1)
    Hash     string // SHA256 of chunk
    Size     int    // Actual chunk size
    IsParit  bool   // True if parity chunk
}
```

### Replication Messages

```go
// Storage → Network: Request to replicate chunks
type ReplicateRequest struct {
    FileHash      string
    Chunks        []ChunkData
    TargetReplicas int
    Priority      int
}

type ChunkData struct {
    ChunkID  string
    Data     []byte
    Metadata ChunkInfo
}

// Network → Storage: Replication status
type ReplicationStatus struct {
    FileHash   string
    ChunkID    string
    NodeID     string
    Success    bool
    Error      string
    Timestamp  time.Time
}
```

## File Operations

### Upload Flow
1. Client uploads file via streaming API
2. Storage plugin encodes file using erasure coding
3. Storage plugin stores some chunks locally
4. Storage plugin sends ReplicateRequest to network plugin
5. Network plugin distributes chunks to peers
6. Network plugin reports back with chunk locations
7. Storage plugin updates metadata with replica information

### Download Flow
1. Client requests file by hash
2. Storage plugin checks local chunks
3. If insufficient chunks locally:
   - Query network plugin for chunk locations
   - Retrieve missing chunks from peers
4. Decode file using erasure coding
5. Stream file back to client

### Repair Flow
1. Periodic health check identifies missing chunks
2. If replicas < threshold:
   - Retrieve chunk from another replica
   - Find new nodes for replication
   - Distribute chunk to maintain redundancy

## Benefits of Combined Approach

1. **Storage Efficiency**: Erasure coding reduces storage overhead from 300% (3x replication) to 140% (10+4 encoding)
2. **Network Efficiency**: Only transfer chunks, not entire files
3. **Fault Tolerance**: Can survive multiple node failures
4. **Scalability**: Nodes only store small portions of each file
5. **Performance**: Parallel chunk retrieval improves download speeds

## Configuration Options

```yaml
storage:
  erasure_coding:
    enabled: true
    type: "reed-solomon"
    data_chunks: 10
    parity_chunks: 4
    chunk_size: 1048576  # 1MB chunks
  
  replication:
    enabled: true
    target_replicas: 3
    min_replicas: 2
    repair_threshold: 2
    peer_selection:
      strategy: "weighted"  # random, weighted, geographic
      factors:
        - reputation: 0.4
        - bandwidth: 0.3
        - storage_available: 0.3
```

## Next Steps

1. Implement erasure coding library integration
2. Design chunk storage format
3. Create replication protocol specification
4. Build peer selection algorithm
5. Implement repair mechanisms