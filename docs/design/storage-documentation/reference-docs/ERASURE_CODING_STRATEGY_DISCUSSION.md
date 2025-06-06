# Erasure Coding Strategy Discussion

## Context: Unique Challenges for Blackhole Network

Before diving into erasure coding parameters, let's consider the unique aspects of our system:

1. **Home User Nodes**: Unreliable availability, varying bandwidth, consumer hardware
2. **Economic Model**: Token payments for storage, need to incentivize participation
3. **Plugin Architecture**: Must work within our IPC message-passing constraints
4. **No Central Authority**: Fully decentralized, no trusted coordinators

## Key Design Questions

### 1. Erasure Coding Parameters

**Option A: Conservative (4+2)**
- 4 data chunks, 2 parity chunks
- 50% storage overhead
- Can lose any 2 chunks
- ✅ Less bandwidth for repair
- ❌ Higher storage cost

**Option B: Balanced (10+4)**
- 10 data chunks, 4 parity chunks  
- 40% storage overhead
- Can lose any 4 chunks
- ✅ Good balance of efficiency and resilience
- ❌ More chunks to track

**Option C: Aggressive (20+4)**
- 20 data chunks, 4 parity chunks
- 20% storage overhead
- Can lose any 4 chunks
- ✅ Very storage efficient
- ❌ High repair bandwidth when node fails

**Considerations for Home Users:**
- Home nodes go offline frequently (sleep, reboot, network issues)
- Need higher redundancy than data center nodes
- Bandwidth is often asymmetric (fast down, slow up)

### 2. Chunk Size Strategy

**Option A: Fixed Size (1MB chunks)**
```
Pros: Simple, predictable
Cons: Inefficient for small files
```

**Option B: Dynamic Sizing**
```
Small files (<10MB): No erasure coding, 3x replication
Medium files (10MB-100MB): 256KB chunks, 6+3 encoding  
Large files (>100MB): 1MB chunks, 10+4 encoding
```

**Option C: Adaptive Based on Network**
```
Monitor network reliability → Adjust redundancy dynamically
High churn period: Use 8+6 encoding
Stable period: Use 12+4 encoding
```

### 3. Chunk Distribution Strategy

**Critical Question: How do we ensure chunks are distributed to maximize availability?**

**Option A: Random Distribution**
- Simple but could cluster on unreliable nodes

**Option B: Reputation-Weighted**
- Prefer nodes with good uptime history
- But new nodes can't build reputation

**Option C: Geographic/Network Diversity**
- Spread chunks across different regions/ISPs
- But requires location awareness

**Option D: Economic Incentive Based**
- Nodes stake tokens to store chunks
- Higher stakes = more chunks
- Slashing for unavailability

### 4. Repair Strategy

**When and how do we repair lost chunks?**

**Lazy Repair**
```
Trigger: When redundancy drops below threshold (e.g., only 11 of 14 chunks remain)
Pro: Saves bandwidth
Con: Risk accumulates
```

**Eager Repair**
```
Trigger: As soon as any chunk is lost
Pro: Maintains full redundancy
Con: High bandwidth usage
```

**Hybrid Approach**
```
Critical threshold (12/14): Repair immediately
Warning threshold (13/14): Repair during low-traffic periods
```

### 5. Economic Considerations

**How do we price storage of parity chunks vs data chunks?**

**Equal Pricing Problem:**
- Parity chunks less likely to be accessed
- Nodes prefer storing popular data chunks
- System becomes vulnerable

**Proposed Solutions:**

1. **Parity Premium**: Pay 1.2x for storing parity chunks

2. **Bundle Requirement**: To store profitable data chunks, must also store parity chunks

3. **Repair Rewards**: Extra payment for providing chunks during repair

4. **Availability Proofs**: Regular challenges, higher rewards for proven availability

### 6. Chunk Location Discovery

**How do we track which nodes have which chunks?**

**Option A: DHT-Based**
```
chunk_id → [node1, node2, node3]
Pro: Fully decentralized
Con: DHT churn with home nodes
```

**Option B: Gossip Protocol**
```
Nodes periodically announce their chunks
Pro: Resilient to churn
Con: Higher overhead
```

**Option C: Hybrid**
```
DHT for lookup + Gossip for updates
Smart caching of frequent lookups
```

### 7. File Size Considerations

**Should we use different strategies for different file sizes?**

```
Tiny (<1MB): 
  - No erasure coding
  - Simple 3x replication
  - Bundled together for efficiency

Small (1-10MB):
  - Light erasure coding (4+2)
  - 512KB chunks

Medium (10-100MB):  
  - Standard erasure coding (8+4)
  - 1MB chunks

Large (100MB-1GB):
  - Efficient erasure coding (14+4)
  - 2MB chunks
  
Huge (>1GB):
  - Streaming erasure coding
  - Process in segments
  - 4MB chunks
```

### 8. Security Considerations

**Chunk Verification**
- Each chunk needs hash verification
- Merkle tree for efficient proofs
- How to prevent chunk substitution attacks?

**Privacy**
- Chunks reveal nothing about content
- But access patterns might
- Consider mixing/padding strategies

### 9. Implementation Priorities

Given our constraints, what order should we implement?

**Phase 1: Simple Redundancy**
- Start with 3x replication
- Get P2P distribution working
- Learn about network dynamics

**Phase 2: Basic Erasure Coding**
- Add erasure coding for large files only
- Fixed parameters (10+4)
- Manual repair

**Phase 3: Adaptive System**
- Dynamic parameters based on file size
- Automatic repair
- Economic incentives

**Phase 4: Advanced Features**
- Geographic distribution
- Predictive pre-repair
- Bandwidth-aware scheduling

## Recommended Initial Strategy

Based on the analysis above, here's my recommendation for initial implementation:

### 1. Start Simple
- Use 8+4 erasure coding (50% overhead, can lose 4 nodes)
- 1MB fixed chunk size
- Only for files >10MB

### 2. Distribution Rules
- No more than 2 chunks on same node
- Prefer nodes that have been online >24 hours
- Simple round-robin among eligible nodes

### 3. Repair Policy  
- Repair when down to 10 chunks (2 losses)
- Repair immediately, don't wait
- Track repair history to identify unreliable nodes

### 4. Economic Model
- Equal pay for all chunks initially
- Track which nodes participate in repairs
- Use this data to design incentives

### 5. Discovery
- Simple DHT with aggressive caching
- Backup: nodes remember recent peers
- Client assists in discovery

## Questions for Discussion

1. **Node Churn**: What's acceptable downtime? Hours? Days?
2. **Bandwidth Limits**: Should we limit repair bandwidth?
3. **Storage Commitment**: Minimum time to store chunks?
4. **File Popularity**: Different strategy for hot vs cold files?
5. **Metadata Storage**: Where do we store file→chunks mapping?

## Next Steps

1. Collect data on node availability patterns
2. Simulate different strategies
3. Start with simple implementation
4. Measure and iterate

The key is to start simple and evolve based on real network behavior rather than over-engineering upfront.