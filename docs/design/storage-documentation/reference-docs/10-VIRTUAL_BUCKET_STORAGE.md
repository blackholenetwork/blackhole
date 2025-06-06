# Virtual Bucket Storage Architecture

## Overview

The Virtual Bucket System is the cornerstone of Blackhole Network's distributed storage, providing deterministic chunk placement without metadata explosion. This architecture scales from 10 to 100,000+ nodes while maintaining efficient chunk discovery and load distribution.

## Core Concepts

### Virtual Buckets

- **Fixed Count**: 65,536 (2^16) buckets, established at network genesis
- **Never Changes**: This number remains constant forever, providing stable addressing
- **Purpose**: Intermediate mapping layer between chunks and nodes

### Two-Level Deterministic Mapping

```
Level 1: Chunk → Bucket (permanent)
         chunk_id → hash(chunk_id) % 65536 → bucket_id

Level 2: Bucket → Node(s) (dynamic)
         bucket_id → consistent_hash_ring → node_id(s)
```

## Architecture Components

### 1. Chunk to Bucket Mapping

```python
TOTAL_VIRTUAL_BUCKETS = 65536  # Fixed forever

def get_bucket_for_chunk(chunk_id):
    """Deterministic mapping that never changes"""
    return hash(chunk_id) % TOTAL_VIRTUAL_BUCKETS
```

**Properties**:
- Deterministic: Same chunk always maps to same bucket
- Permanent: Mapping never changes as network grows
- Uniform: Even distribution across all buckets

### 2. Bucket Ownership

Each bucket can be served by:
- **Early Network**: Single node per bucket
- **Growing Network**: Multiple nodes share a bucket
- **Mature Network**: 20-30 nodes for popular buckets

```python
class BucketOwnership:
    def __init__(self, bucket_id):
        self.bucket_id = bucket_id
        self.nodes = {}  # node_id -> hash_ranges
        self.ring = ConsistentHashRing()

    def add_node(self, node_id, capacity):
        # Node joins bucket based on capacity
        virtual_nodes = capacity // STANDARD_NODE_SIZE
        for i in range(virtual_nodes):
            position = hash(f"{node_id}:{i}")
            self.ring.add_node(position, node_id)
```

### 3. Consistent Hashing Within Buckets

Each bucket operates as a mini-network with consistent hashing:

```python
class BucketRing:
    def get_responsible_node(self, chunk_id):
        # Hash chunk to position on ring
        position = hash(chunk_id) % RING_SIZE

        # Find successor node
        return self.ring.find_successor(position)

    def rebalance_on_join(self, new_node):
        # New node takes over hash ranges
        ranges = self.calculate_takeover_ranges(new_node)
        self.transfer_chunks(ranges, new_node)
```

## Reed-Solomon Integration

### Chunk Naming Convention

```
file_id:rs_chunk:0    # Data chunk 0
file_id:rs_chunk:1    # Data chunk 1
...
file_id:rs_chunk:9    # Data chunk 9
file_id:rs_chunk:10   # Parity chunk 0
file_id:rs_chunk:11   # Parity chunk 1
...
file_id:rs_chunk:29   # Parity chunk 19 (for 10+20 encoding)
```

### Deterministic Placement

Each RS chunk is placed deterministically:

```python
def store_rs_chunk(file_id, chunk_index, chunk_data):
    # Generate chunk ID
    chunk_id = f"{file_id}:rs_chunk:{chunk_index}"

    # Find bucket (Level 1)
    bucket_id = hash(chunk_id) % 65536

    # Find node within bucket (Level 2)
    bucket_ring = get_bucket_ring(bucket_id)
    target_node = bucket_ring.get_responsible_node(chunk_id)

    # Store chunk
    target_node.store_chunk(chunk_id, chunk_data)
```

## Dynamic Parity Management

### Parity Expansion Flow

```python
def expand_parity_for_viral_content(file_id, current_parity, target_parity):
    """Coordinator expands parity for viral content"""

    # Generate new parity chunks deterministically
    for parity_index in range(current_parity, target_parity):
        chunk_index = 10 + parity_index

        # RS encoding is deterministic
        parity_data = generate_parity_chunk(file_id, parity_index)

        # Place in deterministic location
        chunk_id = f"{file_id}:rs_chunk:{chunk_index}"
        bucket_id = hash(chunk_id) % 65536

        # Store in appropriate bucket
        store_chunk_in_bucket(bucket_id, chunk_id, parity_data)
```

### Permanent Coordinator System

```python
class PermanentCoordinator:
    def get_coordinator(self, file_id):
        """First parity owner is permanent coordinator"""

        # Deterministic: whoever owns parity chunk 10
        chunk_id = f"{file_id}:rs_chunk:10"
        bucket_id = hash(chunk_id) % 65536

        # This node coordinates for file's lifetime
        return get_chunk_owner(bucket_id, chunk_id)

    def handle_coordinator_failure(self, file_id):
        """Deterministic succession if coordinator leaves"""

        # Try parity owners in order: 10, 11, 12...
        for i in range(current_parity_count):
            chunk_id = f"{file_id}:rs_chunk:{10+i}"
            owner = try_get_chunk_owner(chunk_id)
            if owner and owner.is_alive():
                return owner
```

### Why Permanent Coordinators

1. **Minimal CPU Overhead**: <0.01% CPU for thousands of files
2. **Rich History**: Builds complete understanding of file access patterns
3. **No Handover Complexity**: Eliminates rotation overhead
4. **"One Person, One Job"**: Prevents duplicate work and wasted resources

```python
class CoordinatorResponsibilities:
    def __init__(self, file_id):
        self.file_id = file_id
        self.history = FileHistory()  # Accumulates over lifetime

    def monitor_demand(self):
        """Track access patterns - negligible CPU"""
        self.history.record_access(timestamp, region, size)

    def decide_parity_changes(self):
        """Make informed decisions based on history"""
        if self.history.indicates_viral_growth():
            self.expand_parity()
        elif self.history.shows_declining_interest():
            self.contract_parity()
```

## Retrieval Strategy

### Simple BitTorrent-Style Retrieval

```python
def retrieve_file(file_id, metadata):
    """Simple, efficient retrieval for 256KB chunks"""

    chunks_needed = 10  # k chunks
    chunks_to_try = 20  # Request 2x what we need

    # Start parallel requests
    futures = []
    for i in range(min(chunks_to_try, metadata.total_chunks)):
        chunk_id = f"{file_id}:rs_chunk:{i}"
        bucket_id = hash(chunk_id) % 65536

        # Find and request from node
        node = get_bucket_node(bucket_id, chunk_id)
        future = request_chunk_async(node, chunk_id)
        futures.append((i, future))

    # Use first k chunks that complete
    chunks_received = []
    for chunk_index, future in as_completed(futures):
        if chunk := future.result():
            chunks_received.append((chunk_index, chunk))
            if len(chunks_received) >= chunks_needed:
                break

    # Decode file
    return reed_solomon_decode(chunks_received)
```

## Scaling Examples

### Network Growth Timeline

```
10 Nodes (10TB total):
- Each node handles ~6,553 buckets
- Bucket contains ~156MB average
- Single node per bucket

1,000 Nodes (1PB total):
- Each node handles ~65 buckets
- Bucket contains ~15.6GB average
- 1-3 nodes per bucket

100,000 Nodes (100PB total):
- Each node handles 0-2 buckets
- Bucket contains ~1.5TB average
- 20-30 nodes per popular bucket
```

### Bucket Load Distribution

```python
def calculate_bucket_load(network_size, total_storage):
    buckets = 65536

    avg_storage_per_bucket = total_storage / buckets
    avg_nodes_per_bucket = network_size / buckets

    if avg_nodes_per_bucket < 1:
        # Early network: nodes handle multiple buckets
        buckets_per_node = buckets / network_size
    else:
        # Mature network: multiple nodes per bucket
        nodes_per_bucket = network_size / buckets
```

## Benefits

### 1. No Metadata Explosion
- Only track 65,536 bucket→nodes mappings
- Not millions of chunk→node mappings

### 2. Deterministic Discovery
- Calculate bucket from chunk ID
- Query DHT for bucket's current nodes
- Two hops to find any chunk

### 3. Natural Load Balancing
- New nodes join loaded buckets
- Automatic rebalancing within buckets
- No central coordination needed

### 4. Network Growth
- Buckets remain stable
- Only node assignments change
- Existing chunks don't move unnecessarily

## Implementation Considerations

### Node Selection Strategy

```python
def select_buckets_to_join(node_capacity):
    """Node autonomously selects buckets"""

    # Find underserved buckets
    bucket_loads = query_all_bucket_loads()

    # Calculate how many buckets to join
    network_avg_load = get_network_average_load()
    my_fair_share = node_capacity / network_avg_load

    # Join most needed buckets first
    buckets_to_join = select_highest_priority_buckets(
        bucket_loads,
        count=my_fair_share
    )

    return buckets_to_join
```

### Chunk Uniqueness Enforcement

```python
def ensure_unique_chunks(bucket_id, chunk_id, node_id):
    """Prevent duplicate RS chunks"""

    # Check if chunk already exists in bucket
    existing_owner = get_chunk_owner(bucket_id, chunk_id)

    if existing_owner and existing_owner != node_id:
        # Reject duplicate storage
        return Error("Chunk already exists in bucket")

    # Proceed with storage
    return store_chunk(chunk_id, node_id)
```

### Handover Protocol

```python
def graceful_handover(leaving_node, bucket_id):
    """Transfer chunks when node leaves"""

    # Get node's hash ranges in bucket
    my_ranges = get_node_ranges(leaving_node, bucket_id)

    # Find successor for each range
    for range_start, range_end in my_ranges:
        successor = find_range_successor(bucket_id, range_end)

        # Transfer chunks in range
        chunks = list_chunks_in_range(range_start, range_end)
        transfer_chunks_to_node(chunks, successor)

    # Remove from bucket ring
    remove_node_from_bucket(leaving_node, bucket_id)
```

## Future Optimizations

### Geographic Awareness
- Buckets can track node locations
- Prefer geographically diverse storage
- Optimize retrieval for locality

### Bucket Specialization
- Hot buckets for popular content
- Cold buckets for archival storage
- Different replication strategies per bucket

### Economic Incentives
- Higher rewards for underserved buckets
- Dynamic pricing based on bucket load
- Market-driven bucket selection

## Conclusion

The Virtual Bucket System with permanent coordinators provides a scalable, deterministic foundation for distributed storage that:
- Scales from tiny to massive networks (10 to 1M+ nodes)
- Maintains efficient chunk discovery through two-level mapping
- Automatically balances load through economic incentives
- Uses permanent coordinators for minimal overhead and rich history
- Integrates seamlessly with Reed-Solomon erasure coding
- Spreads viral content load across the entire network
- Prevents duplicate work through clear role separation

This architecture ensures that Blackhole Network can grow organically while maintaining performance, reliability, and simplicity. The design philosophy of "deterministic placement, permanent coordination, simple retrieval" creates a system that is both theoretically elegant and practically efficient.
