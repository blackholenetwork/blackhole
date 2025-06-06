# Blackhole Network Storage Architecture Overview

**Generated:** December 5, 2024  
**Based on:** Current implementation analysis and design documents

## Executive Summary

The Blackhole Network storage architecture implements a sophisticated decentralized storage system that combines content-addressed storage, adaptive redundancy, cryptographic privacy, and deterministic placement algorithms. This document provides a comprehensive architectural overview of the storage system.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SERVICE LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  HTTP/WebSocket API  │  Real-time Services  │  Search Integration          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VIRTUAL FILE SYSTEM                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Public VFS          │  Private VFS          │  Permission System           │
│  (/system/, /public/) │ (/private/<hash>/)   │  (DID-based access)         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                     CID ENHANCED STORAGE SERVICE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Content Addressing  │  Erasure Coding      │  Virtual Bucket System       │
│  (IPFS CIDs)        │  (Adaptive 10+3→100) │  (4.29B positions)           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                       INFRASTRUCTURE LAYER                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  P2P Network         │  Node Management     │  Position Negotiation        │
│  (libp2p)           │  (Health Monitoring) │  (Deterministic Placement)   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHYSICAL STORAGE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Local Chunk Store   │  BadgerDB Cache      │  File System                 │
│  (Content-based)     │  (VFS metadata)      │  (Configurable paths)       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components Deep Dive

### 1. Content-Addressed Storage (CAS) Layer

#### CID System Architecture
```
Content Input
     │
     ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   File Content  │───▶│  Chunk (256KB)   │───▶│   Block (10     │
│   (Any Size)    │    │  Generation      │    │   chunks)       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
     │                          │                        │
     ▼                          ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Content CID   │    │    Chunk CID     │    │  Erasure Coded  │
│ (IPFS v1 format)│    │  (SHA-256 hash)  │    │  Parity Chunks  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

#### Key Properties:
- **Immutable**: Content changes result in different CIDs
- **Deduplication**: Identical content shares the same CID
- **Verifiable**: CID cryptographically proves content integrity
- **IPFS Compatible**: Standard v1 CIDs with SHA-256 + Raw codec

### 2. Adaptive Erasure Coding System

#### Redundancy Scaling Architecture
```
Content Demand Assessment
          │
          ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                Demand Thresholds                            │
    │  Low: <10 req/min    Medium: 10-100    High: 100-1000      │
    │  Viral: >1000 req/min                                      │
    └─────────────────────────────────────────────────────────────┘
          │
          ▼
    ┌─────────────────────────────────────────────────────────────┐
    │              Parity Level Selection                         │
    │  Low: 10+3 (30%)     Medium: 10+10 (100%)                 │
    │  High: 10+50 (500%)  Viral: 10+100 (1000%)               │
    └─────────────────────────────────────────────────────────────┘
          │
          ▼
    ┌─────────────────────────────────────────────────────────────┐
    │           Reed-Solomon Encoding                             │
    │  Generate additional parity chunks for popular content     │
    └─────────────────────────────────────────────────────────────┘
```

#### Adaptive Features:
- **Baseline**: 10 data + 3 parity shards (can lose 3 shards)
- **Auto-scaling**: Increases parity based on access patterns
- **Demand-driven**: Popular content gets more redundancy
- **Cost-efficient**: Low-demand content uses minimal redundancy

### 3. Virtual Bucket System

#### Deterministic Placement Architecture
```
ChunkCID Input
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│                SHA-256 Hash Generation                          │
│  Primary: SHA-256(ChunkCID + "primary")                        │
│  Secondary: SHA-256(ChunkCID + "secondary")                    │
│  Tertiary: SHA-256(ChunkCID + "tertiary")                     │
└─────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│               Global Position Calculation                       │
│  Position = hash[0:8] % 4,294,967,296                         │
│  Bucket = Position / 65,536                                   │
│  Local = Position % 65,536                                    │
└─────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Storage Location Result                        │
│  Primary: Bucket 12,345 Position 6,789                        │
│  Secondary: Bucket 54,321 Position 9,876                      │
│  Tertiary: Bucket 98,765 Position 4,321                       │
└─────────────────────────────────────────────────────────────────┘
```

#### Scale and Distribution:
- **Total Positions**: 4,294,967,296 (2^32)
- **Bucket Count**: 65,536 buckets
- **Positions per Bucket**: 65,536 positions
- **Redundancy**: 3 deterministic locations per chunk

### 4. Virtual File System Architecture

#### Dual-Layer VFS Design
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VFS LAYER                                     │
├─────────────────────────────────┬───────────────────────────────────────────┤
│           PUBLIC VFS            │             PRIVATE VFS                   │
├─────────────────────────────────┼───────────────────────────────────────────┤
│  • /system/                     │  • /private/<sha256(DID:secret)>/        │
│  • /schemas/                    │  • Cryptographic namespace isolation     │
│  • /public/                     │  • DID-based permissions                 │
│  • /governance/                 │  • Sharing capabilities                  │
│  • Global path registry         │  • Directory metadata encryption        │
│  • BadgerDB caching            │  • Secret-based access control          │
└─────────────────────────────────┴───────────────────────────────────────────┘
                                    │
                              ┌─────▼─────┐
                              │ Path→CID  │
                              │  Mapping  │
                              └─────┬─────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CONTENT STORAGE LAYER                               │
│  ContentCID → ChunkCIDs → Physical Storage Locations                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Privacy Architecture:
```
User Identity (DID) + Secret
          │
          ▼
    SHA-256(DID + ":" + secret)
          │
          ▼
/private/a1b2c3d4e5f6...789/ (64-char hex)
          │
          ├── personal/
          ├── shared/
          └── schemas/
```

### 5. Node Management and Position Allocation

#### Node Architecture
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            NODE MANAGEMENT                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Node Registration  │  Position Claiming  │  Health Monitoring             │
│  • Unique Node ID   │  • Strategy-based   │  • Availability tracking       │
│  • Capacity info    │  • Load balancing   │  • Performance metrics         │
│  • Address/contact  │  • Geographic dist. │  • Failure detection           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                        POSITION STRATEGIES                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Static Strategy    │  Dynamic Strategy   │  Load-Balanced Strategy        │
│  • Fixed positions  │  • Adaptive         │  • Capacity-aware              │
│  • Predictable      │  • Network-aware    │  • Performance-optimized       │
│  • Simple           │  • Demand-driven    │  • Cost-efficient              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Architecture

### 1. Storage Flow
```
Client Request
     │
     ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   VFS Layer     │    │   CID Service   │    │  Chunk Store    │
│ (Path handling) │───▶│ (Content→CID)   │───▶│ (Physical data) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
     │                          │                        │
     ▼                          ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Path Registry   │    │ Erasure Coding  │    │ Position Claim  │
│ (Path→CID map) │    │ (Parity gen.)   │    │ (Virtual bucket)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 2. Retrieval Flow
```
Client Request (Path or CID)
     │
     ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Path Resolution │    │  CID→Chunks     │    │ Chunk Retrieval │
│ (Path→CID)     │───▶│  Mapping        │───▶│ (Multi-source)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
     │                          │                        │
     ▼                          ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Permission      │    │ Position Lookup │    │ Content Recon.  │
│ Validation      │    │ (Virtual bucket)│    │ (Stream output) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Architecture

### 1. Cryptographic Guarantees
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY LAYERS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Content Integrity  │  Namespace Privacy  │  Access Control                │
│  • SHA-256 CIDs     │  • Secret-based     │  • DID permissions             │
│  • Tamper detection │  • Computational    │  • Path-based rules            │
│  • Cryptographic    │    infeasibility    │  • Sharing workflows           │
│    verification     │  • No enumeration   │  • Expiration support          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Privacy Preservation
```
Public Discovery (Impossible)
     │
     ▼
Private Namespace: /private/<hash>/
     │
     ▼
SHA-256(DID + ":" + secret) = 256-bit space
     │
     ▼
2^256 possible namespaces (computationally infeasible to enumerate)
```

## Performance Characteristics

### 1. Scalability Metrics
- **Address Space**: 2^32 positions (4.29 billion)
- **Concurrent Operations**: Configurable (default: 100)
- **Chunk Size**: 256KB (optimized for network transfer)
- **Block Size**: 2.56MB (10 chunks, optimized for erasure coding)

### 2. Redundancy Efficiency
- **Baseline Overhead**: 30% (10+3 erasure coding)
- **Popular Content**: Up to 1000% (10+100 for viral content)
- **Adaptive Scaling**: Automatic based on demand patterns
- **Geographic Distribution**: Configurable regional weights

### 3. Caching Strategy
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CACHING LAYERS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Application Cache  │  VFS Metadata Cache │  Chunk Content Cache           │
│  • In-memory maps   │  • BadgerDB storage │  • LRU eviction                │
│  • CID→Chunk cache  │  • TTL-based expiry │  • Configurable size           │
│  • Access tracking  │  • Path→CID mapping │  • Compression support         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Configuration Architecture

### 1. Layered Configuration
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CONFIGURATION LAYERS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Default Config     │  Environment Config │  User Config                   │
│  • Baseline values  │  • Runtime overrides│  • Custom settings             │
│  • Development mode │  • Deployment vars  │  • Identity information        │
│  • Production ready │  • Security params  │  • Path preferences            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Key Configuration Areas
- **Storage Paths**: Data directories, cache locations
- **Capacity Limits**: Storage quotas, operation limits
- **Erasure Coding**: Redundancy levels, demand thresholds
- **Network**: P2P settings, concurrent operations
- **Identity**: User DID, secrets, permissions
- **Performance**: Cache sizes, timeouts, compression

## Integration Points

### 1. External System Integration
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL INTEGRATIONS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  P2P Network        │  Economic Layer     │  Service Layer                 │
│  • libp2p protocols │  • Usage tracking   │  • HTTP/WebSocket APIs         │
│  • DHT integration  │  • Billing systems  │  • Real-time services          │
│  • Peer discovery   │  • Market pricing   │  • Search integration          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2. Internal Service Dependencies
- **Core System**: Resource management, lifecycle, metrics
- **Infrastructure**: Identity, authorization, discovery
- **Data Layer**: Schema management, indexing, querying
- **Economic Layer**: Billing, incentives, payments

## Operational Characteristics

### 1. Monitoring and Observability
- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured logging with zerolog
- **Health Checks**: Service health endpoints
- **Performance**: Built-in profiling support

### 2. Deployment and Operations
- **Single Binary**: Monolithic deployment model
- **Configuration**: YAML/Environment variable driven
- **Graceful Shutdown**: Signal handling and cleanup
- **Resource Limits**: Configurable quotas and limits

## Future Architecture Considerations

### 1. Planned Enhancements
- **Cross-region Replication**: Geographic redundancy
- **Smart Contracts**: Blockchain integration for governance
- **AI-driven Optimization**: ML-based placement strategies
- **Advanced Compression**: Content-aware compression

### 2. Scalability Roadmap
- **Sharding**: Horizontal scaling beyond single nodes
- **Federation**: Multi-cluster deployments
- **Edge Computing**: CDN-like distribution
- **Mobile Support**: Lightweight client implementations

This architecture provides a robust, scalable foundation for decentralized storage with enterprise-grade features for privacy, performance, and reliability.