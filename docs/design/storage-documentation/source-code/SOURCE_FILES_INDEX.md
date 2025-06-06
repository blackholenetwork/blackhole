# Storage Source Code Files Index

**Generated:** December 5, 2024
**Source Location:** `pkg/resources/storage/`

## Core Storage Implementation Files

### 1. Main Service Interface and Implementation
- **`service.go`** - Primary storage service interface definitions
- **`cid_enhanced_service.go`** - Main CID-based storage service implementation
- **`cid_enhanced_service_helpers.go`** - Helper methods for CID enhanced service
- **`constructor.go`** - Service constructors and factory methods

### 2. Content-Addressed Storage (CID System)
- **`cid_system.go`** - Core CID generation and management
- **`cid_interface.go`** - CID system interfaces
- **`cid_chunk_store.go`** - Chunk storage implementation

### 3. Erasure Coding and Redundancy
- **`erasure.go`** - Reed-Solomon erasure coding implementation
- **`deterministic.go`** - Deterministic placement algorithms

### 4. Virtual Bucket System
- **`bucket_system_simple.go`** - Virtual bucket system for deterministic placement
- **`node_manager.go`** - Node management and registration
- **`position_health.go`** - Position health monitoring
- **`position_negotiation.go`** - Position negotiation engine
- **`position_strategies.go`** - Position allocation strategies

### 5. Virtual File System (VFS)
- **`vfs.go`** - Public virtual filesystem implementation
- **`vfs_private.go`** - Private VFS with cryptographic namespaces
- **`vfs_helpers.go`** - VFS helper methods and utilities
- **`vfs_permissions.go`** - Permission checking and management
- **`vfs_directory_management.go`** - Directory creation and management
- **`vfs_deletion.go`** - File and directory deletion operations
- **`vfs_compat.go`** - VFS compatibility layer

### 6. Schema and Network Integration
- **`schema_integrated_service.go`** - Schema-aware storage service
- **`network_schema_policy.go`** - Network schema policies
- **`network_schema_service.go`** - Network schema service integration

### 7. Configuration and Setup
- **`config.go`** - Storage configuration structures and defaults

### 8. User-Defined Features
- **`user_defined_use_cases.go`** - User-defined storage use cases

## File Descriptions and Key Functions

### Core Service (`service.go`)
```go
type Service interface {
    core.Service

    // Pure content operations (no metadata required)
    Store(ctx context.Context, reader io.Reader) (ContentCID, error)
    Retrieve(ctx context.Context, cid ContentCID) (io.ReadCloser, error)
    Delete(ctx context.Context, cid ContentCID) error
    HasContent(ctx context.Context, cid ContentCID) bool
    GetContentInfo(ctx context.Context, cid ContentCID) (ContentInfo, error)

    // Chunk operations (content-based)
    StoreChunk(ctx context.Context, chunk *ContentBasedChunk) error
    RetrieveChunk(ctx context.Context, chunkCID ChunkCID) (*ContentBasedChunk, error)

    // Virtual Filesystem operations
    GetVFS() VirtualFilesystemInterface
    GetPrivateVFS() PrivateVFSInterface
}
```

### CID System (`cid_system.go`)
```go
type CIDSystem struct {
    chunkSize int // 256KB
    blockSize int // 10 chunks per block
}

// Core CID generation methods
func (cs *CIDSystem) GenerateFileCID(content []byte) ContentCID
func (cs *CIDSystem) GenerateChunkCID(chunkContent []byte) ChunkCID
func (cs *CIDSystem) CalculateFileProperties(content []byte) FileProperties
```

### Erasure Coding (`erasure.go`)
```go
type AdaptiveErasureCoder struct {
    baseDataShards int
    coders         map[int]*ErasureCoder
}

// Adaptive parity generation
func (aec *AdaptiveErasureCoder) GenerateAdditionalParity(
    dataChunks [][]byte,
    currentParity int,
    targetParity int,
) ([][]byte, error)
```

### Virtual Bucket System (`bucket_system_simple.go`)
```go
type SimpleBucketSystem struct {
    mutex sync.RWMutex
}

// Deterministic placement
func (sbs *SimpleBucketSystem) GetStorageLocations(chunkID ChunkCID) StorageLocation
```

### Virtual File System (`vfs.go`)
```go
type VirtualFilesystem struct {
    mu      sync.RWMutex
    logger  zerolog.Logger
    config  *VFSConfig
    storage Service
    cache   *badger.DB
}

// Core VFS operations
func (vfs *VirtualFilesystem) WriteFile(ctx context.Context, path string, data []byte, metadata map[string]string) error
func (vfs *VirtualFilesystem) ReadFile(ctx context.Context, path string) ([]byte, error)
func (vfs *VirtualFilesystem) ListDir(ctx context.Context, path string) ([]VFSFileInfo, error)
```

### Private VFS (`vfs_private.go`)
```go
type PrivateVFS struct {
    *VirtualFilesystem
    userSecret   string
    userDID      string
    userBase     string
    publicBases  []string
    sharedBases  map[string]string
}

// Privacy-focused operations
func (pvfs *PrivateVFS) WriteFileToNamespace(ctx context.Context, path string, data []byte, metadata map[string]string) error
func (pvfs *PrivateVFS) ReadFileFromNamespace(ctx context.Context, path string) ([]byte, error)
func (pvfs *PrivateVFS) SharePath(ctx context.Context, path string, targetDID string, permission string) error
```

### Configuration (`config.go`)
```go
type Config struct {
    DataDir     string
    MaxCapacity uint64
    ChunkSize   int
    BlockSize   int
    Erasure     ErasureConfig
    Reactive    ReactiveConfig
    VFS         *VFSConfig
    UserDID     string
    UserSecret  string
}

// Default configurations
func DefaultConfig() *Config
func DevelopmentConfig() *Config
```

## Integration Points

### 1. Core System Integration
- **Resource Manager**: Integrates with `pkg/core/resource_manager.go`
- **Metrics**: Uses `pkg/core` metrics collection
- **Logging**: Structured logging with zerolog

### 2. Network Integration
- **P2P**: Integrates with `pkg/infrastructure/network/`
- **Discovery**: Works with `pkg/infrastructure/discovery/`
- **Identity**: Uses `pkg/infrastructure/identity/`

### 3. Service Layer Integration
- **Web Server**: Exposed via `pkg/service/webserver/`
- **API Endpoints**: REST and WebSocket endpoints
- **Real-time**: Integration with real-time services

## Test Files Reference

Located in `tests/integration/storage/`:
- `storage_test.go` - Core storage service tests
- `vfs_test.go` - Virtual filesystem tests
- `private_vfs_test.go` - Private VFS tests
- `erasure_test.go` - Erasure coding tests
- `directory_autocreate_test.go` - Directory auto-creation tests
- `private_namespace_test.go` - Private namespace tests
- `private_path_test.go` - Private path tests
- `recursive_deletion_test.go` - Recursive deletion tests

## Development Guidelines

### 1. Adding New Features
- Follow the interface-driven design patterns
- Add comprehensive tests in `tests/integration/storage/`
- Update configuration in `config.go`
- Document new functionality

### 2. Performance Considerations
- Use sync.Pool for frequently allocated objects
- Implement circuit breakers for external calls
- Profile regularly with pprof
- Consider caching strategies

### 3. Security Guidelines
- Validate all inputs
- Use prepared statements for any SQL
- Implement rate limiting
- Regular security scanning

## Architecture Patterns

### 1. Interface Segregation
- Clear separation between public and private interfaces
- VFS abstracts underlying storage complexity
- Service interfaces hide implementation details

### 2. Dependency Injection
- Services receive dependencies through constructors
- Easy testing and mocking
- Clear dependency graphs

### 3. Immutable Design
- Content-addressed storage ensures immutability
- CIDs provide tamper-evident storage
- Versioning through content changes

This source code represents a production-ready, enterprise-grade storage system with advanced features for privacy, redundancy, and scalability.
