# Blackhole Network - Coding Standards and Patterns

This document defines the coding standards, patterns, and conventions that MUST be followed across the entire codebase. These standards ensure consistency, maintainability, and prevent spaghetti code.

## 1. Method Signature Standards

### Context-First Pattern
```go
// ✅ CORRECT - Context always first
func (s *Storage) GetFile(ctx context.Context, id FileID) (*File, error)
func (s *Storage) StoreFile(ctx context.Context, reader io.Reader, meta Metadata) (FileID, error)

// ❌ WRONG - Missing context or wrong position
func (s *Storage) GetFile(id FileID) (*File, error)
func (s *Storage) GetFile(id FileID, ctx context.Context) (*File, error)
```

### Error-Last Pattern
```go
// ✅ CORRECT - Error always last return value
func DoSomething() (Result, error)
func DoMultiple() (Result1, Result2, error)

// ❌ WRONG - Error not last
func DoSomething() (error, Result)
```

### Options Pattern for Complex Configs
```go
// ✅ CORRECT - Use functional options for optional parameters
type Option func(*Config)

func WithTimeout(d time.Duration) Option {
    return func(c *Config) {
        c.Timeout = d
    }
}

func NewClient(required string, opts ...Option) *Client {
    cfg := defaultConfig()
    for _, opt := range opts {
        opt(cfg)
    }
    return &Client{required: required, config: cfg}
}

// Usage
client := NewClient("required", WithTimeout(30*time.Second), WithRetry(3))
```

## 2. Error Handling Standards

### Error Wrapping
```go
// ✅ CORRECT - Always wrap errors with context
if err != nil {
    return fmt.Errorf("failed to get file %s: %w", id, err)
}

// ❌ WRONG - Lost error context
if err != nil {
    return err
}
```

### Standard Error Types
```go
// Define in pkg/errors/errors.go
var (
    ErrNotFound        = errors.New("not found")
    ErrUnauthorized    = errors.New("unauthorized")  
    ErrQuotaExceeded   = errors.New("quota exceeded")
    ErrInvalidInput    = errors.New("invalid input")
    ErrUnavailable     = errors.New("service unavailable")
    ErrAlreadyExists   = errors.New("already exists")
    ErrTimeout         = errors.New("operation timeout")
    ErrCanceled        = errors.New("operation canceled")
)

// Usage
if !exists {
    return nil, fmt.Errorf("file %s: %w", id, ErrNotFound)
}
```

### Error Checking Pattern
```go
// ✅ CORRECT - Use errors.Is for sentinel errors
if errors.Is(err, ErrNotFound) {
    return respond(404, "Not found")
}

// ✅ CORRECT - Use errors.As for typed errors
var validationErr *ValidationError
if errors.As(err, &validationErr) {
    return respond(400, validationErr.Fields)
}
```

## 3. Resource Management Standards

### Request/Response Pattern
```go
// All requests follow this structure
type XxxRequest struct {
    // Required fields at top
    UserID   UserID   `json:"user_id" validate:"required"`
    Resource Resource `json:"resource" validate:"required"`
    
    // Optional fields below
    Priority Priority     `json:"priority,omitempty"`
    Timeout  time.Duration `json:"timeout,omitempty"`
}

// All responses include standard fields
type XxxResponse struct {
    ID        string         `json:"id"`
    Status    Status         `json:"status"`
    CreatedAt time.Time      `json:"created_at"`
    Metadata  map[string]any `json:"metadata,omitempty"`
}
```

### Resource Cleanup Pattern
```go
// ✅ CORRECT - Always cleanup resources
func ProcessFile(id FileID) error {
    file, err := storage.Open(id)
    if err != nil {
        return err
    }
    defer file.Close() // Always defer cleanup
    
    // Process file
    return nil
}

// ✅ CORRECT - Cleanup with error checking
defer func() {
    if err := file.Close(); err != nil {
        log.Error("failed to close file", "error", err)
    }
}()
```

## 4. Concurrency Standards

### Goroutine Management
```go
// ✅ CORRECT - Always manage goroutine lifecycle
func (s *Service) Start(ctx context.Context) error {
    g, ctx := errgroup.WithContext(ctx)
    
    g.Go(func() error {
        return s.runWorker(ctx)
    })
    
    g.Go(func() error {
        return s.runMonitor(ctx)
    })
    
    return g.Wait()
}

// ❌ WRONG - Unmanaged goroutine
func (s *Service) Start() {
    go s.runWorker() // No way to stop or track
}
```

### Channel Patterns
```go
// ✅ CORRECT - Channel ownership clear
func StreamData(ctx context.Context) (<-chan Data, <-chan error) {
    dataCh := make(chan Data)
    errCh := make(chan error, 1) // Buffered for error
    
    go func() {
        defer close(dataCh) // Producer closes
        defer close(errCh)
        
        for {
            select {
            case <-ctx.Done():
                errCh <- ctx.Err()
                return
            default:
                data, err := getNext()
                if err != nil {
                    errCh <- err
                    return
                }
                
                select {
                case dataCh <- data:
                case <-ctx.Done():
                    errCh <- ctx.Err()
                    return
                }
            }
        }
    }()
    
    return dataCh, errCh
}
```

### Mutex Usage
```go
// ✅ CORRECT - Consistent lock/unlock pattern
type SafeMap struct {
    mu sync.RWMutex
    m  map[string]any
}

func (s *SafeMap) Get(key string) (any, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    val, ok := s.m[key]
    return val, ok
}

func (s *SafeMap) Set(key string, val any) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.m[key] = val
}
```

## 5. Interface Standards

### Interface Segregation
```go
// ✅ CORRECT - Small, focused interfaces
type Reader interface {
    Read(ctx context.Context, id ID) (Data, error)
}

type Writer interface {
    Write(ctx context.Context, data Data) (ID, error)
}

type ReadWriter interface {
    Reader
    Writer
}

// ❌ WRONG - God interface
type Storage interface {
    Read()
    Write()
    Delete()
    List()
    Search()
    Index()
    Backup()
    // ... 20 more methods
}
```

### Interface Naming
```go
// ✅ CORRECT - Interface names describe capability
type Storer interface { }      // -er suffix for single method
type Storage interface { }      // Noun for multiple related methods
type ReadWriter interface { }   // Combination for composed

// ❌ WRONG
type StorageInterface interface { }  // Don't use Interface suffix
type IStorage interface { }          // Don't use I prefix
```

## 6. Testing Standards

### Test Naming
```go
// ✅ CORRECT - Test names describe scenario
func TestStorage_GetFile_WhenFileExists_ReturnsFile(t *testing.T) { }
func TestStorage_GetFile_WhenFileNotExists_ReturnsNotFoundError(t *testing.T) { }

// Table driven tests
func TestStorage_GetFile(t *testing.T) {
    tests := []struct {
        name    string
        fileID  FileID
        want    *File
        wantErr error
    }{
        {
            name:    "existing file",
            fileID:  "file123",
            want:    &File{ID: "file123"},
            wantErr: nil,
        },
        {
            name:    "non-existent file",
            fileID:  "notfound",
            want:    nil,
            wantErr: ErrNotFound,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := storage.GetFile(ctx, tt.fileID)
            assert.Equal(t, tt.want, got)
            assert.Equal(t, tt.wantErr, err)
        })
    }
}
```

### Mock Standards
```go
// ✅ CORRECT - Interface-based mocks
type MockStorage struct {
    GetFileFunc func(ctx context.Context, id FileID) (*File, error)
}

func (m *MockStorage) GetFile(ctx context.Context, id FileID) (*File, error) {
    if m.GetFileFunc != nil {
        return m.GetFileFunc(ctx, id)
    }
    return nil, nil
}

// Usage in tests
mock := &MockStorage{
    GetFileFunc: func(ctx context.Context, id FileID) (*File, error) {
        return nil, ErrNotFound
    },
}
```

## 7. Logging Standards

### Structured Logging
```go
// ✅ CORRECT - Use structured logging with fields
log.Info("file uploaded",
    "file_id", fileID,
    "size", fileSize,
    "duration", duration,
    "user_id", userID,
)

// ❌ WRONG - String concatenation
log.Info("File " + fileID + " uploaded by " + userID)
```

### Log Levels
```go
// DEBUG - Detailed information for debugging
log.Debug("entering function", "func", "GetFile", "id", id)

// INFO - General information
log.Info("server started", "port", 8080)

// WARN - Warning conditions
log.Warn("storage almost full", "used", used, "total", total)

// ERROR - Error conditions
log.Error("failed to store file", "error", err, "id", id)

// FATAL - Fatal errors (program will exit)
log.Fatal("failed to connect to database", "error", err)
```

## 8. Package Organization Standards

### Package Structure
```
pkg/
├── component/              # Each component in its own package
│   ├── component.go       # Main implementation
│   ├── component_test.go  # Tests next to code
│   ├── types.go          # Types specific to this package
│   ├── errors.go         # Package-specific errors
│   └── doc.go            # Package documentation
├── common/               # Shared utilities
│   ├── errors/          # Common error types
│   ├── types/           # Common types
│   └── utils/           # Common utilities
```

### Import Ordering
```go
import (
    // Standard library
    "context"
    "fmt"
    "time"
    
    // External packages
    "github.com/gofiber/fiber/v2"
    "github.com/stretchr/testify/assert"
    
    // Internal packages
    "github.com/blackhole/pkg/common/errors"
    "github.com/blackhole/pkg/storage"
)
```

## 9. Documentation Standards

### Package Documentation
```go
// Package storage provides distributed storage functionality for the Blackhole Network.
// It handles file chunking, erasure coding, and distribution across nodes.
//
// Basic usage:
//
//	store := storage.New(config)
//	id, err := store.StoreFile(ctx, reader, metadata)
//	if err != nil {
//	    return err
//	}
package storage
```

### Function Documentation
```go
// GetFile retrieves a file by its ID from the distributed storage.
// It returns ErrNotFound if the file doesn't exist.
// The caller is responsible for closing the returned reader.
//
// Example:
//
//	reader, err := storage.GetFile(ctx, fileID)
//	if err != nil {
//	    return err
//	}
//	defer reader.Close()
func (s *Storage) GetFile(ctx context.Context, id FileID) (io.ReadCloser, error) {
```

### Type Documentation
```go
// FileMetadata contains metadata about a stored file.
// All fields are immutable after creation except Tags.
type FileMetadata struct {
    // ID is the unique identifier for the file
    ID FileID `json:"id"`
    
    // Name is the original filename
    Name string `json:"name"`
    
    // Size in bytes
    Size int64 `json:"size"`
    
    // Tags can be updated after creation
    Tags []string `json:"tags,omitempty"`
}
```

## 10. Performance Standards

### Preallocation
```go
// ✅ CORRECT - Preallocate slices when size is known
results := make([]Result, 0, len(items))
for _, item := range items {
    results = append(results, process(item))
}

// ❌ WRONG - Growing slice
var results []Result
for _, item := range items {
    results = append(results, process(item))
}
```

### String Building
```go
// ✅ CORRECT - Use strings.Builder for concatenation
var b strings.Builder
b.WriteString("Hello")
b.WriteString(" ")
b.WriteString("World")
result := b.String()

// ❌ WRONG - String concatenation in loop
result := ""
for _, s := range strings {
    result += s // Creates new string each time
}
```

### Resource Pooling
```go
// ✅ CORRECT - Use sync.Pool for frequently allocated objects
var bufferPool = sync.Pool{
    New: func() any {
        return make([]byte, 4096)
    },
}

func Process() {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    // Use buffer
}
```

## 11. Security Standards

### Input Validation
```go
// ✅ CORRECT - Always validate inputs
func (s *Storage) StoreFile(ctx context.Context, name string, size int64) error {
    // Validate filename
    if err := validateFilename(name); err != nil {
        return fmt.Errorf("invalid filename: %w", err)
    }
    
    // Validate size
    if size <= 0 || size > MaxFileSize {
        return fmt.Errorf("invalid file size %d: %w", size, ErrInvalidInput)
    }
    
    // Proceed with storage
}
```

### Sensitive Data
```go
// ✅ CORRECT - Never log sensitive data
log.Info("user authenticated", "user_id", userID) // OK
log.Info("auth failed", "user_id", userID, "reason", "invalid password") // OK

// ❌ WRONG
log.Info("auth attempt", "password", password) // NEVER log passwords
log.Info("api key generated", "key", apiKey)   // NEVER log secrets
```

## 12. Configuration Standards

### Configuration Structure
```go
// ✅ CORRECT - Hierarchical configuration
type Config struct {
    // Required fields with no defaults
    NodeID string `env:"NODE_ID" validate:"required"`
    
    // Optional with defaults
    Port int `env:"PORT" default:"8080"`
    
    // Nested configs
    Storage StorageConfig
    Network NetworkConfig
}

type StorageConfig struct {
    Path     string `env:"STORAGE_PATH" default:"~/.blackhole/storage"`
    MaxSize  int64  `env:"STORAGE_MAX_SIZE" default:"536870912000"` // 500GB
}
```

### Environment Variables
```go
// ✅ CORRECT - Consistent naming
BLACKHOLE_NODE_ID=abc123
BLACKHOLE_STORAGE_PATH=/data
BLACKHOLE_STORAGE_MAX_SIZE=1099511627776

// ❌ WRONG - Inconsistent
NodeId=abc123
storage_path=/data
MAX-SIZE=1099511627776
```

## Enforcement

1. **Linter Configuration**: All these standards are enforced via `.golangci.yml`
2. **Pre-commit Hooks**: Automatically check before commit
3. **CI/CD**: PR checks enforce all standards
4. **Code Reviews**: Reviewers verify standard compliance

These standards are not suggestions - they are requirements for maintaining a clean, scalable codebase.