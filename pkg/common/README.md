# Common Reusable Components

This package contains shared utilities used across all layers. If you find yourself writing the same code twice, it probably belongs here.

## Quick Reference - What Goes Where

### 🔧 `/pkg/common/` - Shared Utilities

```
common/
├── retry/          # Retry logic with backoff
├── pool/           # Object pools (buffer, worker)
├── cache/          # Generic caching
├── validation/     # Input validators
├── converter/      # Type conversions
├── hasher/         # Hashing utilities
├── logger/         # Structured logging
└── errors/         # Common error types
```

### ✅ When to Add to Common

1. **Used by 2+ components** - If multiple packages need it
2. **No business logic** - Pure utilities only
3. **Well-tested** - 100% test coverage
4. **Single responsibility** - Does one thing well

### ❌ What NOT to Put in Common

- Business logic
- Component-specific code
- External service clients
- Configuration

## Most Used Utilities

### 1. Retry with Backoff
```go
// Instead of writing retry logic everywhere
result, err := retry.Do(func() error {
    return someFlakeyOperation()
}, retry.Attempts(3), retry.Delay(time.Second))
```

### 2. Worker Pool
```go
// Reuse worker pool pattern
pool := pool.NewWorkerPool(10)
for _, item := range items {
    pool.Submit(func() {
        processItem(item)
    })
}
pool.Wait()
```

### 3. Generic Cache
```go
// Don't implement caching multiple times
cache := cache.New[string, *File](cache.WithTTL(5 * time.Minute))
cache.Set("key", file)
file, found := cache.Get("key")
```

### 4. Validation
```go
// Reusable validators
if err := validation.ValidateEmail(email); err != nil {
    return err
}
if err := validation.ValidateUUID(id); err != nil {
    return err
}
```

## Quick Start

Just import what you need:

```go
import (
    "github.com/blackhole/pkg/common/retry"
    "github.com/blackhole/pkg/common/pool"
    "github.com/blackhole/pkg/common/cache"
)
```

No need to reinvent the wheel!
