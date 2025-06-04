# Common Patterns Library

Quick reference for solving common problems. Copy, paste, and adapt.

## 1. Retry Operations

```go
// Simple retry with exponential backoff
import "github.com/blackhole/pkg/common/retry"

err := retry.Do(func() error {
    return client.Connect()
}, retry.Attempts(3))
```

## 2. Concurrent Processing

```go
// Process items concurrently with worker pool
import "github.com/blackhole/pkg/common/pool"

pool := pool.NewWorkerPool(runtime.NumCPU())
for _, item := range items {
    item := item // capture
    pool.Submit(func() {
        process(item)
    })
}
pool.Wait()
```

## 3. Caching Results

```go
// Cache expensive operations
import "github.com/blackhole/pkg/common/cache"

var userCache = cache.New[string, *User](
    cache.WithTTL[string, *User](10*time.Minute),
)

func GetUser(id string) (*User, error) {
    // Check cache first
    if user, found := userCache.Get(id); found {
        return user, nil
    }
    
    // Fetch from database
    user, err := db.GetUser(id)
    if err != nil {
        return nil, err
    }
    
    // Cache for next time
    userCache.Set(id, user)
    return user, nil
}
```

## 4. Graceful Shutdown

```go
// Standard graceful shutdown pattern
func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    // Start services
    server := startServer(ctx)
    
    // Wait for interrupt
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    <-sigCh
    
    // Graceful shutdown
    log.Println("Shutting down...")
    shutdownCtx, _ := context.WithTimeout(context.Background(), 30*time.Second)
    server.Shutdown(shutdownCtx)
}
```

## 5. Error Collection

```go
// Collect errors from multiple operations
type errorCollector struct {
    mu     sync.Mutex
    errors []error
}

func (ec *errorCollector) Add(err error) {
    if err != nil {
        ec.mu.Lock()
        ec.errors = append(ec.errors, err)
        ec.mu.Unlock()
    }
}

func (ec *errorCollector) Error() error {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    if len(ec.errors) == 0 {
        return nil
    }
    return fmt.Errorf("multiple errors: %v", ec.errors)
}
```

## 6. Rate Limiting

```go
// Simple rate limiter
type RateLimiter struct {
    rate     int
    interval time.Duration
    ticker   *time.Ticker
    tokens   chan struct{}
}

func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
    rl := &RateLimiter{
        rate:     rate,
        interval: interval,
        tokens:   make(chan struct{}, rate),
    }
    
    // Fill initial tokens
    for i := 0; i < rate; i++ {
        rl.tokens <- struct{}{}
    }
    
    // Refill tokens
    rl.ticker = time.NewTicker(interval / time.Duration(rate))
    go func() {
        for range rl.ticker.C {
            select {
            case rl.tokens <- struct{}{}:
            default:
            }
        }
    }()
    
    return rl
}

func (rl *RateLimiter) Wait() {
    <-rl.tokens
}
```

## 7. Batch Processing

```go
// Process items in batches
func ProcessInBatches[T any](items []T, batchSize int, fn func([]T) error) error {
    for i := 0; i < len(items); i += batchSize {
        end := i + batchSize
        if end > len(items) {
            end = len(items)
        }
        
        batch := items[i:end]
        if err := fn(batch); err != nil {
            return fmt.Errorf("batch %d failed: %w", i/batchSize, err)
        }
    }
    return nil
}
```

## 8. Circuit Breaker

```go
// Simple circuit breaker
type CircuitBreaker struct {
    mu           sync.Mutex
    failures     int
    lastFailTime time.Time
    state        string // "closed", "open", "half-open"
    threshold    int
    timeout      time.Duration
}

func (cb *CircuitBreaker) Call(fn func() error) error {
    cb.mu.Lock()
    
    // Check if circuit should be half-open
    if cb.state == "open" && time.Since(cb.lastFailTime) > cb.timeout {
        cb.state = "half-open"
    }
    
    if cb.state == "open" {
        cb.mu.Unlock()
        return fmt.Errorf("circuit breaker is open")
    }
    
    cb.mu.Unlock()
    
    // Execute function
    err := fn()
    
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    if err != nil {
        cb.failures++
        cb.lastFailTime = time.Now()
        
        if cb.failures >= cb.threshold {
            cb.state = "open"
        }
        return err
    }
    
    // Success - reset
    cb.failures = 0
    cb.state = "closed"
    return nil
}
```

## 9. Leader Election

```go
// Simple leader election using file lock
type LeaderElection struct {
    lockFile string
    file     *os.File
    isLeader bool
}

func (le *LeaderElection) Campaign() error {
    file, err := os.OpenFile(le.lockFile, os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return err
    }
    
    err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
    if err != nil {
        file.Close()
        return fmt.Errorf("not elected as leader")
    }
    
    le.file = file
    le.isLeader = true
    return nil
}
```

## 10. Timeout Wrapper

```go
// Wrap any function with timeout
func WithTimeout[T any](timeout time.Duration, fn func() (T, error)) (T, error) {
    type result struct {
        value T
        err   error
    }
    
    resultCh := make(chan result, 1)
    
    go func() {
        value, err := fn()
        resultCh <- result{value, err}
    }()
    
    select {
    case res := <-resultCh:
        return res.value, res.err
    case <-time.After(timeout):
        var zero T
        return zero, fmt.Errorf("operation timed out after %v", timeout)
    }
}

// Usage
data, err := WithTimeout(5*time.Second, func() ([]byte, error) {
    return fetchDataFromSlowSource()
})
```

## Quick Decision Guide

- **Need to retry?** → Use `retry` package
- **Need concurrency?** → Use `pool` package  
- **Need caching?** → Use `cache` package
- **Need validation?** → Use `validation` package
- **Need custom pattern?** → Check this document first

Remember: Don't reinvent these patterns. Use what's already tested and working.