package common_test

import (
    "fmt"
    "log"
    "time"
    
    "github.com/blackhole/pkg/common/cache"
    "github.com/blackhole/pkg/common/pool"
    "github.com/blackhole/pkg/common/retry"
    "github.com/blackhole/pkg/common/validation"
)

// Example_retry shows how to use the retry package
func Example_retry() {
    // Simple retry
    err := retry.Do(func() error {
        return doSomethingFlaky()
    })
    
    // Retry with options
    err = retry.Do(
        func() error {
            return doSomethingFlaky()
        },
        retry.Attempts(5),
        retry.Delay(2*time.Second),
        retry.OnRetry(func(n int, err error) {
            log.Printf("Retry #%d: %v", n, err)
        }),
    )
    
    fmt.Println("Error:", err)
}

// Example_workerPool shows how to use worker pools
func Example_workerPool() {
    // Create a pool with 10 workers
    pool := pool.NewWorkerPool(10)
    
    // Submit tasks
    for i := 0; i < 100; i++ {
        taskID := i
        pool.Submit(func() {
            processTask(taskID)
        })
    }
    
    // Wait for all tasks to complete
    pool.Wait()
}

// Example_cache shows how to use the generic cache
func Example_cache() {
    // Create a cache with 5 minute TTL
    c := cache.New[string, *User](
        cache.WithTTL[string, *User](5*time.Minute),
        cache.WithMaxSize[string, *User](1000),
    )
    defer c.Close()
    
    // Store user
    c.Set("user:123", &User{ID: "123", Name: "Alice"})
    
    // Retrieve user
    if user, found := c.Get("user:123"); found {
        fmt.Printf("Found user: %s\n", user.Name)
    }
}

// Example_validation shows common validations
func Example_validation() {
    // Validate email
    if err := validation.ValidateEmail("user@example.com"); err != nil {
        log.Printf("Invalid email: %v", err)
    }
    
    // Validate UUID
    if err := validation.ValidateUUID("550e8400-e29b-41d4-a716-446655440000"); err != nil {
        log.Printf("Invalid UUID: %v", err)
    }
    
    // Validate password
    if err := validation.ValidatePassword("SecurePass123!"); err != nil {
        log.Printf("Weak password: %v", err)
    }
    
    // Validate enum
    status := "active"
    if err := validation.ValidateEnum(status, []string{"active", "inactive", "pending"}); err != nil {
        log.Printf("Invalid status: %v", err)
    }
}

// Helper types for examples
type User struct {
    ID   string
    Name string
}

func doSomethingFlaky() error {
    // Simulated flaky operation
    return nil
}

func processTask(id int) {
    // Simulated task processing
}