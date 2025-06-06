# Error Handling Strategy

This document defines a comprehensive error handling strategy to ensure consistent, debuggable, and user-friendly error management.

## Error Types Hierarchy

```go
// pkg/errors/types.go
package errors

// Base error types
type Category string

const (
    CategoryValidation   Category = "VALIDATION"
    CategoryAuth        Category = "AUTH"
    CategoryNotFound    Category = "NOT_FOUND"
    CategoryConflict    Category = "CONFLICT"
    CategoryRateLimit   Category = "RATE_LIMIT"
    CategoryInternal    Category = "INTERNAL"
    CategoryNetwork     Category = "NETWORK"
    CategoryStorage     Category = "STORAGE"
    CategoryCompute     Category = "COMPUTE"
)

// Structured error
type Error struct {
    Code       string                 // Machine-readable code
    Category   Category               // Error category
    Message    string                 // Human-readable message
    Details    map[string]interface{} // Additional context
    Cause      error                  // Wrapped error
    StackTrace []string               // Stack trace for debugging
    Timestamp  time.Time              // When error occurred
    RequestID  string                 // Trace request
}

// Implement error interface
func (e *Error) Error() string {
    if e.Cause != nil {
        return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
    }
    return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap for errors.Is/As
func (e *Error) Unwrap() error {
    return e.Cause
}
```

## Error Creation Patterns

```go
// pkg/errors/builders.go

// Validation errors
func ValidationError(field, reason string) *Error {
    return &Error{
        Code:     "VALIDATION_FAILED",
        Category: CategoryValidation,
        Message:  fmt.Sprintf("Validation failed for field '%s': %s", field, reason),
        Details: map[string]interface{}{
            "field":  field,
            "reason": reason,
        },
    }
}

// Not found errors
func NotFound(resource, id string) *Error {
    return &Error{
        Code:     "RESOURCE_NOT_FOUND",
        Category: CategoryNotFound,
        Message:  fmt.Sprintf("%s with ID '%s' not found", resource, id),
        Details: map[string]interface{}{
            "resource": resource,
            "id":       id,
        },
    }
}

// Wrap external errors
func Wrap(err error, message string) *Error {
    if err == nil {
        return nil
    }

    // If already our error, add context
    var appErr *Error
    if errors.As(err, &appErr) {
        appErr.Message = fmt.Sprintf("%s: %s", message, appErr.Message)
        return appErr
    }

    // Wrap external error
    return &Error{
        Code:     "INTERNAL_ERROR",
        Category: CategoryInternal,
        Message:  message,
        Cause:    err,
    }
}
```

## Error Handling Patterns

### 1. At Service Boundaries

```go
// Transform internal errors to API errors
func (h *Handler) GetFile(c *fiber.Ctx) error {
    file, err := h.storage.GetFile(c.Context(), fileID)
    if err != nil {
        return h.handleError(c, err)
    }

    return c.JSON(file)
}

func (h *Handler) handleError(c *fiber.Ctx, err error) error {
    var appErr *Error
    if !errors.As(err, &appErr) {
        // Unknown error - don't leak details
        appErr = &Error{
            Code:     "INTERNAL_ERROR",
            Category: CategoryInternal,
            Message:  "An internal error occurred",
        }

        // Log the real error
        log.Error("Unhandled error",
            "error", err,
            "request_id", c.Locals("request_id"),
        )
    }

    // Map to HTTP status
    status := categoryToHTTPStatus(appErr.Category)

    return c.Status(status).JSON(ErrorResponse{
        Error: appErr,
        RequestID: c.Locals("request_id").(string),
    })
}

func categoryToHTTPStatus(cat Category) int {
    switch cat {
    case CategoryValidation:
        return 400
    case CategoryAuth:
        return 401
    case CategoryNotFound:
        return 404
    case CategoryConflict:
        return 409
    case CategoryRateLimit:
        return 429
    default:
        return 500
    }
}
```

### 2. Error Context Propagation

```go
// Add context as you go up the stack
func (s *Storage) StoreFile(ctx context.Context, data []byte) (string, error) {
    // Validate
    if len(data) == 0 {
        return "", ValidationError("data", "cannot be empty")
    }

    // Try to store
    id, err := s.writeToDatabase(ctx, data)
    if err != nil {
        // Add context about what we were doing
        return "", Wrap(err, "failed to write file to database").
            WithDetails(map[string]interface{}{
                "size": len(data),
                "operation": "store_file",
            })
    }

    // Update index
    if err := s.updateIndex(ctx, id); err != nil {
        // Non-critical error - log but don't fail
        log.Warn("Failed to update index",
            "error", err,
            "file_id", id,
        )
    }

    return id, nil
}
```

### 3. Error Recovery Patterns

```go
// Retry with backoff for transient errors
func (c *Client) RequestWithRetry(ctx context.Context, req Request) (Response, error) {
    var lastErr error

    for attempt := 0; attempt < maxRetries; attempt++ {
        resp, err := c.doRequest(ctx, req)
        if err == nil {
            return resp, nil
        }

        // Check if retryable
        var appErr *Error
        if errors.As(err, &appErr) {
            if !isRetryable(appErr.Category) {
                return Response{}, err
            }
        }

        lastErr = err

        // Exponential backoff
        delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second

        select {
        case <-time.After(delay):
            continue
        case <-ctx.Done():
            return Response{}, ctx.Err()
        }
    }

    return Response{}, Wrap(lastErr, "max retries exceeded")
}

func isRetryable(cat Category) bool {
    switch cat {
    case CategoryNetwork, CategoryRateLimit:
        return true
    default:
        return false
    }
}
```

### 4. Panic Recovery

```go
// Recover from panics in goroutines
func SafeGo(fn func()) {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                err := fmt.Errorf("panic recovered: %v", r)
                stack := debug.Stack()

                log.Error("Panic in goroutine",
                    "error", err,
                    "stack", string(stack),
                )

                // Send to monitoring
                metrics.PanicCount.Inc()
                alerts.SendPanic(err, stack)
            }
        }()

        fn()
    }()
}
```

## Error Monitoring

```go
// Track errors by category
var (
    ErrorCount = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "errors_total",
            Help: "Total number of errors",
        },
        []string{"category", "code"},
    )
)

// Middleware to track errors
func ErrorTracking() fiber.Handler {
    return func(c *fiber.Ctx) error {
        err := c.Next()

        if err != nil {
            var appErr *Error
            if errors.As(err, &appErr) {
                ErrorCount.WithLabelValues(
                    string(appErr.Category),
                    appErr.Code,
                ).Inc()
            }
        }

        return err
    }
}
```

## Error Documentation

```go
// Document all error codes
var ErrorCodes = map[string]ErrorDoc{
    "VALIDATION_FAILED": {
        Description: "Input validation failed",
        Category:    CategoryValidation,
        HTTPStatus:  400,
        Example:     `{"code":"VALIDATION_FAILED","message":"Validation failed for field 'name': cannot be empty"}`,
    },
    "RESOURCE_NOT_FOUND": {
        Description: "Requested resource was not found",
        Category:    CategoryNotFound,
        HTTPStatus:  404,
        Example:     `{"code":"RESOURCE_NOT_FOUND","message":"File with ID 'abc123' not found"}`,
    },
    // ... all other codes
}
```

## Testing Error Handling

```go
func TestErrorHandling(t *testing.T) {
    tests := []struct {
        name     string
        err      error
        wantCode string
        wantCat  Category
    }{
        {
            name:     "validation error",
            err:      ValidationError("name", "too long"),
            wantCode: "VALIDATION_FAILED",
            wantCat:  CategoryValidation,
        },
        {
            name:     "wrapped error",
            err:      Wrap(io.EOF, "failed to read"),
            wantCode: "INTERNAL_ERROR",
            wantCat:  CategoryInternal,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            var appErr *Error
            require.ErrorAs(t, tt.err, &appErr)
            assert.Equal(t, tt.wantCode, appErr.Code)
            assert.Equal(t, tt.wantCat, appErr.Category)
        })
    }
}
```

## Best Practices

1. **Always wrap errors with context** as they bubble up
2. **Use structured errors** for machine parsing
3. **Don't leak sensitive information** in error messages
4. **Log full errors internally**, return safe errors to users
5. **Make errors actionable** - what should the user do?
6. **Track error metrics** for monitoring
7. **Document all error codes** in API documentation
8. **Test error paths** as thoroughly as success paths

This strategy ensures consistent, debuggable, and user-friendly error handling throughout the system.
