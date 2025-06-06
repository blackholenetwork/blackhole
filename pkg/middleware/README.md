# Middleware Library

Reusable middleware components that can be composed to handle cross-cutting concerns.

## HTTP Middleware

```go
// Standard middleware signature
type Middleware func(http.Handler) http.Handler

// Compose multiple middleware
handler := Chain(
    WithRequestID(),
    WithLogging(),
    WithAuth(),
    WithRateLimit(100),
    WithTimeout(30*time.Second),
)(yourHandler)
```

## Available Middleware

### 1. Request Context
- `WithRequestID()` - Adds unique request ID
- `WithTracing()` - Adds distributed tracing
- `WithTimeout()` - Adds request timeout
- `WithContext()` - Enriches context

### 2. Security
- `WithAuth()` - JWT authentication
- `WithAPIKey()` - API key validation
- `WithCORS()` - CORS handling
- `WithCSRF()` - CSRF protection

### 3. Rate Limiting & Protection
- `WithRateLimit()` - Per-user rate limiting
- `WithThrottle()` - Global throttling
- `WithCircuitBreaker()` - Circuit breaker pattern
- `WithBulkhead()` - Bulkhead isolation

### 4. Observability
- `WithLogging()` - Structured request logging
- `WithMetrics()` - Prometheus metrics
- `WithTracing()` - OpenTelemetry tracing
- `WithProfiling()` - Performance profiling

### 5. Data Processing
- `WithCompression()` - Gzip compression
- `WithCache()` - Response caching
- `WithValidation()` - Request validation
- `WithSanitization()` - Input sanitization

## Usage Example

```go
// In your API setup
func SetupAPI() *fiber.App {
    app := fiber.New()

    // Global middleware
    app.Use(middleware.WithRequestID())
    app.Use(middleware.WithLogging())
    app.Use(middleware.WithMetrics())

    // Public routes
    public := app.Group("/api/v1")
    public.Use(middleware.WithRateLimit(100))

    // Protected routes
    protected := app.Group("/api/v1")
    protected.Use(middleware.WithAuth())
    protected.Use(middleware.WithRateLimit(1000))

    return app
}
```
