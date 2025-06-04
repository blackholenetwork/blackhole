# API Standards

This document defines standards for all APIs in the Blackhole Network, including REST, WebSocket, and internal APIs.

## 1. REST API Standards

### URL Structure
```
# Resource naming - always plural nouns
GET    /api/v1/files              # List files
POST   /api/v1/files              # Create file
GET    /api/v1/files/{id}         # Get specific file
PUT    /api/v1/files/{id}         # Update file
DELETE /api/v1/files/{id}         # Delete file

# Nested resources
GET    /api/v1/files/{id}/chunks  # Get file's chunks
POST   /api/v1/nodes/{id}/jobs    # Submit job to node

# Actions that don't fit REST
POST   /api/v1/files/{id}/transcode    # Action as sub-resource
POST   /api/v1/search                  # Search across resources
```

### HTTP Methods
```
GET     # Read-only, safe, idempotent
POST    # Create new resource or non-idempotent action
PUT     # Update entire resource (idempotent)
PATCH   # Partial update (idempotent)
DELETE  # Remove resource (idempotent)
```

### Status Codes
```go
// Success
200 OK                  # Successful GET, PUT, PATCH
201 Created            # Successful POST creating resource
204 No Content         # Successful DELETE
206 Partial Content    # Range request

// Client Errors  
400 Bad Request        # Invalid request format
401 Unauthorized       # Missing/invalid authentication
403 Forbidden          # Authenticated but not authorized
404 Not Found          # Resource doesn't exist
409 Conflict           # Conflict with current state
413 Payload Too Large  # Request body too large
429 Too Many Requests  # Rate limit exceeded

// Server Errors
500 Internal Server Error  # Unexpected error
502 Bad Gateway           # Upstream service error
503 Service Unavailable   # Temporary unavailability
504 Gateway Timeout       # Upstream timeout
```

### Request/Response Format

#### Request Headers
```http
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
X-Request-ID: <uuid>
X-User-ID: <user-id>
```

#### Standard Response Envelope
```json
{
  "data": {...},           // Actual response data
  "metadata": {
    "request_id": "uuid",
    "timestamp": "2025-06-04T10:00:00Z",
    "version": "1.0.0"
  },
  "pagination": {          // Only for list endpoints
    "page": 1,
    "per_page": 20,
    "total": 100,
    "total_pages": 5
  }
}
```

#### Error Response Format
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "File not found",
    "details": {
      "file_id": "abc123",
      "searched_locations": ["node1", "node2"]
    },
    "request_id": "uuid",
    "timestamp": "2025-06-04T10:00:00Z"
  }
}
```

### Pagination
```
# Request
GET /api/v1/files?page=2&per_page=20&sort=created_at:desc

# Response headers
X-Total-Count: 100
X-Page: 2
X-Per-Page: 20
Link: <...?page=1>; rel="first",
      <...?page=5>; rel="last",
      <...?page=3>; rel="next",
      <...?page=1>; rel="prev"
```

### Filtering and Sorting
```
# Filtering
GET /api/v1/files?type=video&size_gt=1000000&owner=user123

# Sorting  
GET /api/v1/files?sort=created_at:desc,size:asc

# Field selection
GET /api/v1/files?fields=id,name,size
```

### Versioning
```go
// URL versioning for major versions
/api/v1/files
/api/v2/files

// Header versioning for minor versions
Accept: application/vnd.blackhole.v1.2+json
```

## 2. WebSocket API Standards

### Connection Lifecycle
```javascript
// Client connects
ws://localhost:8080/ws?token=<auth-token>

// Server sends welcome
{
  "type": "welcome",
  "data": {
    "connection_id": "conn_123",
    "server_time": "2025-06-04T10:00:00Z",
    "version": "1.0.0"
  }
}

// Client subscribes
{
  "type": "subscribe",
  "channel": "files.updates",
  "params": {
    "user_id": "user123"
  }
}

// Server confirms
{
  "type": "subscribed",
  "channel": "files.updates",
  "subscription_id": "sub_456"
}
```

### Message Format
```typescript
interface WebSocketMessage {
  id: string;           // Unique message ID
  type: MessageType;    // Message type
  channel?: string;     // Channel for pub/sub
  data: any;           // Message payload
  timestamp: string;    // ISO 8601 timestamp
  correlation_id?: string; // For request/response
}

enum MessageType {
  // Connection
  WELCOME = "welcome",
  PING = "ping",
  PONG = "pong",
  
  // Subscription
  SUBSCRIBE = "subscribe",
  UNSUBSCRIBE = "unsubscribe",
  SUBSCRIBED = "subscribed",
  UNSUBSCRIBED = "unsubscribed",
  
  // Data
  MESSAGE = "message",
  REQUEST = "request",
  RESPONSE = "response",
  
  // Errors
  ERROR = "error"
}
```

### Error Handling
```json
{
  "type": "error",
  "data": {
    "code": "SUBSCRIPTION_FAILED",
    "message": "Cannot subscribe to private channel",
    "channel": "private.updates",
    "details": {
      "reason": "insufficient_permissions"
    }
  },
  "correlation_id": "req_123"
}
```

### Heartbeat
```go
// Client sends every 30s
{"type": "ping", "timestamp": "2025-06-04T10:00:00Z"}

// Server responds
{"type": "pong", "timestamp": "2025-06-04T10:00:00Z"}

// If no ping in 60s, server closes connection
```

## 3. Internal API Standards

### Service-to-Service Communication
```go
// Always use interfaces
type StorageClient interface {
    GetFile(ctx context.Context, id FileID) (*File, error)
    StoreFile(ctx context.Context, data io.Reader) (FileID, error)
}

// Standard client configuration
type ClientConfig struct {
    BaseURL     string
    Timeout     time.Duration
    MaxRetries  int
    APIKey      string
}

// Standard client implementation
type storageClient struct {
    config     ClientConfig
    httpClient *http.Client
    limiter    *rate.Limiter
}
```

### Circuit Breaker Pattern
```go
// All internal clients must implement circuit breaker
client := NewStorageClient(config,
    WithCircuitBreaker(
        Threshold(5),      // 5 failures to open
        Timeout(30*time.Second), // Try again after 30s
        OnOpen(logCircuitOpen),
    ),
)
```

### Request Context
```go
// Propagate context through all calls
type RequestContext struct {
    RequestID   string
    UserID      string
    TraceID     string
    SpanID      string
}

// Add to context
ctx = context.WithValue(ctx, RequestContextKey, reqCtx)

// Extract in handlers
reqCtx := ctx.Value(RequestContextKey).(RequestContext)
```

## 4. GraphQL Standards (Future)

### Schema Design
```graphql
# Use clear, descriptive names
type File {
  id: ID!
  name: String!
  size: Int!
  owner: User!
  chunks: [Chunk!]!
  createdAt: DateTime!
  updatedAt: DateTime!
}

# Mutations return payload types
type CreateFilePayload {
  file: File
  errors: [Error!]
}

# Consistent error type
type Error {
  field: String
  message: String!
  code: ErrorCode!
}
```

### Query Structure
```graphql
query GetFile($id: ID!) {
  file(id: $id) {
    id
    name
    size
    owner {
      id
      name
    }
  }
}

mutation CreateFile($input: CreateFileInput!) {
  createFile(input: $input) {
    file {
      id
      name
    }
    errors {
      field
      message
      code
    }
  }
}
```

## 5. API Documentation Standards

### OpenAPI Specification
```yaml
openapi: 3.0.0
info:
  title: Blackhole Network API
  version: 1.0.0
  description: Decentralized storage and compute API

paths:
  /api/v1/files:
    get:
      summary: List files
      description: Returns a paginated list of files
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            default: 1
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FileList'
```

### Code Documentation
```go
// GetFile retrieves a file by ID.
//
// This endpoint returns the file metadata and download URL.
// The actual file content is served from the storage nodes.
//
// Errors:
//   - 404: File not found
//   - 403: Insufficient permissions
//   - 500: Internal server error
func (h *Handler) GetFile(c *fiber.Ctx) error {
    // Implementation
}
```

## 6. Rate Limiting Standards

### Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1622505600
X-RateLimit-Reset-After: 3600
X-RateLimit-Bucket: user_123
```

### Rate Limit Response
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "retry_after": 3600,
    "limit": 100,
    "window": "1h"
  }
}
```

## 7. API Security Standards

### Authentication
```go
// Bearer token in Authorization header
Authorization: Bearer <jwt-token>

// API key for service-to-service
X-API-Key: <api-key>

// Never in URL parameters
// ❌ GET /api/v1/files?token=secret
```

### CORS Configuration
```go
app.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://app.blackhole.network"},
    AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowHeaders:     []string{"Authorization", "Content-Type"},
    AllowCredentials: true,
    MaxAge:          86400,
}))
```

### Security Headers
```go
app.Use(func(c *fiber.Ctx) error {
    c.Set("X-Content-Type-Options", "nosniff")
    c.Set("X-Frame-Options", "DENY")
    c.Set("X-XSS-Protection", "1; mode=block")
    c.Set("Strict-Transport-Security", "max-age=31536000")
    return c.Next()
})
```

## 8. Performance Standards

### Response Time Targets
- GET single resource: < 100ms (p99)
- GET list resources: < 200ms (p99)
- POST/PUT/DELETE: < 500ms (p99)
- Search operations: < 1s (p99)

### Caching Headers
```http
# Immutable resources (by content hash)
Cache-Control: public, max-age=31536000, immutable
ETag: "33a64df551"

# Dynamic resources
Cache-Control: private, max-age=0, must-revalidate
ETag: W/"33a64df551"

# No caching
Cache-Control: no-store
```

### Compression
```go
// Enable compression for responses > 1KB
app.Use(compress.New(compress.Config{
    Level: compress.LevelBestSpeed,
    Threshold: 1024,
}))
```

## 9. API Testing Standards

### Integration Tests
```go
func TestAPI_GetFile(t *testing.T) {
    // Setup
    app := setupTestApp()
    file := createTestFile()
    
    // Test successful request
    req := httptest.NewRequest("GET", "/api/v1/files/"+file.ID, nil)
    req.Header.Set("Authorization", "Bearer "+validToken)
    
    resp, err := app.Test(req)
    require.NoError(t, err)
    assert.Equal(t, 200, resp.StatusCode)
    
    // Test error cases
    testCases := []struct {
        name       string
        fileID     string
        token      string
        wantStatus int
    }{
        {"not found", "invalid", validToken, 404},
        {"unauthorized", file.ID, "", 401},
        {"forbidden", file.ID, otherUserToken, 403},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            req := httptest.NewRequest("GET", "/api/v1/files/"+tc.fileID, nil)
            if tc.token != "" {
                req.Header.Set("Authorization", "Bearer "+tc.token)
            }
            resp, _ := app.Test(req)
            assert.Equal(t, tc.wantStatus, resp.StatusCode)
        })
    }
}
```

## 10. API Evolution Standards

### Backward Compatibility
- Never remove fields from responses
- Never change field types
- Never change field meanings
- Use deprecation warnings before removal

### Deprecation Process
```go
// 1. Mark as deprecated in docs
// @deprecated Use 'size_bytes' instead

// 2. Add deprecation header
c.Set("X-Deprecated", "field 'size' is deprecated, use 'size_bytes'")

// 3. Log deprecation usage
if hasDeprecatedField(req) {
    log.Warn("deprecated field used", 
        "field", "size",
        "user", userID,
        "endpoint", "/api/v1/files",
    )
}

// 4. Remove after 6 months + major version
```

These API standards ensure consistent, secure, and performant APIs across all components of the Blackhole Network.