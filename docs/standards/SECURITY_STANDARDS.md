# Security Standards

This document defines security standards and practices for the Blackhole Network. Security is not optional - these standards are mandatory.

## 1. Authentication Standards

### Token Management
```go
// JWT token structure
type Claims struct {
    jwt.StandardClaims
    UserID   string   `json:"user_id"`
    Tier     UserTier `json:"tier"`
    Scopes   []string `json:"scopes"`
    DeviceID string   `json:"device_id"`
}

// Token expiration
const (
    AccessTokenTTL  = 15 * time.Minute      // Short-lived
    RefreshTokenTTL = 30 * 24 * time.Hour   // 30 days
    APIKeyTTL       = 365 * 24 * time.Hour  // 1 year
)

// Token generation with proper entropy
func GenerateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

### Password Requirements
```go
// Minimum password requirements
type PasswordPolicy struct {
    MinLength      int  // 12
    RequireUpper   bool // true
    RequireLower   bool // true
    RequireNumber  bool // true
    RequireSpecial bool // true
    MaxAge         time.Duration // 90 days
}

// Password hashing - only bcrypt or argon2
func HashPassword(password string) (string, error) {
    // Use cost factor 12 minimum
    return bcrypt.GenerateFromPassword([]byte(password), 12)
}

// Constant-time comparison
func ComparePassword(hash, password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
```

### Session Management
```go
// Session security
type SessionConfig struct {
    // Security settings
    Secure   bool // true in production
    HttpOnly bool // always true
    SameSite string // "strict"

    // Rotation
    RotateOnLogin bool // true
    MaxAge        time.Duration // 24 hours

    // Tracking
    TrackIP       bool // true
    TrackUA       bool // true
}

// Session invalidation
func InvalidateAllSessions(userID string) error {
    // Must invalidate all user sessions on:
    // - Password change
    // - Privilege change
    // - Security incident
}
```

## 2. Authorization Standards

### Role-Based Access Control (RBAC)
```go
// Define permissions explicitly
type Permission string

const (
    PermFileRead    Permission = "file:read"
    PermFileWrite   Permission = "file:write"
    PermFileDelete  Permission = "file:delete"
    PermNodeManage  Permission = "node:manage"
    PermUserManage  Permission = "user:manage"
)

// Role definitions
type Role struct {
    Name        string
    Permissions []Permission
}

var Roles = map[string]Role{
    "user": {
        Name: "user",
        Permissions: []Permission{
            PermFileRead,
            PermFileWrite,
        },
    },
    "admin": {
        Name: "admin",
        Permissions: []Permission{
            PermFileRead,
            PermFileWrite,
            PermFileDelete,
            PermNodeManage,
            PermUserManage,
        },
    },
}

// Authorization middleware
func RequirePermission(perm Permission) fiber.Handler {
    return func(c *fiber.Ctx) error {
        user := GetUser(c)
        if !user.HasPermission(perm) {
            return c.Status(403).JSON(ErrorResponse{
                Code: "FORBIDDEN",
                Message: "Insufficient permissions",
            })
        }
        return c.Next()
    }
}
```

### Resource-Level Security
```go
// Check ownership
func CanAccessFile(user *User, file *File) bool {
    // Owner always has access
    if file.OwnerID == user.ID {
        return true
    }

    // Check sharing permissions
    if file.IsPublic {
        return true
    }

    // Check explicit grants
    return file.HasGrant(user.ID)
}

// Secure by default
type File struct {
    ID       string
    OwnerID  string
    IsPublic bool `default:"false"`
    Grants   []Grant
}
```

## 3. Input Validation Standards

### Validation Rules
```go
// Always validate all inputs
type FileUploadRequest struct {
    Name string `json:"name" validate:"required,min=1,max=255,filename"`
    Size int64  `json:"size" validate:"required,min=1,max=5368709120"` // 5GB max
    Type string `json:"type" validate:"required,mimetype"`
}

// Custom validators
func init() {
    validate.RegisterValidation("filename", validateFilename)
    validate.RegisterValidation("mimetype", validateMimeType)
}

func validateFilename(fl validator.FieldLevel) bool {
    // No path traversal
    name := fl.Field().String()
    if strings.Contains(name, "..") || strings.Contains(name, "/") {
        return false
    }
    // No special characters
    return filenameRegex.MatchString(name)
}
```

### Sanitization
```go
// HTML/Script injection prevention
func SanitizeString(input string) string {
    // Remove all HTML tags
    p := bluemonday.StrictPolicy()
    return p.Sanitize(input)
}

// SQL injection prevention - use parameterized queries
func GetFileByName(name string) (*File, error) {
    // ✅ Safe
    query := "SELECT * FROM files WHERE name = ?"
    return db.QueryRow(query, name)

    // ❌ Never do this
    // query := fmt.Sprintf("SELECT * FROM files WHERE name = '%s'", name)
}

// Path traversal prevention
func SafeJoinPath(base, userPath string) (string, error) {
    cleaned := filepath.Clean(userPath)
    if strings.Contains(cleaned, "..") {
        return "", ErrInvalidPath
    }

    joined := filepath.Join(base, cleaned)

    // Ensure still within base
    if !strings.HasPrefix(joined, base) {
        return "", ErrInvalidPath
    }

    return joined, nil
}
```

## 4. Cryptography Standards

### Encryption at Rest
```go
// Use AES-256-GCM for file encryption
type EncryptionConfig struct {
    Algorithm string // "AES-256-GCM"
    KeySize   int    // 32 bytes
    NonceSize int    // 12 bytes
}

func EncryptFile(data []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }

    return gcm.Seal(nonce, nonce, data, nil), nil
}
```

### Key Management
```go
// Never hardcode keys
type KeyManager struct {
    masterKey []byte // From environment or KMS
}

// Key derivation for different purposes
func (km *KeyManager) DeriveKey(purpose string, salt []byte) []byte {
    return pbkdf2.Key(km.masterKey, salt, 10000, 32, sha256.New)
}

// Key rotation
func (km *KeyManager) RotateKeys() error {
    // 1. Generate new key
    // 2. Re-encrypt all data
    // 3. Securely delete old key
}
```

### Transport Security
```go
// TLS configuration
func CreateTLSConfig() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        PreferServerCipherSuites: true,
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
        },
    }
}

// Certificate pinning for internal services
func VerifyCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    for _, rawCert := range rawCerts {
        cert, _ := x509.ParseCertificate(rawCert)
        hash := sha256.Sum256(cert.Raw)
        if !isPinnedCert(hash) {
            return ErrInvalidCertificate
        }
    }
    return nil
}
```

## 5. Security Headers

### HTTP Security Headers
```go
func SecurityHeaders() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Prevent XSS
        c.Set("X-XSS-Protection", "1; mode=block")
        c.Set("X-Content-Type-Options", "nosniff")

        // Prevent clickjacking
        c.Set("X-Frame-Options", "DENY")

        // HTTPS enforcement
        c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        // Content Security Policy
        c.Set("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self' wss://;")

        // Referrer policy
        c.Set("Referrer-Policy", "strict-origin-when-cross-origin")

        // Permissions policy
        c.Set("Permissions-Policy",
            "geolocation=(), " +
            "microphone=(), " +
            "camera=(), " +
            "payment=()")

        return c.Next()
    }
}
```

## 6. Audit Logging

### Security Event Logging
```go
// Security events that must be logged
type SecurityEvent struct {
    EventType  SecurityEventType
    UserID     string
    IP         string
    UserAgent  string
    Resource   string
    Action     string
    Result     string
    Timestamp  time.Time
    Details    map[string]any
}

type SecurityEventType string

const (
    EventLogin           SecurityEventType = "login"
    EventLogout          SecurityEventType = "logout"
    EventLoginFailed     SecurityEventType = "login_failed"
    EventPasswordChange  SecurityEventType = "password_change"
    EventPermissionDenied SecurityEventType = "permission_denied"
    EventDataAccess      SecurityEventType = "data_access"
    EventDataModification SecurityEventType = "data_modification"
    EventAPIKeyCreated   SecurityEventType = "api_key_created"
    EventSuspiciousActivity SecurityEventType = "suspicious_activity"
)

// Log security events
func LogSecurityEvent(event SecurityEvent) {
    // Never log sensitive data
    sanitized := sanitizeEvent(event)

    // Write to secure audit log
    auditLogger.Info("security event",
        "type", sanitized.EventType,
        "user_id", sanitized.UserID,
        "ip", sanitized.IP,
        "resource", sanitized.Resource,
        "result", sanitized.Result,
    )
}
```

### Audit Trail Requirements
```go
// Audit trail must be:
// 1. Immutable - use append-only log
// 2. Tamper-evident - include hash chain
// 3. Time-accurate - use NTP-synced time
// 4. Retained - minimum 1 year

type AuditEntry struct {
    ID           string
    Timestamp    time.Time
    EventHash    string // SHA256 of event
    PreviousHash string // Chain integrity
    Event        SecurityEvent
    Signature    string // Digital signature
}
```

## 7. Rate Limiting & DDoS Protection

### Rate Limiting Configuration
```go
// Different limits for different operations
var RateLimits = map[string]RateLimit{
    "login":        {Requests: 5, Window: 15 * time.Minute},
    "api_read":     {Requests: 100, Window: time.Minute},
    "api_write":    {Requests: 20, Window: time.Minute},
    "file_upload":  {Requests: 10, Window: time.Hour},
    "password_reset": {Requests: 3, Window: time.Hour},
}

// Progressive delays for failed attempts
func CalculateDelay(failures int) time.Duration {
    delay := time.Duration(math.Pow(2, float64(failures))) * time.Second
    if delay > 30*time.Minute {
        delay = 30 * time.Minute
    }
    return delay
}
```

### DDoS Mitigation
```go
// Connection limits
type ConnectionLimits struct {
    MaxConnectionsPerIP     int           // 100
    MaxRequestsPerSecond    int           // 10
    MaxConcurrentUploads    int           // 3
    MaxRequestBodySize      int64         // 100MB
    SlowRequestTimeout      time.Duration // 30s
}

// Adaptive rate limiting
func AdaptiveRateLimit(c *fiber.Ctx) error {
    // Check system load
    load := getSystemLoad()

    // Tighten limits under high load
    if load > 0.8 {
        limits.MaxRequestsPerSecond = 5
        limits.MaxConnectionsPerIP = 50
    }

    return nil
}
```

## 8. Secure Coding Practices

### Memory Safety
```go
// Clear sensitive data from memory
func ClearBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
}

// Use defer for cleanup
func ProcessSensitiveData(data []byte) error {
    defer ClearBytes(data)
    // Process data
}

// Avoid buffer overflows
func SafeCopy(dst, src []byte) int {
    n := len(src)
    if n > len(dst) {
        n = len(dst)
    }
    return copy(dst[:n], src[:n])
}
```

### Error Handling
```go
// Don't leak sensitive info in errors
func AuthenticateUser(username, password string) error {
    user, err := getUserByUsername(username)
    if err != nil {
        // Don't reveal if user exists
        return ErrInvalidCredentials
    }

    if !comparePassword(user.Password, password) {
        // Same error for wrong password
        return ErrInvalidCredentials
    }

    return nil
}
```

## 9. Third-Party Dependencies

### Dependency Security
```bash
# Regular vulnerability scanning
go list -json -m all | nancy sleuth

# Keep dependencies updated
go get -u ./...
go mod tidy

# Review licenses
go-licenses check ./...
```

### Allowed Cryptography Libraries
```go
// Approved libraries only
crypto/rand      // Random number generation
crypto/aes       // AES encryption
crypto/cipher    // Block cipher modes
crypto/sha256    // SHA-256 hashing
golang.org/x/crypto/bcrypt  // Password hashing
golang.org/x/crypto/nacl    // NaCl crypto
```

## 10. Incident Response

### Security Incident Checklist
1. **Detect** - Monitoring alerts
2. **Contain** - Isolate affected systems
3. **Assess** - Determine scope and impact
4. **Notify** - Alert stakeholders
5. **Remediate** - Fix vulnerabilities
6. **Recover** - Restore services
7. **Review** - Post-mortem analysis

### Emergency Procedures
```go
// Kill switch for emergencies
func EmergencyShutdown(reason string) {
    log.Fatal("EMERGENCY SHUTDOWN", "reason", reason)

    // 1. Stop accepting new requests
    server.Shutdown()

    // 2. Invalidate all sessions
    sessions.InvalidateAll()

    // 3. Rotate all keys
    keys.RotateAll()

    // 4. Alert administrators
    alerts.SendEmergency(reason)

    // 5. Preserve audit logs
    audit.Backup()

    os.Exit(1)
}
```

## Security Checklist for Code Reviews

- [ ] All inputs validated and sanitized
- [ ] Authentication required for protected resources
- [ ] Authorization checks for user actions
- [ ] Sensitive data encrypted at rest and in transit
- [ ] No hardcoded secrets or credentials
- [ ] SQL queries use parameters, not string concat
- [ ] Errors don't leak sensitive information
- [ ] Rate limiting on sensitive operations
- [ ] Audit logging for security events
- [ ] Dependencies checked for vulnerabilities

Security is everyone's responsibility. When in doubt, ask for a security review.
