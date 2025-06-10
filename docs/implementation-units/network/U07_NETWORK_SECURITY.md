# Unit U07: Network Security Layer - Implementation Design

## 1. Unit Overview

### Purpose and Goals

Unit U07 implements comprehensive network security for the Blackhole platform, providing transport encryption, node authentication, and connection security. This unit builds upon the libp2p security framework to ensure all network communications are encrypted, authenticated, and protected against various attack vectors.

**Primary Goals:**
- Implement TLS 1.3 and Noise Protocol for transport security
- Provide mutual authentication between nodes
- Enable connection encryption with perfect forward secrecy
- Implement certificate and key management
- Protect against man-in-the-middle attacks

### Dependencies

- **U01: libp2p Core Setup** - Basic security protocols and transport layer
- **U02: Kademlia DHT Implementation** - Secure peer discovery
- **U03: NAT Traversal & Connectivity** - Secure connection establishment

### Deliverables

1. **Transport Security Implementation**
   - TLS 1.3 with modern cipher suites
   - Noise Protocol framework integration
   - Protocol negotiation and selection

2. **Node Authentication System**
   - Peer identity verification
   - Certificate validation
   - Public key infrastructure

3. **Connection Encryption**
   - End-to-end encryption for all connections
   - Perfect forward secrecy
   - Key rotation mechanisms

4. **Security Policy Engine**
   - Connection policy enforcement
   - Blacklist/whitelist management
   - Security audit logging

### Integration Points

This unit secures:
- All P2P communications (U01-U09)
- Service discovery traffic (U06)
- Storage transfers (U10-U13)
- Payment channel communications (U16)
- All API communications (U41)

## 2. Technical Specifications

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│                    Security Policy Engine                    │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Policies   │  │   Auditing   │  │  Access Control  │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Authentication Layer                        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Peer ID   │  │ Certificate  │  │   Reputation     │  │
│  │ Verification │  │  Validation  │  │   Integration    │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Encryption Layer                            │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   TLS 1.3   │  │    Noise     │  │  Key Exchange    │  │
│  │   Protocol   │  │   Protocol   │  │   & Rotation     │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Transport Layer                           │
│              (TCP, QUIC, WebSocket, WebRTC)                 │
└─────────────────────────────────────────────────────────────┘
```

### Cryptographic Specifications

#### TLS 1.3 Configuration
- **Cipher Suites**:
  - TLS_AES_256_GCM_SHA384 (preferred)
  - TLS_AES_128_GCM_SHA256
  - TLS_CHACHA20_POLY1305_SHA256
- **Key Exchange**: X25519, P-256
- **Signature Algorithms**: Ed25519, ECDSA-P256-SHA256
- **Minimum Version**: TLS 1.3 only

#### Noise Protocol Configuration
- **Pattern**: XX (mutual authentication)
- **DH Function**: Curve25519
- **Cipher**: ChaChaPoly
- **Hash**: SHA256

#### Key Management
- **Identity Keys**: Ed25519 (256-bit)
- **Session Keys**: Ephemeral X25519
- **Key Rotation**: Every 24 hours or 1GB transferred
- **Key Storage**: Hardware security module (HSM) compatible

## 3. Implementation Details

### Project Structure

```
pkg/security/
├── security.go         # Main security manager
├── tls.go              # TLS 1.3 implementation
├── noise.go            # Noise protocol implementation
├── auth.go             # Authentication system
├── policy.go           # Security policy engine
├── keystore.go         # Key management
├── audit.go            # Security audit logging
├── blacklist.go        # Peer blacklist management
├── certificate.go      # Certificate handling
├── metrics.go          # Security metrics
├── errors.go           # Security-specific errors
├── tests/
│   ├── security_test.go
│   ├── tls_test.go
│   ├── noise_test.go
│   ├── auth_test.go
│   ├── policy_test.go
│   └── integration_test.go
└── examples/
    ├── secure_host/    # Secure host example
    └── mutual_auth/    # Mutual authentication example
```

### Core Security Manager

```go
// pkg/security/security.go
package security

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "fmt"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
    "github.com/libp2p/go-libp2p/core/protocol"
    "github.com/libp2p/go-libp2p/core/sec"
    "github.com/prometheus/client_golang/prometheus"
)

const (
    // Security protocol IDs
    TLSProtocol   = "/tls/1.3"
    NoiseProtocol = "/noise/xx/25519/chachapoly/sha256"
    
    // Default security parameters
    DefaultKeyRotationInterval = 24 * time.Hour
    DefaultKeyRotationBytes    = 1 << 30 // 1GB
    DefaultSessionTimeout      = 1 * time.Hour
    DefaultMaxConcurrentAuths  = 100
)

// SecurityManager manages all security aspects of the network
type SecurityManager struct {
    host      host.Host
    keystore  *KeyStore
    policy    *PolicyEngine
    audit     *AuditLogger
    blacklist *Blacklist
    
    // Authentication state
    authMu    sync.RWMutex
    authState map[peer.ID]*AuthState
    
    // Session management
    sessionMu sync.RWMutex
    sessions  map[string]*Session
    
    // Metrics
    metrics *SecurityMetrics
    
    // Configuration
    config *Config
    
    // Lifecycle
    ctx    context.Context
    cancel context.CancelFunc
    wg     sync.WaitGroup
}

// Config holds security configuration
type Config struct {
    // TLS configuration
    TLSEnabled     bool
    TLSCertPath    string
    TLSKeyPath     string
    TLSMinVersion  uint16
    TLSCipherSuites []uint16
    
    // Noise configuration
    NoiseEnabled   bool
    NoiseStaticKey crypto.PrivKey
    
    // Key management
    KeyRotationInterval time.Duration
    KeyRotationBytes    uint64
    KeyStorePath        string
    
    // Authentication
    RequireMutualAuth   bool
    AuthTimeout         time.Duration
    MaxConcurrentAuths  int
    
    // Policy
    PolicyPath          string
    EnforcePolicies     bool
    
    // Audit
    AuditEnabled        bool
    AuditPath           string
    AuditRetention      time.Duration
    
    // Session management
    SessionTimeout      time.Duration
    MaxSessions         int
}

// AuthState tracks authentication state for a peer
type AuthState struct {
    PeerID        peer.ID
    Authenticated bool
    AuthTime      time.Time
    Certificate   *x509.Certificate
    PublicKey     crypto.PubKey
    Reputation    float64
    Attributes    map[string]string
}

// Session represents an encrypted session
type Session struct {
    ID            string
    LocalPeer     peer.ID
    RemotePeer    peer.ID
    Protocol      string
    CipherSuite   string
    Established   time.Time
    LastActivity  time.Time
    BytesIn       uint64
    BytesOut      uint64
    KeyRotations  uint32
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(h host.Host, cfg *Config) (*SecurityManager, error) {
    if cfg == nil {
        cfg = DefaultConfig()
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    // Initialize components
    keystore, err := NewKeyStore(cfg.KeyStorePath)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("failed to create keystore: %w", err)
    }
    
    policy, err := NewPolicyEngine(cfg.PolicyPath)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("failed to create policy engine: %w", err)
    }
    
    audit, err := NewAuditLogger(cfg.AuditPath, cfg.AuditEnabled)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("failed to create audit logger: %w", err)
    }
    
    sm := &SecurityManager{
        host:      h,
        keystore:  keystore,
        policy:    policy,
        audit:     audit,
        blacklist: NewBlacklist(),
        authState: make(map[peer.ID]*AuthState),
        sessions:  make(map[string]*Session),
        config:    cfg,
        metrics:   NewSecurityMetrics(),
        ctx:       ctx,
        cancel:    cancel,
    }
    
    // Set up connection handlers
    h.Network().Notify(&network.NotifyBundle{
        ConnectedF:    sm.onConnected,
        DisconnectedF: sm.onDisconnected,
    })
    
    // Start background tasks
    sm.wg.Add(3)
    go sm.keyRotationLoop()
    go sm.sessionCleanupLoop()
    go sm.auditFlushLoop()
    
    return sm, nil
}

// AuthenticatePeer performs mutual authentication with a peer
func (sm *SecurityManager) AuthenticatePeer(ctx context.Context, p peer.ID) error {
    // Check blacklist
    if sm.blacklist.IsBlacklisted(p) {
        sm.metrics.AuthFailures.Inc()
        return ErrPeerBlacklisted
    }
    
    // Check if already authenticated
    sm.authMu.RLock()
    if state, exists := sm.authState[p]; exists && state.Authenticated {
        sm.authMu.RUnlock()
        return nil
    }
    sm.authMu.RUnlock()
    
    // Rate limit authentication attempts
    if !sm.rateLimitAuth(p) {
        return ErrAuthRateLimited
    }
    
    // Create authentication context with timeout
    authCtx, cancel := context.WithTimeout(ctx, sm.config.AuthTimeout)
    defer cancel()
    
    // Perform authentication protocol
    sm.metrics.AuthAttempts.Inc()
    
    start := time.Now()
    authResult, err := sm.performAuthentication(authCtx, p)
    duration := time.Since(start)
    
    sm.metrics.AuthDuration.Observe(duration.Seconds())
    
    if err != nil {
        sm.metrics.AuthFailures.Inc()
        sm.audit.LogAuthFailure(p, err)
        
        // Update blacklist on repeated failures
        if sm.shouldBlacklist(p, err) {
            sm.blacklist.Add(p, 24*time.Hour, "repeated auth failures")
        }
        
        return fmt.Errorf("authentication failed: %w", err)
    }
    
    // Store authentication state
    sm.authMu.Lock()
    sm.authState[p] = authResult
    sm.authMu.Unlock()
    
    sm.metrics.AuthSuccesses.Inc()
    sm.metrics.AuthenticatedPeers.Inc()
    sm.audit.LogAuthSuccess(p, authResult)
    
    return nil
}

// performAuthentication executes the authentication protocol
func (sm *SecurityManager) performAuthentication(ctx context.Context, p peer.ID) (*AuthState, error) {
    // Open authentication stream
    stream, err := sm.host.NewStream(ctx, p, protocol.ID("/blackhole/auth/1.0.0"))
    if err != nil {
        return nil, fmt.Errorf("failed to open auth stream: %w", err)
    }
    defer stream.Close()
    
    // Generate challenge
    challenge := make([]byte, 32)
    if _, err := rand.Read(challenge); err != nil {
        return nil, fmt.Errorf("failed to generate challenge: %w", err)
    }
    
    // Send authentication request
    authReq := &AuthRequest{
        Version:   "1.0.0",
        PeerID:    sm.host.ID().String(),
        Challenge: challenge,
        Timestamp: time.Now().Unix(),
    }
    
    if err := writeAuthMessage(stream, authReq); err != nil {
        return nil, fmt.Errorf("failed to send auth request: %w", err)
    }
    
    // Read authentication response
    var authResp AuthResponse
    if err := readAuthMessage(stream, &authResp); err != nil {
        return nil, fmt.Errorf("failed to read auth response: %w", err)
    }
    
    // Verify response
    if err := sm.verifyAuthResponse(&authResp, challenge); err != nil {
        return nil, fmt.Errorf("auth verification failed: %w", err)
    }
    
    // Extract peer's public key
    pubKey, err := crypto.UnmarshalPublicKey(authResp.PublicKey)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
    }
    
    // Verify peer ID matches public key
    derivedID, err := peer.IDFromPublicKey(pubKey)
    if err != nil {
        return nil, fmt.Errorf("failed to derive peer ID: %w", err)
    }
    
    if derivedID != p {
        return nil, ErrPeerIDMismatch
    }
    
    // Create authentication state
    authState := &AuthState{
        PeerID:        p,
        Authenticated: true,
        AuthTime:      time.Now(),
        PublicKey:     pubKey,
        Attributes:    authResp.Attributes,
    }
    
    // Verify certificate if provided
    if len(authResp.Certificate) > 0 {
        cert, err := x509.ParseCertificate(authResp.Certificate)
        if err == nil {
            authState.Certificate = cert
        }
    }
    
    return authState, nil
}

// EstablishSecureConnection creates an encrypted connection to a peer
func (sm *SecurityManager) EstablishSecureConnection(ctx context.Context, p peer.ID) (network.Stream, error) {
    // Ensure peer is authenticated
    if err := sm.AuthenticatePeer(ctx, p); err != nil {
        return nil, fmt.Errorf("authentication required: %w", err)
    }
    
    // Check security policy
    if sm.config.EnforcePolicies {
        if err := sm.policy.CheckConnectionPolicy(sm.host.ID(), p); err != nil {
            sm.audit.LogPolicyViolation(p, err)
            return nil, fmt.Errorf("policy violation: %w", err)
        }
    }
    
    // Select security protocol
    protocol := sm.selectSecurityProtocol(p)
    
    // Create secure stream
    stream, err := sm.host.NewStream(ctx, p, protocol)
    if err != nil {
        return nil, fmt.Errorf("failed to create secure stream: %w", err)
    }
    
    // Wrap stream with encryption
    secureStream, err := sm.wrapSecureStream(stream, p, protocol)
    if err != nil {
        stream.Close()
        return nil, fmt.Errorf("failed to establish encryption: %w", err)
    }
    
    // Create session
    session := &Session{
        ID:          generateSessionID(),
        LocalPeer:   sm.host.ID(),
        RemotePeer:  p,
        Protocol:    string(protocol),
        Established: time.Now(),
        LastActivity: time.Now(),
    }
    
    sm.sessionMu.Lock()
    sm.sessions[session.ID] = session
    sm.sessionMu.Unlock()
    
    sm.metrics.SecureConnections.Inc()
    sm.audit.LogSecureConnection(session)
    
    return secureStream, nil
}

// wrapSecureStream wraps a stream with encryption
func (sm *SecurityManager) wrapSecureStream(stream network.Stream, p peer.ID, proto protocol.ID) (network.Stream, error) {
    switch proto {
    case TLSProtocol:
        return sm.wrapTLSStream(stream, p)
    case NoiseProtocol:
        return sm.wrapNoiseStream(stream, p)
    default:
        return nil, fmt.Errorf("unsupported security protocol: %s", proto)
    }
}

// RotateKeys performs key rotation for all active sessions
func (sm *SecurityManager) RotateKeys() error {
    sm.sessionMu.RLock()
    sessions := make([]*Session, 0, len(sm.sessions))
    for _, session := range sm.sessions {
        sessions = append(sessions, session)
    }
    sm.sessionMu.RUnlock()
    
    rotated := 0
    errors := 0
    
    for _, session := range sessions {
        // Check if rotation is needed
        if !sm.needsKeyRotation(session) {
            continue
        }
        
        // Perform key rotation
        if err := sm.rotateSessionKeys(session); err != nil {
            log.Warnf("Failed to rotate keys for session %s: %v", session.ID, err)
            errors++
            continue
        }
        
        rotated++
        session.KeyRotations++
        sm.metrics.KeyRotations.Inc()
    }
    
    log.Infof("Key rotation completed: %d rotated, %d errors", rotated, errors)
    
    if errors > 0 {
        return fmt.Errorf("key rotation completed with %d errors", errors)
    }
    
    return nil
}

// needsKeyRotation checks if a session needs key rotation
func (sm *SecurityManager) needsKeyRotation(session *Session) bool {
    // Time-based rotation
    if time.Since(session.Established) > sm.config.KeyRotationInterval {
        return true
    }
    
    // Volume-based rotation
    totalBytes := session.BytesIn + session.BytesOut
    if totalBytes > sm.config.KeyRotationBytes {
        return true
    }
    
    return false
}

// GetSecurityInfo returns security information for a peer
func (sm *SecurityManager) GetSecurityInfo(p peer.ID) (*SecurityInfo, error) {
    sm.authMu.RLock()
    authState, exists := sm.authState[p]
    sm.authMu.RUnlock()
    
    if !exists {
        return nil, ErrPeerNotAuthenticated
    }
    
    info := &SecurityInfo{
        PeerID:        p,
        Authenticated: authState.Authenticated,
        AuthTime:      authState.AuthTime,
        PublicKey:     authState.PublicKey,
    }
    
    // Add certificate info if available
    if authState.Certificate != nil {
        info.CertificateInfo = &CertificateInfo{
            Subject:   authState.Certificate.Subject.String(),
            Issuer:    authState.Certificate.Issuer.String(),
            NotBefore: authState.Certificate.NotBefore,
            NotAfter:  authState.Certificate.NotAfter,
        }
    }
    
    // Add active sessions
    sm.sessionMu.RLock()
    for _, session := range sm.sessions {
        if session.RemotePeer == p {
            info.ActiveSessions = append(info.ActiveSessions, session)
        }
    }
    sm.sessionMu.RUnlock()
    
    return info, nil
}

// keyRotationLoop periodically rotates encryption keys
func (sm *SecurityManager) keyRotationLoop() {
    defer sm.wg.Done()
    
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if err := sm.RotateKeys(); err != nil {
                log.Errorf("Key rotation failed: %v", err)
            }
        case <-sm.ctx.Done():
            return
        }
    }
}

// sessionCleanupLoop removes expired sessions
func (sm *SecurityManager) sessionCleanupLoop() {
    defer sm.wg.Done()
    
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            sm.cleanupSessions()
        case <-sm.ctx.Done():
            return
        }
    }
}

// Close shuts down the security manager
func (sm *SecurityManager) Close() error {
    sm.cancel()
    sm.wg.Wait()
    
    // Close all secure connections
    sm.sessionMu.Lock()
    for _, session := range sm.sessions {
        sm.closeSession(session)
    }
    sm.sessionMu.Unlock()
    
    // Flush audit logs
    if err := sm.audit.Flush(); err != nil {
        log.Warnf("Failed to flush audit logs: %v", err)
    }
    
    return sm.keystore.Close()
}
```

### TLS 1.3 Implementation

```go
// pkg/security/tls.go
package security

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "net"
    "time"

    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
)

// TLSTransport implements TLS 1.3 security transport
type TLSTransport struct {
    sm        *SecurityManager
    tlsConfig *tls.Config
}

// NewTLSTransport creates a new TLS transport
func NewTLSTransport(sm *SecurityManager) (*TLSTransport, error) {
    // Load certificates
    cert, err := sm.keystore.GetTLSCertificate()
    if err != nil {
        return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
    }
    
    // Create TLS configuration
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{*cert},
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
        },
        SessionTicketsDisabled: false,
        Renegotiation:         tls.RenegotiateNever,
        
        // Custom verification
        VerifyPeerCertificate: sm.verifyPeerCertificate,
        
        // Client authentication
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs:  sm.getClientCAs(),
    }
    
    return &TLSTransport{
        sm:        sm,
        tlsConfig: tlsConfig,
    }, nil
}

// wrapTLSStream wraps a stream with TLS encryption
func (sm *SecurityManager) wrapTLSStream(stream network.Stream, p peer.ID) (network.Stream, error) {
    transport, err := NewTLSTransport(sm)
    if err != nil {
        return nil, err
    }
    
    // Create TLS connection
    conn := &tlsConn{
        Stream: stream,
        local:  sm.host.ID(),
        remote: p,
    }
    
    var tlsConn *tls.Conn
    
    // Determine if we're client or server
    if sm.host.ID() < p {
        // We're the client
        tlsConn = tls.Client(conn, transport.tlsConfig)
    } else {
        // We're the server
        tlsConn = tls.Server(conn, transport.tlsConfig)
    }
    
    // Perform handshake
    handshakeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
        return nil, fmt.Errorf("TLS handshake failed: %w", err)
    }
    
    // Verify connection state
    state := tlsConn.ConnectionState()
    if !state.HandshakeComplete {
        return nil, ErrHandshakeIncomplete
    }
    
    // Update metrics
    sm.metrics.TLSHandshakes.Inc()
    sm.metrics.CipherSuites.WithLabelValues(
        tls.CipherSuiteName(state.CipherSuite),
    ).Inc()
    
    // Create secure stream wrapper
    return &secureStream{
        Stream:   stream,
        conn:     tlsConn,
        security: TLSProtocol,
        state:    &state,
    }, nil
}

// verifyPeerCertificate performs custom certificate verification
func (sm *SecurityManager) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    if len(rawCerts) == 0 {
        return ErrNoCertificate
    }
    
    // Parse peer certificate
    cert, err := x509.ParseCertificate(rawCerts[0])
    if err != nil {
        return fmt.Errorf("failed to parse certificate: %w", err)
    }
    
    // Extract peer ID from certificate
    peerID, err := extractPeerIDFromCert(cert)
    if err != nil {
        return fmt.Errorf("failed to extract peer ID: %w", err)
    }
    
    // Check blacklist
    if sm.blacklist.IsBlacklisted(peerID) {
        return ErrPeerBlacklisted
    }
    
    // Verify certificate policy
    if sm.config.EnforcePolicies {
        if err := sm.policy.CheckCertificatePolicy(cert); err != nil {
            return fmt.Errorf("certificate policy violation: %w", err)
        }
    }
    
    // Custom verification logic
    opts := x509.VerifyOptions{
        Roots:         sm.getRootCAs(),
        Intermediates: sm.getIntermediateCAs(),
        CurrentTime:   time.Now(),
        KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
    }
    
    _, err = cert.Verify(opts)
    if err != nil {
        return fmt.Errorf("certificate verification failed: %w", err)
    }
    
    return nil
}

// tlsConn wraps a libp2p stream as a net.Conn for TLS
type tlsConn struct {
    network.Stream
    local  peer.ID
    remote peer.ID
}

func (c *tlsConn) LocalAddr() net.Addr {
    return &tlsAddr{id: c.local}
}

func (c *tlsConn) RemoteAddr() net.Addr {
    return &tlsAddr{id: c.remote}
}

func (c *tlsConn) SetDeadline(t time.Time) error {
    return c.Stream.SetDeadline(t)
}

func (c *tlsConn) SetReadDeadline(t time.Time) error {
    return c.Stream.SetReadDeadline(t)
}

func (c *tlsConn) SetWriteDeadline(t time.Time) error {
    return c.Stream.SetWriteDeadline(t)
}

// tlsAddr implements net.Addr
type tlsAddr struct {
    id peer.ID
}

func (a *tlsAddr) Network() string {
    return "libp2p-tls"
}

func (a *tlsAddr) String() string {
    return a.id.String()
}

// secureStream wraps an encrypted connection
type secureStream struct {
    network.Stream
    conn     io.ReadWriteCloser
    security protocol.ID
    state    *tls.ConnectionState
}

func (s *secureStream) Read(b []byte) (int, error) {
    return s.conn.Read(b)
}

func (s *secureStream) Write(b []byte) (int, error) {
    return s.conn.Write(b)
}

func (s *secureStream) Close() error {
    if err := s.conn.Close(); err != nil {
        return err
    }
    return s.Stream.Close()
}

func (s *secureStream) Security() protocol.ID {
    return s.security
}

func (s *secureStream) ConnectionState() tls.ConnectionState {
    if s.state != nil {
        return *s.state
    }
    return tls.ConnectionState{}
}
```

### Noise Protocol Implementation

```go
// pkg/security/noise.go
package security

import (
    "bytes"
    "crypto/rand"
    "fmt"
    "io"

    "github.com/flynn/noise"
    "github.com/libp2p/go-libp2p/core/crypto"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/libp2p/go-libp2p/core/peer"
)

// NoiseTransport implements Noise Protocol Framework
type NoiseTransport struct {
    sm         *SecurityManager
    privateKey crypto.PrivKey
    pattern    noise.HandshakePattern
}

// NewNoiseTransport creates a new Noise transport
func NewNoiseTransport(sm *SecurityManager) (*NoiseTransport, error) {
    return &NoiseTransport{
        sm:         sm,
        privateKey: sm.host.Peerstore().PrivKey(sm.host.ID()),
        pattern:    noise.HandshakeXX, // Mutual authentication
    }, nil
}

// wrapNoiseStream wraps a stream with Noise encryption
func (sm *SecurityManager) wrapNoiseStream(stream network.Stream, p peer.ID) (network.Stream, error) {
    transport, err := NewNoiseTransport(sm)
    if err != nil {
        return nil, err
    }
    
    // Convert Ed25519 key to Curve25519 for Noise
    x25519Key, err := ed25519ToCurve25519(transport.privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to convert key: %w", err)
    }
    
    // Create Noise configuration
    config := noise.Config{
        CipherSuite: noise.NewCipherSuite(
            noise.DH25519,
            noise.CipherChaChaPoly,
            noise.HashSHA256,
        ),
        Pattern:      transport.pattern,
        Initiator:    sm.host.ID() < p,
        StaticKeypair: noise.DHKey{
            Private: x25519Key,
            Public:  getPublicKey(x25519Key),
        },
    }
    
    // Create handshake state
    handshakeState, err := noise.NewHandshakeState(config)
    if err != nil {
        return nil, fmt.Errorf("failed to create handshake state: %w", err)
    }
    
    // Perform handshake
    var handshakeComplete bool
    var sendCipher, recvCipher *noise.CipherState
    
    // Buffer for handshake messages
    msgBuf := make([]byte, 65535)
    
    for !handshakeComplete {
        var msg []byte
        var err error
        
        if handshakeState.MessageIndex()%2 == 0 {
            // Our turn to send
            msg, sendCipher, recvCipher, err = handshakeState.WriteMessage(nil, msgBuf[:0])
            if err != nil {
                return nil, fmt.Errorf("handshake write failed: %w", err)
            }
            
            // Send message length
            lengthBuf := make([]byte, 2)
            binary.BigEndian.PutUint16(lengthBuf, uint16(len(msg)))
            if _, err := stream.Write(lengthBuf); err != nil {
                return nil, err
            }
            
            // Send message
            if _, err := stream.Write(msg); err != nil {
                return nil, err
            }
        } else {
            // Our turn to receive
            // Read message length
            lengthBuf := make([]byte, 2)
            if _, err := io.ReadFull(stream, lengthBuf); err != nil {
                return nil, err
            }
            msgLen := binary.BigEndian.Uint16(lengthBuf)
            
            // Read message
            msg = msgBuf[:msgLen]
            if _, err := io.ReadFull(stream, msg); err != nil {
                return nil, err
            }
            
            // Process message
            _, sendCipher, recvCipher, err = handshakeState.ReadMessage(msg, nil)
            if err != nil {
                return nil, fmt.Errorf("handshake read failed: %w", err)
            }
        }
        
        // Check if handshake is complete
        if sendCipher != nil && recvCipher != nil {
            handshakeComplete = true
        }
    }
    
    // Verify remote peer identity
    remotePubKey := handshakeState.PeerStatic()
    if err := sm.verifyNoiseHandshake(p, remotePubKey); err != nil {
        return nil, fmt.Errorf("handshake verification failed: %w", err)
    }
    
    // Update metrics
    sm.metrics.NoiseHandshakes.Inc()
    
    // Create secure stream
    return &noiseStream{
        Stream:      stream,
        sendCipher:  sendCipher,
        recvCipher:  recvCipher,
        readBuffer:  bytes.NewBuffer(nil),
        writeBuffer: bytes.NewBuffer(nil),
    }, nil
}

// noiseStream implements encrypted communication using Noise
type noiseStream struct {
    network.Stream
    sendCipher  *noise.CipherState
    recvCipher  *noise.CipherState
    readBuffer  *bytes.Buffer
    writeBuffer *bytes.Buffer
}

func (ns *noiseStream) Read(b []byte) (int, error) {
    // Check if we have buffered data
    if ns.readBuffer.Len() > 0 {
        return ns.readBuffer.Read(b)
    }
    
    // Read encrypted message length
    lengthBuf := make([]byte, 2)
    if _, err := io.ReadFull(ns.Stream, lengthBuf); err != nil {
        return 0, err
    }
    msgLen := binary.BigEndian.Uint16(lengthBuf)
    
    // Read encrypted message
    encryptedMsg := make([]byte, msgLen)
    if _, err := io.ReadFull(ns.Stream, encryptedMsg); err != nil {
        return 0, err
    }
    
    // Decrypt message
    plaintext, err := ns.recvCipher.Decrypt(nil, nil, encryptedMsg)
    if err != nil {
        return 0, fmt.Errorf("decryption failed: %w", err)
    }
    
    // Buffer decrypted data
    ns.readBuffer.Write(plaintext)
    
    // Read from buffer
    return ns.readBuffer.Read(b)
}

func (ns *noiseStream) Write(b []byte) (int, error) {
    // Encrypt data
    ciphertext, err := ns.sendCipher.Encrypt(nil, nil, b)
    if err != nil {
        return 0, fmt.Errorf("encryption failed: %w", err)
    }
    
    // Write message length
    lengthBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(lengthBuf, uint16(len(ciphertext)))
    if _, err := ns.Stream.Write(lengthBuf); err != nil {
        return 0, err
    }
    
    // Write encrypted message
    if _, err := ns.Stream.Write(ciphertext); err != nil {
        return 0, err
    }
    
    return len(b), nil
}

func (ns *noiseStream) Security() protocol.ID {
    return NoiseProtocol
}

// verifyNoiseHandshake verifies the remote peer's identity
func (sm *SecurityManager) verifyNoiseHandshake(expectedPeer peer.ID, remotePubKey []byte) error {
    // Convert Curve25519 public key back to Ed25519
    ed25519PubKey, err := curve25519ToEd25519(remotePubKey)
    if err != nil {
        return fmt.Errorf("failed to convert key: %w", err)
    }
    
    // Create libp2p public key
    pubKey, err := crypto.UnmarshalEd25519PublicKey(ed25519PubKey)
    if err != nil {
        return fmt.Errorf("failed to unmarshal public key: %w", err)
    }
    
    // Derive peer ID from public key
    derivedID, err := peer.IDFromPublicKey(pubKey)
    if err != nil {
        return fmt.Errorf("failed to derive peer ID: %w", err)
    }
    
    // Verify it matches expected peer
    if derivedID != expectedPeer {
        return ErrPeerIDMismatch
    }
    
    return nil
}
```

### Security Policy Engine

```go
// pkg/security/policy.go
package security

import (
    "crypto/x509"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/peer"
    "gopkg.in/yaml.v3"
)

// PolicyEngine enforces security policies
type PolicyEngine struct {
    mu       sync.RWMutex
    policies *SecurityPolicies
}

// SecurityPolicies defines all security policies
type SecurityPolicies struct {
    // Connection policies
    Connection ConnectionPolicies `yaml:"connection"`
    
    // Certificate policies
    Certificate CertificatePolicies `yaml:"certificate"`
    
    // Encryption policies
    Encryption EncryptionPolicies `yaml:"encryption"`
    
    // Access control policies
    Access AccessPolicies `yaml:"access"`
}

// ConnectionPolicies defines connection-level policies
type ConnectionPolicies struct {
    // Require mutual authentication
    RequireMutualAuth bool `yaml:"require_mutual_auth"`
    
    // Minimum TLS version
    MinTLSVersion string `yaml:"min_tls_version"`
    
    // Allowed cipher suites
    AllowedCipherSuites []string `yaml:"allowed_cipher_suites"`
    
    // Connection rate limits
    RateLimits RateLimitPolicies `yaml:"rate_limits"`
    
    // IP-based restrictions
    IPRestrictions IPRestrictionPolicies `yaml:"ip_restrictions"`
}

// CertificatePolicies defines certificate validation policies
type CertificatePolicies struct {
    // Required certificate attributes
    RequiredAttributes map[string]string `yaml:"required_attributes"`
    
    // Minimum key size (bits)
    MinKeySize int `yaml:"min_key_size"`
    
    // Maximum certificate lifetime
    MaxLifetime time.Duration `yaml:"max_lifetime"`
    
    // Required extensions
    RequiredExtensions []string `yaml:"required_extensions"`
    
    // Trusted CAs
    TrustedCAs []string `yaml:"trusted_cas"`
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(policyPath string) (*PolicyEngine, error) {
    pe := &PolicyEngine{
        policies: DefaultPolicies(),
    }
    
    if policyPath != "" {
        if err := pe.LoadPolicies(policyPath); err != nil {
            return nil, fmt.Errorf("failed to load policies: %w", err)
        }
    }
    
    return pe, nil
}

// CheckConnectionPolicy verifies connection meets policy requirements
func (pe *PolicyEngine) CheckConnectionPolicy(local, remote peer.ID) error {
    pe.mu.RLock()
    defer pe.mu.RUnlock()
    
    // Check if peer is explicitly allowed
    if pe.isPeerAllowed(remote) {
        return nil
    }
    
    // Check if peer is explicitly denied
    if pe.isPeerDenied(remote) {
        return ErrPeerDenied
    }
    
    // Check rate limits
    if err := pe.checkRateLimits(remote); err != nil {
        return err
    }
    
    return nil
}

// CheckCertificatePolicy verifies certificate meets policy requirements
func (pe *PolicyEngine) CheckCertificatePolicy(cert *x509.Certificate) error {
    pe.mu.RLock()
    defer pe.mu.RUnlock()
    
    policies := pe.policies.Certificate
    
    // Check key size
    keySize := getKeySize(cert.PublicKey)
    if keySize < policies.MinKeySize {
        return fmt.Errorf("key size %d below minimum %d", keySize, policies.MinKeySize)
    }
    
    // Check certificate lifetime
    lifetime := cert.NotAfter.Sub(cert.NotBefore)
    if lifetime > policies.MaxLifetime {
        return fmt.Errorf("certificate lifetime %v exceeds maximum %v", lifetime, policies.MaxLifetime)
    }
    
    // Check required attributes
    for key, value := range policies.RequiredAttributes {
        if !certificateHasAttribute(cert, key, value) {
            return fmt.Errorf("missing required attribute: %s=%s", key, value)
        }
    }
    
    // Check required extensions
    for _, ext := range policies.RequiredExtensions {
        if !certificateHasExtension(cert, ext) {
            return fmt.Errorf("missing required extension: %s", ext)
        }
    }
    
    return nil
}

// CheckEncryptionPolicy verifies encryption parameters meet requirements
func (pe *PolicyEngine) CheckEncryptionPolicy(protocol string, cipherSuite string) error {
    pe.mu.RLock()
    defer pe.mu.RUnlock()
    
    // Check if cipher suite is allowed
    allowed := false
    for _, cs := range pe.policies.Connection.AllowedCipherSuites {
        if cs == cipherSuite {
            allowed = true
            break
        }
    }
    
    if !allowed {
        return fmt.Errorf("cipher suite not allowed: %s", cipherSuite)
    }
    
    return nil
}

// UpdatePolicy updates a specific policy
func (pe *PolicyEngine) UpdatePolicy(path string, value interface{}) error {
    pe.mu.Lock()
    defer pe.mu.Unlock()
    
    // Implementation would update specific policy based on path
    // e.g., "connection.rate_limits.max_connections_per_peer"
    
    return nil
}

// LoadPolicies loads policies from a file
func (pe *PolicyEngine) LoadPolicies(path string) error {
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    
    var policies SecurityPolicies
    if err := yaml.Unmarshal(data, &policies); err != nil {
        return err
    }
    
    pe.mu.Lock()
    pe.policies = &policies
    pe.mu.Unlock()
    
    return nil
}

// DefaultPolicies returns default security policies
func DefaultPolicies() *SecurityPolicies {
    return &SecurityPolicies{
        Connection: ConnectionPolicies{
            RequireMutualAuth: true,
            MinTLSVersion:    "1.3",
            AllowedCipherSuites: []string{
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
            },
            RateLimits: RateLimitPolicies{
                MaxConnectionsPerPeer: 10,
                MaxConnectionsPerIP:   50,
                ConnectionsPerSecond:  10,
            },
        },
        Certificate: CertificatePolicies{
            MinKeySize:  2048,
            MaxLifetime: 365 * 24 * time.Hour,
            RequiredAttributes: map[string]string{
                "O": "Blackhole Network",
            },
        },
        Encryption: EncryptionPolicies{
            MinKeySize:        256,
            RequirePFS:        true,
            KeyRotationPeriod: 24 * time.Hour,
        },
        Access: AccessPolicies{
            DefaultAction: "allow",
            Rules:         []AccessRule{},
        },
    }
}
```

## 4. Key Functions

### AuthenticatePeer() - Authenticate a peer

```go
// AuthenticatePeer performs mutual authentication with a peer
// Parameters:
//   - ctx: Context for cancellation
//   - p: Peer ID to authenticate
// Returns:
//   - error: Authentication errors
func (sm *SecurityManager) AuthenticatePeer(ctx context.Context, p peer.ID) error
```

### EstablishSecureConnection() - Create encrypted connection

```go
// EstablishSecureConnection creates an encrypted connection to a peer
// Parameters:
//   - ctx: Context for cancellation
//   - p: Target peer ID
// Returns:
//   - network.Stream: Secure stream
//   - error: Connection errors
func (sm *SecurityManager) EstablishSecureConnection(ctx context.Context, p peer.ID) (network.Stream, error)
```

### RotateKeys() - Perform key rotation

```go
// RotateKeys performs key rotation for all active sessions
// Returns:
//   - error: Rotation errors
func (sm *SecurityManager) RotateKeys() error
```

### VerifyPeerCertificate() - Verify peer certificate

```go
// verifyPeerCertificate performs custom certificate verification
// Parameters:
//   - rawCerts: Raw certificate bytes
//   - verifiedChains: Verified certificate chains
// Returns:
//   - error: Verification errors
func (sm *SecurityManager) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
```

## 5. Configuration

### Configuration Structure

```go
// pkg/security/config.go
package security

import "time"

// DefaultConfig returns production-ready security configuration
func DefaultConfig() *Config {
    return &Config{
        // TLS configuration
        TLSEnabled:     true,
        TLSMinVersion:  tls.VersionTLS13,
        TLSCipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        
        // Noise configuration
        NoiseEnabled: true,
        
        // Key management
        KeyRotationInterval: 24 * time.Hour,
        KeyRotationBytes:    1 << 30, // 1GB
        KeyStorePath:        "/var/lib/blackhole/keys",
        
        // Authentication
        RequireMutualAuth:  true,
        AuthTimeout:        30 * time.Second,
        MaxConcurrentAuths: 100,
        
        // Policy
        EnforcePolicies: true,
        PolicyPath:      "/etc/blackhole/security-policy.yaml",
        
        // Audit
        AuditEnabled:   true,
        AuditPath:      "/var/log/blackhole/security-audit.log",
        AuditRetention: 30 * 24 * time.Hour,
        
        // Session management
        SessionTimeout: 1 * time.Hour,
        MaxSessions:    10000,
    }
}
```

### YAML Configuration Example

```yaml
# config/security.yaml
security:
  # TLS settings
  tls:
    enabled: true
    cert_path: "/etc/blackhole/tls/cert.pem"
    key_path: "/etc/blackhole/tls/key.pem"
    min_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_CHACHA20_POLY1305_SHA256"
  
  # Noise protocol
  noise:
    enabled: true
    pattern: "XX"  # Mutual authentication
  
  # Key management
  keys:
    rotation_interval: 24h
    rotation_bytes: 1073741824  # 1GB
    store_path: "/var/lib/blackhole/keys"
  
  # Authentication
  auth:
    require_mutual: true
    timeout: 30s
    max_concurrent: 100
    max_attempts_per_peer: 5
  
  # Security policies
  policy:
    enforce: true
    path: "/etc/blackhole/security-policy.yaml"
    
  # Audit logging
  audit:
    enabled: true
    path: "/var/log/blackhole/security-audit.log"
    retention: 720h  # 30 days
    max_size: 1GB
    
  # Session management
  session:
    timeout: 1h
    max_sessions: 10000
    cleanup_interval: 5m
```

### Security Policy Example

```yaml
# security-policy.yaml
connection:
  require_mutual_auth: true
  min_tls_version: "1.3"
  allowed_cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
    - "TLS_AES_128_GCM_SHA256"
  rate_limits:
    max_connections_per_peer: 10
    max_connections_per_ip: 50
    connections_per_second: 10
  ip_restrictions:
    allow_private: false
    blocked_ranges:
      - "10.0.0.0/8"
    allowed_ranges:
      - "0.0.0.0/0"

certificate:
  min_key_size: 2048
  max_lifetime: 8760h  # 1 year
  required_attributes:
    O: "Blackhole Network"
  required_extensions:
    - "keyUsage"
    - "extKeyUsage"
  trusted_cas:
    - "/etc/blackhole/ca/root-ca.pem"

encryption:
  min_key_size: 256
  require_pfs: true
  key_rotation_period: 24h
  allowed_algorithms:
    - "AES-256-GCM"
    - "ChaCha20-Poly1305"

access:
  default_action: "allow"
  rules:
    - name: "block-malicious"
      action: "deny"
      peers:
        - "QmMaliciousPeer1"
        - "QmMaliciousPeer2"
    - name: "allow-trusted"
      action: "allow"
      peers:
        - "QmTrustedPeer1"
      priority: 100
```

## 6. Testing Requirements

### Unit Tests

```go
// pkg/security/tests/security_test.go
package security_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/blackhole/pkg/security"
)

func TestMutualAuthentication(t *testing.T) {
    ctx := context.Background()
    
    // Create two security managers
    sm1 := setupTestSecurityManager(t, "peer1")
    defer sm1.Close()
    
    sm2 := setupTestSecurityManager(t, "peer2")
    defer sm2.Close()
    
    // Connect peers
    connectPeers(t, sm1.Host(), sm2.Host())
    
    // Perform mutual authentication
    err := sm1.AuthenticatePeer(ctx, sm2.Host().ID())
    require.NoError(t, err)
    
    err = sm2.AuthenticatePeer(ctx, sm1.Host().ID())
    require.NoError(t, err)
    
    // Verify both peers are authenticated
    info1, err := sm1.GetSecurityInfo(sm2.Host().ID())
    require.NoError(t, err)
    assert.True(t, info1.Authenticated)
    
    info2, err := sm2.GetSecurityInfo(sm1.Host().ID())
    require.NoError(t, err)
    assert.True(t, info2.Authenticated)
}

func TestTLSConnection(t *testing.T) {
    ctx := context.Background()
    
    // Create security managers with TLS
    cfg1 := security.DefaultConfig()
    cfg1.TLSEnabled = true
    cfg1.NoiseEnabled = false
    sm1 := setupTestSecurityManagerWithConfig(t, "peer1", cfg1)
    defer sm1.Close()
    
    cfg2 := security.DefaultConfig()
    cfg2.TLSEnabled = true
    cfg2.NoiseEnabled = false
    sm2 := setupTestSecurityManagerWithConfig(t, "peer2", cfg2)
    defer sm2.Close()
    
    // Connect and authenticate
    connectPeers(t, sm1.Host(), sm2.Host())
    
    // Establish secure connection
    stream, err := sm1.EstablishSecureConnection(ctx, sm2.Host().ID())
    require.NoError(t, err)
    defer stream.Close()
    
    // Verify TLS is used
    assert.Equal(t, security.TLSProtocol, stream.Security())
    
    // Test encrypted communication
    testMsg := []byte("Hello, secure world!")
    _, err = stream.Write(testMsg)
    require.NoError(t, err)
    
    received := make([]byte, len(testMsg))
    _, err = stream.Read(received)
    require.NoError(t, err)
    
    assert.Equal(t, testMsg, received)
}

func TestNoiseConnection(t *testing.T) {
    ctx := context.Background()
    
    // Create security managers with Noise
    cfg1 := security.DefaultConfig()
    cfg1.TLSEnabled = false
    cfg1.NoiseEnabled = true
    sm1 := setupTestSecurityManagerWithConfig(t, "peer1", cfg1)
    defer sm1.Close()
    
    cfg2 := security.DefaultConfig()
    cfg2.TLSEnabled = false
    cfg2.NoiseEnabled = true
    sm2 := setupTestSecurityManagerWithConfig(t, "peer2", cfg2)
    defer sm2.Close()
    
    // Connect and authenticate
    connectPeers(t, sm1.Host(), sm2.Host())
    
    // Establish secure connection
    stream, err := sm1.EstablishSecureConnection(ctx, sm2.Host().ID())
    require.NoError(t, err)
    defer stream.Close()
    
    // Verify Noise is used
    assert.Equal(t, security.NoiseProtocol, stream.Security())
    
    // Test encrypted communication
    testMsg := []byte("Hello, Noise!")
    _, err = stream.Write(testMsg)
    require.NoError(t, err)
    
    received := make([]byte, len(testMsg))
    _, err = stream.Read(received)
    require.NoError(t, err)
    
    assert.Equal(t, testMsg, received)
}

func TestKeyRotation(t *testing.T) {
    ctx := context.Background()
    
    // Create security manager with fast rotation
    cfg := security.DefaultConfig()
    cfg.KeyRotationInterval = 1 * time.Second
    cfg.KeyRotationBytes = 100
    sm := setupTestSecurityManagerWithConfig(t, "peer1", cfg)
    defer sm.Close()
    
    peer2 := setupTestSecurityManager(t, "peer2")
    defer peer2.Close()
    
    // Establish connection
    connectPeers(t, sm.Host(), peer2.Host())
    stream, err := sm.EstablishSecureConnection(ctx, peer2.Host().ID())
    require.NoError(t, err)
    defer stream.Close()
    
    // Get initial session
    info, err := sm.GetSecurityInfo(peer2.Host().ID())
    require.NoError(t, err)
    require.Len(t, info.ActiveSessions, 1)
    initialRotations := info.ActiveSessions[0].KeyRotations
    
    // Wait for rotation
    time.Sleep(2 * time.Second)
    
    // Force rotation
    err = sm.RotateKeys()
    require.NoError(t, err)
    
    // Check rotation occurred
    info, err = sm.GetSecurityInfo(peer2.Host().ID())
    require.NoError(t, err)
    require.Len(t, info.ActiveSessions, 1)
    assert.Greater(t, info.ActiveSessions[0].KeyRotations, initialRotations)
}

func TestBlacklist(t *testing.T) {
    ctx := context.Background()
    
    sm := setupTestSecurityManager(t, "peer1")
    defer sm.Close()
    
    badPeer := setupTestSecurityManager(t, "bad-peer")
    defer badPeer.Close()
    
    // Add peer to blacklist
    sm.Blacklist().Add(badPeer.Host().ID(), 1*time.Hour, "test")
    
    // Try to authenticate - should fail
    err := sm.AuthenticatePeer(ctx, badPeer.Host().ID())
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "blacklisted")
}

func TestPolicyEnforcement(t *testing.T) {
    ctx := context.Background()
    
    // Create security manager with strict policy
    cfg := security.DefaultConfig()
    cfg.EnforcePolicies = true
    sm := setupTestSecurityManagerWithConfig(t, "peer1", cfg)
    defer sm.Close()
    
    // Create peer that violates policy
    peer2 := setupTestSecurityManager(t, "peer2")
    defer peer2.Close()
    
    // Add policy rule to block peer2
    sm.Policy().UpdatePolicy("access.rules", []security.AccessRule{
        {
            Name:   "block-peer2",
            Action: "deny",
            Peers:  []string{peer2.Host().ID().String()},
        },
    })
    
    // Try to establish connection - should fail
    connectPeers(t, sm.Host(), peer2.Host())
    _, err := sm.EstablishSecureConnection(ctx, peer2.Host().ID())
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "policy violation")
}
```

### Integration Tests

```go
// pkg/security/tests/integration_test.go
package security_test

import (
    "context"
    "crypto/rand"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSecureMultiNodeCommunication(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create 5 nodes
    nodes := make([]*security.SecurityManager, 5)
    for i := range nodes {
        nodes[i] = setupTestSecurityManager(t, fmt.Sprintf("node%d", i))
        defer nodes[i].Close()
    }
    
    // Connect all nodes in a mesh
    for i := range nodes {
        for j := i + 1; j < len(nodes); j++ {
            connectPeers(t, nodes[i].Host(), nodes[j].Host())
        }
    }
    
    // Each node authenticates with all others
    for i := range nodes {
        for j := range nodes {
            if i != j {
                err := nodes[i].AuthenticatePeer(ctx, nodes[j].Host().ID())
                require.NoError(t, err)
            }
        }
    }
    
    // Verify all nodes can communicate securely
    testData := make([]byte, 1024)
    rand.Read(testData)
    
    // Node 0 sends to all others
    for i := 1; i < len(nodes); i++ {
        stream, err := nodes[0].EstablishSecureConnection(ctx, nodes[i].Host().ID())
        require.NoError(t, err)
        
        _, err = stream.Write(testData)
        require.NoError(t, err)
        
        stream.Close()
    }
}

func TestMixedProtocolSupport(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    ctx := context.Background()
    
    // Create nodes with different protocols
    tlsNode := setupTestSecurityManagerWithProtocol(t, "tls-node", "tls")
    defer tlsNode.Close()
    
    noiseNode := setupTestSecurityManagerWithProtocol(t, "noise-node", "noise")
    defer noiseNode.Close()
    
    bothNode := setupTestSecurityManagerWithProtocol(t, "both-node", "both")
    defer bothNode.Close()
    
    // Connect all nodes
    connectPeers(t, tlsNode.Host(), bothNode.Host())
    connectPeers(t, noiseNode.Host(), bothNode.Host())
    
    // TLS node connects to both node (should use TLS)
    stream1, err := tlsNode.EstablishSecureConnection(ctx, bothNode.Host().ID())
    require.NoError(t, err)
    assert.Equal(t, security.TLSProtocol, stream1.Security())
    stream1.Close()
    
    // Noise node connects to both node (should use Noise)
    stream2, err := noiseNode.EstablishSecureConnection(ctx, bothNode.Host().ID())
    require.NoError(t, err)
    assert.Equal(t, security.NoiseProtocol, stream2.Security())
    stream2.Close()
}

func TestSecurityUnderLoad(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test")
    }
    
    ctx := context.Background()
    
    // Create two nodes
    node1 := setupTestSecurityManager(t, "load-node1")
    defer node1.Close()
    
    node2 := setupTestSecurityManager(t, "load-node2")
    defer node2.Close()
    
    connectPeers(t, node1.Host(), node2.Host())
    
    // Authenticate once
    err := node1.AuthenticatePeer(ctx, node2.Host().ID())
    require.NoError(t, err)
    
    // Create many concurrent secure connections
    concurrency := 100
    errors := make(chan error, concurrency)
    
    for i := 0; i < concurrency; i++ {
        go func() {
            stream, err := node1.EstablishSecureConnection(ctx, node2.Host().ID())
            if err != nil {
                errors <- err
                return
            }
            
            // Send some data
            data := make([]byte, 1024)
            rand.Read(data)
            
            if _, err := stream.Write(data); err != nil {
                errors <- err
                return
            }
            
            stream.Close()
            errors <- nil
        }()
    }
    
    // Collect results
    successCount := 0
    for i := 0; i < concurrency; i++ {
        err := <-errors
        if err == nil {
            successCount++
        }
    }
    
    // Should handle most connections successfully
    assert.Greater(t, successCount, concurrency*9/10)
}
```

### Performance Benchmarks

```go
// pkg/security/tests/benchmark_test.go
package security_test

import (
    "context"
    "crypto/rand"
    "testing"
)

func BenchmarkTLSHandshake(b *testing.B) {
    ctx := context.Background()
    
    // Setup nodes with TLS
    node1 := setupBenchmarkNode(b, "bench1", "tls")
    defer node1.Close()
    
    node2 := setupBenchmarkNode(b, "bench2", "tls")
    defer node2.Close()
    
    connectPeers(b, node1.Host(), node2.Host())
    
    // Pre-authenticate
    node1.AuthenticatePeer(ctx, node2.Host().ID())
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        stream, err := node1.EstablishSecureConnection(ctx, node2.Host().ID())
        if err != nil {
            b.Fatal(err)
        }
        stream.Close()
    }
}

func BenchmarkNoiseHandshake(b *testing.B) {
    ctx := context.Background()
    
    // Setup nodes with Noise
    node1 := setupBenchmarkNode(b, "bench1", "noise")
    defer node1.Close()
    
    node2 := setupBenchmarkNode(b, "bench2", "noise")
    defer node2.Close()
    
    connectPeers(b, node1.Host(), node2.Host())
    
    // Pre-authenticate
    node1.AuthenticatePeer(ctx, node2.Host().ID())
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        stream, err := node1.EstablishSecureConnection(ctx, node2.Host().ID())
        if err != nil {
            b.Fatal(err)
        }
        stream.Close()
    }
}

func BenchmarkEncryptedThroughput(b *testing.B) {
    sizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB
    
    for _, size := range sizes {
        b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
            ctx := context.Background()
            
            node1 := setupBenchmarkNode(b, "bench1", "tls")
            defer node1.Close()
            
            node2 := setupBenchmarkNode(b, "bench2", "tls")
            defer node2.Close()
            
            connectPeers(b, node1.Host(), node2.Host())
            
            stream, _ := node1.EstablishSecureConnection(ctx, node2.Host().ID())
            defer stream.Close()
            
            data := make([]byte, size)
            rand.Read(data)
            
            b.SetBytes(int64(size))
            b.ResetTimer()
            
            for i := 0; i < b.N; i++ {
                if _, err := stream.Write(data); err != nil {
                    b.Fatal(err)
                }
            }
        })
    }
}

func BenchmarkAuthentication(b *testing.B) {
    ctx := context.Background()
    
    node1 := setupBenchmarkNode(b, "bench1", "both")
    defer node1.Close()
    
    // Create many peers
    peers := make([]*security.SecurityManager, 100)
    for i := range peers {
        peers[i] = setupBenchmarkNode(b, fmt.Sprintf("peer%d", i), "both")
        defer peers[i].Close()
        connectPeers(b, node1.Host(), peers[i].Host())
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        peer := peers[i%len(peers)]
        if err := node1.AuthenticatePeer(ctx, peer.Host().ID()); err != nil {
            b.Fatal(err)
        }
    }
}
```

## 7. Monitoring & Metrics

### Security Metrics

```go
// pkg/security/metrics.go
package security

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

// SecurityMetrics tracks security-related metrics
type SecurityMetrics struct {
    // Authentication metrics
    AuthAttempts       prometheus.Counter
    AuthSuccesses      prometheus.Counter
    AuthFailures       prometheus.Counter
    AuthDuration       prometheus.Histogram
    AuthenticatedPeers prometheus.Gauge
    
    // Connection metrics
    SecureConnections  prometheus.Counter
    ActiveSessions     prometheus.Gauge
    
    // Protocol metrics
    TLSHandshakes      prometheus.Counter
    NoiseHandshakes    prometheus.Counter
    CipherSuites       *prometheus.CounterVec
    
    // Key management metrics
    KeyRotations       prometheus.Counter
    KeyRotationErrors  prometheus.Counter
    
    // Policy metrics
    PolicyViolations   prometheus.Counter
    PolicyEvaluations  prometheus.Counter
    
    // Blacklist metrics
    BlacklistedPeers   prometheus.Gauge
    BlacklistHits      prometheus.Counter
    
    // Error metrics
    SecurityErrors     *prometheus.CounterVec
}

// NewSecurityMetrics creates security metrics
func NewSecurityMetrics() *SecurityMetrics {
    return &SecurityMetrics{
        AuthAttempts: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_auth_attempts_total",
            Help: "Total authentication attempts",
        }),
        
        AuthSuccesses: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_auth_successes_total",
            Help: "Successful authentications",
        }),
        
        AuthFailures: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_auth_failures_total",
            Help: "Failed authentications",
        }),
        
        AuthDuration: promauto.NewHistogram(prometheus.HistogramOpts{
            Name:    "blackhole_security_auth_duration_seconds",
            Help:    "Authentication duration",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
        }),
        
        AuthenticatedPeers: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_security_authenticated_peers",
            Help: "Number of authenticated peers",
        }),
        
        SecureConnections: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_connections_total",
            Help: "Total secure connections established",
        }),
        
        ActiveSessions: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_security_active_sessions",
            Help: "Number of active secure sessions",
        }),
        
        TLSHandshakes: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_tls_handshakes_total",
            Help: "Total TLS handshakes",
        }),
        
        NoiseHandshakes: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_noise_handshakes_total",
            Help: "Total Noise handshakes",
        }),
        
        CipherSuites: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_security_cipher_suites_total",
            Help: "Cipher suites used",
        }, []string{"suite"}),
        
        KeyRotations: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_key_rotations_total",
            Help: "Total key rotations",
        }),
        
        KeyRotationErrors: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_key_rotation_errors_total",
            Help: "Key rotation errors",
        }),
        
        PolicyViolations: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_policy_violations_total",
            Help: "Security policy violations",
        }),
        
        PolicyEvaluations: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_policy_evaluations_total",
            Help: "Policy evaluations performed",
        }),
        
        BlacklistedPeers: promauto.NewGauge(prometheus.GaugeOpts{
            Name: "blackhole_security_blacklisted_peers",
            Help: "Number of blacklisted peers",
        }),
        
        BlacklistHits: promauto.NewCounter(prometheus.CounterOpts{
            Name: "blackhole_security_blacklist_hits_total",
            Help: "Blacklist matches",
        }),
        
        SecurityErrors: promauto.NewCounterVec(prometheus.CounterOpts{
            Name: "blackhole_security_errors_total",
            Help: "Security errors by type",
        }, []string{"error_type"}),
    }
}
```

### Monitoring Dashboard

```yaml
# Grafana dashboard configuration
panels:
  - title: "Authentication Success Rate"
    query: |
      rate(blackhole_security_auth_successes_total[5m]) /
      rate(blackhole_security_auth_attempts_total[5m])
      
  - title: "Active Secure Sessions"
    query: "blackhole_security_active_sessions"
    
  - title: "Protocol Usage"
    queries:
      - "rate(blackhole_security_tls_handshakes_total[5m])"
      - "rate(blackhole_security_noise_handshakes_total[5m])"
      
  - title: "Cipher Suite Distribution"
    query: "rate(blackhole_security_cipher_suites_total[5m])"
    legend: "{{suite}}"
    
  - title: "Key Rotation Activity"
    query: "rate(blackhole_security_key_rotations_total[1h])"
    
  - title: "Security Violations"
    queries:
      - "rate(blackhole_security_policy_violations_total[5m])"
      - "rate(blackhole_security_blacklist_hits_total[5m])"
      
  - title: "Authentication Latency"
    query: |
      histogram_quantile(0.95,
        rate(blackhole_security_auth_duration_seconds_bucket[5m])
      )
```

## 8. Error Handling

### Error Types

```go
// pkg/security/errors.go
package security

import "errors"

var (
    // Authentication errors
    ErrAuthenticationFailed = errors.New("authentication failed")
    ErrPeerNotAuthenticated = errors.New("peer not authenticated")
    ErrAuthTimeout          = errors.New("authentication timeout")
    ErrAuthRateLimited      = errors.New("authentication rate limited")
    ErrPeerIDMismatch       = errors.New("peer ID mismatch")
    
    // Certificate errors
    ErrNoCertificate        = errors.New("no certificate provided")
    ErrInvalidCertificate   = errors.New("invalid certificate")
    ErrCertificateExpired   = errors.New("certificate expired")
    ErrCertificateRevoked   = errors.New("certificate revoked")
    
    // Connection errors
    ErrConnectionRefused    = errors.New("connection refused")
    ErrHandshakeFailed      = errors.New("handshake failed")
    ErrHandshakeIncomplete  = errors.New("handshake incomplete")
    ErrProtocolMismatch     = errors.New("security protocol mismatch")
    
    // Policy errors
    ErrPolicyViolation      = errors.New("security policy violation")
    ErrPeerBlacklisted      = errors.New("peer is blacklisted")
    ErrPeerDenied           = errors.New("peer access denied")
    
    // Key management errors
    ErrKeyRotationFailed    = errors.New("key rotation failed")
    ErrKeyGenerationFailed  = errors.New("key generation failed")
    ErrKeyStorageError      = errors.New("key storage error")
)
```

## 9. Acceptance Criteria

### Functional Requirements

1. **Transport Security**
   - [ ] TLS 1.3 implementation working
   - [ ] Noise protocol implementation working
   - [ ] Protocol negotiation functional
   - [ ] All connections encrypted

2. **Authentication**
   - [ ] Mutual authentication enforced
   - [ ] Peer identity verification working
   - [ ] Certificate validation functional
   - [ ] Authentication timeout enforced

3. **Key Management**
   - [ ] Key generation secure
   - [ ] Key rotation working
   - [ ] Key storage encrypted
   - [ ] Perfect forward secrecy enabled

4. **Policy Enforcement**
   - [ ] Connection policies enforced
   - [ ] Certificate policies validated
   - [ ] Blacklist functioning
   - [ ] Audit logging operational

### Performance Requirements

1. **Handshake Performance**
   - TLS handshake: < 50ms
   - Noise handshake: < 30ms
   - Authentication: < 100ms

2. **Throughput**
   - Encryption overhead: < 5%
   - 100MB/s+ encrypted throughput
   - Minimal CPU impact

3. **Scalability**
   - Support 10,000+ secure connections
   - Handle 100+ auth/second
   - Efficient session management

## 10. Example Usage

### Setting Up Secure Host

```go
package main

import (
    "context"
    "log"
    
    "github.com/blackhole/pkg/network"
    "github.com/blackhole/pkg/security"
)

func main() {
    // Create libp2p host
    host, err := network.NewHost(context.Background(), network.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    
    // Create security manager
    secConfig := security.DefaultConfig()
    secConfig.TLSEnabled = true
    secConfig.NoiseEnabled = true
    secConfig.RequireMutualAuth = true
    
    secMgr, err := security.NewSecurityManager(host, secConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer secMgr.Close()
    
    // Start host
    if err := host.Start(); err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Secure host running: %s", host.ID())
    
    // Accept secure connections
    host.SetStreamHandler("/blackhole/secure/1.0.0", func(stream network.Stream) {
        defer stream.Close()
        
        // Verify peer is authenticated
        peerID := stream.Conn().RemotePeer()
        if err := secMgr.AuthenticatePeer(context.Background(), peerID); err != nil {
            log.Printf("Authentication failed for %s: %v", peerID, err)
            return
        }
        
        // Handle secure communication
        log.Printf("Secure connection from %s", peerID)
        // ... handle stream
    })
    
    select {}
}
```

### Establishing Secure Connection

```go
package main

import (
    "context"
    "fmt"
    "log"
    
    "github.com/libp2p/go-libp2p/core/peer"
)

func connectSecurely(secMgr *security.SecurityManager, targetPeer string) error {
    // Parse peer ID
    peerID, err := peer.Decode(targetPeer)
    if err != nil {
        return fmt.Errorf("invalid peer ID: %w", err)
    }
    
    ctx := context.Background()
    
    // Authenticate peer
    log.Printf("Authenticating %s...", peerID)
    if err := secMgr.AuthenticatePeer(ctx, peerID); err != nil {
        return fmt.Errorf("authentication failed: %w", err)
    }
    
    // Establish secure connection
    log.Printf("Establishing secure connection...")
    stream, err := secMgr.EstablishSecureConnection(ctx, peerID)
    if err != nil {
        return fmt.Errorf("connection failed: %w", err)
    }
    defer stream.Close()
    
    // Get security info
    info, err := secMgr.GetSecurityInfo(peerID)
    if err != nil {
        return err
    }
    
    log.Printf("Connected securely to %s", peerID)
    log.Printf("Protocol: %s", stream.Security())
    log.Printf("Auth time: %v", info.AuthTime)
    
    // Send encrypted message
    msg := []byte("Hello, secure peer!")
    if _, err := stream.Write(msg); err != nil {
        return fmt.Errorf("write failed: %w", err)
    }
    
    log.Printf("Sent encrypted message")
    
    return nil
}
```

## Summary

Unit U07 implements comprehensive network security for the Blackhole platform, providing multiple layers of protection including transport encryption, mutual authentication, and policy enforcement. The implementation supports both TLS 1.3 and Noise Protocol, allowing flexibility in security protocol selection while maintaining strong security guarantees.

Key achievements:
- Modern cryptographic protocols (TLS 1.3, Noise)
- Mutual authentication with identity verification
- Perfect forward secrecy for all connections
- Flexible security policy engine
- Comprehensive audit logging
- Automatic key rotation
- Blacklist and rate limiting protection
- Production-ready monitoring and metrics

This unit ensures that all network communications in the Blackhole platform are secure, authenticated, and protected against various attack vectors.