# U21: WebAuthn Authentication

## Overview
WebAuthn/passkey authentication implementation for BlackHole, providing passwordless login with biometric support, device registration, and secure authentication flows.

## Implementation

### Core WebAuthn Types

```go
package webauthn

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "time"
)

// Credential represents a WebAuthn credential
type Credential struct {
    ID              []byte    `json:"id"`
    PublicKey       []byte    `json:"publicKey"`
    AttestationType string    `json:"attestationType"`
    Transport       []string  `json:"transport"`
    Flags           AuthFlags `json:"flags"`
    Authenticator   AAGUID    `json:"authenticator"`
    CreatedAt       time.Time `json:"createdAt"`
    LastUsedAt      time.Time `json:"lastUsedAt"`
    SignCount       uint32    `json:"signCount"`
}

// User represents a WebAuthn user
type User struct {
    ID          []byte       `json:"id"`
    Name        string       `json:"name"`
    DisplayName string       `json:"displayName"`
    Icon        string       `json:"icon,omitempty"`
    Credentials []Credential `json:"credentials"`
}

// AuthFlags represents authenticator flags
type AuthFlags struct {
    UserPresent    bool `json:"userPresent"`
    UserVerified   bool `json:"userVerified"`
    BackupEligible bool `json:"backupEligible"`
    BackupState    bool `json:"backupState"`
}

// AAGUID represents Authenticator Attestation GUID
type AAGUID [16]byte

// PublicKeyCredentialCreationOptions for registration
type PublicKeyCredentialCreationOptions struct {
    Challenge                []byte                    `json:"challenge"`
    RP                       RelyingPartyEntity        `json:"rp"`
    User                     UserEntity                `json:"user"`
    PubKeyCredParams         []PublicKeyCredParam      `json:"pubKeyCredParams"`
    Timeout                  uint32                    `json:"timeout,omitempty"`
    ExcludeCredentials       []PublicKeyCredDescriptor `json:"excludeCredentials,omitempty"`
    AuthenticatorSelection   *AuthenticatorSelection   `json:"authenticatorSelection,omitempty"`
    Attestation              AttestationConveyance     `json:"attestation,omitempty"`
    Extensions               map[string]interface{}    `json:"extensions,omitempty"`
}

// PublicKeyCredentialRequestOptions for authentication
type PublicKeyCredentialRequestOptions struct {
    Challenge          []byte                    `json:"challenge"`
    Timeout            uint32                    `json:"timeout,omitempty"`
    RPID               string                    `json:"rpId,omitempty"`
    AllowCredentials   []PublicKeyCredDescriptor `json:"allowCredentials,omitempty"`
    UserVerification   UserVerificationRequirement `json:"userVerification,omitempty"`
    Extensions         map[string]interface{}    `json:"extensions,omitempty"`
}

// RelyingPartyEntity represents the relying party
type RelyingPartyEntity struct {
    ID   string `json:"id"`
    Name string `json:"name"`
    Icon string `json:"icon,omitempty"`
}

// UserEntity represents user information
type UserEntity struct {
    ID          []byte `json:"id"`
    Name        string `json:"name"`
    DisplayName string `json:"displayName"`
    Icon        string `json:"icon,omitempty"`
}

// PublicKeyCredParam specifies credential parameters
type PublicKeyCredParam struct {
    Type string `json:"type"`
    Alg  int32  `json:"alg"`
}

// PublicKeyCredDescriptor describes a credential
type PublicKeyCredDescriptor struct {
    Type       string   `json:"type"`
    ID         []byte   `json:"id"`
    Transports []string `json:"transports,omitempty"`
}

// AuthenticatorSelection criteria
type AuthenticatorSelection struct {
    AuthenticatorAttachment AuthenticatorAttachment `json:"authenticatorAttachment,omitempty"`
    RequireResidentKey      bool                    `json:"requireResidentKey,omitempty"`
    ResidentKey             ResidentKeyRequirement  `json:"residentKey,omitempty"`
    UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`
}

// Enums
type AttestationConveyance string
type AuthenticatorAttachment string
type ResidentKeyRequirement string
type UserVerificationRequirement string

const (
    AttestationNone     AttestationConveyance = "none"
    AttestationIndirect AttestationConveyance = "indirect"
    AttestationDirect   AttestationConveyance = "direct"

    AttachmentPlatform     AuthenticatorAttachment = "platform"
    AttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"

    ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
    ResidentKeyPreferred   ResidentKeyRequirement = "preferred"
    ResidentKeyRequired    ResidentKeyRequirement = "required"

    VerificationRequired    UserVerificationRequirement = "required"
    VerificationPreferred   UserVerificationRequirement = "preferred"
    VerificationDiscouraged UserVerificationRequirement = "discouraged"
)
```

### WebAuthn Server Implementation

```go
package webauthn

import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "sync"
)

// Server handles WebAuthn operations
type Server struct {
    mu         sync.RWMutex
    config     *Config
    users      UserStore
    sessions   SessionStore
    challenges ChallengeStore
}

// Config holds WebAuthn configuration
type Config struct {
    RPID                    string
    RPName                  string
    RPIcon                  string
    Timeout                 uint32
    AuthenticatorAttachment AuthenticatorAttachment
    ResidentKey             ResidentKeyRequirement
    UserVerification        UserVerificationRequirement
    Attestation             AttestationConveyance
}

// UserStore interface for user persistence
type UserStore interface {
    GetUser(userID []byte) (*User, error)
    GetUserByName(username string) (*User, error)
    CreateUser(user *User) error
    UpdateUser(user *User) error
    AddCredential(userID []byte, credential *Credential) error
    GetCredential(credentialID []byte) (*Credential, error)
    UpdateCredential(credential *Credential) error
}

// SessionStore interface for session management
type SessionStore interface {
    CreateSession(userID []byte, sessionID string) error
    GetSession(sessionID string) ([]byte, error)
    DeleteSession(sessionID string) error
}

// ChallengeStore interface for challenge management
type ChallengeStore interface {
    StoreChallenge(challenge []byte, data interface{}) error
    GetChallenge(challenge []byte) (interface{}, error)
    DeleteChallenge(challenge []byte) error
}

// NewServer creates a new WebAuthn server
func NewServer(config *Config, users UserStore, sessions SessionStore, challenges ChallengeStore) *Server {
    return &Server{
        config:     config,
        users:      users,
        sessions:   sessions,
        challenges: challenges,
    }
}

// BeginRegistration starts the registration process
func (s *Server) BeginRegistration(username, displayName string, userID []byte) (*PublicKeyCredentialCreationOptions, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Check if user exists
    existingUser, _ := s.users.GetUserByName(username)
    if existingUser != nil {
        return nil, fmt.Errorf("user already exists")
    }

    // Generate challenge
    challenge := make([]byte, 32)
    if _, err := rand.Read(challenge); err != nil {
        return nil, fmt.Errorf("failed to generate challenge: %w", err)
    }

    // Create user entity
    user := &UserEntity{
        ID:          userID,
        Name:        username,
        DisplayName: displayName,
    }

    // Create options
    options := &PublicKeyCredentialCreationOptions{
        Challenge: challenge,
        RP: RelyingPartyEntity{
            ID:   s.config.RPID,
            Name: s.config.RPName,
            Icon: s.config.RPIcon,
        },
        User: *user,
        PubKeyCredParams: []PublicKeyCredParam{
            {Type: "public-key", Alg: -7},  // ES256
            {Type: "public-key", Alg: -257}, // RS256
        },
        Timeout: s.config.Timeout,
        AuthenticatorSelection: &AuthenticatorSelection{
            AuthenticatorAttachment: s.config.AuthenticatorAttachment,
            ResidentKey:             s.config.ResidentKey,
            UserVerification:        s.config.UserVerification,
        },
        Attestation: s.config.Attestation,
    }

    // Store challenge data
    challengeData := map[string]interface{}{
        "user":      user,
        "operation": "registration",
    }
    if err := s.challenges.StoreChallenge(challenge, challengeData); err != nil {
        return nil, fmt.Errorf("failed to store challenge: %w", err)
    }

    return options, nil
}

// FinishRegistration completes the registration process
func (s *Server) FinishRegistration(response *RegistrationResponse) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Verify challenge
    challengeData, err := s.challenges.GetChallenge(response.Response.ClientDataJSON.Challenge)
    if err != nil {
        return fmt.Errorf("invalid challenge")
    }

    data := challengeData.(map[string]interface{})
    if data["operation"] != "registration" {
        return fmt.Errorf("invalid operation")
    }

    userEntity := data["user"].(*UserEntity)

    // Verify origin
    if response.Response.ClientDataJSON.Origin != s.getOrigin() {
        return fmt.Errorf("invalid origin")
    }

    // Verify RP ID hash
    rpIDHash := sha256.Sum256([]byte(s.config.RPID))
    if !bytes.Equal(response.Response.AttestationObject.AuthData.RPIDHash[:], rpIDHash[:]) {
        return fmt.Errorf("invalid RP ID")
    }

    // Parse credential
    credential := &Credential{
        ID:              response.RawID,
        PublicKey:       response.Response.AttestationObject.AuthData.AttestedCredentialData.PublicKey,
        AttestationType: response.Response.AttestationObject.Format,
        Flags:           response.Response.AttestationObject.AuthData.Flags,
        SignCount:       response.Response.AttestationObject.AuthData.SignCount,
        CreatedAt:       time.Now(),
        LastUsedAt:      time.Now(),
    }

    // Create or update user
    user := &User{
        ID:          userEntity.ID,
        Name:        userEntity.Name,
        DisplayName: userEntity.DisplayName,
        Credentials: []Credential{*credential},
    }

    if err := s.users.CreateUser(user); err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }

    // Clean up challenge
    s.challenges.DeleteChallenge(response.Response.ClientDataJSON.Challenge)

    return nil
}

// BeginLogin starts the authentication process
func (s *Server) BeginLogin(username string) (*PublicKeyCredentialRequestOptions, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    var allowCredentials []PublicKeyCredDescriptor

    if username != "" {
        // Get user credentials
        user, err := s.users.GetUserByName(username)
        if err != nil {
            return nil, fmt.Errorf("user not found")
        }

        for _, cred := range user.Credentials {
            allowCredentials = append(allowCredentials, PublicKeyCredDescriptor{
                Type:       "public-key",
                ID:         cred.ID,
                Transports: cred.Transport,
            })
        }
    }

    // Generate challenge
    challenge := make([]byte, 32)
    if _, err := rand.Read(challenge); err != nil {
        return nil, fmt.Errorf("failed to generate challenge: %w", err)
    }

    options := &PublicKeyCredentialRequestOptions{
        Challenge:        challenge,
        Timeout:          s.config.Timeout,
        RPID:             s.config.RPID,
        AllowCredentials: allowCredentials,
        UserVerification: s.config.UserVerification,
    }

    // Store challenge data
    challengeData := map[string]interface{}{
        "operation": "authentication",
        "username":  username,
    }
    if err := s.challenges.StoreChallenge(challenge, challengeData); err != nil {
        return nil, fmt.Errorf("failed to store challenge: %w", err)
    }

    return options, nil
}

// FinishLogin completes the authentication process
func (s *Server) FinishLogin(response *AuthenticationResponse) (string, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Verify challenge
    challengeData, err := s.challenges.GetChallenge(response.Response.ClientDataJSON.Challenge)
    if err != nil {
        return "", fmt.Errorf("invalid challenge")
    }

    data := challengeData.(map[string]interface{})
    if data["operation"] != "authentication" {
        return "", fmt.Errorf("invalid operation")
    }

    // Get credential
    credential, err := s.users.GetCredential(response.RawID)
    if err != nil {
        return "", fmt.Errorf("credential not found")
    }

    // Verify origin
    if response.Response.ClientDataJSON.Origin != s.getOrigin() {
        return "", fmt.Errorf("invalid origin")
    }

    // Verify signature
    if err := s.verifyAssertion(credential, response); err != nil {
        return "", fmt.Errorf("signature verification failed: %w", err)
    }

    // Update credential
    credential.LastUsedAt = time.Now()
    credential.SignCount = response.Response.AuthenticatorData.SignCount
    if err := s.users.UpdateCredential(credential); err != nil {
        return "", fmt.Errorf("failed to update credential: %w", err)
    }

    // Create session
    sessionID := generateSessionID()
    user, err := s.users.GetUser(response.Response.UserHandle)
    if err != nil {
        return "", fmt.Errorf("user not found")
    }

    if err := s.sessions.CreateSession(user.ID, sessionID); err != nil {
        return "", fmt.Errorf("failed to create session: %w", err)
    }

    // Clean up challenge
    s.challenges.DeleteChallenge(response.Response.ClientDataJSON.Challenge)

    return sessionID, nil
}

// getOrigin returns the expected origin
func (s *Server) getOrigin() string {
    return fmt.Sprintf("https://%s", s.config.RPID)
}

// generateSessionID generates a random session ID
func generateSessionID() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}
```

### Response Types

```go
package webauthn

// RegistrationResponse from the client
type RegistrationResponse struct {
    ID       string                        `json:"id"`
    RawID    []byte                        `json:"rawId"`
    Type     string                        `json:"type"`
    Response AuthenticatorAttestationResponse `json:"response"`
}

// AuthenticatorAttestationResponse contains attestation data
type AuthenticatorAttestationResponse struct {
    ClientDataJSON    ClientDataJSON    `json:"clientDataJSON"`
    AttestationObject AttestationObject `json:"attestationObject"`
}

// AuthenticationResponse from the client
type AuthenticationResponse struct {
    ID       string                       `json:"id"`
    RawID    []byte                       `json:"rawId"`
    Type     string                       `json:"type"`
    Response AuthenticatorAssertionResponse `json:"response"`
}

// AuthenticatorAssertionResponse contains assertion data
type AuthenticatorAssertionResponse struct {
    ClientDataJSON    ClientDataJSON    `json:"clientDataJSON"`
    AuthenticatorData AuthenticatorData `json:"authenticatorData"`
    Signature         []byte            `json:"signature"`
    UserHandle        []byte            `json:"userHandle"`
}

// ClientDataJSON represents client data
type ClientDataJSON struct {
    Type         string `json:"type"`
    Challenge    []byte `json:"challenge"`
    Origin       string `json:"origin"`
    CrossOrigin  bool   `json:"crossOrigin"`
    TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`
}

// TokenBinding information
type TokenBinding struct {
    Status string `json:"status"`
    ID     string `json:"id,omitempty"`
}

// AttestationObject contains attestation data
type AttestationObject struct {
    Format    string          `json:"fmt"`
    AuthData  AuthenticatorData `json:"authData"`
    AttStmt   json.RawMessage `json:"attStmt"`
}

// AuthenticatorData contains authenticator data
type AuthenticatorData struct {
    RPIDHash               [32]byte                `json:"rpIdHash"`
    Flags                  AuthFlags               `json:"flags"`
    SignCount              uint32                  `json:"signCount"`
    AttestedCredentialData *AttestedCredentialData `json:"attestedCredentialData,omitempty"`
    Extensions             []byte                  `json:"extensions,omitempty"`
}

// AttestedCredentialData contains credential data
type AttestedCredentialData struct {
    AAGUID              AAGUID `json:"aaguid"`
    CredentialID        []byte `json:"credentialId"`
    CredentialPublicKey []byte `json:"credentialPublicKey"`
}
```

### Signature Verification

```go
package webauthn

import (
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/asn1"
    "fmt"
    "math/big"
)

// verifyAssertion verifies the assertion signature
func (s *Server) verifyAssertion(credential *Credential, response *AuthenticationResponse) error {
    // Parse public key
    publicKey, err := parsePublicKey(credential.PublicKey)
    if err != nil {
        return fmt.Errorf("failed to parse public key: %w", err)
    }

    // Create verification data
    clientDataHash := sha256.Sum256(response.Response.ClientDataJSON.Marshal())
    authData := response.Response.AuthenticatorData.Marshal()
    
    verificationData := append(authData, clientDataHash[:]...)

    // Verify signature based on key type
    switch key := publicKey.(type) {
    case *ecdsa.PublicKey:
        return verifyECDSASignature(key, verificationData, response.Response.Signature)
    case *rsa.PublicKey:
        return verifyRSASignature(key, verificationData, response.Response.Signature)
    default:
        return fmt.Errorf("unsupported key type")
    }
}

// parsePublicKey parses a COSE public key
func parsePublicKey(keyData []byte) (crypto.PublicKey, error) {
    // Parse COSE key format
    var coseKey map[int]interface{}
    if err := decodeCBOR(keyData, &coseKey); err != nil {
        return nil, fmt.Errorf("failed to decode COSE key: %w", err)
    }

    kty, ok := coseKey[1].(int)
    if !ok {
        return nil, fmt.Errorf("missing key type")
    }

    switch kty {
    case 2: // EC2 key
        return parseEC2Key(coseKey)
    case 3: // RSA key
        return parseRSAKey(coseKey)
    default:
        return nil, fmt.Errorf("unsupported key type: %d", kty)
    }
}

// parseEC2Key parses an EC2 COSE key
func parseEC2Key(coseKey map[int]interface{}) (*ecdsa.PublicKey, error) {
    // Get curve
    crv, ok := coseKey[-1].(int)
    if !ok {
        return nil, fmt.Errorf("missing curve")
    }

    var curve elliptic.Curve
    switch crv {
    case 1: // P-256
        curve = elliptic.P256()
    case 2: // P-384
        curve = elliptic.P384()
    case 3: // P-521
        curve = elliptic.P521()
    default:
        return nil, fmt.Errorf("unsupported curve: %d", crv)
    }

    // Get coordinates
    xBytes, ok := coseKey[-2].([]byte)
    if !ok {
        return nil, fmt.Errorf("missing x coordinate")
    }

    yBytes, ok := coseKey[-3].([]byte)
    if !ok {
        return nil, fmt.Errorf("missing y coordinate")
    }

    x := new(big.Int).SetBytes(xBytes)
    y := new(big.Int).SetBytes(yBytes)

    return &ecdsa.PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }, nil
}

// parseRSAKey parses an RSA COSE key
func parseRSAKey(coseKey map[int]interface{}) (*rsa.PublicKey, error) {
    // Get modulus
    nBytes, ok := coseKey[-1].([]byte)
    if !ok {
        return nil, fmt.Errorf("missing modulus")
    }

    // Get exponent
    eBytes, ok := coseKey[-2].([]byte)
    if !ok {
        return nil, fmt.Errorf("missing exponent")
    }

    n := new(big.Int).SetBytes(nBytes)
    e := new(big.Int).SetBytes(eBytes)

    return &rsa.PublicKey{
        N: n,
        E: int(e.Int64()),
    }, nil
}

// verifyECDSASignature verifies an ECDSA signature
func verifyECDSASignature(publicKey *ecdsa.PublicKey, data, signature []byte) error {
    // Parse ASN.1 signature
    var sig struct {
        R, S *big.Int
    }
    if _, err := asn1.Unmarshal(signature, &sig); err != nil {
        return fmt.Errorf("failed to parse signature: %w", err)
    }

    hash := sha256.Sum256(data)
    if !ecdsa.Verify(publicKey, hash[:], sig.R, sig.S) {
        return fmt.Errorf("signature verification failed")
    }

    return nil
}

// verifyRSASignature verifies an RSA signature
func verifyRSASignature(publicKey *rsa.PublicKey, data, signature []byte) error {
    hash := sha256.Sum256(data)
    if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
        return fmt.Errorf("signature verification failed: %w", err)
    }
    return nil
}
```

### Device Registration Manager

```go
package webauthn

import (
    "fmt"
    "sync"
    "time"
)

// DeviceManager manages device registrations
type DeviceManager struct {
    mu      sync.RWMutex
    devices map[string]*Device
    store   DeviceStore
}

// Device represents a registered device
type Device struct {
    ID           string    `json:"id"`
    UserID       []byte    `json:"userId"`
    Name         string    `json:"name"`
    Type         string    `json:"type"`
    Platform     string    `json:"platform"`
    CredentialID []byte    `json:"credentialId"`
    RegisteredAt time.Time `json:"registeredAt"`
    LastSeenAt   time.Time `json:"lastSeenAt"`
    TrustScore   int       `json:"trustScore"`
}

// DeviceStore interface for device persistence
type DeviceStore interface {
    StoreDevice(device *Device) error
    GetDevice(deviceID string) (*Device, error)
    GetUserDevices(userID []byte) ([]*Device, error)
    UpdateDevice(device *Device) error
    DeleteDevice(deviceID string) error
}

// NewDeviceManager creates a new device manager
func NewDeviceManager(store DeviceStore) *DeviceManager {
    return &DeviceManager{
        devices: make(map[string]*Device),
        store:   store,
    }
}

// RegisterDevice registers a new device
func (dm *DeviceManager) RegisterDevice(userID []byte, name, platform string, credentialID []byte) (*Device, error) {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    device := &Device{
        ID:           generateDeviceID(),
        UserID:       userID,
        Name:         name,
        Platform:     platform,
        CredentialID: credentialID,
        RegisteredAt: time.Now(),
        LastSeenAt:   time.Now(),
        TrustScore:   50, // Start with medium trust
    }

    if err := dm.store.StoreDevice(device); err != nil {
        return nil, fmt.Errorf("failed to store device: %w", err)
    }

    dm.devices[device.ID] = device
    return device, nil
}

// UpdateDeviceTrust updates device trust score
func (dm *DeviceManager) UpdateDeviceTrust(deviceID string, delta int) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    device, exists := dm.devices[deviceID]
    if !exists {
        var err error
        device, err = dm.store.GetDevice(deviceID)
        if err != nil {
            return fmt.Errorf("device not found")
        }
    }

    device.TrustScore += delta
    if device.TrustScore > 100 {
        device.TrustScore = 100
    } else if device.TrustScore < 0 {
        device.TrustScore = 0
    }

    device.LastSeenAt = time.Now()

    if err := dm.store.UpdateDevice(device); err != nil {
        return fmt.Errorf("failed to update device: %w", err)
    }

    return nil
}

// GetUserDevices returns all devices for a user
func (dm *DeviceManager) GetUserDevices(userID []byte) ([]*Device, error) {
    return dm.store.GetUserDevices(userID)
}

// RemoveDevice removes a device
func (dm *DeviceManager) RemoveDevice(deviceID string) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    delete(dm.devices, deviceID)
    return dm.store.DeleteDevice(deviceID)
}

// generateDeviceID generates a unique device ID
func generateDeviceID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}
```

### Storage Implementation

```go
package webauthn

import (
    "encoding/json"
    "fmt"
    "sync"
    "time"
)

// MemoryUserStore implements in-memory user storage
type MemoryUserStore struct {
    mu          sync.RWMutex
    users       map[string]*User
    usersByName map[string]*User
    credentials map[string]*Credential
}

// NewMemoryUserStore creates a new memory user store
func NewMemoryUserStore() *MemoryUserStore {
    return &MemoryUserStore{
        users:       make(map[string]*User),
        usersByName: make(map[string]*User),
        credentials: make(map[string]*Credential),
    }
}

func (s *MemoryUserStore) GetUser(userID []byte) (*User, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    user, exists := s.users[string(userID)]
    if !exists {
        return nil, fmt.Errorf("user not found")
    }
    return user, nil
}

func (s *MemoryUserStore) GetUserByName(username string) (*User, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    user, exists := s.usersByName[username]
    if !exists {
        return nil, fmt.Errorf("user not found")
    }
    return user, nil
}

func (s *MemoryUserStore) CreateUser(user *User) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.users[string(user.ID)] = user
    s.usersByName[user.Name] = user

    // Store credentials
    for i := range user.Credentials {
        s.credentials[string(user.Credentials[i].ID)] = &user.Credentials[i]
    }

    return nil
}

func (s *MemoryUserStore) UpdateUser(user *User) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.users[string(user.ID)] = user
    s.usersByName[user.Name] = user
    return nil
}

func (s *MemoryUserStore) AddCredential(userID []byte, credential *Credential) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    user, exists := s.users[string(userID)]
    if !exists {
        return fmt.Errorf("user not found")
    }

    user.Credentials = append(user.Credentials, *credential)
    s.credentials[string(credential.ID)] = credential

    return nil
}

func (s *MemoryUserStore) GetCredential(credentialID []byte) (*Credential, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    credential, exists := s.credentials[string(credentialID)]
    if !exists {
        return nil, fmt.Errorf("credential not found")
    }
    return credential, nil
}

func (s *MemoryUserStore) UpdateCredential(credential *Credential) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.credentials[string(credential.ID)] = credential
    return nil
}

// MemoryChallengeStore implements in-memory challenge storage
type MemoryChallengeStore struct {
    mu         sync.RWMutex
    challenges map[string]*challengeEntry
}

type challengeEntry struct {
    data      interface{}
    expiresAt time.Time
}

// NewMemoryChallengeStore creates a new memory challenge store
func NewMemoryChallengeStore() *MemoryChallengeStore {
    store := &MemoryChallengeStore{
        challenges: make(map[string]*challengeEntry),
    }
    
    // Start cleanup routine
    go store.cleanup()
    
    return store
}

func (s *MemoryChallengeStore) StoreChallenge(challenge []byte, data interface{}) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.challenges[string(challenge)] = &challengeEntry{
        data:      data,
        expiresAt: time.Now().Add(5 * time.Minute),
    }
    return nil
}

func (s *MemoryChallengeStore) GetChallenge(challenge []byte) (interface{}, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    entry, exists := s.challenges[string(challenge)]
    if !exists || time.Now().After(entry.expiresAt) {
        return nil, fmt.Errorf("challenge not found or expired")
    }
    return entry.data, nil
}

func (s *MemoryChallengeStore) DeleteChallenge(challenge []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    delete(s.challenges, string(challenge))
    return nil
}

func (s *MemoryChallengeStore) cleanup() {
    ticker := time.NewTicker(time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        s.mu.Lock()
        now := time.Now()
        for challenge, entry := range s.challenges {
            if now.After(entry.expiresAt) {
                delete(s.challenges, challenge)
            }
        }
        s.mu.Unlock()
    }
}
```

### HTTP Handlers

```go
package webauthn

import (
    "encoding/json"
    "net/http"
)

// Handler provides HTTP handlers for WebAuthn
type Handler struct {
    server        *Server
    deviceManager *DeviceManager
}

// NewHandler creates a new HTTP handler
func NewHandler(server *Server, deviceManager *DeviceManager) *Handler {
    return &Handler{
        server:        server,
        deviceManager: deviceManager,
    }
}

// BeginRegistration handles registration initiation
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username    string `json:"username"`
        DisplayName string `json:"displayName"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Generate user ID
    userID := generateUserID()

    options, err := h.server.BeginRegistration(req.Username, req.DisplayName, userID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(options)
}

// FinishRegistration handles registration completion
func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
    var response RegistrationResponse
    if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
        http.Error(w, "Invalid response", http.StatusBadRequest)
        return
    }

    if err := h.server.FinishRegistration(&response); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Register device
    platform := r.Header.Get("User-Agent")
    device, err := h.deviceManager.RegisterDevice(
        response.Response.UserHandle,
        "Primary Device",
        platform,
        response.RawID,
    )
    if err != nil {
        http.Error(w, "Failed to register device", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success":  true,
        "deviceId": device.ID,
    })
}

// BeginLogin handles authentication initiation
func (h *Handler) BeginLogin(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username string `json:"username,omitempty"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    options, err := h.server.BeginLogin(req.Username)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(options)
}

// FinishLogin handles authentication completion
func (h *Handler) FinishLogin(w http.ResponseWriter, r *http.Request) {
    var response AuthenticationResponse
    if err := json.NewDecoder(r.Body).Decode(&response); err != nil {
        http.Error(w, "Invalid response", http.StatusBadRequest)
        return
    }

    sessionID, err := h.server.FinishLogin(&response)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // Set session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    sessionID,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        MaxAge:   86400, // 24 hours
    })

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
    })
}

// ListDevices lists user's devices
func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
    // Get user from session
    userID := getUserFromSession(r)
    if userID == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    devices, err := h.deviceManager.GetUserDevices(userID)
    if err != nil {
        http.Error(w, "Failed to get devices", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(devices)
}

// RemoveDevice removes a device
func (h *Handler) RemoveDevice(w http.ResponseWriter, r *http.Request) {
    deviceID := r.URL.Query().Get("id")
    if deviceID == "" {
        http.Error(w, "Device ID required", http.StatusBadRequest)
        return
    }

    if err := h.deviceManager.RemoveDevice(deviceID); err != nil {
        http.Error(w, "Failed to remove device", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

// generateUserID generates a unique user ID
func generateUserID() []byte {
    b := make([]byte, 16)
    rand.Read(b)
    return b
}

// getUserFromSession gets user ID from session
func getUserFromSession(r *http.Request) []byte {
    // This is a placeholder - implement actual session lookup
    cookie, err := r.Cookie("session")
    if err != nil {
        return nil
    }
    
    // Look up session and return user ID
    _ = cookie.Value
    return nil
}
```

## Usage Example

```go
// Initialize WebAuthn server
config := &Config{
    RPID:                    "blackhole.local",
    RPName:                  "BlackHole",
    Timeout:                 60000,
    AuthenticatorAttachment: AttachmentPlatform,
    ResidentKey:             ResidentKeyPreferred,
    UserVerification:        VerificationPreferred,
    Attestation:             AttestationDirect,
}

userStore := NewMemoryUserStore()
sessionStore := NewMemorySessionStore()
challengeStore := NewMemoryChallengeStore()

server := NewServer(config, userStore, sessionStore, challengeStore)
deviceManager := NewDeviceManager(NewMemoryDeviceStore())

handler := NewHandler(server, deviceManager)

// Setup routes
http.HandleFunc("/webauthn/register/begin", handler.BeginRegistration)
http.HandleFunc("/webauthn/register/finish", handler.FinishRegistration)
http.HandleFunc("/webauthn/login/begin", handler.BeginLogin)
http.HandleFunc("/webauthn/login/finish", handler.FinishLogin)
http.HandleFunc("/webauthn/devices", handler.ListDevices)
http.HandleFunc("/webauthn/devices/remove", handler.RemoveDevice)
```

## Client-Side JavaScript

```javascript
// Registration
async function register(username, displayName) {
    // Get options from server
    const optionsResponse = await fetch('/webauthn/register/begin', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, displayName})
    });
    
    const options = await optionsResponse.json();
    
    // Convert base64 to ArrayBuffer
    options.challenge = base64ToArrayBuffer(options.challenge);
    options.user.id = base64ToArrayBuffer(options.user.id);
    
    // Create credential
    const credential = await navigator.credentials.create({
        publicKey: options
    });
    
    // Send to server
    const response = await fetch('/webauthn/register/finish', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            id: credential.id,
            rawId: arrayBufferToBase64(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                attestationObject: arrayBufferToBase64(credential.response.attestationObject)
            }
        })
    });
    
    return response.json();
}

// Authentication
async function login(username) {
    // Get options from server
    const optionsResponse = await fetch('/webauthn/login/begin', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username})
    });
    
    const options = await optionsResponse.json();
    
    // Convert base64 to ArrayBuffer
    options.challenge = base64ToArrayBuffer(options.challenge);
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({
            ...c,
            id: base64ToArrayBuffer(c.id)
        }));
    }
    
    // Get credential
    const credential = await navigator.credentials.get({
        publicKey: options
    });
    
    // Send to server
    const response = await fetch('/webauthn/login/finish', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            id: credential.id,
            rawId: arrayBufferToBase64(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
                authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
                signature: arrayBufferToBase64(credential.response.signature),
                userHandle: arrayBufferToBase64(credential.response.userHandle)
            }
        })
    });
    
    return response.json();
}
```

## Security Considerations

1. **Challenge Validation**: Single-use challenges with expiration
2. **Origin Verification**: Strict origin checking
3. **RP ID Validation**: Verify RP ID hash in authenticator data
4. **Signature Verification**: Cryptographic signature validation
5. **Replay Protection**: Sign count verification
6. **Session Security**: Secure session management

## Performance Optimizations

1. **Credential Caching**: In-memory credential cache
2. **Parallel Verification**: Concurrent signature verification
3. **Challenge Cleanup**: Automatic expired challenge removal
4. **Device Trust Scoring**: Adaptive authentication based on trust

## Testing

```go
func TestWebAuthnRegistration(t *testing.T) {
    // Setup
    config := &Config{
        RPID:   "localhost",
        RPName: "Test",
    }
    
    server := NewServer(
        config,
        NewMemoryUserStore(),
        NewMemorySessionStore(),
        NewMemoryChallengeStore(),
    )
    
    // Begin registration
    options, err := server.BeginRegistration("testuser", "Test User", []byte("user123"))
    assert.NoError(t, err)
    assert.NotNil(t, options.Challenge)
    
    // Simulate client response
    response := &RegistrationResponse{
        // ... mock response data
    }
    
    // Finish registration
    err = server.FinishRegistration(response)
    assert.NoError(t, err)
}

func TestDeviceManagement(t *testing.T) {
    dm := NewDeviceManager(NewMemoryDeviceStore())
    
    // Register device
    device, err := dm.RegisterDevice(
        []byte("user123"),
        "iPhone",
        "iOS",
        []byte("cred123"),
    )
    
    assert.NoError(t, err)
    assert.Equal(t, 50, device.TrustScore)
    
    // Update trust
    err = dm.UpdateDeviceTrust(device.ID, 10)
    assert.NoError(t, err)
    
    // Get user devices
    devices, err := dm.GetUserDevices([]byte("user123"))
    assert.NoError(t, err)
    assert.Len(t, devices, 1)
}
```

## Next Steps

1. Implement attestation verification
2. Add support for resident keys
3. Implement conditional UI support
4. Add device attestation tracking
5. Create admin interface for device management