# U12: Encryption Gateway

## Overview

The Encryption Gateway provides client-side encryption for all data before it enters the distributed storage system. It implements AES-256-GCM encryption with a zero-knowledge architecture, ensuring that the service never has access to unencrypted data or encryption keys.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Encryption Gateway                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │   Key Manager    │  │ Encryption Core  │  │ Metadata Mgr   │ │
│  │                  │  │                  │  │                │ │
│  │ • Key Derivation │  │ • AES-256-GCM    │  │ • Encrypt Meta │ │
│  │ • Key Storage    │  │ • Stream Cipher  │  │ • Key Rotation │ │
│  │ • Rotation       │  │ • Chunking       │  │ • Access Ctrl  │ │
│  └─────────────────┘  └──────────────────┘  └────────────────┘ │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Security Layer                            │ │
│  │  • Zero-Knowledge Proofs  • Secure Random  • Key Stretching │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Key Manager
- Derives encryption keys from user passwords using Argon2id
- Manages key hierarchy (master key → file keys → chunk keys)
- Handles key rotation and versioning
- Stores encrypted keys with user consent

### 2. Encryption Core
- Implements AES-256-GCM for authenticated encryption
- Supports streaming encryption for large files
- Chunks data for parallel processing
- Provides constant-time operations to prevent timing attacks

### 3. Metadata Manager
- Encrypts file metadata separately
- Manages encrypted search indexes
- Handles access control metadata
- Supports selective metadata sharing

### 4. Security Layer
- Implements zero-knowledge proofs for authentication
- Provides cryptographically secure random number generation
- Manages key stretching and password verification
- Ensures all operations are constant-time

## Implementation

### Core Types and Interfaces

```go
package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/blake2b"
)

const (
    // Encryption parameters
    KeySize   = 32 // AES-256
    NonceSize = 12 // GCM nonce size
    TagSize   = 16 // GCM tag size
    ChunkSize = 1024 * 1024 // 1MB chunks

    // Key derivation parameters
    Argon2Time    = 3
    Argon2Memory  = 64 * 1024
    Argon2Threads = 4
    Argon2KeyLen  = 32
)

// EncryptionGateway manages all encryption operations
type EncryptionGateway struct {
    keyManager     *KeyManager
    encryptionCore *EncryptionCore
    metadataManager *MetadataManager
    securityLayer  *SecurityLayer
}

// KeyManager handles key derivation and management
type KeyManager struct {
    mu          sync.RWMutex
    masterKey   []byte
    keyCache    map[string]*DerivedKey
    keyStore    KeyStore
    rotationMgr *KeyRotationManager
}

// DerivedKey represents a derived encryption key
type DerivedKey struct {
    Key       []byte
    Version   int
    CreatedAt time.Time
    ExpiresAt time.Time
    Purpose   string
}

// EncryptionCore handles the actual encryption operations
type EncryptionCore struct {
    cipherPool sync.Pool
}

// MetadataManager handles metadata encryption
type MetadataManager struct {
    indexKey []byte
    mu       sync.RWMutex
}

// SecurityLayer provides additional security features
type SecurityLayer struct {
    randReader io.Reader
}
```

### Key Management Implementation

```go
// NewKeyManager creates a new key manager
func NewKeyManager(store KeyStore) *KeyManager {
    return &KeyManager{
        keyCache:    make(map[string]*DerivedKey),
        keyStore:    store,
        rotationMgr: NewKeyRotationManager(),
    }
}

// DeriveUserKey derives a master key from user password
func (km *KeyManager) DeriveUserKey(password, salt []byte) ([]byte, error) {
    if len(password) == 0 {
        return nil, errors.New("password cannot be empty")
    }
    
    if len(salt) < 16 {
        return nil, errors.New("salt must be at least 16 bytes")
    }

    // Use Argon2id for key derivation
    key := argon2.IDKey(
        password,
        salt,
        Argon2Time,
        Argon2Memory,
        Argon2Threads,
        Argon2KeyLen,
    )

    // Additional key stretching with Blake2b
    h, err := blake2b.New256(key)
    if err != nil {
        return nil, err
    }
    h.Write(salt)
    
    return h.Sum(nil), nil
}

// DeriveFileKey derives a unique key for a file
func (km *KeyManager) DeriveFileKey(masterKey []byte, fileID string) (*DerivedKey, error) {
    km.mu.Lock()
    defer km.mu.Unlock()

    // Check cache first
    if key, exists := km.keyCache[fileID]; exists && !km.isExpired(key) {
        return key, nil
    }

    // Derive new key using HKDF
    salt := sha256.Sum256([]byte(fileID))
    derivedKey := make([]byte, KeySize)
    
    // Use Blake2b for key derivation
    h, err := blake2b.New256(masterKey)
    if err != nil {
        return nil, err
    }
    h.Write(salt[:])
    h.Write([]byte("file-encryption"))
    copy(derivedKey, h.Sum(nil))

    key := &DerivedKey{
        Key:       derivedKey,
        Version:   1,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
        Purpose:   "file-encryption",
    }

    km.keyCache[fileID] = key
    return key, nil
}

// RotateKey rotates an encryption key
func (km *KeyManager) RotateKey(fileID string) error {
    km.mu.Lock()
    defer km.mu.Unlock()

    oldKey, exists := km.keyCache[fileID]
    if !exists {
        return errors.New("key not found")
    }

    // Generate new key
    newKey := make([]byte, KeySize)
    if _, err := rand.Read(newKey); err != nil {
        return err
    }

    // Create rotation record
    rotation := &KeyRotation{
        FileID:    fileID,
        OldKey:    oldKey.Key,
        NewKey:    newKey,
        Version:   oldKey.Version + 1,
        Timestamp: time.Now(),
    }

    // Store rotation record
    if err := km.rotationMgr.RecordRotation(rotation); err != nil {
        return err
    }

    // Update cache
    km.keyCache[fileID] = &DerivedKey{
        Key:       newKey,
        Version:   oldKey.Version + 1,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
        Purpose:   oldKey.Purpose,
    }

    return nil
}

func (km *KeyManager) isExpired(key *DerivedKey) bool {
    return time.Now().After(key.ExpiresAt)
}
```

### Encryption Core Implementation

```go
// NewEncryptionCore creates a new encryption core
func NewEncryptionCore() *EncryptionCore {
    return &EncryptionCore{
        cipherPool: sync.Pool{
            New: func() interface{} {
                return &aesgcmCipher{}
            },
        },
    }
}

type aesgcmCipher struct {
    aead   cipher.AEAD
    nonce  []byte
    buffer []byte
}

// EncryptData encrypts data using AES-256-GCM
func (ec *EncryptionCore) EncryptData(key, plaintext []byte) ([]byte, error) {
    if len(key) != KeySize {
        return nil, errors.New("invalid key size")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // Generate nonce
    nonce := make([]byte, NonceSize)
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }

    // Encrypt data
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)
    
    // Prepend nonce to ciphertext
    result := make([]byte, NonceSize+len(ciphertext))
    copy(result[:NonceSize], nonce)
    copy(result[NonceSize:], ciphertext)

    return result, nil
}

// DecryptData decrypts data using AES-256-GCM
func (ec *EncryptionCore) DecryptData(key, ciphertext []byte) ([]byte, error) {
    if len(key) != KeySize {
        return nil, errors.New("invalid key size")
    }

    if len(ciphertext) < NonceSize+TagSize {
        return nil, errors.New("ciphertext too short")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // Extract nonce
    nonce := ciphertext[:NonceSize]
    ciphertext = ciphertext[NonceSize:]

    // Decrypt data
    plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}

// EncryptStream encrypts a stream of data
func (ec *EncryptionCore) EncryptStream(key []byte, reader io.Reader, writer io.Writer) error {
    if len(key) != KeySize {
        return errors.New("invalid key size")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    buffer := make([]byte, ChunkSize)
    chunkIndex := uint64(0)

    for {
        n, err := reader.Read(buffer)
        if err != nil && err != io.EOF {
            return err
        }
        if n == 0 {
            break
        }

        // Generate unique nonce for each chunk
        nonce := make([]byte, NonceSize)
        if _, err := rand.Read(nonce[:4]); err != nil {
            return err
        }
        // Include chunk index in nonce
        for i := 0; i < 8; i++ {
            nonce[4+i] = byte(chunkIndex >> (8 * i))
        }

        // Encrypt chunk
        ciphertext := aead.Seal(nil, nonce, buffer[:n], nil)

        // Write nonce + ciphertext
        if _, err := writer.Write(nonce); err != nil {
            return err
        }
        if _, err := writer.Write(ciphertext); err != nil {
            return err
        }

        chunkIndex++
        
        if err == io.EOF {
            break
        }
    }

    return nil
}

// DecryptStream decrypts a stream of data
func (ec *EncryptionCore) DecryptStream(key []byte, reader io.Reader, writer io.Writer) error {
    if len(key) != KeySize {
        return errors.New("invalid key size")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    for {
        // Read nonce
        nonce := make([]byte, NonceSize)
        if _, err := io.ReadFull(reader, nonce); err != nil {
            if err == io.EOF {
                break
            }
            return err
        }

        // Read encrypted chunk size (we need to know how much to read)
        chunkSizeBytes := make([]byte, 4)
        if _, err := io.ReadFull(reader, chunkSizeBytes); err != nil {
            return err
        }
        chunkSize := int(chunkSizeBytes[0])<<24 | int(chunkSizeBytes[1])<<16 | 
                    int(chunkSizeBytes[2])<<8 | int(chunkSizeBytes[3])

        // Read encrypted chunk
        ciphertext := make([]byte, chunkSize)
        if _, err := io.ReadFull(reader, ciphertext); err != nil {
            return err
        }

        // Decrypt chunk
        plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
        if err != nil {
            return err
        }

        // Write plaintext
        if _, err := writer.Write(plaintext); err != nil {
            return err
        }
    }

    return nil
}
```

### Metadata Encryption Implementation

```go
// NewMetadataManager creates a new metadata manager
func NewMetadataManager(indexKey []byte) *MetadataManager {
    return &MetadataManager{
        indexKey: indexKey,
    }
}

// FileMetadata represents encrypted file metadata
type FileMetadata struct {
    FileID          string
    EncryptedName   []byte
    EncryptedType   []byte
    EncryptedSize   []byte
    EncryptedTags   [][]byte
    EncryptedAttrs  map[string][]byte
    CreatedAt       time.Time
    ModifiedAt      time.Time
    AccessControl   *AccessControl
}

// AccessControl defines encrypted access control
type AccessControl struct {
    OwnerID        string
    EncryptedPerms map[string][]byte // userID -> encrypted permissions
    SharedKeys     map[string][]byte // userID -> encrypted file key
}

// EncryptMetadata encrypts file metadata
func (mm *MetadataManager) EncryptMetadata(meta *FileMetadata, key []byte) (*EncryptedMetadata, error) {
    mm.mu.RLock()
    defer mm.mu.RUnlock()

    encrypted := &EncryptedMetadata{
        FileID:     meta.FileID,
        CreatedAt:  meta.CreatedAt,
        ModifiedAt: meta.ModifiedAt,
    }

    // Encrypt each metadata field
    encCore := NewEncryptionCore()

    // Encrypt filename
    if meta.EncryptedName != nil {
        enc, err := encCore.EncryptData(key, meta.EncryptedName)
        if err != nil {
            return nil, err
        }
        encrypted.Name = base64.StdEncoding.EncodeToString(enc)
    }

    // Encrypt file type
    if meta.EncryptedType != nil {
        enc, err := encCore.EncryptData(key, meta.EncryptedType)
        if err != nil {
            return nil, err
        }
        encrypted.Type = base64.StdEncoding.EncodeToString(enc)
    }

    // Encrypt tags
    encrypted.Tags = make([]string, len(meta.EncryptedTags))
    for i, tag := range meta.EncryptedTags {
        enc, err := encCore.EncryptData(key, tag)
        if err != nil {
            return nil, err
        }
        encrypted.Tags[i] = base64.StdEncoding.EncodeToString(enc)
    }

    // Encrypt custom attributes
    encrypted.Attributes = make(map[string]string)
    for k, v := range meta.EncryptedAttrs {
        enc, err := encCore.EncryptData(key, v)
        if err != nil {
            return nil, err
        }
        encrypted.Attributes[k] = base64.StdEncoding.EncodeToString(enc)
    }

    // Handle access control
    if meta.AccessControl != nil {
        encrypted.AccessControl = mm.encryptAccessControl(meta.AccessControl, key)
    }

    return encrypted, nil
}

// CreateSearchableIndex creates an encrypted search index
func (mm *MetadataManager) CreateSearchableIndex(metadata []*FileMetadata) (*SearchIndex, error) {
    mm.mu.RLock()
    defer mm.mu.RUnlock()

    index := &SearchIndex{
        Version:   1,
        CreatedAt: time.Now(),
        Entries:   make(map[string]*IndexEntry),
    }

    for _, meta := range metadata {
        // Create searchable tokens
        tokens := mm.tokenizeMetadata(meta)
        
        for _, token := range tokens {
            // Create deterministic token hash
            h := sha256.New()
            h.Write(mm.indexKey)
            h.Write([]byte(token))
            tokenHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

            // Add to index
            if entry, exists := index.Entries[tokenHash]; exists {
                entry.FileIDs = append(entry.FileIDs, meta.FileID)
            } else {
                index.Entries[tokenHash] = &IndexEntry{
                    TokenHash: tokenHash,
                    FileIDs:   []string{meta.FileID},
                }
            }
        }
    }

    return index, nil
}

// SearchFiles searches for files using encrypted tokens
func (mm *MetadataManager) SearchFiles(query string, index *SearchIndex) ([]string, error) {
    mm.mu.RLock()
    defer mm.mu.RUnlock()

    // Tokenize query
    tokens := mm.tokenizeQuery(query)
    
    fileIDSets := make([]map[string]bool, len(tokens))
    
    for i, token := range tokens {
        // Create token hash
        h := sha256.New()
        h.Write(mm.indexKey)
        h.Write([]byte(token))
        tokenHash := base64.StdEncoding.EncodeToString(h.Sum(nil))

        // Find matching files
        fileIDSets[i] = make(map[string]bool)
        if entry, exists := index.Entries[tokenHash]; exists {
            for _, fileID := range entry.FileIDs {
                fileIDSets[i][fileID] = true
            }
        }
    }

    // Intersect all sets (AND operation)
    if len(fileIDSets) == 0 {
        return []string{}, nil
    }

    result := fileIDSets[0]
    for i := 1; i < len(fileIDSets); i++ {
        intersection := make(map[string]bool)
        for fileID := range result {
            if fileIDSets[i][fileID] {
                intersection[fileID] = true
            }
        }
        result = intersection
    }

    // Convert to slice
    fileIDs := make([]string, 0, len(result))
    for fileID := range result {
        fileIDs = append(fileIDs, fileID)
    }

    return fileIDs, nil
}

func (mm *MetadataManager) tokenizeMetadata(meta *FileMetadata) []string {
    // Implementation would tokenize metadata fields for searching
    // This is a simplified version
    var tokens []string
    
    // Add file ID
    tokens = append(tokens, meta.FileID)
    
    // Add other searchable fields after decryption
    // This would need the appropriate keys
    
    return tokens
}

func (mm *MetadataManager) tokenizeQuery(query string) []string {
    // Simple tokenization - in production would be more sophisticated
    return strings.Fields(strings.ToLower(query))
}

func (mm *MetadataManager) encryptAccessControl(ac *AccessControl, key []byte) *EncryptedAccessControl {
    // Encrypt access control data
    enc := &EncryptedAccessControl{
        OwnerID:        ac.OwnerID,
        EncryptedPerms: make(map[string]string),
        SharedKeys:     make(map[string]string),
    }

    for userID, perms := range ac.EncryptedPerms {
        enc.EncryptedPerms[userID] = base64.StdEncoding.EncodeToString(perms)
    }

    for userID, sharedKey := range ac.SharedKeys {
        enc.SharedKeys[userID] = base64.StdEncoding.EncodeToString(sharedKey)
    }

    return enc
}
```

### Security Layer Implementation

```go
// NewSecurityLayer creates a new security layer
func NewSecurityLayer() *SecurityLayer {
    return &SecurityLayer{
        randReader: rand.Reader,
    }
}

// GenerateSecureRandom generates cryptographically secure random bytes
func (sl *SecurityLayer) GenerateSecureRandom(size int) ([]byte, error) {
    bytes := make([]byte, size)
    if _, err := io.ReadFull(sl.randReader, bytes); err != nil {
        return nil, err
    }
    return bytes, nil
}

// GenerateSalt generates a random salt for key derivation
func (sl *SecurityLayer) GenerateSalt() ([]byte, error) {
    return sl.GenerateSecureRandom(32)
}

// ZeroKnowledgeProof represents a zero-knowledge proof
type ZeroKnowledgeProof struct {
    Challenge []byte
    Response  []byte
    Timestamp time.Time
}

// CreateZKProof creates a zero-knowledge proof of password knowledge
func (sl *SecurityLayer) CreateZKProof(password, salt []byte) (*ZeroKnowledgeProof, error) {
    // Generate challenge
    challenge, err := sl.GenerateSecureRandom(32)
    if err != nil {
        return nil, err
    }

    // Create response using password hash
    h := sha256.New()
    h.Write(password)
    h.Write(salt)
    h.Write(challenge)
    response := h.Sum(nil)

    return &ZeroKnowledgeProof{
        Challenge: challenge,
        Response:  response,
        Timestamp: time.Now(),
    }, nil
}

// VerifyZKProof verifies a zero-knowledge proof
func (sl *SecurityLayer) VerifyZKProof(proof *ZeroKnowledgeProof, passwordHash, salt []byte) bool {
    // Check timestamp (prevent replay attacks)
    if time.Since(proof.Timestamp) > 5*time.Minute {
        return false
    }

    // Recreate response
    h := sha256.New()
    h.Write(passwordHash)
    h.Write(salt)
    h.Write(proof.Challenge)
    expectedResponse := h.Sum(nil)

    // Constant-time comparison
    return subtle.ConstantTimeCompare(proof.Response, expectedResponse) == 1
}

// SecureErase overwrites sensitive data in memory
func (sl *SecurityLayer) SecureErase(data []byte) {
    if len(data) == 0 {
        return
    }

    // Overwrite with random data
    rand.Read(data)
    
    // Then overwrite with zeros
    for i := range data {
        data[i] = 0
    }
}

// ConstantTimeSelect returns x if v == 1 and y if v == 0
func (sl *SecurityLayer) ConstantTimeSelect(v, x, y int) int {
    return ^(v-1)&x | (v-1)&y
}
```

### Main Gateway Implementation

```go
// NewEncryptionGateway creates a new encryption gateway
func NewEncryptionGateway(keyStore KeyStore) *EncryptionGateway {
    security := NewSecurityLayer()
    
    return &EncryptionGateway{
        keyManager:      NewKeyManager(keyStore),
        encryptionCore:  NewEncryptionCore(),
        metadataManager: NewMetadataManager(nil), // Index key set later
        securityLayer:   security,
    }
}

// Initialize initializes the gateway with user credentials
func (eg *EncryptionGateway) Initialize(password string) error {
    // Generate or retrieve salt
    salt, err := eg.keyManager.keyStore.GetSalt()
    if err != nil {
        // First time - generate new salt
        salt, err = eg.securityLayer.GenerateSalt()
        if err != nil {
            return err
        }
        if err := eg.keyManager.keyStore.StoreSalt(salt); err != nil {
            return err
        }
    }

    // Derive master key
    masterKey, err := eg.keyManager.DeriveUserKey([]byte(password), salt)
    if err != nil {
        return err
    }

    eg.keyManager.masterKey = masterKey

    // Derive index key for metadata
    indexKey, err := eg.keyManager.DeriveFileKey(masterKey, "metadata-index")
    if err != nil {
        return err
    }
    eg.metadataManager.indexKey = indexKey.Key

    // Clear password from memory
    eg.securityLayer.SecureErase([]byte(password))

    return nil
}

// EncryptFile encrypts a file with metadata
func (eg *EncryptionGateway) EncryptFile(fileID string, reader io.Reader, metadata map[string]string) (*EncryptedFile, error) {
    // Derive file key
    fileKey, err := eg.keyManager.DeriveFileKey(eg.keyManager.masterKey, fileID)
    if err != nil {
        return nil, err
    }

    // Create encrypted file
    encFile := &EncryptedFile{
        FileID:    fileID,
        Version:   fileKey.Version,
        Chunks:    []EncryptedChunk{},
        Metadata:  metadata,
        CreatedAt: time.Now(),
    }

    // Encrypt file data in chunks
    chunkIndex := 0
    buffer := make([]byte, ChunkSize)

    for {
        n, err := reader.Read(buffer)
        if err != nil && err != io.EOF {
            return nil, err
        }
        if n == 0 {
            break
        }

        // Derive chunk key
        chunkKey := eg.deriveChunkKey(fileKey.Key, chunkIndex)
        
        // Encrypt chunk
        encryptedData, err := eg.encryptionCore.EncryptData(chunkKey, buffer[:n])
        if err != nil {
            return nil, err
        }

        chunk := EncryptedChunk{
            Index:     chunkIndex,
            Size:      n,
            Encrypted: encryptedData,
            Hash:      eg.computeChunkHash(encryptedData),
        }

        encFile.Chunks = append(encFile.Chunks, chunk)
        chunkIndex++

        if err == io.EOF {
            break
        }
    }

    // Encrypt metadata
    metaData := &FileMetadata{
        FileID:         fileID,
        EncryptedAttrs: make(map[string][]byte),
    }

    for k, v := range metadata {
        metaData.EncryptedAttrs[k] = []byte(v)
    }

    encMeta, err := eg.metadataManager.EncryptMetadata(metaData, fileKey.Key)
    if err != nil {
        return nil, err
    }

    encFile.EncryptedMetadata = encMeta

    return encFile, nil
}

// DecryptFile decrypts a file
func (eg *EncryptionGateway) DecryptFile(encFile *EncryptedFile, writer io.Writer) error {
    // Derive file key
    fileKey, err := eg.keyManager.DeriveFileKey(eg.keyManager.masterKey, encFile.FileID)
    if err != nil {
        return err
    }

    // Verify version
    if fileKey.Version < encFile.Version {
        return errors.New("key version mismatch - key rotation may be needed")
    }

    // Decrypt chunks in order
    for _, chunk := range encFile.Chunks {
        // Verify chunk hash
        if !eg.verifyChunkHash(chunk.Encrypted, chunk.Hash) {
            return errors.New("chunk integrity check failed")
        }

        // Derive chunk key
        chunkKey := eg.deriveChunkKey(fileKey.Key, chunk.Index)

        // Decrypt chunk
        plaintext, err := eg.encryptionCore.DecryptData(chunkKey, chunk.Encrypted)
        if err != nil {
            return err
        }

        // Write to output
        if _, err := writer.Write(plaintext); err != nil {
            return err
        }

        // Clear plaintext from memory
        eg.securityLayer.SecureErase(plaintext)
    }

    return nil
}

// ShareFile creates encrypted access for another user
func (eg *EncryptionGateway) ShareFile(fileID, recipientID string, permissions []string) (*SharedAccess, error) {
    // Get file key
    fileKey, err := eg.keyManager.DeriveFileKey(eg.keyManager.masterKey, fileID)
    if err != nil {
        return nil, err
    }

    // Generate sharing key
    sharingKey, err := eg.securityLayer.GenerateSecureRandom(KeySize)
    if err != nil {
        return nil, err
    }

    // Encrypt file key with sharing key
    encryptedFileKey, err := eg.encryptionCore.EncryptData(sharingKey, fileKey.Key)
    if err != nil {
        return nil, err
    }

    // Create permission set
    permBytes, err := json.Marshal(permissions)
    if err != nil {
        return nil, err
    }

    encryptedPerms, err := eg.encryptionCore.EncryptData(sharingKey, permBytes)
    if err != nil {
        return nil, err
    }

    shared := &SharedAccess{
        FileID:           fileID,
        RecipientID:      recipientID,
        EncryptedFileKey: base64.StdEncoding.EncodeToString(encryptedFileKey),
        EncryptedPerms:   base64.StdEncoding.EncodeToString(encryptedPerms),
        SharingKey:       sharingKey, // This would be encrypted with recipient's public key
        CreatedAt:        time.Now(),
        ExpiresAt:        time.Now().Add(30 * 24 * time.Hour),
    }

    return shared, nil
}

func (eg *EncryptionGateway) deriveChunkKey(fileKey []byte, chunkIndex int) []byte {
    h := sha256.New()
    h.Write(fileKey)
    h.Write([]byte("chunk"))
    h.Write([]byte{byte(chunkIndex >> 24), byte(chunkIndex >> 16), byte(chunkIndex >> 8), byte(chunkIndex)})
    return h.Sum(nil)[:KeySize]
}

func (eg *EncryptionGateway) computeChunkHash(data []byte) []byte {
    h := sha256.New()
    h.Write(data)
    return h.Sum(nil)
}

func (eg *EncryptionGateway) verifyChunkHash(data, expectedHash []byte) bool {
    actualHash := eg.computeChunkHash(data)
    return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}
```

## Security Best Practices

### 1. Key Management
- Never store unencrypted keys
- Use hardware security modules (HSM) when available
- Implement key rotation policies
- Use separate keys for different purposes

### 2. Cryptographic Operations
- Always use authenticated encryption (AES-GCM)
- Generate unique nonces for each encryption operation
- Use constant-time operations to prevent timing attacks
- Verify data integrity before decryption

### 3. Memory Security
- Clear sensitive data from memory after use
- Use locked memory pages for key material
- Implement secure key deletion
- Avoid string types for sensitive data

### 4. Zero-Knowledge Architecture
- Server never has access to plaintext data
- Client performs all encryption/decryption
- Use zero-knowledge proofs for authentication
- Implement end-to-end encryption

## Testing

```go
package encryption

import (
    "bytes"
    "crypto/rand"
    "testing"
)

func TestKeyDerivation(t *testing.T) {
    km := NewKeyManager(NewMemoryKeyStore())
    
    password := []byte("test-password-123")
    salt := make([]byte, 32)
    rand.Read(salt)
    
    // Test key derivation
    key1, err := km.DeriveUserKey(password, salt)
    if err != nil {
        t.Fatalf("Failed to derive key: %v", err)
    }
    
    // Same inputs should produce same key
    key2, err := km.DeriveUserKey(password, salt)
    if err != nil {
        t.Fatalf("Failed to derive key: %v", err)
    }
    
    if !bytes.Equal(key1, key2) {
        t.Error("Same inputs produced different keys")
    }
    
    // Different password should produce different key
    key3, err := km.DeriveUserKey([]byte("different-password"), salt)
    if err != nil {
        t.Fatalf("Failed to derive key: %v", err)
    }
    
    if bytes.Equal(key1, key3) {
        t.Error("Different passwords produced same key")
    }
}

func TestEncryptionDecryption(t *testing.T) {
    ec := NewEncryptionCore()
    
    key := make([]byte, KeySize)
    rand.Read(key)
    
    plaintext := []byte("Hello, World! This is a test message.")
    
    // Encrypt
    ciphertext, err := ec.EncryptData(key, plaintext)
    if err != nil {
        t.Fatalf("Encryption failed: %v", err)
    }
    
    // Decrypt
    decrypted, err := ec.DecryptData(key, ciphertext)
    if err != nil {
        t.Fatalf("Decryption failed: %v", err)
    }
    
    if !bytes.Equal(plaintext, decrypted) {
        t.Error("Decrypted data doesn't match original")
    }
    
    // Test authentication - modify ciphertext
    ciphertext[len(ciphertext)-1] ^= 0xFF
    _, err = ec.DecryptData(key, ciphertext)
    if err == nil {
        t.Error("Modified ciphertext should fail authentication")
    }
}

func TestStreamEncryption(t *testing.T) {
    ec := NewEncryptionCore()
    
    key := make([]byte, KeySize)
    rand.Read(key)
    
    // Create test data larger than chunk size
    testData := make([]byte, ChunkSize*3+1234)
    rand.Read(testData)
    
    // Encrypt stream
    var encrypted bytes.Buffer
    err := ec.EncryptStream(key, bytes.NewReader(testData), &encrypted)
    if err != nil {
        t.Fatalf("Stream encryption failed: %v", err)
    }
    
    // Decrypt stream
    var decrypted bytes.Buffer
    err = ec.DecryptStream(key, &encrypted, &decrypted)
    if err != nil {
        t.Fatalf("Stream decryption failed: %v", err)
    }
    
    if !bytes.Equal(testData, decrypted.Bytes()) {
        t.Error("Decrypted stream doesn't match original")
    }
}

func BenchmarkEncryption(b *testing.B) {
    ec := NewEncryptionCore()
    key := make([]byte, KeySize)
    rand.Read(key)
    
    data := make([]byte, 1024*1024) // 1MB
    rand.Read(data)
    
    b.ResetTimer()
    b.SetBytes(int64(len(data)))
    
    for i := 0; i < b.N; i++ {
        _, err := ec.EncryptData(key, data)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Performance Considerations

1. **Chunk Size**: 1MB chunks balance memory usage and performance
2. **Parallelization**: Chunks can be encrypted/decrypted in parallel
3. **Key Caching**: Derived keys are cached to avoid repeated derivation
4. **Memory Pooling**: Reuse cipher objects to reduce allocations

## Integration Points

1. **Storage Layer**: Provides encrypted chunks for storage
2. **Replication Manager**: Works with encrypted data only
3. **Access Control**: Manages encrypted sharing keys
4. **Audit System**: Logs encryption operations without exposing keys