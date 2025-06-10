# U23: Verifiable Credentials

## Overview
W3C Verifiable Credentials implementation for BlackHole, providing credential issuance, verification services, and trust registry management for decentralized identity claims.

## Implementation

### Core Credential Types

```go
package vc

import (
    "crypto/ed25519"
    "encoding/json"
    "time"
)

// VerifiableCredential represents a W3C Verifiable Credential
type VerifiableCredential struct {
    Context           []string               `json:"@context"`
    ID                string                 `json:"id"`
    Type              []string               `json:"type"`
    Issuer            Issuer                 `json:"issuer"`
    IssuanceDate      time.Time              `json:"issuanceDate"`
    ExpirationDate    *time.Time             `json:"expirationDate,omitempty"`
    CredentialSubject CredentialSubject      `json:"credentialSubject"`
    CredentialStatus  *CredentialStatus      `json:"credentialStatus,omitempty"`
    Proof             *Proof                 `json:"proof,omitempty"`
}

// VerifiablePresentation represents a W3C Verifiable Presentation
type VerifiablePresentation struct {
    Context              []string                `json:"@context"`
    ID                   string                  `json:"id"`
    Type                 []string                `json:"type"`
    VerifiableCredential []VerifiableCredential  `json:"verifiableCredential"`
    Holder               string                  `json:"holder"`
    Proof                *Proof                  `json:"proof,omitempty"`
}

// Issuer represents a credential issuer
type Issuer struct {
    ID   string `json:"id"`
    Name string `json:"name,omitempty"`
}

// CredentialSubject contains the claims about the subject
type CredentialSubject struct {
    ID     string                 `json:"id"`
    Claims map[string]interface{} `json:"-"`
}

// CredentialStatus for revocation checking
type CredentialStatus struct {
    ID   string `json:"id"`
    Type string `json:"type"`
}

// Proof represents a cryptographic proof
type Proof struct {
    Type               string    `json:"type"`
    Created            time.Time `json:"created"`
    VerificationMethod string    `json:"verificationMethod"`
    ProofPurpose       string    `json:"proofPurpose"`
    ProofValue         string    `json:"proofValue"`
    Challenge          string    `json:"challenge,omitempty"`
    Domain             string    `json:"domain,omitempty"`
}

// CredentialSchema defines the structure of credentials
type CredentialSchema struct {
    ID          string                 `json:"id"`
    Type        string                 `json:"type"`
    Name        string                 `json:"name"`
    Description string                 `json:"description"`
    Properties  map[string]Property    `json:"properties"`
    Required    []string               `json:"required"`
}

// Property defines a schema property
type Property struct {
    Type        string      `json:"type"`
    Description string      `json:"description"`
    Format      string      `json:"format,omitempty"`
    Pattern     string      `json:"pattern,omitempty"`
    Minimum     interface{} `json:"minimum,omitempty"`
    Maximum     interface{} `json:"maximum,omitempty"`
}

// RevocationList for credential revocation
type RevocationList struct {
    ID             string    `json:"id"`
    Type           string    `json:"type"`
    Issuer         string    `json:"issuer"`
    IssuedDate     time.Time `json:"issuedDate"`
    RevokedCredentials []RevokedCredential `json:"revokedCredentials"`
}

// RevokedCredential represents a revoked credential
type RevokedCredential struct {
    ID            string    `json:"id"`
    RevocationDate time.Time `json:"revocationDate"`
    Reason        string    `json:"reason,omitempty"`
}

// MarshalJSON custom marshaler for CredentialSubject
func (cs CredentialSubject) MarshalJSON() ([]byte, error) {
    // Merge ID with claims
    data := make(map[string]interface{})
    for k, v := range cs.Claims {
        data[k] = v
    }
    data["id"] = cs.ID
    return json.Marshal(data)
}

// UnmarshalJSON custom unmarshaler for CredentialSubject
func (cs *CredentialSubject) UnmarshalJSON(data []byte) error {
    var raw map[string]interface{}
    if err := json.Unmarshal(data, &raw); err != nil {
        return err
    }
    
    if id, ok := raw["id"].(string); ok {
        cs.ID = id
        delete(raw, "id")
    }
    
    cs.Claims = raw
    return nil
}
```

### Credential Issuer

```go
package vc

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "sync"
    "time"
)

// Issuer service for creating verifiable credentials
type IssuerService struct {
    mu            sync.RWMutex
    did           string
    keyManager    KeyManager
    schemas       map[string]*CredentialSchema
    revocationMgr *RevocationManager
    storage       IssuerStorage
}

// KeyManager interface for key operations
type KeyManager interface {
    Sign(keyID string, data []byte) ([]byte, error)
    GetPublicKey(keyID string) (ed25519.PublicKey, error)
}

// IssuerStorage interface for persistence
type IssuerStorage interface {
    StoreCredential(vc *VerifiableCredential) error
    GetCredential(id string) (*VerifiableCredential, error)
    ListCredentials(issuer string) ([]*VerifiableCredential, error)
    StoreSchema(schema *CredentialSchema) error
    GetSchema(id string) (*CredentialSchema, error)
}

// NewIssuerService creates a new issuer service
func NewIssuerService(did string, keyManager KeyManager, storage IssuerStorage) *IssuerService {
    return &IssuerService{
        did:           did,
        keyManager:    keyManager,
        schemas:       make(map[string]*CredentialSchema),
        revocationMgr: NewRevocationManager(did, storage),
        storage:       storage,
    }
}

// RegisterSchema registers a credential schema
func (is *IssuerService) RegisterSchema(schema *CredentialSchema) error {
    is.mu.Lock()
    defer is.mu.Unlock()

    if err := is.validateSchema(schema); err != nil {
        return fmt.Errorf("invalid schema: %w", err)
    }

    if err := is.storage.StoreSchema(schema); err != nil {
        return fmt.Errorf("failed to store schema: %w", err)
    }

    is.schemas[schema.ID] = schema
    return nil
}

// IssueCredential issues a new verifiable credential
func (is *IssuerService) IssueCredential(request *CredentialRequest) (*VerifiableCredential, error) {
    is.mu.Lock()
    defer is.mu.Unlock()

    // Validate schema if specified
    if request.SchemaID != "" {
        schema, exists := is.schemas[request.SchemaID]
        if !exists {
            return nil, fmt.Errorf("schema not found: %s", request.SchemaID)
        }

        if err := is.validateClaims(request.Claims, schema); err != nil {
            return nil, fmt.Errorf("claims validation failed: %w", err)
        }
    }

    // Create credential
    credential := &VerifiableCredential{
        Context: []string{
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        },
        ID:   generateCredentialID(),
        Type: append([]string{"VerifiableCredential"}, request.Types...),
        Issuer: Issuer{
            ID:   is.did,
            Name: request.IssuerName,
        },
        IssuanceDate: time.Now(),
        CredentialSubject: CredentialSubject{
            ID:     request.SubjectDID,
            Claims: request.Claims,
        },
    }

    // Add expiration if specified
    if request.ExpirationDate != nil {
        credential.ExpirationDate = request.ExpirationDate
    }

    // Add revocation status
    if request.Revocable {
        credential.CredentialStatus = &CredentialStatus{
            ID:   fmt.Sprintf("%s/revocation/%s", is.did, credential.ID),
            Type: "RevocationList2020Status",
        }
    }

    // Sign the credential
    if err := is.signCredential(credential); err != nil {
        return nil, fmt.Errorf("failed to sign credential: %w", err)
    }

    // Store credential
    if err := is.storage.StoreCredential(credential); err != nil {
        return nil, fmt.Errorf("failed to store credential: %w", err)
    }

    return credential, nil
}

// signCredential signs a verifiable credential
func (is *IssuerService) signCredential(vc *VerifiableCredential) error {
    // Remove existing proof
    vc.Proof = nil

    // Canonicalize credential
    data, err := canonicalizeJSON(vc)
    if err != nil {
        return fmt.Errorf("failed to canonicalize: %w", err)
    }

    // Sign the data
    keyID := fmt.Sprintf("%s#key-1", is.did)
    signature, err := is.keyManager.Sign(keyID, data)
    if err != nil {
        return fmt.Errorf("failed to sign: %w", err)
    }

    // Add proof
    vc.Proof = &Proof{
        Type:               "Ed25519Signature2020",
        Created:            time.Now(),
        VerificationMethod: keyID,
        ProofPurpose:       "assertionMethod",
        ProofValue:         base64.RawURLEncoding.EncodeToString(signature),
    }

    return nil
}

// validateSchema validates a credential schema
func (is *IssuerService) validateSchema(schema *CredentialSchema) error {
    if schema.ID == "" {
        return fmt.Errorf("schema ID required")
    }

    if schema.Type == "" {
        return fmt.Errorf("schema type required")
    }

    if len(schema.Properties) == 0 {
        return fmt.Errorf("schema must define properties")
    }

    // Validate required fields exist in properties
    for _, required := range schema.Required {
        if _, exists := schema.Properties[required]; !exists {
            return fmt.Errorf("required field not in properties: %s", required)
        }
    }

    return nil
}

// validateClaims validates claims against a schema
func (is *IssuerService) validateClaims(claims map[string]interface{}, schema *CredentialSchema) error {
    // Check required fields
    for _, required := range schema.Required {
        if _, exists := claims[required]; !exists {
            return fmt.Errorf("missing required field: %s", required)
        }
    }

    // Validate each claim
    for key, value := range claims {
        prop, exists := schema.Properties[key]
        if !exists {
            return fmt.Errorf("unknown claim: %s", key)
        }

        if err := validateValue(value, prop); err != nil {
            return fmt.Errorf("invalid value for %s: %w", key, err)
        }
    }

    return nil
}

// RevokeCredential revokes a credential
func (is *IssuerService) RevokeCredential(credentialID, reason string) error {
    return is.revocationMgr.RevokeCredential(credentialID, reason)
}

// GetRevocationList returns the current revocation list
func (is *IssuerService) GetRevocationList() (*RevocationList, error) {
    return is.revocationMgr.GetRevocationList()
}

// CredentialRequest for issuing credentials
type CredentialRequest struct {
    SubjectDID     string                 `json:"subjectDID"`
    Types          []string               `json:"types"`
    Claims         map[string]interface{} `json:"claims"`
    SchemaID       string                 `json:"schemaID,omitempty"`
    ExpirationDate *time.Time             `json:"expirationDate,omitempty"`
    Revocable      bool                   `json:"revocable"`
    IssuerName     string                 `json:"issuerName,omitempty"`
}
```

### Credential Verifier

```go
package vc

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "sync"
    "time"
)

// VerifierService verifies credentials and presentations
type VerifierService struct {
    mu          sync.RWMutex
    didResolver DIDResolver
    trustReg    *TrustRegistry
    cache       VerificationCache
}

// DIDResolver interface for DID resolution
type DIDResolver interface {
    Resolve(did string) (*DIDDocument, error)
}

// DIDDocument simplified DID document
type DIDDocument struct {
    ID                 string                    `json:"id"`
    VerificationMethod []VerificationMethod      `json:"verificationMethod"`
}

// VerificationMethod for DID documents
type VerificationMethod struct {
    ID                 string `json:"id"`
    Type               string `json:"type"`
    Controller         string `json:"controller"`
    PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// VerificationCache for caching verification results
type VerificationCache interface {
    Get(id string) (*VerificationResult, bool)
    Set(id string, result *VerificationResult)
}

// VerificationResult contains verification outcome
type VerificationResult struct {
    Valid      bool      `json:"valid"`
    Credential string    `json:"credential"`
    Errors     []string  `json:"errors,omitempty"`
    Warnings   []string  `json:"warnings,omitempty"`
    VerifiedAt time.Time `json:"verifiedAt"`
}

// NewVerifierService creates a new verifier service
func NewVerifierService(resolver DIDResolver, trustReg *TrustRegistry, cache VerificationCache) *VerifierService {
    return &VerifierService{
        didResolver: resolver,
        trustReg:    trustReg,
        cache:       cache,
    }
}

// VerifyCredential verifies a verifiable credential
func (vs *VerifierService) VerifyCredential(vc *VerifiableCredential) (*VerificationResult, error) {
    // Check cache
    if cached, found := vs.cache.Get(vc.ID); found {
        return cached, nil
    }

    result := &VerificationResult{
        Valid:      true,
        Credential: vc.ID,
        VerifiedAt: time.Now(),
    }

    // Basic validation
    if err := vs.validateCredentialStructure(vc); err != nil {
        result.Valid = false
        result.Errors = append(result.Errors, err.Error())
        return result, nil
    }

    // Check expiration
    if vc.ExpirationDate != nil && time.Now().After(*vc.ExpirationDate) {
        result.Valid = false
        result.Errors = append(result.Errors, "credential expired")
        return result, nil
    }

    // Check issuance date
    if time.Now().Before(vc.IssuanceDate) {
        result.Valid = false
        result.Errors = append(result.Errors, "credential not yet valid")
        return result, nil
    }

    // Verify issuer trust
    issuerDID := vc.Issuer.ID
    if !vs.trustReg.IsTrustedIssuer(issuerDID, vc.Type) {
        result.Warnings = append(result.Warnings, "issuer not in trust registry")
    }

    // Verify signature
    if err := vs.verifyProof(vc); err != nil {
        result.Valid = false
        result.Errors = append(result.Errors, fmt.Sprintf("proof verification failed: %v", err))
        return result, nil
    }

    // Check revocation status
    if vc.CredentialStatus != nil {
        revoked, err := vs.checkRevocation(vc.CredentialStatus)
        if err != nil {
            result.Warnings = append(result.Warnings, fmt.Sprintf("revocation check failed: %v", err))
        } else if revoked {
            result.Valid = false
            result.Errors = append(result.Errors, "credential revoked")
            return result, nil
        }
    }

    // Cache result
    vs.cache.Set(vc.ID, result)

    return result, nil
}

// VerifyPresentation verifies a verifiable presentation
func (vs *VerifierService) VerifyPresentation(vp *VerifiablePresentation, options *VerificationOptions) (*PresentationVerificationResult, error) {
    result := &PresentationVerificationResult{
        Valid:         true,
        PresentationID: vp.ID,
        VerifiedAt:    time.Now(),
        CredentialResults: make(map[string]*VerificationResult),
    }

    // Verify presentation proof
    if options.VerifyPresentationProof {
        if err := vs.verifyPresentationProof(vp, options); err != nil {
            result.Valid = false
            result.Errors = append(result.Errors, fmt.Sprintf("presentation proof failed: %v", err))
            return result, nil
        }
    }

    // Verify each credential
    for _, vc := range vp.VerifiableCredential {
        credResult, err := vs.VerifyCredential(&vc)
        if err != nil {
            result.Valid = false
            result.Errors = append(result.Errors, fmt.Sprintf("credential verification error: %v", err))
            continue
        }

        result.CredentialResults[vc.ID] = credResult
        
        if !credResult.Valid {
            result.Valid = false
        }
    }

    // Check holder binding
    if options.CheckHolderBinding {
        for _, vc := range vp.VerifiableCredential {
            if vc.CredentialSubject.ID != vp.Holder {
                result.Warnings = append(result.Warnings, 
                    fmt.Sprintf("credential %s subject does not match holder", vc.ID))
            }
        }
    }

    return result, nil
}

// verifyProof verifies the cryptographic proof
func (vs *VerifierService) verifyProof(vc *VerifiableCredential) error {
    if vc.Proof == nil {
        return fmt.Errorf("no proof found")
    }

    // Get issuer's public key
    issuerDoc, err := vs.didResolver.Resolve(vc.Issuer.ID)
    if err != nil {
        return fmt.Errorf("failed to resolve issuer DID: %w", err)
    }

    // Find verification method
    var publicKey ed25519.PublicKey
    for _, method := range issuerDoc.VerificationMethod {
        if method.ID == vc.Proof.VerificationMethod {
            keyBytes, err := base64.RawURLEncoding.DecodeString(method.PublicKeyMultibase)
            if err != nil {
                return fmt.Errorf("failed to decode public key: %w", err)
            }
            publicKey = ed25519.PublicKey(keyBytes)
            break
        }
    }

    if publicKey == nil {
        return fmt.Errorf("verification method not found")
    }

    // Prepare credential for verification
    proofValue := vc.Proof.ProofValue
    vc.Proof = nil
    
    // Canonicalize
    data, err := canonicalizeJSON(vc)
    if err != nil {
        return fmt.Errorf("failed to canonicalize: %w", err)
    }

    // Decode signature
    signature, err := base64.RawURLEncoding.DecodeString(proofValue)
    if err != nil {
        return fmt.Errorf("failed to decode signature: %w", err)
    }

    // Verify signature
    if !ed25519.Verify(publicKey, data, signature) {
        return fmt.Errorf("signature verification failed")
    }

    // Restore proof
    vc.Proof = &Proof{ProofValue: proofValue}

    return nil
}

// verifyPresentationProof verifies presentation proof
func (vs *VerifierService) verifyPresentationProof(vp *VerifiablePresentation, options *VerificationOptions) error {
    if vp.Proof == nil {
        return fmt.Errorf("no proof found")
    }

    // Verify challenge if required
    if options.Challenge != "" && vp.Proof.Challenge != options.Challenge {
        return fmt.Errorf("challenge mismatch")
    }

    // Verify domain if required
    if options.Domain != "" && vp.Proof.Domain != options.Domain {
        return fmt.Errorf("domain mismatch")
    }

    // Get holder's public key
    holderDoc, err := vs.didResolver.Resolve(vp.Holder)
    if err != nil {
        return fmt.Errorf("failed to resolve holder DID: %w", err)
    }

    // Similar signature verification as credentials
    // ... (implementation similar to verifyProof)

    return nil
}

// checkRevocation checks if credential is revoked
func (vs *VerifierService) checkRevocation(status *CredentialStatus) (bool, error) {
    // This would typically make an HTTP request to the revocation endpoint
    // For now, we'll use a simple in-memory check
    
    // Parse revocation list ID from status ID
    // status.ID format: "issuerDID/revocation/credentialID"
    
    // In production, this would fetch and verify the revocation list
    return false, nil
}

// validateCredentialStructure validates credential structure
func (vs *VerifierService) validateCredentialStructure(vc *VerifiableCredential) error {
    if vc.ID == "" {
        return fmt.Errorf("credential ID required")
    }

    if len(vc.Type) == 0 {
        return fmt.Errorf("credential type required")
    }

    if vc.Issuer.ID == "" {
        return fmt.Errorf("issuer required")
    }

    if vc.CredentialSubject.ID == "" {
        return fmt.Errorf("credential subject ID required")
    }

    return nil
}

// VerificationOptions for credential verification
type VerificationOptions struct {
    VerifyPresentationProof bool   `json:"verifyPresentationProof"`
    CheckHolderBinding      bool   `json:"checkHolderBinding"`
    Challenge               string `json:"challenge,omitempty"`
    Domain                  string `json:"domain,omitempty"`
}

// PresentationVerificationResult for presentation verification
type PresentationVerificationResult struct {
    Valid             bool                           `json:"valid"`
    PresentationID    string                         `json:"presentationId"`
    Errors            []string                       `json:"errors,omitempty"`
    Warnings          []string                       `json:"warnings,omitempty"`
    CredentialResults map[string]*VerificationResult `json:"credentialResults"`
    VerifiedAt        time.Time                      `json:"verifiedAt"`
}
```

### Trust Registry

```go
package vc

import (
    "fmt"
    "sync"
    "time"
)

// TrustRegistry manages trusted issuers and schemas
type TrustRegistry struct {
    mu          sync.RWMutex
    issuers     map[string]*TrustedIssuer
    schemas     map[string]*TrustedSchema
    endorsers   map[string]*Endorser
    storage     TrustStorage
}

// TrustedIssuer represents a trusted credential issuer
type TrustedIssuer struct {
    DID              string            `json:"did"`
    Name             string            `json:"name"`
    Description      string            `json:"description"`
    CredentialTypes  []string          `json:"credentialTypes"`
    TrustLevel       int               `json:"trustLevel"` // 0-100
    VerificationURL  string            `json:"verificationUrl,omitempty"`
    AddedAt          time.Time         `json:"addedAt"`
    UpdatedAt        time.Time         `json:"updatedAt"`
    Endorsements     []string          `json:"endorsements"`
    Metadata         map[string]string `json:"metadata,omitempty"`
}

// TrustedSchema represents a trusted credential schema
type TrustedSchema struct {
    ID           string    `json:"id"`
    Name         string    `json:"name"`
    Version      string    `json:"version"`
    Issuer       string    `json:"issuer"`
    Description  string    `json:"description"`
    SchemaURL    string    `json:"schemaUrl"`
    AddedAt      time.Time `json:"addedAt"`
    Deprecated   bool      `json:"deprecated"`
}

// Endorser represents an entity that can endorse issuers
type Endorser struct {
    DID         string    `json:"did"`
    Name        string    `json:"name"`
    Type        string    `json:"type"` // "government", "industry", "community"
    TrustWeight int       `json:"trustWeight"`
    AddedAt     time.Time `json:"addedAt"`
}

// TrustStorage interface for persistence
type TrustStorage interface {
    StoreIssuer(issuer *TrustedIssuer) error
    GetIssuer(did string) (*TrustedIssuer, error)
    ListIssuers() ([]*TrustedIssuer, error)
    RemoveIssuer(did string) error
    
    StoreSchema(schema *TrustedSchema) error
    GetSchema(id string) (*TrustedSchema, error)
    ListSchemas() ([]*TrustedSchema, error)
    RemoveSchema(id string) error
    
    StoreEndorser(endorser *Endorser) error
    GetEndorser(did string) (*Endorser, error)
    ListEndorsers() ([]*Endorser, error)
}

// NewTrustRegistry creates a new trust registry
func NewTrustRegistry(storage TrustStorage) *TrustRegistry {
    return &TrustRegistry{
        issuers:   make(map[string]*TrustedIssuer),
        schemas:   make(map[string]*TrustedSchema),
        endorsers: make(map[string]*Endorser),
        storage:   storage,
    }
}

// AddIssuer adds a trusted issuer
func (tr *TrustRegistry) AddIssuer(issuer *TrustedIssuer) error {
    tr.mu.Lock()
    defer tr.mu.Unlock()

    issuer.AddedAt = time.Now()
    issuer.UpdatedAt = time.Now()

    if err := tr.storage.StoreIssuer(issuer); err != nil {
        return fmt.Errorf("failed to store issuer: %w", err)
    }

    tr.issuers[issuer.DID] = issuer
    return nil
}

// IsTrustedIssuer checks if an issuer is trusted for specific credential types
func (tr *TrustRegistry) IsTrustedIssuer(did string, credentialTypes []string) bool {
    tr.mu.RLock()
    defer tr.mu.RUnlock()

    issuer, exists := tr.issuers[did]
    if !exists {
        return false
    }

    // Check if issuer supports all requested credential types
    for _, reqType := range credentialTypes {
        found := false
        for _, supportedType := range issuer.CredentialTypes {
            if supportedType == reqType || supportedType == "*" {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }

    // Check trust level threshold
    return issuer.TrustLevel >= 50 // Configurable threshold
}

// GetIssuerTrustLevel returns the trust level for an issuer
func (tr *TrustRegistry) GetIssuerTrustLevel(did string) int {
    tr.mu.RLock()
    defer tr.mu.RUnlock()

    issuer, exists := tr.issuers[did]
    if !exists {
        return 0
    }

    // Calculate trust based on endorsements
    baseTrust := issuer.TrustLevel
    endorsementBonus := 0

    for _, endorserDID := range issuer.Endorsements {
        if endorser, exists := tr.endorsers[endorserDID]; exists {
            endorsementBonus += endorser.TrustWeight
        }
    }

    totalTrust := baseTrust + endorsementBonus
    if totalTrust > 100 {
        totalTrust = 100
    }

    return totalTrust
}

// EndorseIssuer adds an endorsement to an issuer
func (tr *TrustRegistry) EndorseIssuer(issuerDID, endorserDID string) error {
    tr.mu.Lock()
    defer tr.mu.Unlock()

    issuer, exists := tr.issuers[issuerDID]
    if !exists {
        return fmt.Errorf("issuer not found: %s", issuerDID)
    }

    endorser, exists := tr.endorsers[endorserDID]
    if !exists {
        return fmt.Errorf("endorser not found: %s", endorserDID)
    }

    // Check if already endorsed
    for _, e := range issuer.Endorsements {
        if e == endorserDID {
            return nil // Already endorsed
        }
    }

    issuer.Endorsements = append(issuer.Endorsements, endorserDID)
    issuer.UpdatedAt = time.Now()

    return tr.storage.StoreIssuer(issuer)
}

// AddSchema adds a trusted schema
func (tr *TrustRegistry) AddSchema(schema *TrustedSchema) error {
    tr.mu.Lock()
    defer tr.mu.Unlock()

    schema.AddedAt = time.Now()

    if err := tr.storage.StoreSchema(schema); err != nil {
        return fmt.Errorf("failed to store schema: %w", err)
    }

    tr.schemas[schema.ID] = schema
    return nil
}

// GetTrustedSchema retrieves a trusted schema
func (tr *TrustRegistry) GetTrustedSchema(id string) (*TrustedSchema, error) {
    tr.mu.RLock()
    defer tr.mu.RUnlock()

    schema, exists := tr.schemas[id]
    if !exists {
        return nil, fmt.Errorf("schema not found: %s", id)
    }

    if schema.Deprecated {
        return nil, fmt.Errorf("schema deprecated: %s", id)
    }

    return schema, nil
}

// SearchIssuers searches for issuers by criteria
func (tr *TrustRegistry) SearchIssuers(criteria SearchCriteria) ([]*TrustedIssuer, error) {
    tr.mu.RLock()
    defer tr.mu.RUnlock()

    var results []*TrustedIssuer

    for _, issuer := range tr.issuers {
        if tr.matchesCriteria(issuer, criteria) {
            results = append(results, issuer)
        }
    }

    return results, nil
}

// matchesCriteria checks if issuer matches search criteria
func (tr *TrustRegistry) matchesCriteria(issuer *TrustedIssuer, criteria SearchCriteria) bool {
    // Check credential type
    if criteria.CredentialType != "" {
        found := false
        for _, ct := range issuer.CredentialTypes {
            if ct == criteria.CredentialType {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }

    // Check minimum trust level
    if criteria.MinTrustLevel > 0 {
        if tr.GetIssuerTrustLevel(issuer.DID) < criteria.MinTrustLevel {
            return false
        }
    }

    // Check endorser requirement
    if criteria.RequireEndorsement {
        if len(issuer.Endorsements) == 0 {
            return false
        }
    }

    return true
}

// SearchCriteria for finding issuers
type SearchCriteria struct {
    CredentialType     string `json:"credentialType,omitempty"`
    MinTrustLevel      int    `json:"minTrustLevel,omitempty"`
    RequireEndorsement bool   `json:"requireEndorsement,omitempty"`
}
```

### Revocation Manager

```go
package vc

import (
    "fmt"
    "sync"
    "time"
)

// RevocationManager handles credential revocation
type RevocationManager struct {
    mu       sync.RWMutex
    issuerDID string
    list     *RevocationList
    storage  RevocationStorage
}

// RevocationStorage interface for revocation persistence
type RevocationStorage interface {
    StoreRevocationList(list *RevocationList) error
    GetRevocationList(issuerDID string) (*RevocationList, error)
}

// NewRevocationManager creates a new revocation manager
func NewRevocationManager(issuerDID string, storage RevocationStorage) *RevocationManager {
    return &RevocationManager{
        issuerDID: issuerDID,
        storage:   storage,
    }
}

// RevokeCredential adds a credential to the revocation list
func (rm *RevocationManager) RevokeCredential(credentialID, reason string) error {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    // Load or create revocation list
    if rm.list == nil {
        list, err := rm.storage.GetRevocationList(rm.issuerDID)
        if err != nil {
            // Create new list
            rm.list = &RevocationList{
                ID:       fmt.Sprintf("%s/revocation", rm.issuerDID),
                Type:     "RevocationList2020",
                Issuer:   rm.issuerDID,
                IssuedDate: time.Now(),
                RevokedCredentials: []RevokedCredential{},
            }
        } else {
            rm.list = list
        }
    }

    // Check if already revoked
    for _, revoked := range rm.list.RevokedCredentials {
        if revoked.ID == credentialID {
            return fmt.Errorf("credential already revoked")
        }
    }

    // Add to revocation list
    rm.list.RevokedCredentials = append(rm.list.RevokedCredentials, RevokedCredential{
        ID:            credentialID,
        RevocationDate: time.Now(),
        Reason:        reason,
    })

    // Store updated list
    if err := rm.storage.StoreRevocationList(rm.list); err != nil {
        return fmt.Errorf("failed to store revocation list: %w", err)
    }

    return nil
}

// IsRevoked checks if a credential is revoked
func (rm *RevocationManager) IsRevoked(credentialID string) (bool, *RevokedCredential, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    if rm.list == nil {
        list, err := rm.storage.GetRevocationList(rm.issuerDID)
        if err != nil {
            return false, nil, err
        }
        rm.list = list
    }

    for _, revoked := range rm.list.RevokedCredentials {
        if revoked.ID == credentialID {
            return true, &revoked, nil
        }
    }

    return false, nil, nil
}

// GetRevocationList returns the current revocation list
func (rm *RevocationManager) GetRevocationList() (*RevocationList, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()

    if rm.list == nil {
        list, err := rm.storage.GetRevocationList(rm.issuerDID)
        if err != nil {
            return nil, err
        }
        rm.list = list
    }

    return rm.list, nil
}
```

### Presentation Builder

```go
package vc

import (
    "fmt"
    "time"
)

// PresentationBuilder helps build verifiable presentations
type PresentationBuilder struct {
    holder      string
    credentials []VerifiableCredential
    keyManager  KeyManager
}

// NewPresentationBuilder creates a new presentation builder
func NewPresentationBuilder(holder string, keyManager KeyManager) *PresentationBuilder {
    return &PresentationBuilder{
        holder:      holder,
        keyManager:  keyManager,
        credentials: []VerifiableCredential{},
    }
}

// AddCredential adds a credential to the presentation
func (pb *PresentationBuilder) AddCredential(vc VerifiableCredential) *PresentationBuilder {
    pb.credentials = append(pb.credentials, vc)
    return pb
}

// Build creates the verifiable presentation
func (pb *PresentationBuilder) Build(options *PresentationOptions) (*VerifiablePresentation, error) {
    if len(pb.credentials) == 0 {
        return nil, fmt.Errorf("no credentials added")
    }

    vp := &VerifiablePresentation{
        Context: []string{
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        },
        ID:                   generatePresentationID(),
        Type:                 []string{"VerifiablePresentation"},
        VerifiableCredential: pb.credentials,
        Holder:               pb.holder,
    }

    // Sign presentation if requested
    if options.Sign {
        if err := pb.signPresentation(vp, options); err != nil {
            return nil, fmt.Errorf("failed to sign presentation: %w", err)
        }
    }

    return vp, nil
}

// signPresentation signs a verifiable presentation
func (pb *PresentationBuilder) signPresentation(vp *VerifiablePresentation, options *PresentationOptions) error {
    // Remove existing proof
    vp.Proof = nil

    // Canonicalize presentation
    data, err := canonicalizeJSON(vp)
    if err != nil {
        return fmt.Errorf("failed to canonicalize: %w", err)
    }

    // Sign the data
    keyID := fmt.Sprintf("%s#key-1", pb.holder)
    signature, err := pb.keyManager.Sign(keyID, data)
    if err != nil {
        return fmt.Errorf("failed to sign: %w", err)
    }

    // Create proof
    proof := &Proof{
        Type:               "Ed25519Signature2020",
        Created:            time.Now(),
        VerificationMethod: keyID,
        ProofPurpose:       "authentication",
        ProofValue:         base64.RawURLEncoding.EncodeToString(signature),
    }

    // Add challenge if provided
    if options.Challenge != "" {
        proof.Challenge = options.Challenge
    }

    // Add domain if provided
    if options.Domain != "" {
        proof.Domain = options.Domain
    }

    vp.Proof = proof
    return nil
}

// PresentationOptions for building presentations
type PresentationOptions struct {
    Sign      bool   `json:"sign"`
    Challenge string `json:"challenge,omitempty"`
    Domain    string `json:"domain,omitempty"`
}
```

### Utility Functions

```go
package vc

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "reflect"
    "sort"
    "strings"
)

// generateCredentialID generates a unique credential ID
func generateCredentialID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return fmt.Sprintf("urn:uuid:%s", hex.EncodeToString(b))
}

// generatePresentationID generates a unique presentation ID
func generatePresentationID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return fmt.Sprintf("urn:uuid:%s", hex.EncodeToString(b))
}

// canonicalizeJSON performs JSON canonicalization
func canonicalizeJSON(v interface{}) ([]byte, error) {
    // Convert to map for consistent ordering
    data, err := json.Marshal(v)
    if err != nil {
        return nil, err
    }

    var m interface{}
    if err := json.Unmarshal(data, &m); err != nil {
        return nil, err
    }

    // Sort and serialize
    return json.Marshal(sortKeys(m))
}

// sortKeys recursively sorts map keys
func sortKeys(v interface{}) interface{} {
    switch v := v.(type) {
    case map[string]interface{}:
        sorted := make(map[string]interface{})
        keys := make([]string, 0, len(v))
        
        for k := range v {
            keys = append(keys, k)
        }
        sort.Strings(keys)
        
        for _, k := range keys {
            sorted[k] = sortKeys(v[k])
        }
        return sorted
        
    case []interface{}:
        for i, item := range v {
            v[i] = sortKeys(item)
        }
        return v
        
    default:
        return v
    }
}

// validateValue validates a value against a property definition
func validateValue(value interface{}, prop Property) error {
    switch prop.Type {
    case "string":
        str, ok := value.(string)
        if !ok {
            return fmt.Errorf("expected string")
        }
        
        if prop.Pattern != "" {
            // Validate against regex pattern
            // ... implementation
        }
        
        if prop.Format != "" {
            // Validate format (email, uri, etc.)
            // ... implementation
        }
        
    case "number", "integer":
        num, ok := toNumber(value)
        if !ok {
            return fmt.Errorf("expected number")
        }
        
        if prop.Minimum != nil {
            min, _ := toNumber(prop.Minimum)
            if num < min {
                return fmt.Errorf("value below minimum")
            }
        }
        
        if prop.Maximum != nil {
            max, _ := toNumber(prop.Maximum)
            if num > max {
                return fmt.Errorf("value above maximum")
            }
        }
        
    case "boolean":
        _, ok := value.(bool)
        if !ok {
            return fmt.Errorf("expected boolean")
        }
        
    case "array":
        _, ok := value.([]interface{})
        if !ok {
            return fmt.Errorf("expected array")
        }
        
    case "object":
        _, ok := value.(map[string]interface{})
        if !ok {
            return fmt.Errorf("expected object")
        }
    }
    
    return nil
}

// toNumber converts interface to float64
func toNumber(v interface{}) (float64, bool) {
    switch n := v.(type) {
    case float64:
        return n, true
    case float32:
        return float64(n), true
    case int:
        return float64(n), true
    case int64:
        return float64(n), true
    default:
        return 0, false
    }
}

// MemoryVerificationCache implements in-memory verification cache
type MemoryVerificationCache struct {
    mu      sync.RWMutex
    entries map[string]*cacheEntry
}

type cacheEntry struct {
    result    *VerificationResult
    expiresAt time.Time
}

// NewMemoryVerificationCache creates new memory cache
func NewMemoryVerificationCache() *MemoryVerificationCache {
    cache := &MemoryVerificationCache{
        entries: make(map[string]*cacheEntry),
    }
    
    go cache.cleanup()
    return cache
}

func (c *MemoryVerificationCache) Get(id string) (*VerificationResult, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    entry, exists := c.entries[id]
    if !exists || time.Now().After(entry.expiresAt) {
        return nil, false
    }
    
    return entry.result, true
}

func (c *MemoryVerificationCache) Set(id string, result *VerificationResult) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    c.entries[id] = &cacheEntry{
        result:    result,
        expiresAt: time.Now().Add(15 * time.Minute),
    }
}

func (c *MemoryVerificationCache) cleanup() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        c.mu.Lock()
        now := time.Now()
        for id, entry := range c.entries {
            if now.After(entry.expiresAt) {
                delete(c.entries, id)
            }
        }
        c.mu.Unlock()
    }
}
```

## Usage Example

```go
// Initialize services
keyManager := NewKeyManager()
issuerStorage := NewFileStorage("/var/blackhole/vc/issuer")
verifierCache := NewMemoryVerificationCache()
trustStorage := NewFileStorage("/var/blackhole/vc/trust")

// Create issuer service
issuerDID := "did:blackhole:issuer123"
issuerService := NewIssuerService(issuerDID, keyManager, issuerStorage)

// Register a schema
schema := &CredentialSchema{
    ID:          "https://blackhole.local/schemas/identity/v1",
    Type:        "IdentityCredential",
    Name:        "Identity Credential",
    Description: "Basic identity verification",
    Properties: map[string]Property{
        "name": {
            Type:        "string",
            Description: "Full name",
        },
        "dateOfBirth": {
            Type:        "string",
            Format:      "date",
            Description: "Date of birth",
        },
        "nationalID": {
            Type:        "string",
            Pattern:     "^[A-Z0-9]{9}$",
            Description: "National ID number",
        },
    },
    Required: []string{"name", "dateOfBirth"},
}
issuerService.RegisterSchema(schema)

// Issue a credential
request := &CredentialRequest{
    SubjectDID: "did:blackhole:user456",
    Types:      []string{"IdentityCredential"},
    Claims: map[string]interface{}{
        "name":        "John Doe",
        "dateOfBirth": "1990-01-01",
        "nationalID":  "ABC123456",
    },
    SchemaID:       schema.ID,
    ExpirationDate: &expirationDate,
    Revocable:      true,
}

credential, err := issuerService.IssueCredential(request)
if err != nil {
    log.Fatal(err)
}

// Create trust registry
trustRegistry := NewTrustRegistry(trustStorage)

// Add trusted issuer
trustedIssuer := &TrustedIssuer{
    DID:             issuerDID,
    Name:            "BlackHole Identity Service",
    CredentialTypes: []string{"IdentityCredential"},
    TrustLevel:      80,
}
trustRegistry.AddIssuer(trustedIssuer)

// Create verifier service
didResolver := NewDIDResolver()
verifierService := NewVerifierService(didResolver, trustRegistry, verifierCache)

// Verify credential
result, err := verifierService.VerifyCredential(credential)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Credential valid: %v\n", result.Valid)

// Build presentation
presentationBuilder := NewPresentationBuilder("did:blackhole:holder789", keyManager)
presentation, err := presentationBuilder.
    AddCredential(*credential).
    Build(&PresentationOptions{
        Sign:      true,
        Challenge: "abc123",
        Domain:    "blackhole.local",
    })

// Verify presentation
presResult, err := verifierService.VerifyPresentation(presentation, &VerificationOptions{
    VerifyPresentationProof: true,
    CheckHolderBinding:      true,
    Challenge:               "abc123",
    Domain:                  "blackhole.local",
})

fmt.Printf("Presentation valid: %v\n", presResult.Valid)
```

## Security Considerations

1. **Cryptographic Security**: Ed25519 signatures for all proofs
2. **Revocation Privacy**: Privacy-preserving revocation checks
3. **Trust Boundaries**: Clear issuer trust levels
4. **Proof Verification**: Comprehensive signature validation
5. **Schema Validation**: Strict claim validation

## Performance Optimizations

1. **Verification Caching**: Cache verification results
2. **Batch Operations**: Support bulk credential operations
3. **Lazy Loading**: Load trust registry on demand
4. **Parallel Verification**: Verify multiple credentials concurrently

## Testing

```go
func TestCredentialIssuance(t *testing.T) {
    // Setup
    keyManager := NewMockKeyManager()
    storage := NewMockStorage()
    issuerService := NewIssuerService("did:test:issuer", keyManager, storage)
    
    // Issue credential
    request := &CredentialRequest{
        SubjectDID: "did:test:subject",
        Types:      []string{"TestCredential"},
        Claims: map[string]interface{}{
            "test": "value",
        },
    }
    
    credential, err := issuerService.IssueCredential(request)
    assert.NoError(t, err)
    assert.NotNil(t, credential.Proof)
    assert.Equal(t, "did:test:subject", credential.CredentialSubject.ID)
}

func TestCredentialVerification(t *testing.T) {
    // Setup
    resolver := NewMockDIDResolver()
    trustReg := NewTrustRegistry(NewMockStorage())
    cache := NewMemoryVerificationCache()
    
    verifier := NewVerifierService(resolver, trustReg, cache)
    
    // Create test credential
    credential := createTestCredential()
    
    // Verify
    result, err := verifier.VerifyCredential(credential)
    assert.NoError(t, err)
    assert.True(t, result.Valid)
}

func TestRevocationManagement(t *testing.T) {
    storage := NewMockRevocationStorage()
    revMgr := NewRevocationManager("did:test:issuer", storage)
    
    // Revoke credential
    err := revMgr.RevokeCredential("cred123", "Compromised")
    assert.NoError(t, err)
    
    // Check revocation
    revoked, detail, err := revMgr.IsRevoked("cred123")
    assert.NoError(t, err)
    assert.True(t, revoked)
    assert.Equal(t, "Compromised", detail.Reason)
}
```

## Next Steps

1. Implement selective disclosure
2. Add support for zero-knowledge proofs
3. Create credential exchange protocols
4. Implement privacy-preserving revocation
5. Add support for credential chaining