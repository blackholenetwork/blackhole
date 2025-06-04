package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// SecurityPlugin implements security functionality as a plugin
type SecurityPlugin struct {
	mu         sync.RWMutex
	config     plugin.Config
	keyPair    *KeyPair
	identities map[string]*Identity
	started    bool
}

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// Identity represents a node's identity
type Identity struct {
	ID        string
	PublicKey ed25519.PublicKey
	DID       string
	CreatedAt time.Time
}

// NewSecurityPlugin creates a new security plugin
func NewSecurityPlugin() *SecurityPlugin {
	return &SecurityPlugin{
		identities: make(map[string]*Identity),
	}
}

// Info returns metadata about the plugin
func (sp *SecurityPlugin) Info() plugin.Info {
	return plugin.Info{
		Name:         "security",
		Version:      "1.0.0",
		Description:  "Provides authentication, authorization, and DID management",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{}, // No dependencies
		Capabilities: []string{
			string(plugin.CapabilitySecurity),
		},
	}
}

// Init initializes the plugin with configuration
func (sp *SecurityPlugin) Init(ctx context.Context, config plugin.Config) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	sp.config = config

	// Generate or load node key pair
	if err := sp.initializeKeyPair(); err != nil {
		return fmt.Errorf("failed to initialize key pair: %w", err)
	}

	// Create node identity
	if err := sp.createNodeIdentity(); err != nil {
		return fmt.Errorf("failed to create node identity: %w", err)
	}

	return nil
}

// Start starts the plugin
func (sp *SecurityPlugin) Start(ctx context.Context) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.started {
		return fmt.Errorf("security plugin already started")
	}

	// Start any background tasks here
	// For now, just mark as started
	sp.started = true

	return nil
}

// Stop gracefully shuts down the plugin
func (sp *SecurityPlugin) Stop(ctx context.Context) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if !sp.started {
		return nil
	}

	// Clean up resources
	sp.started = false

	return nil
}

// Health returns the current health status
func (sp *SecurityPlugin) Health() plugin.Health {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	if !sp.started {
		return plugin.Health{
			Status:    plugin.HealthStatusUnhealthy,
			Message:   "Security plugin not started",
			LastCheck: time.Now(),
		}
	}

	return plugin.Health{
		Status:    plugin.HealthStatusHealthy,
		Message:   "Security plugin is operational",
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"identities_count": len(sp.identities),
			"has_keypair":      sp.keyPair != nil,
		},
	}
}

// Plugin-specific methods

// GenerateIdentity generates a new identity
func (sp *SecurityPlugin) GenerateIdentity() (*Identity, error) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	// Generate new key pair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create identity
	id := base64.URLEncoding.EncodeToString(pub[:8])
	did := fmt.Sprintf("did:key:%s", base64.URLEncoding.EncodeToString(pub))

	identity := &Identity{
		ID:        id,
		PublicKey: pub,
		DID:       did,
		CreatedAt: time.Now(),
	}

	// Store identity
	sp.identities[id] = identity

	return identity, nil
}

// GetIdentity retrieves an identity by ID
func (sp *SecurityPlugin) GetIdentity(id string) (*Identity, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	identity, exists := sp.identities[id]
	if !exists {
		return nil, fmt.Errorf("identity not found: %s", id)
	}

	return identity, nil
}

// SignData signs data with the node's private key
func (sp *SecurityPlugin) SignData(data []byte) ([]byte, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	if sp.keyPair == nil {
		return nil, fmt.Errorf("no key pair available")
	}

	signature := ed25519.Sign(sp.keyPair.PrivateKey, data)
	return signature, nil
}

// VerifySignature verifies a signature
func (sp *SecurityPlugin) VerifySignature(publicKey ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

// Private methods

func (sp *SecurityPlugin) initializeKeyPair() error {
	// In a real implementation, this would load from disk if exists
	// For now, generate new
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sp.keyPair = &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}

	return nil
}

func (sp *SecurityPlugin) createNodeIdentity() error {
	if sp.keyPair == nil {
		return fmt.Errorf("no key pair available")
	}

	id := base64.URLEncoding.EncodeToString(sp.keyPair.PublicKey[:8])
	did := fmt.Sprintf("did:key:%s", base64.URLEncoding.EncodeToString(sp.keyPair.PublicKey))

	identity := &Identity{
		ID:        id,
		PublicKey: sp.keyPair.PublicKey,
		DID:       did,
		CreatedAt: time.Now(),
	}

	sp.identities[id] = identity

	return nil
}

// Ensure SecurityPlugin implements the Plugin interface
var _ plugin.Plugin = (*SecurityPlugin)(nil)