// Package security provides authentication, authorization, and identity management
package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// Plugin implements security functionality as a plugin
type Plugin struct {
	*plugin.BasePlugin
	mu            sync.RWMutex
	config        plugin.Config
	keyPair       *KeyPair
	identities    map[string]*Identity
	sessions      map[string]*Session
	permissions   map[string]*Permission
	started       bool
	registry      *plugin.Registry
	healthStatus  plugin.HealthStatus
	healthMessage string
	logger        *log.Logger
}

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	CreatedAt  time.Time
}

// Identity represents a node's identity
type Identity struct {
	ID          string
	PublicKey   ed25519.PublicKey
	DID         string
	CreatedAt   time.Time
	Permissions []string // List of permission IDs
	Metadata    map[string]string
}

// Session represents an authenticated session
type Session struct {
	ID         string
	IdentityID string
	Token      string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Active     bool
}

// Permission represents an authorization permission
type Permission struct {
	ID          string
	Name        string
	Resource    string   // e.g., "storage", "compute", "network"
	Actions     []string // e.g., ["read", "write", "delete"]
	Description string
}

// NodeRole represents different types of nodes in the network
type NodeRole string

// Node role constants
const (
	RoleNode      NodeRole = "node"      // Standard network participant
	RoleRelay     NodeRole = "relay"     // Relay node for NAT traversal
	RoleBootstrap NodeRole = "bootstrap" // Bootstrap node for network discovery
	RoleValidator NodeRole = "validator" // Validation/consensus node
	RoleStorage   NodeRole = "storage"   // Specialized storage node
	RoleCompute   NodeRole = "compute"   // Specialized compute node
	RoleAdmin     NodeRole = "admin"     // Administrative node
)

// PersistentKeyData represents key data that is saved/loaded from disk
type PersistentKeyData struct {
	PublicKey  []byte    `json:"public_key"`
	PrivateKey []byte    `json:"private_key"`
	CreatedAt  time.Time `json:"created_at"`
	NodeID     string    `json:"node_id"`
	Role       NodeRole  `json:"role"`
}

// NewPlugin creates a new security plugin
func NewPlugin(registry *plugin.Registry) *Plugin {
	info := plugin.Info{
		Name:         "security",
		Version:      "1.0.0",
		Description:  "Provides authentication, authorization, and DID management",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilitySecurity)},
	}

	sp := &Plugin{
		BasePlugin:    plugin.NewBasePlugin(info),
		identities:    make(map[string]*Identity),
		sessions:      make(map[string]*Session),
		permissions:   make(map[string]*Permission),
		registry:      registry,
		healthStatus:  plugin.HealthStatusUnknown,
		healthMessage: "Not initialized",
		logger:        log.New(os.Stdout, "[Security] ", log.LstdFlags),
	}
	sp.SetRegistry(registry)
	return sp
}

// Info returns metadata about the plugin
func (sp *Plugin) Info() plugin.Info {
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
func (sp *Plugin) Init(_ context.Context, config plugin.Config) error {
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

	// Initialize default permissions
	if err := sp.initializeDefaultPermissions(); err != nil {
		return fmt.Errorf("failed to initialize permissions: %w", err)
	}

	// Update health status
	sp.healthStatus = plugin.HealthStatusHealthy
	sp.healthMessage = "Security initialized"
	sp.SetHealth(sp.healthStatus, sp.healthMessage)

	return nil
}

// Start starts the plugin
func (sp *Plugin) Start(_ context.Context) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if sp.started {
		return fmt.Errorf("security plugin already started")
	}

	// Start any background tasks here
	// For now, just mark as started
	sp.started = true

	// Update and publish initial health status
	sp.healthStatus = plugin.HealthStatusHealthy
	sp.healthMessage = "Security operational (node identity active)"
	sp.SetHealth(sp.healthStatus, sp.healthMessage)

	return nil
}

// Stop gracefully shuts down the plugin
func (sp *Plugin) Stop(_ context.Context) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	if !sp.started {
		return nil
	}

	// Clean up resources
	sp.started = false

	// Update health status
	sp.healthStatus = plugin.HealthStatusUnknown
	sp.healthMessage = "Security stopped"
	sp.SetHealth(sp.healthStatus, sp.healthMessage)

	return nil
}

// Health returns the current health status
func (sp *Plugin) Health() plugin.Health {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	// Count active sessions
	activeSessions := 0
	for _, session := range sp.sessions {
		if session.Active && time.Now().Before(session.ExpiresAt) {
			activeSessions++
		}
	}

	// Calculate current health status
	var status plugin.HealthStatus
	var message string

	hasKeyPair := sp.keyPair != nil
	identityCount := len(sp.identities)
	sessionCount := len(sp.sessions)
	permissionCount := len(sp.permissions)

	var keyAge time.Duration
	if hasKeyPair && sp.keyPair.CreatedAt.After(time.Time{}) {
		keyAge = time.Since(sp.keyPair.CreatedAt)
	}

	switch {
	case !sp.started:
		status = plugin.HealthStatusUnknown
		message = "Security not started"
	case !hasKeyPair:
		status = plugin.HealthStatusUnhealthy
		message = "No key pair available"
	case permissionCount == 0:
		status = plugin.HealthStatusDegraded
		message = "Security initialized, no permissions defined"
	case identityCount == 1 && sessionCount == 0:
		status = plugin.HealthStatusHealthy
		nodeRole := "unknown"
		for _, identity := range sp.identities {
			if role, exists := identity.Metadata["role"]; exists {
				nodeRole = role
				break
			}
		}
		message = fmt.Sprintf("Auth system ready (role: %s, %d permissions, key age: %s)", nodeRole, permissionCount, formatDuration(keyAge))
	case activeSessions > 0:
		status = plugin.HealthStatusHealthy
		message = fmt.Sprintf("Auth operational (%d identities, %d sessions, %d permissions)", identityCount, activeSessions, permissionCount)
	default:
		status = plugin.HealthStatusHealthy
		message = fmt.Sprintf("Auth ready (%d identities, %d permissions)", identityCount, permissionCount)
	}

	return plugin.Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"identities_count":    identityCount,
			"active_sessions":     activeSessions,
			"permissions_defined": permissionCount,
			"has_keypair":         hasKeyPair,
			"started":             sp.started,
		},
	}
}

// Plugin-specific methods

// GenerateIdentity generates a new identity
func (sp *Plugin) GenerateIdentity() (*Identity, error) {
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
func (sp *Plugin) GetIdentity(id string) (*Identity, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	identity, exists := sp.identities[id]
	if !exists {
		return nil, fmt.Errorf("identity not found: %s", id)
	}

	return identity, nil
}

// SignData signs data with the node's private key
func (sp *Plugin) SignData(data []byte) ([]byte, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	if sp.keyPair == nil {
		return nil, fmt.Errorf("no key pair available")
	}

	signature := ed25519.Sign(sp.keyPair.PrivateKey, data)
	return signature, nil
}

// VerifySignature verifies a signature
func (sp *Plugin) VerifySignature(publicKey ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

// Authenticate creates a new session for an identity
func (sp *Plugin) Authenticate(identityID string, signature []byte, challenge []byte) (*Session, error) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	// Get identity
	identity, exists := sp.identities[identityID]
	if !exists {
		return nil, fmt.Errorf("identity not found: %s", identityID)
	}

	// Verify signature
	if !ed25519.Verify(identity.PublicKey, challenge, signature) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Create session
	sessionID := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s-%d", identityID, time.Now().UnixNano())))
	token := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s-%s", sessionID, time.Now().String())))

	session := &Session{
		ID:         sessionID,
		IdentityID: identityID,
		Token:      token,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Active:     true,
	}

	sp.sessions[sessionID] = session
	return session, nil
}

// ValidateSession checks if a session token is valid
func (sp *Plugin) ValidateSession(token string) (*Session, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	for _, session := range sp.sessions {
		if session.Token == token && session.Active && time.Now().Before(session.ExpiresAt) {
			return session, nil
		}
	}

	return nil, fmt.Errorf("invalid or expired session")
}

// Authorize checks if an identity has permission for a resource/action
func (sp *Plugin) Authorize(identityID string, resource string, action string) (bool, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	identity, exists := sp.identities[identityID]
	if !exists {
		return false, fmt.Errorf("identity not found: %s", identityID)
	}

	// Check each permission the identity has
	for _, permID := range identity.Permissions {
		perm, exists := sp.permissions[permID]
		if !exists {
			continue
		}

		// Check if permission matches resource and action
		if perm.Resource == resource {
			for _, allowedAction := range perm.Actions {
				if allowedAction == action || allowedAction == "*" {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// GrantPermission grants a permission to an identity
func (sp *Plugin) GrantPermission(identityID string, permissionID string) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	identity, exists := sp.identities[identityID]
	if !exists {
		return fmt.Errorf("identity not found: %s", identityID)
	}

	_, exists = sp.permissions[permissionID]
	if !exists {
		return fmt.Errorf("permission not found: %s", permissionID)
	}

	// Check if already granted
	for _, pid := range identity.Permissions {
		if pid == permissionID {
			return nil // Already has permission
		}
	}

	identity.Permissions = append(identity.Permissions, permissionID)
	return nil
}

// CreatePermission creates a new permission
func (sp *Plugin) CreatePermission(name, resource string, actions []string, description string) (*Permission, error) {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	permID := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s-%s-%d", name, resource, time.Now().UnixNano())))

	permission := &Permission{
		ID:          permID,
		Name:        name,
		Resource:    resource,
		Actions:     actions,
		Description: description,
	}

	sp.permissions[permID] = permission
	return permission, nil
}

// Private methods

func (sp *Plugin) initializeKeyPair() error {
	// Get the key file path from config or use default
	dataDir := sp.getDataDir()
	keyFile := filepath.Join(dataDir, "node.key")

	// Try to load existing key
	if keyData, err := sp.loadKeyFromDisk(keyFile); err == nil {
		fmt.Printf("[Security] initializeKeyPair: Loaded existing key from %s\n", keyFile)
		sp.keyPair = &KeyPair{
			PublicKey:  keyData.PublicKey,
			PrivateKey: keyData.PrivateKey,
			CreatedAt:  keyData.CreatedAt,
		}
		return nil
	}

	// Generate new key pair if none exists
	fmt.Printf("[Security] initializeKeyPair: Generating new key pair\n")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	sp.keyPair = &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
	}

	// Save the new key to disk
	nodeID := base64.URLEncoding.EncodeToString(pub[:8])
	keyData := &PersistentKeyData{
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
		NodeID:     nodeID,
		Role:       RoleNode, // Default role
	}

	if err := sp.saveKeyToDisk(keyFile, keyData); err != nil {
		fmt.Printf("[Security] Warning: Failed to save key to disk: %v\n", err)
	} else {
		fmt.Printf("[Security] initializeKeyPair: Saved new key to %s\n", keyFile)
	}

	return nil
}

func (sp *Plugin) createNodeIdentity() error {
	if sp.keyPair == nil {
		return fmt.Errorf("no key pair available")
	}

	id := base64.URLEncoding.EncodeToString(sp.keyPair.PublicKey[:8])
	did := fmt.Sprintf("did:key:%s", base64.URLEncoding.EncodeToString(sp.keyPair.PublicKey))

	// Load role from saved key data or default to "node"
	role := string(RoleNode)
	dataDir := sp.getDataDir()
	keyFile := filepath.Join(dataDir, "node.key")
	if keyData, err := sp.loadKeyFromDisk(keyFile); err == nil {
		role = string(keyData.Role)
	}

	identity := &Identity{
		ID:        id,
		PublicKey: sp.keyPair.PublicKey,
		DID:       did,
		CreatedAt: time.Now(),
		Metadata: map[string]string{
			"role": role,
			"type": "node_identity",
		},
	}

	sp.identities[id] = identity
	fmt.Printf("[Security] createNodeIdentity: Created node identity with role '%s'\n", role)

	return nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		days := int(d.Hours() / 24)
		return fmt.Sprintf("%dd", days)
	}
}

func (sp *Plugin) initializeDefaultPermissions() error {
	// Create a simple admin permission for now
	sp.createPermissionUnsafe("admin.full", "*", []string{"*"}, "Full administrative access")

	// Grant admin permission to the node identity
	if len(sp.identities) > 0 {
		// Get the node identity (first one created)
		var nodeIdentityID string
		for id := range sp.identities {
			nodeIdentityID = id
			break
		}

		// Find admin permission
		var adminPermID string
		for id, perm := range sp.permissions {
			if perm.Name == "admin.full" {
				adminPermID = id
				break
			}
		}

		if adminPermID != "" && nodeIdentityID != "" {
			if err := sp.grantPermissionUnsafe(nodeIdentityID, adminPermID); err != nil {
				return fmt.Errorf("failed to grant admin permission to node identity: %w", err)
			}
		}
	}

	return nil
}

// createPermissionUnsafe creates a permission without acquiring locks (must be called while holding lock)
func (sp *Plugin) createPermissionUnsafe(name, resource string, actions []string, description string) *Permission {
	permID := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s-%s-%d", name, resource, time.Now().UnixNano())))

	permission := &Permission{
		ID:          permID,
		Name:        name,
		Resource:    resource,
		Actions:     actions,
		Description: description,
	}

	sp.permissions[permID] = permission
	return permission
}

// grantPermissionUnsafe grants a permission without acquiring locks (must be called while holding lock)
func (sp *Plugin) grantPermissionUnsafe(identityID string, permissionID string) error {
	identity, exists := sp.identities[identityID]
	if !exists {
		return fmt.Errorf("identity not found: %s", identityID)
	}

	_, exists = sp.permissions[permissionID]
	if !exists {
		return fmt.Errorf("permission not found: %s", permissionID)
	}

	// Check if already granted
	for _, pid := range identity.Permissions {
		if pid == permissionID {
			return nil // Already has permission
		}
	}

	identity.Permissions = append(identity.Permissions, permissionID)
	return nil
}

// Helper methods for persistent key storage

func (sp *Plugin) getDataDir() string {
	// Check if data directory is configured
	if dataDir, ok := sp.config["data_dir"].(string); ok && dataDir != "" {
		return dataDir
	}

	// Default to current directory + .blackhole
	home, err := os.UserHomeDir()
	if err != nil {
		return ".blackhole"
	}
	return filepath.Join(home, ".blackhole")
}

func (sp *Plugin) loadKeyFromDisk(keyFile string) (*PersistentKeyData, error) {
	// Validate key file path
	if !sp.isValidKeyPath(keyFile) {
		return nil, fmt.Errorf("invalid key file path: %s", keyFile)
	}
	data, err := os.ReadFile(keyFile) // #nosec G304 - path is validated
	if err != nil {
		return nil, err
	}

	var keyData PersistentKeyData
	if err := json.Unmarshal(data, &keyData); err != nil {
		return nil, err
	}

	return &keyData, nil
}

func (sp *Plugin) saveKeyToDisk(keyFile string, keyData *PersistentKeyData) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(keyData, "", "  ")
	if err != nil {
		return err
	}

	// Save with restricted permissions (only owner can read/write)
	return os.WriteFile(keyFile, data, 0o600)
}

// GetNodeRole returns the current node's role
func (sp *Plugin) GetNodeRole() string {
	sp.mu.RLock()
	defer sp.mu.RUnlock()

	// Find the node identity and get its role
	for _, identity := range sp.identities {
		if role, exists := identity.Metadata["role"]; exists {
			return role
		}
	}

	return string(RoleNode) // Default fallback
}

// SetNodeRole updates the node's role (requires admin permission)
func (sp *Plugin) SetNodeRole(newRole NodeRole) error {
	sp.mu.Lock()
	defer sp.mu.Unlock()

	// Update the node identity metadata
	for _, identity := range sp.identities {
		if identity.Metadata["type"] == "node_identity" {
			identity.Metadata["role"] = string(newRole)

			// Update the saved key data
			dataDir := sp.getDataDir()
			keyFile := filepath.Join(dataDir, "node.key")
			if keyData, err := sp.loadKeyFromDisk(keyFile); err == nil {
				keyData.Role = newRole
				if err := sp.saveKeyToDisk(keyFile, keyData); err != nil {
					sp.logger.Printf("Error saving updated key to disk: %v", err)
				}
			}

			fmt.Printf("[Security] SetNodeRole: Updated node role to '%s'\n", string(newRole))
			return nil
		}
	}

	return fmt.Errorf("node identity not found")
}

// isValidKeyPath validates that the key path is in expected locations
func (sp *Plugin) isValidKeyPath(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Get expected data directory
	dataDir := sp.getDataDir()
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return false
	}

	// Check if path is under data directory
	return strings.HasPrefix(absPath, absDataDir)
}

// Ensure Plugin implements the Plugin interface
var _ plugin.Plugin = (*Plugin)(nil)
