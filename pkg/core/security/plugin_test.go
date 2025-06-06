package security

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// MockRegistry implements a mock plugin registry for testing
type MockRegistry struct {
	mu      sync.Mutex
	events  []plugin.Event
	plugins map[string]plugin.Plugin
}

func NewMockRegistry() *MockRegistry {
	return &MockRegistry{
		events:  make([]plugin.Event, 0),
		plugins: make(map[string]plugin.Plugin),
	}
}

func (mr *MockRegistry) Register(p plugin.Plugin) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.plugins[p.Info().Name] = p
	return nil
}

func (mr *MockRegistry) Unregister(name string) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	delete(mr.plugins, name)
	return nil
}

func (mr *MockRegistry) Get(name string) (plugin.Plugin, error) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	if p, exists := mr.plugins[name]; exists {
		return p, nil
	}
	return nil, fmt.Errorf("plugin not found")
}

func (mr *MockRegistry) List() []plugin.Plugin {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	result := make([]plugin.Plugin, 0, len(mr.plugins))
	for _, p := range mr.plugins {
		result = append(result, p)
	}
	return result
}

func (mr *MockRegistry) Publish(event plugin.Event) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.events = append(mr.events, event)
}

func (mr *MockRegistry) Subscribe(pluginName string, eventTypes []string) (<-chan plugin.Event, error) {
	ch := make(chan plugin.Event, 10)
	return ch, nil
}

func (mr *MockRegistry) Unsubscribe(pluginName string, ch <-chan plugin.Event) error {
	return nil
}

// TestNewPlugin tests plugin creation
func TestNewPlugin(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	if p == nil {
		t.Fatal("Expected plugin to be created")
	}

	info := p.Info()
	if info.Name != "security" {
		t.Errorf("Expected name 'security', got %s", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %s", info.Version)
	}
	if len(info.Capabilities) != 1 || info.Capabilities[0] != string(plugin.CapabilitySecurity) {
		t.Error("Expected security capability")
	}
}

// TestPluginInit tests plugin initialization
func TestPluginInit(t *testing.T) {
	// Create temp directory for testing
	tempDir := t.TempDir()

	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	config := plugin.Config{
		"data_dir": tempDir,
	}

	err := p.Init(ctx, config)
	if err != nil {
		t.Fatalf("Expected no error on init, got: %v", err)
	}

	// Check that key pair was created
	if p.keyPair == nil {
		t.Error("Expected key pair to be initialized")
	}

	// Check that node identity was created
	if len(p.identities) == 0 {
		t.Error("Expected at least one identity")
	}

	// Check that permissions were initialized
	if len(p.permissions) == 0 {
		t.Error("Expected default permissions to be created")
	}

	// Check health after init - should be unknown since not started yet
	health := p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status after init (not started), got %v", health.Status)
	}
	if health.Message != "Security not started" {
		t.Errorf("Expected 'Security not started' message, got %s", health.Message)
	}
}

// TestPluginStart tests plugin start
func TestPluginStart(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize first
	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Start the plugin
	err := p.Start(ctx)
	if err != nil {
		t.Fatalf("Expected no error on start, got: %v", err)
	}

	// Check if plugin is started
	if !p.started {
		t.Error("Expected plugin to be started")
	}

	// Check health after start
	health := p.Health()
	if health.Status != plugin.HealthStatusHealthy {
		t.Errorf("Expected healthy status after start, got %v", health.Status)
	}
}

// TestPluginStart_AlreadyStarted tests starting an already started plugin
func TestPluginStart_AlreadyStarted(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize and start
	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})
	_ = p.Start(ctx)

	// Try to start again
	err := p.Start(ctx)
	if err == nil {
		t.Fatal("Expected error when starting already started plugin")
	}
	if err.Error() != "security plugin already started" {
		t.Errorf("Expected 'already started' error, got: %v", err)
	}
}

// TestPluginStop tests plugin stop
func TestPluginStop(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize and start
	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})
	_ = p.Start(ctx)

	// Stop the plugin
	err := p.Stop(ctx)
	if err != nil {
		t.Fatalf("Expected no error on stop, got: %v", err)
	}

	// Check if plugin is stopped
	if p.started {
		t.Error("Expected plugin to be stopped")
	}

	// Check health after stop
	health := p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status after stop, got %v", health.Status)
	}
}

// TestGenerateIdentity tests identity generation
func TestGenerateIdentity(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Generate identity
	identity, err := p.GenerateIdentity()
	if err != nil {
		t.Fatalf("Expected no error generating identity, got: %v", err)
	}

	if identity == nil {
		t.Fatal("Expected identity to be created")
	}

	// Verify identity fields
	if identity.ID == "" {
		t.Error("Expected identity to have ID")
	}
	if identity.PublicKey == nil {
		t.Error("Expected identity to have public key")
	}
	if !startsWith(identity.DID, "did:key:") {
		t.Errorf("Expected DID to start with 'did:key:', got %s", identity.DID)
	}

	// Verify identity was stored
	retrieved, err := p.GetIdentity(identity.ID)
	if err != nil {
		t.Errorf("Failed to retrieve identity: %v", err)
	}
	if retrieved.ID != identity.ID {
		t.Error("Retrieved identity doesn't match")
	}
}

// TestSignAndVerify tests signing and verification
func TestSignAndVerify(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	data := []byte("test data to sign")

	// Sign data
	signature, err := p.SignData(data)
	if err != nil {
		t.Fatalf("Expected no error signing data, got: %v", err)
	}

	// Verify signature
	valid := p.VerifySignature(p.keyPair.PublicKey, data, signature)
	if !valid {
		t.Error("Expected signature to be valid")
	}

	// Verify with wrong data
	wrongData := []byte("wrong data")
	valid = p.VerifySignature(p.keyPair.PublicKey, wrongData, signature)
	if valid {
		t.Error("Expected signature to be invalid with wrong data")
	}

	// Verify with wrong public key
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	valid = p.VerifySignature(wrongPub, data, signature)
	if valid {
		t.Error("Expected signature to be invalid with wrong public key")
	}
}

// TestAuthentication tests the authentication flow
func TestAuthentication(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Get the node identity
	var nodeIdentity *Identity
	for _, id := range p.identities {
		nodeIdentity = id
		break
	}

	// Create challenge
	challenge := []byte("authentication challenge")

	// Sign challenge with node's private key
	signature := ed25519.Sign(p.keyPair.PrivateKey, challenge)

	// Authenticate
	session, err := p.Authenticate(nodeIdentity.ID, signature, challenge)
	if err != nil {
		t.Fatalf("Expected no error on authenticate, got: %v", err)
	}

	if session == nil {
		t.Fatal("Expected session to be created")
	}

	// Verify session fields
	if session.ID == "" {
		t.Error("Expected session to have ID")
	}
	if session.Token == "" {
		t.Error("Expected session to have token")
	}
	if !session.Active {
		t.Error("Expected session to be active")
	}

	// Validate session
	validatedSession, err := p.ValidateSession(session.Token)
	if err != nil {
		t.Errorf("Expected no error validating session, got: %v", err)
	}
	if validatedSession.ID != session.ID {
		t.Error("Validated session doesn't match original")
	}

	// Test invalid signature
	badSignature := []byte("bad signature")
	_, err = p.Authenticate(nodeIdentity.ID, badSignature, challenge)
	if err == nil {
		t.Error("Expected error with invalid signature")
	}

	// Test non-existent identity
	_, err = p.Authenticate("non-existent", signature, challenge)
	if err == nil {
		t.Error("Expected error with non-existent identity")
	}
}

// TestAuthorization tests permission checking
func TestAuthorization(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Get the node identity
	var nodeIdentity *Identity
	for _, id := range p.identities {
		nodeIdentity = id
		break
	}

	// Create a test permission
	perm, err := p.CreatePermission("test.read", "test_resource", []string{"read"}, "Test read permission")
	if err != nil {
		t.Fatalf("Failed to create permission: %v", err)
	}

	// Grant permission to identity
	err = p.GrantPermission(nodeIdentity.ID, perm.ID)
	if err != nil {
		t.Fatalf("Failed to grant permission: %v", err)
	}

	// Test authorization - should succeed
	authorized, err := p.Authorize(nodeIdentity.ID, "test_resource", "read")
	if err != nil {
		t.Errorf("Authorization check failed: %v", err)
	}
	if !authorized {
		t.Error("Expected authorization to succeed")
	}

	// Test authorization for different action - should fail
	authorized, err = p.Authorize(nodeIdentity.ID, "test_resource", "write")
	if err != nil {
		t.Errorf("Authorization check failed: %v", err)
	}
	if authorized {
		t.Error("Expected authorization to fail for unpermitted action")
	}

	// Test wildcard permission
	wildcardPerm, _ := p.CreatePermission("admin", "test_resource", []string{"*"}, "Admin permission")
	_ = p.GrantPermission(nodeIdentity.ID, wildcardPerm.ID)

	authorized, err = p.Authorize(nodeIdentity.ID, "test_resource", "write")
	if err != nil {
		t.Errorf("Authorization check failed: %v", err)
	}
	if !authorized {
		t.Error("Expected wildcard authorization to succeed")
	}
}

// TestPersistentKeyStorage tests key persistence
func TestPersistentKeyStorage(t *testing.T) {
	tempDir := t.TempDir()

	// First plugin instance - generates key
	registry1 := plugin.NewRegistry()
	p1 := NewPlugin(registry1)
	ctx := context.Background()
	_ = p1.Init(ctx, plugin.Config{"data_dir": tempDir})

	originalPubKey := p1.keyPair.PublicKey
	originalPrivKey := p1.keyPair.PrivateKey

	// Second plugin instance - should load existing key
	registry2 := plugin.NewRegistry()
	p2 := NewPlugin(registry2)
	_ = p2.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Verify keys match
	if !bytesEqual(p2.keyPair.PublicKey, originalPubKey) {
		t.Error("Public key not persisted correctly")
	}
	if !bytesEqual(p2.keyPair.PrivateKey, originalPrivKey) {
		t.Error("Private key not persisted correctly")
	}

	// Verify key file exists
	keyFile := filepath.Join(tempDir, "node.key")
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify key file has correct permissions
	info, _ := os.Stat(keyFile)
	mode := info.Mode()
	if mode.Perm() != 0600 {
		t.Errorf("Expected key file permissions 0600, got %v", mode.Perm())
	}
}

// TestNodeRoles tests node role functionality
func TestNodeRoles(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Check default role
	role := p.GetNodeRole()
	if role != string(RoleNode) {
		t.Errorf("Expected default role 'node', got %s", role)
	}

	// Set new role
	err := p.SetNodeRole(RoleRelay)
	if err != nil {
		t.Fatalf("Failed to set node role: %v", err)
	}

	// Verify role was updated
	role = p.GetNodeRole()
	if role != string(RoleRelay) {
		t.Errorf("Expected role 'relay', got %s", role)
	}

	// Create new plugin instance to verify persistence
	registry2 := plugin.NewRegistry()
	p2 := NewPlugin(registry2)
	_ = p2.Init(ctx, plugin.Config{"data_dir": tempDir})

	role = p2.GetNodeRole()
	if role != string(RoleRelay) {
		t.Errorf("Expected persisted role 'relay', got %s", role)
	}
}

// TestHealthStates tests various health states
func TestHealthStates(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Test 1: After init but not started - security plugin returns Unknown when not started
	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})
	health := p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status when not started, got %v", health.Status)
	}
	if health.Message != "Security not started" {
		t.Errorf("Expected 'Security not started' message, got %s", health.Message)
	}

	// Test 2: Started state
	_ = p.Start(ctx)
	health = p.Health()
	if health.Status != plugin.HealthStatusHealthy {
		t.Errorf("Expected healthy status when started, got %v", health.Status)
	}
	if !contains(health.Message, "Auth system ready") || !contains(health.Message, "key age:") {
		t.Errorf("Expected auth ready message with key age, got %s", health.Message)
	}

	// Create a session to test active sessions state
	var nodeIdentity *Identity
	for _, id := range p.identities {
		nodeIdentity = id
		break
	}
	challenge := []byte("test")
	signature := ed25519.Sign(p.keyPair.PrivateKey, challenge)
	_, _ = p.Authenticate(nodeIdentity.ID, signature, challenge)

	health = p.Health()
	if !contains(health.Message, "Auth operational") {
		t.Errorf("Expected operational message with sessions, got %s", health.Message)
	}

	// Test 3: No key pair state
	p.keyPair = nil
	health = p.Health()
	if health.Status != plugin.HealthStatusUnhealthy {
		t.Errorf("Expected unhealthy status without key pair, got %v", health.Status)
	}

	// Verify health details
	details := health.Details
	if details["has_keypair"].(bool) != false {
		t.Error("Expected has_keypair=false in health details")
	}
}

// TestConcurrentAccess tests concurrent access to plugin methods
func TestConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})
	_ = p.Start(ctx)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Identity generation
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_, err := p.GenerateIdentity()
				if err != nil {
					errors <- err
				}
			}
		}()
	}

	// Permission creation
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				name := fmt.Sprintf("perm_%d_%d", id, j)
				_, err := p.CreatePermission(name, "resource", []string{"read"}, "Test")
				if err != nil {
					errors <- err
				}
			}
		}(i)
	}

	// Health checks
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				health := p.Health()
				if health.Status == "" {
					errors <- fmt.Errorf("empty health status")
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}

	// Verify state consistency
	if len(p.identities) < 5 {
		t.Error("Expected multiple identities to be created")
	}
	if len(p.permissions) < 5 {
		t.Error("Expected multiple permissions to be created")
	}
}

// TestSessionExpiration tests session validation with expiry
func TestSessionExpiration(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"data_dir": tempDir})

	// Create an expired session manually
	expiredSession := &Session{
		ID:         "expired-session",
		IdentityID: "test-identity",
		Token:      "expired-token",
		CreatedAt:  time.Now().Add(-25 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
		Active:     true,
	}
	p.sessions[expiredSession.ID] = expiredSession

	// Try to validate expired session
	_, err := p.ValidateSession(expiredSession.Token)
	if err == nil {
		t.Error("Expected error validating expired session")
	}

	// Create an inactive session
	inactiveSession := &Session{
		ID:         "inactive-session",
		IdentityID: "test-identity",
		Token:      "inactive-token",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		Active:     false,
	}
	p.sessions[inactiveSession.ID] = inactiveSession

	// Try to validate inactive session
	_, err = p.ValidateSession(inactiveSession.Token)
	if err == nil {
		t.Error("Expected error validating inactive session")
	}
}

// TestKeyFileValidation tests the key file path validation
func TestKeyFileValidation(t *testing.T) {
	tempDir := t.TempDir()
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	_ = p.Init(context.Background(), plugin.Config{"data_dir": tempDir})

	// Test valid path
	validPath := filepath.Join(tempDir, "node.key")
	if !p.isValidKeyPath(validPath) {
		t.Error("Expected valid path to be accepted")
	}

	// Test path outside data directory
	invalidPath := "/etc/passwd"
	if p.isValidKeyPath(invalidPath) {
		t.Error("Expected path outside data directory to be rejected")
	}

	// Test path traversal attempt
	traversalPath := filepath.Join(tempDir, "..", "..", "etc", "passwd")
	if p.isValidKeyPath(traversalPath) {
		t.Error("Expected path traversal to be rejected")
	}
}

// TestFormatDuration tests the duration formatting function
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m"},
		{2 * time.Hour, "2h"},
		{3 * 24 * time.Hour, "3d"},
		{7 * 24 * time.Hour, "7d"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.duration)
		if result != tt.expected {
			t.Errorf("formatDuration(%v) = %s, expected %s", tt.duration, result, tt.expected)
		}
	}
}

// TestPersistentKeyData tests key data serialization
func TestPersistentKeyData(t *testing.T) {
	// Create test key data
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyData := &PersistentKeyData{
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
		NodeID:     "test-node",
		Role:       RoleRelay,
	}

	// Serialize
	data, err := json.Marshal(keyData)
	if err != nil {
		t.Fatalf("Failed to marshal key data: %v", err)
	}

	// Deserialize
	var loaded PersistentKeyData
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("Failed to unmarshal key data: %v", err)
	}

	// Verify
	if !bytesEqual(loaded.PublicKey, keyData.PublicKey) {
		t.Error("Public key not serialized correctly")
	}
	if !bytesEqual(loaded.PrivateKey, keyData.PrivateKey) {
		t.Error("Private key not serialized correctly")
	}
	if loaded.NodeID != keyData.NodeID {
		t.Error("NodeID not serialized correctly")
	}
	if loaded.Role != keyData.Role {
		t.Error("Role not serialized correctly")
	}
}

// Helper functions
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
