package feature

import (
	"context"
	"fmt"
	"testing"
	"time"
)

//nolint:staticcheck // Test uses string keys for context in multiple places


func TestNewManager(t *testing.T) {
	manager := NewManager()
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}
	if manager.flags == nil {
		t.Fatal("flags map not initialized")
	}
}

func TestManager_Register(t *testing.T) {
	manager := NewManager()
	flag := &Flag{
		Name:        "test-flag",
		Description: "Test flag",
		Enabled:     true,
	}

	manager.Register(flag)

	manager.mu.RLock()
	registered := manager.flags["test-flag"]
	manager.mu.RUnlock()

	if registered == nil {
		t.Fatal("Flag was not registered")
	}
	if registered.Name != "test-flag" {
		t.Errorf("Expected name 'test-flag', got %s", registered.Name)
	}
}

func TestManager_IsEnabled_UnknownFlag(t *testing.T) {
	manager := NewManager()
	if manager.IsEnabled("unknown-flag") {
		t.Error("Unknown flag should be disabled")
	}
}

func TestManager_IsEnabled_GloballyDisabled(t *testing.T) {
	manager := NewManager()
	flag := &Flag{
		Name:    "disabled-flag",
		Enabled: false,
	}
	manager.Register(flag)

	if manager.IsEnabled("disabled-flag") {
		t.Error("Globally disabled flag should return false")
	}
}

func TestManager_IsEnabled_TimeWindow(t *testing.T) {
	manager := NewManager()

	// Test start time in future
	future := time.Now().Add(time.Hour)
	flag := &Flag{
		Name:      "future-flag",
		Enabled:   true,
		StartTime: &future,
		Percentage: 100,
	}
	manager.Register(flag)

	if manager.IsEnabled("future-flag") {
		t.Error("Flag with future start time should be disabled")
	}

	// Test end time in past
	past := time.Now().Add(-time.Hour)
	flag2 := &Flag{
		Name:      "past-flag",
		Enabled:   true,
		EndTime:   &past,
		Percentage: 100,
	}
	manager.Register(flag2)

	if manager.IsEnabled("past-flag") {
		t.Error("Flag with past end time should be disabled")
	}

	// Test valid time window
	startTime := time.Now().Add(-time.Hour)
	endTime := time.Now().Add(time.Hour)
	flag3 := &Flag{
		Name:      "valid-time-flag",
		Enabled:   true,
		StartTime: &startTime,
		EndTime:   &endTime,
		Percentage: 100,
	}
	manager.Register(flag3)

	if !manager.IsEnabled("valid-time-flag") {
		t.Error("Flag with valid time window should be enabled")
	}
}

func TestManager_IsEnabled_Percentage(t *testing.T) {
	manager := NewManager()

	// Test 100% rollout
	flag := &Flag{
		Name:       "hundred-percent",
		Enabled:    true,
		Percentage: 100,
	}
	manager.Register(flag)

	if !manager.IsEnabled("hundred-percent") {
		t.Error("100% rollout flag should be enabled")
	}

	// Test 0% rollout
	flag2 := &Flag{
		Name:       "zero-percent",
		Enabled:    true,
		Percentage: 0,
	}
	manager.Register(flag2)

	if manager.IsEnabled("zero-percent") {
		t.Error("0% rollout flag should be disabled")
	}
}

func TestManager_IsEnabled_WithContext_SpecificUsers(t *testing.T) {
	manager := NewManager()
	flag := &Flag{
		Name:    "user-specific",
		Enabled: true,
		Users:   []string{"user1", "user2"},
	}
	manager.Register(flag)

	// Test with allowed user
	ctx := context.WithValue(context.Background(), "user_id", "user1")  //nolint:staticcheck
	if !manager.IsEnabled("user-specific", ctx) {
		t.Error("Flag should be enabled for specific user")
	}

	// Test with non-allowed user
	ctx2 := context.WithValue(context.Background(), "user_id", "user3")  //nolint:staticcheck
	if manager.IsEnabled("user-specific", ctx2) {
		t.Error("Flag should be disabled for non-specific user")
	}

	// Test without user context
	if manager.IsEnabled("user-specific") {
		t.Error("Flag should be disabled without user context")
	}
}

func TestManager_IsEnabled_WithContext_SpecificTiers(t *testing.T) {
	manager := NewManager()
	flag := &Flag{
		Name:    "tier-specific",
		Enabled: true,
		Tiers:   []string{"ultimate", "advance"},
	}
	manager.Register(flag)

	// Test with allowed tier
	ctx := context.WithValue(context.Background(), "tier", "ultimate")  //nolint:staticcheck
	if !manager.IsEnabled("tier-specific", ctx) {
		t.Error("Flag should be enabled for specific tier")
	}

	// Test with non-allowed tier
	ctx2 := context.WithValue(context.Background(), "tier", "free")  //nolint:staticcheck
	if manager.IsEnabled("tier-specific", ctx2) {
		t.Error("Flag should be disabled for non-specific tier")
	}
}

func TestManager_IsEnabled_WithContext_PercentageRollout(t *testing.T) {
	manager := NewManager()
	flag := &Flag{
		Name:       "percentage-rollout",
		Enabled:    true,
		Percentage: 50,
	}
	manager.Register(flag)

	// Test with specific user ID that should hash to different values
	ctx1 := context.WithValue(context.Background(), "user_id", "user1")  //nolint:staticcheck
	ctx2 := context.WithValue(context.Background(), "user_id", "user2")  //nolint:staticcheck

	// The results should be consistent for the same user
	result1a := manager.IsEnabled("percentage-rollout", ctx1)
	result1b := manager.IsEnabled("percentage-rollout", ctx1)
	if result1a != result1b {
		t.Error("Results should be consistent for the same user")
	}

	result2a := manager.IsEnabled("percentage-rollout", ctx2)
	result2b := manager.IsEnabled("percentage-rollout", ctx2)
	if result2a != result2b {
		t.Error("Results should be consistent for the same user")
	}
}

func TestGetUserID(t *testing.T) {
	// Test with user_id in context
	ctx := context.WithValue(context.Background(), "user_id", "test-user")  //nolint:staticcheck
	userID := getUserID(ctx)
	if userID != "test-user" {
		t.Errorf("Expected 'test-user', got %s", userID)
	}

	// Test without user_id in context
	emptyCtx := context.Background()
	userID2 := getUserID(emptyCtx)
	if userID2 != "" {
		t.Errorf("Expected empty string, got %s", userID2)
	}
}

func TestGetTier(t *testing.T) {
	// Test with tier in context
	ctx := context.WithValue(context.Background(), "tier", "ultimate")  //nolint:staticcheck
	tier := getTier(ctx)
	if tier != "ultimate" {
		t.Errorf("Expected 'ultimate', got %s", tier)
	}

	// Test without tier in context
	emptyCtx := context.Background()
	tier2 := getTier(emptyCtx)
	if tier2 != "" {
		t.Errorf("Expected empty string, got %s", tier2)
	}
}

func TestHashUserID(t *testing.T) {
	// Test that hash is consistent
	hash1 := hashUserID("user1", "feature1")
	hash2 := hashUserID("user1", "feature1")
	if hash1 != hash2 {
		t.Error("Hash should be consistent for same input")
	}

	// Test that different inputs produce different hashes
	hash3 := hashUserID("user2", "feature1")
	if hash1 == hash3 {
		t.Error("Different users should produce different hashes")
	}

	hash4 := hashUserID("user1", "feature2")
	if hash1 == hash4 {
		t.Error("Different features should produce different hashes")
	}

	// Test that hash is in valid range [0, 100)
	if hash1 < 0 || hash1 >= 100 {
		t.Errorf("Hash %d should be in range [0, 100)", hash1)
	}
}

func TestWithFeature(t *testing.T) {
	// Clear default manager and add test flag
	Default = NewManager()
	flag := &Flag{
		Name:       "test-with-feature",
		Enabled:    true,
		Percentage: 100,
	}
	Default.Register(flag)

	executed := false
	WithFeature("test-with-feature", func() {
		executed = true
	})

	if !executed {
		t.Error("Function should have been executed when feature is enabled")
	}

	// Test with disabled feature
	flag2 := &Flag{
		Name:    "disabled-feature",
		Enabled: false,
	}
	Default.Register(flag2)

	executed2 := false
	WithFeature("disabled-feature", func() {
		executed2 = true
	})

	if executed2 {
		t.Error("Function should not have been executed when feature is disabled")
	}
}

func TestChoose(t *testing.T) {
	// Clear default manager and add test flag
	Default = NewManager()
	flag := &Flag{
		Name:       "test-choose",
		Enabled:    true,
		Percentage: 100,
	}
	Default.Register(flag)

	result := Choose("test-choose", "enabled", "disabled")
	if result != "enabled" {
		t.Errorf("Expected 'enabled', got %s", result)
	}

	// Test with disabled feature
	flag2 := &Flag{
		Name:    "disabled-choose",
		Enabled: false,
	}
	Default.Register(flag2)

	result2 := Choose("disabled-choose", "enabled", "disabled")
	if result2 != "disabled" {
		t.Errorf("Expected 'disabled', got %s", result2)
	}

	// Test with unknown feature
	result3 := Choose("unknown-choose", "enabled", "disabled")
	if result3 != "disabled" {
		t.Errorf("Expected 'disabled' for unknown feature, got %s", result3)
	}
}

func TestDefaultManagerInitialization(t *testing.T) {
	// Create a fresh manager to test initialization logic
	manager := NewManager()

	// Register the same flags as the default manager
	manager.Register(&Flag{
		Name:        NewStorageEngine,
		Description: "Use new optimized storage engine",
		Enabled:     true,
		Percentage:  0, // Start with 0% rollout
	})

	manager.Register(&Flag{
		Name:        BetaAPI,
		Description: "Enable beta API endpoints",
		Enabled:     true,
		Tiers:       []string{"ultimate", "advance"},
	})

	// Test that flags are registered
	if manager.IsEnabled(NewStorageEngine) {
		t.Error("NewStorageEngine should be disabled by default due to 0% rollout")
	}

	// Test BetaAPI with correct tier
	ctx := context.WithValue(context.Background(), "tier", "ultimate")  //nolint:staticcheck
	if !manager.IsEnabled(BetaAPI, ctx) {
		t.Error("BetaAPI should be enabled for ultimate tier")
	}

	// Test BetaAPI with advance tier
	ctx1 := context.WithValue(context.Background(), "tier", "advance")  //nolint:staticcheck
	if !manager.IsEnabled(BetaAPI, ctx1) {
		t.Error("BetaAPI should be enabled for advance tier")
	}

	// Test BetaAPI with incorrect tier
	ctx2 := context.WithValue(context.Background(), "tier", "free")  //nolint:staticcheck
	if manager.IsEnabled(BetaAPI, ctx2) {
		t.Error("BetaAPI should be disabled for free tier")
	}

	// Test BetaAPI without context (should be disabled since no percentage set)
	if manager.IsEnabled(BetaAPI) {
		t.Error("BetaAPI should be disabled without context since no percentage rollout")
	}
}

func TestFlag_ComplexScenarios(t *testing.T) {
	manager := NewManager()

	// Test flag with multiple conditions
	startTime := time.Now().Add(-time.Hour)
	endTime := time.Now().Add(time.Hour)
	flag := &Flag{
		Name:       "complex-flag",
		Enabled:    true,
		Percentage: 50,
		Users:      []string{"special-user"},
		Tiers:      []string{"ultimate"},
		StartTime:  &startTime,
		EndTime:    &endTime,
	}
	manager.Register(flag)

	// Test special user (should always be enabled regardless of percentage)
	ctx1 := context.WithValue(context.Background(), "user_id", "special-user")  //nolint:staticcheck
	if !manager.IsEnabled("complex-flag", ctx1) {
		t.Error("Flag should be enabled for special user")
	}

	// Test ultimate tier (should always be enabled regardless of percentage)
	ctx2 := context.WithValue(context.Background(), "tier", "ultimate")  //nolint:staticcheck
	if !manager.IsEnabled("complex-flag", ctx2) {
		t.Error("Flag should be enabled for ultimate tier")
	}

	// Test regular user with percentage rollout
	ctx3 := context.WithValue(context.Background(), "user_id", "regular-user")  //nolint:staticcheck
	result := manager.IsEnabled("complex-flag", ctx3)
	// Result depends on hash, but should be consistent
	result2 := manager.IsEnabled("complex-flag", ctx3)
	if result != result2 {
		t.Error("Percentage rollout should be consistent for same user")
	}
}

func TestConcurrentAccess(t *testing.T) {
	manager := NewManager()
	flag := &Flag{
		Name:       "concurrent-flag",
		Enabled:    true,
		Percentage: 100,
	}

	// Test concurrent registration and access
	done := make(chan bool, 10)

	// Concurrent registrations
	for i := 0; i < 5; i++ {
		go func(id int) {
			testFlag := &Flag{
				Name:       fmt.Sprintf("test-flag-%d", id),
				Enabled:    true,
				Percentage: 100,
			}
			manager.Register(testFlag)
			done <- true
		}(i)
	}

	// Concurrent access
	for i := 0; i < 5; i++ {
		go func() {
			manager.Register(flag)
			manager.IsEnabled("concurrent-flag")
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify flag is still accessible
	if !manager.IsEnabled("concurrent-flag") {
		t.Error("Flag should be enabled after concurrent access")
	}
}

func TestEdgeCases(t *testing.T) {
	manager := NewManager()

	// Test nil context values
	ctx := context.WithValue(context.Background(), "user_id", nil)  //nolint:staticcheck
	ctx = context.WithValue(ctx, "tier", nil)  //nolint:staticcheck

	flag := &Flag{
		Name:       "edge-case-flag",
		Enabled:    true,
		Users:      []string{"test-user"},
		Percentage: 100,
	}
	manager.Register(flag)

	// Should fallback to percentage since user_id is nil
	if !manager.IsEnabled("edge-case-flag", ctx) {
		t.Error("Flag should be enabled with 100% rollout when context values are nil")
	}

	// Test empty slices
	flag2 := &Flag{
		Name:       "empty-slices-flag",
		Enabled:    true,
		Users:      []string{},
		Tiers:      []string{},
		Percentage: 100,
	}
	manager.Register(flag2)

	if !manager.IsEnabled("empty-slices-flag") {
		t.Error("Flag with empty user/tier slices should fallback to percentage")
	}
}
