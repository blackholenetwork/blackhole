// Package feature provides feature flag functionality for gradual rollouts
package feature

import (
	"context"
	"sync"
	"time"
)

// Flag represents a feature flag
type Flag struct {
	Name        string
	Description string
	Enabled     bool
	Percentage  int      // 0-100 for gradual rollout
	Users       []string // Specific users
	Tiers       []string // Specific tiers
	StartTime   *time.Time
	EndTime     *time.Time
}

// Manager manages feature flags
type Manager struct {
	mu    sync.RWMutex
	flags map[string]*Flag
}

// RemoteConfig interface for dynamic updates
type RemoteConfig interface {
	GetFlags(ctx context.Context) (map[string]*Flag, error)
	Subscribe(ctx context.Context, onChange func(map[string]*Flag))
}

// NewManager creates a new feature manager
func NewManager() *Manager {
	return &Manager{
		flags: make(map[string]*Flag),
	}
}

// Register adds a feature flag
func (m *Manager) Register(flag *Flag) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.flags[flag.Name] = flag
}

// IsEnabled checks if a feature is enabled
func (m *Manager) IsEnabled(name string, ctx ...context.Context) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	flag, ok := m.flags[name]
	if !ok {
		return false // Unknown features are disabled
	}

	// Check time window
	now := time.Now()
	if flag.StartTime != nil && now.Before(*flag.StartTime) {
		return false
	}
	if flag.EndTime != nil && now.After(*flag.EndTime) {
		return false
	}

	// Global enable/disable
	if !flag.Enabled {
		return false
	}

	// Check context for user/tier info
	if len(ctx) > 0 {
		return m.isEnabledForContext(ctx[0], flag)
	}

	return flag.Percentage >= 100
}

// isEnabledForContext checks if enabled for specific context
func (m *Manager) isEnabledForContext(ctx context.Context, flag *Flag) bool {
	// Check specific users
	if userID := getUserID(ctx); userID != "" {
		for _, u := range flag.Users {
			if u == userID {
				return true
			}
		}
	}

	// Check tiers
	if tier := getTier(ctx); tier != "" {
		for _, t := range flag.Tiers {
			if t == tier {
				return true
			}
		}
	}

	// Check percentage rollout
	if flag.Percentage > 0 && flag.Percentage < 100 {
		if userID := getUserID(ctx); userID != "" {
			// Consistent hashing for gradual rollout
			return hashUserID(userID, flag.Name) < flag.Percentage
		}
	}

	return flag.Percentage >= 100
}

// Helper functions
func getUserID(ctx context.Context) string {
	if val := ctx.Value("user_id"); val != nil {
		return val.(string)
	}
	return ""
}

func getTier(ctx context.Context) string {
	if val := ctx.Value("tier"); val != nil {
		return val.(string)
	}
	return ""
}

func hashUserID(userID, feature string) int {
	// Simple hash for consistent rollout
	h := 0
	for _, c := range userID + feature {
		h = (h * 31) + int(c)
	}
	return (h & 0x7FFFFFFF) % 100
}

// Usage helpers

// WithFeature executes function only if feature is enabled
func WithFeature(name string, fn func()) {
	if Default.IsEnabled(name) {
		fn()
	}
}

// Choose returns first value if feature is enabled, second otherwise
func Choose[T any](name string, enabled, disabled T) T {
	if Default.IsEnabled(name) {
		return enabled
	}
	return disabled
}

// Default manager instance
var Default = NewManager()

// Common feature flags
const (
	NewStorageEngine = "new-storage-engine"
	BetaAPI          = "beta-api"
	EnhancedSecurity = "enhanced-security"
	PerformanceMode  = "performance-mode"
)

// Initialize common flags
func init() {
	Default.Register(&Flag{
		Name:        NewStorageEngine,
		Description: "Use new optimized storage engine",
		Enabled:     true,
		Percentage:  0, // Start with 0% rollout
	})

	Default.Register(&Flag{
		Name:        BetaAPI,
		Description: "Enable beta API endpoints",
		Enabled:     true,
		Tiers:       []string{"ultimate", "advance"},
	})
}
