package orchestrator

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blackholenetwork/blackhole/internal/config"
)

// mockComponent is a test component
type mockComponent struct {
	name         string
	dependencies []string
	started      bool
	stopped      bool
	health       HealthStatus
	startErr     error
	stopErr      error
}

func (m *mockComponent) Name() string {
	return m.name
}

func (m *mockComponent) Dependencies() []string {
	return m.dependencies
}

func (m *mockComponent) Start(_ context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	return nil
}

func (m *mockComponent) Stop(_ context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.stopped = true
	return nil
}

func (m *mockComponent) Health() ComponentHealth {
	return ComponentHealth{
		Status:    m.health,
		Message:   "test health",
		LastCheck: time.Now(),
	}
}

func TestOrchestrator_New(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)
	assert.NotNil(t, orch)
	assert.Equal(t, StateInitialized, orch.state)
}

func TestOrchestrator_Register(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)

	// Test successful registration
	comp1 := &mockComponent{name: "test1", health: HealthStatusHealthy}
	err = orch.Register(comp1)
	assert.NoError(t, err)

	// Test duplicate registration
	err = orch.Register(comp1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")

	// Test registration with dependencies
	comp2 := &mockComponent{
		name:         "test2",
		dependencies: []string{"test1"},
		health:       HealthStatusHealthy,
	}
	err = orch.Register(comp2)
	assert.NoError(t, err)

	// Test registration with missing dependencies
	comp3 := &mockComponent{
		name:         "test3",
		dependencies: []string{"missing"},
		health:       HealthStatusHealthy,
	}
	err = orch.Register(comp3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dependency")
}

func TestOrchestrator_StartupOrder(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)

	// Create components with dependencies
	// comp3 depends on comp2, comp2 depends on comp1
	comp1 := &mockComponent{name: "comp1", health: HealthStatusHealthy}
	comp2 := &mockComponent{
		name:         "comp2",
		dependencies: []string{"comp1"},
		health:       HealthStatusHealthy,
	}
	comp3 := &mockComponent{
		name:         "comp3",
		dependencies: []string{"comp2"},
		health:       HealthStatusHealthy,
	}

	// Register in reverse order to test dependency resolution
	require.NoError(t, orch.Register(comp1))
	require.NoError(t, orch.Register(comp2))
	require.NoError(t, orch.Register(comp3))

	// Verify startup order
	assert.Equal(t, []string{"comp1", "comp2", "comp3"}, orch.order)
}

func TestOrchestrator_CircularDependency(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)

	// Register base component first
	comp1 := &mockComponent{
		name:   "comp1",
		health: HealthStatusHealthy,
	}
	require.NoError(t, orch.Register(comp1))

	// Create component that depends on comp1
	comp2 := &mockComponent{
		name:         "comp2",
		dependencies: []string{"comp1"},
		health:       HealthStatusHealthy,
	}
	require.NoError(t, orch.Register(comp2))

	// Try to add dependency from comp1 to comp2 (creating circular dependency)
	// This should fail because we can't modify already registered components
	// Instead, let's test a three-way circular dependency: comp3 -> comp2 -> comp1 -> comp3
	comp3 := &mockComponent{
		name:         "comp3",
		dependencies: []string{"comp2"},
		health:       HealthStatusHealthy,
	}
	require.NoError(t, orch.Register(comp3))

	// Now try to register comp4 that would create a circular dependency
	comp4 := &mockComponent{
		name:         "comp4",
		dependencies: []string{"comp3"},
		health:       HealthStatusHealthy,
	}

	// Manually add comp4 to test circular dependency
	orch.components["comp4"] = comp4

	// Modify comp1 to depend on comp4 (creating circular dependency)
	comp1.dependencies = []string{"comp4"}

	// Recalculate startup order should fail
	err = orch.calculateStartupOrder()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency")
}

func TestOrchestrator_StartStop(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)

	// Register components
	comp1 := &mockComponent{name: "comp1", health: HealthStatusHealthy}
	comp2 := &mockComponent{
		name:         "comp2",
		dependencies: []string{"comp1"},
		health:       HealthStatusHealthy,
	}

	require.NoError(t, orch.Register(comp1))
	require.NoError(t, orch.Register(comp2))

	// Start orchestrator
	ctx := context.Background()
	err = orch.Start(ctx)
	assert.NoError(t, err)
	assert.Equal(t, StateRunning, orch.state)
	assert.True(t, comp1.started)
	assert.True(t, comp2.started)

	// Stop orchestrator
	err = orch.Stop(ctx)
	assert.NoError(t, err)
	assert.Equal(t, StateStopped, orch.state)
	assert.True(t, comp1.stopped)
	assert.True(t, comp2.stopped)
}

func TestOrchestrator_StartFailure(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)

	// Register components where comp2 fails to start
	comp1 := &mockComponent{name: "comp1", health: HealthStatusHealthy}
	comp2 := &mockComponent{
		name:         "comp2",
		dependencies: []string{"comp1"},
		health:       HealthStatusHealthy,
		startErr:     assert.AnError,
	}

	require.NoError(t, orch.Register(comp1))
	require.NoError(t, orch.Register(comp2))

	// Start should fail
	ctx := context.Background()
	err = orch.Start(ctx)
	assert.Error(t, err)
	assert.Equal(t, StateError, orch.state)

	// comp1 should be started then stopped (rollback)
	assert.True(t, comp1.started)
	assert.True(t, comp1.stopped)

	// comp2 should not be started
	assert.False(t, comp2.started)
}

func TestOrchestrator_Health(t *testing.T) {
	cfg := &config.Config{}
	logger := log.New(os.Stdout, "TEST: ", 0)

	orch, err := New(cfg, logger)
	require.NoError(t, err)

	// Register components with different health states
	comp1 := &mockComponent{name: "comp1", health: HealthStatusHealthy}
	comp2 := &mockComponent{name: "comp2", health: HealthStatusDegraded}
	comp3 := &mockComponent{name: "comp3", health: HealthStatusUnhealthy}

	require.NoError(t, orch.Register(comp1))
	require.NoError(t, orch.Register(comp2))
	require.NoError(t, orch.Register(comp3))

	// Check health
	health := orch.Health()
	assert.Len(t, health, 3)
	assert.Equal(t, HealthStatusHealthy, health["comp1"].Status)
	assert.Equal(t, HealthStatusDegraded, health["comp2"].Status)
	assert.Equal(t, HealthStatusUnhealthy, health["comp3"].Status)
}
