package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlugin is a simple test plugin
type TestPlugin struct {
	*BasePlugin
	initCalled  bool
	startCalled bool
	stopCalled  bool
}

func NewTestPlugin(name string, dependencies ...string) *TestPlugin {
	info := Info{
		Name:         name,
		Version:      "1.0.0",
		Description:  "Test plugin",
		Author:       "Test",
		License:      "MIT",
		Dependencies: dependencies,
		Capabilities: []string{"test"},
	}

	return &TestPlugin{
		BasePlugin: NewBasePlugin(info),
	}
}

func (tp *TestPlugin) Init(ctx context.Context, config Config) error {
	if err := tp.BasePlugin.Init(ctx, config); err != nil {
		return err
	}
	tp.initCalled = true
	return nil
}

func (tp *TestPlugin) Start(ctx context.Context) error {
	if err := tp.BasePlugin.Start(ctx); err != nil {
		return err
	}
	tp.startCalled = true
	return nil
}

func (tp *TestPlugin) Stop(ctx context.Context) error {
	tp.stopCalled = true
	return tp.BasePlugin.Stop(ctx)
}

func TestRegistry_RegisterAndStart(t *testing.T) {
	registry := NewRegistry()
	
	// Create test plugins
	plugin1 := NewTestPlugin("plugin1")
	plugin2 := NewTestPlugin("plugin2", "plugin1")
	plugin3 := NewTestPlugin("plugin3", "plugin2")

	// Register plugins
	require.NoError(t, registry.Register(plugin1))
	require.NoError(t, registry.Register(plugin2))
	require.NoError(t, registry.Register(plugin3))

	// Start all plugins
	ctx := context.Background()
	require.NoError(t, registry.Start(ctx))

	// Verify all plugins were initialized and started
	assert.True(t, plugin1.initCalled)
	assert.True(t, plugin1.startCalled)
	assert.True(t, plugin2.initCalled)
	assert.True(t, plugin2.startCalled)
	assert.True(t, plugin3.initCalled)
	assert.True(t, plugin3.startCalled)

	// Stop all plugins
	require.NoError(t, registry.Stop(ctx))

	// Verify all plugins were stopped
	assert.True(t, plugin1.stopCalled)
	assert.True(t, plugin2.stopCalled)
	assert.True(t, plugin3.stopCalled)
}

func TestRegistry_CircularDependency(t *testing.T) {
	registry := NewRegistry()
	
	// Create plugins with circular dependency: plugin1 -> plugin2 -> plugin3 -> plugin1
	plugin1 := NewTestPlugin("plugin1")
	plugin2 := NewTestPlugin("plugin2", "plugin1")
	plugin3 := NewTestPlugin("plugin3", "plugin2")

	// Register plugins in order
	require.NoError(t, registry.Register(plugin1))
	require.NoError(t, registry.Register(plugin2))
	require.NoError(t, registry.Register(plugin3))

	// Manually create circular dependency by modifying plugin1's dependencies
	// This simulates a circular dependency that would be detected at start time
	plugin1.info.Dependencies = []string{"plugin3"}
	
	// Starting should fail due to circular dependency
	ctx := context.Background()
	err := registry.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency")
}

func TestRegistry_GetByCapability(t *testing.T) {
	registry := NewRegistry()
	
	// Create plugins with different capabilities
	plugin1 := NewTestPlugin("plugin1")
	plugin1.info.Capabilities = []string{"storage", "compute"}
	
	plugin2 := NewTestPlugin("plugin2")
	plugin2.info.Capabilities = []string{"storage"}
	
	plugin3 := NewTestPlugin("plugin3")
	plugin3.info.Capabilities = []string{"compute"}

	// Register plugins
	require.NoError(t, registry.Register(plugin1))
	require.NoError(t, registry.Register(plugin2))
	require.NoError(t, registry.Register(plugin3))

	// Get plugins by capability
	storagePlugins := registry.GetByCapability(CapabilityStorage)
	assert.Len(t, storagePlugins, 2)

	computePlugins := registry.GetByCapability(CapabilityCompute)
	assert.Len(t, computePlugins, 2)
}

func TestRegistry_Events(t *testing.T) {
	registry := NewRegistry()
	
	// Subscribe to events
	events := make([]Event, 0)
	unsubscribe := registry.Subscribe("plugin.started", func(event Event) {
		events = append(events, event)
	})
	defer unsubscribe()

	// Register and start a plugin
	plugin := NewTestPlugin("test")
	require.NoError(t, registry.Register(plugin))

	ctx := context.Background()
	require.NoError(t, registry.Start(ctx))

	// Give events time to propagate
	time.Sleep(100 * time.Millisecond)

	// Verify event was received
	assert.Len(t, events, 1)
	assert.Equal(t, "plugin.started", events[0].Type)
}

func TestRegistry_Hooks(t *testing.T) {
	registry := NewRegistry()
	
	// Register hooks
	preStartCalled := false
	postStartCalled := false
	
	registry.RegisterHook(HookPreStart, func(ctx context.Context, data interface{}) error {
		preStartCalled = true
		return nil
	})
	
	registry.RegisterHook(HookPostStart, func(ctx context.Context, data interface{}) error {
		postStartCalled = true
		return nil
	})

	// Register and start a plugin
	plugin := NewTestPlugin("test")
	require.NoError(t, registry.Register(plugin))

	ctx := context.Background()
	require.NoError(t, registry.Start(ctx))

	// Verify hooks were called
	assert.True(t, preStartCalled)
	assert.True(t, postStartCalled)
}

func TestPluginBuilder(t *testing.T) {
	// Build a plugin using the builder
	plugin := NewPluginBuilder("test-builder").
		WithVersion("2.0.0").
		WithDescription("A test plugin built with builder").
		WithAuthor("Test Author").
		WithLicense("MIT").
		WithDependencies("dep1", "dep2").
		WithCapabilities(CapabilityStorage, CapabilityCompute).
		Build()

	// Verify plugin info
	info := plugin.Info()
	assert.Equal(t, "test-builder", info.Name)
	assert.Equal(t, "2.0.0", info.Version)
	assert.Equal(t, "A test plugin built with builder", info.Description)
	assert.Equal(t, "Test Author", info.Author)
	assert.Equal(t, "MIT", info.License)
	assert.Equal(t, []string{"dep1", "dep2"}, info.Dependencies)
	assert.Contains(t, info.Capabilities, string(CapabilityStorage))
	assert.Contains(t, info.Capabilities, string(CapabilityCompute))

	// Test plugin lifecycle
	ctx := context.Background()
	require.NoError(t, plugin.Init(ctx, make(Config)))
	require.NoError(t, plugin.Start(ctx))
	
	health := plugin.Health()
	assert.Equal(t, HealthStatusHealthy, health.Status)
	
	require.NoError(t, plugin.Stop(ctx))
}

func TestBasePlugin_Configuration(t *testing.T) {
	plugin := NewBasePlugin(Info{Name: "test"})
	
	// Test configuration methods
	ctx := context.Background()
	config := Config{
		"string_key":   "value",
		"int_key":      42,
		"bool_key":     true,
		"duration_key": "5s",
	}
	
	require.NoError(t, plugin.Configure(ctx, config))
	
	// Test GetConfigString
	assert.Equal(t, "value", plugin.GetConfigString("string_key", "default"))
	assert.Equal(t, "default", plugin.GetConfigString("missing_key", "default"))
	
	// Test GetConfigInt
	assert.Equal(t, 42, plugin.GetConfigInt("int_key", 0))
	assert.Equal(t, 0, plugin.GetConfigInt("missing_key", 0))
	
	// Test GetConfigBool
	assert.True(t, plugin.GetConfigBool("bool_key", false))
	assert.False(t, plugin.GetConfigBool("missing_key", false))
	
	// Test GetConfigDuration
	assert.Equal(t, 5*time.Second, plugin.GetConfigDuration("duration_key", time.Second))
	assert.Equal(t, time.Second, plugin.GetConfigDuration("missing_key", time.Second))
}