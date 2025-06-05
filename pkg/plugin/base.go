package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BasePlugin provides common functionality for all plugins
type BasePlugin struct {
	mu      sync.RWMutex
	info    Info
	config  Config
	started bool
	hooks   map[Hook][]HookFunc
	events  chan Event
	registry *Registry
}

// NewBasePlugin creates a new base plugin
func NewBasePlugin(info Info) *BasePlugin {
	// Set CreatedAt if not already set
	if info.CreatedAt.IsZero() {
		info.CreatedAt = time.Now()
	}
	
	return &BasePlugin{
		info:   info,
		config: make(Config),
		hooks:  make(map[Hook][]HookFunc),
		events: make(chan Event, 100),
	}
}

// SetRegistry sets the plugin registry for event publishing
func (bp *BasePlugin) SetRegistry(registry *Registry) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.registry = registry
}

// Info returns metadata about the plugin
func (bp *BasePlugin) Info() Info {
	return bp.info
}

// Init initializes the plugin with configuration
func (bp *BasePlugin) Init(ctx context.Context, config Config) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.started {
		return fmt.Errorf("plugin already initialized")
	}

	bp.config = config

	// Trigger init hooks
	bp.triggerHook(HookPostInit, nil)

	return nil
}

// Start starts the plugin
func (bp *BasePlugin) Start(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.started {
		return fmt.Errorf("plugin already started")
	}

	bp.started = true

	// Trigger start hooks
	bp.triggerHook(HookPostStart, nil)

	return nil
}

// Stop gracefully shuts down the plugin
func (bp *BasePlugin) Stop(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if !bp.started {
		return nil
	}

	// Trigger stop hooks
	bp.triggerHook(HookPreStop, nil)

	bp.started = false

	close(bp.events)

	return nil
}

// Health returns the current health status
// This is a default implementation that should be overridden by plugins
func (bp *BasePlugin) Health() Health {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	if !bp.started {
		return Health{
			Status:    HealthStatusUnknown,
			Message:   "Plugin not started",
			LastCheck: time.Now(),
		}
	}

	return Health{
		Status:    HealthStatusHealthy,
		Message:   "Plugin is running",
		LastCheck: time.Now(),
	}
}

// Configure updates the plugin configuration
func (bp *BasePlugin) Configure(ctx context.Context, config Config) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Merge configurations
	for k, v := range config {
		bp.config[k] = v
	}

	return nil
}

// GetConfig returns the current configuration
func (bp *BasePlugin) GetConfig() Config {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	// Return a copy
	config := make(Config)
	for k, v := range bp.config {
		config[k] = v
	}

	return config
}

// RegisterHook registers a function for a specific hook
func (bp *BasePlugin) RegisterHook(hook Hook, fn HookFunc) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.hooks[hook] = append(bp.hooks[hook], fn)
}

// PublishEvent publishes an event
func (bp *BasePlugin) PublishEvent(event Event) {
	select {
	case bp.events <- event:
	default:
		// Event channel full, drop event
		// In production, we might want to log this
	}
}

// Events returns the event channel
func (bp *BasePlugin) Events() <-chan Event {
	return bp.events
}

// SetHealth publishes a health change event
// Note: This method only publishes events, it does not store health state
// Plugins should manage their own health status internally
func (bp *BasePlugin) SetHealth(status HealthStatus, message string) {
	bp.mu.RLock()
	registry := bp.registry
	name := bp.info.Name
	bp.mu.RUnlock()

	health := Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
	}

	// Publish health change event
	if registry != nil {
		registry.Publish(Event{
			Type:      EventHealthChanged,
			Source:    name,
			Data:      health,
			Timestamp: time.Now(),
		})
	}
}

// SetHealthWithDetails publishes a health change event with details
// Note: This method only publishes events, it does not store health state
// Plugins should manage their own health status internally
func (bp *BasePlugin) SetHealthWithDetails(status HealthStatus, message string, details map[string]interface{}) {
	bp.mu.RLock()
	registry := bp.registry
	name := bp.info.Name
	bp.mu.RUnlock()

	health := Health{
		Status:    status,
		Message:   message,
		Details:   details,
		LastCheck: time.Now(),
	}

	// Publish health change event
	if registry != nil {
		registry.Publish(Event{
			Type:      EventHealthChanged,
			Source:    name,
			Data:      health,
			Timestamp: time.Now(),
		})
	}
}

// IsStarted returns whether the plugin is started
func (bp *BasePlugin) IsStarted() bool {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.started
}

// GetConfigValue retrieves a configuration value
func (bp *BasePlugin) GetConfigValue(key string) (interface{}, bool) {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	value, exists := bp.config[key]
	return value, exists
}

// GetConfigString retrieves a string configuration value
func (bp *BasePlugin) GetConfigString(key string, defaultValue string) string {
	value, exists := bp.GetConfigValue(key)
	if !exists {
		return defaultValue
	}

	str, ok := value.(string)
	if !ok {
		return defaultValue
	}

	return str
}

// GetConfigInt retrieves an integer configuration value
func (bp *BasePlugin) GetConfigInt(key string, defaultValue int) int {
	value, exists := bp.GetConfigValue(key)
	if !exists {
		return defaultValue
	}

	// Handle different numeric types
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return defaultValue
	}
}

// GetConfigBool retrieves a boolean configuration value
func (bp *BasePlugin) GetConfigBool(key string, defaultValue bool) bool {
	value, exists := bp.GetConfigValue(key)
	if !exists {
		return defaultValue
	}

	b, ok := value.(bool)
	if !ok {
		return defaultValue
	}

	return b
}

// GetConfigDuration retrieves a duration configuration value
func (bp *BasePlugin) GetConfigDuration(key string, defaultValue time.Duration) time.Duration {
	value, exists := bp.GetConfigValue(key)
	if !exists {
		return defaultValue
	}

	switch v := value.(type) {
	case time.Duration:
		return v
	case string:
		d, err := time.ParseDuration(v)
		if err != nil {
			return defaultValue
		}
		return d
	case int64:
		return time.Duration(v)
	default:
		return defaultValue
	}
}

// Private methods

func (bp *BasePlugin) triggerHook(hook Hook, data interface{}) {
	hooks := bp.hooks[hook]
	for _, fn := range hooks {
		// Run hooks in goroutines to prevent blocking
		go func(hookFn HookFunc) {
			_ = hookFn(context.Background(), data)
		}(fn)
	}
}

// PluginBuilder provides a fluent interface for building plugins
type PluginBuilder struct {
	info   Info
	initFn func(context.Context, Config) error
	startFn func(context.Context) error
	stopFn func(context.Context) error
	healthFn func() Health
}

// NewPluginBuilder creates a new plugin builder
func NewPluginBuilder(name string) *PluginBuilder {
	return &PluginBuilder{
		info: Info{
			Name:    name,
			Version: "1.0.0",
		},
	}
}

// WithVersion sets the plugin version
func (pb *PluginBuilder) WithVersion(version string) *PluginBuilder {
	pb.info.Version = version
	return pb
}

// WithDescription sets the plugin description
func (pb *PluginBuilder) WithDescription(description string) *PluginBuilder {
	pb.info.Description = description
	return pb
}

// WithAuthor sets the plugin author
func (pb *PluginBuilder) WithAuthor(author string) *PluginBuilder {
	pb.info.Author = author
	return pb
}

// WithLicense sets the plugin license
func (pb *PluginBuilder) WithLicense(license string) *PluginBuilder {
	pb.info.License = license
	return pb
}

// WithDependencies sets the plugin dependencies
func (pb *PluginBuilder) WithDependencies(dependencies ...string) *PluginBuilder {
	pb.info.Dependencies = dependencies
	return pb
}

// WithCapabilities sets the plugin capabilities
func (pb *PluginBuilder) WithCapabilities(capabilities ...Capability) *PluginBuilder {
	pb.info.Capabilities = make([]string, len(capabilities))
	for i, cap := range capabilities {
		pb.info.Capabilities[i] = string(cap)
	}
	return pb
}

// WithInit sets the init function
func (pb *PluginBuilder) WithInit(fn func(context.Context, Config) error) *PluginBuilder {
	pb.initFn = fn
	return pb
}

// WithStart sets the start function
func (pb *PluginBuilder) WithStart(fn func(context.Context) error) *PluginBuilder {
	pb.startFn = fn
	return pb
}

// WithStop sets the stop function
func (pb *PluginBuilder) WithStop(fn func(context.Context) error) *PluginBuilder {
	pb.stopFn = fn
	return pb
}

// WithHealth sets the health function
func (pb *PluginBuilder) WithHealth(fn func() Health) *PluginBuilder {
	pb.healthFn = fn
	return pb
}

// Build creates the plugin
func (pb *PluginBuilder) Build() Plugin {
	return &builtPlugin{
		BasePlugin: NewBasePlugin(pb.info),
		initFn:     pb.initFn,
		startFn:    pb.startFn,
		stopFn:     pb.stopFn,
		healthFn:   pb.healthFn,
	}
}

// builtPlugin is a plugin created by the builder
type builtPlugin struct {
	*BasePlugin
	initFn   func(context.Context, Config) error
	startFn  func(context.Context) error
	stopFn   func(context.Context) error
	healthFn func() Health
}

// Init initializes the plugin
func (bp *builtPlugin) Init(ctx context.Context, config Config) error {
	if err := bp.BasePlugin.Init(ctx, config); err != nil {
		return err
	}

	if bp.initFn != nil {
		return bp.initFn(ctx, config)
	}

	return nil
}

// Start starts the plugin
func (bp *builtPlugin) Start(ctx context.Context) error {
	if err := bp.BasePlugin.Start(ctx); err != nil {
		return err
	}

	if bp.startFn != nil {
		return bp.startFn(ctx)
	}

	return nil
}

// Stop stops the plugin
func (bp *builtPlugin) Stop(ctx context.Context) error {
	if bp.stopFn != nil {
		if err := bp.stopFn(ctx); err != nil {
			return err
		}
	}

	return bp.BasePlugin.Stop(ctx)
}

// Health returns the plugin health
func (bp *builtPlugin) Health() Health {
	if bp.healthFn != nil {
		return bp.healthFn()
	}

	return bp.BasePlugin.Health()
}