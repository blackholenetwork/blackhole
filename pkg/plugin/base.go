// Package plugin provides the base plugin infrastructure and interfaces
package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BasePlugin provides common functionality for all plugins
type BasePlugin struct {
	mu       sync.RWMutex
	info     Info
	config   Config
	state    PluginState
	hooks    map[Hook][]HookFunc
	events   chan Event
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
		state:  StateInitialized,
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

	if bp.state != StateInitialized {
		return fmt.Errorf("plugin cannot be initialized from state %s", bp.state)
	}

	bp.logStateTransition(StateInitialized, StateInitialized, "configuring plugin")
	bp.config = config

	// Trigger init hooks
	if err := bp.triggerHookSync(ctx, HookPostInit, nil); err != nil {
		bp.setState(StateError)
		bp.logStateTransition(StateInitialized, StateError, fmt.Sprintf("init hook failed: %v", err))
		return fmt.Errorf("init hook failed: %w", err)
	}

	bp.logStateTransition(StateInitialized, StateInitialized, "plugin configured successfully")
	return nil
}

// Start starts the plugin
func (bp *BasePlugin) Start(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.state != StateInitialized {
		return fmt.Errorf("plugin cannot be started from state %s", bp.state)
	}

	// Transition to starting
	bp.setState(StateStarting)
	bp.logStateTransition(StateInitialized, StateStarting, "plugin starting")

	// Trigger pre-start hooks
	if err := bp.triggerHookSync(ctx, HookPreStart, nil); err != nil {
		bp.setState(StateError)
		bp.logStateTransition(StateStarting, StateError, fmt.Sprintf("pre-start hook failed: %v", err))
		return fmt.Errorf("pre-start hook failed: %w", err)
	}

	// Transition to running
	bp.setState(StateRunning)
	bp.logStateTransition(StateStarting, StateRunning, "plugin started successfully")

	// Trigger post-start hooks
	if err := bp.triggerHookSync(ctx, HookPostStart, nil); err != nil {
		bp.logStateTransition(StateRunning, StateRunning, fmt.Sprintf("post-start hook failed (plugin still running): %v", err))
		// Don't fail the start if post-start hooks fail, just log it
	}

	return nil
}

// Stop gracefully shuts down the plugin
func (bp *BasePlugin) Stop(ctx context.Context) error {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	if bp.state == StateStopped {
		return nil // Already stopped
	}

	if bp.state != StateRunning {
		return fmt.Errorf("plugin cannot be stopped from state %s", bp.state)
	}

	// Transition to stopping
	bp.setState(StateStopping)
	bp.logStateTransition(StateRunning, StateStopping, "plugin stopping")

	// Trigger pre-stop hooks
	if err := bp.triggerHookSync(ctx, HookPreStop, nil); err != nil {
		bp.logStateTransition(StateStopping, StateStopping, fmt.Sprintf("pre-stop hook failed (continuing shutdown): %v", err))
		// Continue with shutdown even if pre-stop hooks fail
	}

	// Transition to stopped
	bp.setState(StateStopped)
	bp.logStateTransition(StateStopping, StateStopped, "plugin stopped successfully")

	// Trigger post-stop hooks
	if err := bp.triggerHookSync(ctx, HookPostStop, nil); err != nil {
		bp.logStateTransition(StateStopped, StateStopped, fmt.Sprintf("post-stop hook failed: %v", err))
		// Don't fail the stop if post-stop hooks fail
	}

	close(bp.events)

	return nil
}

// Health returns the current health status
// This is a default implementation that should be overridden by plugins
func (bp *BasePlugin) Health() Health {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	switch bp.state {
	case StateRunning:
		return Health{
			Status:    HealthStatusHealthy,
			Message:   "Plugin is running",
			LastCheck: time.Now(),
		}
	case StateError:
		return Health{
			Status:    HealthStatusUnhealthy,
			Message:   "Plugin is in error state",
			LastCheck: time.Now(),
		}
	case StateStarting, StateStopping:
		return Health{
			Status:    HealthStatusDegraded,
			Message:   fmt.Sprintf("Plugin is %s", bp.state),
			LastCheck: time.Now(),
		}
	default:
		return Health{
			Status:    HealthStatusUnknown,
			Message:   fmt.Sprintf("Plugin state: %s", bp.state),
			LastCheck: time.Now(),
		}
	}
}

// Configure updates the plugin configuration
func (bp *BasePlugin) Configure(_ context.Context, config Config) error {
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
	return bp.state == StateRunning
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

// Builder provides a fluent interface for building plugins
type Builder struct {
	info     Info
	initFn   func(context.Context, Config) error
	startFn  func(context.Context) error
	stopFn   func(context.Context) error
	healthFn func() Health
}

// NewBuilder creates a new plugin builder
func NewBuilder(name string) *Builder {
	return &Builder{
		info: Info{
			Name:    name,
			Version: "1.0.0",
		},
	}
}

// WithVersion sets the plugin version
func (pb *Builder) WithVersion(version string) *Builder {
	pb.info.Version = version
	return pb
}

// WithDescription sets the plugin description
func (pb *Builder) WithDescription(description string) *Builder {
	pb.info.Description = description
	return pb
}

// WithAuthor sets the plugin author
func (pb *Builder) WithAuthor(author string) *Builder {
	pb.info.Author = author
	return pb
}

// WithLicense sets the plugin license
func (pb *Builder) WithLicense(license string) *Builder {
	pb.info.License = license
	return pb
}

// WithDependencies sets the plugin dependencies
func (pb *Builder) WithDependencies(dependencies ...string) *Builder {
	pb.info.Dependencies = dependencies
	return pb
}

// WithCapabilities sets the plugin capabilities
func (pb *Builder) WithCapabilities(capabilities ...Capability) *Builder {
	pb.info.Capabilities = make([]string, len(capabilities))
	for i, cap := range capabilities {
		pb.info.Capabilities[i] = string(cap)
	}
	return pb
}

// WithInit sets the init function
func (pb *Builder) WithInit(fn func(context.Context, Config) error) *Builder {
	pb.initFn = fn
	return pb
}

// WithStart sets the start function
func (pb *Builder) WithStart(fn func(context.Context) error) *Builder {
	pb.startFn = fn
	return pb
}

// WithStop sets the stop function
func (pb *Builder) WithStop(fn func(context.Context) error) *Builder {
	pb.stopFn = fn
	return pb
}

// WithHealth sets the health function
func (pb *Builder) WithHealth(fn func() Health) *Builder {
	pb.healthFn = fn
	return pb
}

// Build creates the plugin
func (pb *Builder) Build() Plugin {
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

// setState sets the plugin state (internal method)
func (bp *BasePlugin) setState(state PluginState) {
	bp.state = state
}

// GetState returns the current plugin state
func (bp *BasePlugin) GetState() PluginState {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	return bp.state
}

// logStateTransition logs a state transition to the orchestrator
func (bp *BasePlugin) logStateTransition(from, to PluginState, message string) {
	// This will be implemented to send events to orchestrator for logging
	// For now, we'll just emit an event if registry is available
	if bp.registry != nil {
		event := Event{
			Type:      "state_transition",
			Source:    bp.info.Name,
			Data: map[string]interface{}{
				"from":    from,
				"to":      to,
				"message": message,
			},
			Timestamp: time.Now(),
		}
		bp.registry.Publish(event)
	}
}

// triggerHookSync triggers hooks synchronously and returns any error
func (bp *BasePlugin) triggerHookSync(ctx context.Context, hook Hook, data interface{}) error {
	hooks := bp.hooks[hook]
	for _, fn := range hooks {
		if err := fn(ctx, data); err != nil {
			return err
		}
	}
	return nil
}
