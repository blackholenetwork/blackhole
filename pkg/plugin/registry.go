package plugin

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/common/errors"
)

// Registry manages all plugins in the system
type Registry struct {
	mu           sync.RWMutex
	plugins      map[string]Plugin
	hooks        map[Hook][]HookFunc
	events       *EventBus
	state        RegistryState
	sharedStore  *SharedStore
	messageQueue *MessageQueue
}

// RegistryState represents the state of the plugin registry
type RegistryState string

// Registry state constants
const (
	RegistryStateInitialized RegistryState = "initialized"
	RegistryStateStarting    RegistryState = "starting"
	RegistryStateRunning     RegistryState = "running"
	RegistryStateStopping    RegistryState = "stopping"
	RegistryStateStopped     RegistryState = "stopped"
)

// EventBus handles event publishing and subscription
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]EventHandler
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
		hooks:   make(map[Hook][]HookFunc),
		events: &EventBus{
			subscribers: make(map[string][]EventHandler),
		},
		state:        RegistryStateInitialized,
		sharedStore:  NewSharedStore(),
		messageQueue: nil, // Will be initialized on Start
	}
}

// Register registers a plugin
func (r *Registry) Register(plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != RegistryStateInitialized {
		return fmt.Errorf("cannot register plugin in state %s", r.state)
	}

	info := plugin.Info()
	if info.Name == "" {
		return errors.NewValidationError("name", "plugin name cannot be empty")
	}

	if _, exists := r.plugins[info.Name]; exists {
		return fmt.Errorf("plugin %s already registered", info.Name)
	}

	// Validate dependencies exist
	for _, dep := range info.Dependencies {
		if _, exists := r.plugins[dep]; !exists {
			return fmt.Errorf("dependency %s not found for plugin %s", dep, info.Name)
		}
	}

	r.plugins[info.Name] = plugin

	// Publish registration event
	r.events.Publish(Event{
		Type:      "plugin.registered",
		Source:    "registry",
		Data:      info,
		Timestamp: time.Now(),
	})

	return nil
}

// Get returns a plugin by name
func (r *Registry) Get(name string) (Plugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.plugins[name]
	if !exists {
		return nil, errors.NewNotFoundError("plugin", name)
	}

	return plugin, nil
}

// GetByCapability returns all plugins with a specific capability
func (r *Registry) GetByCapability(capability Capability) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Plugin
	for _, plugin := range r.plugins {
		info := plugin.Info()
		for _, cap := range info.Capabilities {
			if cap == string(capability) {
				result = append(result, plugin)
				break
			}
		}
	}

	return result
}

// List returns all registered plugins
func (r *Registry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Plugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		result = append(result, plugin)
	}

	return result
}

// Start initializes and starts all plugins
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.state != RegistryStateInitialized {
		r.mu.Unlock()
		return fmt.Errorf("cannot start from state %s", r.state)
	}
	r.state = RegistryStateStarting

	// Initialize message queue
	r.messageQueue = NewMessageQueue(ctx)
	r.mu.Unlock()

	// Calculate startup order based on dependencies
	order, err := r.calculateStartupOrder()
	if err != nil {
		r.mu.Lock()
		r.state = RegistryStateInitialized
		r.mu.Unlock()
		return fmt.Errorf("failed to calculate startup order: %w", err)
	}

	// Trigger pre-start hooks
	if err := r.TriggerHook(ctx, HookPreStart, nil); err != nil {
		r.mu.Lock()
		r.state = RegistryStateInitialized
		r.mu.Unlock()
		return fmt.Errorf("pre-start hook failed: %w", err)
	}

	// Initialize and start plugins in order
	started := []string{}
	for _, name := range order {
		plugin := r.plugins[name]

		// Initialize plugin
		if err := plugin.Init(ctx, make(Config)); err != nil {
			r.rollbackStarted(ctx, started)
			r.mu.Lock()
			r.state = RegistryStateInitialized
			r.mu.Unlock()
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
		}

		// Start plugin
		if err := plugin.Start(ctx); err != nil {
			r.rollbackStarted(ctx, started)
			r.mu.Lock()
			r.state = RegistryStateInitialized
			r.mu.Unlock()
			return fmt.Errorf("failed to start plugin %s: %w", name, err)
		}

		started = append(started, name)

		// Publish start event
		r.events.Publish(Event{
			Type:      "plugin.started",
			Source:    "registry",
			Data:      plugin.Info(),
			Timestamp: time.Now(),
		})
	}

	// Trigger post-start hooks
	if err := r.TriggerHook(ctx, HookPostStart, nil); err != nil {
		// Non-fatal: log but continue
		fmt.Printf("Warning: post-start hook failed: %v\n", err)
	}

	r.mu.Lock()
	r.state = RegistryStateRunning
	r.mu.Unlock()

	return nil
}

// Stop gracefully shuts down all plugins
func (r *Registry) Stop(ctx context.Context) error {
	r.mu.Lock()
	if r.state != RegistryStateRunning {
		r.mu.Unlock()
		return fmt.Errorf("cannot stop from state %s", r.state)
	}
	r.state = RegistryStateStopping
	r.mu.Unlock()

	// Trigger pre-stop hooks
	if err := r.TriggerHook(ctx, HookPreStop, nil); err != nil {
		// Non-fatal: log but continue
		fmt.Printf("Warning: pre-stop hook failed: %v\n", err)
	}

	// Calculate shutdown order (reverse of startup)
	order, _ := r.calculateStartupOrder()

	// Stop plugins in reverse order
	for i := len(order) - 1; i >= 0; i-- {
		name := order[i]
		plugin := r.plugins[name]

		if err := plugin.Stop(ctx); err != nil {
			// Log error but continue stopping other plugins
			fmt.Printf("Error stopping plugin %s: %v\n", name, err)
		}

		// Publish stop event
		r.events.Publish(Event{
			Type:      "plugin.stopped",
			Source:    "registry",
			Data:      plugin.Info(),
			Timestamp: time.Now(),
		})
	}

	// Trigger post-stop hooks
	if err := r.TriggerHook(ctx, HookPostStop, nil); err != nil {
		// Non-fatal: log
		fmt.Printf("Warning: post-stop hook failed: %v\n", err)
	}

	// Stop message queue
	r.mu.Lock()
	if r.messageQueue != nil {
		r.messageQueue.Stop()
		r.messageQueue = nil
	}
	r.state = RegistryStateStopped
	r.mu.Unlock()

	return nil
}

// RegisterHook registers a function for a specific hook
func (r *Registry) RegisterHook(hook Hook, fn HookFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hooks[hook] = append(r.hooks[hook], fn)
}

// TriggerHook executes all functions registered for a hook
func (r *Registry) TriggerHook(ctx context.Context, hook Hook, data interface{}) error {
	r.mu.RLock()
	hooks := r.hooks[hook]
	r.mu.RUnlock()

	for _, fn := range hooks {
		if err := fn(ctx, data); err != nil {
			return fmt.Errorf("hook %s failed: %w", hook, err)
		}
	}

	return nil
}

// Publish publishes an event
func (r *Registry) Publish(event Event) {
	r.events.Publish(event)
}

// Subscribe subscribes to events of a specific type
func (r *Registry) Subscribe(eventType string, handler EventHandler) func() {
	return r.events.Subscribe(eventType, handler)
}

// calculateStartupOrder determines the order to start plugins based on dependencies
func (r *Registry) calculateStartupOrder() ([]string, error) {
	// Simple topological sort
	visited := make(map[string]bool)
	temp := make(map[string]bool)
	order := []string{}

	var visit func(string) error
	visit = func(name string) error {
		if temp[name] {
			return fmt.Errorf("circular dependency detected at plugin %s", name)
		}
		if visited[name] {
			return nil
		}

		temp[name] = true
		plugin := r.plugins[name]

		for _, dep := range plugin.Info().Dependencies {
			if err := visit(dep); err != nil {
				return err
			}
		}

		temp[name] = false
		visited[name] = true
		order = append(order, name)

		return nil
	}

	for name := range r.plugins {
		if err := visit(name); err != nil {
			return nil, err
		}
	}

	return order, nil
}

// rollbackStarted stops plugins that were started
func (r *Registry) rollbackStarted(ctx context.Context, started []string) {
	for i := len(started) - 1; i >= 0; i-- {
		name := started[i]
		plugin := r.plugins[name]

		if err := plugin.Stop(ctx); err != nil {
			fmt.Printf("Error stopping plugin %s during rollback: %v\n", name, err)
		}
	}
}

// EventBus methods

// Publish publishes an event to all subscribers
func (eb *EventBus) Publish(event Event) {
	eb.mu.RLock()
	handlers := eb.subscribers[event.Type]
	eb.mu.RUnlock()

	for _, handler := range handlers {
		// Call handler in goroutine to prevent blocking
		go handler(event)
	}
}

// Subscribe subscribes to events of a specific type
func (eb *EventBus) Subscribe(eventType string, handler EventHandler) func() {
	eb.mu.Lock()
	eb.subscribers[eventType] = append(eb.subscribers[eventType], handler)
	eb.mu.Unlock()

	// Return unsubscribe function
	return func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		handlers := eb.subscribers[eventType]
		for i, h := range handlers {
			// Compare function pointers properly
			if fmt.Sprintf("%p", h) == fmt.Sprintf("%p", handler) {
				eb.subscribers[eventType] = append(handlers[:i], handlers[i+1:]...)
				break
			}
		}
	}
}

// Communication component access methods

// SharedStore returns the shared data store
func (r *Registry) SharedStore() *SharedStore {
	return r.sharedStore
}

// MessageQueue returns the message queue
func (r *Registry) MessageQueue() *MessageQueue {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.messageQueue
}

// SetShared stores a value in the shared store
func (r *Registry) SetShared(key string, value interface{}) {
	r.sharedStore.Set(key, value)

	// Also publish event for watchers
	r.Publish(Event{
		Type:   "shared.updated",
		Source: "registry",
		Data: map[string]interface{}{
			"key":   key,
			"value": value,
		},
	})
}

// GetShared retrieves a value from the shared store
func (r *Registry) GetShared(key string) (interface{}, bool) {
	return r.sharedStore.Get(key)
}

// PublishMessage publishes a message to a topic
func (r *Registry) PublishMessage(topic string, payload interface{}) error {
	r.mu.RLock()
	mq := r.messageQueue
	r.mu.RUnlock()

	if mq == nil {
		return fmt.Errorf("message queue not initialized")
	}

	return mq.Publish(topic, payload)
}

// SubscribeToTopic subscribes to messages on a topic
func (r *Registry) SubscribeToTopic(topic string, handler MessageHandler) (func(), error) {
	r.mu.RLock()
	mq := r.messageQueue
	r.mu.RUnlock()

	if mq == nil {
		return nil, fmt.Errorf("message queue not initialized")
	}

	return mq.Subscribe(topic, handler), nil
}
