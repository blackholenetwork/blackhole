package plugin

import (
    "context"
    "fmt"
    "sync"
)

// Plugin is the base interface all plugins must implement
type Plugin interface {
    Name() string
    Version() string
    Description() string
    Init(config map[string]interface{}) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    Health() HealthStatus
}

// HealthStatus represents plugin health
type HealthStatus struct {
    Healthy bool
    Message string
}

// Registry manages all plugins
type Registry struct {
    mu      sync.RWMutex
    plugins map[string]Plugin
    started map[string]bool
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
    return &Registry{
        plugins: make(map[string]Plugin),
        started: make(map[string]bool),
    }
}

// Register adds a plugin to the registry
func (r *Registry) Register(p Plugin) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    name := p.Name()
    if _, exists := r.plugins[name]; exists {
        return fmt.Errorf("plugin %s already registered", name)
    }
    
    r.plugins[name] = p
    return nil
}

// Get retrieves a plugin by name
func (r *Registry) Get(name string) (Plugin, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    p, ok := r.plugins[name]
    return p, ok
}

// List returns all registered plugins
func (r *Registry) List() []Plugin {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    plugins := make([]Plugin, 0, len(r.plugins))
    for _, p := range r.plugins {
        plugins = append(plugins, p)
    }
    return plugins
}

// InitAll initializes all plugins
func (r *Registry) InitAll(configs map[string]map[string]interface{}) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    for name, plugin := range r.plugins {
        config := configs[name]
        if config == nil {
            config = make(map[string]interface{})
        }
        
        if err := plugin.Init(config); err != nil {
            return fmt.Errorf("failed to init plugin %s: %w", name, err)
        }
    }
    
    return nil
}

// StartAll starts all plugins
func (r *Registry) StartAll(ctx context.Context) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    for name, plugin := range r.plugins {
        if err := plugin.Start(ctx); err != nil {
            // Stop already started plugins
            r.stopStartedPlugins(ctx)
            return fmt.Errorf("failed to start plugin %s: %w", name, err)
        }
        r.started[name] = true
    }
    
    return nil
}

// StopAll stops all plugins
func (r *Registry) StopAll(ctx context.Context) error {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    return r.stopStartedPlugins(ctx)
}

// stopStartedPlugins stops only plugins that were started
func (r *Registry) stopStartedPlugins(ctx context.Context) error {
    var errs []error
    
    for name, plugin := range r.plugins {
        if !r.started[name] {
            continue
        }
        
        if err := plugin.Stop(ctx); err != nil {
            errs = append(errs, fmt.Errorf("failed to stop plugin %s: %w", name, err))
        }
        delete(r.started, name)
    }
    
    if len(errs) > 0 {
        return fmt.Errorf("errors stopping plugins: %v", errs)
    }
    
    return nil
}

// HealthCheck checks health of all plugins
func (r *Registry) HealthCheck() map[string]HealthStatus {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    health := make(map[string]HealthStatus)
    for name, plugin := range r.plugins {
        health[name] = plugin.Health()
    }
    
    return health
}

// Hook system for extensibility

// HookPoint represents a point where plugins can hook into
type HookPoint string

const (
    HookBeforeRequest  HookPoint = "before_request"
    HookAfterRequest   HookPoint = "after_request"
    HookBeforeStorage  HookPoint = "before_storage"
    HookAfterStorage   HookPoint = "after_storage"
)

// Hook represents a function that can be called at hook points
type Hook func(ctx context.Context, data interface{}) (interface{}, error)

// HookRegistry manages hooks
type HookRegistry struct {
    mu    sync.RWMutex
    hooks map[HookPoint][]Hook
}

// NewHookRegistry creates a new hook registry
func NewHookRegistry() *HookRegistry {
    return &HookRegistry{
        hooks: make(map[HookPoint][]Hook),
    }
}

// Register adds a hook
func (h *HookRegistry) Register(point HookPoint, hook Hook) {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    h.hooks[point] = append(h.hooks[point], hook)
}

// Execute runs all hooks for a point
func (h *HookRegistry) Execute(ctx context.Context, point HookPoint, data interface{}) (interface{}, error) {
    h.mu.RLock()
    defer h.mu.RUnlock()
    
    hooks := h.hooks[point]
    
    var err error
    for _, hook := range hooks {
        data, err = hook(ctx, data)
        if err != nil {
            return data, err
        }
    }
    
    return data, nil
}