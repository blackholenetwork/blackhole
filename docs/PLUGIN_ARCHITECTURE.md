# Blackhole Network - Plugin Architecture

## Overview

All components in the Blackhole Network are implemented as plugins. This provides:

1. **Modular Development**: Each component can be developed independently
2. **Clean Interfaces**: Well-defined plugin interfaces ensure proper boundaries
3. **Easy Extension**: New functionality can be added without modifying core code
4. **Hot Reload** (future): Plugins can be updated without restarting the entire system
5. **Third-party Integration**: External developers can create custom plugins

## Plugin Interface

Every plugin must implement the base `Plugin` interface:

```go
type Plugin interface {
    // Info returns metadata about the plugin
    Info() Info

    // Init initializes the plugin with configuration
    Init(ctx context.Context, config Config) error

    // Start starts the plugin
    Start(ctx context.Context) error

    // Stop gracefully shuts down the plugin
    Stop(ctx context.Context) error

    // Health returns the current health status
    Health() Health
}
```

## Plugin Types

### 1. Core Plugins
- **Orchestrator**: System coordination and lifecycle management
- **Security**: Authentication, authorization, and DID management
- **Networking**: P2P communication and peer discovery
- **Monitoring**: Telemetry collection and system notifications
- **ResourceManager**: Resource allocation and job scheduling

### 2. Resource Plugins
- **Storage**: Distributed file storage with erasure coding
- **Compute**: CPU/GPU processing power
- **Bandwidth**: Network bandwidth management
- **Memory**: RAM allocation and monitoring

### 3. Data Plugins
- **Schema**: Dynamic schema evolution
- **Indexer**: Global search and discovery
- **Query**: SQL-like analytics
- **Search**: ML-enhanced search

### 4. Service Plugins
- **WebServer**: HTTP/WebSocket API
- **RealTime**: WebSocket/WebRTC communication
- **Social**: Social graph system

### 5. Economic Plugins
- **Incentive**: Real-time market distribution
- **Contract**: Subscription management

## Creating a Plugin

### Method 1: Using BasePlugin

```go
type MyPlugin struct {
    *plugin.BasePlugin
    // Your fields
}

func NewMyPlugin() *MyPlugin {
    info := plugin.Info{
        Name:         "my-plugin",
        Version:      "1.0.0",
        Description:  "My custom plugin",
        Author:       "Me",
        License:      "Apache-2.0",
        Dependencies: []string{},
        Capabilities: []string{"custom"},
    }

    return &MyPlugin{
        BasePlugin: plugin.NewBasePlugin(info),
    }
}

// Override methods as needed
func (mp *MyPlugin) Start(ctx context.Context) error {
    if err := mp.BasePlugin.Start(ctx); err != nil {
        return err
    }

    // Your start logic
    return nil
}
```

### Method 2: Using PluginBuilder

```go
func NewMyPlugin() plugin.Plugin {
    return plugin.NewPluginBuilder("my-plugin").
        WithVersion("1.0.0").
        WithDescription("My custom plugin").
        WithAuthor("Me").
        WithCapabilities(plugin.CapabilityCustom).
        WithInit(func(ctx context.Context, config plugin.Config) error {
            // Initialization logic
            return nil
        }).
        WithStart(func(ctx context.Context) error {
            // Start logic
            return nil
        }).
        WithStop(func(ctx context.Context) error {
            // Stop logic
            return nil
        }).
        Build()
}
```

## Plugin Lifecycle

1. **Registration**: Plugin is registered with the registry
2. **Dependency Resolution**: Registry calculates startup order based on dependencies
3. **Initialization**: `Init()` is called with configuration
4. **Starting**: `Start()` is called in dependency order
5. **Running**: Plugin operates and reports health
6. **Stopping**: `Stop()` is called in reverse dependency order

## Plugin Registry

The registry manages all plugins:

```go
registry := plugin.NewRegistry()

// Register plugins
registry.Register(NewSecurityPlugin())
registry.Register(NewStoragePlugin())

// Start all plugins
err := registry.Start(ctx)

// Stop all plugins
err := registry.Stop(ctx)

// Get plugin by name
plugin, err := registry.Get("security")

// Get plugins by capability
storagePlugins := registry.GetByCapability(plugin.CapabilityStorage)
```

## Events and Hooks

### Events

Plugins can publish and subscribe to events:

```go
// Publishing events
plugin.PublishEvent(plugin.Event{
    Type:   "file.stored",
    Source: "storage",
    Data:   fileInfo,
})

// Subscribing to events
unsubscribe := registry.Subscribe("file.stored", func(event plugin.Event) {
    // Handle event
})
defer unsubscribe()
```

### Hooks

Plugins can register hooks for lifecycle events:

```go
registry.RegisterHook(plugin.HookPreStart, func(ctx context.Context, data interface{}) error {
    // Called before any plugin starts
    return nil
})
```

## Configuration

Plugins receive configuration during initialization:

```go
config := plugin.Config{
    "storage_path": "/data/storage",
    "max_size":     1024 * 1024 * 1024, // 1GB
    "cache_enabled": true,
}

plugin.Init(ctx, config)
```

Plugins can access configuration using helper methods:

```go
path := plugin.GetConfigString("storage_path", "/tmp")
maxSize := plugin.GetConfigInt("max_size", 1024)
cacheEnabled := plugin.GetConfigBool("cache_enabled", false)
timeout := plugin.GetConfigDuration("timeout", 30*time.Second)
```

## Health Monitoring

Plugins report their health status:

```go
func (p *MyPlugin) Health() plugin.Health {
    return plugin.Health{
        Status:    plugin.HealthStatusHealthy,
        Message:   "Operating normally",
        LastCheck: time.Now(),
        Details: map[string]interface{}{
            "connections": 42,
            "uptime":      time.Since(startTime),
        },
    }
}
```

## Best Practices

1. **Single Responsibility**: Each plugin should have a focused purpose
2. **Clean Dependencies**: Minimize dependencies between plugins
3. **Graceful Shutdown**: Always implement proper cleanup in `Stop()`
4. **Health Reporting**: Provide meaningful health information
5. **Event-Driven**: Use events for loose coupling between plugins
6. **Configuration Validation**: Validate configuration in `Init()`
7. **Error Handling**: Return descriptive errors with context

## Example: Storage Plugin

```go
package storage

import (
    "context"
    "github.com/blackholenetwork/blackhole/pkg/plugin"
)

type StoragePlugin struct {
    *plugin.BasePlugin
    store    *DataStore
    metrics  *Metrics
}

func NewStoragePlugin() *StoragePlugin {
    info := plugin.Info{
        Name:         "storage",
        Version:      "1.0.0",
        Description:  "Distributed storage with erasure coding",
        Author:       "Blackhole Network",
        License:      "Apache-2.0",
        Dependencies: []string{"security", "networking"},
        Capabilities: []string{string(plugin.CapabilityStorage)},
    }

    return &StoragePlugin{
        BasePlugin: plugin.NewBasePlugin(info),
    }
}

func (sp *StoragePlugin) Init(ctx context.Context, config plugin.Config) error {
    if err := sp.BasePlugin.Init(ctx, config); err != nil {
        return err
    }

    // Initialize data store
    sp.store = NewDataStore(
        sp.GetConfigString("path", "/data"),
        sp.GetConfigInt("max_size", 1024*1024*1024),
    )

    // Initialize metrics
    sp.metrics = NewMetrics()

    return nil
}

func (sp *StoragePlugin) Start(ctx context.Context) error {
    if err := sp.BasePlugin.Start(ctx); err != nil {
        return err
    }

    // Start background tasks
    go sp.garbageCollector(ctx)
    go sp.metricsCollector(ctx)

    // Publish ready event
    sp.PublishEvent(plugin.Event{
        Type:   "storage.ready",
        Source: sp.Info().Name,
        Data:   map[string]interface{}{
            "capacity": sp.store.Capacity(),
            "used":     sp.store.Used(),
        },
    })

    sp.SetHealth(plugin.HealthStatusHealthy, "Storage plugin started")

    return nil
}

// Implement ResourceProvider interface
func (sp *StoragePlugin) GetResourceType() string {
    return "storage"
}

func (sp *StoragePlugin) GetCapacity() (total, used, available int64) {
    return sp.store.Capacity(), sp.store.Used(), sp.store.Available()
}

func (sp *StoragePlugin) Allocate(ctx context.Context, amount int64) (plugin.AllocationID, error) {
    return sp.store.Allocate(amount)
}

func (sp *StoragePlugin) Release(ctx context.Context, id plugin.AllocationID) error {
    return sp.store.Release(id)
}
```

## Future Enhancements

1. **Dynamic Loading**: Load plugins from external binaries
2. **Plugin Marketplace**: Discover and install third-party plugins
3. **Hot Reload**: Update plugins without system restart
4. **Plugin Sandboxing**: Isolate plugins for security
5. **Plugin Versioning**: Support multiple versions of the same plugin
6. **Remote Plugins**: Plugins running on different nodes

The plugin architecture ensures the Blackhole Network remains extensible and maintainable while providing clear boundaries between components.
