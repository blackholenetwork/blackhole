# Plugin System

A flexible plugin system that allows extending functionality without modifying core code.

## Overview

The plugin system enables:
- Adding new storage backends
- Custom authentication methods
- Additional API endpoints
- New data processors
- Custom metrics collectors

## Plugin Interface

```go
type Plugin interface {
    // Metadata
    Name() string
    Version() string
    Description() string
    
    // Lifecycle
    Init(config map[string]interface{}) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    
    // Health
    Health() HealthStatus
}
```

## Plugin Types

### Storage Plugin
```go
type StoragePlugin interface {
    Plugin
    Storage // Implements storage interface
}

// Register custom storage
registry.RegisterStorage("s3", &S3StoragePlugin{})
```

### Processor Plugin
```go
type ProcessorPlugin interface {
    Plugin
    Process(ctx context.Context, data []byte) ([]byte, error)
}

// Add custom processor
registry.RegisterProcessor("compress", &CompressionPlugin{})
```

### API Plugin
```go
type APIPlugin interface {
    Plugin
    RegisterRoutes(router fiber.Router)
}

// Add custom endpoints
registry.RegisterAPI("analytics", &AnalyticsPlugin{})
```

## Usage

```go
// Load plugins
registry := plugin.NewRegistry()

// Register built-in plugins
registry.Register(&LocalStoragePlugin{})
registry.Register(&S3StoragePlugin{})

// Load external plugins
if err := registry.LoadFromDir("/etc/blackhole/plugins"); err != nil {
    log.Fatal(err)
}

// Initialize all plugins
if err := registry.InitAll(config); err != nil {
    log.Fatal(err)
}

// Start plugins
if err := registry.StartAll(ctx); err != nil {
    log.Fatal(err)
}

// Use plugin
storage := registry.GetStorage(config.StorageType)
```

## Creating a Plugin

```go
package myplugin

import (
    "github.com/blackhole/pkg/plugin"
)

type MyStoragePlugin struct {
    config Config
}

func (p *MyStoragePlugin) Name() string {
    return "my-storage"
}

func (p *MyStoragePlugin) Init(config map[string]interface{}) error {
    // Parse configuration
    return nil
}

func (p *MyStoragePlugin) StoreFile(ctx context.Context, data []byte) (string, error) {
    // Custom storage implementation
    return "", nil
}

// Export plugin
var Plugin plugin.Plugin = &MyStoragePlugin{}
```

## Plugin Discovery

Plugins are discovered from:
1. Built-in plugins (compiled in)
2. Plugin directory (`/etc/blackhole/plugins/`)
3. Environment variable (`BLACKHOLE_PLUGINS`)
4. Explicit registration

## Plugin Configuration

```yaml
plugins:
  - name: s3-storage
    enabled: true
    config:
      bucket: my-bucket
      region: us-east-1
      
  - name: compression
    enabled: true
    config:
      level: 9
      types: ["text", "json"]
```