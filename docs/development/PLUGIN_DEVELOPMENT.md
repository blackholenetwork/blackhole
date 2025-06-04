# Plugin Development Guide

This guide covers how to develop plugins for the Blackhole Network system.

## Table of Contents

1. [Overview](#overview)
2. [Plugin Architecture](#plugin-architecture)
3. [Plugin Types](#plugin-types)
4. [Getting Started](#getting-started)
5. [Plugin Interface](#plugin-interface)
6. [Development Workflow](#development-workflow)
7. [Best Practices](#best-practices)
8. [Testing](#testing)
9. [Debugging](#debugging)
10. [Advanced Topics](#advanced-topics)

## Overview

Plugins are the primary extension mechanism for the Blackhole Network. They allow you to add new functionality without modifying the core system. All plugins follow a consistent interface and lifecycle pattern.

### Key Features

- **Hot-reloadable**: Plugins can be updated without system restart
- **Isolated**: Each plugin runs in its own context with resource limits
- **Observable**: Built-in metrics and health monitoring
- **Configurable**: Flexible configuration through YAML or environment variables
- **Testable**: Comprehensive testing utilities and mocks

## Plugin Architecture

### Plugin Lifecycle

```
┌─────────────────┐
│  Uninitialized  │
└────────┬────────┘
         │ Init()
┌────────▼────────┐
│   Initialized   │
└────────┬────────┘
         │ Start()
┌────────▼────────┐
│     Running     │
└────────┬────────┘
         │ Stop()
┌────────▼────────┐
│     Stopped     │
└─────────────────┘
```

### Plugin Components

1. **Core Interface**: Base plugin interface all plugins must implement
2. **Type-Specific Interface**: Additional interfaces for resource, service, etc.
3. **Configuration**: Plugin-specific configuration handling
4. **Health Monitoring**: Built-in health check support
5. **Metrics Collection**: Automatic metrics tracking
6. **Event System**: Publish/subscribe event communication

## Plugin Types

### Core Plugins

Core plugins provide fundamental system functionality:
- Orchestration
- Security
- Networking
- Monitoring

Example capabilities:
```go
CapabilityOrchestration
CapabilitySecurity
CapabilityNetworking
CapabilityMonitoring
```

### Resource Plugins

Resource plugins manage computational resources:
- Storage
- Compute (CPU/GPU)
- Bandwidth
- Memory

Example implementation:
```go
type ResourceProvider interface {
    Plugin
    GetResourceType() string
    GetCapacity() (total, used, available int64)
    Allocate(ctx context.Context, amount int64) (AllocationID, error)
    Release(ctx context.Context, id AllocationID) error
}
```

### Data Plugins

Data plugins handle data management:
- Schema management
- Indexing
- Query processing
- Search

Example capabilities:
```go
CapabilitySchema
CapabilityIndexing
CapabilityQuery
CapabilitySearch
```

### Service Plugins

Service plugins provide API endpoints:
- REST APIs
- WebSocket services
- Real-time communication
- Social features

Example implementation:
```go
type ServiceProvider interface {
    Plugin
    GetEndpoints() []Endpoint
    HandleRequest(ctx context.Context, req Request) (Response, error)
}
```

### Economic Plugins

Economic plugins manage incentives and contracts:
- Token distribution
- Contract management
- Reward calculation
- Usage tracking

## Getting Started

### Using the Plugin Generator

The easiest way to create a new plugin is using the generator script:

```bash
# Basic usage
./scripts/generate-plugin.sh -n my-plugin -t resource -d "My awesome plugin"

# With dependencies and custom options
./scripts/generate-plugin.sh \
    -n storage-cache \
    -t resource \
    -d "High-performance storage cache" \
    -a "John Doe" \
    -v "1.0.0" \
    --deps "storage,monitoring" \
    --caps "CapabilityStorage,CapabilityCache"
```

### Generated Structure

```
pkg/plugin/my_plugin/
├── my_plugin.go         # Main plugin implementation
├── my_plugin_test.go    # Unit tests
├── config.yaml          # Default configuration
├── README.md            # Plugin documentation
├── Makefile             # Build and test commands
├── example/
│   └── main.go          # Example usage
└── internal/            # Internal packages
    └── .gitkeep
```

## Plugin Interface

### Base Plugin Interface

All plugins must implement the base interface:

```go
type Plugin interface {
    // Metadata
    Info() Info
    
    // Lifecycle
    Init(ctx context.Context, config Config) error
    Start(ctx context.Context) error
    Stop(ctx context.Context) error
    
    // Health
    Health() Health
}
```

### Plugin Metadata

```go
type Info struct {
    Name         string    // Unique plugin name
    Version      string    // Semantic version
    Description  string    // Human-readable description
    Author       string    // Plugin author
    License      string    // License type
    Dependencies []string  // Required plugins
    Capabilities []string  // Provided capabilities
    CreatedAt    time.Time // Creation timestamp
}
```

### Configuration

Plugins support multiple configuration sources:

1. **Configuration file** (highest priority)
```yaml
my_plugin:
  enabled: true
  capacity: 1000
  timeout: 30s
```

2. **Environment variables**
```bash
export BLACKHOLE_MY_PLUGIN_ENABLED=true
export BLACKHOLE_MY_PLUGIN_CAPACITY=1000
export BLACKHOLE_MY_PLUGIN_TIMEOUT=30s
```

3. **Default values** (lowest priority)

### Health Monitoring

Plugins provide health status:

```go
type Health struct {
    Status    HealthStatus           // healthy, degraded, unhealthy, unknown
    Message   string                 // Human-readable status
    Details   map[string]interface{} // Additional details
    LastCheck time.Time              // Last health check time
}
```

## Development Workflow

### 1. Create Plugin

```bash
# Generate plugin scaffold
./scripts/generate-plugin.sh -n my-feature -t service -d "My feature service"

# Navigate to plugin directory
cd pkg/plugin/my_feature
```

### 2. Implement Logic

Edit `my_feature.go`:

```go
// Add your initialization logic
func (p *myFeature) Init(ctx context.Context, config plugin.Config) error {
    // Validate configuration
    if err := p.validateConfig(config); err != nil {
        return fmt.Errorf("invalid configuration: %w", err)
    }
    
    // Initialize resources
    // TODO: Add your initialization logic
    
    return nil
}

// Add your business logic
func (p *myFeature) doSomething(ctx context.Context) error {
    // TODO: Implement your feature
    return nil
}
```

### 3. Add Tests

Edit `my_feature_test.go`:

```go
func TestMyFeature_DoSomething(t *testing.T) {
    plugin := New()
    ctx := context.Background()
    
    // Initialize
    err := plugin.Init(ctx, plugin.Config{})
    require.NoError(t, err)
    
    // Start
    err = plugin.Start(ctx)
    require.NoError(t, err)
    defer plugin.Stop(ctx)
    
    // Test your logic
    // TODO: Add test cases
}
```

### 4. Test Plugin

```bash
# Run tests
make test

# Run with coverage
make coverage

# Run benchmarks
make bench

# Run example
go run example/main.go
```

### 5. Register Plugin

Add to the main application's plugin registry:

```go
import "github.com/blackholenetwork/blackhole/pkg/plugin/my_feature"

// In your initialization code
registry.Register(my_feature.New())
```

## Best Practices

### 1. Error Handling

Always wrap errors with context:

```go
if err := someOperation(); err != nil {
    return fmt.Errorf("failed to perform operation: %w", err)
}
```

### 2. Context Usage

Respect context cancellation:

```go
select {
case <-ctx.Done():
    return ctx.Err()
case result := <-resultChan:
    return processResult(result)
}
```

### 3. Resource Management

Always clean up resources:

```go
func (p *myPlugin) Start(ctx context.Context) error {
    p.ctx, p.cancel = context.WithCancel(ctx)
    
    // Start goroutines
    p.wg.Add(1)
    go func() {
        defer p.wg.Done()
        p.worker()
    }()
    
    return nil
}

func (p *myPlugin) Stop(ctx context.Context) error {
    // Signal shutdown
    p.cancel()
    
    // Wait for goroutines
    done := make(chan struct{})
    go func() {
        p.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        return nil
    case <-ctx.Done():
        return fmt.Errorf("shutdown timeout")
    }
}
```

### 4. Configuration Validation

Validate configuration early:

```go
func (p *myPlugin) validateConfig(config plugin.Config) error {
    helper := utils.NewConfigHelper(config, "BLACKHOLE_MY_PLUGIN")
    
    // Validate required fields
    if err := helper.Validate([]string{"required_field"}); err != nil {
        return err
    }
    
    // Validate ranges
    capacity := helper.GetInt64("capacity", 0)
    if capacity < 0 {
        return fmt.Errorf("capacity must be non-negative")
    }
    
    return nil
}
```

### 5. Health Checks

Implement meaningful health checks:

```go
func (p *myPlugin) performHealthCheck() {
    checker := utils.NewHealthChecker(utils.DefaultHealthCheckerConfig())
    
    // Register checks
    checker.RegisterCheck("database", func(ctx context.Context) error {
        return p.checkDatabaseConnection(ctx)
    })
    
    checker.RegisterCheck("resources", func(ctx context.Context) error {
        return p.checkResourceAvailability(ctx)
    })
    
    // Run checks
    checker.RunChecks(context.Background())
    
    // Update plugin health
    p.health = checker.GetHealth()
}
```

### 6. Metrics Collection

Track important metrics:

```go
func (p *myPlugin) initMetrics() {
    p.metrics = utils.NewMetricsCollector()
    
    // Track operations
    p.metrics.IncrementCounter("operations_total")
    p.metrics.RecordHistogram("operation_duration_seconds", duration)
    
    // Track resources
    p.metrics.SetGauge("resource_usage_bytes", usage)
    
    // Use timer for functions
    p.metrics.ObserveDuration("process_time", func() {
        p.processData()
    })
}
```

### 7. Logging

Use structured logging:

```go
p.logger.Info("Plugin started",
    "version", p.info.Version,
    "capabilities", p.info.Capabilities,
)

p.logger.Error("Operation failed",
    "error", err,
    "operation", "allocate",
    "requested", amount,
)
```

## Testing

### Unit Tests

Test individual components:

```go
func TestPlugin_Init(t *testing.T) {
    tests := []struct {
        name    string
        config  plugin.Config
        wantErr bool
    }{
        {
            name:    "valid config",
            config:  plugin.Config{"capacity": int64(100)},
            wantErr: false,
        },
        {
            name:    "invalid config",
            config:  plugin.Config{"capacity": int64(-1)},
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            p := New()
            err := p.Init(context.Background(), tt.config)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Integration Tests

Test plugin interactions:

```go
func TestPlugin_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    // Create test registry
    registry := plugin.NewRegistry()
    
    // Register plugins
    registry.Register(New())
    registry.Register(dependency.New())
    
    // Start registry
    ctx := context.Background()
    err := registry.Start(ctx)
    require.NoError(t, err)
    defer registry.Stop(ctx)
    
    // Test plugin interaction
    // ...
}
```

### Benchmarks

Measure performance:

```go
func BenchmarkPlugin_Allocate(b *testing.B) {
    p := New()
    ctx := context.Background()
    
    p.Init(ctx, plugin.Config{"capacity": int64(1000000)})
    p.Start(ctx)
    defer p.Stop(ctx)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        id, _ := p.Allocate(ctx, 10)
        p.Release(ctx, id)
    }
}
```

## Debugging

### Enable Debug Logging

```yaml
logging:
  level: debug
```

Or via environment:
```bash
export BLACKHOLE_MY_PLUGIN_LOG_LEVEL=debug
```

### Inspect Plugin State

```go
// Add debug endpoints
func (p *myPlugin) handleDebug(ctx context.Context, req plugin.Request) (plugin.Response, error) {
    state := map[string]interface{}{
        "health": p.Health(),
        "metrics": p.metrics.GetAllMetrics(),
        "config": p.config,
        "state": p.getInternalState(),
    }
    
    body, _ := json.Marshal(state)
    return plugin.Response{
        Status: 200,
        Body: body,
    }, nil
}
```

### Memory Profiling

```bash
# Generate memory profile
make profile-mem

# Analyze profile
go tool pprof mem.prof
```

### CPU Profiling

```bash
# Generate CPU profile
make profile-cpu

# Analyze profile
go tool pprof cpu.prof
```

## Advanced Topics

### Plugin Communication

Plugins can communicate via events:

```go
// Publish event
registry.Publish(plugin.Event{
    Type: "resource.allocated",
    Source: p.info.Name,
    Data: map[string]interface{}{
        "allocation_id": id,
        "amount": amount,
    },
})

// Subscribe to events
unsubscribe := registry.Subscribe("resource.allocated", func(event plugin.Event) {
    // Handle event
    p.handleResourceAllocated(event)
})
defer unsubscribe()
```

### Dynamic Configuration

Support runtime reconfiguration:

```go
// Implement Configurable interface
func (p *myPlugin) Configure(ctx context.Context, config plugin.Config) error {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Validate new config
    if err := p.validateConfig(config); err != nil {
        return err
    }
    
    // Apply changes
    p.config = config
    p.applyConfigChanges()
    
    return nil
}
```

### Plugin Hooks

Register hooks for lifecycle events:

```go
// Register pre-start hook
registry.RegisterHook(plugin.HookPreStart, func(ctx context.Context, data interface{}) error {
    // Prepare for startup
    return p.prepare()
})

// Register post-stop hook
registry.RegisterHook(plugin.HookPostStop, func(ctx context.Context, data interface{}) error {
    // Cleanup after stop
    return p.cleanup()
})
```

### Custom Health Checks

Implement sophisticated health monitoring:

```go
func (p *myPlugin) setupHealthChecks() {
    checker := utils.NewHealthChecker(utils.HealthCheckerConfig{
        CheckInterval: 30 * time.Second,
        FailureThreshold: 3,
        Timeout: 5 * time.Second,
    })
    
    // Check external dependencies
    checker.RegisterCheck("upstream", utils.HTTPHealthCheck("https://api.example.com/health"))
    
    // Check resource limits
    checker.RegisterCheck("memory", utils.MemoryHealthCheck(80.0))
    
    // Check disk space
    checker.RegisterCheck("disk", utils.DiskSpaceHealthCheck("/data", 1<<30)) // 1GB
    
    // Start health check loop
    checker.StartHealthCheckLoop(p.ctx)
    
    p.healthChecker = checker
}
```

### Plugin Versioning

Handle multiple plugin versions:

```go
// Version compatibility check
func (p *myPlugin) IsCompatibleWith(version string) bool {
    // Parse versions
    current, _ := semver.Parse(p.info.Version)
    required, _ := semver.Parse(version)
    
    // Check major version compatibility
    return current.Major == required.Major
}
```

## Troubleshooting

### Common Issues

1. **Plugin won't start**
   - Check logs for initialization errors
   - Verify all dependencies are satisfied
   - Ensure configuration is valid

2. **High memory usage**
   - Profile memory allocation
   - Check for goroutine leaks
   - Review resource cleanup

3. **Poor performance**
   - Profile CPU usage
   - Check for blocking operations
   - Review concurrent access patterns

4. **Health check failures**
   - Review health check implementation
   - Check external dependencies
   - Verify resource availability

### Debug Checklist

- [ ] Enable debug logging
- [ ] Check plugin state transitions
- [ ] Verify configuration values
- [ ] Monitor resource usage
- [ ] Profile performance bottlenecks
- [ ] Review error logs
- [ ] Test in isolation
- [ ] Validate dependencies

## Examples

### Complete Resource Plugin Example

See `pkg/plugin/template/resource.go.tmpl` for a complete example.

### Complete Service Plugin Example

See `pkg/plugin/template/service.go.tmpl` for a complete example.

## Contributing

When contributing plugins:

1. Follow the coding standards
2. Include comprehensive tests
3. Document configuration options
4. Provide usage examples
5. Update this guide if needed

## Resources

- [Plugin Interface Documentation](../architecture/INTERFACES.md)
- [Coding Standards](../standards/CODING_STANDARDS.md)
- [Testing Guide](../development/TESTING.md)
- [API Documentation](../standards/API_STANDARDS.md)