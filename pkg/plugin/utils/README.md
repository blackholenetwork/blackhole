# Plugin Utilities

This package provides common utilities for plugin development in the Blackhole Network.

## Components

### Lifecycle Manager (`lifecycle.go`)
Manages plugin state transitions and lifecycle events.

```go
lm := utils.NewLifecycleManager()

// Transition states
err := lm.TransitionTo(utils.StateInitialized)
err := lm.TransitionTo(utils.StateRunning)

// Check state
if lm.IsRunning() {
    // Plugin is running
}
```

### Configuration Loader (`config.go`)
Loads and validates plugin configuration from multiple sources.

```go
type MyConfig struct {
    Port     int    `yaml:"port" default:"8080" min:"1024" max:"65535"`
    Host     string `yaml:"host" default:"localhost" required:"true"`
    Timeout  time.Duration `yaml:"timeout" default:"30s"`
}

cfg := &MyConfig{}
err := utils.LoadConfig("myplugin", pluginConfig, cfg)
```

Configuration priority (highest to lowest):
1. Environment variables (MYPLUGIN_PORT=9000)
2. Plugin config overrides
3. Config file (if specified)
4. Default values

### Metrics Collector (`metrics.go`)
Collects and manages plugin metrics.

```go
mc := utils.NewMetricsCollector()

// Register metrics
requests := mc.RegisterCounter("requests_total", map[string]string{"method": "GET"})
latency := mc.RegisterHistogram("request_duration_seconds", nil, []float64{0.1, 0.5, 1, 5})
connections := mc.RegisterGauge("active_connections", nil)

// Use metrics
requests.Inc()
connections.Set(42)

// Measure duration
defer utils.MeasureDuration(mc, "operation_duration", map[string]string{"op": "query"})()

// Get all metrics
metrics := mc.GetMetrics()
```

## Usage Example

```go
type MyPlugin struct {
    *plugin.BasePlugin
    lifecycle *utils.LifecycleManager
    metrics   *utils.MetricsCollector
    config    *MyConfig
}

func New() *MyPlugin {
    return &MyPlugin{
        BasePlugin: plugin.NewBasePlugin(info),
        lifecycle:  utils.NewLifecycleManager(),
        metrics:    utils.NewMetricsCollector(),
    }
}

func (p *MyPlugin) Init(ctx context.Context, config plugin.Config) error {
    // Load configuration
    p.config = &MyConfig{}
    if err := utils.LoadConfig("myplugin", config, p.config); err != nil {
        return err
    }

    // Register metrics
    p.metrics.RegisterCounter("operations_total", nil)

    return p.lifecycle.TransitionTo(utils.StateInitialized)
}
```

These utilities help ensure consistent behavior across all plugins while reducing boilerplate code.
