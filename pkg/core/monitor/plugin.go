// Package monitor provides system monitoring and metrics collection functionality
package monitor

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// Plugin provides system monitoring and metrics collection
type Plugin struct {
	*plugin.BasePlugin
	mu       sync.RWMutex
	metrics  map[string]*Metric
	ticker   *time.Ticker
	stopChan chan struct{}
	registry *plugin.Registry
}

// Metric represents a collected metric
type Metric struct {
	Name      string            `json:"name"`
	Value     interface{}       `json:"value"`
	Unit      string            `json:"unit"`
	Timestamp time.Time         `json:"timestamp"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// NewPlugin creates a new analytics plugin
func NewPlugin(registry *plugin.Registry) *Plugin {
	info := plugin.Info{
		Name:         "monitor",
		Version:      "1.0.0",
		Description:  "System monitoring and metrics collection",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilityMonitoring)},
	}

	ap := &Plugin{
		BasePlugin: plugin.NewBasePlugin(info),
		metrics:    make(map[string]*Metric),
		stopChan:   make(chan struct{}),
		registry:   registry,
	}
	ap.SetRegistry(registry)

	// Register lifecycle hooks
	ap.RegisterHook(plugin.HookPreStart, ap.preStartHook)
	ap.RegisterHook(plugin.HookPostStart, ap.postStartHook)
	ap.RegisterHook(plugin.HookPreStop, ap.preStopHook)

	return ap
}

// Info returns metadata about the plugin
func (ap *Plugin) Info() plugin.Info {
	return plugin.Info{
		Name:         "monitor",
		Version:      "1.0.0",
		Description:  "System monitoring and metrics collection",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilityMonitoring)},
	}
}

// Init initializes the plugin with configuration
func (ap *Plugin) Init(ctx context.Context, config plugin.Config) error {
	// Call BasePlugin Init first
	if err := ap.BasePlugin.Init(ctx, config); err != nil {
		return err
	}

	ap.mu.Lock()
	defer ap.mu.Unlock()

	// Initialize initial metrics collection
	ap.collectSystemMetrics()

	return nil
}

// preStartHook is called before the plugin starts
func (ap *Plugin) preStartHook(ctx context.Context, data interface{}) error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// Get collection interval from config or use default
	interval := 10 * time.Second
	config := ap.GetConfig()
	if intervalVal, ok := config["interval"]; ok {
		if dur, ok := intervalVal.(time.Duration); ok {
			interval = dur
		}
	}

	// Setup metrics collection
	ap.ticker = time.NewTicker(interval)
	ap.stopChan = make(chan struct{}) // Recreate channel in case of restart

	return nil
}

// postStartHook is called after the plugin starts
func (ap *Plugin) postStartHook(ctx context.Context, data interface{}) error {
	// Start collection goroutine
	go ap.collectLoop(ctx)

	// Update health status
	ap.SetHealth(plugin.HealthStatusHealthy, "Monitor operational")

	return nil
}

// preStopHook is called before the plugin stops
func (ap *Plugin) preStopHook(ctx context.Context, data interface{}) error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// Stop collection
	if ap.stopChan != nil {
		close(ap.stopChan)
	}
	if ap.ticker != nil {
		ap.ticker.Stop()
		ap.ticker = nil
	}

	ap.SetHealth(plugin.HealthStatusUnknown, "Monitor stopping")
	return nil
}

// Health returns the current health status
func (ap *Plugin) Health() plugin.Health {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	// Calculate current health status
	var status plugin.HealthStatus
	var message string

	metricsCount := len(ap.metrics)

	switch {
	case ap.GetState() != plugin.StateRunning:
		status = plugin.HealthStatusUnknown
		message = fmt.Sprintf("Monitor plugin state: %s", ap.GetState())
	case metricsCount == 0:
		status = plugin.HealthStatusDegraded
		message = "No metrics collected yet"
	default:
		status = plugin.HealthStatusHealthy
		message = fmt.Sprintf("Monitor operational (%d metrics collected)", metricsCount)
	}

	return plugin.Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"metrics_count": metricsCount,
			"goroutines":    runtime.NumGoroutine(),
			"cpu_count":     runtime.NumCPU(),
			"started":       ap.IsStarted(),
		},
	}
}

// collectLoop runs the metrics collection in a background goroutine
func (ap *Plugin) collectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ap.stopChan:
			return
		case <-ap.ticker.C:
			ap.collectSystemMetrics()
		}
	}
}

// collectSystemMetrics collects current system metrics
func (ap *Plugin) collectSystemMetrics() {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	now := time.Now()

	// Collect runtime metrics
	ap.metrics["memory.alloc"] = &Metric{
		Name:      "memory.alloc",
		Value:     m.Alloc,
		Unit:      "bytes",
		Timestamp: now,
		Tags:      map[string]string{"type": "memory"},
	}

	ap.metrics["memory.total_alloc"] = &Metric{
		Name:      "memory.total_alloc",
		Value:     m.TotalAlloc,
		Unit:      "bytes",
		Timestamp: now,
		Tags:      map[string]string{"type": "memory"},
	}

	ap.metrics["memory.sys"] = &Metric{
		Name:      "memory.sys",
		Value:     m.Sys,
		Unit:      "bytes",
		Timestamp: now,
		Tags:      map[string]string{"type": "memory"},
	}

	ap.metrics["memory.num_gc"] = &Metric{
		Name:      "memory.num_gc",
		Value:     m.NumGC,
		Unit:      "count",
		Timestamp: now,
		Tags:      map[string]string{"type": "memory"},
	}

	ap.metrics["runtime.goroutines"] = &Metric{
		Name:      "runtime.goroutines",
		Value:     runtime.NumGoroutine(),
		Unit:      "count",
		Timestamp: now,
		Tags:      map[string]string{"type": "runtime"},
	}

	ap.metrics["runtime.cpu_count"] = &Metric{
		Name:      "runtime.cpu_count",
		Value:     runtime.NumCPU(),
		Unit:      "count",
		Timestamp: now,
		Tags:      map[string]string{"type": "runtime"},
	}

	// Publish metrics collection event
	if ap.registry != nil {
		ap.registry.Publish(plugin.Event{
			Type:      "monitor.metrics_collected",
			Source:    ap.Info().Name,
			Timestamp: now,
			Data: map[string]interface{}{
				"metrics_count":   len(ap.metrics),
				"collection_time": now,
			},
		})
	}
}

// GetMetrics returns all collected metrics
func (ap *Plugin) GetMetrics() map[string]*Metric {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	// Return a copy to prevent external modification
	result := make(map[string]*Metric)
	for k, v := range ap.metrics {
		result[k] = v
	}
	return result
}

// GetMetric returns a specific metric by name
func (ap *Plugin) GetMetric(name string) (*Metric, bool) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	metric, exists := ap.metrics[name]
	return metric, exists
}

// GetMetricsCount returns the number of collected metrics
func (ap *Plugin) GetMetricsCount() int {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	return len(ap.metrics)
}

// Ensure Plugin implements the Plugin interface
var _ plugin.Plugin = (*Plugin)(nil)
