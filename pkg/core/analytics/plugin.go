package analytics

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// AnalyticsPlugin provides system analytics and metrics collection
type AnalyticsPlugin struct {
	*plugin.BasePlugin
	mu             sync.RWMutex
	config         plugin.Config
	metrics        map[string]*Metric
	ticker         *time.Ticker
	stopChan       chan struct{}
	started        bool
	registry       *plugin.Registry
	healthStatus   plugin.HealthStatus
	healthMessage  string
}

// Metric represents a collected metric
type Metric struct {
	Name      string      `json:"name"`
	Value     interface{} `json:"value"`
	Unit      string      `json:"unit"`
	Timestamp time.Time   `json:"timestamp"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// NewAnalyticsPlugin creates a new analytics plugin
func NewAnalyticsPlugin(registry *plugin.Registry) *AnalyticsPlugin {
	info := plugin.Info{
		Name:         "analytics",
		Version:      "1.0.0",
		Description:  "System analytics and metrics collection",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilityMonitoring)},
	}
	
	ap := &AnalyticsPlugin{
		BasePlugin:    plugin.NewBasePlugin(info),
		metrics:       make(map[string]*Metric),
		stopChan:      make(chan struct{}),
		registry:      registry,
		healthStatus:  plugin.HealthStatusUnknown,
		healthMessage: "Not initialized",
	}
	ap.BasePlugin.SetRegistry(registry)
	return ap
}

// Info returns metadata about the plugin
func (ap *AnalyticsPlugin) Info() plugin.Info {
	return plugin.Info{
		Name:         "analytics",
		Version:      "1.0.0",
		Description:  "System analytics and metrics collection",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilityMonitoring)},
	}
}

// Init initializes the plugin with configuration
func (ap *AnalyticsPlugin) Init(ctx context.Context, config plugin.Config) error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	ap.config = config
	
	// Update health status
	ap.healthStatus = plugin.HealthStatusHealthy
	ap.healthMessage = "Analytics initialized"
	ap.SetHealth(ap.healthStatus, ap.healthMessage)

	return nil
}

// Start starts the plugin
func (ap *AnalyticsPlugin) Start(ctx context.Context) error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	if ap.started {
		return fmt.Errorf("analytics plugin already started")
	}

	// Get collection interval from config or use default
	interval := 10 * time.Second
	if intervalVal, ok := ap.config["interval"]; ok {
		if dur, ok := intervalVal.(time.Duration); ok {
			interval = dur
		}
	}

	// Start metrics collection
	ap.ticker = time.NewTicker(interval)
	ap.started = true
	
	// Start collection goroutine
	go ap.collectLoop(ctx)
	
	// Update and publish initial health status
	ap.healthStatus = plugin.HealthStatusHealthy
	ap.healthMessage = "Analytics operational"
	ap.SetHealth(ap.healthStatus, ap.healthMessage)

	return nil
}

// Stop gracefully shuts down the plugin
func (ap *AnalyticsPlugin) Stop(ctx context.Context) error {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	if !ap.started {
		return nil
	}

	// Stop collection
	close(ap.stopChan)
	if ap.ticker != nil {
		ap.ticker.Stop()
	}
	
	// Clean up resources
	ap.started = false
	
	// Update health status
	ap.healthStatus = plugin.HealthStatusUnknown
	ap.healthMessage = "Analytics stopped"
	ap.SetHealth(ap.healthStatus, ap.healthMessage)

	return nil
}

// Health returns the current health status
func (ap *AnalyticsPlugin) Health() plugin.Health {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	// Calculate current health status
	var status plugin.HealthStatus
	var message string
	
	metricsCount := len(ap.metrics)
	
	if !ap.started {
		status = plugin.HealthStatusUnknown
		message = "Analytics not started"
	} else if metricsCount == 0 {
		status = plugin.HealthStatusDegraded
		message = "No metrics collected yet"
	} else {
		status = plugin.HealthStatusHealthy
		message = fmt.Sprintf("Analytics operational (%d metrics collected)", metricsCount)
	}

	return plugin.Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"metrics_count": metricsCount,
			"goroutines":    runtime.NumGoroutine(),
			"cpu_count":     runtime.NumCPU(),
			"started":       ap.started,
		},
	}
}

// collectLoop runs the metrics collection in a background goroutine
func (ap *AnalyticsPlugin) collectLoop(ctx context.Context) {
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
func (ap *AnalyticsPlugin) collectSystemMetrics() {
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
			Type:      "analytics.metrics_collected",
			Source:    ap.Info().Name,
			Timestamp: now,
			Data: map[string]interface{}{
				"metrics_count": len(ap.metrics),
				"collection_time": now,
			},
		})
	}
}

// GetMetrics returns all collected metrics
func (ap *AnalyticsPlugin) GetMetrics() map[string]*Metric {
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
func (ap *AnalyticsPlugin) GetMetric(name string) (*Metric, bool) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	metric, exists := ap.metrics[name]
	return metric, exists
}

// GetMetricsCount returns the number of collected metrics
func (ap *AnalyticsPlugin) GetMetricsCount() int {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	return len(ap.metrics)
}

// Ensure AnalyticsPlugin implements the Plugin interface
var _ plugin.Plugin = (*AnalyticsPlugin)(nil)