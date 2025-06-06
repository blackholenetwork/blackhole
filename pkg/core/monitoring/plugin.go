// Package monitoring provides system monitoring and analytics functionality
package monitoring

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// Plugin provides system monitoring capabilities
type Plugin struct {
	*plugin.BasePlugin
}

// NewPlugin creates a new monitoring plugin using the builder pattern
func NewPlugin(registry *plugin.Registry) plugin.Plugin {
	// Store registry for use in the plugin
	monitoringRegistry = registry

	return plugin.NewBuilder("monitoring").
		WithDescription("System monitoring and metrics collection").
		WithAuthor("Blackhole Network").
		WithLicense("Apache-2.0").
		WithCapabilities(plugin.CapabilityMonitoring).
		WithInit(initMonitoring).
		WithStart(startMonitoring).
		WithStop(stopMonitoring).
		WithHealth(healthMonitoring).
		Build()
}

// Plugin state stored in context
type monitoringState struct {
	metrics       map[string]interface{}
	ticker        *time.Ticker
	stopChan      chan struct{}
	mu            sync.RWMutex
	healthStatus  plugin.HealthStatus
	healthMessage string
}

var (
	monitoringRegistry *plugin.Registry
	globalState        *monitoringState
	healthTicker       *time.Ticker
	healthDone         chan struct{}
)

func initMonitoring(_ context.Context, _ plugin.Config) error {
	globalState = &monitoringState{
		metrics:       make(map[string]interface{}),
		stopChan:      make(chan struct{}),
		healthStatus:  plugin.HealthStatusHealthy,
		healthMessage: "Monitoring initialized",
	}

	// Publish initial health status
	if monitoringRegistry != nil {
		monitoringRegistry.Publish(plugin.Event{
			Type:      plugin.EventHealthChanged,
			Source:    "monitoring",
			Data:      healthMonitoring(),
			Timestamp: time.Now(),
		})
	}

	return nil
}

func startMonitoring(ctx context.Context) error {
	if globalState == nil {
		globalState = &monitoringState{
			metrics:       make(map[string]interface{}),
			stopChan:      make(chan struct{}),
			healthStatus:  plugin.HealthStatusHealthy,
			healthMessage: "Monitoring is operational",
		}
	}

	globalState.ticker = time.NewTicker(10 * time.Second)

	// Update health status
	globalState.mu.Lock()
	globalState.healthStatus = plugin.HealthStatusHealthy
	globalState.healthMessage = "Monitoring is operational"
	globalState.mu.Unlock()

	// Start metrics collection
	go func() {
		for {
			select {
			case <-globalState.ticker.C:
				collectMetrics(globalState)
			case <-globalState.stopChan:
				return
			}
		}
	}()

	// Start health monitoring
	healthDone = make(chan struct{})
	healthTicker = time.NewTicker(5 * time.Second)
	go monitorHealth(ctx)

	return nil
}

func stopMonitoring(_ context.Context) error {
	if globalState != nil {
		// Update health status
		globalState.mu.Lock()
		globalState.healthStatus = plugin.HealthStatusUnknown
		globalState.healthMessage = "Monitoring stopped"
		globalState.mu.Unlock()

		close(globalState.stopChan)
		if globalState.ticker != nil {
			globalState.ticker.Stop()
		}
	}

	// Stop health monitoring
	if healthTicker != nil {
		healthTicker.Stop()
	}
	if healthDone != nil {
		close(healthDone)
	}

	return nil
}

func healthMonitoring() plugin.Health {
	if globalState == nil {
		return plugin.Health{
			Status:    plugin.HealthStatusUnknown,
			Message:   "Monitoring not initialized",
			LastCheck: time.Now(),
		}
	}

	globalState.mu.RLock()
	status := globalState.healthStatus
	message := globalState.healthMessage
	metricsCount := len(globalState.metrics)
	globalState.mu.RUnlock()

	return plugin.Health{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"goroutines":    runtime.NumGoroutine(),
			"cpu_count":     runtime.NumCPU(),
			"metrics_count": metricsCount,
		},
	}
}

func collectMetrics(state *monitoringState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	state.metrics["memory_alloc"] = m.Alloc
	state.metrics["memory_total_alloc"] = m.TotalAlloc
	state.metrics["memory_sys"] = m.Sys
	state.metrics["num_gc"] = m.NumGC
	state.metrics["goroutines"] = runtime.NumGoroutine()
	state.metrics["timestamp"] = time.Now()
}

// monitorHealth periodically reports health status
func monitorHealth(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-healthDone:
			return
		case <-healthTicker.C:
			if globalState == nil {
				continue
			}

			// Check current status
			globalState.mu.RLock()
			metricsCount := len(globalState.metrics)
			globalState.mu.RUnlock()

			// Determine health based on metrics
			var status plugin.HealthStatus
			var message string
			if metricsCount == 0 {
				status = plugin.HealthStatusDegraded
				message = "No metrics collected yet"
			} else {
				status = plugin.HealthStatusHealthy
				message = "Monitoring is operational"
			}

			// Update if changed
			globalState.mu.Lock()
			if globalState.healthStatus != status || globalState.healthMessage != message {
				globalState.healthStatus = status
				globalState.healthMessage = message
				globalState.mu.Unlock()

				// Publish health event
				if monitoringRegistry != nil {
					monitoringRegistry.Publish(plugin.Event{
						Type:      plugin.EventHealthChanged,
						Source:    "monitoring",
						Data:      healthMonitoring(),
						Timestamp: time.Now(),
					})
				}
			} else {
				globalState.mu.Unlock()
			}
		}
	}
}

// Alternative: Full implementation as a struct

// FullMonitoringPlugin provides a complete monitoring implementation
type FullMonitoringPlugin struct {
	*plugin.BasePlugin
	metrics  *MetricsCollector
	ticker   *time.Ticker
	stopChan chan struct{}
}

// MetricsCollector handles metrics collection
type MetricsCollector struct {
	mu      sync.RWMutex
	metrics map[string]Metric
}

// Metric represents a single metric
type Metric struct {
	Name      string
	Value     interface{}
	Unit      string
	Timestamp time.Time
}

// NewFullMonitoringPlugin creates a monitoring plugin with full implementation
func NewFullMonitoringPlugin() *FullMonitoringPlugin {
	info := plugin.Info{
		Name:         "monitoring-full",
		Version:      "1.0.0",
		Description:  "Comprehensive system monitoring",
		Author:       "Blackhole Network",
		License:      "Apache-2.0",
		Dependencies: []string{},
		Capabilities: []string{string(plugin.CapabilityMonitoring)},
	}

	return &FullMonitoringPlugin{
		BasePlugin: plugin.NewBasePlugin(info),
		metrics: &MetricsCollector{
			metrics: make(map[string]Metric),
		},
		stopChan: make(chan struct{}),
	}
}

// Start starts the monitoring plugin
func (mp *FullMonitoringPlugin) Start(ctx context.Context) error {
	if err := mp.BasePlugin.Start(ctx); err != nil {
		return err
	}

	// Start metrics collection
	mp.ticker = time.NewTicker(mp.GetConfigDuration("interval", 10*time.Second))

	go mp.collectLoop()

	mp.SetHealth(plugin.HealthStatusHealthy, "Monitoring started")

	return nil
}

// Stop stops the monitoring plugin
func (mp *FullMonitoringPlugin) Stop(ctx context.Context) error {
	close(mp.stopChan)
	if mp.ticker != nil {
		mp.ticker.Stop()
	}

	return mp.BasePlugin.Stop(ctx)
}

// GetMetrics returns current metrics (implements plugin.Metrics interface)
func (mp *FullMonitoringPlugin) GetMetrics() map[string]interface{} {
	return mp.metrics.GetAll()
}

// GetDiagnostics returns diagnostic information (implements plugin.Diagnostics interface)
func (mp *FullMonitoringPlugin) GetDiagnostics() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"runtime": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"cpu_count":  runtime.NumCPU(),
			"go_version": runtime.Version(),
			"memory":     m,
		},
		"metrics_count": mp.metrics.Count(),
		"uptime":        time.Since(mp.BasePlugin.Info().CreatedAt),
	}
}

func (mp *FullMonitoringPlugin) collectLoop() {
	for {
		select {
		case <-mp.ticker.C:
			mp.collectSystemMetrics()
		case <-mp.stopChan:
			return
		}
	}
}

func (mp *FullMonitoringPlugin) collectSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	mp.metrics.Set("memory.alloc", m.Alloc, "bytes")
	mp.metrics.Set("memory.total_alloc", m.TotalAlloc, "bytes")
	mp.metrics.Set("memory.sys", m.Sys, "bytes")
	mp.metrics.Set("memory.num_gc", m.NumGC, "count")
	mp.metrics.Set("runtime.goroutines", runtime.NumGoroutine(), "count")
	mp.metrics.Set("runtime.cpu_count", runtime.NumCPU(), "count")

	// Publish metrics event
	mp.PublishEvent(plugin.Event{
		Type:      "metrics.collected",
		Source:    mp.Info().Name,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"metrics": mp.metrics.GetAll(),
		},
	})
}

// MetricsCollector methods

// Set adds or updates a metric in the collector
func (mc *MetricsCollector) Set(name string, value interface{}, unit string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics[name] = Metric{
		Name:      name,
		Value:     value,
		Unit:      unit,
		Timestamp: time.Now(),
	}
}

// Get retrieves a specific metric by name
func (mc *MetricsCollector) Get(name string) (Metric, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metric, exists := mc.metrics[name]
	return metric, exists
}

// GetAll returns all metrics as a map
func (mc *MetricsCollector) GetAll() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]interface{})
	for name, metric := range mc.metrics {
		result[name] = map[string]interface{}{
			"value":     metric.Value,
			"unit":      metric.Unit,
			"timestamp": metric.Timestamp,
		}
	}

	return result
}

// Count returns the number of metrics in the collector
func (mc *MetricsCollector) Count() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.metrics)
}

// Ensure plugins implement the correct interfaces
var (
	_ plugin.Plugin      = (*FullMonitoringPlugin)(nil)
	_ plugin.Metrics     = (*FullMonitoringPlugin)(nil)
	_ plugin.Diagnostics = (*FullMonitoringPlugin)(nil)
)
