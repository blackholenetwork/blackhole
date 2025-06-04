package monitoring

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// MonitoringPlugin provides system monitoring capabilities
type MonitoringPlugin struct {
	*plugin.BasePlugin
	mu       sync.RWMutex
	metrics  map[string]interface{}
	ticker   *time.Ticker
	stopChan chan struct{}
}

// NewMonitoringPlugin creates a new monitoring plugin using the builder pattern
func NewMonitoringPlugin() plugin.Plugin {
	return plugin.NewPluginBuilder("monitoring").
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
	metrics  map[string]interface{}
	ticker   *time.Ticker
	stopChan chan struct{}
	mu       sync.RWMutex
}

var stateKey = struct{}{}

func initMonitoring(ctx context.Context, config plugin.Config) error {
	state := &monitoringState{
		metrics:  make(map[string]interface{}),
		stopChan: make(chan struct{}),
	}

	// Store state in context (in real implementation, use proper state management)
	context.WithValue(ctx, stateKey, state)

	return nil
}

func startMonitoring(ctx context.Context) error {
	// In a real implementation, retrieve state properly
	state := &monitoringState{
		metrics:  make(map[string]interface{}),
		stopChan: make(chan struct{}),
		ticker:   time.NewTicker(10 * time.Second),
	}

	// Start metrics collection
	go func() {
		for {
			select {
			case <-state.ticker.C:
				collectMetrics(state)
			case <-state.stopChan:
				return
			}
		}
	}()

	return nil
}

func stopMonitoring(ctx context.Context) error {
	// In a real implementation, retrieve state properly
	state := &monitoringState{
		stopChan: make(chan struct{}),
	}

	close(state.stopChan)
	if state.ticker != nil {
		state.ticker.Stop()
	}

	return nil
}

func healthMonitoring() plugin.Health {
	return plugin.Health{
		Status:    plugin.HealthStatusHealthy,
		Message:   "Monitoring is operational",
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"cpu_count":  runtime.NumCPU(),
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
			"goroutines":  runtime.NumGoroutine(),
			"cpu_count":   runtime.NumCPU(),
			"go_version":  runtime.Version(),
			"memory":      m,
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

func (mc *MetricsCollector) Get(name string) (Metric, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metric, exists := mc.metrics[name]
	return metric, exists
}

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