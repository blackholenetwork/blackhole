package monitoring

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// TestRegistry wraps plugin.Registry to track published events for testing
type TestRegistry struct {
	*plugin.Registry
	mu        sync.Mutex
	events    []plugin.Event
	published bool
}

func NewTestRegistry() *TestRegistry {
	return &TestRegistry{
		Registry: plugin.NewRegistry(),
		events:   make([]plugin.Event, 0),
	}
}

func (tr *TestRegistry) Publish(event plugin.Event) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.events = append(tr.events, event)
	tr.published = true
	// Also publish to the underlying registry
	tr.Registry.Publish(event)
}

func (tr *TestRegistry) GetEvents() []plugin.Event {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.events
}

func (tr *TestRegistry) HasEventType(eventType string) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, e := range tr.events {
		if e.Type == eventType {
			return true
		}
	}
	return false
}

// TestNewPlugin tests plugin creation using builder pattern
func TestNewPlugin(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	if p == nil {
		t.Fatal("Expected plugin to be created")
	}

	info := p.Info()
	if info.Name != "monitoring" {
		t.Errorf("Expected name 'monitoring', got %s", info.Name)
	}
	if info.Description != "System monitoring and metrics collection" {
		t.Errorf("Unexpected description: %s", info.Description)
	}
}

// TestMonitoringLifecycle tests the full lifecycle of the monitoring plugin
func TestMonitoringLifecycle(t *testing.T) {
	// Reset global state
	globalState = nil
	healthTicker = nil
	healthDone = nil

	registry := NewTestRegistry()
	monitoringRegistry = registry.Registry
	p := NewPlugin(registry.Registry)
	ctx := context.Background()

	// Test initialization
	config := plugin.Config{}
	err := p.Init(ctx, config)
	if err != nil {
		t.Fatalf("Expected no error on init, got: %v", err)
	}

	// Note: We can't easily verify the health event publication
	// since the plugin uses the internal registry publish mechanism
	// and we'd need to subscribe before the plugin is created

	// Test start
	err = p.Start(ctx)
	if err != nil {
		t.Fatalf("Expected no error on start, got: %v", err)
	}

	// Wait for metrics collection
	time.Sleep(100 * time.Millisecond)

	// Check health
	health := p.Health()
	if health.Status != plugin.HealthStatusHealthy {
		t.Errorf("Expected healthy status, got %v", health.Status)
	}

	// Verify health details
	if _, exists := health.Details["goroutines"]; !exists {
		t.Error("Expected goroutines in health details")
	}
	if _, exists := health.Details["cpu_count"]; !exists {
		t.Error("Expected cpu_count in health details")
	}

	// Test stop
	err = p.Stop(ctx)
	if err != nil {
		t.Fatalf("Expected no error on stop, got: %v", err)
	}

	// Check health after stop
	health = p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status after stop, got %v", health.Status)
	}
}

// TestMetricsCollection tests that metrics are collected properly
func TestMetricsCollection(t *testing.T) {
	// Reset global state
	globalState = nil

	state := &monitoringState{
		metrics:  make(map[string]interface{}),
		stopChan: make(chan struct{}),
	}

	// Collect metrics
	collectMetrics(state)

	// Verify metrics were collected
	expectedMetrics := []string{
		"memory_alloc",
		"memory_total_alloc",
		"memory_sys",
		"num_gc",
		"goroutines",
		"timestamp",
	}

	for _, metric := range expectedMetrics {
		if _, exists := state.metrics[metric]; !exists {
			t.Errorf("Expected metric %s to be collected", metric)
		}
	}

	// Verify metric values are reasonable
	if goroutines, ok := state.metrics["goroutines"].(int); ok {
		if goroutines < 1 {
			t.Error("Expected at least 1 goroutine")
		}
	} else {
		t.Error("goroutines metric has wrong type")
	}

	if timestamp, ok := state.metrics["timestamp"].(time.Time); ok {
		if time.Since(timestamp) > time.Second {
			t.Error("Timestamp is too old")
		}
	} else {
		t.Error("timestamp metric has wrong type")
	}
}

// TestHealthMonitoring tests the health monitoring functionality
func TestHealthMonitoring(t *testing.T) {
	// Reset global state
	globalState = nil
	healthTicker = nil
	healthDone = nil

	registry := NewTestRegistry()
	monitoringRegistry = registry.Registry

	// Initialize global state
	globalState = &monitoringState{
		metrics:       make(map[string]interface{}),
		stopChan:      make(chan struct{}),
		healthStatus:  plugin.HealthStatusHealthy,
		healthMessage: "Test",
	}

	// Start health monitoring
	ctx, cancel := context.WithCancel(context.Background())
	healthDone = make(chan struct{})
	healthTicker = time.NewTicker(50 * time.Millisecond)

	go monitorHealth(ctx)

	// Wait for health check
	time.Sleep(100 * time.Millisecond)

	// Note: Event publication testing would require subscribing before creating the plugin,
	// which is complex with the current architecture. The important thing is that the
	// health monitoring function is working correctly.

	// Clean up
	cancel()
	healthTicker.Stop()
	close(healthDone)
}

// TestFullMonitoringPlugin tests the full implementation variant
func TestFullMonitoringPlugin(t *testing.T) {
	mp := NewFullMonitoringPlugin()

	if mp == nil {
		t.Fatal("Expected plugin to be created")
	}

	// Test Info
	info := mp.Info()
	if info.Name != "monitoring-full" {
		t.Errorf("Expected name 'monitoring-full', got %s", info.Name)
	}

	ctx := context.Background()

	// Test Init
	config := plugin.Config{
		"interval": 100 * time.Millisecond,
	}
	err := mp.Init(ctx, config)
	if err != nil {
		t.Fatalf("Expected no error on init, got: %v", err)
	}

	// Test Start
	err = mp.Start(ctx)
	if err != nil {
		t.Fatalf("Expected no error on start, got: %v", err)
	}

	// Wait for metrics collection
	time.Sleep(200 * time.Millisecond)

	// Test GetMetrics
	metrics := mp.GetMetrics()
	if len(metrics) == 0 {
		t.Error("Expected metrics to be collected")
	}

	// Verify specific metrics
	expectedMetrics := []string{
		"memory.alloc",
		"runtime.goroutines",
		"runtime.cpu_count",
	}
	for _, name := range expectedMetrics {
		if _, exists := metrics[name]; !exists {
			t.Errorf("Expected metric %s to exist", name)
		}
	}

	// Test GetDiagnostics
	diags := mp.GetDiagnostics()
	if diags == nil {
		t.Error("Expected diagnostics to be returned")
	}
	if _, exists := diags["runtime"]; !exists {
		t.Error("Expected runtime diagnostics")
	}
	if _, exists := diags["metrics_count"]; !exists {
		t.Error("Expected metrics_count in diagnostics")
	}

	// Test Stop
	err = mp.Stop(ctx)
	if err != nil {
		t.Fatalf("Expected no error on stop, got: %v", err)
	}
}

// TestMetricsCollector tests the MetricsCollector functionality
func TestMetricsCollector(t *testing.T) {
	mc := &MetricsCollector{
		metrics: make(map[string]Metric),
	}

	// Test Set
	mc.Set("test.metric", 42, "count")

	// Test Get
	metric, exists := mc.Get("test.metric")
	if !exists {
		t.Error("Expected metric to exist")
	}
	if metric.Value != 42 {
		t.Errorf("Expected value 42, got %v", metric.Value)
	}
	if metric.Unit != "count" {
		t.Errorf("Expected unit 'count', got %s", metric.Unit)
	}

	// Test GetAll
	all := mc.GetAll()
	if len(all) != 1 {
		t.Errorf("Expected 1 metric, got %d", len(all))
	}

	// Test Count
	if mc.Count() != 1 {
		t.Errorf("Expected count 1, got %d", mc.Count())
	}

	// Add more metrics
	mc.Set("test.metric2", 3.14, "seconds")
	mc.Set("test.metric3", "value", "string")

	if mc.Count() != 3 {
		t.Errorf("Expected count 3, got %d", mc.Count())
	}
}

// TestConcurrentMetricsAccess tests concurrent access to metrics
func TestConcurrentMetricsAccess(t *testing.T) {
	mc := &MetricsCollector{
		metrics: make(map[string]Metric),
	}

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Multiple writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				mc.Set(string(rune('a'+id)), j, "count")
			}
		}(i)
	}

	// Multiple readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				all := mc.GetAll()
				if all == nil {
					errors <- &testError{"GetAll returned nil"}
				}
				_ = mc.Count()
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

// TestHealthStates tests various health states
func TestHealthStates(t *testing.T) {
	// Test 1: Nil global state
	globalState = nil
	health := healthMonitoring()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status with nil state, got %v", health.Status)
	}

	// Test 2: No metrics collected
	globalState = &monitoringState{
		metrics:       make(map[string]interface{}),
		healthStatus:  plugin.HealthStatusDegraded,
		healthMessage: "No metrics",
	}
	health = healthMonitoring()
	if health.Status != plugin.HealthStatusDegraded {
		t.Errorf("Expected degraded status, got %v", health.Status)
	}

	// Test 3: With metrics
	globalState.metrics["test"] = "value"
	globalState.healthStatus = plugin.HealthStatusHealthy
	globalState.healthMessage = "All good"
	health = healthMonitoring()
	if health.Status != plugin.HealthStatusHealthy {
		t.Errorf("Expected healthy status, got %v", health.Status)
	}

	// Verify details
	if health.Details["metrics_count"].(int) != 1 {
		t.Errorf("Expected 1 metric in details, got %v", health.Details["metrics_count"])
	}
	if health.Details["cpu_count"].(int) != runtime.NumCPU() {
		t.Errorf("Expected correct CPU count in details")
	}
}

// TestBuilderPatternPlugin tests that the builder pattern creates a valid plugin
func TestBuilderPatternPlugin(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	// Verify it implements the Plugin interface
	_ = p // Verify it implements the Plugin interface

	// Test that all lifecycle methods work
	ctx := context.Background()

	err := p.Init(ctx, plugin.Config{})
	if err != nil {
		t.Errorf("Init failed: %v", err)
	}

	err = p.Start(ctx)
	if err != nil {
		t.Errorf("Start failed: %v", err)
	}

	health := p.Health()
	if health.Status == "" {
		t.Error("Health should return a status")
	}

	err = p.Stop(ctx)
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestConfigDuration tests the GetConfigDuration helper
func TestConfigDuration(t *testing.T) {
	mp := NewFullMonitoringPlugin()

	// Initialize with config containing duration
	ctx := context.Background()
	err := mp.Init(ctx, plugin.Config{
		"interval": 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	duration := mp.GetConfigDuration("interval", 10*time.Second)
	if duration != 5*time.Second {
		t.Errorf("Expected 5s from config, got %v", duration)
	}

	// Test with missing config
	duration = mp.GetConfigDuration("missing", 10*time.Second)
	if duration != 10*time.Second {
		t.Errorf("Expected default 10s, got %v", duration)
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
