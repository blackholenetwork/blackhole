package analytics

import (
	"context"
	"fmt"
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

func (tr *TestRegistry) WasPublished() bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.published
}

// TestNewPlugin tests plugin creation
func TestNewPlugin(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	if p == nil {
		t.Fatal("Expected plugin to be created")
	}

	info := p.Info()
	if info.Name != "analytics" {
		t.Errorf("Expected name 'analytics', got %s", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got %s", info.Version)
	}
	if len(info.Capabilities) != 1 || info.Capabilities[0] != string(plugin.CapabilityMonitoring) {
		t.Error("Expected monitoring capability")
	}
}

// TestPluginInit tests plugin initialization
func TestPluginInit(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	config := plugin.Config{
		"interval": 5 * time.Second,
	}

	err := p.Init(ctx, config)
	if err != nil {
		t.Fatalf("Expected no error on init, got: %v", err)
	}

	// Check health after init - should be unknown since not started
	health := p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status after init (not started), got %v", health.Status)
	}
	if health.Message != "Analytics not started" {
		t.Errorf("Expected 'Analytics not started' message, got %s", health.Message)
	}
}

// TestPluginStart tests plugin start
func TestPluginStart(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize first
	err := p.Init(ctx, plugin.Config{})
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Start the plugin
	err = p.Start(ctx)
	if err != nil {
		t.Fatalf("Expected no error on start, got: %v", err)
	}

	// Check if plugin is started
	if !p.started {
		t.Error("Expected plugin to be started")
	}

	// Check health after start - should be degraded since no metrics collected yet
	health := p.Health()
	if health.Status != plugin.HealthStatusDegraded {
		t.Errorf("Expected degraded status after start (no metrics yet), got %v", health.Status)
	}

	// Clean up
	err = p.Stop(ctx)
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestPluginStart_AlreadyStarted tests starting an already started plugin
func TestPluginStart_AlreadyStarted(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize and start
	_ = p.Init(ctx, plugin.Config{})
	_ = p.Start(ctx)

	// Try to start again
	err := p.Start(ctx)
	if err == nil {
		t.Fatal("Expected error when starting already started plugin")
	}
	if err.Error() != "analytics plugin already started" {
		t.Errorf("Expected 'already started' error, got: %v", err)
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestPluginStop tests plugin stop
func TestPluginStop(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize and start
	_ = p.Init(ctx, plugin.Config{})
	_ = p.Start(ctx)

	// Stop the plugin
	err := p.Stop(ctx)
	if err != nil {
		t.Fatalf("Expected no error on stop, got: %v", err)
	}

	// Check if plugin is stopped
	if p.started {
		t.Error("Expected plugin to be stopped")
	}

	// Check health after stop
	health := p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status after stop, got %v", health.Status)
	}
}

// TestPluginStop_NotStarted tests stopping a non-started plugin
func TestPluginStop_NotStarted(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Try to stop without starting
	err := p.Stop(ctx)
	if err != nil {
		t.Errorf("Expected no error when stopping non-started plugin, got: %v", err)
	}
}

// TestMetricsCollection tests that metrics are collected
func TestMetricsCollection(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Use a very short interval for testing
	config := plugin.Config{
		"interval": 100 * time.Millisecond,
	}

	_ = p.Init(ctx, config)
	_ = p.Start(ctx)

	// Wait for metrics to be collected
	time.Sleep(200 * time.Millisecond)

	// Check if metrics were collected
	metrics := p.GetMetrics()
	if len(metrics) == 0 {
		t.Error("Expected metrics to be collected")
	}

	// Verify specific metrics exist
	expectedMetrics := []string{
		"memory.alloc",
		"memory.total_alloc",
		"memory.sys",
		"memory.num_gc",
		"runtime.goroutines",
		"runtime.cpu_count",
	}

	for _, name := range expectedMetrics {
		if _, exists := metrics[name]; !exists {
			t.Errorf("Expected metric %s to exist", name)
		}
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestGetMetric tests retrieving a specific metric
func TestGetMetric(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initialize, start, and collect metrics
	_ = p.Init(ctx, plugin.Config{"interval": 100 * time.Millisecond})
	_ = p.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Test existing metric
	metric, exists := p.GetMetric("runtime.goroutines")
	if !exists {
		t.Error("Expected metric to exist")
	}
	if metric == nil {
		t.Error("Expected metric to be non-nil")
		return
	}
	if metric.Name != "runtime.goroutines" {
		t.Errorf("Expected metric name 'runtime.goroutines', got %s", metric.Name)
	}

	// Test non-existing metric
	_, exists = p.GetMetric("non.existing.metric")
	if exists {
		t.Error("Expected metric to not exist")
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestGetMetricsCount tests the metrics count function
func TestGetMetricsCount(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Initially should be 0
	if count := p.GetMetricsCount(); count != 0 {
		t.Errorf("Expected 0 metrics initially, got %d", count)
	}

	// Initialize, start, and collect metrics
	_ = p.Init(ctx, plugin.Config{"interval": 100 * time.Millisecond})
	_ = p.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Should have collected metrics
	count := p.GetMetricsCount()
	if count == 0 {
		t.Error("Expected metrics to be collected")
	}
	if count != 6 { // We collect 6 metrics in collectSystemMetrics
		t.Errorf("Expected 6 metrics, got %d", count)
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestHealthStates tests various health states
func TestHealthStates(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	// Test 1: Not started state
	health := p.Health()
	if health.Status != plugin.HealthStatusUnknown {
		t.Errorf("Expected unknown status when not started, got %v", health.Status)
	}
	if health.Message != "Analytics not started" {
		t.Errorf("Expected 'Analytics not started' message, got %s", health.Message)
	}

	// Test 2: Started but no metrics yet
	_ = p.Init(ctx, plugin.Config{"interval": 10 * time.Second}) // Long interval
	_ = p.Start(ctx)

	// Immediately check health (before metrics collection)
	health = p.Health()
	if health.Status != plugin.HealthStatusDegraded {
		t.Errorf("Expected degraded status with no metrics, got %v", health.Status)
	}
	if health.Message != "No metrics collected yet" {
		t.Errorf("Expected 'No metrics collected yet' message, got %s", health.Message)
	}

	// Test 3: Metrics collected
	p.collectSystemMetrics() // Manually trigger collection
	health = p.Health()
	if health.Status != plugin.HealthStatusHealthy {
		t.Errorf("Expected healthy status with metrics, got %v", health.Status)
	}
	if !contains(health.Message, "Analytics operational") {
		t.Errorf("Expected 'Analytics operational' in message, got %s", health.Message)
	}

	// Verify health details
	details := health.Details
	if details["metrics_count"].(int) != 6 {
		t.Errorf("Expected 6 metrics in health details, got %v", details["metrics_count"])
	}
	if details["started"].(bool) != true {
		t.Error("Expected started=true in health details")
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestConcurrentAccess tests concurrent access to metrics
func TestConcurrentAccess(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"interval": 10 * time.Millisecond})
	_ = p.Start(ctx)

	// Create multiple goroutines accessing metrics concurrently
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				p.collectSystemMetrics()
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				metrics := p.GetMetrics()
				if metrics == nil {
					errors <- fmt.Errorf("GetMetrics returned nil")
				}
				count := p.GetMetricsCount()
				if count < 0 {
					errors <- fmt.Errorf("negative metrics count: %d", count)
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Health checkers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				health := p.Health()
				if health.Status == "" {
					errors <- fmt.Errorf("empty health status")
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestEventPublication tests that events are published
func TestEventPublication(t *testing.T) {
	// Create a channel to capture events
	eventChan := make(chan plugin.Event, 10)

	registry := plugin.NewRegistry()

	// Subscribe to events before creating the plugin
	unsubscribe := registry.Subscribe("analytics.metrics_collected", func(event plugin.Event) {
		eventChan <- event
	})
	defer unsubscribe()

	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"interval": 100 * time.Millisecond})
	_ = p.Start(ctx)

	// Wait for metrics collection
	time.Sleep(200 * time.Millisecond)

	// Check if event was published
	select {
	case event := <-eventChan:
		if event.Type != "analytics.metrics_collected" {
			t.Errorf("Expected event type 'analytics.metrics_collected', got %s", event.Type)
		}
		if event.Source != "analytics" {
			t.Errorf("Expected event source 'analytics', got %s", event.Source)
		}
		if data, ok := event.Data.(map[string]interface{}); ok {
			if _, exists := data["metrics_count"]; !exists {
				t.Error("Expected metrics_count in event data")
			}
			if _, exists := data["collection_time"]; !exists {
				t.Error("Expected collection_time in event data")
			}
		} else {
			t.Error("Expected event data to be map[string]interface{}")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for analytics.metrics_collected event")
	}

	// Clean up
	_ = p.Stop(ctx)
}

// TestMetricValues tests that metric values are reasonable
func TestMetricValues(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)
	ctx := context.Background()

	_ = p.Init(ctx, plugin.Config{"interval": 100 * time.Millisecond})
	_ = p.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	metrics := p.GetMetrics()

	// Test memory metrics
	if memAlloc, exists := metrics["memory.alloc"]; exists {
		if memAlloc.Value.(uint64) == 0 {
			t.Error("Expected non-zero memory allocation")
		}
		if memAlloc.Unit != "bytes" {
			t.Errorf("Expected unit 'bytes' for memory.alloc, got %s", memAlloc.Unit)
		}
	}

	// Test runtime metrics
	if goroutines, exists := metrics["runtime.goroutines"]; exists {
		if goroutines.Value.(int) < 1 {
			t.Error("Expected at least 1 goroutine")
		}
		if goroutines.Unit != "count" {
			t.Errorf("Expected unit 'count' for runtime.goroutines, got %s", goroutines.Unit)
		}
	}

	if cpuCount, exists := metrics["runtime.cpu_count"]; exists {
		if cpuCount.Value.(int) < 1 {
			t.Error("Expected at least 1 CPU")
		}
	}

	// Test that all metrics have timestamps
	for name, metric := range metrics {
		if metric.Timestamp.IsZero() {
			t.Errorf("Metric %s has zero timestamp", name)
		}
		if time.Since(metric.Timestamp) > time.Second {
			t.Errorf("Metric %s has old timestamp", name)
		}
	}

	// Clean up
	_ = p.Stop(ctx)
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
