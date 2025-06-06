package utils

import (
	"fmt"
	"sync"
	"time"
)

// MetricsCollector collects and stores metrics for plugins
type MetricsCollector struct {
	mu      sync.RWMutex
	metrics map[string]*Metric
}

// Metric represents a single metric
type Metric struct {
	Name      string
	Type      MetricType
	Value     float64
	Labels    map[string]string
	Timestamp time.Time
	mu        sync.RWMutex

	// For histograms
	buckets []float64
	counts  []int64
	sum     float64
	count   int64
}

// MetricType represents the type of metric
type MetricType string

// Metric type constants
const (
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeCounter   MetricType = "counter"
	MetricTypeHistogram MetricType = "histogram"
)

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: make(map[string]*Metric),
	}
}

// RegisterGauge registers a gauge metric
func (mc *MetricsCollector) RegisterGauge(name string, labels map[string]string) *Metric {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := metricKey(name, labels)
	metric := &Metric{
		Name:      name,
		Type:      MetricTypeGauge,
		Labels:    labels,
		Timestamp: time.Now(),
	}

	mc.metrics[key] = metric
	return metric
}

// RegisterCounter registers a counter metric
func (mc *MetricsCollector) RegisterCounter(name string, labels map[string]string) *Metric {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := metricKey(name, labels)
	metric := &Metric{
		Name:      name,
		Type:      MetricTypeCounter,
		Labels:    labels,
		Value:     0,
		Timestamp: time.Now(),
	}

	mc.metrics[key] = metric
	return metric
}

// RegisterHistogram registers a histogram metric
func (mc *MetricsCollector) RegisterHistogram(name string, labels map[string]string, buckets []float64) *Metric {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := metricKey(name, labels)
	metric := &Metric{
		Name:      name,
		Type:      MetricTypeHistogram,
		Labels:    labels,
		Timestamp: time.Now(),
		buckets:   buckets,
		counts:    make([]int64, len(buckets)+1),
	}

	mc.metrics[key] = metric
	return metric
}

// Set sets the value of a gauge metric
func (mc *MetricsCollector) Set(name string, value float64, labels map[string]string) {
	mc.mu.RLock()
	key := metricKey(name, labels)
	metric, exists := mc.metrics[key]
	mc.mu.RUnlock()

	if !exists {
		metric = mc.RegisterGauge(name, labels)
	}

	metric.Set(value)
}

// Inc increments a counter metric
func (mc *MetricsCollector) Inc(name string, labels map[string]string) {
	mc.mu.RLock()
	key := metricKey(name, labels)
	metric, exists := mc.metrics[key]
	mc.mu.RUnlock()

	if !exists {
		metric = mc.RegisterCounter(name, labels)
	}

	metric.Inc()
}

// Add adds a value to a counter metric
func (mc *MetricsCollector) Add(name string, value float64, labels map[string]string) {
	mc.mu.RLock()
	key := metricKey(name, labels)
	metric, exists := mc.metrics[key]
	mc.mu.RUnlock()

	if !exists {
		metric = mc.RegisterCounter(name, labels)
	}

	metric.Add(value)
}

// Observe records an observation in a histogram
func (mc *MetricsCollector) Observe(name string, value float64, labels map[string]string) {
	mc.mu.RLock()
	key := metricKey(name, labels)
	metric, exists := mc.metrics[key]
	mc.mu.RUnlock()

	if exists && metric.Type == MetricTypeHistogram {
		metric.Observe(value)
	}
}

// GetMetrics returns all metrics
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	result := make(map[string]interface{})

	for key, metric := range mc.metrics {
		result[key] = metric.GetValue()
	}

	return result
}

// GetMetric returns a specific metric
func (mc *MetricsCollector) GetMetric(name string, labels map[string]string) (*Metric, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	key := metricKey(name, labels)
	metric, exists := mc.metrics[key]
	return metric, exists
}

// Metric methods

// Set sets the value of a gauge
func (m *Metric) Set(value float64) {
	if m.Type != MetricTypeGauge {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.Value = value
	m.Timestamp = time.Now()
}

// Inc increments a counter by 1
func (m *Metric) Inc() {
	m.Add(1)
}

// Add adds a value to a counter
func (m *Metric) Add(value float64) {
	if m.Type != MetricTypeCounter {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.Value += value
	m.Timestamp = time.Now()
}

// Observe records an observation in a histogram
func (m *Metric) Observe(value float64) {
	if m.Type != MetricTypeHistogram {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update histogram
	m.sum += value
	m.count++

	// Find the right bucket
	bucketIndex := len(m.buckets)
	for i, boundary := range m.buckets {
		if value <= boundary {
			bucketIndex = i
			break
		}
	}

	m.counts[bucketIndex]++
	m.Timestamp = time.Now()
}

// GetValue returns the current value of the metric
func (m *Metric) GetValue() interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch m.Type {
	case MetricTypeGauge, MetricTypeCounter:
		return map[string]interface{}{
			"type":      m.Type,
			"value":     m.Value,
			"timestamp": m.Timestamp,
			"labels":    m.Labels,
		}

	case MetricTypeHistogram:
		return map[string]interface{}{
			"type":      m.Type,
			"sum":       m.sum,
			"count":     m.count,
			"average":   m.sum / float64(m.count),
			"buckets":   m.buckets,
			"counts":    m.counts,
			"timestamp": m.Timestamp,
			"labels":    m.Labels,
		}

	default:
		return nil
	}
}

// Helper functions

// metricKey generates a unique key for a metric
func metricKey(name string, labels map[string]string) string {
	key := name

	// Sort labels for consistent keys
	for k, v := range labels {
		key += fmt.Sprintf(",%s=%s", k, v)
	}

	return key
}

// Common metric helpers

// MeasureDuration measures the duration of a function call
func MeasureDuration(mc *MetricsCollector, name string, labels map[string]string) func() {
	start := time.Now()

	return func() {
		duration := time.Since(start).Seconds()
		mc.Observe(name, duration, labels)
	}
}

// TrackGoroutines tracks the number of goroutines
func TrackGoroutines(mc *MetricsCollector, name string, labels map[string]string) func() {
	mc.Inc(name+"_started", labels)

	return func() {
		mc.Inc(name+"_completed", labels)
	}
}

// TrackError increments error counters
func TrackError(mc *MetricsCollector, name string, err error, labels map[string]string) {
	if err != nil {
		errorLabels := make(map[string]string)
		for k, v := range labels {
			errorLabels[k] = v
		}
		errorLabels["error"] = err.Error()

		mc.Inc(name+"_errors", errorLabels)
	}
}
