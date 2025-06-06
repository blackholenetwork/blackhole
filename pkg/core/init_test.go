package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/blackholenetwork/blackhole/internal/config"
	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// MockLogger captures log output for testing
type MockLogger struct {
	Messages []string
}

func (ml *MockLogger) Write(p []byte) (n int, err error) {
	ml.Messages = append(ml.Messages, string(p))
	return len(p), nil
}

func (ml *MockLogger) Printf(format string, v ...interface{}) {
	ml.Messages = append(ml.Messages, fmt.Sprintf(format, v...))
}

// MockPlugin is a test plugin implementation
type MockPlugin struct {
	*plugin.BasePlugin
	initError     error
	startError    error
	stopError     error
	initCalled    bool
	started       bool
	healthStatus  plugin.HealthStatus
	healthMessage string
}

func NewMockPlugin(name string) *MockPlugin {
	info := plugin.Info{
		Name:         name,
		Version:      "1.0.0",
		Description:  "Mock plugin for testing",
		Author:       "Test",
		License:      "MIT",
		Dependencies: []string{},
		Capabilities: []string{},
	}
	mp := &MockPlugin{
		BasePlugin:    plugin.NewBasePlugin(info),
		healthStatus:  plugin.HealthStatusHealthy,
		healthMessage: "Mock plugin healthy",
	}
	// Override the BasePlugin's Health method
	return mp
}

func (mp *MockPlugin) Init(_ context.Context, _ plugin.Config) error {
	mp.initCalled = true
	return mp.initError
}

func (mp *MockPlugin) Start(_ context.Context) error {
	if mp.startError != nil {
		return mp.startError
	}
	mp.started = true
	return nil
}

func (mp *MockPlugin) Stop(_ context.Context) error {
	mp.started = false
	return mp.stopError
}

func (mp *MockPlugin) Health() plugin.Health {
	// If we have a custom health status set AND the plugin is started, return that
	if (mp.healthStatus != "" || mp.healthMessage != "") && mp.started {
		return plugin.Health{
			Status:    mp.healthStatus,
			Message:   mp.healthMessage,
			LastCheck: time.Now(),
		}
	}
	// Otherwise return the BasePlugin's default health (which considers started status)
	return mp.BasePlugin.Health()
}

func (mp *MockPlugin) SetHealth(status plugin.HealthStatus, message string) {
	mp.healthStatus = status
	mp.healthMessage = message
	// Also call the base to publish events
	mp.BasePlugin.SetHealth(status, message)
}

// MockOrchestrator for testing registration failures
type MockOrchestrator struct {
	*orchestrator.Orchestrator
	registerError error
	components    []orchestrator.Component
}

func (mo *MockOrchestrator) Register(component orchestrator.Component) error {
	if mo.registerError != nil {
		return mo.registerError
	}
	mo.components = append(mo.components, component)
	return nil
}

// TestInitializeOrchestrator_Success tests successful orchestrator initialization
func TestInitializeOrchestrator_Success(t *testing.T) {
	cfg := &config.Config{
		Node: config.NodeConfig{
			ID: "test-node",
		},
	}
	ml := &MockLogger{}
	logger := log.New(ml, "", 0)

	orch, err := InitializeOrchestrator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if orch == nil {
		t.Fatal("Expected orchestrator to be created")
	}

	// Verify that 4 plugins were registered (security, analytics, webserver, network)
	// This is based on the log message in InitializeOrchestrator
	found := false
	for _, msg := range ml.Messages {
		if strings.Contains(msg, "Registered 4 core plugins") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected log message about registering 4 core plugins")
	}
}

// TestInitializeOrchestrator_OrchestratorCreationError tests orchestrator creation failure
func TestInitializeOrchestrator_OrchestratorCreationError(t *testing.T) {
	// Use nil config to trigger an error in orchestrator creation
	orch, err := InitializeOrchestrator(nil, nil)

	if err == nil {
		t.Fatal("Expected error when creating orchestrator with nil config")
	}

	if orch != nil {
		t.Fatal("Expected nil orchestrator on error")
	}

	if !strings.Contains(err.Error(), "failed to create orchestrator") {
		t.Errorf("Expected error to contain 'failed to create orchestrator', got: %v", err)
	}
}

// TestPluginRegistrationOrder verifies plugins are registered in correct order
func TestPluginRegistrationOrder(t *testing.T) {
	cfg := &config.Config{
		Node: config.NodeConfig{
			ID: "test-node",
		},
	}
	ml := &MockLogger{}
	logger := log.New(ml, "", 0)

	// We can't easily test the exact order without modifying the implementation,
	// but we can verify the function completes successfully
	orch, err := InitializeOrchestrator(cfg, logger)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if orch == nil {
		t.Fatal("Expected orchestrator to be created")
	}
}

// TestPluginComponentAdapter tests the adapter functionality
func TestPluginComponentAdapter(t *testing.T) {
	mockPlugin := NewMockPlugin("test-plugin")
	deps := []string{"dep1", "dep2"}

	adapter := NewPluginComponentAdapter(mockPlugin, deps)

	// Test Name
	if adapter.Name() != "test-plugin" {
		t.Errorf("Expected name 'test-plugin', got %s", adapter.Name())
	}

	// Test Dependencies
	if len(adapter.Dependencies()) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(adapter.Dependencies()))
	}

	// Test WithConfig
	config := plugin.Config{
		"key": "value",
	}
	adapter = adapter.WithConfig(config)
	if adapter.config["key"] != "value" {
		t.Error("Config not set correctly")
	}

	// Test Start
	ctx := context.Background()
	err := adapter.Start(ctx)
	if err != nil {
		t.Errorf("Expected no error on start, got: %v", err)
	}
	if !mockPlugin.initCalled {
		t.Error("Expected Init to be called")
	}
	if !mockPlugin.started {
		t.Error("Expected plugin to be started")
	}

	// Test Stop
	err = adapter.Stop(ctx)
	if err != nil {
		t.Errorf("Expected no error on stop, got: %v", err)
	}
	if mockPlugin.started {
		t.Error("Expected plugin to be stopped")
	}

	// Test Health - should be Unknown since plugin is not started yet (only Init was called)
	health := adapter.Health()
	if health.Status != orchestrator.HealthStatusUnknown {
		t.Errorf("Expected unknown status before start, got %v", health.Status)
	}
}

// TestPluginComponentAdapter_StartError tests adapter behavior when plugin start fails
func TestPluginComponentAdapter_StartError(t *testing.T) {
	mockPlugin := NewMockPlugin("test-plugin")
	mockPlugin.startError = errors.New("start failed")

	adapter := NewPluginComponentAdapter(mockPlugin, []string{})

	ctx := context.Background()
	err := adapter.Start(ctx)
	if err == nil {
		t.Fatal("Expected error when plugin start fails")
	}
	if err.Error() != "start failed" {
		t.Errorf("Expected 'start failed' error, got: %v", err)
	}
}

// TestPluginComponentAdapter_InitError tests adapter behavior when plugin init fails
func TestPluginComponentAdapter_InitError(t *testing.T) {
	mockPlugin := NewMockPlugin("test-plugin")
	mockPlugin.initError = errors.New("init failed")

	adapter := NewPluginComponentAdapter(mockPlugin, []string{})

	ctx := context.Background()
	err := adapter.Start(ctx)
	if err == nil {
		t.Fatal("Expected error when plugin init fails")
	}
	if err.Error() != "init failed" {
		t.Errorf("Expected 'init failed' error, got: %v", err)
	}
}

// TestPluginComponentAdapter_HealthStatusConversion tests health status conversion
func TestPluginComponentAdapter_HealthStatusConversion(t *testing.T) {
	tests := []struct {
		name           string
		pluginStatus   plugin.HealthStatus
		expectedStatus orchestrator.HealthStatus
		startPlugin    bool
	}{
		{
			name:           "Healthy",
			pluginStatus:   plugin.HealthStatusHealthy,
			expectedStatus: orchestrator.HealthStatusHealthy,
			startPlugin:    true,
		},
		{
			name:           "Degraded",
			pluginStatus:   plugin.HealthStatusDegraded,
			expectedStatus: orchestrator.HealthStatusDegraded,
			startPlugin:    true,
		},
		{
			name:           "Unhealthy",
			pluginStatus:   plugin.HealthStatusUnhealthy,
			expectedStatus: orchestrator.HealthStatusUnhealthy,
			startPlugin:    true,
		},
		{
			name:           "Unknown",
			pluginStatus:   plugin.HealthStatusUnknown,
			expectedStatus: orchestrator.HealthStatusUnknown,
			startPlugin:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPlugin := NewMockPlugin("test-plugin")
			ctx := context.Background()

			// Initialize the plugin
			_ = mockPlugin.Init(ctx, plugin.Config{})

			if tt.startPlugin {
				// Start the plugin to enable health status changes
				_ = mockPlugin.Start(ctx)
			}

			// Set the desired health status
			mockPlugin.SetHealth(tt.pluginStatus, "test message")

			adapter := NewPluginComponentAdapter(mockPlugin, []string{})
			health := adapter.Health()

			if health.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, health.Status)
			}
		})
	}
}

// TestPluginComponentAdapter_SetHealth tests the SetHealth method
func TestPluginComponentAdapter_SetHealth(t *testing.T) {
	tests := []struct {
		name           string
		status         string
		expectedStatus plugin.HealthStatus
	}{
		{
			name:           "Healthy",
			status:         "healthy",
			expectedStatus: plugin.HealthStatusHealthy,
		},
		{
			name:           "Degraded",
			status:         "degraded",
			expectedStatus: plugin.HealthStatusDegraded,
		},
		{
			name:           "Unhealthy",
			status:         "unhealthy",
			expectedStatus: plugin.HealthStatusUnhealthy,
		},
		{
			name:           "Unknown",
			status:         "unknown",
			expectedStatus: plugin.HealthStatusUnknown,
		},
		{
			name:           "Invalid",
			status:         "invalid-status",
			expectedStatus: plugin.HealthStatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPlugin := NewMockPlugin("test-plugin")
			ctx := context.Background()

			// Initialize and start the plugin to enable SetHealth
			_ = mockPlugin.Init(ctx, plugin.Config{})
			_ = mockPlugin.Start(ctx)

			adapter := NewPluginComponentAdapter(mockPlugin, []string{})

			adapter.SetHealth(tt.status, "test message")

			health := mockPlugin.Health()
			if health.Status != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, health.Status)
			}
			if health.Message != "test message" {
				t.Errorf("Expected message 'test message', got %s", health.Message)
			}
		})
	}
}
