// Package core provides core infrastructure components for the Blackhole Network
package core

import (
	"context"

	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// PluginComponentAdapter adapts a Plugin to the orchestrator.Component interface
type PluginComponentAdapter struct {
	plugin       plugin.Plugin
	dependencies []string
	config       plugin.Config
}

// NewPluginComponentAdapter creates a new adapter
func NewPluginComponentAdapter(p plugin.Plugin, dependencies []string) *PluginComponentAdapter {
	return &PluginComponentAdapter{
		plugin:       p,
		dependencies: dependencies,
		config:       make(plugin.Config),
	}
}

// WithConfig sets the plugin configuration
func (a *PluginComponentAdapter) WithConfig(config plugin.Config) *PluginComponentAdapter {
	a.config = config
	return a
}

// Name returns the component name
func (a *PluginComponentAdapter) Name() string {
	return a.plugin.Info().Name
}

// Dependencies returns the names of components this one depends on
func (a *PluginComponentAdapter) Dependencies() []string {
	return a.dependencies
}

// Start initializes and starts the component
func (a *PluginComponentAdapter) Start(ctx context.Context) error {
	// Initialize with the configured settings
	if err := a.plugin.Init(ctx, a.config); err != nil {
		return err
	}

	return a.plugin.Start(ctx)
}

// Stop gracefully shuts down the component
func (a *PluginComponentAdapter) Stop(ctx context.Context) error {
	return a.plugin.Stop(ctx)
}

// Health returns the current health status
func (a *PluginComponentAdapter) Health() orchestrator.ComponentHealth {
	pluginHealth := a.plugin.Health()

	// Convert plugin health status to orchestrator health status
	var status orchestrator.HealthStatus
	switch pluginHealth.Status {
	case plugin.HealthStatusHealthy:
		status = orchestrator.HealthStatusHealthy
	case plugin.HealthStatusDegraded:
		status = orchestrator.HealthStatusDegraded
	case plugin.HealthStatusUnhealthy:
		status = orchestrator.HealthStatusUnhealthy
	default:
		status = orchestrator.HealthStatusUnknown
	}

	return orchestrator.ComponentHealth{
		Status:    status,
		Message:   pluginHealth.Message,
		LastCheck: pluginHealth.LastCheck,
	}
}

// SetHealth sets the health status on the underlying plugin
func (a *PluginComponentAdapter) SetHealth(status string, message string) {
	// Convert string status to plugin health status
	var healthStatus plugin.HealthStatus
	switch status {
	case "healthy":
		healthStatus = plugin.HealthStatusHealthy
	case "degraded":
		healthStatus = plugin.HealthStatusDegraded
	case "unhealthy":
		healthStatus = plugin.HealthStatusUnhealthy
	default:
		healthStatus = plugin.HealthStatusUnknown
	}

	// Call SetHealth on the plugin's base
	a.plugin.SetHealth(healthStatus, message)
}

// Ensure PluginComponentAdapter implements Component interface
var _ orchestrator.Component = (*PluginComponentAdapter)(nil)
