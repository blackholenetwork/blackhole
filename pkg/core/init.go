package core

import (
	"fmt"
	"log"

	"github.com/blackholenetwork/blackhole/internal/config"
	"github.com/blackholenetwork/blackhole/pkg/core/monitor"
	"github.com/blackholenetwork/blackhole/pkg/core/network"
	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
	"github.com/blackholenetwork/blackhole/pkg/core/resourcemanager"
	"github.com/blackholenetwork/blackhole/pkg/core/security"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
	"github.com/blackholenetwork/blackhole/pkg/service/webserver"
)

// InitializeOrchestrator creates and configures the orchestrator with all core plugins
func InitializeOrchestrator(cfg *config.Config, logger *log.Logger) (*orchestrator.Orchestrator, error) {
	// Create orchestrator
	orch, err := orchestrator.New(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrator: %w", err)
	}

	// Create plugin registry
	registry := plugin.NewRegistry()

	// Track the number of registered plugins
	registeredPlugins := 0

	// Define plugin initialization order and dependencies
	// The order matters: dependencies must be registered before dependents

	// 1. Security Plugin - No dependencies, needed for authentication
	securityPlugin := security.NewPlugin(registry)
	securityAdapter := NewPluginComponentAdapter(securityPlugin, []string{})
	if err := orch.Register(securityAdapter); err != nil {
		return nil, fmt.Errorf("failed to register security plugin: %w", err)
	}
	if err := registry.Register(securityPlugin); err != nil {
		return nil, fmt.Errorf("failed to register security plugin in registry: %w", err)
	}
	registeredPlugins++

	// 2. Monitor Plugin - No dependencies, provides system metrics
	monitorPlugin := monitor.NewPlugin(registry)
	monitorAdapter := NewPluginComponentAdapter(monitorPlugin, []string{})
	if err := orch.Register(monitorAdapter); err != nil {
		return nil, fmt.Errorf("failed to register monitor plugin: %w", err)
	}
	if err := registry.Register(monitorPlugin); err != nil {
		return nil, fmt.Errorf("failed to register monitor plugin in registry: %w", err)
	}
	registeredPlugins++

	// 3. Web Server Plugin - Depends on security for auth, starts early with limited functionality
	webserverPlugin := webserver.New(registry, orch)
	webserverConfig := plugin.Config{
		"port":             8080,
		"host":             "127.0.0.1", // Localhost only for security
		"enable_dashboard": true,
		"enable_websocket": true,
	}
	webserverAdapter := NewPluginComponentAdapter(webserverPlugin, []string{"security"}).
		WithConfig(webserverConfig)
	if err := orch.Register(webserverAdapter); err != nil {
		return nil, fmt.Errorf("failed to register webserver plugin: %w", err)
	}
	if err := registry.Register(webserverPlugin); err != nil {
		return nil, fmt.Errorf("failed to register webserver plugin in registry: %w", err)
	}
	registeredPlugins++

	// 4. Network Plugin - Depends on security for node identity
	networkPlugin := network.New(registry)
	networkConfig := plugin.Config{
		"enable_auto_relay": false, // Disable for local development without bootstrap peers
		"port":              4001,
		// In production, add bootstrap peers:
		// "bootstrap_peers": []string{
		//     "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId1",
		//     "/ip4/5.6.7.8/tcp/4001/p2p/QmPeerId2",
		// },
	}
	networkAdapter := NewPluginComponentAdapter(networkPlugin, []string{"security"}).
		WithConfig(networkConfig)
	if err := orch.Register(networkAdapter); err != nil {
		return nil, fmt.Errorf("failed to register network plugin: %w", err)
	}
	if err := registry.Register(networkPlugin); err != nil {
		return nil, fmt.Errorf("failed to register network plugin in registry: %w", err)
	}
	registeredPlugins++

	// 5. ResourceManager Plugin - Depends on monitor for system metrics
	resourceManagerPlugin := resourcemanager.NewPlugin(registry)
	resourceManagerAdapter := NewPluginComponentAdapter(resourceManagerPlugin, []string{"monitor"})
	if err := orch.Register(resourceManagerAdapter); err != nil {
		return nil, fmt.Errorf("failed to register resourcemanager plugin: %w", err)
	}
	if err := registry.Register(resourceManagerPlugin); err != nil {
		return nil, fmt.Errorf("failed to register resourcemanager plugin in registry: %w", err)
	}
	registeredPlugins++

	// Future plugins would be registered here with their dependencies:
	//
	// 4. Storage Plugin - Depends on network for data distribution
	// storageAdapter := NewPluginComponentAdapter(storagePlugin, []string{"network"})
	//
	// 5. Compute Plugin - Depends on network for job distribution
	// computeAdapter := NewPluginComponentAdapter(computePlugin, []string{"network", "monitor"})
	//
	// 6. Economic Plugin - Depends on all resource plugins
	// economicAdapter := NewPluginComponentAdapter(economicPlugin, []string{"storage", "compute", "network"})

	logger.Printf("Registered %d core plugins", registeredPlugins)

	return orch, nil
}

// Plugin Dependency Tree:
//
// security (no deps)
// monitor (no deps)
// webserver (depends on security) - starts early with progressive API activation
// network (depends on security)
// resourcemanager (depends on monitor)
// ├── storage (depends on network)
// ├── compute (depends on network, resourcemanager)
// └── economic (depends on storage, compute, network)
//
// Startup Order (topological sort):
// 1. security, monitor (can start in parallel)
// 2. webserver, network (can start in parallel after security)
// 3. resourcemanager (after monitor)
// 4. storage, compute (can start in parallel)
// 5. economic
