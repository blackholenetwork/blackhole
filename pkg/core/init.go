package core

import (
	"fmt"
	"log"

	"github.com/blackholenetwork/blackhole/internal/config"
	"github.com/blackholenetwork/blackhole/pkg/core/analytics"
	"github.com/blackholenetwork/blackhole/pkg/core/networking"
	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
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

	// 2. Analytics Plugin - No dependencies, provides system metrics
	analyticsPlugin := analytics.NewPlugin(registry)
	analyticsAdapter := NewPluginComponentAdapter(analyticsPlugin, []string{})
	if err := orch.Register(analyticsAdapter); err != nil {
		return nil, fmt.Errorf("failed to register analytics plugin: %w", err)
	}
	if err := registry.Register(analyticsPlugin); err != nil {
		return nil, fmt.Errorf("failed to register analytics plugin in registry: %w", err)
	}

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

	// 4. Network Plugin - Depends on security for node identity
	networkPlugin := networking.New(registry)
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

	// Future plugins would be registered here with their dependencies:
	//
	// 4. Storage Plugin - Depends on networking for data distribution
	// storageAdapter := NewPluginComponentAdapter(storagePlugin, []string{"networking"})
	//
	// 5. Compute Plugin - Depends on networking for job distribution
	// computeAdapter := NewPluginComponentAdapter(computePlugin, []string{"networking", "monitoring"})
	//
	// 6. Economic Plugin - Depends on all resource plugins
	// economicAdapter := NewPluginComponentAdapter(economicPlugin, []string{"storage", "compute", "networking"})

	logger.Printf("Registered %d core plugins", 4)

	return orch, nil
}

// Plugin Dependency Tree:
//
// security (no deps)
// analytics (no deps)
// webserver (depends on security) - starts early with progressive API activation
// network (depends on security)
// ├── storage (depends on network)
// ├── compute (depends on network, analytics)
// └── economic (depends on storage, compute, network)
//
// Startup Order (topological sort):
// 1. security, analytics (can start in parallel)
// 2. webserver, network (can start in parallel after security)
// 3. storage, compute (can start in parallel)
// 4. economic
