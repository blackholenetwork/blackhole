package core

import (
	"fmt"
	"log"

	"github.com/blackholenetwork/blackhole/internal/config"
	"github.com/blackholenetwork/blackhole/pkg/core/monitoring"
	"github.com/blackholenetwork/blackhole/pkg/core/networking"
	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
	"github.com/blackholenetwork/blackhole/pkg/core/security"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
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
	securityPlugin := security.NewSecurityPlugin()
	securityAdapter := NewPluginComponentAdapter(securityPlugin, []string{})
	if err := orch.Register(securityAdapter); err != nil {
		return nil, fmt.Errorf("failed to register security plugin: %w", err)
	}
	if err := registry.Register(securityPlugin); err != nil {
		return nil, fmt.Errorf("failed to register security plugin in registry: %w", err)
	}

	// 2. Monitoring Plugin - No dependencies, provides system metrics
	monitoringPlugin := monitoring.NewMonitoringPlugin()
	monitoringAdapter := NewPluginComponentAdapter(monitoringPlugin, []string{})
	if err := orch.Register(monitoringAdapter); err != nil {
		return nil, fmt.Errorf("failed to register monitoring plugin: %w", err)
	}
	if err := registry.Register(monitoringPlugin); err != nil {
		return nil, fmt.Errorf("failed to register monitoring plugin in registry: %w", err)
	}

	// 3. Networking Plugin - Depends on security for node identity
	networkingPlugin := networking.New(registry)
	networkingConfig := plugin.Config{
		"enable_auto_relay": false, // Disable for local development without bootstrap peers
		"port": 4001,
		// In production, add bootstrap peers:
		// "bootstrap_peers": []string{
		//     "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId1",
		//     "/ip4/5.6.7.8/tcp/4001/p2p/QmPeerId2",
		// },
	}
	networkingAdapter := NewPluginComponentAdapter(networkingPlugin, []string{"security"}).
		WithConfig(networkingConfig)
	if err := orch.Register(networkingAdapter); err != nil {
		return nil, fmt.Errorf("failed to register networking plugin: %w", err)
	}
	if err := registry.Register(networkingPlugin); err != nil {
		return nil, fmt.Errorf("failed to register networking plugin in registry: %w", err)
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

	logger.Printf("Registered %d core plugins", 3)
	
	return orch, nil
}

// Plugin Dependency Tree:
//
// security (no deps)
// monitoring (no deps)
// networking (depends on security)
// ├── storage (depends on networking)
// ├── compute (depends on networking, monitoring)
// └── economic (depends on storage, compute, networking)
//
// Startup Order (topological sort):
// 1. security, monitoring (can start in parallel)
// 2. networking
// 3. storage, compute (can start in parallel)
// 4. economic