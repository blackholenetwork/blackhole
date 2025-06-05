package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/internal/config"
)

// Component represents a system component that can be managed by the orchestrator
type Component interface {
	// Name returns the component name
	Name() string
	
	// Dependencies returns the names of components this one depends on
	Dependencies() []string
	
	// Start initializes and starts the component
	Start(ctx context.Context) error
	
	// Stop gracefully shuts down the component
	Stop(ctx context.Context) error
	
	// Health returns the current health status
	Health() ComponentHealth
}

// ComponentHealth represents the health status of a component
type ComponentHealth struct {
	Status    HealthStatus
	Message   string
	LastCheck time.Time
}

// HealthStatus represents the health state
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// Orchestrator manages the lifecycle of all components
type Orchestrator struct {
	config     *config.Config
	logger     *log.Logger
	components map[string]Component
	order      []string // Startup order based on dependencies
	mu         sync.RWMutex
	state      OrchestratorState
	ctx        context.Context
	cancel     context.CancelFunc
}

// OrchestratorState represents the orchestrator's current state
type OrchestratorState string

const (
	StateInitialized OrchestratorState = "initialized"
	StateStarting    OrchestratorState = "starting"
	StateRunning     OrchestratorState = "running"
	StateStopping    OrchestratorState = "stopping"
	StateStopped     OrchestratorState = "stopped"
	StateError       OrchestratorState = "error"
)

// New creates a new orchestrator instance
func New(cfg *config.Config, logger *log.Logger) (*Orchestrator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &Orchestrator{
		config:     cfg,
		logger:     logger,
		components: make(map[string]Component),
		state:      StateInitialized,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Register adds a component to the orchestrator
func (o *Orchestrator) Register(component Component) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.state != StateInitialized {
		return fmt.Errorf("cannot register component in state %s", o.state)
	}

	name := component.Name()
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}

	if _, exists := o.components[name]; exists {
		return fmt.Errorf("component %s already registered", name)
	}

	// Validate dependencies exist
	for _, dep := range component.Dependencies() {
		if _, exists := o.components[dep]; !exists {
			return fmt.Errorf("dependency %s not found for component %s", dep, name)
		}
	}

	o.components[name] = component
	o.logger.Printf("Registered component: %s", name)
	
	// Recalculate startup order
	if err := o.calculateStartupOrder(); err != nil {
		delete(o.components, name)
		return fmt.Errorf("failed to calculate startup order: %w", err)
	}

	return nil
}

// Start initializes and starts all components in the correct order
func (o *Orchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.state != StateInitialized {
		o.mu.Unlock()
		return fmt.Errorf("cannot start from state %s", o.state)
	}
	o.state = StateStarting
	o.mu.Unlock()

	o.logger.Println("Starting orchestrator...")

	// Start components in order
	for _, name := range o.order {
		component := o.components[name]
		o.logger.Printf("Starting component: %s", name)
		
		if err := component.Start(ctx); err != nil {
			o.mu.Lock()
			o.state = StateError
			o.mu.Unlock()
			
			// Stop already started components
			o.stopStartedComponents(name)
			
			return fmt.Errorf("failed to start component %s: %w", name, err)
		}
		
		o.logger.Printf("Component %s started successfully", name)
	}

	o.mu.Lock()
	o.state = StateRunning
	o.mu.Unlock()

	o.logger.Println("All components started successfully")

	// Start periodic health reporting
	go o.periodicHealthReport(ctx)

	return nil
}

// Stop gracefully shuts down all components in reverse order
func (o *Orchestrator) Stop(ctx context.Context) error {
	o.mu.Lock()
	if o.state != StateRunning && o.state != StateError {
		o.mu.Unlock()
		return fmt.Errorf("cannot stop from state %s", o.state)
	}
	o.state = StateStopping
	o.mu.Unlock()

	o.logger.Println("Stopping orchestrator...")

	// Cancel internal context
	o.cancel()

	// Stop components in reverse order
	for i := len(o.order) - 1; i >= 0; i-- {
		name := o.order[i]
		component := o.components[name]
		
		o.logger.Printf("Stopping component: %s", name)
		
		// Create timeout context for each component
		stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := component.Stop(stopCtx)
		cancel()
		
		if err != nil {
			o.logger.Printf("Error stopping component %s: %v", name, err)
			// Continue stopping other components
		} else {
			o.logger.Printf("Component %s stopped successfully", name)
		}
	}

	o.mu.Lock()
	o.state = StateStopped
	o.mu.Unlock()

	o.logger.Println("Orchestrator stopped")
	return nil
}

// Health returns the health status of all components
func (o *Orchestrator) Health() map[string]ComponentHealth {
	return o.HealthExcluding("")
}

// HealthExcluding returns the health status of all components except the specified caller
func (o *Orchestrator) HealthExcluding(caller string) map[string]ComponentHealth {
	o.mu.RLock()
	defer o.mu.RUnlock()

	health := make(map[string]ComponentHealth)
	for name, component := range o.components {
		// Skip the caller to avoid circular dependencies
		if name == caller {
			continue
		}
		health[name] = component.Health()
	}
	
	return health
}

// State returns the current orchestrator state
func (o *Orchestrator) State() OrchestratorState {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.state
}

// calculateStartupOrder determines the order to start components based on dependencies
func (o *Orchestrator) calculateStartupOrder() error {
	// Simple topological sort
	visited := make(map[string]bool)
	temp := make(map[string]bool)
	order := []string{}

	var visit func(string) error
	visit = func(name string) error {
		if temp[name] {
			return fmt.Errorf("circular dependency detected at component %s", name)
		}
		if visited[name] {
			return nil
		}

		temp[name] = true
		component := o.components[name]
		
		for _, dep := range component.Dependencies() {
			if err := visit(dep); err != nil {
				return err
			}
		}
		
		temp[name] = false
		visited[name] = true
		order = append(order, name)
		
		return nil
	}

	for name := range o.components {
		if err := visit(name); err != nil {
			return err
		}
	}

	o.order = order
	return nil
}

// stopStartedComponents stops components that were started before the given component
func (o *Orchestrator) stopStartedComponents(failedComponent string) {
	// Find index of failed component
	failedIndex := -1
	for i, name := range o.order {
		if name == failedComponent {
			failedIndex = i
			break
		}
	}

	if failedIndex <= 0 {
		return
	}

	// Stop in reverse order up to the failed component
	for i := failedIndex - 1; i >= 0; i-- {
		name := o.order[i]
		component := o.components[name]
		
		o.logger.Printf("Rolling back component: %s", name)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := component.Stop(ctx); err != nil {
			o.logger.Printf("Error stopping component %s during rollback: %v", name, err)
		}
		cancel()
	}
}

// periodicHealthReport periodically triggers health reporting for all components
func (o *Orchestrator) periodicHealthReport(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-o.ctx.Done():
			return
		case <-ticker.C:
			o.mu.RLock()
			components := make(map[string]Component, len(o.components))
			for k, v := range o.components {
				components[k] = v
			}
			o.mu.RUnlock()

			// Note: We no longer trigger SetHealth from orchestrator to avoid circular dependencies.
			// Each plugin manages its own health reporting through internal timers.
			// The orchestrator's Health() method can still be called directly when needed.
		}
	}
}