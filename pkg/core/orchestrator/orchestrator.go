// Package orchestrator manages the lifecycle and coordination of components
package orchestrator

import (
	"context"
	"fmt"
	"log"
	"os"
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

// Health status constants
const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// Orchestrator manages the lifecycle of all components
type Orchestrator struct {
	config        *config.Config
	logger        *log.Logger
	components    map[string]Component
	order         []string // Startup order based on dependencies
	mu            sync.RWMutex
	state         State
	ctx           context.Context
	cancel        context.CancelFunc
	startupLog    *os.File
	startupLogger *log.Logger
}

// State represents the orchestrator's current state
type State string

// Orchestrator state constants
const (
	StateInitialized State = "initialized"
	StateStarting    State = "starting"
	StateRunning     State = "running"
	StateStopping    State = "stopping"
	StateStopped     State = "stopped"
	StateError       State = "error"
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

	o := &Orchestrator{
		config:     cfg,
		logger:     logger,
		components: make(map[string]Component),
		state:      StateInitialized,
		ctx:        ctx,
		cancel:     cancel,
	}

	// Initialize startup log
	if err := o.initStartupLog(); err != nil {
		logger.Printf("Warning: failed to initialize startup log: %v", err)
		// Continue without startup logging
	}

	// Log initial orchestrator state
	o.logStartupEvent("ORCHESTRATOR", "state", fmt.Sprintf("Orchestrator created with state: %s", StateInitialized))

	return o, nil
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

	// Log registration event to startup log
	o.logStartupEvent("REGISTERED", name, fmt.Sprintf("Component %s registered", name))

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

	// Log orchestrator state transition
	o.logStartupEvent("ORCHESTRATOR", "state", fmt.Sprintf("State transition: %s → %s", StateInitialized, StateStarting))

	o.logger.Println("Starting orchestrator...")

	// Start components in order
	for _, name := range o.order {
		component := o.components[name]
		o.logger.Printf("Starting component: %s", name)

		if err := component.Start(ctx); err != nil {
			o.mu.Lock()
			o.state = StateError
			o.mu.Unlock()

			// Log error state transition
			o.logStartupEvent("ORCHESTRATOR", "state", fmt.Sprintf("State transition: %s → %s (failed on component %s)", StateStarting, StateError, name))

			// Stop already started components
			o.stopStartedComponents(name)

			return fmt.Errorf("failed to start component %s: %w", name, err)
		}

		o.logger.Printf("Component %s started successfully", name)

		// Log startup event to startup log
		o.logStartupEvent("STARTED", name, fmt.Sprintf("Component %s started successfully", name))
	}

	o.mu.Lock()
	o.state = StateRunning
	o.mu.Unlock()

	// Log state transition to running
	o.logStartupEvent("ORCHESTRATOR", "state", fmt.Sprintf("State transition: %s → %s", StateStarting, StateRunning))

	o.logger.Println("All components started successfully")

	// Log system event to startup log
	o.logStartupEvent("SYSTEM", "orchestrator", "=== All components started successfully ===")

	// Start periodic health reporting
	go o.periodicHealthReport(ctx)

	return nil
}

// Stop gracefully shuts down all components in reverse order
func (o *Orchestrator) Stop(ctx context.Context) error {
	o.mu.Lock()
	prevState := o.state
	if o.state != StateRunning && o.state != StateError {
		o.mu.Unlock()
		return fmt.Errorf("cannot stop from state %s", o.state)
	}
	o.state = StateStopping
	o.mu.Unlock()

	// Log orchestrator state transition
	o.logStartupEvent("ORCHESTRATOR", "state", fmt.Sprintf("State transition: %s → %s", prevState, StateStopping))

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
			// Log stop event to startup log
			o.logStartupEvent("STOPPED", name, fmt.Sprintf("Component %s stopped", name))
		}
	}

	o.mu.Lock()
	o.state = StateStopped
	o.mu.Unlock()

	// Log final state transition
	o.logStartupEvent("ORCHESTRATOR", "state", fmt.Sprintf("State transition: %s → %s", StateStopping, StateStopped))

	o.logger.Println("Orchestrator stopped")

	// Close the startup log
	o.closeStartupLog()

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
func (o *Orchestrator) State() State {
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

// initStartupLog initializes the startup log file
func (o *Orchestrator) initStartupLog() error {
	// Create logs directory if it doesn't exist
	logsDir := "./logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	// Open startup log file
	startupLogPath := fmt.Sprintf("%s/startup_%s.log", logsDir, time.Now().Format("2006-01-02"))
	logFile, err := os.OpenFile(startupLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open startup log file: %w", err)
	}

	o.startupLog = logFile
	o.startupLogger = log.New(logFile, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	// Write initial startup marker
	o.logStartupEvent("SYSTEM", "orchestrator", "=== Blackhole Network Startup Sequence Started ===")
	o.logger.Printf("Startup log created at: %s", startupLogPath)

	return nil
}

// logStartupEvent writes a startup event to the log file
func (o *Orchestrator) logStartupEvent(eventType, componentName, message string) {
	if o.startupLogger == nil {
		return
	}

	if eventType == "SYSTEM" {
		o.startupLogger.Printf("%s", message)
	} else {
		o.startupLogger.Printf("[%s] %s: %s", eventType, componentName, message)
	}
}

// closeStartupLog closes the startup log file
func (o *Orchestrator) closeStartupLog() {
	if o.startupLog != nil {
		o.logStartupEvent("SYSTEM", "orchestrator", "=== Blackhole Network Shutdown Sequence Started ===")
		o.startupLog.Close()
		o.startupLog = nil
		o.startupLogger = nil
	}
}
