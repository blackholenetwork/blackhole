package plugin

import (
	"context"
	"time"
)

// Plugin represents the base interface that all plugins must implement
type Plugin interface {
	// Info returns metadata about the plugin
	Info() Info

	// Init initializes the plugin with configuration
	Init(ctx context.Context, config Config) error

	// Start starts the plugin
	Start(ctx context.Context) error

	// Stop gracefully shuts down the plugin
	Stop(ctx context.Context) error

	// Health returns the current health status
	Health() Health

	// SetHealth sets the current health status
	SetHealth(status HealthStatus, message string)
}

// Info contains plugin metadata
type Info struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Description  string    `json:"description"`
	Author       string    `json:"author"`
	License      string    `json:"license"`
	Dependencies []string  `json:"dependencies"`
	Capabilities []string  `json:"capabilities"`
	CreatedAt    time.Time `json:"created_at"`
}

// Config represents plugin-specific configuration
type Config map[string]interface{}

// Health represents the health status of a plugin
type Health struct {
	Status    HealthStatus           `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	LastCheck time.Time              `json:"last_check"`
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

// PluginState represents the lifecycle state of a plugin
type PluginState string

// Plugin state constants
const (
	StateInitialized PluginState = "initialized"
	StateStarting    PluginState = "starting"
	StateRunning     PluginState = "running"
	StateStopping    PluginState = "stopping"
	StateStopped     PluginState = "stopped"
	StateError       PluginState = "error"
)

// Type represents the type of plugin
type Type string

// Plugin type constants
const (
	TypeCore      Type = "core"
	TypeResource  Type = "resource"
	TypeData      Type = "data"
	TypeService   Type = "service"
	TypeEconomic  Type = "economic"
	TypeExtension Type = "extension"
)

// Capability represents what a plugin can do
type Capability string

// Plugin capability constants
const (
	// CapabilityOrchestration enables orchestration of other plugins
	CapabilityOrchestration Capability = "orchestration"
	// CapabilitySecurity enables security features
	CapabilitySecurity Capability = "security"
	// CapabilityNetworking enables P2P networking
	CapabilityNetworking Capability = "networking"
	// CapabilityMonitoring enables system monitoring
	CapabilityMonitoring Capability = "monitoring"
	// CapabilityResourceManagement enables resource allocation and job scheduling
	CapabilityResourceManagement Capability = "resource-management"

	// CapabilityStorage enables storage management
	CapabilityStorage Capability = "storage"
	// CapabilityCompute enables compute resource management
	CapabilityCompute Capability = "compute"
	// CapabilityBandwidth enables bandwidth management
	CapabilityBandwidth Capability = "bandwidth"
	// CapabilityMemory enables memory management
	CapabilityMemory Capability = "memory"

	// CapabilitySchema enables data schema management
	CapabilitySchema Capability = "schema"
	// CapabilityIndexing enables data indexing
	CapabilityIndexing Capability = "indexing"
	// CapabilityQuery enables data queries
	CapabilityQuery Capability = "query"
	// CapabilitySearch enables search functionality
	CapabilitySearch Capability = "search"

	// CapabilityAPI enables API services
	CapabilityAPI Capability = "api"
	// CapabilityRealtime enables real-time communication
	CapabilityRealtime Capability = "realtime"
	// CapabilitySocial enables social features
	CapabilitySocial Capability = "social"

	// CapabilityIncentive enables incentive mechanisms
	CapabilityIncentive Capability = "incentive"
	// CapabilityContract enables smart contracts
	CapabilityContract Capability = "contract"

	// CapabilityCustom enables custom plugin capabilities
	CapabilityCustom Capability = "custom"
)

// Hook represents a plugin hook point
type Hook string

// Hook constants
const (
	// HookPreInit is called before plugin initialization
	HookPreInit Hook = "pre_init"
	// HookPostInit is called after plugin initialization
	HookPostInit Hook = "post_init"
	// HookPreStart is called before plugin start
	HookPreStart Hook = "pre_start"
	// HookPostStart is called after plugin start
	HookPostStart Hook = "post_start"
	// HookPreStop is called before plugin stop
	HookPreStop Hook = "pre_stop"
	// HookPostStop is called after plugin stop
	HookPostStop Hook = "post_stop"

	// HookPreRequest is called before handling a request
	HookPreRequest Hook = "pre_request"
	// HookPostRequest is called after handling a request
	HookPostRequest Hook = "post_request"
	// HookPreStore is called before storing data
	HookPreStore Hook = "pre_store"
	// HookPostStore is called after storing data
	HookPostStore Hook = "post_store"
	// HookPreCompute is called before compute operations
	HookPreCompute Hook = "pre_compute"
	// HookPostCompute is called after compute operations
	HookPostCompute Hook = "post_compute"
)

// HookFunc is a function that can be registered for a hook
type HookFunc func(ctx context.Context, data interface{}) error

// Hookable allows plugins to register and trigger hooks
type Hookable interface {
	// RegisterHook registers a function for a specific hook
	RegisterHook(hook Hook, fn HookFunc)

	// TriggerHook executes all functions registered for a hook
	TriggerHook(ctx context.Context, hook Hook, data interface{}) error
}

// Observable allows plugins to publish and subscribe to events
type Observable interface {
	// Publish publishes an event
	Publish(event Event)

	// Subscribe subscribes to events of a specific type
	Subscribe(eventType string, handler EventHandler) (unsubscribe func())
}

// Event represents an event that can be published
type Event struct {
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// EventHandler handles events
type EventHandler func(event Event)

// Configurable allows plugins to be reconfigured at runtime
type Configurable interface {
	// Configure updates the plugin configuration
	Configure(ctx context.Context, config Config) error

	// GetConfig returns the current configuration
	GetConfig() Config
}

// Metrics allows plugins to expose metrics
type Metrics interface {
	// GetMetrics returns current metrics
	GetMetrics() map[string]interface{}
}

// Diagnostics allows plugins to provide diagnostic information
type Diagnostics interface {
	// GetDiagnostics returns diagnostic information
	GetDiagnostics() map[string]interface{}
}

// ResourceProvider is implemented by resource plugins
type ResourceProvider interface {
	Plugin

	// GetResourceType returns the type of resource provided
	GetResourceType() string

	// GetCapacity returns the current capacity
	GetCapacity() (total, used, available int64)

	// Allocate allocates resources
	Allocate(ctx context.Context, amount int64) (AllocationID, error)

	// Release releases allocated resources
	Release(ctx context.Context, id AllocationID) error
}

// AllocationID represents a resource allocation
type AllocationID string

// ServiceProvider is implemented by service plugins
type ServiceProvider interface {
	Plugin

	// GetEndpoints returns the service endpoints
	GetEndpoints() []Endpoint

	// HandleRequest handles a service request
	HandleRequest(ctx context.Context, req Request) (Response, error)
}

// Endpoint represents a service endpoint
type Endpoint struct {
	Path        string      `json:"path"`
	Method      string      `json:"method"`
	Description string      `json:"description"`
	Parameters  []Parameter `json:"parameters,omitempty"`
}

// Parameter represents an endpoint parameter
type Parameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// ServiceRequest represents a service request
type ServiceRequest struct {
	Method   string                 `json:"method"`
	Path     string                 `json:"path"`
	Headers  map[string]string      `json:"headers"`
	Body     []byte                 `json:"body"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ServiceResponse represents a service response
type ServiceResponse struct {
	Status   int                    `json:"status"`
	Headers  map[string]string      `json:"headers"`
	Body     []byte                 `json:"body"`
	Metadata map[string]interface{} `json:"metadata"`
}
