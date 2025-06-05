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

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// Type represents the type of plugin
type Type string

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

const (
	// Core capabilities
	CapabilityOrchestration Capability = "orchestration"
	CapabilitySecurity      Capability = "security"
	CapabilityNetworking    Capability = "networking"
	CapabilityMonitoring    Capability = "monitoring"
	
	// Resource capabilities
	CapabilityStorage   Capability = "storage"
	CapabilityCompute   Capability = "compute"
	CapabilityBandwidth Capability = "bandwidth"
	CapabilityMemory    Capability = "memory"
	
	// Data capabilities
	CapabilitySchema   Capability = "schema"
	CapabilityIndexing Capability = "indexing"
	CapabilityQuery    Capability = "query"
	CapabilitySearch   Capability = "search"
	
	// Service capabilities
	CapabilityAPI      Capability = "api"
	CapabilityRealtime Capability = "realtime"
	CapabilitySocial   Capability = "social"
	
	// Economic capabilities
	CapabilityIncentive Capability = "incentive"
	CapabilityContract  Capability = "contract"
	
	// Other capabilities
	CapabilityCustom    Capability = "custom"
)

// Hook represents a plugin hook point
type Hook string

const (
	// Lifecycle hooks
	HookPreInit     Hook = "pre_init"
	HookPostInit    Hook = "post_init"
	HookPreStart    Hook = "pre_start"
	HookPostStart   Hook = "post_start"
	HookPreStop     Hook = "pre_stop"
	HookPostStop    Hook = "post_stop"
	
	// Operation hooks
	HookPreRequest  Hook = "pre_request"
	HookPostRequest Hook = "post_request"
	HookPreStore    Hook = "pre_store"
	HookPostStore   Hook = "post_store"
	HookPreCompute  Hook = "pre_compute"
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
	Path        string   `json:"path"`
	Method      string   `json:"method"`
	Description string   `json:"description"`
	Parameters  []Parameter `json:"parameters,omitempty"`
}

// Parameter represents an endpoint parameter
type Parameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// Request represents a service request
type Request struct {
	Method   string                 `json:"method"`
	Path     string                 `json:"path"`
	Headers  map[string]string      `json:"headers"`
	Body     []byte                 `json:"body"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Response represents a service response
type Response struct {
	Status   int                    `json:"status"`
	Headers  map[string]string      `json:"headers"`
	Body     []byte                 `json:"body"`
	Metadata map[string]interface{} `json:"metadata"`
}