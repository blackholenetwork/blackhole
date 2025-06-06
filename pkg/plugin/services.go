package plugin

import (
	"context"
	"errors"
	"time"
)

// Standard service interfaces that plugins can implement

// StorageService provides storage capabilities
type StorageService interface {
	// Store saves data and returns a unique identifier
	Store(ctx context.Context, data []byte, metadata map[string]string) (string, error)

	// Retrieve gets data by its identifier
	Retrieve(ctx context.Context, id string) ([]byte, error)

	// Delete removes data by its identifier
	Delete(ctx context.Context, id string) error

	// List returns all stored identifiers with optional prefix filter
	List(ctx context.Context, prefix string) ([]string, error)

	// GetMetadata returns metadata for a stored item
	GetMetadata(ctx context.Context, id string) (map[string]string, error)
}

// NetworkService provides networking capabilities
type NetworkService interface {
	// Send sends data to a specific peer
	Send(ctx context.Context, peerID string, data []byte) error

	// Broadcast sends data to all connected peers
	Broadcast(ctx context.Context, data []byte) error

	// GetPeers returns list of connected peers
	GetPeers(ctx context.Context) ([]string, error)

	// GetLatency returns latency to a specific peer
	GetLatency(ctx context.Context, peerID string) (time.Duration, error)

	// Subscribe to messages from peers
	Subscribe(ctx context.Context, handler func(peerID string, data []byte)) error
}

// ComputeService provides computation capabilities
type ComputeService interface {
	// SubmitJob submits a computation job
	SubmitJob(ctx context.Context, job ComputeJob) (string, error)

	// GetJobStatus returns the status of a job
	GetJobStatus(ctx context.Context, jobID string) (JobStatus, error)

	// GetJobResult retrieves the result of a completed job
	GetJobResult(ctx context.Context, jobID string) (interface{}, error)

	// CancelJob cancels a running job
	CancelJob(ctx context.Context, jobID string) error

	// GetCapacity returns available compute capacity
	GetCapacity(ctx context.Context) (ComputeCapacity, error)
}

// QueryService provides data query capabilities
type QueryService interface {
	// Execute runs a query and returns results
	Execute(ctx context.Context, query Query) (QueryResult, error)

	// Prepare prepares a query for repeated execution
	Prepare(ctx context.Context, query Query) (PreparedQuery, error)

	// GetSchema returns the current data schema
	GetSchema(ctx context.Context) (Schema, error)
}

// IndexingService provides search and indexing capabilities
type IndexingService interface {
	// Index adds a document to the search index
	Index(ctx context.Context, doc Document) error

	// Search performs a search query
	Search(ctx context.Context, query string, options SearchOptions) (SearchResults, error)

	// Delete removes a document from the index
	Delete(ctx context.Context, docID string) error

	// GetStats returns indexing statistics
	GetStats(ctx context.Context) (IndexStats, error)
}

// EconomicService provides economic/incentive capabilities
type EconomicService interface {
	// GetBalance returns the current credit balance
	GetBalance(ctx context.Context, accountID string) (int64, error)

	// Transfer transfers credits between accounts
	Transfer(ctx context.Context, from, to string, amount int64, reason string) error

	// RecordUsage records resource usage for billing
	RecordUsage(ctx context.Context, accountID string, resource string, amount int64) error

	// GetQuota returns the quota for a resource
	GetQuota(ctx context.Context, accountID string, resource string) (Quota, error)
}

// Service discovery helper functions

// GetStorageService finds and returns a storage service
func GetStorageService(registry *Registry) (StorageService, error) {
	plugins := registry.GetByCapability(CapabilityStorage)
	if len(plugins) == 0 {
		return nil, errors.New("no storage service available")
	}

	// Type assertion needed: GetByCapability returns []Plugin
	service, ok := plugins[0].(StorageService)
	if !ok {
		return nil, errors.New("storage plugin does not implement StorageService")
	}

	return service, nil
}

// GetNetworkService finds and returns a network service
func GetNetworkService(registry *Registry) (NetworkService, error) {
	plugins := registry.GetByCapability(CapabilityNetworking)
	if len(plugins) == 0 {
		return nil, errors.New("no network service available")
	}

	service, ok := plugins[0].(NetworkService)
	if !ok {
		return nil, errors.New("network plugin does not implement NetworkService")
	}

	return service, nil
}

// GetComputeService finds and returns a compute service
func GetComputeService(registry *Registry) (ComputeService, error) {
	plugins := registry.GetByCapability(CapabilityCompute)
	if len(plugins) == 0 {
		return nil, errors.New("no compute service available")
	}

	service, ok := plugins[0].(ComputeService)
	if !ok {
		return nil, errors.New("compute plugin does not implement ComputeService")
	}

	return service, nil
}

// Supporting types for services

// ComputeJob represents a computation job
type ComputeJob struct {
	Type      string               `json:"type"`
	Priority  int                  `json:"priority"`
	Data      interface{}          `json:"data"`
	Resources ResourceRequirements `json:"resources"`
	Timeout   time.Duration        `json:"timeout"`
}

// JobStatus represents the status of a compute job
type JobStatus struct {
	State     string    `json:"state"`
	Progress  float64   `json:"progress"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// ComputeCapacity represents available compute resources
type ComputeCapacity struct {
	CPUCores     int     `json:"cpu_cores"`
	CPUAvailable float64 `json:"cpu_available"`
	MemoryTotal  int64   `json:"memory_total"`
	MemoryFree   int64   `json:"memory_free"`
	GPUAvailable bool    `json:"gpu_available"`
	GPUMemory    int64   `json:"gpu_memory,omitempty"`
}

// Query represents a data query
type Query struct {
	Type       string                 `json:"type"`
	Statement  string                 `json:"statement"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
}

// QueryResult represents query results
type QueryResult struct {
	Columns  []string               `json:"columns"`
	Rows     [][]interface{}        `json:"rows"`
	RowCount int                    `json:"row_count"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// PreparedQuery represents a prepared query
type PreparedQuery interface {
	Execute(ctx context.Context, params map[string]interface{}) (QueryResult, error)
	Close() error
}

// Schema represents a data schema
type Schema struct {
	Version   string                 `json:"version"`
	Tables    map[string]TableSchema `json:"tables"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// TableSchema represents a table schema
type TableSchema struct {
	Name    string         `json:"name"`
	Columns []ColumnSchema `json:"columns"`
	Indexes []string       `json:"indexes"`
}

// ColumnSchema represents a column schema
type ColumnSchema struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`
}

// Document represents a searchable document
type Document struct {
	ID        string                 `json:"id"`
	Title     string                 `json:"title"`
	Content   string                 `json:"content"`
	Tags      []string               `json:"tags,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// SearchOptions configures a search query
type SearchOptions struct {
	Limit     int                    `json:"limit"`
	Offset    int                    `json:"offset"`
	SortBy    string                 `json:"sort_by,omitempty"`
	SortOrder string                 `json:"sort_order,omitempty"`
	Filters   map[string]interface{} `json:"filters,omitempty"`
	Facets    []string               `json:"facets,omitempty"`
}

// SearchResults contains search results
type SearchResults struct {
	Hits      []SearchHit             `json:"hits"`
	TotalHits int                     `json:"total_hits"`
	Facets    map[string][]FacetValue `json:"facets,omitempty"`
	QueryTime time.Duration           `json:"query_time"`
}

// SearchHit represents a single search result
type SearchHit struct {
	ID         string              `json:"id"`
	Score      float64             `json:"score"`
	Document   Document            `json:"document"`
	Highlights map[string][]string `json:"highlights,omitempty"`
}

// FacetValue represents a facet value
type FacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// IndexStats represents indexing statistics
type IndexStats struct {
	DocumentCount int64     `json:"document_count"`
	IndexSize     int64     `json:"index_size"`
	LastIndexed   time.Time `json:"last_indexed"`
	IndexingRate  float64   `json:"indexing_rate"`
}

// Quota represents a resource quota
type Quota struct {
	Resource string    `json:"resource"`
	Limit    int64     `json:"limit"`
	Used     int64     `json:"used"`
	Period   string    `json:"period"`
	ResetAt  time.Time `json:"reset_at"`
}

// ResourceRequirements specifies required resources
type ResourceRequirements struct {
	CPUCores  int   `json:"cpu_cores"`
	Memory    int64 `json:"memory"`
	GPUMemory int64 `json:"gpu_memory,omitempty"`
	Storage   int64 `json:"storage,omitempty"`
	Bandwidth int64 `json:"bandwidth,omitempty"`
}
