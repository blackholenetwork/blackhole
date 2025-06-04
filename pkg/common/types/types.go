package types

import (
	"encoding/hex"
	"fmt"
	"time"
)

// NodeID represents a unique node identifier
type NodeID string

// FileID represents a unique file identifier (CID)
type FileID string

// ChunkID represents a unique chunk identifier
type ChunkID string

// UserID represents a unique user identifier
type UserID string

// JobID represents a unique job identifier
type JobID string

// UserTier represents the economic tier of a user
type UserTier int

const (
	TierFree UserTier = iota
	TierNormal
	TierAdvance
	TierUltimate
)

// String returns the string representation of a user tier
func (t UserTier) String() string {
	switch t {
	case TierFree:
		return "free"
	case TierNormal:
		return "normal"
	case TierAdvance:
		return "advance"
	case TierUltimate:
		return "ultimate"
	default:
		return "unknown"
	}
}

// Priority returns the priority value for the tier
func (t UserTier) Priority() int {
	return int(t)
}

// ResourceType represents the type of resource
type ResourceType string

const (
	ResourceTypeStorage   ResourceType = "storage"
	ResourceTypeCompute   ResourceType = "compute"
	ResourceTypeBandwidth ResourceType = "bandwidth"
	ResourceTypeMemory    ResourceType = "memory"
)

// JobType represents the type of job
type JobType string

const (
	JobTypeCompute   JobType = "compute"
	JobTypeTranscode JobType = "transcode"
	JobTypeIndex     JobType = "index"
	JobTypeSearch    JobType = "search"
)

// Status represents a generic status
type Status string

const (
	StatusPending    Status = "pending"
	StatusInProgress Status = "in_progress"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusCancelled  Status = "cancelled"
)

// ByteSize represents a size in bytes with formatting support
type ByteSize int64

const (
	B  ByteSize = 1
	KB ByteSize = 1024
	MB ByteSize = 1024 * KB
	GB ByteSize = 1024 * MB
	TB ByteSize = 1024 * GB
)

// String returns a human-readable representation of the byte size
func (b ByteSize) String() string {
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// Hash represents a cryptographic hash
type Hash []byte

// String returns the hex representation of the hash
func (h Hash) String() string {
	return hex.EncodeToString(h)
}

// IsZero checks if the hash is empty
func (h Hash) IsZero() bool {
	return len(h) == 0
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Duration returns the duration of the time range
func (tr TimeRange) Duration() time.Duration {
	return tr.End.Sub(tr.Start)
}

// Contains checks if a time is within the range
func (tr TimeRange) Contains(t time.Time) bool {
	return !t.Before(tr.Start) && !t.After(tr.End)
}

// Overlaps checks if two time ranges overlap
func (tr TimeRange) Overlaps(other TimeRange) bool {
	return tr.Start.Before(other.End) && other.Start.Before(tr.End)
}

// Metadata represents generic metadata
type Metadata map[string]interface{}

// Get retrieves a value from metadata
func (m Metadata) Get(key string) (interface{}, bool) {
	val, ok := m[key]
	return val, ok
}

// GetString retrieves a string value from metadata
func (m Metadata) GetString(key string) (string, bool) {
	val, ok := m[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetInt retrieves an int value from metadata
func (m Metadata) GetInt(key string) (int, bool) {
	val, ok := m[key]
	if !ok {
		return 0, false
	}
	
	// Handle different numeric types
	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// Set sets a value in metadata
func (m Metadata) Set(key string, value interface{}) {
	m[key] = value
}

// Delete removes a key from metadata
func (m Metadata) Delete(key string) {
	delete(m, key)
}

// Clone creates a deep copy of metadata
func (m Metadata) Clone() Metadata {
	clone := make(Metadata, len(m))
	for k, v := range m {
		clone[k] = v
	}
	return clone
}

// Pagination represents pagination parameters
type Pagination struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

// TotalPages returns the total number of pages
func (p Pagination) TotalPages() int {
	if p.PerPage == 0 {
		return 0
	}
	return (p.Total + p.PerPage - 1) / p.PerPage
}

// Offset returns the offset for database queries
func (p Pagination) Offset() int {
	if p.Page <= 0 {
		return 0
	}
	return (p.Page - 1) * p.PerPage
}

// HasNext returns true if there are more pages
func (p Pagination) HasNext() bool {
	return p.Page < p.TotalPages()
}

// HasPrev returns true if there are previous pages
func (p Pagination) HasPrev() bool {
	return p.Page > 1
}