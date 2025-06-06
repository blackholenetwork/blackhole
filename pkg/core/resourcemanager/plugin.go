// Package resourcemanager provides resource allocation, job scheduling, and economic priority management
package resourcemanager

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/common/types"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// ResourceType represents the type of resource
type ResourceType string

const (
	ResourceTypeCPU       ResourceType = "cpu"
	ResourceTypeMemory    ResourceType = "memory"
	ResourceTypeStorage   ResourceType = "storage"
	ResourceTypeBandwidth ResourceType = "bandwidth"
)

// ResourceState represents the current state of a resource
type ResourceState struct {
	Type      ResourceType      `json:"type"`       // cpu, memory, storage, bandwidth
	Total     int64             `json:"total"`      // Total available
	Used      int64             `json:"used"`       // Currently used
	Reserved  int64             `json:"reserved"`   // Reserved for jobs
	Available int64             `json:"available"`  // Available for allocation
	Metadata  map[string]string `json:"metadata"`   // Additional info
}

// JobStatus represents the status of a job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
)

// Job represents a resource allocation request
type Job struct {
	ID           string          `json:"id"`
	UserID       string          `json:"user_id"`
	UserTier     types.UserTier  `json:"user_tier"`
	ResourceType ResourceType    `json:"resource_type"`
	Amount       int64           `json:"amount"`
	Duration     time.Duration   `json:"duration"`
	Priority     int             `json:"priority"`     // Based on user tier
	Status       JobStatus       `json:"status"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    *time.Time      `json:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at"`
}

// Plugin provides resource management capabilities
type Plugin struct {
	*plugin.BasePlugin
	mu            sync.RWMutex
	config        plugin.Config
	resources     map[ResourceType]*ResourceState
	jobs          map[string]*Job
	jobQueue      []*Job        // Priority queue
	ticker        *time.Ticker
	stopChan      chan struct{}
	started       bool
	registry      *plugin.Registry
	healthStatus  plugin.HealthStatus
	healthMessage string
}

// NewPlugin creates a new resource manager plugin
func NewPlugin(registry *plugin.Registry) *Plugin {
	p := &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.Info{
			Name:        "resourcemanager",
			Version:     "1.0.0",
			Description: "Resource allocation, job scheduling, and economic priority management",
			Author:      "Blackhole Network",
			License:     "Apache-2.0",
			Capabilities: []string{
				"resource-allocation",
				"job-scheduling",
				"priority-management",
			},
		}),
		resources:     make(map[ResourceType]*ResourceState),
		jobs:          make(map[string]*Job),
		jobQueue:      make([]*Job, 0),
		stopChan:      make(chan struct{}),
		registry:      registry,
		healthStatus:  plugin.HealthStatusUnknown,
		healthMessage: "Not initialized",
	}

	// Initialize resource states
	p.initializeResources()

	return p
}

// initializeResources sets up initial resource states
func (p *Plugin) initializeResources() {
	p.resources[ResourceTypeCPU] = &ResourceState{
		Type:     ResourceTypeCPU,
		Total:    100, // 100% CPU
		Metadata: make(map[string]string),
	}

	p.resources[ResourceTypeMemory] = &ResourceState{
		Type:     ResourceTypeMemory,
		Total:    8 * 1024 * 1024 * 1024, // 8GB in bytes
		Metadata: make(map[string]string),
	}

	p.resources[ResourceTypeStorage] = &ResourceState{
		Type:     ResourceTypeStorage,
		Total:    100 * 1024 * 1024 * 1024, // 100GB in bytes
		Metadata: make(map[string]string),
	}

	p.resources[ResourceTypeBandwidth] = &ResourceState{
		Type:     ResourceTypeBandwidth,
		Total:    100 * 1024 * 1024, // 100 Mbps in bytes/s
		Metadata: make(map[string]string),
	}

	// Update available resources
	for _, res := range p.resources {
		res.Available = res.Total - res.Used - res.Reserved
	}
}

// Init initializes the resource manager plugin
func (p *Plugin) Init(ctx context.Context, config plugin.Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config
	p.healthStatus = plugin.HealthStatusHealthy
	p.healthMessage = "Resource manager initialized"

	// Configure resources based on system capabilities
	// This would be enhanced to actually detect system resources

	return nil
}

// Start starts the resource manager plugin
func (p *Plugin) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return fmt.Errorf("resource manager already started")
	}

	// Start resource monitoring
	p.ticker = time.NewTicker(5 * time.Second)
	go p.monitorResources(ctx)

	// Start job scheduler
	go p.scheduleJobs(ctx)

	p.started = true
	p.healthStatus = plugin.HealthStatusHealthy
	p.healthMessage = "Resource manager is operational"

	return nil
}

// Stop stops the resource manager plugin
func (p *Plugin) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		return nil
	}

	// Stop monitoring
	if p.ticker != nil {
		p.ticker.Stop()
	}
	close(p.stopChan)

	p.started = false
	p.healthStatus = plugin.HealthStatusUnknown
	p.healthMessage = "Resource manager stopped"

	return nil
}

// Health returns the current health status
func (p *Plugin) Health() plugin.Health {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return plugin.Health{
		Status:    p.healthStatus,
		Message:   p.healthMessage,
		LastCheck: time.Now(),
		Details: map[string]interface{}{
			"resources": p.getResourceSummary(),
			"jobs": map[string]int{
				"pending":   p.countJobsByStatus(JobStatusPending),
				"running":   p.countJobsByStatus(JobStatusRunning),
				"completed": p.countJobsByStatus(JobStatusCompleted),
			},
		},
	}
}

// AllocateResource allocates resources for a job
func (p *Plugin) AllocateResource(job *Job) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if resources are available
	resource, exists := p.resources[job.ResourceType]
	if !exists {
		return fmt.Errorf("unknown resource type: %s", job.ResourceType)
	}

	if resource.Available < job.Amount {
		return fmt.Errorf("insufficient resources: requested %d, available %d", job.Amount, resource.Available)
	}

	// Reserve resources
	resource.Reserved += job.Amount
	resource.Available = resource.Total - resource.Used - resource.Reserved

	// Add job to queue
	job.Status = JobStatusPending
	job.CreatedAt = time.Now()
	job.Priority = p.calculatePriority(job.UserTier)

	p.jobs[job.ID] = job
	p.jobQueue = append(p.jobQueue, job)

	// Sort by priority
	p.sortJobQueue()

	return nil
}

// ReleaseResource releases resources from a completed job
func (p *Plugin) ReleaseResource(jobID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	job, exists := p.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	resource := p.resources[job.ResourceType]

	// Update resource state based on job status
	switch job.Status {
	case JobStatusRunning:
		resource.Used -= job.Amount
	case JobStatusPending:
		resource.Reserved -= job.Amount
	}

	resource.Available = resource.Total - resource.Used - resource.Reserved

	// Mark job as completed
	now := time.Now()
	job.CompletedAt = &now
	job.Status = JobStatusCompleted

	return nil
}

// monitorResources periodically updates resource states
func (p *Plugin) monitorResources(ctx context.Context) {
	for {
		select {
		case <-p.ticker.C:
			p.updateResourceStates()
		case <-p.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// scheduleJobs processes the job queue
func (p *Plugin) scheduleJobs(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.processJobQueue()
		case <-p.stopChan:
			return
		case <-ctx.Done():
			return
		}
	}
}

// processJobQueue processes pending jobs based on priority
func (p *Plugin) processJobQueue() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, job := range p.jobQueue {
		if job.Status != JobStatusPending {
			continue
		}

		resource := p.resources[job.ResourceType]

		// Check if we can start this job
		if resource.Reserved >= job.Amount {
			// Move from reserved to used
			resource.Reserved -= job.Amount
			resource.Used += job.Amount
			resource.Available = resource.Total - resource.Used - resource.Reserved

			// Update job status
			now := time.Now()
			job.StartedAt = &now
			job.Status = JobStatusRunning

			// Remove from queue
			p.jobQueue = append(p.jobQueue[:i], p.jobQueue[i+1:]...)

			// Notify about job start
			if p.registry != nil {
				p.registry.Publish(plugin.Event{
					Type:      "job.started",
					Source:    "resourcemanager",
					Data:      job,
					Timestamp: time.Now(),
				})
			}
		}
	}
}

// updateResourceStates updates current resource usage
func (p *Plugin) updateResourceStates() {
	// In a real implementation, this would query actual system resources
	// For now, we'll just ensure consistency
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, resource := range p.resources {
		resource.Available = resource.Total - resource.Used - resource.Reserved
	}
}

// calculatePriority calculates job priority based on user tier
func (p *Plugin) calculatePriority(tier types.UserTier) int {
	switch tier {
	case types.TierUltimate:
		return 100
	case types.TierAdvance:
		return 75
	case types.TierNormal:
		return 50
	case types.TierFree:
		return 25
	default:
		return 0
	}
}

// sortJobQueue sorts jobs by priority (higher priority first)
func (p *Plugin) sortJobQueue() {
	sort.Slice(p.jobQueue, func(i, j int) bool {
		return p.jobQueue[i].Priority > p.jobQueue[j].Priority
	})
}

// getResourceSummary returns a summary of resource states
func (p *Plugin) getResourceSummary() map[string]interface{} {
	summary := make(map[string]interface{})

	for _, resource := range p.resources {
		summary[string(resource.Type)] = map[string]interface{}{
			"total":     resource.Total,
			"used":      resource.Used,
			"reserved":  resource.Reserved,
			"available": resource.Available,
		}
	}

	return summary
}

// countJobsByStatus counts jobs with a specific status
func (p *Plugin) countJobsByStatus(status JobStatus) int {
	count := 0
	for _, job := range p.jobs {
		if job.Status == status {
			count++
		}
	}
	return count
}

// GetResourceState returns the current state of a resource
func (p *Plugin) GetResourceState(resourceType ResourceType) (*ResourceState, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	resource, exists := p.resources[resourceType]
	if !exists {
		return nil, fmt.Errorf("unknown resource type: %s", resourceType)
	}

	// Return a copy to prevent external modification
	return &ResourceState{
		Type:      resource.Type,
		Total:     resource.Total,
		Used:      resource.Used,
		Reserved:  resource.Reserved,
		Available: resource.Available,
		Metadata:  resource.Metadata,
	}, nil
}

// GetJob returns information about a specific job
func (p *Plugin) GetJob(jobID string) (*Job, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	job, exists := p.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}

	// Return a copy
	jobCopy := *job
	return &jobCopy, nil
}
