package resourcemanager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blackholenetwork/blackhole/pkg/common/types"
	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

func TestNewPlugin(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	assert.NotNil(t, p)
	assert.NotNil(t, p.BasePlugin)
	assert.NotNil(t, p.resources)
	assert.NotNil(t, p.jobs)
	assert.NotNil(t, p.jobQueue)
	assert.NotNil(t, p.stopChan)
	assert.Equal(t, registry, p.registry)
	assert.Equal(t, plugin.HealthStatusUnknown, p.healthStatus)
	assert.Equal(t, "Not initialized", p.healthMessage)

	// Verify initial resources
	assert.Len(t, p.resources, 4)
	assert.Contains(t, p.resources, ResourceTypeCPU)
	assert.Contains(t, p.resources, ResourceTypeMemory)
	assert.Contains(t, p.resources, ResourceTypeStorage)
	assert.Contains(t, p.resources, ResourceTypeBandwidth)
}

func TestPlugin_Init(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	config := plugin.Config{
		"test": "value",
	}

	err := p.Init(ctx, config)
	assert.NoError(t, err)
	assert.Equal(t, plugin.HealthStatusHealthy, p.healthStatus)
	assert.Equal(t, "Resource manager initialized", p.healthMessage)
}

func TestPlugin_StartStop(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	config := plugin.Config{}

	// Initialize first
	err := p.Init(ctx, config)
	require.NoError(t, err)

	// Start the plugin
	err = p.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, p.started)
	assert.Equal(t, plugin.HealthStatusHealthy, p.healthStatus)
	assert.Equal(t, "Resource manager is operational", p.healthMessage)

	// Try to start again (should fail)
	err = p.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")

	// Stop the plugin
	err = p.Stop(ctx)
	assert.NoError(t, err)
	assert.False(t, p.started)
	assert.Equal(t, plugin.HealthStatusUnknown, p.healthStatus)
	assert.Equal(t, "Resource manager stopped", p.healthMessage)

	// Stop again (should be idempotent)
	err = p.Stop(ctx)
	assert.NoError(t, err)
}

func TestPlugin_Health(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	config := plugin.Config{}

	// Before initialization
	health := p.Health()
	assert.Equal(t, plugin.HealthStatusUnknown, health.Status)
	assert.Equal(t, "Not initialized", health.Message)
	assert.NotZero(t, health.LastCheck)

	// After initialization
	err := p.Init(ctx, config)
	require.NoError(t, err)

	health = p.Health()
	assert.Equal(t, plugin.HealthStatusHealthy, health.Status)
	assert.Equal(t, "Resource manager initialized", health.Message)
	assert.NotZero(t, health.LastCheck)
	assert.NotNil(t, health.Details)

	// After start
	err = p.Start(ctx)
	require.NoError(t, err)

	health = p.Health()
	assert.Equal(t, plugin.HealthStatusHealthy, health.Status)
	assert.Equal(t, "Resource manager is operational", health.Message)
	assert.NotZero(t, health.LastCheck)
	assert.NotNil(t, health.Details)

	// Check details
	details := health.Details
	assert.Contains(t, details, "resources")
	assert.Contains(t, details, "jobs")

	resources := details["resources"].(map[string]interface{})
	assert.Contains(t, resources, "cpu")
	assert.Contains(t, resources, "memory")
	assert.Contains(t, resources, "storage")
	assert.Contains(t, resources, "bandwidth")

	jobs := details["jobs"].(map[string]int)
	assert.Contains(t, jobs, "pending")
	assert.Contains(t, jobs, "running")
	assert.Contains(t, jobs, "completed")
}

func TestPlugin_AllocateResource(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	err := p.Init(ctx, plugin.Config{})
	require.NoError(t, err)

	err = p.Start(ctx)
	require.NoError(t, err)

	// Create a job
	job := &Job{
		ID:           "test-job-1",
		UserID:       "user-1",
		UserTier:     types.TierNormal,
		ResourceType: ResourceTypeCPU,
		Amount:       50,
		Duration:     time.Hour,
	}

	// Allocate resources
	err = p.AllocateResource(job)
	assert.NoError(t, err)
	assert.Equal(t, JobStatusPending, job.Status)
	assert.Equal(t, 50, job.Priority)
	assert.NotZero(t, job.CreatedAt)

	// Check resource state
	resource := p.resources[ResourceTypeCPU]
	assert.Equal(t, int64(50), resource.Reserved)
	assert.Equal(t, int64(50), resource.Available) // 100 total - 50 reserved

	// Check job is in queue
	assert.Len(t, p.jobQueue, 1)
	assert.Equal(t, job.ID, p.jobQueue[0].ID)

	// Try to allocate more than available
	job2 := &Job{
		ID:           "test-job-2",
		UserID:       "user-2",
		UserTier:     types.TierFree,
		ResourceType: ResourceTypeCPU,
		Amount:       60, // More than available
		Duration:     time.Hour,
	}

	err = p.AllocateResource(job2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient resources")

	// Try unknown resource type
	job3 := &Job{
		ID:           "test-job-3",
		UserID:       "user-3",
		UserTier:     types.TierAdvance,
		ResourceType: "unknown",
		Amount:       10,
		Duration:     time.Hour,
	}

	err = p.AllocateResource(job3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown resource type")
}

func TestPlugin_ReleaseResource(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	err := p.Init(ctx, plugin.Config{})
	require.NoError(t, err)

	err = p.Start(ctx)
	require.NoError(t, err)

	// Create and allocate a job
	job := &Job{
		ID:           "test-job-1",
		UserID:       "user-1",
		UserTier:     types.TierNormal,
		ResourceType: ResourceTypeCPU,
		Amount:       50,
		Duration:     time.Hour,
	}

	err = p.AllocateResource(job)
	require.NoError(t, err)

	// Manually set job to running state
	p.mu.Lock()
	job.Status = JobStatusRunning
	now := time.Now()
	job.StartedAt = &now
	resource := p.resources[ResourceTypeCPU]
	resource.Reserved -= job.Amount
	resource.Used += job.Amount
	resource.Available = resource.Total - resource.Used - resource.Reserved
	p.mu.Unlock()

	// Release the resource
	err = p.ReleaseResource(job.ID)
	assert.NoError(t, err)

	// Check resource state
	resource = p.resources[ResourceTypeCPU]
	assert.Equal(t, int64(0), resource.Used)
	assert.Equal(t, int64(0), resource.Reserved)
	assert.Equal(t, int64(100), resource.Available)

	// Check job state
	assert.Equal(t, JobStatusCompleted, job.Status)
	assert.NotNil(t, job.CompletedAt)

	// Try to release non-existent job
	err = p.ReleaseResource("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "job not found")
}

func TestPlugin_CalculatePriority(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	tests := []struct {
		tier     types.UserTier
		expected int
	}{
		{types.TierUltimate, 100},
		{types.TierAdvance, 75},
		{types.TierNormal, 50},
		{types.TierFree, 25},
		{types.UserTier(999), 0}, // Unknown tier
	}

	for _, tc := range tests {
		t.Run(tc.tier.String(), func(t *testing.T) {
			priority := p.calculatePriority(tc.tier)
			assert.Equal(t, tc.expected, priority)
		})
	}
}

func TestPlugin_GetResourceState(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	err := p.Init(ctx, plugin.Config{})
	require.NoError(t, err)

	// Get CPU resource state
	state, err := p.GetResourceState(ResourceTypeCPU)
	assert.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, ResourceTypeCPU, state.Type)
	assert.Equal(t, int64(100), state.Total)
	assert.Equal(t, int64(0), state.Used)
	assert.Equal(t, int64(0), state.Reserved)
	assert.Equal(t, int64(100), state.Available)

	// Get unknown resource
	state, err = p.GetResourceState("unknown")
	assert.Error(t, err)
	assert.Nil(t, state)
	assert.Contains(t, err.Error(), "unknown resource type")
}

func TestPlugin_GetJob(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	ctx := context.Background()
	err := p.Init(ctx, plugin.Config{})
	require.NoError(t, err)

	// Create and allocate a job
	job := &Job{
		ID:           "test-job-1",
		UserID:       "user-1",
		UserTier:     types.TierNormal,
		ResourceType: ResourceTypeCPU,
		Amount:       50,
		Duration:     time.Hour,
	}

	err = p.AllocateResource(job)
	require.NoError(t, err)

	// Get the job
	retrievedJob, err := p.GetJob(job.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedJob)
	assert.Equal(t, job.ID, retrievedJob.ID)
	assert.Equal(t, job.UserID, retrievedJob.UserID)
	assert.Equal(t, job.UserTier, retrievedJob.UserTier)
	assert.Equal(t, job.ResourceType, retrievedJob.ResourceType)
	assert.Equal(t, job.Amount, retrievedJob.Amount)

	// Get non-existent job
	retrievedJob, err = p.GetJob("non-existent")
	assert.Error(t, err)
	assert.Nil(t, retrievedJob)
	assert.Contains(t, err.Error(), "job not found")
}

func TestPlugin_SortJobQueue(t *testing.T) {
	registry := plugin.NewRegistry()
	p := NewPlugin(registry)

	// Create jobs with different priorities
	jobs := []*Job{
		{ID: "1", Priority: 25},  // Free
		{ID: "2", Priority: 100}, // Ultimate
		{ID: "3", Priority: 50},  // Normal
		{ID: "4", Priority: 75},  // Advance
	}

	p.jobQueue = jobs
	p.sortJobQueue()

	// Check order (highest priority first)
	assert.Equal(t, "2", p.jobQueue[0].ID) // Ultimate (100)
	assert.Equal(t, "4", p.jobQueue[1].ID) // Advance (75)
	assert.Equal(t, "3", p.jobQueue[2].ID) // Normal (50)
	assert.Equal(t, "1", p.jobQueue[3].ID) // Free (25)
}
