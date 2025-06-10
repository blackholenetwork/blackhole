# U24: Job Submission API

## Overview
Ray.io-inspired job submission API that enables users to submit compute jobs to the BlackHole marketplace with resource requirements, queue management, and status tracking.

## Implementation

### Core Types

```go
package compute

import (
    "context"
    "encoding/json"
    "fmt"
    "sync"
    "time"
    
    "github.com/google/uuid"
    "github.com/prometheus/client_golang/prometheus"
)

// JobStatus represents the current state of a job
type JobStatus string

const (
    JobStatusPending   JobStatus = "pending"
    JobStatusQueued    JobStatus = "queued"
    JobStatusRunning   JobStatus = "running"
    JobStatusCompleted JobStatus = "completed"
    JobStatusFailed    JobStatus = "failed"
    JobStatusCancelled JobStatus = "cancelled"
)

// ResourceRequirements specifies compute resources needed
type ResourceRequirements struct {
    CPUCores    float64           `json:"cpu_cores"`
    MemoryMB    uint64            `json:"memory_mb"`
    StorageMB   uint64            `json:"storage_mb"`
    GPUCount    int               `json:"gpu_count,omitempty"`
    GPUType     string            `json:"gpu_type,omitempty"`
    Duration    time.Duration     `json:"duration"`
    Labels      map[string]string `json:"labels,omitempty"`
}

// JobSpec defines a compute job
type JobSpec struct {
    ID           string                `json:"id"`
    Name         string                `json:"name"`
    Owner        string                `json:"owner"`
    WASMModule   []byte                `json:"wasm_module"`
    EntryPoint   string                `json:"entry_point"`
    Arguments    []string              `json:"arguments"`
    Environment  map[string]string     `json:"environment"`
    Requirements ResourceRequirements  `json:"requirements"`
    Priority     int                   `json:"priority"`
    MaxRetries   int                   `json:"max_retries"`
    Timeout      time.Duration         `json:"timeout"`
    CreatedAt    time.Time             `json:"created_at"`
    UpdatedAt    time.Time             `json:"updated_at"`
}

// JobResult contains execution results
type JobResult struct {
    JobID      string            `json:"job_id"`
    Status     JobStatus         `json:"status"`
    Output     []byte            `json:"output,omitempty"`
    Error      string            `json:"error,omitempty"`
    ExitCode   int               `json:"exit_code"`
    StartedAt  *time.Time        `json:"started_at,omitempty"`
    FinishedAt *time.Time        `json:"finished_at,omitempty"`
    WorkerID   string            `json:"worker_id,omitempty"`
    Metrics    map[string]float64 `json:"metrics,omitempty"`
}

// JobQueue manages job submission and scheduling
type JobQueue struct {
    mu              sync.RWMutex
    jobs            map[string]*JobSpec
    results         map[string]*JobResult
    queues          map[int][]*JobSpec // Priority queues
    statusIndex     map[JobStatus]map[string]*JobSpec
    ownerIndex      map[string]map[string]*JobSpec
    
    // Channels
    submitCh        chan *JobSpec
    scheduleCh      chan *JobSpec
    completeCh      chan *JobResult
    
    // Metrics
    jobsSubmitted   prometheus.Counter
    jobsCompleted   prometheus.Counter
    jobsFailed      prometheus.Counter
    queueDepth      prometheus.Gauge
    processingTime  prometheus.Histogram
}

// NewJobQueue creates a new job queue manager
func NewJobQueue() *JobQueue {
    jq := &JobQueue{
        jobs:        make(map[string]*JobSpec),
        results:     make(map[string]*JobResult),
        queues:      make(map[int][]*JobSpec),
        statusIndex: make(map[JobStatus]map[string]*JobSpec),
        ownerIndex:  make(map[string]map[string]*JobSpec),
        submitCh:    make(chan *JobSpec, 1000),
        scheduleCh:  make(chan *JobSpec, 100),
        completeCh:  make(chan *JobResult, 100),
    }
    
    // Initialize metrics
    jq.initMetrics()
    
    // Start background workers
    go jq.processSubmissions()
    go jq.processCompletions()
    
    return jq
}

func (jq *JobQueue) initMetrics() {
    jq.jobsSubmitted = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_jobs_submitted_total",
        Help: "Total number of jobs submitted",
    })
    
    jq.jobsCompleted = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_jobs_completed_total",
        Help: "Total number of jobs completed",
    })
    
    jq.jobsFailed = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_jobs_failed_total",
        Help: "Total number of jobs failed",
    })
    
    jq.queueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "blackhole_job_queue_depth",
        Help: "Current depth of job queue",
    })
    
    jq.processingTime = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "blackhole_job_processing_seconds",
        Help:    "Job processing time in seconds",
        Buckets: prometheus.ExponentialBuckets(1, 2, 10),
    })
    
    prometheus.MustRegister(
        jq.jobsSubmitted,
        jq.jobsCompleted,
        jq.jobsFailed,
        jq.queueDepth,
        jq.processingTime,
    )
}

// SubmitJob submits a new job to the queue
func (jq *JobQueue) SubmitJob(ctx context.Context, spec *JobSpec) (*JobSpec, error) {
    // Validate job spec
    if err := validateJobSpec(spec); err != nil {
        return nil, fmt.Errorf("invalid job spec: %w", err)
    }
    
    // Generate ID if not provided
    if spec.ID == "" {
        spec.ID = uuid.New().String()
    }
    
    // Set timestamps
    now := time.Now()
    spec.CreatedAt = now
    spec.UpdatedAt = now
    
    // Submit to processing queue
    select {
    case jq.submitCh <- spec:
        jq.jobsSubmitted.Inc()
        return spec, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}

func (jq *JobQueue) processSubmissions() {
    for spec := range jq.submitCh {
        jq.mu.Lock()
        
        // Store job
        jq.jobs[spec.ID] = spec
        
        // Initialize result
        jq.results[spec.ID] = &JobResult{
            JobID:  spec.ID,
            Status: JobStatusPending,
        }
        
        // Add to priority queue
        priority := spec.Priority
        if priority < 0 {
            priority = 0
        } else if priority > 9 {
            priority = 9
        }
        jq.queues[priority] = append(jq.queues[priority], spec)
        
        // Update indices
        jq.updateStatusIndex(spec.ID, JobStatusPending)
        jq.updateOwnerIndex(spec)
        
        // Update metrics
        jq.queueDepth.Inc()
        
        jq.mu.Unlock()
        
        // Schedule job
        go func() {
            jq.scheduleCh <- spec
        }()
    }
}

func (jq *JobQueue) updateStatusIndex(jobID string, status JobStatus) {
    if jq.statusIndex[status] == nil {
        jq.statusIndex[status] = make(map[string]*JobSpec)
    }
    jq.statusIndex[status][jobID] = jq.jobs[jobID]
}

func (jq *JobQueue) updateOwnerIndex(spec *JobSpec) {
    if jq.ownerIndex[spec.Owner] == nil {
        jq.ownerIndex[spec.Owner] = make(map[string]*JobSpec)
    }
    jq.ownerIndex[spec.Owner][spec.ID] = spec
}

// GetJob retrieves a job by ID
func (jq *JobQueue) GetJob(jobID string) (*JobSpec, *JobResult, error) {
    jq.mu.RLock()
    defer jq.mu.RUnlock()
    
    spec, ok := jq.jobs[jobID]
    if !ok {
        return nil, nil, fmt.Errorf("job not found: %s", jobID)
    }
    
    result := jq.results[jobID]
    return spec, result, nil
}

// ListJobs lists jobs with filtering
func (jq *JobQueue) ListJobs(owner string, status JobStatus, limit int) ([]*JobSpec, error) {
    jq.mu.RLock()
    defer jq.mu.RUnlock()
    
    var jobs []*JobSpec
    
    if owner != "" && status != "" {
        // Filter by both owner and status
        if ownerJobs, ok := jq.ownerIndex[owner]; ok {
            for _, job := range ownerJobs {
                if result, ok := jq.results[job.ID]; ok && result.Status == status {
                    jobs = append(jobs, job)
                    if limit > 0 && len(jobs) >= limit {
                        break
                    }
                }
            }
        }
    } else if owner != "" {
        // Filter by owner only
        if ownerJobs, ok := jq.ownerIndex[owner]; ok {
            for _, job := range ownerJobs {
                jobs = append(jobs, job)
                if limit > 0 && len(jobs) >= limit {
                    break
                }
            }
        }
    } else if status != "" {
        // Filter by status only
        if statusJobs, ok := jq.statusIndex[status]; ok {
            for _, job := range statusJobs {
                jobs = append(jobs, job)
                if limit > 0 && len(jobs) >= limit {
                    break
                }
            }
        }
    } else {
        // No filters
        for _, job := range jq.jobs {
            jobs = append(jobs, job)
            if limit > 0 && len(jobs) >= limit {
                break
            }
        }
    }
    
    return jobs, nil
}

// CancelJob cancels a pending or running job
func (jq *JobQueue) CancelJob(jobID string) error {
    jq.mu.Lock()
    defer jq.mu.Unlock()
    
    spec, ok := jq.jobs[jobID]
    if !ok {
        return fmt.Errorf("job not found: %s", jobID)
    }
    
    result := jq.results[jobID]
    if result.Status == JobStatusCompleted || result.Status == JobStatusFailed {
        return fmt.Errorf("job already finished: %s", jobID)
    }
    
    // Update status
    result.Status = JobStatusCancelled
    now := time.Now()
    result.FinishedAt = &now
    spec.UpdatedAt = now
    
    // Remove from queue if pending
    if result.Status == JobStatusPending || result.Status == JobStatusQueued {
        jq.removeFromQueue(spec)
    }
    
    return nil
}

func (jq *JobQueue) removeFromQueue(spec *JobSpec) {
    priority := spec.Priority
    if priority < 0 {
        priority = 0
    } else if priority > 9 {
        priority = 9
    }
    
    queue := jq.queues[priority]
    for i, job := range queue {
        if job.ID == spec.ID {
            jq.queues[priority] = append(queue[:i], queue[i+1:]...)
            jq.queueDepth.Dec()
            break
        }
    }
}

// GetNextJob retrieves the next job to execute
func (jq *JobQueue) GetNextJob(ctx context.Context, requirements ResourceRequirements) (*JobSpec, error) {
    jq.mu.Lock()
    defer jq.mu.Unlock()
    
    // Check queues in priority order
    for priority := 9; priority >= 0; priority-- {
        queue := jq.queues[priority]
        for i, spec := range queue {
            // Check if job meets worker requirements
            if canExecute(spec.Requirements, requirements) {
                // Remove from queue
                jq.queues[priority] = append(queue[:i], queue[i+1:]...)
                
                // Update status
                result := jq.results[spec.ID]
                result.Status = JobStatusQueued
                now := time.Now()
                result.StartedAt = &now
                spec.UpdatedAt = now
                
                jq.queueDepth.Dec()
                
                return spec, nil
            }
        }
    }
    
    return nil, nil
}

func canExecute(jobReq, workerCap ResourceRequirements) bool {
    return jobReq.CPUCores <= workerCap.CPUCores &&
           jobReq.MemoryMB <= workerCap.MemoryMB &&
           jobReq.StorageMB <= workerCap.StorageMB &&
           jobReq.GPUCount <= workerCap.GPUCount
}

// CompleteJob marks a job as completed
func (jq *JobQueue) CompleteJob(result *JobResult) error {
    select {
    case jq.completeCh <- result:
        return nil
    default:
        return fmt.Errorf("completion queue full")
    }
}

func (jq *JobQueue) processCompletions() {
    for result := range jq.completeCh {
        jq.mu.Lock()
        
        spec, ok := jq.jobs[result.JobID]
        if !ok {
            jq.mu.Unlock()
            continue
        }
        
        // Update result
        existing := jq.results[result.JobID]
        existing.Status = result.Status
        existing.Output = result.Output
        existing.Error = result.Error
        existing.ExitCode = result.ExitCode
        existing.FinishedAt = result.FinishedAt
        existing.WorkerID = result.WorkerID
        existing.Metrics = result.Metrics
        
        // Update job
        spec.UpdatedAt = time.Now()
        
        // Update metrics
        if result.Status == JobStatusCompleted {
            jq.jobsCompleted.Inc()
            if existing.StartedAt != nil && result.FinishedAt != nil {
                duration := result.FinishedAt.Sub(*existing.StartedAt).Seconds()
                jq.processingTime.Observe(duration)
            }
        } else if result.Status == JobStatusFailed {
            jq.jobsFailed.Inc()
        }
        
        jq.mu.Unlock()
    }
}

func validateJobSpec(spec *JobSpec) error {
    if spec.Name == "" {
        return fmt.Errorf("job name required")
    }
    if spec.Owner == "" {
        return fmt.Errorf("job owner required")
    }
    if len(spec.WASMModule) == 0 {
        return fmt.Errorf("WASM module required")
    }
    if spec.EntryPoint == "" {
        return fmt.Errorf("entry point required")
    }
    if spec.Requirements.CPUCores <= 0 {
        return fmt.Errorf("CPU cores must be > 0")
    }
    if spec.Requirements.MemoryMB <= 0 {
        return fmt.Errorf("memory must be > 0")
    }
    if spec.Timeout <= 0 {
        spec.Timeout = 1 * time.Hour
    }
    return nil
}
```

### Job API Server

```go
package compute

import (
    "encoding/json"
    "net/http"
    "time"
    
    "github.com/gorilla/mux"
    "github.com/rs/zerolog/log"
)

// JobAPIServer provides HTTP API for job submission
type JobAPIServer struct {
    queue  *JobQueue
    router *mux.Router
}

// NewJobAPIServer creates a new API server
func NewJobAPIServer(queue *JobQueue) *JobAPIServer {
    s := &JobAPIServer{
        queue:  queue,
        router: mux.NewRouter(),
    }
    
    s.setupRoutes()
    return s
}

func (s *JobAPIServer) setupRoutes() {
    // Job submission
    s.router.HandleFunc("/api/v1/jobs", s.submitJob).Methods("POST")
    s.router.HandleFunc("/api/v1/jobs/{id}", s.getJob).Methods("GET")
    s.router.HandleFunc("/api/v1/jobs", s.listJobs).Methods("GET")
    s.router.HandleFunc("/api/v1/jobs/{id}/cancel", s.cancelJob).Methods("POST")
    
    // Job results
    s.router.HandleFunc("/api/v1/jobs/{id}/result", s.getJobResult).Methods("GET")
    s.router.HandleFunc("/api/v1/jobs/{id}/logs", s.getJobLogs).Methods("GET")
    
    // Health check
    s.router.HandleFunc("/health", s.healthCheck).Methods("GET")
}

func (s *JobAPIServer) submitJob(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Name         string                `json:"name"`
        WASMModule   string                `json:"wasm_module"` // Base64 encoded
        EntryPoint   string                `json:"entry_point"`
        Arguments    []string              `json:"arguments"`
        Environment  map[string]string     `json:"environment"`
        Requirements ResourceRequirements  `json:"requirements"`
        Priority     int                   `json:"priority"`
        MaxRetries   int                   `json:"max_retries"`
        Timeout      string                `json:"timeout"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Decode WASM module
    wasmModule, err := base64.StdEncoding.DecodeString(req.WASMModule)
    if err != nil {
        http.Error(w, "invalid WASM module encoding", http.StatusBadRequest)
        return
    }
    
    // Parse timeout
    timeout, err := time.ParseDuration(req.Timeout)
    if err != nil {
        timeout = 1 * time.Hour
    }
    
    // Create job spec
    spec := &JobSpec{
        Name:         req.Name,
        Owner:        r.Header.Get("X-User-ID"),
        WASMModule:   wasmModule,
        EntryPoint:   req.EntryPoint,
        Arguments:    req.Arguments,
        Environment:  req.Environment,
        Requirements: req.Requirements,
        Priority:     req.Priority,
        MaxRetries:   req.MaxRetries,
        Timeout:      timeout,
    }
    
    // Submit job
    job, err := s.queue.SubmitJob(r.Context(), spec)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    // Return response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "job_id": job.ID,
        "status": "submitted",
    })
}

func (s *JobAPIServer) getJob(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    jobID := vars["id"]
    
    spec, result, err := s.queue.GetJob(jobID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    
    // Check ownership
    userID := r.Header.Get("X-User-ID")
    if spec.Owner != userID && userID != "admin" {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "job":    spec,
        "result": result,
    })
}

func (s *JobAPIServer) listJobs(w http.ResponseWriter, r *http.Request) {
    owner := r.URL.Query().Get("owner")
    status := JobStatus(r.URL.Query().Get("status"))
    
    // Default to user's own jobs
    userID := r.Header.Get("X-User-ID")
    if owner == "" && userID != "admin" {
        owner = userID
    }
    
    jobs, err := s.queue.ListJobs(owner, status, 100)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "jobs":  jobs,
        "count": len(jobs),
    })
}

func (s *JobAPIServer) cancelJob(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    jobID := vars["id"]
    
    // Check ownership
    spec, _, err := s.queue.GetJob(jobID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    
    userID := r.Header.Get("X-User-ID")
    if spec.Owner != userID && userID != "admin" {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    
    if err := s.queue.CancelJob(jobID); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "cancelled",
    })
}

func (s *JobAPIServer) getJobResult(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    jobID := vars["id"]
    
    spec, result, err := s.queue.GetJob(jobID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusNotFound)
        return
    }
    
    // Check ownership
    userID := r.Header.Get("X-User-ID")
    if spec.Owner != userID && userID != "admin" {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

func (s *JobAPIServer) getJobLogs(w http.ResponseWriter, r *http.Request) {
    // This would stream logs from the worker
    // Implementation depends on log storage system
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("Log streaming not yet implemented\n"))
}

func (s *JobAPIServer) healthCheck(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "healthy",
        "time":   time.Now().Unix(),
    })
}

// ServeHTTP implements http.Handler
func (s *JobAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    s.router.ServeHTTP(w, r)
}
```

### Client SDK

```go
package client

import (
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

// JobClient provides client for job submission API
type JobClient struct {
    baseURL    string
    httpClient *http.Client
    apiKey     string
}

// NewJobClient creates a new job client
func NewJobClient(baseURL, apiKey string) *JobClient {
    return &JobClient{
        baseURL: baseURL,
        apiKey:  apiKey,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// SubmitJob submits a new job
func (c *JobClient) SubmitJob(ctx context.Context, req *JobSubmitRequest) (*JobSubmitResponse, error) {
    body, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }
    
    httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/v1/jobs", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }
    
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
    
    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("API error: %s", string(body))
    }
    
    var result JobSubmitResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    return &result, nil
}

// GetJob retrieves job details
func (c *JobClient) GetJob(ctx context.Context, jobID string) (*JobDetails, error) {
    httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/v1/jobs/"+jobID, nil)
    if err != nil {
        return nil, err
    }
    
    httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
    
    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("API error: %s", string(body))
    }
    
    var result JobDetails
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    return &result, nil
}

// WaitForCompletion waits for job completion
func (c *JobClient) WaitForCompletion(ctx context.Context, jobID string, pollInterval time.Duration) (*JobResult, error) {
    ticker := time.NewTicker(pollInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-ticker.C:
            details, err := c.GetJob(ctx, jobID)
            if err != nil {
                return nil, err
            }
            
            switch details.Result.Status {
            case "completed":
                return details.Result, nil
            case "failed", "cancelled":
                return details.Result, fmt.Errorf("job %s: %s", details.Result.Status, details.Result.Error)
            }
        }
    }
}

// Helper types for client
type JobSubmitRequest struct {
    Name         string                 `json:"name"`
    WASMModule   string                 `json:"wasm_module"`
    EntryPoint   string                 `json:"entry_point"`
    Arguments    []string               `json:"arguments"`
    Environment  map[string]string      `json:"environment"`
    Requirements ResourceRequirements   `json:"requirements"`
    Priority     int                    `json:"priority"`
    Timeout      string                 `json:"timeout"`
}

type JobSubmitResponse struct {
    JobID  string `json:"job_id"`
    Status string `json:"status"`
}

type JobDetails struct {
    Job    *JobSpec    `json:"job"`
    Result *JobResult  `json:"result"`
}

// SubmitWASMFile submits a WASM file as a job
func (c *JobClient) SubmitWASMFile(ctx context.Context, wasmPath string, args []string) (*JobSubmitResponse, error) {
    wasmData, err := os.ReadFile(wasmPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read WASM file: %w", err)
    }
    
    req := &JobSubmitRequest{
        Name:       filepath.Base(wasmPath),
        WASMModule: base64.StdEncoding.EncodeToString(wasmData),
        EntryPoint: "_start",
        Arguments:  args,
        Requirements: ResourceRequirements{
            CPUCores:  1,
            MemoryMB:  512,
            StorageMB: 100,
        },
        Priority: 5,
        Timeout:  "1h",
    }
    
    return c.SubmitJob(ctx, req)
}
```

## Testing

```go
package compute_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestJobQueue(t *testing.T) {
    queue := NewJobQueue()
    
    t.Run("SubmitJob", func(t *testing.T) {
        spec := &JobSpec{
            Name:       "test-job",
            Owner:      "user123",
            WASMModule: []byte("fake-wasm"),
            EntryPoint: "_start",
            Requirements: ResourceRequirements{
                CPUCores: 1,
                MemoryMB: 512,
            },
            Priority: 5,
            Timeout:  1 * time.Hour,
        }
        
        job, err := queue.SubmitJob(context.Background(), spec)
        require.NoError(t, err)
        assert.NotEmpty(t, job.ID)
        assert.Equal(t, "test-job", job.Name)
    })
    
    t.Run("GetJob", func(t *testing.T) {
        // Submit a job first
        spec := &JobSpec{
            Name:       "get-test",
            Owner:      "user123",
            WASMModule: []byte("fake-wasm"),
            EntryPoint: "_start",
            Requirements: ResourceRequirements{
                CPUCores: 1,
                MemoryMB: 512,
            },
        }
        
        submitted, err := queue.SubmitJob(context.Background(), spec)
        require.NoError(t, err)
        
        // Get the job
        retrieved, result, err := queue.GetJob(submitted.ID)
        require.NoError(t, err)
        assert.Equal(t, submitted.ID, retrieved.ID)
        assert.Equal(t, JobStatusPending, result.Status)
    })
    
    t.Run("ListJobs", func(t *testing.T) {
        // List by owner
        jobs, err := queue.ListJobs("user123", "", 10)
        require.NoError(t, err)
        assert.GreaterOrEqual(t, len(jobs), 2)
        
        // List by status
        jobs, err = queue.ListJobs("", JobStatusPending, 10)
        require.NoError(t, err)
        assert.Greater(t, len(jobs), 0)
    })
    
    t.Run("CancelJob", func(t *testing.T) {
        spec := &JobSpec{
            Name:       "cancel-test",
            Owner:      "user123",
            WASMModule: []byte("fake-wasm"),
            EntryPoint: "_start",
            Requirements: ResourceRequirements{
                CPUCores: 1,
                MemoryMB: 512,
            },
        }
        
        job, err := queue.SubmitJob(context.Background(), spec)
        require.NoError(t, err)
        
        err = queue.CancelJob(job.ID)
        require.NoError(t, err)
        
        _, result, err := queue.GetJob(job.ID)
        require.NoError(t, err)
        assert.Equal(t, JobStatusCancelled, result.Status)
    })
}

func TestJobPriorityQueue(t *testing.T) {
    queue := NewJobQueue()
    
    // Submit jobs with different priorities
    for i := 0; i < 10; i++ {
        spec := &JobSpec{
            Name:       fmt.Sprintf("priority-test-%d", i),
            Owner:      "user123",
            WASMModule: []byte("fake-wasm"),
            EntryPoint: "_start",
            Requirements: ResourceRequirements{
                CPUCores: 1,
                MemoryMB: 512,
            },
            Priority: i % 3, // Priorities 0, 1, 2
        }
        
        _, err := queue.SubmitJob(context.Background(), spec)
        require.NoError(t, err)
    }
    
    // Get jobs should return highest priority first
    workerReq := ResourceRequirements{
        CPUCores: 2,
        MemoryMB: 1024,
    }
    
    var priorities []int
    for i := 0; i < 10; i++ {
        job, err := queue.GetNextJob(context.Background(), workerReq)
        require.NoError(t, err)
        if job != nil {
            priorities = append(priorities, job.Priority)
        }
    }
    
    // Verify priorities are in descending order
    for i := 1; i < len(priorities); i++ {
        assert.GreaterOrEqual(t, priorities[i-1], priorities[i])
    }
}
```

## Deployment Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: job-api-server
  namespace: blackhole-compute
spec:
  replicas: 3
  selector:
    matchLabels:
      app: job-api-server
  template:
    metadata:
      labels:
        app: job-api-server
    spec:
      containers:
      - name: server
        image: blackhole/job-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: QUEUE_SIZE
          value: "10000"
        - name: MAX_PRIORITY
          value: "9"
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: job-api-service
  namespace: blackhole-compute
spec:
  selector:
    app: job-api-server
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

## Security Considerations

1. **Authentication**: API keys for job submission
2. **Authorization**: Owner-based access control
3. **Rate Limiting**: Prevent DoS attacks
4. **Input Validation**: Strict validation of job specs
5. **Resource Limits**: Enforce maximum resource allocations
6. **WASM Validation**: Verify WASM module integrity

## Performance Optimizations

1. **Priority Queues**: O(log n) job scheduling
2. **Indexed Lookups**: Fast job retrieval by owner/status
3. **Batch Processing**: Handle multiple submissions
4. **Connection Pooling**: Efficient database connections
5. **Caching**: Redis for frequently accessed jobs
6. **Horizontal Scaling**: Multiple API server instances