# U26: Work Distribution

## Overview
BOINC-inspired work distribution system that manages task scheduling, worker selection, and load balancing for the BlackHole compute marketplace.

## Implementation

### Core Distribution Types

```go
package distribution

import (
    "context"
    "encoding/json"
    "fmt"
    "math"
    "math/rand"
    "sync"
    "time"
    
    "github.com/prometheus/client_golang/prometheus"
    "github.com/rs/zerolog/log"
)

// WorkUnit represents a unit of work to be distributed
type WorkUnit struct {
    ID              string                `json:"id"`
    JobID           string                `json:"job_id"`
    TaskIndex       int                   `json:"task_index"`
    InputData       []byte                `json:"input_data"`
    Requirements    ResourceRequirements  `json:"requirements"`
    Priority        int                   `json:"priority"`
    Deadline        time.Time             `json:"deadline"`
    MaxRetries      int                   `json:"max_retries"`
    RetryCount      int                   `json:"retry_count"`
    CreatedAt       time.Time             `json:"created_at"`
    AssignedAt      *time.Time            `json:"assigned_at,omitempty"`
    CompletedAt     *time.Time            `json:"completed_at,omitempty"`
    AssignedWorker  string                `json:"assigned_worker,omitempty"`
    Status          WorkUnitStatus        `json:"status"`
    Result          []byte                `json:"result,omitempty"`
    Error           string                `json:"error,omitempty"`
    ValidationHash  string                `json:"validation_hash,omitempty"`
}

// WorkUnitStatus represents the status of a work unit
type WorkUnitStatus string

const (
    WorkUnitPending    WorkUnitStatus = "pending"
    WorkUnitAssigned   WorkUnitStatus = "assigned"
    WorkUnitProcessing WorkUnitStatus = "processing"
    WorkUnitCompleted  WorkUnitStatus = "completed"
    WorkUnitFailed     WorkUnitStatus = "failed"
    WorkUnitValidating WorkUnitStatus = "validating"
    WorkUnitValidated  WorkUnitStatus = "validated"
)

// Worker represents a compute worker
type Worker struct {
    ID           string               `json:"id"`
    Address      string               `json:"address"`
    Capabilities ResourceCapabilities `json:"capabilities"`
    Reputation   float64              `json:"reputation"`
    Reliability  float64              `json:"reliability"`
    JoinedAt     time.Time            `json:"joined_at"`
    LastSeen     time.Time            `json:"last_seen"`
    ActiveUnits  int                  `json:"active_units"`
    CompletedUnits int64              `json:"completed_units"`
    FailedUnits  int64                `json:"failed_units"`
    TotalEarnings float64             `json:"total_earnings"`
    Status       WorkerStatus         `json:"status"`
    
    // Performance metrics
    AvgCompletionTime time.Duration    `json:"avg_completion_time"`
    SuccessRate       float64          `json:"success_rate"`
    Throughput        float64          `json:"throughput"`
}

// WorkerStatus represents worker availability
type WorkerStatus string

const (
    WorkerIdle        WorkerStatus = "idle"
    WorkerBusy        WorkerStatus = "busy"
    WorkerOffline     WorkerStatus = "offline"
    WorkerSuspended   WorkerStatus = "suspended"
)

// ResourceCapabilities defines worker capabilities
type ResourceCapabilities struct {
    CPUCores      float64           `json:"cpu_cores"`
    CPUSpeed      float64           `json:"cpu_speed_ghz"`
    MemoryMB      uint64            `json:"memory_mb"`
    StorageMB     uint64            `json:"storage_mb"`
    NetworkMbps   float64           `json:"network_mbps"`
    GPUCount      int               `json:"gpu_count"`
    GPUModel      string            `json:"gpu_model,omitempty"`
    GPUMemoryMB   uint64            `json:"gpu_memory_mb,omitempty"`
    Architecture  string            `json:"architecture"`
    OS            string            `json:"os"`
    Location      string            `json:"location"`
    Features      []string          `json:"features"`
}

// ResourceRequirements from job specification
type ResourceRequirements struct {
    CPUCores    float64           `json:"cpu_cores"`
    MemoryMB    uint64            `json:"memory_mb"`
    StorageMB   uint64            `json:"storage_mb"`
    GPUCount    int               `json:"gpu_count,omitempty"`
    GPUType     string            `json:"gpu_type,omitempty"`
    Duration    time.Duration     `json:"duration"`
    Labels      map[string]string `json:"labels,omitempty"`
}

// WorkDistributor manages work distribution
type WorkDistributor struct {
    mu              sync.RWMutex
    workers         map[string]*Worker
    workUnits       map[string]*WorkUnit
    assignments     map[string]string // workerID -> workUnitID
    
    // Scheduling queues
    pendingQueue    *PriorityQueue
    retryQueue      *PriorityQueue
    
    // Channels
    assignCh        chan *Assignment
    completeCh      chan *Completion
    heartbeatCh     chan *Heartbeat
    
    // Configuration
    config          *DistributorConfig
    
    // Metrics
    unitsDistributed prometheus.Counter
    unitsCompleted   prometheus.Counter
    unitsFailed      prometheus.Counter
    workerUtilization prometheus.Gauge
    avgWaitTime      prometheus.Histogram
    avgProcessTime   prometheus.Histogram
}

// DistributorConfig defines distributor configuration
type DistributorConfig struct {
    MaxWorkersPerUnit     int           `json:"max_workers_per_unit"`
    AssignmentTimeout     time.Duration `json:"assignment_timeout"`
    HeartbeatInterval     time.Duration `json:"heartbeat_interval"`
    WorkerTimeout         time.Duration `json:"worker_timeout"`
    RetryBackoff          time.Duration `json:"retry_backoff"`
    ValidationThreshold   int           `json:"validation_threshold"`
    ReputationThreshold   float64       `json:"reputation_threshold"`
    LoadBalancingStrategy string        `json:"load_balancing_strategy"`
}

// NewWorkDistributor creates a new work distributor
func NewWorkDistributor(config *DistributorConfig) *WorkDistributor {
    if config == nil {
        config = &DistributorConfig{
            MaxWorkersPerUnit:     3,
            AssignmentTimeout:     5 * time.Minute,
            HeartbeatInterval:     30 * time.Second,
            WorkerTimeout:         2 * time.Minute,
            RetryBackoff:          1 * time.Minute,
            ValidationThreshold:   2,
            ReputationThreshold:   0.5,
            LoadBalancingStrategy: "weighted-random",
        }
    }
    
    wd := &WorkDistributor{
        workers:      make(map[string]*Worker),
        workUnits:    make(map[string]*WorkUnit),
        assignments:  make(map[string]string),
        pendingQueue: NewPriorityQueue(),
        retryQueue:   NewPriorityQueue(),
        assignCh:     make(chan *Assignment, 1000),
        completeCh:   make(chan *Completion, 1000),
        heartbeatCh:  make(chan *Heartbeat, 1000),
        config:       config,
    }
    
    wd.initMetrics()
    
    // Start background workers
    go wd.scheduler()
    go wd.assignmentProcessor()
    go wd.completionProcessor()
    go wd.heartbeatProcessor()
    go wd.timeoutChecker()
    
    return wd
}

func (wd *WorkDistributor) initMetrics() {
    wd.unitsDistributed = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_units_distributed_total",
        Help: "Total number of work units distributed",
    })
    
    wd.unitsCompleted = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_units_completed_total",
        Help: "Total number of work units completed",
    })
    
    wd.unitsFailed = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackhole_units_failed_total",
        Help: "Total number of work units failed",
    })
    
    wd.workerUtilization = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "blackhole_worker_utilization_ratio",
        Help: "Current worker utilization ratio",
    })
    
    wd.avgWaitTime = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "blackhole_unit_wait_seconds",
        Help:    "Time units wait before assignment",
        Buckets: prometheus.ExponentialBuckets(1, 2, 10),
    })
    
    wd.avgProcessTime = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "blackhole_unit_process_seconds",
        Help:    "Time to process work units",
        Buckets: prometheus.ExponentialBuckets(1, 2, 12),
    })
    
    prometheus.MustRegister(
        wd.unitsDistributed,
        wd.unitsCompleted,
        wd.unitsFailed,
        wd.workerUtilization,
        wd.avgWaitTime,
        wd.avgProcessTime,
    )
}

// RegisterWorker registers a new worker
func (wd *WorkDistributor) RegisterWorker(worker *Worker) error {
    wd.mu.Lock()
    defer wd.mu.Unlock()
    
    if _, exists := wd.workers[worker.ID]; exists {
        return fmt.Errorf("worker already registered: %s", worker.ID)
    }
    
    worker.Status = WorkerIdle
    worker.LastSeen = time.Now()
    worker.Reputation = 1.0
    worker.Reliability = 1.0
    
    wd.workers[worker.ID] = worker
    
    log.Info().
        Str("worker_id", worker.ID).
        Float64("cpu_cores", worker.Capabilities.CPUCores).
        Uint64("memory_mb", worker.Capabilities.MemoryMB).
        Msg("Worker registered")
    
    return nil
}

// SubmitWorkUnit submits a new work unit
func (wd *WorkDistributor) SubmitWorkUnit(unit *WorkUnit) error {
    wd.mu.Lock()
    defer wd.mu.Unlock()
    
    if _, exists := wd.workUnits[unit.ID]; exists {
        return fmt.Errorf("work unit already exists: %s", unit.ID)
    }
    
    unit.Status = WorkUnitPending
    unit.CreatedAt = time.Now()
    
    wd.workUnits[unit.ID] = unit
    wd.pendingQueue.Push(unit)
    
    return nil
}

// scheduler manages work unit scheduling
func (wd *WorkDistributor) scheduler() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        wd.scheduleWorkUnits()
    }
}

func (wd *WorkDistributor) scheduleWorkUnits() {
    wd.mu.Lock()
    defer wd.mu.Unlock()
    
    // Get available workers
    availableWorkers := wd.getAvailableWorkers()
    if len(availableWorkers) == 0 {
        return
    }
    
    // Schedule pending units
    scheduled := 0
    maxSchedule := len(availableWorkers) * 2
    
    for scheduled < maxSchedule && wd.pendingQueue.Len() > 0 {
        unit := wd.pendingQueue.Peek().(*WorkUnit)
        
        // Find suitable worker
        worker := wd.selectWorker(unit, availableWorkers)
        if worker == nil {
            wd.pendingQueue.Pop()
            wd.retryQueue.Push(unit)
            continue
        }
        
        // Create assignment
        assignment := &Assignment{
            WorkUnitID: unit.ID,
            WorkerID:   worker.ID,
            AssignedAt: time.Now(),
        }
        
        // Update states
        unit.Status = WorkUnitAssigned
        unit.AssignedWorker = worker.ID
        now := time.Now()
        unit.AssignedAt = &now
        
        worker.ActiveUnits++
        if worker.ActiveUnits >= int(worker.Capabilities.CPUCores) {
            worker.Status = WorkerBusy
        }
        
        wd.assignments[worker.ID] = unit.ID
        
        // Send assignment
        select {
        case wd.assignCh <- assignment:
            wd.unitsDistributed.Inc()
            scheduled++
            
            // Record wait time
            waitTime := time.Since(unit.CreatedAt).Seconds()
            wd.avgWaitTime.Observe(waitTime)
            
        default:
            // Assignment channel full, retry later
            unit.Status = WorkUnitPending
            unit.AssignedWorker = ""
            unit.AssignedAt = nil
            worker.ActiveUnits--
            delete(wd.assignments, worker.ID)
        }
        
        wd.pendingQueue.Pop()
    }
    
    // Update utilization metric
    wd.updateUtilization()
}

func (wd *WorkDistributor) getAvailableWorkers() []*Worker {
    var available []*Worker
    
    for _, worker := range wd.workers {
        if worker.Status == WorkerIdle || worker.Status == WorkerBusy {
            if time.Since(worker.LastSeen) < wd.config.WorkerTimeout {
                available = append(available, worker)
            }
        }
    }
    
    return available
}

func (wd *WorkDistributor) selectWorker(unit *WorkUnit, workers []*Worker) *Worker {
    // Filter capable workers
    capable := wd.filterCapableWorkers(unit, workers)
    if len(capable) == 0 {
        return nil
    }
    
    // Apply load balancing strategy
    switch wd.config.LoadBalancingStrategy {
    case "round-robin":
        return wd.roundRobinSelect(capable)
    case "least-loaded":
        return wd.leastLoadedSelect(capable)
    case "weighted-random":
        return wd.weightedRandomSelect(capable)
    case "reputation-based":
        return wd.reputationBasedSelect(capable)
    default:
        return capable[0]
    }
}

func (wd *WorkDistributor) filterCapableWorkers(unit *WorkUnit, workers []*Worker) []*Worker {
    var capable []*Worker
    
    for _, worker := range workers {
        if wd.isCapable(worker, unit.Requirements) &&
           worker.Reputation >= wd.config.ReputationThreshold {
            capable = append(capable, worker)
        }
    }
    
    return capable
}

func (wd *WorkDistributor) isCapable(worker *Worker, req ResourceRequirements) bool {
    cap := worker.Capabilities
    
    return cap.CPUCores >= req.CPUCores &&
           cap.MemoryMB >= req.MemoryMB &&
           cap.StorageMB >= req.StorageMB &&
           cap.GPUCount >= req.GPUCount
}

func (wd *WorkDistributor) weightedRandomSelect(workers []*Worker) *Worker {
    if len(workers) == 0 {
        return nil
    }
    
    // Calculate weights based on reputation and available capacity
    weights := make([]float64, len(workers))
    totalWeight := 0.0
    
    for i, worker := range workers {
        capacityRatio := 1.0 - float64(worker.ActiveUnits)/float64(worker.Capabilities.CPUCores)
        weight := worker.Reputation * worker.Reliability * capacityRatio
        weights[i] = weight
        totalWeight += weight
    }
    
    // Random selection
    r := rand.Float64() * totalWeight
    cumulative := 0.0
    
    for i, weight := range weights {
        cumulative += weight
        if r <= cumulative {
            return workers[i]
        }
    }
    
    return workers[len(workers)-1]
}

func (wd *WorkDistributor) leastLoadedSelect(workers []*Worker) *Worker {
    if len(workers) == 0 {
        return nil
    }
    
    selected := workers[0]
    minLoad := float64(selected.ActiveUnits) / float64(selected.Capabilities.CPUCores)
    
    for _, worker := range workers[1:] {
        load := float64(worker.ActiveUnits) / float64(worker.Capabilities.CPUCores)
        if load < minLoad {
            selected = worker
            minLoad = load
        }
    }
    
    return selected
}

func (wd *WorkDistributor) roundRobinSelect(workers []*Worker) *Worker {
    // Simple round-robin, would need state tracking for true RR
    return workers[rand.Intn(len(workers))]
}

func (wd *WorkDistributor) reputationBasedSelect(workers []*Worker) *Worker {
    if len(workers) == 0 {
        return nil
    }
    
    // Sort by reputation
    selected := workers[0]
    for _, worker := range workers[1:] {
        if worker.Reputation > selected.Reputation {
            selected = worker
        }
    }
    
    return selected
}

// Assignment represents a work assignment
type Assignment struct {
    WorkUnitID string    `json:"work_unit_id"`
    WorkerID   string    `json:"worker_id"`
    AssignedAt time.Time `json:"assigned_at"`
}

// Completion represents work completion
type Completion struct {
    WorkUnitID string    `json:"work_unit_id"`
    WorkerID   string    `json:"worker_id"`
    Result     []byte    `json:"result"`
    Error      string    `json:"error,omitempty"`
    StartedAt  time.Time `json:"started_at"`
    FinishedAt time.Time `json:"finished_at"`
    Metrics    map[string]float64 `json:"metrics"`
}

// Heartbeat represents worker heartbeat
type Heartbeat struct {
    WorkerID   string    `json:"worker_id"`
    Timestamp  time.Time `json:"timestamp"`
    ActiveUnits []string `json:"active_units"`
    Resources  ResourceUsage `json:"resources"`
}

// ResourceUsage represents current resource usage
type ResourceUsage struct {
    CPUPercent    float64 `json:"cpu_percent"`
    MemoryPercent float64 `json:"memory_percent"`
    DiskPercent   float64 `json:"disk_percent"`
    NetworkMbps   float64 `json:"network_mbps"`
}

func (wd *WorkDistributor) assignmentProcessor() {
    for assignment := range wd.assignCh {
        // This would send the assignment to the worker
        log.Info().
            Str("unit_id", assignment.WorkUnitID).
            Str("worker_id", assignment.WorkerID).
            Msg("Work unit assigned")
    }
}

func (wd *WorkDistributor) completionProcessor() {
    for completion := range wd.completeCh {
        wd.handleCompletion(completion)
    }
}

func (wd *WorkDistributor) handleCompletion(completion *Completion) {
    wd.mu.Lock()
    defer wd.mu.Unlock()
    
    unit, exists := wd.workUnits[completion.WorkUnitID]
    if !exists {
        log.Error().Str("unit_id", completion.WorkUnitID).Msg("Unknown work unit")
        return
    }
    
    worker, exists := wd.workers[completion.WorkerID]
    if !exists {
        log.Error().Str("worker_id", completion.WorkerID).Msg("Unknown worker")
        return
    }
    
    // Update work unit
    if completion.Error != "" {
        unit.Status = WorkUnitFailed
        unit.Error = completion.Error
        unit.RetryCount++
        
        worker.FailedUnits++
        wd.unitsFailed.Inc()
        
        // Retry if under limit
        if unit.RetryCount < unit.MaxRetries {
            unit.Status = WorkUnitPending
            wd.retryQueue.Push(unit)
        }
    } else {
        unit.Status = WorkUnitCompleted
        unit.Result = completion.Result
        now := time.Now()
        unit.CompletedAt = &now
        
        worker.CompletedUnits++
        wd.unitsCompleted.Inc()
        
        // Record processing time
        processTime := completion.FinishedAt.Sub(completion.StartedAt).Seconds()
        wd.avgProcessTime.Observe(processTime)
    }
    
    // Update worker
    worker.ActiveUnits--
    if worker.ActiveUnits < int(worker.Capabilities.CPUCores) {
        worker.Status = WorkerIdle
    }
    
    delete(wd.assignments, worker.ID)
    
    // Update worker metrics
    wd.updateWorkerMetrics(worker, completion)
}

func (wd *WorkDistributor) updateWorkerMetrics(worker *Worker, completion *Completion) {
    // Update success rate
    total := float64(worker.CompletedUnits + worker.FailedUnits)
    if total > 0 {
        worker.SuccessRate = float64(worker.CompletedUnits) / total
    }
    
    // Update average completion time
    if completion.Error == "" {
        duration := completion.FinishedAt.Sub(completion.StartedAt)
        if worker.AvgCompletionTime == 0 {
            worker.AvgCompletionTime = duration
        } else {
            // Exponential moving average
            alpha := 0.1
            worker.AvgCompletionTime = time.Duration(
                alpha*float64(duration) + (1-alpha)*float64(worker.AvgCompletionTime),
            )
        }
    }
    
    // Update reputation
    wd.updateReputation(worker, completion.Error == "")
}

func (wd *WorkDistributor) updateReputation(worker *Worker, success bool) {
    // Simple reputation update algorithm
    delta := 0.01
    if success {
        worker.Reputation = math.Min(1.0, worker.Reputation+delta)
    } else {
        worker.Reputation = math.Max(0.0, worker.Reputation-delta*2)
    }
    
    // Update reliability (longer-term metric)
    alpha := 0.05
    if success {
        worker.Reliability = alpha*1.0 + (1-alpha)*worker.Reliability
    } else {
        worker.Reliability = alpha*0.0 + (1-alpha)*worker.Reliability
    }
}

func (wd *WorkDistributor) heartbeatProcessor() {
    for heartbeat := range wd.heartbeatCh {
        wd.mu.Lock()
        
        if worker, exists := wd.workers[heartbeat.WorkerID]; exists {
            worker.LastSeen = heartbeat.Timestamp
            
            // Update resource usage
            // Could be used for dynamic load balancing
        }
        
        wd.mu.Unlock()
    }
}

func (wd *WorkDistributor) timeoutChecker() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        wd.checkTimeouts()
    }
}

func (wd *WorkDistributor) checkTimeouts() {
    wd.mu.Lock()
    defer wd.mu.Unlock()
    
    now := time.Now()
    
    // Check worker timeouts
    for _, worker := range wd.workers {
        if worker.Status != WorkerOffline && 
           now.Sub(worker.LastSeen) > wd.config.WorkerTimeout {
            worker.Status = WorkerOffline
            
            // Reassign work units
            if unitID, assigned := wd.assignments[worker.ID]; assigned {
                if unit, exists := wd.workUnits[unitID]; exists {
                    unit.Status = WorkUnitPending
                    unit.AssignedWorker = ""
                    unit.AssignedAt = nil
                    unit.RetryCount++
                    
                    wd.pendingQueue.Push(unit)
                    delete(wd.assignments, worker.ID)
                }
            }
        }
    }
    
    // Check assignment timeouts
    for _, unit := range wd.workUnits {
        if unit.Status == WorkUnitAssigned && unit.AssignedAt != nil {
            if now.Sub(*unit.AssignedAt) > wd.config.AssignmentTimeout {
                // Timeout - reassign
                if worker, exists := wd.workers[unit.AssignedWorker]; exists {
                    worker.ActiveUnits--
                    worker.FailedUnits++
                    wd.updateReputation(worker, false)
                }
                
                unit.Status = WorkUnitPending
                unit.AssignedWorker = ""
                unit.AssignedAt = nil
                unit.RetryCount++
                
                if unit.RetryCount < unit.MaxRetries {
                    wd.retryQueue.Push(unit)
                } else {
                    unit.Status = WorkUnitFailed
                    unit.Error = "max retries exceeded"
                    wd.unitsFailed.Inc()
                }
            }
        }
    }
}

func (wd *WorkDistributor) updateUtilization() {
    totalCapacity := 0
    totalActive := 0
    
    for _, worker := range wd.workers {
        if worker.Status == WorkerIdle || worker.Status == WorkerBusy {
            totalCapacity += int(worker.Capabilities.CPUCores)
            totalActive += worker.ActiveUnits
        }
    }
    
    if totalCapacity > 0 {
        utilization := float64(totalActive) / float64(totalCapacity)
        wd.workerUtilization.Set(utilization)
    }
}

// GetWorkerStats returns worker statistics
func (wd *WorkDistributor) GetWorkerStats(workerID string) (*WorkerStats, error) {
    wd.mu.RLock()
    defer wd.mu.RUnlock()
    
    worker, exists := wd.workers[workerID]
    if !exists {
        return nil, fmt.Errorf("worker not found: %s", workerID)
    }
    
    return &WorkerStats{
        ID:               worker.ID,
        Status:           worker.Status,
        Reputation:       worker.Reputation,
        Reliability:      worker.Reliability,
        ActiveUnits:      worker.ActiveUnits,
        CompletedUnits:   worker.CompletedUnits,
        FailedUnits:      worker.FailedUnits,
        SuccessRate:      worker.SuccessRate,
        AvgCompletionTime: worker.AvgCompletionTime,
        TotalEarnings:    worker.TotalEarnings,
        LastSeen:         worker.LastSeen,
    }, nil
}

// WorkerStats contains worker statistics
type WorkerStats struct {
    ID                string        `json:"id"`
    Status            WorkerStatus  `json:"status"`
    Reputation        float64       `json:"reputation"`
    Reliability       float64       `json:"reliability"`
    ActiveUnits       int           `json:"active_units"`
    CompletedUnits    int64         `json:"completed_units"`
    FailedUnits       int64         `json:"failed_units"`
    SuccessRate       float64       `json:"success_rate"`
    AvgCompletionTime time.Duration `json:"avg_completion_time"`
    TotalEarnings     float64       `json:"total_earnings"`
    LastSeen          time.Time     `json:"last_seen"`
}
```

### Priority Queue Implementation

```go
package distribution

import (
    "container/heap"
    "time"
)

// PriorityQueue implements a priority queue for work units
type PriorityQueue struct {
    items []*Item
}

// Item wraps a work unit with priority
type Item struct {
    unit     *WorkUnit
    priority float64
    index    int
}

// NewPriorityQueue creates a new priority queue
func NewPriorityQueue() *PriorityQueue {
    pq := &PriorityQueue{
        items: make([]*Item, 0),
    }
    heap.Init(pq)
    return pq
}

// Len returns queue length
func (pq *PriorityQueue) Len() int {
    return len(pq.items)
}

// Less compares items by priority
func (pq *PriorityQueue) Less(i, j int) bool {
    // Higher priority first
    if pq.items[i].priority != pq.items[j].priority {
        return pq.items[i].priority > pq.items[j].priority
    }
    
    // Then by deadline
    return pq.items[i].unit.Deadline.Before(pq.items[j].unit.Deadline)
}

// Swap swaps two items
func (pq *PriorityQueue) Swap(i, j int) {
    pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
    pq.items[i].index = i
    pq.items[j].index = j
}

// Push adds an item
func (pq *PriorityQueue) Push(x interface{}) {
    unit := x.(*WorkUnit)
    
    // Calculate priority based on multiple factors
    priority := float64(unit.Priority)
    
    // Urgency factor
    timeUntilDeadline := time.Until(unit.Deadline).Hours()
    if timeUntilDeadline < 1 {
        priority *= 2
    }
    
    // Retry penalty
    priority -= float64(unit.RetryCount) * 0.1
    
    item := &Item{
        unit:     unit,
        priority: priority,
        index:    len(pq.items),
    }
    
    pq.items = append(pq.items, item)
}

// Pop removes highest priority item
func (pq *PriorityQueue) Pop() interface{} {
    old := pq.items
    n := len(old)
    item := old[n-1]
    old[n-1] = nil
    item.index = -1
    pq.items = old[0 : n-1]
    return item.unit
}

// Peek returns highest priority item without removing
func (pq *PriorityQueue) Peek() interface{} {
    if len(pq.items) == 0 {
        return nil
    }
    return pq.items[0].unit
}
```

### Worker Client

```go
package worker

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
    
    "github.com/rs/zerolog/log"
)

// WorkerClient handles worker-side operations
type WorkerClient struct {
    workerID     string
    serverURL    string
    httpClient   *http.Client
    capabilities ResourceCapabilities
    
    // Channels
    assignmentCh chan *Assignment
    stopCh       chan struct{}
}

// NewWorkerClient creates a new worker client
func NewWorkerClient(workerID, serverURL string, capabilities ResourceCapabilities) *WorkerClient {
    return &WorkerClient{
        workerID:     workerID,
        serverURL:    serverURL,
        capabilities: capabilities,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
        assignmentCh: make(chan *Assignment, 10),
        stopCh:       make(chan struct{}),
    }
}

// Start starts the worker client
func (wc *WorkerClient) Start(ctx context.Context) error {
    // Register with server
    if err := wc.register(); err != nil {
        return fmt.Errorf("registration failed: %w", err)
    }
    
    // Start goroutines
    go wc.heartbeatLoop(ctx)
    go wc.assignmentLoop(ctx)
    go wc.workLoop(ctx)
    
    <-ctx.Done()
    close(wc.stopCh)
    
    return nil
}

func (wc *WorkerClient) register() error {
    req := map[string]interface{}{
        "id":           wc.workerID,
        "capabilities": wc.capabilities,
    }
    
    body, err := json.Marshal(req)
    if err != nil {
        return err
    }
    
    resp, err := wc.httpClient.Post(
        wc.serverURL+"/api/v1/workers/register",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("registration failed: %s", string(body))
    }
    
    log.Info().Msg("Worker registered successfully")
    return nil
}

func (wc *WorkerClient) heartbeatLoop(ctx context.Context) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-wc.stopCh:
            return
        case <-ticker.C:
            wc.sendHeartbeat()
        }
    }
}

func (wc *WorkerClient) sendHeartbeat() {
    heartbeat := &Heartbeat{
        WorkerID:  wc.workerID,
        Timestamp: time.Now(),
        Resources: getResourceUsage(),
    }
    
    body, err := json.Marshal(heartbeat)
    if err != nil {
        log.Error().Err(err).Msg("Failed to marshal heartbeat")
        return
    }
    
    resp, err := wc.httpClient.Post(
        wc.serverURL+"/api/v1/workers/heartbeat",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        log.Error().Err(err).Msg("Failed to send heartbeat")
        return
    }
    resp.Body.Close()
}

func (wc *WorkerClient) assignmentLoop(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-wc.stopCh:
            return
        case <-ticker.C:
            wc.checkAssignments()
        }
    }
}

func (wc *WorkerClient) checkAssignments() {
    resp, err := wc.httpClient.Get(
        wc.serverURL + "/api/v1/workers/" + wc.workerID + "/assignments",
    )
    if err != nil {
        log.Error().Err(err).Msg("Failed to check assignments")
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return
    }
    
    var assignments []Assignment
    if err := json.NewDecoder(resp.Body).Decode(&assignments); err != nil {
        log.Error().Err(err).Msg("Failed to decode assignments")
        return
    }
    
    for _, assignment := range assignments {
        select {
        case wc.assignmentCh <- &assignment:
        default:
            // Assignment queue full
        }
    }
}

func (wc *WorkerClient) workLoop(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case <-wc.stopCh:
            return
        case assignment := <-wc.assignmentCh:
            wc.processAssignment(assignment)
        }
    }
}

func (wc *WorkerClient) processAssignment(assignment *Assignment) {
    log.Info().
        Str("unit_id", assignment.WorkUnitID).
        Msg("Processing work unit")
    
    startTime := time.Now()
    
    // Download work unit
    unit, err := wc.downloadWorkUnit(assignment.WorkUnitID)
    if err != nil {
        wc.reportFailure(assignment, err.Error())
        return
    }
    
    // Execute work
    result, err := wc.executeWork(unit)
    if err != nil {
        wc.reportFailure(assignment, err.Error())
        return
    }
    
    // Report completion
    completion := &Completion{
        WorkUnitID: assignment.WorkUnitID,
        WorkerID:   wc.workerID,
        Result:     result,
        StartedAt:  startTime,
        FinishedAt: time.Now(),
        Metrics: map[string]float64{
            "execution_time": time.Since(startTime).Seconds(),
        },
    }
    
    wc.reportCompletion(completion)
}

func (wc *WorkerClient) downloadWorkUnit(unitID string) (*WorkUnit, error) {
    resp, err := wc.httpClient.Get(
        wc.serverURL + "/api/v1/units/" + unitID,
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("download failed: %s", string(body))
    }
    
    var unit WorkUnit
    if err := json.NewDecoder(resp.Body).Decode(&unit); err != nil {
        return nil, err
    }
    
    return &unit, nil
}

func (wc *WorkerClient) executeWork(unit *WorkUnit) ([]byte, error) {
    // This would execute the actual WASM module
    // For now, return dummy result
    time.Sleep(time.Duration(rand.Intn(10)) * time.Second)
    
    result := map[string]interface{}{
        "unit_id": unit.ID,
        "output":  "computed result",
    }
    
    return json.Marshal(result)
}

func (wc *WorkerClient) reportCompletion(completion *Completion) {
    body, err := json.Marshal(completion)
    if err != nil {
        log.Error().Err(err).Msg("Failed to marshal completion")
        return
    }
    
    resp, err := wc.httpClient.Post(
        wc.serverURL+"/api/v1/completions",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        log.Error().Err(err).Msg("Failed to report completion")
        return
    }
    resp.Body.Close()
}

func (wc *WorkerClient) reportFailure(assignment *Assignment, error string) {
    completion := &Completion{
        WorkUnitID: assignment.WorkUnitID,
        WorkerID:   wc.workerID,
        Error:      error,
        StartedAt:  time.Now(),
        FinishedAt: time.Now(),
    }
    
    wc.reportCompletion(completion)
}

func getResourceUsage() ResourceUsage {
    // This would get actual resource usage
    return ResourceUsage{
        CPUPercent:    rand.Float64() * 100,
        MemoryPercent: rand.Float64() * 100,
        DiskPercent:   rand.Float64() * 100,
        NetworkMbps:   rand.Float64() * 1000,
    }
}
```

## Testing

```go
package distribution_test

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestWorkDistributor(t *testing.T) {
    config := &DistributorConfig{
        MaxWorkersPerUnit:     3,
        AssignmentTimeout:     1 * time.Minute,
        HeartbeatInterval:     5 * time.Second,
        WorkerTimeout:         30 * time.Second,
        RetryBackoff:          5 * time.Second,
        ValidationThreshold:   2,
        ReputationThreshold:   0.5,
        LoadBalancingStrategy: "weighted-random",
    }
    
    distributor := NewWorkDistributor(config)
    
    t.Run("RegisterWorker", func(t *testing.T) {
        worker := &Worker{
            ID:      "worker-1",
            Address: "192.168.1.100:8080",
            Capabilities: ResourceCapabilities{
                CPUCores:  4,
                MemoryMB:  8192,
                StorageMB: 100000,
            },
        }
        
        err := distributor.RegisterWorker(worker)
        require.NoError(t, err)
        
        // Try duplicate registration
        err = distributor.RegisterWorker(worker)
        assert.Error(t, err)
    })
    
    t.Run("SubmitWorkUnit", func(t *testing.T) {
        unit := &WorkUnit{
            ID:    "unit-1",
            JobID: "job-1",
            Requirements: ResourceRequirements{
                CPUCores: 2,
                MemoryMB: 4096,
            },
            Priority:   5,
            Deadline:   time.Now().Add(1 * time.Hour),
            MaxRetries: 3,
        }
        
        err := distributor.SubmitWorkUnit(unit)
        require.NoError(t, err)
    })
    
    t.Run("WorkerSelection", func(t *testing.T) {
        // Register multiple workers
        for i := 2; i <= 5; i++ {
            worker := &Worker{
                ID:      fmt.Sprintf("worker-%d", i),
                Address: fmt.Sprintf("192.168.1.%d:8080", 100+i),
                Capabilities: ResourceCapabilities{
                    CPUCores:  float64(i),
                    MemoryMB:  uint64(i * 4096),
                    StorageMB: 100000,
                },
            }
            distributor.RegisterWorker(worker)
        }
        
        // Submit units with different requirements
        for i := 0; i < 10; i++ {
            unit := &WorkUnit{
                ID:    fmt.Sprintf("unit-%d", i+2),
                JobID: "job-1",
                Requirements: ResourceRequirements{
                    CPUCores: float64(1 + i%3),
                    MemoryMB: uint64((1 + i%3) * 2048),
                },
                Priority: i % 10,
                Deadline: time.Now().Add(time.Duration(i+1) * time.Hour),
            }
            distributor.SubmitWorkUnit(unit)
        }
        
        // Wait for scheduling
        time.Sleep(10 * time.Second)
        
        // Check assignments
        stats, err := distributor.GetWorkerStats("worker-1")
        require.NoError(t, err)
        assert.GreaterOrEqual(t, stats.ActiveUnits, 0)
    })
}

func TestPriorityQueue(t *testing.T) {
    pq := NewPriorityQueue()
    
    units := []*WorkUnit{
        {
            ID:       "low",
            Priority: 1,
            Deadline: time.Now().Add(2 * time.Hour),
        },
        {
            ID:       "high",
            Priority: 9,
            Deadline: time.Now().Add(2 * time.Hour),
        },
        {
            ID:       "medium",
            Priority: 5,
            Deadline: time.Now().Add(2 * time.Hour),
        },
        {
            ID:       "urgent",
            Priority: 5,
            Deadline: time.Now().Add(30 * time.Minute),
        },
    }
    
    for _, unit := range units {
        pq.Push(unit)
    }
    
    // Should get high priority first
    first := pq.Pop().(*WorkUnit)
    assert.Equal(t, "high", first.ID)
    
    // Then urgent (same priority as medium but earlier deadline)
    second := pq.Pop().(*WorkUnit)
    assert.Equal(t, "urgent", second.ID)
    
    // Then medium
    third := pq.Pop().(*WorkUnit)
    assert.Equal(t, "medium", third.ID)
    
    // Finally low
    fourth := pq.Pop().(*WorkUnit)
    assert.Equal(t, "low", fourth.ID)
}

func TestLoadBalancing(t *testing.T) {
    distributor := NewWorkDistributor(nil)
    
    // Register workers with different capabilities
    workers := []*Worker{
        {
            ID: "powerful",
            Capabilities: ResourceCapabilities{
                CPUCores: 16,
                MemoryMB: 65536,
            },
            Reputation:  0.95,
            Reliability: 0.98,
        },
        {
            ID: "medium",
            Capabilities: ResourceCapabilities{
                CPUCores: 8,
                MemoryMB: 32768,
            },
            Reputation:  0.85,
            Reliability: 0.90,
        },
        {
            ID: "weak",
            Capabilities: ResourceCapabilities{
                CPUCores: 4,
                MemoryMB: 16384,
            },
            Reputation:  0.75,
            Reliability: 0.85,
        },
    }
    
    for _, worker := range workers {
        distributor.RegisterWorker(worker)
    }
    
    // Submit many small units
    for i := 0; i < 100; i++ {
        unit := &WorkUnit{
            ID:    fmt.Sprintf("small-%d", i),
            JobID: "test-job",
            Requirements: ResourceRequirements{
                CPUCores: 1,
                MemoryMB: 1024,
            },
            Priority: 5,
            Deadline: time.Now().Add(1 * time.Hour),
        }
        distributor.SubmitWorkUnit(unit)
    }
    
    // Wait for distribution
    time.Sleep(15 * time.Second)
    
    // Check distribution across workers
    for _, worker := range workers {
        stats, err := distributor.GetWorkerStats(worker.ID)
        require.NoError(t, err)
        
        t.Logf("Worker %s: %d active units", worker.ID, stats.ActiveUnits)
        
        // Should have some work based on capacity
        expectedMin := int(worker.Capabilities.CPUCores) / 2
        assert.GreaterOrEqual(t, stats.ActiveUnits, expectedMin)
    }
}

func BenchmarkWorkDistribution(b *testing.B) {
    distributor := NewWorkDistributor(nil)
    
    // Register 100 workers
    for i := 0; i < 100; i++ {
        worker := &Worker{
            ID: fmt.Sprintf("worker-%d", i),
            Capabilities: ResourceCapabilities{
                CPUCores: float64(4 + i%4),
                MemoryMB: uint64((4 + i%4) * 4096),
            },
        }
        distributor.RegisterWorker(worker)
    }
    
    b.ResetTimer()
    
    // Submit work units
    for i := 0; i < b.N; i++ {
        unit := &WorkUnit{
            ID:    fmt.Sprintf("bench-%d", i),
            JobID: "bench-job",
            Requirements: ResourceRequirements{
                CPUCores: float64(1 + i%3),
                MemoryMB: uint64((1 + i%3) * 1024),
            },
            Priority: i % 10,
            Deadline: time.Now().Add(1 * time.Hour),
        }
        distributor.SubmitWorkUnit(unit)
    }
}
```

## Deployment Configuration

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: distributor-config
  namespace: blackhole-compute
data:
  config.yaml: |
    max_workers_per_unit: 3
    assignment_timeout: 5m
    heartbeat_interval: 30s
    worker_timeout: 2m
    retry_backoff: 1m
    validation_threshold: 2
    reputation_threshold: 0.5
    load_balancing_strategy: weighted-random
    
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: work-distributor
  namespace: blackhole-compute
spec:
  replicas: 3
  selector:
    matchLabels:
      app: work-distributor
  template:
    metadata:
      labels:
        app: work-distributor
    spec:
      containers:
      - name: distributor
        image: blackhole/work-distributor:latest
        ports:
        - containerPort: 8080
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        - name: METRICS_PORT
          value: "9090"
        volumeMounts:
        - name: config
          mountPath: /etc/distributor
        resources:
          requests:
            memory: "1Gi"
            cpu: "1"
          limits:
            memory: "2Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: distributor-config
---
apiVersion: v1
kind: Service
metadata:
  name: distributor-service
  namespace: blackhole-compute
spec:
  selector:
    app: work-distributor
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP
```

## Security Considerations

1. **Worker Authentication**: Token-based authentication
2. **Work Validation**: Cryptographic result verification
3. **Resource Isolation**: Prevent resource exhaustion
4. **Reputation System**: Identify malicious workers
5. **Rate Limiting**: Prevent DoS attacks
6. **Encrypted Communication**: TLS for all connections

## Performance Optimizations

1. **Efficient Scheduling**: Priority queue with O(log n) operations
2. **Load Balancing**: Multiple strategies for optimal distribution
3. **Caching**: Redis for assignment state
4. **Batch Operations**: Process multiple units together
5. **Connection Pooling**: Reuse HTTP connections
6. **Metrics Collection**: Prometheus for monitoring