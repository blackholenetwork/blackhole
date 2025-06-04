package utils

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// HealthChecker provides health check functionality for plugins
type HealthChecker struct {
	mu            sync.RWMutex
	checks        map[string]HealthCheckFunc
	lastResults   map[string]HealthCheckResult
	checkInterval time.Duration
	done          chan struct{}
	wg            sync.WaitGroup
}

// HealthCheckFunc is a function that performs a health check
type HealthCheckFunc func(ctx context.Context) error

// HealthCheckResult stores the result of a health check
type HealthCheckResult struct {
	Healthy   bool
	Error     error
	Timestamp time.Time
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(checkInterval time.Duration) *HealthChecker {
	return &HealthChecker{
		checks:        make(map[string]HealthCheckFunc),
		lastResults:   make(map[string]HealthCheckResult),
		checkInterval: checkInterval,
		done:          make(chan struct{}),
	}
}

// RegisterCheck registers a health check
func (hc *HealthChecker) RegisterCheck(name string, check HealthCheckFunc) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.checks[name] = check
}

// Start begins periodic health checks
func (hc *HealthChecker) Start(ctx context.Context) {
	hc.wg.Add(1)
	go hc.run(ctx)
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	close(hc.done)
	hc.wg.Wait()
}

// run performs periodic health checks
func (hc *HealthChecker) run(ctx context.Context) {
	defer hc.wg.Done()
	
	ticker := time.NewTicker(hc.checkInterval)
	defer ticker.Stop()
	
	// Run initial checks
	hc.runChecks(ctx)
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-hc.done:
			return
		case <-ticker.C:
			hc.runChecks(ctx)
		}
	}
}

// runChecks executes all registered health checks
func (hc *HealthChecker) runChecks(ctx context.Context) {
	hc.mu.RLock()
	checks := make(map[string]HealthCheckFunc)
	for name, check := range hc.checks {
		checks[name] = check
	}
	hc.mu.RUnlock()
	
	results := make(map[string]HealthCheckResult)
	
	// Run checks in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for name, check := range checks {
		wg.Add(1)
		go func(name string, check HealthCheckFunc) {
			defer wg.Done()
			
			// Create timeout context for individual check
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			
			err := check(checkCtx)
			
			mu.Lock()
			results[name] = HealthCheckResult{
				Healthy:   err == nil,
				Error:     err,
				Timestamp: time.Now(),
			}
			mu.Unlock()
		}(name, check)
	}
	
	wg.Wait()
	
	// Update results
	hc.mu.Lock()
	for name, result := range results {
		hc.lastResults[name] = result
	}
	hc.mu.Unlock()
}

// GetHealth returns the overall health status
func (hc *HealthChecker) GetHealth() plugin.Health {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	health := plugin.Health{
		Status:    plugin.HealthStatusHealthy,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}
	
	unhealthyCount := 0
	totalChecks := len(hc.lastResults)
	
	checkDetails := make(map[string]interface{})
	
	for name, result := range hc.lastResults {
		checkInfo := map[string]interface{}{
			"healthy":   result.Healthy,
			"timestamp": result.Timestamp,
		}
		
		if !result.Healthy {
			unhealthyCount++
			if result.Error != nil {
				checkInfo["error"] = result.Error.Error()
			}
		}
		
		checkDetails[name] = checkInfo
	}
	
	health.Details["checks"] = checkDetails
	health.Details["total_checks"] = totalChecks
	health.Details["healthy_checks"] = totalChecks - unhealthyCount
	
	// Determine overall status
	if unhealthyCount == 0 {
		health.Status = plugin.HealthStatusHealthy
		health.Message = fmt.Sprintf("All %d checks passing", totalChecks)
	} else if unhealthyCount < totalChecks {
		health.Status = plugin.HealthStatusDegraded
		health.Message = fmt.Sprintf("%d of %d checks failing", unhealthyCount, totalChecks)
	} else {
		health.Status = plugin.HealthStatusUnhealthy
		health.Message = "All checks failing"
	}
	
	return health
}

// IsHealthy returns true if all checks are passing
func (hc *HealthChecker) IsHealthy() bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	for _, result := range hc.lastResults {
		if !result.Healthy {
			return false
		}
	}
	
	return true
}

// Common health check functions

// CheckDependency creates a health check for a dependency
func CheckDependency(name string, checkFunc func() error) HealthCheckFunc {
	return func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return fmt.Errorf("check timeout for %s", name)
		default:
			if err := checkFunc(); err != nil {
				return fmt.Errorf("%s unhealthy: %w", name, err)
			}
			return nil
		}
	}
}

// CheckResource creates a health check for a resource
func CheckResource(resource string, threshold float64, getCurrentUsage func() float64) HealthCheckFunc {
	return func(ctx context.Context) error {
		usage := getCurrentUsage()
		if usage > threshold {
			return fmt.Errorf("%s usage %.1f%% exceeds threshold %.1f%%", resource, usage*100, threshold*100)
		}
		return nil
	}
}

// CheckEndpoint creates a health check for an endpoint
func CheckEndpoint(url string) HealthCheckFunc {
	return func(ctx context.Context) error {
		// Simple connectivity check (would be more sophisticated in practice)
		// This is just an example
		return nil
	}
}

// CombineHealthCheckers combines multiple health checkers
func CombineHealthCheckers(checkers ...*HealthChecker) plugin.Health {
	combined := plugin.Health{
		Status:    plugin.HealthStatusHealthy,
		LastCheck: time.Now(),
		Details:   make(map[string]interface{}),
	}
	
	allHealthy := true
	anyHealthy := false
	
	for i, checker := range checkers {
		health := checker.GetHealth()
		combined.Details[fmt.Sprintf("checker_%d", i)] = health
		
		if health.Status == plugin.HealthStatusHealthy {
			anyHealthy = true
		} else {
			allHealthy = false
		}
	}
	
	if allHealthy {
		combined.Status = plugin.HealthStatusHealthy
		combined.Message = "All subsystems healthy"
	} else if anyHealthy {
		combined.Status = plugin.HealthStatusDegraded
		combined.Message = "Some subsystems degraded"
	} else {
		combined.Status = plugin.HealthStatusUnhealthy
		combined.Message = "All subsystems unhealthy"
	}
	
	return combined
}