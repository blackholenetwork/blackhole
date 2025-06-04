package utils

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LifecycleManager helps manage plugin lifecycle operations
type LifecycleManager struct {
	mu          sync.RWMutex
	state       State
	transitions chan stateTransition
	done        chan struct{}
	wg          sync.WaitGroup
}

// State represents the lifecycle state
type State int

const (
	StateUninitialized State = iota
	StateInitializing
	StateInitialized
	StateStarting
	StateRunning
	StateStopping
	StateStopped
	StateError
)

// String returns the string representation of a state
func (s State) String() string {
	switch s {
	case StateUninitialized:
		return "uninitialized"
	case StateInitializing:
		return "initializing"
	case StateInitialized:
		return "initialized"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

type stateTransition struct {
	from     State
	to       State
	callback func()
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager() *LifecycleManager {
	lm := &LifecycleManager{
		state:       StateUninitialized,
		transitions: make(chan stateTransition, 10),
		done:        make(chan struct{}),
	}
	
	// Start state machine
	lm.wg.Add(1)
	go lm.run()
	
	return lm
}

// run processes state transitions
func (lm *LifecycleManager) run() {
	defer lm.wg.Done()
	
	for {
		select {
		case <-lm.done:
			return
		case transition := <-lm.transitions:
			lm.mu.Lock()
			if lm.state == transition.from {
				lm.state = transition.to
				lm.mu.Unlock()
				
				if transition.callback != nil {
					transition.callback()
				}
			} else {
				lm.mu.Unlock()
			}
		}
	}
}

// GetState returns the current state
func (lm *LifecycleManager) GetState() State {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.state
}

// TransitionTo attempts to transition to a new state
func (lm *LifecycleManager) TransitionTo(newState State) error {
	lm.mu.RLock()
	currentState := lm.state
	lm.mu.RUnlock()
	
	// Validate transition
	if !isValidTransition(currentState, newState) {
		return fmt.Errorf("invalid transition from %s to %s", currentState, newState)
	}
	
	// Queue transition
	select {
	case lm.transitions <- stateTransition{from: currentState, to: newState}:
		// Wait for transition to complete
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		
		for {
			select {
			case <-timeout.C:
				return fmt.Errorf("state transition timeout")
			default:
				if lm.GetState() == newState {
					return nil
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	default:
		return fmt.Errorf("transition queue full")
	}
}

// OnTransition registers a callback for a specific state transition
func (lm *LifecycleManager) OnTransition(from, to State, callback func()) {
	go func() {
		for {
			select {
			case <-lm.done:
				return
			default:
				lm.mu.RLock()
				currentState := lm.state
				lm.mu.RUnlock()
				
				if currentState == from {
					select {
					case lm.transitions <- stateTransition{from: from, to: to, callback: callback}:
						return
					case <-lm.done:
						return
					}
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// WaitForState waits for a specific state with timeout
func (lm *LifecycleManager) WaitForState(state State, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-timer.C:
			return fmt.Errorf("timeout waiting for state %s", state)
		case <-ticker.C:
			if lm.GetState() == state {
				return nil
			}
		}
	}
}

// IsRunning returns true if the lifecycle is in running state
func (lm *LifecycleManager) IsRunning() bool {
	return lm.GetState() == StateRunning
}

// IsStopped returns true if the lifecycle is in stopped state
func (lm *LifecycleManager) IsStopped() bool {
	state := lm.GetState()
	return state == StateStopped || state == StateUninitialized
}

// IsError returns true if the lifecycle is in error state
func (lm *LifecycleManager) IsError() bool {
	return lm.GetState() == StateError
}

// SetError transitions to error state
func (lm *LifecycleManager) SetError() {
	lm.mu.Lock()
	lm.state = StateError
	lm.mu.Unlock()
}

// Close shuts down the lifecycle manager
func (lm *LifecycleManager) Close() {
	close(lm.done)
	lm.wg.Wait()
	close(lm.transitions)
}

// isValidTransition checks if a state transition is valid
func isValidTransition(from, to State) bool {
	validTransitions := map[State][]State{
		StateUninitialized: {StateInitializing},
		StateInitializing:  {StateInitialized, StateError},
		StateInitialized:   {StateStarting, StateStopped},
		StateStarting:      {StateRunning, StateError, StateStopped},
		StateRunning:       {StateStopping, StateError},
		StateStopping:      {StateStopped, StateError},
		StateStopped:       {StateInitializing}, // Allow restart
		StateError:         {StateInitializing, StateStopped},
	}
	
	allowed, exists := validTransitions[from]
	if !exists {
		return false
	}
	
	for _, state := range allowed {
		if state == to {
			return true
		}
	}
	
	return false
}

// RunWithLifecycle runs a function with proper lifecycle management
func RunWithLifecycle(ctx context.Context, lm *LifecycleManager, fn func(context.Context) error) error {
	// Ensure we're in the right state
	if err := lm.TransitionTo(StateStarting); err != nil {
		return fmt.Errorf("failed to transition to starting: %w", err)
	}
	
	// Transition to running
	if err := lm.TransitionTo(StateRunning); err != nil {
		lm.SetError()
		return fmt.Errorf("failed to transition to running: %w", err)
	}
	
	// Run the function
	errChan := make(chan error, 1)
	go func() {
		errChan <- fn(ctx)
	}()
	
	// Wait for completion or context cancellation
	select {
	case err := <-errChan:
		if err != nil {
			lm.SetError()
			return err
		}
		return lm.TransitionTo(StateStopped)
	case <-ctx.Done():
		if err := lm.TransitionTo(StateStopping); err != nil {
			lm.SetError()
		}
		<-errChan // Wait for function to complete
		return lm.TransitionTo(StateStopped)
	}
}