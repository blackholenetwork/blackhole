// Package retry provides a simple, reusable retry mechanism with exponential backoff
package retry

import (
	"context"
	"fmt"
	"math"
	"time"
)

// Operation represents a retryable operation
type Operation func() error

// Config holds retry configuration
type Config struct {
	Attempts   int
	Delay      time.Duration
	MaxDelay   time.Duration
	Multiplier float64
	OnRetry    func(n int, err error)
	RetryIf    func(error) bool
}

// Option configures retry behavior
type Option func(*Config)

// Default configuration
var defaultConfig = Config{
	Attempts:   3,
	Delay:      1 * time.Second,
	MaxDelay:   30 * time.Second,
	Multiplier: 2.0,
	RetryIf:    func(err error) bool { return err != nil },
}

// Do executes the operation with retry logic
func Do(operation Operation, opts ...Option) error {
	config := defaultConfig
	for _, opt := range opts {
		opt(&config)
	}

	var err error
	for attempt := 0; attempt < config.Attempts; attempt++ {
		err = operation()

		// Success
		if err == nil {
			return nil
		}

		// Check if we should retry
		if !config.RetryIf(err) {
			return err
		}

		// Last attempt failed
		if attempt == config.Attempts-1 {
			return fmt.Errorf("operation failed after %d attempts: %w", config.Attempts, err)
		}

		// Calculate delay
		delay := time.Duration(float64(config.Delay) * math.Pow(config.Multiplier, float64(attempt)))
		if delay > config.MaxDelay {
			delay = config.MaxDelay
		}

		// Notify retry
		if config.OnRetry != nil {
			config.OnRetry(attempt+1, err)
		}

		time.Sleep(delay)
	}

	return err
}

// DoWithContext executes operation with context support
func DoWithContext(ctx context.Context, operation func(context.Context) error, opts ...Option) error {
	return Do(func() error {
		return operation(ctx)
	}, opts...)
}

// Options

// Attempts sets the maximum number of attempts
func Attempts(n int) Option {
	return func(c *Config) {
		c.Attempts = n
	}
}

// Delay sets the initial delay between retries
func Delay(d time.Duration) Option {
	return func(c *Config) {
		c.Delay = d
	}
}

// MaxDelay sets the maximum delay between retries
func MaxDelay(d time.Duration) Option {
	return func(c *Config) {
		c.MaxDelay = d
	}
}

// OnRetry sets a callback for each retry attempt
func OnRetry(fn func(n int, err error)) Option {
	return func(c *Config) {
		c.OnRetry = fn
	}
}

// If sets a function to determine if an error is retryable
func If(fn func(error) bool) Option {
	return func(c *Config) {
		c.RetryIf = fn
	}
}
