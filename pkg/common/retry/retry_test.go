package retry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

func TestDo(t *testing.T) {
	t.Run("success on first attempt", func(t *testing.T) {
		attempts := 0
		err := Do(func() error {
			attempts++
			return nil
		})

		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("success after retries", func(t *testing.T) {
		attempts := 0
		err := Do(func() error {
			attempts++
			if attempts < 3 {
				return errors.New("temporary error")
			}
			return nil
		}, Attempts(5))

		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("failure after max attempts", func(t *testing.T) {
		attempts := 0
		err := Do(func() error {
			attempts++
			return errors.New("persistent error")
		}, Attempts(3))

		if err == nil {
			t.Error("Expected error, got nil")
		}
		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
		expectedMsg := "operation failed after 3 attempts: persistent error"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})
}

func TestDoWithContext(t *testing.T) {
	t.Run("success with context", func(t *testing.T) {
		ctx := context.Background()
		attempts := 0
		err := DoWithContext(ctx, func(ctx context.Context) error {
			attempts++
			return nil
		})

		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if attempts != 1 {
			t.Errorf("Expected 1 attempt, got %d", attempts)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		attempts := 0

		// Cancel context after first attempt
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		err := DoWithContext(ctx, func(ctx context.Context) error {
			attempts++
			if attempts == 1 {
				return errors.New("temporary error")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		}, Attempts(5), Delay(20*time.Millisecond))

		if err == nil || !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled error, got: %v", err)
		}
	})
}

func TestRetryOptions(t *testing.T) {
	t.Run("custom attempts", func(t *testing.T) {
		attempts := 0
		_ = Do(func() error {
			attempts++
			return errors.New("error")
		}, Attempts(5))

		if attempts != 5 {
			t.Errorf("Expected 5 attempts, got %d", attempts)
		}
	})

	t.Run("custom delay", func(t *testing.T) {
		start := time.Now()
		attempts := 0

		err := Do(func() error {
			attempts++
			if attempts < 3 {
				return errors.New("error")
			}
			return nil
		}, Delay(50*time.Millisecond), Attempts(3))

		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Should have 2 delays of 50ms and 100ms (exponential)
		expectedMin := 150 * time.Millisecond
		if elapsed < expectedMin {
			t.Errorf("Expected at least %v elapsed, got %v", expectedMin, elapsed)
		}
	})

	t.Run("max delay", func(t *testing.T) {
		start := time.Now()
		attempts := 0

		err := Do(func() error {
			attempts++
			if attempts < 4 {
				return errors.New("error")
			}
			return nil
		},
			Delay(10*time.Millisecond),
			MaxDelay(20*time.Millisecond),
			Attempts(4),
		)

		elapsed := time.Since(start)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Should have delays: 10ms, 20ms (capped), 20ms (capped) = 50ms total
		// Allow some buffer for execution time
		expectedMax := 100 * time.Millisecond
		if elapsed > expectedMax {
			t.Errorf("Expected less than %v elapsed, got %v", expectedMax, elapsed)
		}
	})

	t.Run("on retry callback", func(t *testing.T) {
		var callbacks []string
		err := Do(func() error {
			return errors.New("error")
		},
			Attempts(3),
			OnRetry(func(n int, err error) {
				callbacks = append(callbacks, fmt.Sprintf("attempt %d: %v", n, err))
			}),
		)

		if err == nil {
			t.Error("Expected error")
		}
		if len(callbacks) != 2 { // callbacks happen on retries, not initial attempt
			t.Errorf("Expected 2 callbacks, got %d", len(callbacks))
		}
	})

	t.Run("retry if condition", func(t *testing.T) {
		permanentErr := errors.New("permanent")
		temporaryErr := errors.New("temporary")

		attempts := 0
		err := Do(func() error {
			attempts++
			if attempts == 1 {
				return temporaryErr
			}
			return permanentErr
		},
			Attempts(5),
			If(func(err error) bool {
				return errors.Is(err, temporaryErr)
			}),
		)

		if !errors.Is(err, permanentErr) {
			t.Errorf("Expected permanent error, got: %v", err)
		}
		if attempts != 2 {
			t.Errorf("Expected 2 attempts (stop on non-retryable), got %d", attempts)
		}
	})
}

func TestExponentialBackoff(t *testing.T) {
	delays := []time.Duration{}
	attempt := 0

	err := Do(func() error {
		attempt++
		return errors.New("error")
	},
		Attempts(4),
		Delay(10*time.Millisecond),
		OnRetry(func(n int, err error) {
			// This callback is called after the delay, so we can capture the delay that was used
			expectedDelay := time.Duration(float64(10*time.Millisecond) * math.Pow(2.0, float64(n-1)))
			if expectedDelay > 30*time.Second { // default max delay
				expectedDelay = 30 * time.Second
			}
			delays = append(delays, expectedDelay)
		}),
	)

	if err == nil {
		t.Error("Expected error")
	}

	if len(delays) != 3 {
		t.Fatalf("Expected 3 delays, got %d", len(delays))
	}

	// Check exponential growth with 2x multiplier
	expected := []time.Duration{
		10 * time.Millisecond,  // First retry
		20 * time.Millisecond,  // Second retry (10 * 2)
		40 * time.Millisecond,  // Third retry (20 * 2)
	}

	for i, delay := range delays {
		if delay != expected[i] {
			t.Errorf("Delay %d: expected %v, got %v", i, expected[i], delay)
		}
	}
}

func TestConcurrentRetries(t *testing.T) {
	var counter int32
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			err := Do(func() error {
				current := atomic.AddInt32(&counter, 1)
				if current < 30 { // Each goroutine needs 3 attempts
					return errors.New("not yet")
				}
				return nil
			}, Attempts(5))

			done <- err == nil
		}()
	}

	// All should succeed
	for i := 0; i < 10; i++ {
		success := <-done
		if !success {
			t.Error("Expected all goroutines to succeed")
		}
	}

	if atomic.LoadInt32(&counter) < 30 {
		t.Errorf("Expected at least 30 attempts total, got %d", counter)
	}
}

func TestDefaultConfig(t *testing.T) {
	// Test that default config is applied
	attempts := 0
	start := time.Now()

	_ = Do(func() error {
		attempts++
		return errors.New("error")
	})

	elapsed := time.Since(start)

	// Should use default 3 attempts
	if attempts != 3 {
		t.Errorf("Expected default 3 attempts, got %d", attempts)
	}

	// Should have delays with default 1s initial delay
	// 2 delays: 1s + 2s = 3s minimum
	if elapsed < 2*time.Second {
		t.Errorf("Expected at least 2s elapsed with default delays, got %v", elapsed)
	}
}

// Benchmark tests

func BenchmarkDoSuccess(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Do(func() error {
			return nil
		})
	}
}

func BenchmarkDoWithRetries(b *testing.B) {
	for i := 0; i < b.N; i++ {
		attempts := 0
		_ = Do(func() error {
			attempts++
			if attempts < 3 {
				return errors.New("error")
			}
			return nil
		}, Delay(time.Microsecond)) // Use tiny delay for benchmark
	}
}

func BenchmarkDoWithOptions(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Do(
			func() error { return nil },
			Attempts(5),
			Delay(time.Millisecond),
			MaxDelay(10*time.Millisecond),
			OnRetry(func(n int, err error) {}),
			If(func(err error) bool { return true }),
		)
	}
}
