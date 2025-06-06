package pool

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewWorkerPool(t *testing.T) {
	pool := NewWorkerPool(5)
	if pool == nil {
		t.Fatal("NewWorkerPool returned nil")
	}
	if pool.workers != 5 {
		t.Errorf("Expected 5 workers, got %d", pool.workers)
	}
	pool.Stop()
}

func TestWorkerPoolSubmit(t *testing.T) {
	pool := NewWorkerPool(3)
	defer pool.Stop()

	var counter int32
	var wg sync.WaitGroup

	// Submit 10 tasks
	for i := 0; i < 10; i++ {
		wg.Add(1)
		pool.Submit(func() {
			atomic.AddInt32(&counter, 1)
			wg.Done()
		})
	}

	wg.Wait()

	if atomic.LoadInt32(&counter) != 10 {
		t.Errorf("Expected counter to be 10, got %d", counter)
	}
}

func TestWorkerPoolSubmitWait(t *testing.T) {
	pool := NewWorkerPool(2)
	defer pool.Stop()

	var executed bool
	pool.SubmitWait(func() {
		time.Sleep(10 * time.Millisecond)
		executed = true
	})

	if !executed {
		t.Error("Task was not executed")
	}
}

func TestWorkerPoolConcurrency(t *testing.T) {
	pool := NewWorkerPool(5)
	defer pool.Stop()

	var concurrent int32
	var maxConcurrent int32
	var wg sync.WaitGroup

	// Submit 20 tasks that take some time
	for i := 0; i < 20; i++ {
		wg.Add(1)
		pool.Submit(func() {
			current := atomic.AddInt32(&concurrent, 1)
			defer atomic.AddInt32(&concurrent, -1)

			// Update max concurrent
			for {
				max := atomic.LoadInt32(&maxConcurrent)
				if current <= max || atomic.CompareAndSwapInt32(&maxConcurrent, max, current) {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
			wg.Done()
		})
	}

	wg.Wait()

	// Should not exceed worker count
	if maxConcurrent > 5 {
		t.Errorf("Max concurrent tasks (%d) exceeded worker count (5)", maxConcurrent)
	}

	// Should have used multiple workers
	if maxConcurrent < 2 {
		t.Errorf("Expected to use multiple workers, but max concurrent was %d", maxConcurrent)
	}
}

func TestWorkerPoolWait(t *testing.T) {
	pool := NewWorkerPool(3)

	var counter int32
	for i := 0; i < 10; i++ {
		pool.Submit(func() {
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&counter, 1)
		})
	}

	pool.Wait()

	if atomic.LoadInt32(&counter) != 10 {
		t.Errorf("Expected all tasks to complete, got %d/10", counter)
	}
}

func TestWorkerPoolStop(t *testing.T) {
	pool := NewWorkerPool(3)

	// Submit a context-aware task that can be canceled
	started := make(chan struct{})
	pool.Submit(func() {
		close(started)
		// Simulate context-aware work that can be interrupted
		select {
		case <-pool.ctx.Done():
			return // Task canceled
		case <-time.After(1 * time.Second):
			// This shouldn't complete before context cancellation
		}
	})

	// Wait for task to start
	<-started

	// Stop the pool
	done := make(chan struct{})
	go func() {
		pool.Stop()
		close(done)
	}()

	// Stop should complete reasonably quickly since task respects context cancellation
	select {
	case <-done:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("Stop() took too long")
	}
}

func TestWorkerPoolSubmitAfterStop(t *testing.T) {
	pool := NewWorkerPool(2)
	pool.Stop()

	// Submit should not panic after stop
	executed := false
	pool.Submit(func() {
		executed = true
	})

	// Give it a moment to potentially execute
	time.Sleep(10 * time.Millisecond)

	if executed {
		t.Error("Task should not execute after pool is stopped")
	}
}

func TestWorkerPoolPanic(t *testing.T) {
	pool := NewWorkerPool(2)
	defer pool.Stop()

	// Submit a task that panics
	pool.Submit(func() {
		panic("test panic")
	})

	// Submit another task to ensure pool continues working
	executed := make(chan bool, 1)
	pool.Submit(func() {
		executed <- true
	})

	select {
	case <-executed:
		// Success - pool recovered from panic
	case <-time.After(100 * time.Millisecond):
		t.Error("Pool did not recover from panic")
	}
}

func TestWorkerPoolContextCancellation(t *testing.T) {
	pool := NewWorkerPool(2)

	// Submit tasks that check context
	var cancelled int32
	for i := 0; i < 5; i++ {
		pool.Submit(func() {
			select {
			case <-pool.ctx.Done():
				atomic.AddInt32(&cancelled, 1)
			case <-time.After(1 * time.Second):
			}
		})
	}

	// Stop the pool (which cancels context)
	pool.Stop()

	// Check that context was cancelled
	if pool.ctx.Err() != context.Canceled {
		t.Error("Expected context to be cancelled")
	}
}

// Buffer Pool Tests

func TestNewBufferPool(t *testing.T) {
	pool := NewBufferPool(1024)
	if pool == nil {
		t.Fatal("NewBufferPool returned nil")
	}
}

func TestBufferPoolGetPut(t *testing.T) {
	pool := NewBufferPool(1024)

	// Get a buffer
	buf := pool.Get()
	if len(buf) != 1024 {
		t.Errorf("Expected buffer size 1024, got %d", len(buf))
	}

	// Write some data
	copy(buf, []byte("test data"))

	// Put it back
	pool.Put(buf)

	// Get another buffer
	buf2 := pool.Get()

	// Should be cleared
	for i, b := range buf2 {
		if b != 0 {
			t.Errorf("Buffer not cleared at position %d, got %d", i, b)
			break
		}
	}
}

func TestBufferPoolConcurrent(t *testing.T) {
	pool := NewBufferPool(512)
	var wg sync.WaitGroup

	// Multiple goroutines getting and putting buffers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				buf := pool.Get()
				if len(buf) != 512 {
					t.Errorf("Goroutine %d: Expected buffer size 512, got %d", id, len(buf))
				}
				// Write some data
				buf[0] = byte(id)
				buf[1] = byte(j)
				// Put it back
				pool.Put(buf)
			}
		}(i)
	}

	wg.Wait()
}

func TestBufferPoolReuseEfficiency(t *testing.T) {
	pool := NewBufferPool(1024)

	// Get and put multiple times
	buffers := make([][]byte, 10)
	for i := range buffers {
		buffers[i] = pool.Get()
	}

	// Put them all back
	for _, buf := range buffers {
		pool.Put(buf)
	}

	// Get them again - should reuse from pool
	reusedBuffers := make([][]byte, 10)
	for i := range reusedBuffers {
		reusedBuffers[i] = pool.Get()
	}

	// We can't guarantee exact reuse order, but buffers should be from pool
	// Just verify they have the right size
	for i, buf := range reusedBuffers {
		if len(buf) != 1024 {
			t.Errorf("Buffer %d has wrong size: %d", i, len(buf))
		}
	}
}

// Benchmark tests

func BenchmarkWorkerPoolSubmit(b *testing.B) {
	pool := NewWorkerPool(4)
	defer pool.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Submit(func() {
			// Minimal work
			_ = 1 + 1
		})
	}
}

func BenchmarkWorkerPoolSubmitWait(b *testing.B) {
	pool := NewWorkerPool(4)
	defer pool.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.SubmitWait(func() {
			// Minimal work
			_ = 1 + 1
		})
	}
}

func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := NewBufferPool(4096)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

func BenchmarkBufferPoolParallel(b *testing.B) {
	pool := NewBufferPool(4096)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			buf[0] = 1 // minimal work
			pool.Put(buf)
		}
	})
}
