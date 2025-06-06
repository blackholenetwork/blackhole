// Package pool provides reusable worker pool implementation
package pool

import (
	"context"
	"sync"
)

// Task represents a unit of work
type Task func()

// WorkerPool manages a pool of workers
type WorkerPool struct {
	workers   int
	taskQueue chan Task
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers:   workers,
		taskQueue: make(chan Task, workers*2),
		ctx:       ctx,
		cancel:    cancel,
	}

	pool.start()
	return pool
}

// start initializes workers
func (p *WorkerPool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
}

// worker processes tasks
func (p *WorkerPool) worker() {
	defer p.wg.Done()

	for {
		select {
		case task, ok := <-p.taskQueue:
			if !ok {
				return
			}
			task()
		case <-p.ctx.Done():
			return
		}
	}
}

// Submit adds a task to the pool
func (p *WorkerPool) Submit(task Task) {
	select {
	case p.taskQueue <- task:
	case <-p.ctx.Done():
		// Pool is shutting down
	}
}

// SubmitWait submits a task and waits for completion
func (p *WorkerPool) SubmitWait(task Task) {
	done := make(chan struct{})
	p.Submit(func() {
		task()
		close(done)
	})
	<-done
}

// Wait waits for all tasks to complete
func (p *WorkerPool) Wait() {
	close(p.taskQueue)
	p.wg.Wait()
}

// Stop gracefully shuts down the pool
func (p *WorkerPool) Stop() {
	p.cancel()
	close(p.taskQueue)
	p.wg.Wait()
}

// BufferPool provides pooling for byte buffers
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf []byte) {
	// Clear buffer before returning to pool
	for i := range buf {
		buf[i] = 0
	}
	p.pool.Put(&buf)
}
