// Package cache provides a generic, thread-safe cache implementation
package cache

import (
	"sync"
	"time"
)

// Cache is a generic cache with TTL support
type Cache[K comparable, V any] struct {
	mu          sync.RWMutex
	items       map[K]*item[V]
	ttl         time.Duration
	maxSize     int
	onEvict     func(K, V)
	stopCleanup chan struct{}
}

type item[V any] struct {
	value      V
	expiration time.Time
	createdAt  time.Time // Add creation time for better eviction policy
}

// Option configures cache behavior
type Option[K comparable, V any] func(*Cache[K, V])

// New creates a new cache
func New[K comparable, V any](opts ...Option[K, V]) *Cache[K, V] {
	c := &Cache[K, V]{
		items:       make(map[K]*item[V]),
		ttl:         0, // No expiration by default
		maxSize:     0, // No size limit by default
		stopCleanup: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Start cleanup goroutine if TTL is set and reasonable
	if c.ttl > 0 {
		go c.cleanupLoop()
	}

	return c
}

// Set adds or updates an item in the cache
func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiration := time.Time{}
	if c.ttl > 0 {
		expiration = time.Now().Add(c.ttl)
	}

	c.items[key] = &item[V]{
		value:      value,
		expiration: expiration,
		createdAt:  time.Now(),
	}

	// Evict oldest if over size limit
	if c.maxSize > 0 && len(c.items) > c.maxSize {
		c.evictOldest()
	}
}

// Get retrieves an item from the cache
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		var zero V
		return zero, false
	}

	// Check expiration
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		var zero V
		return zero, false
	}

	return item.value, true
}

// Delete removes an item from the cache
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if item, ok := c.items[key]; ok {
		delete(c.items, key)
		if c.onEvict != nil {
			c.onEvict(key, item.value)
		}
	}
}

// Clear removes all items from the cache
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.onEvict != nil {
		for k, v := range c.items {
			c.onEvict(k, v.value)
		}
	}

	c.items = make(map[K]*item[V])
}

// Size returns the number of items in the cache
func (c *Cache[K, V]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Close stops the cleanup goroutine
func (c *Cache[K, V]) Close() {
	close(c.stopCleanup)
}

// cleanupLoop periodically removes expired items
func (c *Cache[K, V]) cleanupLoop() {
	// Use a reasonable cleanup interval (minimum 1 second)
	interval := c.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired items
func (c *Cache[K, V]) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, item := range c.items {
		if !item.expiration.IsZero() && now.After(item.expiration) {
			delete(c.items, k)
			if c.onEvict != nil {
				c.onEvict(k, item.value)
			}
		}
	}
}

// evictOldest removes the oldest item based on creation time
func (c *Cache[K, V]) evictOldest() {
	var oldestKey K
	var oldestTime time.Time
	first := true

	for k, item := range c.items {
		// Use creation time for eviction policy to ensure deterministic behavior
		if first || item.createdAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = item.createdAt
			first = false
		}
	}

	if !first {
		item := c.items[oldestKey]
		delete(c.items, oldestKey)
		if c.onEvict != nil {
			c.onEvict(oldestKey, item.value)
		}
	}
}

// Options

// WithTTL sets the TTL for cache items
func WithTTL[K comparable, V any](ttl time.Duration) Option[K, V] {
	return func(c *Cache[K, V]) {
		c.ttl = ttl
	}
}

// WithMaxSize sets the maximum number of items
func WithMaxSize[K comparable, V any](size int) Option[K, V] {
	return func(c *Cache[K, V]) {
		c.maxSize = size
	}
}

// WithEvictCallback sets a callback for evicted items
func WithEvictCallback[K comparable, V any](fn func(K, V)) Option[K, V] {
	return func(c *Cache[K, V]) {
		c.onEvict = fn
	}
}
