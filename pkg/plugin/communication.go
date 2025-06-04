package plugin

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Standard event types for plugin communication
const (
	// Resource events
	EventResourceAllocated = "resource.allocated"
	EventResourceReleased  = "resource.released"
	EventResourceDepleted  = "resource.depleted"

	// Data events
	EventDataStored    = "data.stored"
	EventDataRetrieved = "data.retrieved"
	EventDataDeleted   = "data.deleted"
	EventDataUpdated   = "data.updated"

	// Network events
	EventPeerConnected    = "network.peer.connected"
	EventPeerDisconnected = "network.peer.disconnected"
	EventNetworkLatency   = "network.latency.high"

	// Compute events
	EventJobQueued    = "compute.job.queued"
	EventJobStarted   = "compute.job.started"
	EventJobCompleted = "compute.job.completed"
	EventJobFailed    = "compute.job.failed"

	// Economic events
	EventCreditsEarned   = "economic.credits.earned"
	EventCreditsSpent    = "economic.credits.spent"
	EventQuotaExceeded   = "economic.quota.exceeded"
	EventSubscriptionChanged = "economic.subscription.changed"

	// System events
	EventHealthChanged = "system.health.changed"
	EventConfigUpdated = "system.config.updated"
	EventSystemConfigUpdated = "system.config.updated" // Alias for backward compatibility
	EventShutdownRequested = "system.shutdown.requested"
	
	// Plugin lifecycle events
	EventPluginStarted = "plugin.started"
	EventPluginStopped = "plugin.stopped"
)

// PluginRequest represents a synchronous request between plugins
type PluginRequest struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	From     string                 `json:"from"`
	To       string                 `json:"to"`
	Data     interface{}            `json:"data"`
	Headers  map[string]string      `json:"headers,omitempty"`
	Timeout  time.Duration          `json:"timeout"`
	Created  time.Time              `json:"created"`
}

// PluginResponse represents a response to a plugin request
type PluginResponse struct {
	ID      string                 `json:"id"`
	Status  int                    `json:"status"`
	Error   error                  `json:"error,omitempty"`
	Data    interface{}            `json:"data,omitempty"`
	Headers map[string]string      `json:"headers,omitempty"`
	Created time.Time              `json:"created"`
}

// PluginRequestHandler handles synchronous requests
type PluginRequestHandler interface {
	HandlePluginRequest(ctx context.Context, req PluginRequest) (PluginResponse, error)
}

// Message represents an async message for queue-based communication
type Message struct {
	ID        string                 `json:"id"`
	Topic     string                 `json:"topic"`
	Payload   interface{}            `json:"payload"`
	Headers   map[string]string      `json:"headers,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Retries   int                    `json:"retries"`
}

// MessageHandler processes messages from a queue
type MessageHandler func(ctx context.Context, msg Message) error

// SharedStore provides thread-safe shared data storage
type SharedStore struct {
	mu    sync.RWMutex
	data  map[string]interface{}
	watchers map[string][]func(key string, value interface{})
}

// NewSharedStore creates a new shared store
func NewSharedStore() *SharedStore {
	return &SharedStore{
		data:     make(map[string]interface{}),
		watchers: make(map[string][]func(key string, value interface{})),
	}
}

// Set stores a value and notifies watchers
func (s *SharedStore) Set(key string, value interface{}) {
	s.mu.Lock()
	s.data[key] = value
	watchers := s.watchers[key]
	s.mu.Unlock()

	// Notify watchers outside of lock
	for _, watcher := range watchers {
		watcher(key, value)
	}
}

// Get retrieves a value
func (s *SharedStore) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, exists := s.data[key]
	return value, exists
}

// Watch registers a callback for key changes
func (s *SharedStore) Watch(key string, callback func(key string, value interface{})) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchers[key] = append(s.watchers[key], callback)
}

// Delete removes a value
func (s *SharedStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	delete(s.watchers, key)
}

// MessageQueue provides async message queue functionality
type MessageQueue struct {
	mu       sync.RWMutex
	topics   map[string][]MessageHandler
	queues   map[string]chan Message
	workers  sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewMessageQueue creates a new message queue
func NewMessageQueue(ctx context.Context) *MessageQueue {
	ctx, cancel := context.WithCancel(ctx)
	return &MessageQueue{
		topics:   make(map[string][]MessageHandler),
		queues:   make(map[string]chan Message),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Subscribe registers a handler for a topic
func (mq *MessageQueue) Subscribe(topic string, handler MessageHandler) func() {
	mq.mu.Lock()
	defer mq.mu.Unlock()

	// Create queue if doesn't exist
	if _, exists := mq.queues[topic]; !exists {
		mq.queues[topic] = make(chan Message, 100)
		mq.startWorker(topic)
	}

	mq.topics[topic] = append(mq.topics[topic], handler)

	// Return unsubscribe function
	return func() {
		mq.mu.Lock()
		defer mq.mu.Unlock()
		handlers := mq.topics[topic]
		for i, h := range handlers {
			if fmt.Sprintf("%p", h) == fmt.Sprintf("%p", handler) {
				mq.topics[topic] = append(handlers[:i], handlers[i+1:]...)
				break
			}
		}
	}
}

// Publish sends a message to a topic
func (mq *MessageQueue) Publish(topic string, payload interface{}) error {
	mq.mu.RLock()
	queue, exists := mq.queues[topic]
	mq.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no subscribers for topic: %s", topic)
	}

	msg := Message{
		ID:        generateID(),
		Topic:     topic,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	select {
	case queue <- msg:
		return nil
	case <-mq.ctx.Done():
		return mq.ctx.Err()
	default:
		return fmt.Errorf("queue full for topic: %s", topic)
	}
}

// startWorker starts a worker for a topic
func (mq *MessageQueue) startWorker(topic string) {
	mq.workers.Add(1)
	go func() {
		defer mq.workers.Done()
		queue := mq.queues[topic]

		for {
			select {
			case <-mq.ctx.Done():
				return
			case msg := <-queue:
				mq.processMessage(topic, msg)
			}
		}
	}()
}

// processMessage handles a message
func (mq *MessageQueue) processMessage(topic string, msg Message) {
	mq.mu.RLock()
	handlers := mq.topics[topic]
	mq.mu.RUnlock()

	for _, handler := range handlers {
		ctx, cancel := context.WithTimeout(mq.ctx, 30*time.Second)
		err := handler(ctx, msg)
		cancel()

		if err != nil {
			// Handle retry logic
			if msg.Retries < 3 {
				msg.Retries++
				mq.Publish(topic, msg.Payload)
			}
		}
	}
}

// Stop gracefully shuts down the message queue
func (mq *MessageQueue) Stop() {
	mq.cancel()
	mq.workers.Wait()
}

// Communication helpers

// generateID creates a unique ID
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// WrapError wraps an error with plugin context
func WrapError(pluginName string, operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("plugin %s: %s failed: %w", pluginName, operation, err)
}

// ValidateEventType checks if an event type follows naming convention
func ValidateEventType(eventType string) error {
	// Event type should follow: domain.object.action
	parts := strings.Split(eventType, ".")
	if len(parts) != 3 {
		return fmt.Errorf("event type must follow domain.object.action pattern, got: %s", eventType)
	}
	return nil
}