package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// Example plugin that demonstrates communication patterns
type CommunicatingPlugin struct {
	*plugin.BasePlugin
	registry *plugin.Registry
}

func NewCommunicatingPlugin(registry *plugin.Registry) *CommunicatingPlugin {
	info := plugin.Info{
		Name:         "communicator",
		Version:      "1.0.0",
		Description:  "Example plugin showing communication patterns",
		Capabilities: []string{string(plugin.CapabilityCustom)},
	}

	return &CommunicatingPlugin{
		BasePlugin: plugin.NewBasePlugin(info),
		registry:   registry,
	}
}

func (p *CommunicatingPlugin) Start(ctx context.Context) error {
	// 1. Event-based communication
	p.subscribeToEvents()

	// 2. Shared store usage
	p.useSharedStore()

	// 3. Message queue usage
	p.useMessageQueue(ctx)

	// 4. Direct service calls
	p.useDirectCalls()

	return p.BasePlugin.Start(ctx)
}

func (p *CommunicatingPlugin) subscribeToEvents() {
	// Subscribe to resource events
	p.registry.Subscribe(plugin.EventResourceAllocated, func(event plugin.Event) {
		log.Printf("Resource allocated: %v", event.Data)
	})

	// Subscribe to data events
	p.registry.Subscribe(plugin.EventDataStored, func(event plugin.Event) {
		log.Printf("Data stored: %v", event.Data)
	})

	// Publish an event
	p.registry.Publish(plugin.Event{
		Type:      plugin.EventSystemConfigUpdated,
		Source:    p.Info().Name,
		Data:      map[string]interface{}{"key": "value"},
		Timestamp: time.Now(),
	})
}

func (p *CommunicatingPlugin) useSharedStore() {
	// Store configuration
	p.registry.SetShared("app.config.timeout", 30*time.Second)
	p.registry.SetShared("app.config.max_retries", 3)

	// Watch for changes
	p.registry.SharedStore().Watch("app.config.timeout", func(key string, value interface{}) {
		log.Printf("Config changed: %s = %v", key, value)
	})

	// Read configuration
	if timeout, ok := p.registry.GetShared("app.config.timeout"); ok {
		log.Printf("Current timeout: %v", timeout)
	}
}

func (p *CommunicatingPlugin) useMessageQueue(ctx context.Context) {
	// Subscribe to a work queue
	unsubscribe, err := p.registry.SubscribeToTopic("work.process", func(ctx context.Context, msg plugin.Message) error {
		log.Printf("Processing work item: %v", msg.Payload)
		// Simulate work
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	if err != nil {
		log.Printf("Failed to subscribe: %v", err)
		return
	}
	defer unsubscribe()

	// Publish work items
	for i := 0; i < 3; i++ {
		err := p.registry.PublishMessage("work.process", map[string]interface{}{
			"id":   i,
			"task": fmt.Sprintf("Task %d", i),
		})
		if err != nil {
			log.Printf("Failed to publish: %v", err)
		}
	}
}

func (p *CommunicatingPlugin) useDirectCalls() {
	// Find storage service
	storageService, err := plugin.GetStorageService(p.registry)
	if err != nil {
		log.Printf("No storage service available: %v", err)
		return
	}

	// Use the service
	ctx := context.Background()
	id, err := storageService.Store(ctx, []byte("Hello, World!"), map[string]string{
		"content-type": "text/plain",
	})
	if err != nil {
		log.Printf("Failed to store data: %v", err)
		return
	}

	log.Printf("Stored data with ID: %s", id)
}

// PluginRequestHandler implementation for synchronous requests
func (p *CommunicatingPlugin) HandlePluginRequest(ctx context.Context, req plugin.PluginRequest) (plugin.PluginResponse, error) {
	switch req.Type {
	case "echo":
		return plugin.PluginResponse{
			ID:      req.ID,
			Status:  200,
			Data:    req.Data,
			Created: time.Now(),
		}, nil
	case "info":
		return plugin.PluginResponse{
			ID:     req.ID,
			Status: 200,
			Data: map[string]interface{}{
				"name":    p.Info().Name,
				"version": p.Info().Version,
			},
			Created: time.Now(),
		}, nil
	default:
		return plugin.PluginResponse{
			ID:      req.ID,
			Status:  404,
			Error:   fmt.Errorf("unknown request type: %s", req.Type),
			Created: time.Now(),
		}, nil
	}
}

func main() {
	// Create registry
	registry := plugin.NewRegistry()

	// Create and register plugin
	plugin := NewCommunicatingPlugin(registry)
	if err := registry.Register(plugin); err != nil {
		log.Fatal(err)
	}

	// Start registry
	ctx := context.Background()
	if err := registry.Start(ctx); err != nil {
		log.Fatal(err)
	}

	// Let it run for a bit
	time.Sleep(5 * time.Second)

	// Stop registry
	if err := registry.Stop(ctx); err != nil {
		log.Fatal(err)
	}
}