# Plugin Communication Patterns

This document describes the standardized communication patterns for plugins in the Blackhole Network.

## Communication Channels

### 1. Event Bus (Async, Decoupled)

For broadcasting state changes and notifications.

```go
// Subscribe to events
unsubscribe := registry.Subscribe(plugin.EventDataStored, func(event plugin.Event) {
    log.Printf("Data stored: %v", event.Data)
})
defer unsubscribe()

// Publish events
registry.Publish(plugin.Event{
    Type:      plugin.EventResourceAllocated,
    Source:    "my-plugin",
    Data:      resourceInfo,
    Timestamp: time.Now(),
})
```

**Standard Event Types:**
- Resource: `resource.allocated`, `resource.released`, `resource.depleted`
- Data: `data.stored`, `data.retrieved`, `data.deleted`, `data.updated`
- Network: `network.peer.connected`, `network.peer.disconnected`
- Compute: `compute.job.queued`, `compute.job.started`, `compute.job.completed`
- Economic: `economic.credits.earned`, `economic.credits.spent`

### 2. Request/Response (Sync, Direct)

For synchronous plugin-to-plugin communication.

```go
// Implement PluginRequestHandler interface
func (p *MyPlugin) HandlePluginRequest(ctx context.Context, req plugin.PluginRequest) (plugin.PluginResponse, error) {
    switch req.Type {
    case "getData":
        return plugin.PluginResponse{
            ID:     req.ID,
            Status: 200,
            Data:   myData,
        }, nil
    default:
        return plugin.PluginResponse{
            ID:     req.ID,
            Status: 404,
            Error:  fmt.Errorf("unknown request type"),
        }, nil
    }
}
```

### 3. Shared Store (State Sharing)

For configuration and shared state.

```go
// Store shared data
registry.SetShared("config.timeout", 30*time.Second)

// Watch for changes
registry.SharedStore().Watch("config.timeout", func(key string, value interface{}) {
    log.Printf("Config changed: %s = %v", key, value)
})

// Read shared data
if timeout, ok := registry.GetShared("config.timeout"); ok {
    // Use timeout
}
```

### 4. Message Queue (Async, Buffered)

For work distribution and task processing.

```go
// Subscribe to work queue
unsubscribe, _ := registry.SubscribeToTopic("compute.tasks", func(ctx context.Context, msg plugin.Message) error {
    task := msg.Payload.(ComputeTask)
    return processTask(task)
})
defer unsubscribe()

// Publish work
registry.PublishMessage("compute.tasks", ComputeTask{
    ID:   "task-123",
    Type: "image-processing",
})
```

### 5. Service Discovery

For finding and using other plugin services.

```go
// Find storage service
storageService, err := plugin.GetStorageService(registry)
if err != nil {
    return err
}

// Use the service
id, err := storageService.Store(ctx, data, metadata)
```

## Standard Service Interfaces

### StorageService
```go
type StorageService interface {
    Store(ctx context.Context, data []byte, metadata map[string]string) (string, error)
    Retrieve(ctx context.Context, id string) ([]byte, error)
    Delete(ctx context.Context, id string) error
    List(ctx context.Context, prefix string) ([]string, error)
}
```

### NetworkService
```go
type NetworkService interface {
    Send(ctx context.Context, peerID string, data []byte) error
    Broadcast(ctx context.Context, data []byte) error
    GetPeers(ctx context.Context) ([]string, error)
}
```

### ComputeService
```go
type ComputeService interface {
    SubmitJob(ctx context.Context, job ComputeJob) (string, error)
    GetJobStatus(ctx context.Context, jobID string) (JobStatus, error)
    CancelJob(ctx context.Context, jobID string) error
}
```

## Communication Guidelines

### Event Naming Convention
Events follow the pattern: `<domain>.<object>.<action>`

Examples:
- `storage.block.stored`
- `network.peer.connected`
- `compute.job.completed`

### Error Handling
Always wrap errors with context:
```go
return plugin.WrapError(p.Name(), "operation", err)
```

### Context Usage
Always respect context cancellation:
```go
select {
case <-ctx.Done():
    return ctx.Err()
default:
    // Do work
}
```

## Choosing the Right Pattern

| Pattern | Use When |
|---------|----------|
| **Events** | Broadcasting state changes, notifications, monitoring |
| **Request/Response** | Need immediate response, direct service calls |
| **Shared Store** | Configuration, global state, feature flags |
| **Message Queue** | Task distribution, work items, async processing |
| **Direct Service** | Type-safe API calls, tight coupling is OK |

## Best Practices

1. **Prefer Events** for loose coupling between plugins
2. **Use Message Queues** for distributing work
3. **Implement Service Interfaces** for clear APIs
4. **Validate Event Types** using the provided helper
5. **Handle Errors Gracefully** - plugins may not be available
6. **Set Timeouts** on all synchronous operations
7. **Log Communication Failures** for debugging
