package plugin_test

import (
	"context"
	"testing"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

func TestSharedStore(t *testing.T) {
	store := plugin.NewSharedStore()

	// Test Set and Get
	store.Set("test.key", "test.value")
	value, exists := store.Get("test.key")
	if !exists {
		t.Error("Expected key to exist")
	}
	if value != "test.value" {
		t.Errorf("Expected 'test.value', got %v", value)
	}

	// Test Watch
	watchCalled := false
	store.Watch("watch.key", func(key string, value interface{}) {
		watchCalled = true
		if key != "watch.key" {
			t.Errorf("Expected key 'watch.key', got %s", key)
		}
		if value != "watch.value" {
			t.Errorf("Expected value 'watch.value', got %v", value)
		}
	})

	store.Set("watch.key", "watch.value")
	if !watchCalled {
		t.Error("Watch callback was not called")
	}

	// Test Delete
	store.Delete("test.key")
	_, exists = store.Get("test.key")
	if exists {
		t.Error("Expected key to be deleted")
	}
}

func TestMessageQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	queue := plugin.NewMessageQueue(ctx)
	defer queue.Stop()

	// Test Subscribe and Publish
	received := make(chan bool, 1)
	unsubscribe := queue.Subscribe("test.topic", func(_ context.Context, msg plugin.Message) error {
		if msg.Topic != "test.topic" {
			t.Errorf("Expected topic 'test.topic', got %s", msg.Topic)
		}
		if msg.Payload != "test.payload" {
			t.Errorf("Expected payload 'test.payload', got %v", msg.Payload)
		}
		received <- true
		return nil
	})
	defer unsubscribe()

	// Give the worker time to start
	time.Sleep(10 * time.Millisecond)

	err := queue.Publish("test.topic", "test.payload")
	if err != nil {
		t.Errorf("Failed to publish message: %v", err)
	}

	// Wait for message to be received
	select {
	case <-received:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("Message was not received within timeout")
	}

	// Test publish to non-existent topic
	err = queue.Publish("non.existent.topic", "payload")
	if err == nil {
		t.Error("Expected error when publishing to non-existent topic")
	}
}

func TestValidateEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		wantErr   bool
	}{
		{
			name:      "valid event type",
			eventType: "storage.block.stored",
			wantErr:   false,
		},
		{
			name:      "invalid - too few parts",
			eventType: "storage.stored",
			wantErr:   true,
		},
		{
			name:      "invalid - too many parts",
			eventType: "storage.block.data.stored",
			wantErr:   true,
		},
		{
			name:      "invalid - single word",
			eventType: "stored",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateEventType(tt.eventType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEventType() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	// Test nil error
	wrapped := plugin.WrapError("test-plugin", "operation", nil)
	if wrapped != nil {
		t.Error("Expected nil when wrapping nil error")
	}

	// Test non-nil error
	originalErr := context.DeadlineExceeded
	wrapped = plugin.WrapError("test-plugin", "operation", originalErr)
	if wrapped == nil {
		t.Error("Expected non-nil wrapped error")
	}

	expectedMsg := "plugin test-plugin: operation failed: context deadline exceeded"
	if wrapped.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, wrapped.Error())
	}
}
