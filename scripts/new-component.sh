#!/bin/bash
# Generate a new component with proper structure and boilerplate

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <layer> <component-name>"
    echo "Example: $0 storage chunk-manager"
    exit 1
fi

LAYER=$1
COMPONENT=$2
COMPONENT_PASCAL=$(echo $COMPONENT | sed -r 's/(^|-)([a-z])/\U\2/g')
PACKAGE_NAME=$(echo $COMPONENT | sed 's/-/_/g')

# Create directory structure
BASE_DIR="pkg/$LAYER/$PACKAGE_NAME"
mkdir -p $BASE_DIR

# Generate interface file
cat > "$BASE_DIR/interface.go" << EOF
package $PACKAGE_NAME

import (
    "context"
)

// $COMPONENT_PASCAL defines the interface for the $COMPONENT component
type $COMPONENT_PASCAL interface {
    // Start initializes and starts the component
    Start(ctx context.Context) error
    
    // Stop gracefully shuts down the component
    Stop(ctx context.Context) error
    
    // Health returns the current health status
    Health() ComponentHealth
    
    // TODO: Add component-specific methods
}

// ComponentHealth represents the health status of the component
type ComponentHealth struct {
    Status    HealthStatus
    Message   string
    Timestamp time.Time
}

type HealthStatus string

const (
    HealthStatusHealthy   HealthStatus = "healthy"
    HealthStatusDegraded  HealthStatus = "degraded"
    HealthStatusUnhealthy HealthStatus = "unhealthy"
)
EOF

# Generate implementation file
cat > "$BASE_DIR/${PACKAGE_NAME}.go" << EOF
package $PACKAGE_NAME

import (
    "context"
    "fmt"
    "sync"
    "time"
    
    "github.com/blackhole/pkg/common/logger"
)

// Ensure implementation satisfies interface
var _ $COMPONENT_PASCAL = (*${PACKAGE_NAME}Impl)(nil)

// Config holds configuration for $COMPONENT_PASCAL
type Config struct {
    // TODO: Add configuration fields
}

// ${PACKAGE_NAME}Impl implements the $COMPONENT_PASCAL interface
type ${PACKAGE_NAME}Impl struct {
    config Config
    logger logger.Logger
    
    mu     sync.RWMutex
    status HealthStatus
    
    // Context for lifecycle management
    ctx    context.Context
    cancel context.CancelFunc
}

// New creates a new instance of $COMPONENT_PASCAL
func New(config Config, logger logger.Logger) $COMPONENT_PASCAL {
    return &${PACKAGE_NAME}Impl{
        config: config,
        logger: logger,
        status: HealthStatusHealthy,
    }
}

// Start initializes and starts the component
func (c *${PACKAGE_NAME}Impl) Start(ctx context.Context) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.ctx != nil {
        return fmt.Errorf("$PACKAGE_NAME already started")
    }
    
    c.ctx, c.cancel = context.WithCancel(ctx)
    c.logger.Info("Starting $PACKAGE_NAME")
    
    // TODO: Initialize component
    
    c.status = HealthStatusHealthy
    c.logger.Info("$COMPONENT_PASCAL started successfully")
    
    return nil
}

// Stop gracefully shuts down the component
func (c *${PACKAGE_NAME}Impl) Stop(ctx context.Context) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.cancel == nil {
        return fmt.Errorf("$PACKAGE_NAME not started")
    }
    
    c.logger.Info("Stopping $PACKAGE_NAME")
    c.cancel()
    
    // TODO: Cleanup resources
    
    c.status = HealthStatusUnhealthy
    c.ctx = nil
    c.cancel = nil
    
    c.logger.Info("$COMPONENT_PASCAL stopped successfully")
    return nil
}

// Health returns the current health status
func (c *${PACKAGE_NAME}Impl) Health() ComponentHealth {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    return ComponentHealth{
        Status:    c.status,
        Message:   "$COMPONENT_PASCAL is " + string(c.status),
        Timestamp: time.Now(),
    }
}
EOF

# Generate test file
cat > "$BASE_DIR/${PACKAGE_NAME}_test.go" << EOF
package $PACKAGE_NAME

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/blackhole/pkg/common/logger"
)

func TestNew(t *testing.T) {
    config := Config{}
    log := logger.NewTestLogger()
    
    component := New(config, log)
    require.NotNil(t, component)
}

func Test${COMPONENT_PASCAL}_Lifecycle(t *testing.T) {
    config := Config{}
    log := logger.NewTestLogger()
    
    component := New(config, log)
    ctx := context.Background()
    
    // Test Start
    err := component.Start(ctx)
    require.NoError(t, err)
    
    // Check health
    health := component.Health()
    assert.Equal(t, HealthStatusHealthy, health.Status)
    
    // Test Stop
    err = component.Stop(ctx)
    require.NoError(t, err)
    
    // Check health after stop
    health = component.Health()
    assert.Equal(t, HealthStatusUnhealthy, health.Status)
}

func Test${COMPONENT_PASCAL}_DoubleStart(t *testing.T) {
    config := Config{}
    log := logger.NewTestLogger()
    
    component := New(config, log)
    ctx := context.Background()
    
    // First start should succeed
    err := component.Start(ctx)
    require.NoError(t, err)
    
    // Second start should fail
    err = component.Start(ctx)
    assert.Error(t, err)
    
    // Cleanup
    _ = component.Stop(ctx)
}
EOF

# Generate README
cat > "$BASE_DIR/README.md" << EOF
# $COMPONENT_PASCAL

This package implements the $COMPONENT component for the $LAYER layer.

## Overview

TODO: Add component description

## Usage

\`\`\`go
config := Config{
    // Configure component
}

component := New(config, logger)

// Start component
if err := component.Start(ctx); err != nil {
    return err
}

// Use component
// TODO: Add usage examples

// Stop component
if err := component.Stop(ctx); err != nil {
    return err
}
\`\`\`

## Configuration

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| TODO  | TODO | TODO        | TODO    |

## Testing

\`\`\`bash
go test ./pkg/$LAYER/$PACKAGE_NAME
\`\`\`
EOF

echo "✅ Component created at $BASE_DIR"
echo ""
echo "Next steps:"
echo "1. Update the interface in $BASE_DIR/interface.go"
echo "2. Implement the component logic in $BASE_DIR/${PACKAGE_NAME}.go"
echo "3. Add tests in $BASE_DIR/${PACKAGE_NAME}_test.go"
echo "4. Update the README in $BASE_DIR/README.md"
echo "5. Register the component in the orchestrator"

# Make script executable
chmod +x scripts/new-component.sh