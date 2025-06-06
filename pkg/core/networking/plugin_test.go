package networking

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

func TestPlugin_Lifecycle(t *testing.T) {
	ctx := context.Background()
	registry := plugin.NewRegistry()
	p := New(registry)

	// Test plugin info
	assert.Equal(t, "network", p.Info().Name)
	assert.Equal(t, "0.1.0", p.Info().Version)

	// Test initialization
	config := plugin.Config{
		"enable_auto_relay": false, // Disable for tests
	}

	err := p.Init(ctx, config)
	require.NoError(t, err)

	// Test start
	err = p.Start(ctx)
	require.NoError(t, err)

	// Test health
	health := p.Health()
	assert.NotEqual(t, plugin.HealthStatusUnhealthy, health.Status)

	// Test stop
	err = p.Stop(ctx)
	require.NoError(t, err)
}

func TestPlugin_Configuration(_ *testing.T) {
	// TODO: Add configuration tests
}

func TestPlugin_NetworkService(t *testing.T) {
	ctx := context.Background()
	registry := plugin.NewRegistry()
	p := New(registry)

	// Test that it implements NetworkService
	var _ plugin.NetworkService = p

	// Initialize with test config
	config := plugin.Config{
		"port":              0,     // Use random port for testing
		"enable_auto_relay": false, // Disable for tests
	}

	err := p.Init(ctx, config)
	require.NoError(t, err)

	// Test GetPeers (should be empty initially)
	peers, err := p.GetPeers(ctx)
	require.NoError(t, err)
	assert.Empty(t, peers)
}

func BenchmarkPlugin_Start(b *testing.B) {
	ctx := context.Background()
	registry := plugin.NewRegistry()
	config := plugin.Config{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := New(registry)
		_ = p.Init(ctx, config)
		_ = p.Start(ctx)
		_ = p.Stop(ctx)
	}
}
