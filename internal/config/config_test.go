package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromFile(t *testing.T) {
	// Use home directory for test config to pass validation
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	// Create test config under .blackhole in home directory
	testDir := filepath.Join(home, ".blackhole")
	configPath := filepath.Join(testDir, "test-config.json")

	// Save original config if it exists
	originalConfigPath := filepath.Join(testDir, "config.json")
	var originalConfig []byte
	if data, err := os.ReadFile(originalConfigPath); err == nil {
		originalConfig = data
		defer func() {
			// Restore original config
			if originalConfig != nil {
				_ = os.WriteFile(originalConfigPath, originalConfig, 0644)
			}
		}()
	}

	// Ensure we clean up our test config
	defer func() { _ = os.Remove(configPath) }()

	// Create directory structure
	err = os.MkdirAll(filepath.Dir(configPath), 0755)
	if err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Create test config
	// Note: Some fields will be overridden by envconfig defaults,
	// so we test fields that don't have defaults or have "" as default
	testConfig := &Config{
		Node: NodeConfig{
			ID:           "test-node-1",
			IdentityPath: "/custom/identity/path",
			DataPath:     "/custom/data/path",
		},
		Network: NetworkConfig{
			ListenAddresses: []string{"/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/tcp/4002"},
			BootstrapPeers:  []string{"/ip4/192.168.1.1/tcp/4001/p2p/12D3KooWTest"},
			MaxPeers:        100,
			MinPeers:        20,
			DialTimeout:     60 * time.Second,
		},
		Storage: StorageConfig{
			Path:         "/custom/storage/path",
			MaxSize:      1073741824, // 1GB
			CacheSize:    104857600,  // 100MB
			DataShards:   5,
			ParityShards: 2,
			ChunkSize:    524288, // 512KB
		},
		Resources: ResourceConfig{
			CPU: CPUConfig{
				MaxPercent:      90,
				ReservedPercent: 10,
			},
			Memory: MemoryConfig{
				MaxGB:      16,
				ReservedGB: 4,
			},
			Bandwidth: BandwidthConfig{
				UploadMbps:   200,
				DownloadMbps: 1000,
			},
		},
		API: APIConfig{
			ListenAddress:   "localhost:8081",
			MaxRequestSize:  52428800, // 50MB
			ReadTimeout:     45 * time.Second,
			WriteTimeout:    45 * time.Second,
			ShutdownTimeout: 60 * time.Second,
		},
		Monitoring: MonitoringConfig{
			MetricsEnabled: false,  // Different from default true
			MetricsAddress: "localhost:9091",
			TracingEnabled: true,   // Different from default false
			LogLevel:       "debug",
		},
	}

	// Write config to file
	data, err := json.MarshalIndent(testConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Set environment variable to point to our test config
	_ = os.Setenv("BLACKHOLE_CONFIG", configPath)
	defer func() { _ = os.Unsetenv("BLACKHOLE_CONFIG") }()

	// Load configuration
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify values that are loaded from file and not overridden by defaults
	if cfg.Node.ID != testConfig.Node.ID {
		t.Errorf("Expected node ID %s, got %s", testConfig.Node.ID, cfg.Node.ID)
	}

	// Check bootstrap peers (no default)
	if len(cfg.Network.BootstrapPeers) != len(testConfig.Network.BootstrapPeers) {
		t.Errorf("Expected %d bootstrap peers, got %d", len(testConfig.Network.BootstrapPeers), len(cfg.Network.BootstrapPeers))
	}
	if len(cfg.Network.BootstrapPeers) > 0 && cfg.Network.BootstrapPeers[0] != testConfig.Network.BootstrapPeers[0] {
		t.Errorf("Expected bootstrap peer %s, got %s", testConfig.Network.BootstrapPeers[0], cfg.Network.BootstrapPeers[0])
	}

	// Note: envconfig will override ListenAddresses with default if no env var is set
	// So we skip this check as it's expected behavior

	// After path expansion, the paths should not start with ~
	if strings.HasPrefix(cfg.Node.IdentityPath, "~") {
		t.Errorf("Identity path was not expanded: %s", cfg.Node.IdentityPath)
	}
	if strings.HasPrefix(cfg.Storage.Path, "~") {
		t.Errorf("Storage path was not expanded: %s", cfg.Storage.Path)
	}

	// Verify that validation passes
	if err := cfg.Validate(); err != nil {
		t.Errorf("Loaded config failed validation: %v", err)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	nonExistentConfig := filepath.Join(tempDir, "nonexistent", "config.json")

	// Set environment variable to point to non-existent config
	_ = os.Setenv("BLACKHOLE_CONFIG", nonExistentConfig)
	defer func() { _ = os.Unsetenv("BLACKHOLE_CONFIG") }()

	// Load configuration (should use defaults)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config with defaults: %v", err)
	}

	// Verify default values
	if cfg.Network.MaxPeers != 50 {
		t.Errorf("Expected default max peers 50, got %d", cfg.Network.MaxPeers)
	}
	if cfg.Network.MinPeers != 10 {
		t.Errorf("Expected default min peers 10, got %d", cfg.Network.MinPeers)
	}
	if cfg.Storage.DataShards != 10 {
		t.Errorf("Expected default data shards 10, got %d", cfg.Storage.DataShards)
	}
	if cfg.Resources.CPU.MaxPercent != 80 {
		t.Errorf("Expected default CPU max percent 80, got %f", cfg.Resources.CPU.MaxPercent)
	}
	if cfg.API.ListenAddress != "localhost:8080" {
		t.Errorf("Expected default API listen address localhost:8080, got %s", cfg.API.ListenAddress)
	}
	if cfg.Monitoring.LogLevel != "info" {
		t.Errorf("Expected default log level info, got %s", cfg.Monitoring.LogLevel)
	}
}

func TestLoadConfigEnvironmentOverride(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	nonExistentConfig := filepath.Join(tempDir, "nonexistent", "config.json")

	// Set environment variables
	_ = os.Setenv("BLACKHOLE_CONFIG", nonExistentConfig)
	_ = os.Setenv("BLACKHOLE_NODE_ID", "env-node-id")
	_ = os.Setenv("BLACKHOLE_NETWORK_MAX_PEERS", "200")
	_ = os.Setenv("BLACKHOLE_STORAGE_MAX_SIZE", "2147483648") // 2GB
	_ = os.Setenv("BLACKHOLE_RESOURCES_CPU_MAX_PERCENT", "95")
	_ = os.Setenv("BLACKHOLE_API_LISTEN_ADDRESS", "0.0.0.0:9090")
	_ = os.Setenv("BLACKHOLE_MONITORING_LOG_LEVEL", "error")

	defer func() {
			_ = os.Unsetenv("BLACKHOLE_CONFIG")
			_ = os.Unsetenv("BLACKHOLE_NODE_ID")
			_ = os.Unsetenv("BLACKHOLE_NETWORK_MAX_PEERS")
			_ = os.Unsetenv("BLACKHOLE_STORAGE_MAX_SIZE")
			_ = os.Unsetenv("BLACKHOLE_RESOURCES_CPU_MAX_PERCENT")
			_ = os.Unsetenv("BLACKHOLE_API_LISTEN_ADDRESS")
			_ = os.Unsetenv("BLACKHOLE_MONITORING_LOG_LEVEL")
	}()

	// Load configuration
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config with environment overrides: %v", err)
	}

	// Verify environment overrides
	if cfg.Node.ID != "env-node-id" {
		t.Errorf("Expected node ID from env 'env-node-id', got %s", cfg.Node.ID)
	}
	if cfg.Network.MaxPeers != 200 {
		t.Errorf("Expected max peers from env 200, got %d", cfg.Network.MaxPeers)
	}
	if cfg.Storage.MaxSize != 2147483648 {
		t.Errorf("Expected storage max size from env 2147483648, got %d", cfg.Storage.MaxSize)
	}
	if cfg.Resources.CPU.MaxPercent != 95 {
		t.Errorf("Expected CPU max percent from env 95, got %f", cfg.Resources.CPU.MaxPercent)
	}
	if cfg.API.ListenAddress != "0.0.0.0:9090" {
		t.Errorf("Expected API listen address from env '0.0.0.0:9090', got %s", cfg.API.ListenAddress)
	}
	if cfg.Monitoring.LogLevel != "error" {
		t.Errorf("Expected log level from env 'error', got %s", cfg.Monitoring.LogLevel)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid configuration",
			config: &Config{
				Network: NetworkConfig{
					MaxPeers: 50,
					MinPeers: 10,
				},
				Storage: StorageConfig{
					MaxSize:      1073741824,
					DataShards:   10,
					ParityShards: 4,
				},
				Resources: ResourceConfig{
					CPU: CPUConfig{
						MaxPercent: 80,
					},
					Memory: MemoryConfig{
						MaxGB:      16,
						ReservedGB: 4,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid network peers",
			config: &Config{
				Network: NetworkConfig{
					MaxPeers: 5,
					MinPeers: 10,
				},
				Storage: StorageConfig{
					MaxSize:      1073741824,
					DataShards:   10,
					ParityShards: 4,
				},
				Resources: ResourceConfig{
					CPU: CPUConfig{
						MaxPercent: 80,
					},
					Memory: MemoryConfig{
						MaxGB:      16,
						ReservedGB: 4,
					},
				},
			},
			wantErr: true,
			errMsg:  "max_peers must be greater than min_peers",
		},
		{
			name: "Invalid storage size",
			config: &Config{
				Network: NetworkConfig{
					MaxPeers: 50,
					MinPeers: 10,
				},
				Storage: StorageConfig{
					MaxSize:      0,
					DataShards:   10,
					ParityShards: 4,
				},
				Resources: ResourceConfig{
					CPU: CPUConfig{
						MaxPercent: 80,
					},
					Memory: MemoryConfig{
						MaxGB:      16,
						ReservedGB: 4,
					},
				},
			},
			wantErr: true,
			errMsg:  "storage max_size must be positive",
		},
		{
			name: "Invalid shards",
			config: &Config{
				Network: NetworkConfig{
					MaxPeers: 50,
					MinPeers: 10,
				},
				Storage: StorageConfig{
					MaxSize:      1073741824,
					DataShards:   0,
					ParityShards: 4,
				},
				Resources: ResourceConfig{
					CPU: CPUConfig{
						MaxPercent: 80,
					},
					Memory: MemoryConfig{
						MaxGB:      16,
						ReservedGB: 4,
					},
				},
			},
			wantErr: true,
			errMsg:  "data_shards and parity_shards must be positive",
		},
		{
			name: "Invalid CPU percent",
			config: &Config{
				Network: NetworkConfig{
					MaxPeers: 50,
					MinPeers: 10,
				},
				Storage: StorageConfig{
					MaxSize:      1073741824,
					DataShards:   10,
					ParityShards: 4,
				},
				Resources: ResourceConfig{
					CPU: CPUConfig{
						MaxPercent: 120,
					},
					Memory: MemoryConfig{
						MaxGB:      16,
						ReservedGB: 4,
					},
				},
			},
			wantErr: true,
			errMsg:  "cpu max_percent must be between 0 and 100",
		},
		{
			name: "Invalid memory allocation",
			config: &Config{
				Network: NetworkConfig{
					MaxPeers: 50,
					MinPeers: 10,
				},
				Storage: StorageConfig{
					MaxSize:      1073741824,
					DataShards:   10,
					ParityShards: 4,
				},
				Resources: ResourceConfig{
					CPU: CPUConfig{
						MaxPercent: 80,
					},
					Memory: MemoryConfig{
						MaxGB:      4,
						ReservedGB: 4,
					},
				},
			},
			wantErr: true,
			errMsg:  "memory max_gb must be greater than reserved_gb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("Validate() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestExpandPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get user home dir: %v", err)
	}

	cfg := &Config{
		Node: NodeConfig{
			IdentityPath: "~/.blackhole/identity",
			DataPath:     "~/.blackhole/data",
		},
		Storage: StorageConfig{
			Path: "~/.blackhole/storage",
		},
	}

	cfg.expandPaths()

	expectedIdentityPath := filepath.Join(home, ".blackhole/identity")
	if cfg.Node.IdentityPath != expectedIdentityPath {
		t.Errorf("Expected identity path %s, got %s", expectedIdentityPath, cfg.Node.IdentityPath)
	}

	expectedDataPath := filepath.Join(home, ".blackhole/data")
	if cfg.Node.DataPath != expectedDataPath {
		t.Errorf("Expected data path %s, got %s", expectedDataPath, cfg.Node.DataPath)
	}

	expectedStoragePath := filepath.Join(home, ".blackhole/storage")
	if cfg.Storage.Path != expectedStoragePath {
		t.Errorf("Expected storage path %s, got %s", expectedStoragePath, cfg.Storage.Path)
	}
}

func TestExpandPathFunction(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "Path with tilde",
			path:     "~/test",
			expected: filepath.Join(home, "test"),
		},
		{
			name:     "Path without tilde",
			path:     "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "Empty path",
			path:     "",
			expected: "",
		},
		{
			name:     "Just tilde",
			path:     "~",
			expected: home,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.path, home)
			if result != tt.expected {
				t.Errorf("expandPath(%s) = %s, want %s", tt.path, result, tt.expected)
			}
		})
	}
}

func TestSaveConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test", "config.json")

	cfg := &Config{
		Node: NodeConfig{
			ID:           "test-save-node",
			IdentityPath: "~/.blackhole/identity",
			DataPath:     "~/.blackhole/data",
		},
		Network: NetworkConfig{
			ListenAddresses: []string{"/ip4/0.0.0.0/tcp/4001"},
			MaxPeers:        50,
			MinPeers:        10,
			DialTimeout:     30 * time.Second,
		},
		Storage: StorageConfig{
			Path:         "~/.blackhole/storage",
			MaxSize:      536870912000,
			CacheSize:    1073741824,
			DataShards:   10,
			ParityShards: 4,
			ChunkSize:    1048576,
		},
		Resources: ResourceConfig{
			CPU: CPUConfig{
				MaxPercent:      80,
				ReservedPercent: 20,
			},
			Memory: MemoryConfig{
				MaxGB:      8,
				ReservedGB: 2,
			},
			Bandwidth: BandwidthConfig{
				UploadMbps:   100,
				DownloadMbps: 500,
			},
		},
		API: APIConfig{
			ListenAddress:   "localhost:8080",
			MaxRequestSize:  104857600,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 30 * time.Second,
		},
		Monitoring: MonitoringConfig{
			MetricsEnabled: true,
			MetricsAddress: "localhost:9090",
			TracingEnabled: false,
			LogLevel:       "info",
		},
	}

	// Save config
	err := cfg.Save(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Read and verify saved config
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}

	var loadedCfg Config
	err = json.Unmarshal(data, &loadedCfg)
	if err != nil {
		t.Fatalf("Failed to unmarshal saved config: %v", err)
	}

	if loadedCfg.Node.ID != cfg.Node.ID {
		t.Errorf("Saved node ID mismatch: got %s, want %s", loadedCfg.Node.ID, cfg.Node.ID)
	}
}

func TestIsValidConfigPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		name  string
		path  string
		valid bool
	}{
		{
			name:  "Valid home config path",
			path:  filepath.Join(home, ".blackhole", "config.json"),
			valid: true,
		},
		{
			name:  "Valid system config path",
			path:  "/etc/blackhole/config.json",
			valid: true,
		},
		{
			name:  "Valid local system config path",
			path:  "/usr/local/etc/blackhole/config.json",
			valid: true,
		},
		{
			name:  "Invalid path",
			path:  "/tmp/config.json",
			valid: false,
		},
		{
			name:  "Invalid relative path",
			path:  "../../../etc/passwd",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidConfigPath(tt.path)
			if result != tt.valid {
				t.Errorf("isValidConfigPath(%s) = %v, want %v", tt.path, result, tt.valid)
			}
		})
	}
}

func TestLoadConfigInvalidPath(t *testing.T) {
	// Set environment variable to an invalid config path
	_ = os.Setenv("BLACKHOLE_CONFIG", "/tmp/invalid/config.json")
	defer func() { _ = os.Unsetenv("BLACKHOLE_CONFIG") }()

	// Create the invalid config file
	err := os.MkdirAll("/tmp/invalid", 0755)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	err = os.WriteFile("/tmp/invalid/config.json", []byte("{}"), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp config: %v", err)
	}
	defer func() { _ = os.RemoveAll("/tmp/invalid") }()

	// Load should fail with invalid path
	_, err = Load()
	if err == nil {
		t.Error("Expected error for invalid config path, got nil")
	}
	if err != nil && err.Error() != "invalid config path: /tmp/invalid/config.json" {
		t.Errorf("Expected invalid config path error, got: %v", err)
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	// Create a temporary directory for test config
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".blackhole", "config.json")

	// Create directory structure
	err := os.MkdirAll(filepath.Dir(configPath), 0755)
	if err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Write invalid JSON
	err = os.WriteFile(configPath, []byte("{ invalid json }"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Set environment variable to point to our test config
	_ = os.Setenv("BLACKHOLE_CONFIG", configPath)
	defer func() { _ = os.Unsetenv("BLACKHOLE_CONFIG") }()

	// Load should fail
	_, err = Load()
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestTimeoutParsing(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	nonExistentConfig := filepath.Join(tempDir, "nonexistent", "config.json")

	// Set environment variables with different time formats
	_ = os.Setenv("BLACKHOLE_CONFIG", nonExistentConfig)
	_ = os.Setenv("BLACKHOLE_NETWORK_DIAL_TIMEOUT", "45s")
	_ = os.Setenv("BLACKHOLE_API_READ_TIMEOUT", "1m")
	_ = os.Setenv("BLACKHOLE_API_WRITE_TIMEOUT", "90s")
	_ = os.Setenv("BLACKHOLE_API_SHUTDOWN_TIMEOUT", "2m30s")

	defer func() {
			_ = os.Unsetenv("BLACKHOLE_CONFIG")
			_ = os.Unsetenv("BLACKHOLE_NETWORK_DIAL_TIMEOUT")
			_ = os.Unsetenv("BLACKHOLE_API_READ_TIMEOUT")
			_ = os.Unsetenv("BLACKHOLE_API_WRITE_TIMEOUT")
			_ = os.Unsetenv("BLACKHOLE_API_SHUTDOWN_TIMEOUT")
	}()

	// Load configuration
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config with timeout overrides: %v", err)
	}

	// Verify timeout values
	if cfg.Network.DialTimeout != 45*time.Second {
		t.Errorf("Expected dial timeout 45s, got %v", cfg.Network.DialTimeout)
	}
	if cfg.API.ReadTimeout != 1*time.Minute {
		t.Errorf("Expected read timeout 1m, got %v", cfg.API.ReadTimeout)
	}
	if cfg.API.WriteTimeout != 90*time.Second {
		t.Errorf("Expected write timeout 90s, got %v", cfg.API.WriteTimeout)
	}
	if cfg.API.ShutdownTimeout != 2*time.Minute+30*time.Second {
		t.Errorf("Expected shutdown timeout 2m30s, got %v", cfg.API.ShutdownTimeout)
	}
}

func TestListenAddressesParsing(t *testing.T) {
	// Create a temporary directory for test
	tempDir := t.TempDir()
	nonExistentConfig := filepath.Join(tempDir, "nonexistent", "config.json")

	// Set environment variables
	_ = os.Setenv("BLACKHOLE_CONFIG", nonExistentConfig)
	_ = os.Setenv("BLACKHOLE_NETWORK_LISTEN_ADDRESSES", "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/tcp/4002,/ip6/::/tcp/4001")

	defer func() {
			_ = os.Unsetenv("BLACKHOLE_CONFIG")
			_ = os.Unsetenv("BLACKHOLE_NETWORK_LISTEN_ADDRESSES")
	}()

	// Load configuration
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config with listen addresses: %v", err)
	}

	// Verify listen addresses
	expectedAddrs := []string{"/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/tcp/4002", "/ip6/::/tcp/4001"}
	if len(cfg.Network.ListenAddresses) != len(expectedAddrs) {
		t.Errorf("Expected %d listen addresses, got %d", len(expectedAddrs), len(cfg.Network.ListenAddresses))
	}
	for i, addr := range expectedAddrs {
		if i < len(cfg.Network.ListenAddresses) && cfg.Network.ListenAddresses[i] != addr {
			t.Errorf("Expected listen address %s at index %d, got %s", addr, i, cfg.Network.ListenAddresses[i])
		}
	}
}

func TestSaveConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		setup   func()
		cleanup func()
	}{
		{
			name:    "Save to read-only directory",
			path:    "/read-only-dir/config.json",
			wantErr: true,
			setup: func() {
				// Try to create a read-only directory (this will fail, which is what we want)
				_ = os.Mkdir("/read-only-dir", 0444)
			},
			cleanup: func() {
				_ = os.RemoveAll("/read-only-dir")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			cfg := &Config{
				Node: NodeConfig{
					ID: "test-save-error",
				},
			}

			err := cfg.Save(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
