package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Config represents the main configuration structure
type Config struct {
	// Node configuration
	Node NodeConfig `json:"node" envconfig:"NODE"`
	
	// Network configuration
	Network NetworkConfig `json:"network" envconfig:"NETWORK"`
	
	// Storage configuration
	Storage StorageConfig `json:"storage" envconfig:"STORAGE"`
	
	// Resource limits
	Resources ResourceConfig `json:"resources" envconfig:"RESOURCES"`
	
	// API configuration
	API APIConfig `json:"api" envconfig:"API"`
	
	// Monitoring configuration
	Monitoring MonitoringConfig `json:"monitoring" envconfig:"MONITORING"`
}

// NodeConfig contains node-specific settings
type NodeConfig struct {
	ID           string `json:"id" envconfig:"ID"`
	IdentityPath string `json:"identity_path" envconfig:"IDENTITY_PATH" default:"~/.blackhole/identity"`
	DataPath     string `json:"data_path" envconfig:"DATA_PATH" default:"~/.blackhole/data"`
}

// NetworkConfig contains P2P network settings
type NetworkConfig struct {
	ListenAddresses []string      `json:"listen_addresses" envconfig:"LISTEN_ADDRESSES" default:"/ip4/0.0.0.0/tcp/4001"`
	BootstrapPeers  []string      `json:"bootstrap_peers" envconfig:"BOOTSTRAP_PEERS"`
	MaxPeers        int           `json:"max_peers" envconfig:"MAX_PEERS" default:"50"`
	MinPeers        int           `json:"min_peers" envconfig:"MIN_PEERS" default:"10"`
	DialTimeout     time.Duration `json:"dial_timeout" envconfig:"DIAL_TIMEOUT" default:"30s"`
}

// StorageConfig contains storage settings
type StorageConfig struct {
	Path          string `json:"path" envconfig:"PATH" default:"~/.blackhole/storage"`
	MaxSize       int64  `json:"max_size" envconfig:"MAX_SIZE" default:"536870912000"` // 500GB
	CacheSize     int64  `json:"cache_size" envconfig:"CACHE_SIZE" default:"1073741824"` // 1GB
	DataShards    int    `json:"data_shards" envconfig:"DATA_SHARDS" default:"10"`
	ParityShards  int    `json:"parity_shards" envconfig:"PARITY_SHARDS" default:"4"`
	ChunkSize     int    `json:"chunk_size" envconfig:"CHUNK_SIZE" default:"1048576"` // 1MB
}

// ResourceConfig contains resource allocation limits
type ResourceConfig struct {
	CPU       CPUConfig       `json:"cpu" envconfig:"CPU"`
	Memory    MemoryConfig    `json:"memory" envconfig:"MEMORY"`
	Bandwidth BandwidthConfig `json:"bandwidth" envconfig:"BANDWIDTH"`
}

// CPUConfig contains CPU resource limits
type CPUConfig struct {
	MaxPercent      float64 `json:"max_percent" envconfig:"MAX_PERCENT" default:"80"`
	ReservedPercent float64 `json:"reserved_percent" envconfig:"RESERVED_PERCENT" default:"20"`
}

// MemoryConfig contains memory resource limits
type MemoryConfig struct {
	MaxGB      int `json:"max_gb" envconfig:"MAX_GB" default:"8"`
	ReservedGB int `json:"reserved_gb" envconfig:"RESERVED_GB" default:"2"`
}

// BandwidthConfig contains bandwidth limits
type BandwidthConfig struct {
	UploadMbps   int `json:"upload_mbps" envconfig:"UPLOAD_MBPS" default:"100"`
	DownloadMbps int `json:"download_mbps" envconfig:"DOWNLOAD_MBPS" default:"500"`
}

// APIConfig contains API server settings
type APIConfig struct {
	ListenAddress   string        `json:"listen_address" envconfig:"LISTEN_ADDRESS" default:"localhost:8080"`
	MaxRequestSize  int64         `json:"max_request_size" envconfig:"MAX_REQUEST_SIZE" default:"104857600"` // 100MB
	ReadTimeout     time.Duration `json:"read_timeout" envconfig:"READ_TIMEOUT" default:"30s"`
	WriteTimeout    time.Duration `json:"write_timeout" envconfig:"WRITE_TIMEOUT" default:"30s"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout" envconfig:"SHUTDOWN_TIMEOUT" default:"30s"`
}

// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	MetricsEnabled bool   `json:"metrics_enabled" envconfig:"METRICS_ENABLED" default:"true"`
	MetricsAddress string `json:"metrics_address" envconfig:"METRICS_ADDRESS" default:"localhost:9090"`
	TracingEnabled bool   `json:"tracing_enabled" envconfig:"TRACING_ENABLED" default:"false"`
	LogLevel       string `json:"log_level" envconfig:"LOG_LEVEL" default:"info"`
}

// Load loads configuration from file and environment
func Load() (*Config, error) {
	cfg := &Config{}

	// Try to load from config file first
	configPath := os.Getenv("BLACKHOLE_CONFIG")
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".blackhole", "config.json")
	}

	// Load from file if it exists
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with environment variables
	if err := envconfig.Process("BLACKHOLE", cfg); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	// Expand paths
	cfg.expandPaths()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// expandPaths expands ~ in paths to home directory
func (c *Config) expandPaths() {
	home, _ := os.UserHomeDir()
	
	c.Node.IdentityPath = expandPath(c.Node.IdentityPath, home)
	c.Node.DataPath = expandPath(c.Node.DataPath, home)
	c.Storage.Path = expandPath(c.Storage.Path, home)
}

func expandPath(path, home string) string {
	if len(path) > 0 && path[0] == '~' {
		return filepath.Join(home, path[1:])
	}
	return path
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate network settings
	if c.Network.MaxPeers < c.Network.MinPeers {
		return fmt.Errorf("max_peers must be greater than min_peers")
	}

	// Validate storage settings
	if c.Storage.MaxSize <= 0 {
		return fmt.Errorf("storage max_size must be positive")
	}
	if c.Storage.DataShards <= 0 || c.Storage.ParityShards <= 0 {
		return fmt.Errorf("data_shards and parity_shards must be positive")
	}

	// Validate resource limits
	if c.Resources.CPU.MaxPercent <= 0 || c.Resources.CPU.MaxPercent > 100 {
		return fmt.Errorf("cpu max_percent must be between 0 and 100")
	}
	if c.Resources.Memory.MaxGB <= c.Resources.Memory.ReservedGB {
		return fmt.Errorf("memory max_gb must be greater than reserved_gb")
	}

	return nil
}

// Save saves the configuration to a file
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}