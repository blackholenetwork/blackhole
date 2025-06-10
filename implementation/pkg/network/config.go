package network

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete node configuration
type Config struct {
	Network   NetworkConfig   `yaml:"network"`
	Identity  IdentityConfig  `yaml:"identity"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Logging   LoggingConfig   `yaml:"logging"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Resources ResourceConfig  `yaml:"resources"`
}

// NetworkConfig defines network-related configuration
type NetworkConfig struct {
	ListenAddresses   []string               `yaml:"listen_addresses"`
	BootstrapPeers    []string               `yaml:"bootstrap_peers"`
	ConnectionManager *ConnectionManagerConf `yaml:"connection_manager"`
	Transports        *TransportConfig       `yaml:"transports"`
	Security          *SecurityConfig        `yaml:"security"`
	EnableRelay       bool                   `yaml:"enable_relay"`
	EnableAutoRelay   bool                   `yaml:"enable_auto_relay"`
	StaticRelays      []string               `yaml:"static_relays"`
}

// ConnectionManagerConf defines connection manager configuration
type ConnectionManagerConf struct {
	HighWater   int           `yaml:"high_water"`
	LowWater    int           `yaml:"low_water"`
	GracePeriod time.Duration `yaml:"grace_period"`
}

// IdentityConfig defines peer identity configuration
type IdentityConfig struct {
	PrivateKeyPath string `yaml:"private_key_path"`
}

// MetricsConfig defines metrics configuration
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// LoggingConfig defines logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// DiscoveryConfig defines peer discovery configuration
type DiscoveryConfig struct {
	MDNS *MDNSConfig `yaml:"mdns"`
	DHT  *DHTConfig  `yaml:"dht"`
}

// MDNSConfig defines mDNS discovery configuration
type MDNSConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
}

// DHTConfig defines DHT configuration
type DHTConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"`
}

// ResourceConfig defines resource limits
type ResourceConfig struct {
	MaxMemory          string `yaml:"max_memory"`
	MaxFileDescriptors int    `yaml:"max_file_descriptors"`
	MaxConnections     int    `yaml:"max_connections"`
}

// DefaultTransportConfig returns a default transport configuration
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		TCP: &TCPConfig{
			Enabled: true,
			KeepAlive: 30 * time.Second,
		},
		QUIC: &QUICConfig{
			Enabled: true,
			MaxIdleTimeout: 30 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
		},
		WebSocket: &WebSocketConfig{
			Enabled: false,
		},
		WebRTC: &WebRTCConfig{
			Enabled: false,
		},
	}
}

// DefaultSecurityConfig returns a default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		TLS: &TLSConfig{
			Enabled: true,
			MinVersion: 0x0304, // TLS 1.3
		},
		Noise: &NoiseConfig{
			Enabled: true,
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults
	if err := config.applyDefaults(); err != nil {
		return nil, fmt.Errorf("failed to apply defaults: %w", err)
	}

	// Validate configuration
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// applyDefaults applies default values to the configuration
func (c *Config) applyDefaults() error {
	// Apply transport defaults if not specified
	if c.Network.Transports == nil {
		c.Network.Transports = DefaultTransportConfig()
	}

	// Apply security defaults if not specified
	if c.Network.Security == nil {
		c.Network.Security = DefaultSecurityConfig()
	}

	// Apply connection manager defaults
	if c.Network.ConnectionManager == nil {
		c.Network.ConnectionManager = &ConnectionManagerConf{
			HighWater:   900,
			LowWater:    600,
			GracePeriod: 20 * time.Second,
		}
	}

	// Apply metrics defaults
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = "localhost"
	}
	
	// Apply logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Output == "" {
		c.Logging.Output = "stdout"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}

	return nil
}

// validate validates the configuration
func (c *Config) validate() error {
	// Validate listen addresses
	if len(c.Network.ListenAddresses) == 0 {
		return fmt.Errorf("at least one listen address must be specified")
	}

	// Validate connection manager
	if c.Network.ConnectionManager != nil {
		if c.Network.ConnectionManager.LowWater >= c.Network.ConnectionManager.HighWater {
			return fmt.Errorf("connection manager low water must be less than high water")
		}
	}

	// Validate identity
	if c.Identity.PrivateKeyPath == "" {
		return fmt.Errorf("private key path must be specified")
	}

	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			ListenAddresses: []string{
				"/ip4/0.0.0.0/tcp/4001",
				"/ip6/::/tcp/4001",
			},
			BootstrapPeers: []string{},
			ConnectionManager: &ConnectionManagerConf{
				HighWater:   900,
				LowWater:    600,
				GracePeriod: 20 * time.Second,
			},
			Transports: DefaultTransportConfig(),
			Security:   DefaultSecurityConfig(),
		},
		Identity: IdentityConfig{
			PrivateKeyPath: "~/.blackhole/private_key",
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Address: ":9090",
			Path:    "/metrics",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Discovery: DiscoveryConfig{
			MDNS: &MDNSConfig{
				Enabled:  true,
				Interval: 10 * time.Second,
			},
			DHT: &DHTConfig{
				Enabled: true,
				Mode:    "auto",
			},
		},
		Resources: ResourceConfig{
			MaxMemory:          "1GB",
			MaxFileDescriptors: 4096,
			MaxConnections:     1000,
		},
	}
}