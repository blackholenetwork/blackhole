package network

import (
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

// SecurityConfig defines the security configuration
type SecurityConfig struct {
	TLS              *TLSConfig              `yaml:"tls"`
	Noise            *NoiseConfig            `yaml:"noise"`
	CertificateStore *CertificateStoreConfig `yaml:"certificate_store"`
}

// TLSConfig defines TLS security configuration
type TLSConfig struct {
	Enabled               bool     `yaml:"enabled"`
	MinVersion            uint16   `yaml:"min_version"`
	CipherSuites          []uint16 `yaml:"cipher_suites"`
	PreferServerCiphers   bool     `yaml:"prefer_server_ciphers"`
	ClientAuth            bool     `yaml:"client_auth"`
	InsecureSkipVerify    bool     `yaml:"insecure_skip_verify"`
}

// NoiseConfig defines Noise protocol configuration
type NoiseConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Patterns []string `yaml:"patterns"`
}

// CertificateStoreConfig defines certificate storage configuration
type CertificateStoreConfig struct {
	Path          string `yaml:"path"`
	CACertPath    string `yaml:"ca_cert_path"`
	ServerCertPath string `yaml:"server_cert_path"`
	ServerKeyPath  string `yaml:"server_key_path"`
}

// buildSecurityOptions creates libp2p security options based on config
func buildSecurityOptions(config *SecurityConfig) []libp2p.Option {
	var opts []libp2p.Option
	
	// Always enable both TLS and Noise for compatibility
	// The order matters - first one is preferred
	if config.TLS != nil && config.TLS.Enabled {
		opts = append(opts, libp2p.Security(libp2ptls.ID, libp2ptls.New))
	}
	
	if config.Noise != nil && config.Noise.Enabled {
		opts = append(opts, libp2p.Security(noise.ID, noise.New))
	}
	
	// If no security is explicitly configured, enable both by default
	if len(opts) == 0 {
		opts = append(opts,
			libp2p.Security(libp2ptls.ID, libp2ptls.New),
			libp2p.Security(noise.ID, noise.New),
		)
	}
	
	return opts
}