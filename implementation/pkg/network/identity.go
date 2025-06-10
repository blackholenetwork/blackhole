package network

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// LoadOrCreateIdentity loads an existing identity or creates a new one
func LoadOrCreateIdentity(keyPath string) (crypto.PrivKey, error) {
	// Expand home directory if needed
	if keyPath[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		keyPath = filepath.Join(home, keyPath[2:])
	}

	// Check if key file exists
	if _, err := os.Stat(keyPath); err == nil {
		// Load existing key
		return loadPrivateKey(keyPath)
	}

	// Create new identity
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save the key
	if err := savePrivateKey(priv, keyPath); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return priv, nil
}

// loadPrivateKey loads a private key from file
func loadPrivateKey(path string) (crypto.PrivKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	priv, err := crypto.UnmarshalPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return priv, nil
}

// savePrivateKey saves a private key to file
func savePrivateKey(priv crypto.PrivKey, path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal the key
	keyData, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(path, keyData, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// GetPeerID returns the peer ID for a given private key
func GetPeerID(priv crypto.PrivKey) (peer.ID, error) {
	pub := priv.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to derive peer ID: %w", err)
	}
	return id, nil
}

// IdentityInfo contains information about a peer's identity
type IdentityInfo struct {
	PeerID    peer.ID
	PublicKey crypto.PubKey
	Addresses []string
}

// GetIdentityInfo returns information about the current identity
func GetIdentityInfo(h *Host) (*IdentityInfo, error) {
	id := h.ID()
	
	// Get public key
	pubKey := h.Peerstore().PubKey(id)
	if pubKey == nil {
		return nil, fmt.Errorf("public key not found for peer %s", id)
	}

	// Get addresses
	addrs := h.Addrs()
	addrStrings := make([]string, len(addrs))
	for i, addr := range addrs {
		addrStrings[i] = addr.String()
	}

	return &IdentityInfo{
		PeerID:    id,
		PublicKey: pubKey,
		Addresses: addrStrings,
	}, nil
}