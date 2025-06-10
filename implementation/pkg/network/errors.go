package network

import (
	"errors"
	"fmt"
)

// Common errors
var (
	// ErrInvalidConfig indicates an invalid configuration
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrHostNotStarted indicates the host has not been started
	ErrHostNotStarted = errors.New("host not started")

	// ErrHostAlreadyStarted indicates the host is already started
	ErrHostAlreadyStarted = errors.New("host already started")

	// ErrNoBootstrapPeers indicates no bootstrap peers are configured
	ErrNoBootstrapPeers = errors.New("no bootstrap peers configured")

	// ErrConnectionFailed indicates a connection attempt failed
	ErrConnectionFailed = errors.New("connection failed")

	// ErrStreamCreationFailed indicates stream creation failed
	ErrStreamCreationFailed = errors.New("stream creation failed")

	// ErrPeerNotFound indicates the requested peer was not found
	ErrPeerNotFound = errors.New("peer not found")

	// ErrProtocolNotSupported indicates the protocol is not supported
	ErrProtocolNotSupported = errors.New("protocol not supported")

	// ErrTimeout indicates an operation timed out
	ErrTimeout = errors.New("operation timed out")

	// ErrResourceExhausted indicates a resource limit was reached
	ErrResourceExhausted = errors.New("resource exhausted")
)

// ConfigError represents a configuration error
type ConfigError struct {
	Field   string
	Message string
}

func (e ConfigError) Error() string {
	return fmt.Sprintf("config error: %s: %s", e.Field, e.Message)
}

// ConnectionError represents a connection error
type ConnectionError struct {
	PeerID  string
	Address string
	Cause   error
}

func (e ConnectionError) Error() string {
	return fmt.Sprintf("connection error: peer=%s, addr=%s: %v", e.PeerID, e.Address, e.Cause)
}

func (e ConnectionError) Unwrap() error {
	return e.Cause
}

// ProtocolError represents a protocol-level error
type ProtocolError struct {
	Protocol string
	Message  string
	Cause    error
}

func (e ProtocolError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("protocol error: %s: %s: %v", e.Protocol, e.Message, e.Cause)
	}
	return fmt.Sprintf("protocol error: %s: %s", e.Protocol, e.Message)
}

func (e ProtocolError) Unwrap() error {
	return e.Cause
}

// TransportError represents a transport-level error
type TransportError struct {
	Transport string
	Message   string
	Cause     error
}

func (e TransportError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("transport error: %s: %s: %v", e.Transport, e.Message, e.Cause)
	}
	return fmt.Sprintf("transport error: %s: %s", e.Transport, e.Message)
}

func (e TransportError) Unwrap() error {
	return e.Cause
}

// IsConnectionError checks if an error is a connection error
func IsConnectionError(err error) bool {
	var connErr ConnectionError
	return errors.As(err, &connErr)
}

// IsConfigError checks if an error is a configuration error
func IsConfigError(err error) bool {
	var cfgErr ConfigError
	return errors.As(err, &cfgErr)
}

// IsProtocolError checks if an error is a protocol error
func IsProtocolError(err error) bool {
	var protoErr ProtocolError
	return errors.As(err, &protoErr)
}

// IsTransportError checks if an error is a transport error
func IsTransportError(err error) bool {
	var transErr TransportError
	return errors.As(err, &transErr)
}

// WrapError wraps an error with additional context
func WrapError(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(format+": %w", append(args, err)...)
}