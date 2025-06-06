// Package errors provides common error types and handling functions
package errors

import (
	"errors"
	"fmt"
)

// Common error types for the Blackhole Network

// ValidationError indicates invalid input or configuration
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// NotFoundError indicates a requested resource was not found
type NotFoundError struct {
	Resource string
	ID       string
}

func (e NotFoundError) Error() string {
	return fmt.Sprintf("%s not found: %s", e.Resource, e.ID)
}

// ConflictError indicates a resource conflict
type ConflictError struct {
	Resource string
	Message  string
}

func (e ConflictError) Error() string {
	return fmt.Sprintf("conflict for %s: %s", e.Resource, e.Message)
}

// TimeoutError indicates an operation timed out
type TimeoutError struct {
	Operation string
	Duration  string
}

func (e TimeoutError) Error() string {
	return fmt.Sprintf("operation '%s' timed out after %s", e.Operation, e.Duration)
}

// InternalError indicates an internal system error
type InternalError struct {
	Message string
	Cause   error
}

func (e InternalError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("internal error: %s (caused by: %v)", e.Message, e.Cause)
	}
	return fmt.Sprintf("internal error: %s", e.Message)
}

func (e InternalError) Unwrap() error {
	return e.Cause
}

// Helper functions for creating errors

// New creates a new error with the given message
func New(message string) error {
	return errors.New(message)
}

// Wrap wraps an error with an additional message
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message string) error {
	return ValidationError{Field: field, Message: message}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(resource, id string) error {
	return NotFoundError{Resource: resource, ID: id}
}

// NewConflictError creates a new conflict error
func NewConflictError(resource, message string) error {
	return ConflictError{Resource: resource, Message: message}
}

// NewTimeoutError creates a new timeout error
func NewTimeoutError(operation, duration string) error {
	return TimeoutError{Operation: operation, Duration: duration}
}

// NewInternalError creates a new internal error
func NewInternalError(message string, cause error) error {
	return InternalError{Message: message, Cause: cause}
}
