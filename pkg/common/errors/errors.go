package errors

import (
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

func NewValidationError(field, message string) error {
	return ValidationError{Field: field, Message: message}
}

func NewNotFoundError(resource, id string) error {
	return NotFoundError{Resource: resource, ID: id}
}

func NewConflictError(resource, message string) error {
	return ConflictError{Resource: resource, Message: message}
}

func NewTimeoutError(operation, duration string) error {
	return TimeoutError{Operation: operation, Duration: duration}
}

func NewInternalError(message string, cause error) error {
	return InternalError{Message: message, Cause: cause}
}