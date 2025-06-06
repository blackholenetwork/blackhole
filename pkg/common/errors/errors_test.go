package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		message  string
		expected string
	}{
		{
			name:     "basic validation error",
			field:    "email",
			message:  "invalid format",
			expected: "validation error for field 'email': invalid format",
		},
		{
			name:     "empty field",
			field:    "",
			message:  "required",
			expected: "validation error for field '': required",
		},
		{
			name:     "special characters",
			field:    "user.name",
			message:  "contains invalid characters",
			expected: "validation error for field 'user.name': contains invalid characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidationError{Field: tt.field, Message: tt.message}
			if got := err.Error(); got != tt.expected {
				t.Errorf("ValidationError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		id       string
		expected string
	}{
		{
			name:     "user not found",
			resource: "user",
			id:       "123",
			expected: "user not found: 123",
		},
		{
			name:     "file not found",
			resource: "file",
			id:       "abc-def",
			expected: "file not found: abc-def",
		},
		{
			name:     "empty resource",
			resource: "",
			id:       "456",
			expected: " not found: 456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NotFoundError{Resource: tt.resource, ID: tt.id}
			if got := err.Error(); got != tt.expected {
				t.Errorf("NotFoundError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConflictError(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		message  string
		expected string
	}{
		{
			name:     "duplicate username",
			resource: "username",
			message:  "already exists",
			expected: "conflict for username: already exists",
		},
		{
			name:     "resource locked",
			resource: "file",
			message:  "currently being modified",
			expected: "conflict for file: currently being modified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ConflictError{Resource: tt.resource, Message: tt.message}
			if got := err.Error(); got != tt.expected {
				t.Errorf("ConflictError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTimeoutError(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		duration  string
		expected  string
	}{
		{
			name:      "database timeout",
			operation: "database query",
			duration:  "30s",
			expected:  "operation 'database query' timed out after 30s",
		},
		{
			name:      "file upload timeout",
			operation: "file upload",
			duration:  "5m",
			expected:  "operation 'file upload' timed out after 5m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := TimeoutError{Operation: tt.operation, Duration: tt.duration}
			if got := err.Error(); got != tt.expected {
				t.Errorf("TimeoutError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInternalError(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		cause    error
		expected string
	}{
		{
			name:     "without cause",
			message:  "system failure",
			cause:    nil,
			expected: "internal error: system failure",
		},
		{
			name:     "with cause",
			message:  "database connection failed",
			cause:    errors.New("connection refused"),
			expected: "internal error: database connection failed (caused by: connection refused)",
		},
		{
			name:     "with wrapped cause",
			message:  "service unavailable",
			cause:    fmt.Errorf("wrapped: %w", errors.New("original error")),
			expected: "internal error: service unavailable (caused by: wrapped: original error)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InternalError{Message: tt.message, Cause: tt.cause}
			if got := err.Error(); got != tt.expected {
				t.Errorf("InternalError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInternalErrorUnwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := InternalError{Message: "wrapper", Cause: cause}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("InternalError.Unwrap() = %v, want %v", unwrapped, cause)
	}

	// Test nil cause
	err2 := InternalError{Message: "no cause", Cause: nil}
	if unwrapped2 := err2.Unwrap(); unwrapped2 != nil {
		t.Errorf("InternalError.Unwrap() with nil cause = %v, want nil", unwrapped2)
	}
}

func TestNew(t *testing.T) {
	msg := "test error"
	err := New(msg)

	if err == nil {
		t.Fatal("New() returned nil")
	}

	if err.Error() != msg {
		t.Errorf("New() = %v, want %v", err.Error(), msg)
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		message  string
		expected string
		isNil    bool
	}{
		{
			name:     "wrap existing error",
			err:      errors.New("original"),
			message:  "context",
			expected: "context: original",
			isNil:    false,
		},
		{
			name:     "wrap nil error",
			err:      nil,
			message:  "context",
			expected: "",
			isNil:    true,
		},
		{
			name:     "wrap with empty message",
			err:      errors.New("original"),
			message:  "",
			expected: ": original",
			isNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := Wrap(tt.err, tt.message)

			if tt.isNil {
				if wrapped != nil {
					t.Errorf("Wrap() = %v, want nil", wrapped)
				}
			} else {
				if wrapped == nil {
					t.Fatal("Wrap() returned nil")
				}
				if got := wrapped.Error(); got != tt.expected {
					t.Errorf("Wrap() = %v, want %v", got, tt.expected)
				}

				// Check unwrapping
				if tt.err != nil {
					if !errors.Is(wrapped, tt.err) {
						t.Errorf("errors.Is(wrapped, original) = false, want true")
					}
				}
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("NewValidationError", func(t *testing.T) {
		err := NewValidationError("email", "invalid format")
		expected := "validation error for field 'email': invalid format"
		if err.Error() != expected {
			t.Errorf("NewValidationError() = %v, want %v", err.Error(), expected)
		}

		// Type assertion
		if _, ok := err.(ValidationError); !ok { //nolint:gocritic // false positive
			t.Errorf("NewValidationError() type = %T, want ValidationError", err)
		}
	})

	t.Run("NewNotFoundError", func(t *testing.T) {
		err := NewNotFoundError("user", "123")
		expected := "user not found: 123"
		if err.Error() != expected {
			t.Errorf("NewNotFoundError() = %v, want %v", err.Error(), expected)
		}

		// Type assertion
		if _, ok := err.(NotFoundError); !ok { //nolint:gocritic // false positive
			t.Errorf("NewNotFoundError() type = %T, want NotFoundError", err)
		}
	})

	t.Run("NewConflictError", func(t *testing.T) {
		err := NewConflictError("resource", "already exists")
		expected := "conflict for resource: already exists"
		if err.Error() != expected {
			t.Errorf("NewConflictError() = %v, want %v", err.Error(), expected)
		}

		// Type assertion
		if _, ok := err.(ConflictError); !ok { //nolint:gocritic // false positive
			t.Errorf("NewConflictError() type = %T, want ConflictError", err)
		}
	})

	t.Run("NewTimeoutError", func(t *testing.T) {
		err := NewTimeoutError("operation", "5s")
		expected := "operation 'operation' timed out after 5s"
		if err.Error() != expected {
			t.Errorf("NewTimeoutError() = %v, want %v", err.Error(), expected)
		}

		// Type assertion
		if _, ok := err.(TimeoutError); !ok { //nolint:gocritic // false positive
			t.Errorf("NewTimeoutError() type = %T, want TimeoutError", err)
		}
	})

	t.Run("NewInternalError", func(t *testing.T) {
		cause := errors.New("cause")
		err := NewInternalError("message", cause)
		expected := "internal error: message (caused by: cause)"
		if err.Error() != expected {
			t.Errorf("NewInternalError() = %v, want %v", err.Error(), expected)
		}

		// Type assertion
		internalErr, ok := err.(InternalError) //nolint:gocritic // false positive
		if !ok {
			t.Errorf("NewInternalError() type = %T, want InternalError", err)
		}

		// Check unwrap
		if internalErr.Unwrap() != cause {
			t.Errorf("NewInternalError().Unwrap() = %v, want %v", internalErr.Unwrap(), cause)
		}
	})
}

// Benchmark tests
func BenchmarkValidationError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := ValidationError{Field: "email", Message: "invalid format"}
		_ = err.Error()
	}
}

func BenchmarkWrap(b *testing.B) {
	err := errors.New("original error")
	for i := 0; i < b.N; i++ {
		_ = Wrap(err, "context message")
	}
}

func BenchmarkNewInternalError(b *testing.B) {
	cause := errors.New("cause")
	for i := 0; i < b.N; i++ {
		_ = NewInternalError("message", cause)
	}
}
