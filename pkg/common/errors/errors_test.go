package errors

import (
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	err := New("test error")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "test error" {
		t.Errorf("expected 'test error', got %q", err.Error())
	}
}

func TestWrap(t *testing.T) {
	original := errors.New("original error")
	wrapped := Wrap(original, "wrapped")
	
	if wrapped == nil {
		t.Fatal("expected error, got nil")
	}
	
	// Check that the wrapped error contains both messages
	if err := wrapped.Error(); err != "wrapped: original error" {
		t.Errorf("expected 'wrapped: original error', got %q", err)
	}
}

func TestWrapNil(t *testing.T) {
	wrapped := Wrap(nil, "wrapped")
	if wrapped != nil {
		t.Errorf("expected nil when wrapping nil error, got %v", wrapped)
	}
}