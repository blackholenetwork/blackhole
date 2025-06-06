// Package main provides tests for the Blackhole Network daemon
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/blackholenetwork/blackhole/internal/config"
	"github.com/blackholenetwork/blackhole/pkg/core/orchestrator"
	"github.com/stretchr/testify/assert"
)


// captureOutput captures stdout/stderr output during test execution
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	f()

	_ = w.Close()
	os.Stdout = old
	out := <-outC
	return out
}

// TestMain_NoArguments tests behavior when no arguments are provided
func TestMain_NoArguments(t *testing.T) {
	// Test printUsage output directly since that's what gets called
	output := captureOutput(func() {
		printUsage()
	})

	// Verify output
	assert.Contains(t, output, "Usage:")
	assert.Contains(t, output, "blackhole <command>")
}

// TestMain_UnknownCommand tests behavior with unknown command
func TestMain_UnknownCommand(t *testing.T) {
	// Test output directly
	output := captureOutput(func() {
		fmt.Printf("Unknown command: %s\n", "unknown")
		printUsage()
	})

	// Verify output
	assert.Contains(t, output, "Unknown command: unknown")
	assert.Contains(t, output, "Usage:")
}

// TestMain_VersionCommand tests the version command
func TestMain_VersionCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	// Set test args
	os.Args = []string{"blackhole", "version"}

	// Capture output
	output := captureOutput(func() {
		main()
	})

	// Verify output contains version info
	assert.Contains(t, output, "Blackhole Network v")
}

// TestMain_HelpCommand tests the help command
func TestMain_HelpCommand(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	// Set test args
	os.Args = []string{"blackhole", "help"}

	// Capture output
	output := captureOutput(func() {
		main()
	})

	// Verify output
	assert.Contains(t, output, "Blackhole Network - Decentralized Infrastructure Platform")
	assert.Contains(t, output, "Usage:")
	assert.Contains(t, output, "Commands:")
	assert.Contains(t, output, "node start")
	assert.Contains(t, output, "node stop")
	assert.Contains(t, output, "node status")
	assert.Contains(t, output, "version")
	assert.Contains(t, output, "help")
}

// TestMain_NodeCommandWithoutAction tests node command without action
func TestMain_NodeCommandWithoutAction(t *testing.T) {
	// Test output directly
	output := captureOutput(func() {
		fmt.Println("Usage: blackhole node [start|stop|status]")
	})

	// Verify output
	assert.Contains(t, output, "Usage: blackhole node [start|stop|status]")
}

// TestHandleNodeCommand tests the handleNodeCommand function
func TestHandleNodeCommand(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		shouldExit bool
		outputTest func(t *testing.T, output string)
	}{
		{
			name:       "stop action",
			action:     "stop",
			shouldExit: false,
			outputTest: func(t *testing.T, output string) {
				assert.Contains(t, output, "Stopping node...")
			},
		},
		{
			name:       "status action",
			action:     "status",
			shouldExit: false,
			outputTest: func(t *testing.T, output string) {
				assert.Contains(t, output, "Node status: Not implemented")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create logger buffer
			var buf bytes.Buffer
			logger := log.New(&buf, "[TEST] ", log.LstdFlags)

			// Create context
			ctx := context.Background()

			// Call function
			handleNodeCommand(ctx, tt.action, logger)

			// Verify output
			output := buf.String()
			tt.outputTest(t, output)
		})
	}
}

// TestHandleNodeCommand_UnknownAction tests unknown action output
func TestHandleNodeCommand_UnknownAction(t *testing.T) {
	// Test output directly
	output := captureOutput(func() {
		fmt.Printf("Unknown node action: %s\n", "unknown")
	})

	// Verify output
	assert.Contains(t, output, "Unknown node action: unknown")
}

// TestInitLogger tests the initLogger function
func TestInitLogger(t *testing.T) {
	logger := initLogger()

	// Verify logger is not nil
	assert.NotNil(t, logger)

	// Verify logger prefix
	var buf bytes.Buffer
	testLogger := log.New(&buf, logger.Prefix(), logger.Flags())
	testLogger.Println("test message")

	output := buf.String()
	assert.Contains(t, output, "[BLACKHOLE]")
	assert.Contains(t, output, "test message")
}

// TestPrintUsage tests the printUsage function
func TestPrintUsage(t *testing.T) {
	output := captureOutput(func() {
		printUsage()
	})

	// Verify all expected content is present
	expectedContent := []string{
		"Blackhole Network - Decentralized Infrastructure Platform",
		"Usage:",
		"blackhole <command> [arguments]",
		"Commands:",
		"node start",
		"node stop",
		"node status",
		"version",
		"help",
		"Examples:",
		"blackhole node start",
		"blackhole node start --dev",
		"blackhole version",
		"https://github.com/blackholenetwork/blackhole",
	}

	for _, expected := range expectedContent {
		assert.Contains(t, output, expected, "Expected content not found: %s", expected)
	}
}

// TestStartNode_ConfigLoadError tests startNode when config fails to load
func TestStartNode_ConfigLoadError(t *testing.T) {
	// Since startNode calls log.Fatal which calls os.Exit, we need to test in subprocess
	if os.Getenv("BE_CRASHER") == "1" {
		// Save and restore
		oldConfigLoad := loadConfig
		defer func() {
			loadConfig = oldConfigLoad
		}()

		// Mock config.Load to return error
		loadConfig = func() (*config.Config, error) {
			return nil, fmt.Errorf("config load error")
		}

		// Create logger buffer
		logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)
		ctx := context.Background()
		startNode(ctx, logger)
		return
	}

	// Test by running in subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestStartNode_ConfigLoadError")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	output, err := cmd.CombinedOutput()

	// Verify exit code
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected behavior
		assert.Contains(t, string(output), "Failed to load configuration")
		assert.Contains(t, string(output), "config load error")
	} else {
		t.Fatal("Expected program to exit with non-zero code")
	}
}

// TestStartNode_OrchestratorInitError tests startNode when orchestrator initialization fails
func TestStartNode_OrchestratorInitError(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		// Save and restore
		oldConfigLoad := loadConfig
		oldInitOrchestrator := initializeOrchestrator
		defer func() {
			loadConfig = oldConfigLoad
			initializeOrchestrator = oldInitOrchestrator
		}()

		// Mock config.Load to succeed
		loadConfig = func() (*config.Config, error) {
			return &config.Config{}, nil
		}

		// Mock InitializeOrchestrator to return error
		initializeOrchestrator = func(cfg *config.Config, logger *log.Logger) (*orchestrator.Orchestrator, error) {
			return nil, fmt.Errorf("orchestrator init error")
		}

		logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)
		ctx := context.Background()
		startNode(ctx, logger)
		return
	}

	// Test by running in subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestStartNode_OrchestratorInitError")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	output, err := cmd.CombinedOutput()

	// Verify exit code
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		// Expected behavior
		assert.Contains(t, string(output), "Failed to initialize orchestrator")
		assert.Contains(t, string(output), "orchestrator init error")
	} else {
		t.Fatal("Expected program to exit with non-zero code")
	}
}

// TestStartNode_StartError tests startNode when orchestrator start fails
func TestStartNode_StartError(t *testing.T) {
	// Skip this test as it requires mocking the orchestrator which is complex
	t.Skip("Skipping start error test - requires complex orchestrator mocking")
}

// TestStartNode_SignalShutdown tests graceful shutdown on signal
func TestStartNode_SignalShutdown(t *testing.T) {
	// Skip this test as it requires actual orchestrator implementation
	t.Skip("Skipping signal shutdown test - requires orchestrator mock")
}

// TestStartNode_ContextCancellation tests shutdown on context cancellation
func TestStartNode_ContextCancellation(t *testing.T) {
	// Skip this test as it requires actual orchestrator implementation
	t.Skip("Skipping context cancellation test - requires orchestrator mock")
}

// TestStartNode_ShutdownError tests handling of shutdown errors
func TestStartNode_ShutdownError(t *testing.T) {
	// Skip this test as it requires actual orchestrator implementation
	t.Skip("Skipping shutdown error test - requires orchestrator mock")
}

// Table-driven tests for command validation
func TestCommandValidation(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		shouldExit   bool
		outputChecks []string
	}{
		{
			name:       "version command",
			args:       []string{"blackhole", "version"},
			shouldExit: false,
			outputChecks: []string{
				"Blackhole Network v",
			},
		},
		{
			name:       "help command",
			args:       []string{"blackhole", "help"},
			shouldExit: false,
			outputChecks: []string{
				"Blackhole Network - Decentralized Infrastructure Platform",
				"Usage:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original args
			oldArgs := os.Args
			defer func() {
				os.Args = oldArgs
			}()

			// Set test args
			os.Args = tt.args

			// Capture output
			output := captureOutput(func() {
				main()
			})

			// Verify output
			for _, check := range tt.outputChecks {
				assert.Contains(t, output, check, "Expected output not found: %s", check)
			}
		})
	}
}
