// Package main provides the entry point for the Blackhole Network daemon
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/blackholenetwork/blackhole/internal/config"
	"github.com/blackholenetwork/blackhole/internal/version"
	"github.com/blackholenetwork/blackhole/pkg/core"
)

// Version is set at build time
var Version = "dev"

func main() {
	// Set version
	version.Set(Version)

	// Initialize logger
	logger := initLogger()

	// Parse command line arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Validate node command arguments early
	if command == "node" && len(os.Args) < 3 {
		fmt.Println("Usage: blackhole node [start|stop|status]")
		os.Exit(1)
	}

	// Check for unknown commands early
	validCommands := map[string]bool{
		"node":    true,
		"version": true,
		"help":    true,
	}
	if !validCommands[command] {
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	// Create root context after all validation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch command {
	case "node":
		handleNodeCommand(ctx, os.Args[2], logger)

	case "version":
		fmt.Printf("Blackhole Network v%s\n", version.Get())

	case "help":
		printUsage()
	}
}

func handleNodeCommand(ctx context.Context, action string, logger *log.Logger) {
	switch action {
	case "start":
		startNode(ctx, logger)
	case "stop":
		stopNode(logger)
	case "status":
		showNodeStatus(logger)
	default:
		fmt.Printf("Unknown node action: %s\n", action)
		os.Exit(1)
	}
}

func startNode(ctx context.Context, logger *log.Logger) {
	logger.Printf("Starting Blackhole Network node v%s...\n", version.Get())

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize orchestrator with all plugins
	orch, err := core.InitializeOrchestrator(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize orchestrator: %v", err)
	}

	// Start orchestrator
	if err := orch.Start(ctx); err != nil {
		logger.Fatalf("Failed to start orchestrator: %v", err)
	}

	logger.Println("Node started successfully")

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Wait for shutdown signal
	select {
	case <-sigCh:
		logger.Println("Shutdown signal received")
	case <-ctx.Done():
		logger.Println("Context cancelled")
	}

	// Graceful shutdown
	logger.Println("Shutting down node...")
	if err := orch.Stop(ctx); err != nil {
		logger.Printf("Error during shutdown: %v", err)
	}

	logger.Println("Node stopped")
}

func stopNode(logger *log.Logger) {
	// TODO: Implement node stop via API/signal
	logger.Println("Stopping node...")
}

func showNodeStatus(logger *log.Logger) {
	// TODO: Implement node status check
	logger.Println("Node status: Not implemented")
}

func initLogger() *log.Logger {
	return log.New(os.Stdout, "[BLACKHOLE] ", log.LstdFlags|log.Lshortfile)
}

func printUsage() {
	fmt.Println(`Blackhole Network - Decentralized Infrastructure Platform

Usage:
  blackhole <command> [arguments]

Commands:
  node start    Start the Blackhole node
  node stop     Stop the Blackhole node
  node status   Show node status
  version       Show version information
  help          Show this help message

Examples:
  blackhole node start           Start node with default config
  blackhole node start --dev     Start node in development mode
  blackhole version              Show version information

For more information, visit: https://github.com/blackholenetwork/blackhole`)
}
