package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/blackhole/blackhole/pkg/network"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	configPath = flag.String("config", "config/default.yaml", "Path to configuration file")
	version    = flag.Bool("version", false, "Print version and exit")
)

// Version information (set during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Blackhole Node\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		os.Exit(0)
	}

	// Load configuration
	config, err := network.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Create and start the host
	log.Printf("Starting Blackhole node...")
	host, err := network.NewHost(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create host: %v", err)
	}
	defer host.Close()

	// Get identity info
	identityInfo, err := network.GetIdentityInfo(host)
	if err != nil {
		log.Fatalf("Failed to get identity info: %v", err)
	}

	log.Printf("Node started with ID: %s", identityInfo.PeerID)
	log.Printf("Listening on:")
	for _, addr := range identityInfo.Addresses {
		log.Printf("  %s", addr)
	}

	// Bootstrap if configured
	if len(config.Network.BootstrapPeers) > 0 {
		log.Printf("Bootstrapping with %d peers...", len(config.Network.BootstrapPeers))
		if err := host.Bootstrap(ctx); err != nil {
			log.Printf("Warning: Bootstrap failed: %v", err)
		}
	}

	// Start metrics server if enabled
	if config.Metrics.Enabled {
		go startMetricsServer(config.Metrics.Address, config.Metrics.Path)
	}

	// Main loop
	log.Printf("Node is running. Press Ctrl+C to stop.")
	select {
	case <-sigCh:
		log.Printf("Received shutdown signal")
	case <-ctx.Done():
		log.Printf("Context cancelled")
	}

	// Graceful shutdown
	log.Printf("Shutting down...")
	if err := host.Shutdown(context.Background()); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Printf("Shutdown complete")
}

// startMetricsServer starts the Prometheus metrics HTTP server
func startMetricsServer(address, path string) {
	http.Handle(path, promhttp.Handler())
	log.Printf("Metrics server listening on %s%s", address, path)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Printf("Metrics server error: %v", err)
	}
}