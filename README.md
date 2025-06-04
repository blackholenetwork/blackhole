# Blackhole Network

A decentralized infrastructure platform that transforms idle computing resources into a global shared network.

## Overview

Blackhole Network enables home users to monetize their unused storage, compute, bandwidth, and memory resources while developers build applications on a universal data layer where users truly own their data.

## Architecture

The system is built with a six-layer architecture:

0. **Infrastructure Layer**: Build pipeline, CI/CD, packaging, distribution
1. **Core Layer**: Orchestrator, Security (DID), Networking (libp2p), ResourceManager, Monitoring
2. **Resources Layer**: Storage (VFS), Compute (CPU/GPU), Bandwidth, Memory allocation
3. **Data Layer**: Schema evolution, Indexer (Bleve), Query (SQL-like), Search (ML-enhanced)
4. **Service Layer**: WebServer, RealTime (WebSocket/WebRTC), Social graph
5. **Economic Layer**: Incentive distribution, Contract management

## Getting Started

### Prerequisites

- Go 1.22 or higher
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/blackholenetwork/blackhole.git
cd blackhole

# Install dependencies
make deps

# Build the binary
make build

# Run tests
make test
```

### Running a Node

```bash
# Start the node
./blackhole node start

# Check node status
./blackhole node status

# Stop the node
./blackhole node stop
```

### Development

```bash
# Set up development environment
make dev-setup

# Run in development mode
make run

# Run linters
make lint

# Format code
make fmt
```

## Project Structure

```
blackhole/
├── cmd/blackhole/          # Main application entry point
├── pkg/                    # Public packages
│   ├── core/              # Core layer components
│   ├── resources/         # Resources layer
│   ├── data/              # Data layer
│   ├── service/           # Service layer
│   ├── economic/          # Economic layer
│   └── common/            # Shared utilities
├── internal/              # Private packages
│   ├── config/            # Configuration
│   └── version/           # Version information
├── docs/                  # Documentation
├── test/                  # Integration tests
└── scripts/               # Build and deployment scripts
```

## Documentation

- [Project Overview](PROJECT.md)
- [Technical Summary](BLACKHOLE_NETWORK_SUMMARY.md)
- [Architecture Documentation](docs/architecture/)
- [Development Standards](docs/standards/)

## Contributing

Please read our contributing guidelines before submitting pull requests.

## License

Copyright (c) 2025 Blackhole Network. All rights reserved.