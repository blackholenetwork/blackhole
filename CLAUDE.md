# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Blackhole Network is a decentralized infrastructure platform written in Go that transforms idle computing resources into a global shared network. The system follows a six-layer architecture (Infrastructure, Core, Resources, Data, Service, Economic) with a monolithic design using modular internal services.

## Technology Stack

- **Language**: Go (targeting single binary distribution)
- **Web Framework**: Fiber v2 for HTTP/WebSocket APIs
- **P2P Network**: libp2p with DHT-based peer discovery
- **Storage**: IPFS-compatible CID addressing with Reed-Solomon erasure coding
- **Search**: Bleve engine for full-text search and indexing
- **Database**: BadgerDB for embedded local state
- **Monitoring**: gopsutil for real-time system metrics

## Architecture Principles

- **Modular Services**: Clean dependency injection between internal services
- **Service Lifecycle**: Managed startup/shutdown with health monitoring
- **Context-based**: Proper cancellation and timeout handling throughout
- **Load-Aware**: Economic priority management (Ultimate > Advance > Normal > Free)
- **Antifragile Design**: System resilience with 50-80% node uptime assumptions

## Core Components

### Six-Layer Architecture
0. **Infrastructure Layer**: Project setup, Build pipeline (CI/CD, packaging, distribution)
1. **Core Layer**: Orchestrator (with lifecycle management), Security (DID), Networking (libp2p), ResourceManager, Monitoring
2. **Resources Layer**: Storage (VFS), Compute (CPU/GPU), Bandwidth, Memory allocation
3. **Data Layer**: Schema evolution, Indexer (Bleve), Query (SQL-like), Search (ML-enhanced)
4. **Service Layer**: WebServer, RealTime (WebSocket/WebRTC), Social graph
5. **Economic Layer**: Incentive distribution, Contract management

## Development Commands

When implementing this system, the standard Go development workflow will apply:

```bash
# Build the application
go build -o blackhole ./cmd/blackhole

# Run tests
go test ./...

# Run specific test
go test -v ./pkg/[component]

# Format code
go fmt ./...

# Vet code
go vet ./...

# Generate dependencies
go mod tidy
```

## Key Design Constraints

- **Single Binary**: All components must compile into one executable
- **Resource Limits**: Design for home network constraints and intermittent connectivity
- **Economic Priority**: All resource allocation must respect tier-based user prioritization
- **P2P First**: Avoid centralized dependencies; use libp2p for all inter-node communication
- **CID Addressing**: All data storage must use content-addressed identifiers
- **Embedded Storage**: Use BadgerDB for local state, not external databases

## Target Deployment

- Desktop installation via package managers (Homebrew, MSI, APT)
- Background service with web dashboard at localhost:8080
- Automatic resource detection and one-click setup
- Cross-platform support (macOS, Windows, Linux)
