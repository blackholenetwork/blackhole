# Blackhole Network - Project Overview

## Vision

Blackhole Network is a decentralized infrastructure platform that transforms idle computing resources into a global, shared network. Built with a six-layer architecture, home users monetize their unused storage, compute, and bandwidth while developers build applications on a universal data layer where users truly own their data.

## Core Principles

1. **Decentralized Infrastructure**: No central servers or control points
2. **Resource Monetization**: Home users earn tokens for sharing resources
3. **Universal Data Layer**: Same data accessible across all applications
4. **Modular Architecture**: Services organized in clean layers with clear boundaries
5. **User Ownership**: Users own their data and can move freely between services
6. **Antifragile Design**: System gets stronger from volatility and node churn
7. **No Barriers to Entry**: Any device can contribute without commitments
8. **Resilient by Default**: Designed for unreliable home networks (50-80% uptime)
9. **Intelligent Resource Management**: Load-based decisions with economic priority enforcement

## Six-Layer Architecture

### 0. Infrastructure Layer
**Foundation for all other layers**
- **Project Setup**: Go module structure, build system, and development tooling
- **Build Pipeline**: CI/CD workflows, automated testing, cross-platform packaging and distribution

### 1. Core Layer
- **Orchestrator**: System coordination, component lifecycle management, health monitoring, and startup/shutdown sequencing
- **Security**: Authentication, authorization, and self-sovereign identity (DID) management
- **Networking**: P2P communication, peer discovery, and inter-component messaging using libp2p
- **ResourceManager**: Resource allocation, job scheduling, and economic priority management
- **Monitoring**: Telemetry collection, analytics processing, and system notifications

### 2. Resources Layer
**What can be shared**
- **Storage**: Distributed file and data storage with CID-based addressing VFS
- **Compute**: CPU/GPU processing power with economic priority
- **Bandwidth**: Content delivery and routing with allocation management
- **Memory**: RAM allocation with real-time monitoring

### 3. Data Layer
**What makes data portable**
- **Schema**: Dynamic schema evolution with metadata management
- **Indexer**: Global search and discovery with Bleve engine
- **Query**: SQL-like analytics across distributed services
- **Search**: ML-enhanced intelligent search across network data

### 4. Service Layer
**How services are delivered**
- **WebServer**: HTTP/WebSocket API with comprehensive storage integration
- **RealTime**: WebSocket/WebRTC communication for live interactions
- **Social**: Comprehensive social graph system with VFS integration

### 5. Economic Layer
**How value is exchanged**
- **Incentive**: Real-time market distribution with load-aware pricing
- **Contract**: Traditional subscription management with tier-based priority

## Technology Stack

### Core Technologies
- **Language**: Go (performance, single binary)
- **Web Framework**: Fiber v2 for high-performance HTTP/WebSocket
- **P2P Network**: libp2p with DHT-based discovery
- **Storage**: IPFS-compatible CID addressing with Reed-Solomon erasure coding
- **Load Monitoring**: gopsutil for real-time system metrics
- **Search Engine**: Bleve for full-text search and indexing
- **Database**: Embedded BadgerDB for local state

### Architecture Design
- **Six-Layer Structure**: Infrastructure → Core → Resources → Data → Service → Economic
- **Monolithic**: Single binary with modular internal services
- **Dependency Injection**: Clean interfaces between services
- **Service Lifecycle**: Managed start/stop with health checks
- **Context-based**: Proper cancellation and timeout handling
- **Load-Aware**: Intelligent resource allocation with economic priority
- **Economic Tiers**: Ultimate > Advance > Normal > Free user prioritization
- **Cross-Platform**: Unified codebase with platform-specific distribution

## Use Cases

### Resource Providers (Home Users)
- Run lightweight node software
- Share idle storage, compute, bandwidth
- Earn tokens automatically
- Set resource limits via dashboard

### Application Developers
- Build on decentralized infrastructure
- Access universal data layer
- No infrastructure management

### Service Providers
- Create value-added services
- Compete on UX and features
- Access existing user base
- Examples:
  - "YouTube for Education"
  - "Privacy-focused Social Network"
  - "Decentralized Web Hosting"

## Distribution Strategy

### Desktop Installation
- **macOS**: Homebrew tap and formula
- **Windows**: MSI installer with auto-update
- **Linux**: Package managers + install script

### Node Operation
- One-click install and start
- Automatic resource detection
- Web dashboard at localhost:8080
- Background service operation

## Economic Model

### Resource Pricing
- **Storage**: Per GB per month
- **Compute**: Per CPU/GPU hour
- **Bandwidth**: Per GB transferred
- User and content driven
- Subscription model
- Cost sharing with all resource providers

### Economic Flow
1. Resource providers earn tokens
2. Automatic calculation and verification
3. Instant settlement on completion

### Incentive Alignment
- Purely based on job or work done
- Bad actors lose opportunity
- Network effects reward growth

## Development Phases

### Phase 0: Infrastructure (Feb 2025)
- Project Setup: Go module structure and development tooling
- Build Pipeline: CI/CD, testing, packaging, and distribution

### Phase 1: Core Layer (Mar 2025)
- Orchestrator: System coordination, lifecycle management, and health monitoring
- Security: Authentication, authorization, and DID management
- Networking: P2P communication using libp2p
- ResourceManager: Resource allocation and job scheduling
- Monitoring: Telemetry collection and system notifications

### Phase 2: Resources Layer (Apr 2025)
- Storage: Distributed file storage with CID addressing
- Compute: CPU/GPU processing with economic priority
- Bandwidth: Content delivery and routing management
- Memory: RAM allocation with real-time monitoring

### Phase 3: Data Layer (May 2025)
- Schema: Dynamic schema evolution with metadata management
- Indexer: Global search and discovery with Bleve engine
- Query: SQL-like analytics across distributed services
- Search: ML-enhanced intelligent search across network data

### Phase 4: Service Layer (Jun 2025)
- WebServer: HTTP/WebSocket API with Fiber v2
- RealTime: WebSocket/WebRTC communication for live interactions
- Social: Comprehensive social graph system with VFS integration

### Phase 5: Economic Layer (Jul 2025)
- Incentive: Real-time market distribution with load-aware pricing
- Contract: Subscription management with tier-based priority

## Success Metrics

- **Network Growth**: Active nodes, total resources
- **Usage**: Storage/compute utilization rates
- **Economic**: Provider earnings
- **Developer**: Apps built, API calls
- **User**: Data portability usage, cross-app activity