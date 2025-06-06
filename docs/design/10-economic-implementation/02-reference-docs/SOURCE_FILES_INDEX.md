# Economic Implementation Source Files Index

This directory contains the actual source code files from the economic implementation, copied for reference.

## Directory Structure

```
source-code/
├── incentive/                  # Main economic engine
│   ├── service.go             # Core incentive service implementation
│   ├── types.go               # Data structures and types
│   ├── config.go              # Configuration structures
│   ├── market_pricing.go      # Market-based pricing engine
│   ├── content_economy.go     # Content monetization system
│   ├── calculator.go          # Reward calculation algorithms
│   ├── usage_tracker.go       # Resource usage tracking
│   ├── pool.go                # Subscription pool management
│   ├── revenue_stream.go      # Revenue stream management
│   ├── live_usage_aggregator.go # Real-time usage aggregation
│   ├── realtime_engine.go     # Real-time distribution engine
│   ├── prorated_billing.go    # Per-second billing implementation
│   ├── billing_cycles.go      # Billing cycle management
│   ├── persistence.go         # Economic data persistence
│   ├── persistence_queries.go # Database query layer
│   ├── streaming_distributor.go # Real-time fund distribution
│   ├── realtime_infrastructure_distributor.go # Infrastructure rewards
│   ├── realtime_content_distributor.go # Content creator rewards
│   ├── realtime_app_developer_distributor.go # Developer rewards
│   ├── unused_funds_distributor.go # Unused fund management
│   └── resource_integration.go # Integration with resource layer
└── contract/                   # Subscription and contract management
    ├── service.go             # Contract service implementation
    ├── types.go               # Contract data structures
    ├── config.go              # Contract configuration
    ├── storage.go             # Contract storage layer
    ├── payment_processor.go   # Payment processing logic
    ├── service_methods.go     # Service method implementations
    └── workers.go             # Background worker processes
```

## Key Files Overview

### Core Service Files

- **`incentive/service.go`**: Main economic engine with dual-mode billing support
- **`contract/service.go`**: Subscription lifecycle and payment management

### Data Structures

- **`incentive/types.go`**: All economic data types including subscriptions, billing events, usage tracking
- **`contract/types.go`**: Contract and subscription management types

### Real-Time System

- **`incentive/prorated_billing.go`**: Per-second revenue calculation and distribution
- **`incentive/realtime_engine.go`**: Orchestrates real-time economic operations
- **`incentive/streaming_distributor.go`**: Manages continuous fund streaming

### Market Economics

- **`incentive/market_pricing.go`**: AWS-compatible pricing with dynamic market rates
- **`incentive/content_economy.go`**: Content investment and monetization system

### Persistence Layer

- **`incentive/persistence.go`**: Regulatory-compliant audit trail and data storage
- **`incentive/persistence_queries.go`**: Optimized database queries for economic data

### Payment Processing

- **`contract/payment_processor.go`**: Multi-provider payment processing (Stripe, etc.)
- **`contract/workers.go`**: Background jobs for payment processing

## Usage Notes

These files represent the actual implementation as of the time of documentation. For the most current version, always refer to the main source tree at `pkg/economic/`.

## Integration Points

The economic system integrates with:
- Resource management layer (`pkg/core/resource_manager.go`)
- Authentication system (`pkg/core/auth_service.go`)
- Web server handlers (`pkg/service/webserver/economics_dashboard_handlers.go`)
- VFS storage system (`pkg/resources/storage/`)

## Configuration

Default configuration can be found in:
- `configs/blackhole.yaml` (production)
- `configs/blackhole-dev.yaml` (development)