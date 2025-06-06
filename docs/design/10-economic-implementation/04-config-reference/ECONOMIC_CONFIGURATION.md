# Economic Configuration Reference

This document provides comprehensive configuration options for the economic system based on the actual implementation.

## Configuration Structure

Economic configuration is defined in YAML format within the main application config file.

## Base Configuration Schema

```yaml
economic:
  # Core economic engine settings
  core:
    use_realtime_billing: true          # Enable per-second billing vs monthly
    billing_cycle: "monthly"            # monthly, weekly, daily
    currency: "USD"                     # Base currency for all operations
    timezone: "UTC"                     # Timezone for billing calculations
    
  # Subscription tier definitions
  subscription_tiers:
    free:
      price: 0.00
      storage_quota_gb: 1.0
      bandwidth_quota_gb: 5.0
      compute_quota_hours: 0.5
    normal:
      price: 10.00
      storage_quota_gb: 50.0
      bandwidth_quota_gb: 100.0
      compute_quota_hours: 10.0
    advance:
      price: 25.00
      storage_quota_gb: 200.0
      bandwidth_quota_gb: 500.0
      compute_quota_hours: 50.0
    ultimate:
      price: 50.00
      storage_quota_gb: 1000.0
      bandwidth_quota_gb: 2000.0
      compute_quota_hours: 200.0
      
  # Revenue distribution percentages
  distribution:
    content_creator_percentage: 70.0    # Fixed allocation to content creators
    network_ops_percentage: 2.5         # Fixed allocation to network operations
    app_developer_percentage: 2.5       # Fixed allocation to app developers
    infrastructure_percentage: 25.0     # Remaining for infrastructure providers
    
  # Market-based pricing rates (AWS-compatible)
  market_rates:
    storage_per_gb_month: 0.023         # S3 Standard pricing
    bandwidth_per_gb: 0.09              # Data transfer out pricing
    compute_per_cpu_hour: 0.0464        # t3.medium equivalent
    memory_per_gb_hour: 0.0058          # Memory pricing
    storage_read_per_1k: 0.0004         # Read operation pricing
    storage_write_per_1k: 0.005         # Write operation pricing
    content_delivery_per_gb: 0.085      # CloudFront equivalent
    gpu_compute_per_hour: 2.50          # GPU instance pricing
    
  # Content economy configuration
  content_economy:
    enabled: true
    min_content_price: 1.00             # Minimum content price
    max_content_price: 1000.00          # Maximum content price
    max_investors_per_creator: 1000     # Maximum investors per creator
    creator_royalty_rate: 0.10          # 10% royalty on secondary sales
    marketplace_fee_rate: 0.025         # 2.5% platform fee
    tip_investor_share: 0.10            # 10% of tips shared with investors
    investment_threshold: 10.00         # Minimum investment amount
    
  # Real-time billing configuration
  realtime_billing:
    enabled: true
    distribution_interval_seconds: 1    # How often to distribute rewards
    aggregation_window_seconds: 60      # Usage aggregation window
    max_pending_distributions: 1000    # Maximum queued distributions
    
  # Persistence and audit configuration
  persistence:
    retention_period: "7y"              # 7 years for regulatory compliance
    audit_level: "full"                 # none, basic, full
    encryption_enabled: true            # Encrypt sensitive data
    backup_interval: "24h"              # Backup frequency
    
  # Payment processing configuration
  payment_processor:
    provider: "stripe"                  # stripe, mock, custom
    webhook_endpoint: "/api/v1/webhooks/payments"
    retry_attempts: 3
    retry_delay_seconds: 30
    
  # Payment processor specific configs
  stripe:
    public_key: "${STRIPE_PUBLIC_KEY}"
    secret_key: "${STRIPE_SECRET_KEY}"
    webhook_secret: "${STRIPE_WEBHOOK_SECRET}"
    
  # Efficiency and performance settings
  efficiency:
    provider_efficiency_threshold: 0.80  # Minimum efficiency for bonuses
    efficiency_bonus_percentage: 0.20    # 20% bonus for efficient providers
    market_rate_update_interval: "1h"    # How often to update market rates
    
  # Compliance and regulatory settings
  compliance:
    gdpr_enabled: true                   # GDPR compliance features
    data_residency: "auto"               # auto, EU, US, specific region
    audit_retention_years: 7             # Audit data retention
    regulatory_reporting: true           # Generate regulatory reports
    
  # Dashboard and analytics configuration
  dashboard:
    realtime_updates: true               # Enable WebSocket updates
    cache_duration_seconds: 300          # Dashboard data cache duration
    max_concurrent_streams: 1000         # Max WebSocket connections
    
  # Advanced features
  advanced:
    dynamic_pricing: false               # Enable dynamic market pricing
    prediction_engine: false             # Enable revenue prediction
    fraud_detection: true                # Enable fraud detection
    automated_payouts: true              # Enable automatic payouts
    
  # Resource-specific configurations
  resources:
    storage:
      efficiency_weight: 0.35            # Weight in efficiency calculations
      base_allocation_percentage: 8.75   # % of infrastructure pool
      
    bandwidth:
      efficiency_weight: 0.40            # Weight in efficiency calculations
      base_allocation_percentage: 10.0   # % of infrastructure pool
      
    compute:
      efficiency_weight: 0.25            # Weight in efficiency calculations
      base_allocation_percentage: 6.25   # % of infrastructure pool
```

## Environment Variable Overrides

Many configuration values can be overridden via environment variables:

```bash
# Core settings
BLACKHOLE_ECONOMIC_USE_REALTIME_BILLING=true
BLACKHOLE_ECONOMIC_CURRENCY=USD

# Payment processor
STRIPE_PUBLIC_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Database
BLACKHOLE_ECONOMIC_DB_PATH=/data/economic.db
BLACKHOLE_ECONOMIC_BACKUP_PATH=/backups/

# Security
BLACKHOLE_ECONOMIC_ENCRYPTION_KEY=base64_encoded_key
BLACKHOLE_ECONOMIC_AUDIT_LEVEL=full
```

## Development vs Production Configurations

### Development Configuration (`configs/blackhole-dev.yaml`)

```yaml
economic:
  core:
    use_realtime_billing: false         # Use simpler monthly billing for dev
    currency: "USD"
    
  subscription_tiers:
    free:
      price: 0.00
      storage_quota_gb: 10.0            # Higher quotas for testing
      bandwidth_quota_gb: 50.0
    normal:
      price: 1.00                       # Lower prices for testing
      storage_quota_gb: 100.0
      
  market_rates:
    storage_per_gb_month: 0.001         # Reduced rates for development
    bandwidth_per_gb: 0.01
    compute_per_cpu_hour: 0.005
    
  payment_processor:
    provider: "mock"                    # Use mock payments in development
    
  persistence:
    retention_period: "30d"             # Shorter retention for development
    audit_level: "basic"
    encryption_enabled: false           # Disable encryption for easier debugging
    
  compliance:
    gdpr_enabled: false                 # Disable compliance features
    regulatory_reporting: false
```

### Production Configuration (`configs/blackhole.yaml`)

```yaml
economic:
  core:
    use_realtime_billing: true          # Full real-time billing
    currency: "USD"
    
  subscription_tiers:
    # Production pricing as defined above
    
  market_rates:
    # Full AWS-compatible pricing
    
  payment_processor:
    provider: "stripe"                  # Real payment processing
    
  persistence:
    retention_period: "7y"              # Full regulatory compliance
    audit_level: "full"
    encryption_enabled: true
    
  compliance:
    gdpr_enabled: true                  # Full compliance features
    regulatory_reporting: true
    
  advanced:
    dynamic_pricing: true               # Enable advanced features
    prediction_engine: true
    fraud_detection: true
```

## Configuration Validation

The system validates configuration on startup:

```go
type ConfigValidationRules struct {
    // Percentages must sum to 100
    DistributionPercentagesSum float64 `validate:"eq=100"`
    
    // Subscription prices must be non-negative
    SubscriptionPrices []float64 `validate:"dive,gte=0"`
    
    // Market rates must be positive
    MarketRates map[string]float64 `validate:"dive,gt=0"`
    
    // Content economy limits
    MaxInvestorsPerCreator int `validate:"gte=1,lte=10000"`
    InvestmentThreshold float64 `validate:"gte=0.01"`
}
```

## Configuration Loading Order

1. Default configuration (embedded in binary)
2. Main config file (`configs/blackhole.yaml`)
3. Environment-specific overrides (`configs/blackhole-dev.yaml`)
4. Environment variables
5. Command-line flags

## Dynamic Configuration Updates

Some configuration values can be updated at runtime via API:

```bash
# Update market rates
curl -X POST /api/v1/admin/config/market-rates \
  -H "Authorization: Bearer admin_token" \
  -d '{"storage_per_gb_month": 0.025}'

# Update distribution percentages (requires system restart)
curl -X POST /api/v1/admin/config/distribution \
  -H "Authorization: Bearer admin_token" \
  -d '{"infrastructure_percentage": 30.0}'
```

## Configuration Monitoring

The system provides configuration change auditing:

```json
{
  "config_changes": [
    {
      "timestamp": "2024-01-10T15:30:00Z",
      "admin_user": "admin_123",
      "field": "market_rates.storage_per_gb_month",
      "old_value": 0.023,
      "new_value": 0.025,
      "reason": "Market rate adjustment"
    }
  ]
}
```

## Common Configuration Patterns

### High-Performance Setup
```yaml
economic:
  realtime_billing:
    distribution_interval_seconds: 0.1  # Very frequent distributions
    aggregation_window_seconds: 10      # Short aggregation window
  dashboard:
    cache_duration_seconds: 60          # Faster cache refresh
```

### Conservative Setup
```yaml
economic:
  core:
    use_realtime_billing: false         # Traditional monthly billing
  persistence:
    audit_level: "full"                 # Maximum audit trail
  compliance:
    gdpr_enabled: true                  # Full compliance
```

### High-Volume Setup
```yaml
economic:
  dashboard:
    max_concurrent_streams: 10000       # Support many concurrent users
  persistence:
    backup_interval: "6h"               # More frequent backups
  advanced:
    automated_payouts: true             # Reduce manual processing
```

## Configuration Best Practices

1. **Environment Separation**: Always use separate configs for dev/staging/prod
2. **Secret Management**: Never commit secrets to config files, use environment variables
3. **Gradual Changes**: Test configuration changes in staging before production
4. **Monitoring**: Monitor configuration-related metrics after changes
5. **Backup**: Always backup current config before making changes
6. **Documentation**: Document the reason for each configuration change

## Troubleshooting Configuration Issues

### Common Issues

1. **Invalid Percentages**: Distribution percentages don't sum to 100%
2. **Missing Secrets**: Payment processor secrets not configured
3. **Invalid Rates**: Negative market rates specified
4. **Retention Conflicts**: Retention period shorter than compliance requirements

### Validation Commands

```bash
# Validate configuration
./blackhole validate-config --config configs/blackhole.yaml

# Test economic configuration
./blackhole test-economic --dry-run

# Check compliance settings
./blackhole compliance-check --config configs/blackhole.yaml
```