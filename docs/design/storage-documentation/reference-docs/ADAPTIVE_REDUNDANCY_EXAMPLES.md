# Adaptive Redundancy Examples

## Real-World Scenarios

### Scenario 1: Viral Video
```
Day 1: User uploads 500MB video
- Initial: 10+5 encoding (15 chunks total)
- Distribution: 15 nodes

Day 2: Video starts trending (100 views)
- Boost to: 10+6 encoding (16 chunks)
- Distribution: 20 nodes

Day 3: Goes viral (5,000 views)
- Boost to: 10+10 encoding (20 chunks)
- Distribution: 50 nodes across regions
- Automatic geographic spreading for global access

Day 10: Traffic normalizes (500 views/day)
- Maintain: 10+8 encoding (18 chunks)
- Distribution: 30 nodes

Day 30: Becomes archive content (50 views/day)
- Reduce to: 10+5 encoding (15 chunks)
- Distribution: 15 nodes

Day 365: Rarely accessed
- Reduce to: 10+2 encoding (12 chunks)
- Distribution: 10 nodes
- Storage cost: 50% of original
```

### Scenario 2: Personal Photo Album
```
Day 1: User uploads 50MB photo album
- Initial: 10+5 encoding (15 chunks)
- Distribution: 15 nodes

Day 7: Accessed once by owner
- Maintain: 10+5 encoding
- Mark as "personal content" pattern

Day 30: No access
- Reduce to: 10+3 encoding (13 chunks)
- Distribution: 12 nodes

Day 90: Still no access
- Reduce to: 10+2 encoding (12 chunks)
- Distribution: 10 nodes

Day 180: Owner shares with family (10 accesses)
- Detect spike, boost to: 10+4 encoding
- Temporary boost for 7 days

Day 365: Archive status
- Minimum: 10+1 encoding (11 chunks)
- Cost: 20% of original
- Still recoverable but minimal redundancy
```

### Scenario 3: Company Dataset
```
Initial: 1GB dataset for machine learning
- Start: 10+5 encoding (15 chunks of ~70MB each)
- Distribution: 15 nodes

Week 1-4: Daily access by research team (50 accesses/day)
- Boost to: 10+7 encoding (17 chunks)
- Identify as "workday pattern"
- Pre-warm chunks Monday-Friday 8am

Month 2: Project intensity increases (200 accesses/day)
- Boost to: 10+8 encoding (18 chunks)
- Spread across 3 geographic regions
- Cache hot chunks near frequent accessors

Month 3: Project completes
- Gradual reduction to: 10+4 encoding
- Maintain workday access pattern

Year 2: Archived for compliance
- Minimum: 10+1 encoding
- Compress before storage
- 90% cost reduction
```

### Scenario 4: News Article with Images
```
Hour 0: Breaking news article published (10MB)
- Initial: 10+5 encoding
- Predict high access, preemptive boost to: 10+7

Hour 1: 1,000 views
- Boost to: 10+9 encoding (19 chunks)
- Geographic distribution across continents

Hour 6: Peak traffic (10,000 views)
- Maximum: 10+10 encoding (20 chunks)
- 60 nodes globally
- Edge caching enabled

Day 2: Traffic declining (1,000 views)
- Maintain: 10+8 encoding

Week 2: Becomes archive (100 views/day)
- Reduce to: 10+6 encoding

Month 6: Historical archive (10 views/day)
- Reduce to: 10+3 encoding
- Consolidate to regional nodes only
```

## Redundancy Patterns

### Pattern 1: Burst Access
```python
if hourly_access > 10 * daily_average:
    # Immediate response
    new_parity = current_parity + 3
    distribute_urgently(new_parity_chunks)
    
    # Schedule review in 24 hours
    schedule_redundancy_review(file_hash, "24h")
```

### Pattern 2: Scheduled Access
```python
# Detected: File accessed Mon-Fri 9am-5pm
if is_scheduled_pattern(access_history):
    # Boost before business hours
    schedule_daily_boost(file_hash, "08:00", boost=2)
    
    # Reduce after hours
    schedule_daily_reduction(file_hash, "18:00", reduce=2)
```

### Pattern 3: Seasonal Content
```python
# Holiday photos accessed annually
if is_seasonal_pattern(access_history):
    # Boost one month before expected access
    schedule_seasonal_boost(file_hash, date="Nov 1", boost=5)
    
    # Reduce after season
    schedule_seasonal_reduction(file_hash, date="Jan 15", reduce=3)
```

## Cost Analysis

### Storage Cost Over Time

| File Type | Month 1 | Month 3 | Month 6 | Month 12 |
|-----------|---------|---------|---------|----------|
| Viral Content | 150 tokens | 120 tokens | 80 tokens | 50 tokens |
| Active Dataset | 150 tokens | 150 tokens | 100 tokens | 70 tokens |
| Personal Files | 150 tokens | 90 tokens | 60 tokens | 30 tokens |
| Archive Data | 150 tokens | 70 tokens | 40 tokens | 20 tokens |

### Network Benefit Analysis

**Without Adaptive Redundancy:**
- All files: 10+5 encoding forever
- Network storage: 1.5x of actual data
- No load distribution for popular content
- High repair traffic for unused files

**With Adaptive Redundancy:**
- Popular files: Up to 10+10 (better availability)
- Cold files: Down to 10+1 (90% storage savings)
- Network storage: ~0.8x of actual data (weighted average)
- Automatic load balancing
- Minimal repair traffic

## Implementation Priority

### Quick Wins (Month 1)
1. Time-based decay for files >30 days old
2. Basic popularity boost for files >100 accesses/day
3. Simple burst detection

### Medium Term (Month 2-3)
1. Geographic distribution for popular content
2. Scheduled access pattern recognition
3. Predictive boosting

### Long Term (Month 4-6)
1. Machine learning for access prediction
2. Economic incentives for adaptive storage
3. Automatic content tiering

## Success Metrics

```yaml
kpis:
  storage_efficiency:
    target: 50% reduction in cold storage costs
    measure: tokens_spent_on_cold_files / total_storage_cost
    
  availability:
    target: 99.9% for hot files, 99% for warm, 95% for cold
    measure: successful_reads / total_read_attempts
    
  repair_traffic:
    target: 70% reduction
    measure: repair_bandwidth / total_bandwidth
    
  user_satisfaction:
    target: <100ms retrieval for hot files
    measure: p99_latency_by_file_temperature
```

This adaptive approach ensures the network automatically optimizes for both cost and performance based on actual usage patterns.