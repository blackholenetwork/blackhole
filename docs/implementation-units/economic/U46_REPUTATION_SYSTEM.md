# U46: Reputation System

## Overview
Provider reputation scoring system with performance tracking, penalty mechanisms, and trust metrics to ensure reliable storage services.

## Implementation

### Core Types

```go
package reputation

import (
    "context"
    "math"
    "sync"
    "time"
)

// ReputationScore represents a provider's reputation
type ReputationScore struct {
    ProviderID       string
    OverallScore     float64
    ReliabilityScore float64
    PerformanceScore float64
    UptimeScore      float64
    ResponseScore    float64
    TrustScore       float64
    LastUpdated      time.Time
    ScoreHistory     []ScoreSnapshot
    Penalties        []Penalty
    Rewards          []Reward
}

// ScoreSnapshot represents a point-in-time score
type ScoreSnapshot struct {
    Timestamp        time.Time
    OverallScore     float64
    ReliabilityScore float64
    PerformanceScore float64
    UptimeScore      float64
    ResponseScore    float64
    TrustScore       float64
    EventCount       int
}

// PerformanceMetric represents a performance measurement
type PerformanceMetric struct {
    ProviderID       string
    MetricType       MetricType
    Value            float64
    Timestamp        time.Time
    Weight           float64
    Context          string
}

// MetricType defines types of performance metrics
type MetricType int

const (
    MetricUptime MetricType = iota
    MetricResponseTime
    MetricThroughput
    MetricAvailability
    MetricDataIntegrity
    MetricNetworkLatency
    MetricStorageReliability
    MetricServiceQuality
)

// Penalty represents a reputation penalty
type Penalty struct {
    ID          string
    ProviderID  string
    Type        PenaltyType
    Severity    PenaltySeverity
    Points      float64
    Reason      string
    Timestamp   time.Time
    Expiry      time.Time
    Applied     bool
    Context     map[string]interface{}
}

// PenaltyType defines penalty categories
type PenaltyType int

const (
    PenaltyDowntime PenaltyType = iota
    PenaltySlowResponse
    PenaltyDataLoss
    PenaltyUnavailability
    PenaltyContractBreach
    PenaltyFraud
    PenaltyMaliciousBehavior
    PenaltyPoorPerformance
)

// PenaltySeverity defines penalty severity levels
type PenaltySeverity int

const (
    SeverityMinor PenaltySeverity = iota
    SeverityModerate
    SeverityMajor
    SeverityCritical
)

// Reward represents a reputation reward
type Reward struct {
    ID         string
    ProviderID string
    Type       RewardType
    Points     float64
    Reason     string
    Timestamp  time.Time
    Context    map[string]interface{}
}

// RewardType defines reward categories
type RewardType int

const (
    RewardHighUptime RewardType = iota
    RewardFastResponse
    RewardDataIntegrity
    RewardLongTermService
    RewardExceptionalPerformance
    RewardCommunityContribution
)
```

### Reputation Manager

```go
// ReputationManager manages provider reputation scores
type ReputationManager struct {
    scores       map[string]*ReputationScore
    config       ReputationConfig
    eventChan    chan ReputationEvent
    subscribers  []chan ReputationUpdate
    storage      ReputationStorage
    calculator   *ScoreCalculator
    validator    *MetricValidator
    mu           sync.RWMutex
    stopCh       chan struct{}
}

// ReputationConfig configures the reputation system
type ReputationConfig struct {
    InitialScore         float64
    MaxScore             float64
    MinScore             float64
    DecayRate            float64
    UpdateInterval       time.Duration
    HistoryRetention     time.Duration
    PenaltyWeights       map[PenaltyType]float64
    RewardWeights        map[RewardType]float64
    MetricWeights        map[MetricType]float64
    RecoveryEnabled      bool
    RecoveryRate         float64
    TrustThreshold       float64
    PerformanceThreshold float64
}

// ReputationEvent represents an event affecting reputation
type ReputationEvent struct {
    Type       EventType
    ProviderID string
    Data       interface{}
    Timestamp  time.Time
}

// EventType defines event types
type EventType int

const (
    EventMetricUpdate EventType = iota
    EventPenaltyApplied
    EventRewardGranted
    EventScoreDecay
    EventScoreRecovery
)

// ReputationUpdate represents a reputation change notification
type ReputationUpdate struct {
    ProviderID  string
    OldScore    float64
    NewScore    float64
    Change      float64
    Reason      string
    Timestamp   time.Time
    ScoreBreakdown map[string]float64
}

// NewReputationManager creates a new reputation manager
func NewReputationManager(config ReputationConfig, storage ReputationStorage) *ReputationManager {
    return &ReputationManager{
        scores:      make(map[string]*ReputationScore),
        config:      config,
        eventChan:   make(chan ReputationEvent, 1000),
        subscribers: make([]chan ReputationUpdate, 0),
        storage:     storage,
        calculator:  NewScoreCalculator(config),
        validator:   NewMetricValidator(),
        stopCh:      make(chan struct{}),
    }
}

// Start begins the reputation manager
func (rm *ReputationManager) Start(ctx context.Context) error {
    // Load existing scores
    if err := rm.loadScores(); err != nil {
        return err
    }
    
    // Start event processor
    go rm.processEvents(ctx)
    
    // Start periodic updates
    ticker := time.NewTicker(rm.config.UpdateInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-rm.stopCh:
            return nil
        case <-ticker.C:
            rm.performPeriodicUpdate()
        }
    }
}

// RecordMetric records a performance metric
func (rm *ReputationManager) RecordMetric(metric PerformanceMetric) error {
    if err := rm.validator.ValidateMetric(metric); err != nil {
        return err
    }
    
    select {
    case rm.eventChan <- ReputationEvent{
        Type:       EventMetricUpdate,
        ProviderID: metric.ProviderID,
        Data:       metric,
        Timestamp:  time.Now(),
    }:
        return nil
    default:
        return ErrEventChannelFull
    }
}

// ApplyPenalty applies a penalty to a provider
func (rm *ReputationManager) ApplyPenalty(penalty Penalty) error {
    penalty.ID = generatePenaltyID()
    penalty.Timestamp = time.Now()
    penalty.Applied = true
    
    select {
    case rm.eventChan <- ReputationEvent{
        Type:       EventPenaltyApplied,
        ProviderID: penalty.ProviderID,
        Data:       penalty,
        Timestamp:  time.Now(),
    }:
        return nil
    default:
        return ErrEventChannelFull
    }
}

// GrantReward grants a reward to a provider
func (rm *ReputationManager) GrantReward(reward Reward) error {
    reward.ID = generateRewardID()
    reward.Timestamp = time.Now()
    
    select {
    case rm.eventChan <- ReputationEvent{
        Type:       EventRewardGranted,
        ProviderID: reward.ProviderID,
        Data:       reward,
        Timestamp:  time.Now(),
    }:
        return nil
    default:
        return ErrEventChannelFull
    }
}

// GetScore returns a provider's reputation score
func (rm *ReputationManager) GetScore(providerID string) (*ReputationScore, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    score, exists := rm.scores[providerID]
    if !exists {
        // Initialize new provider with default score
        score = rm.initializeProvider(providerID)
        rm.scores[providerID] = score
    }
    
    // Return a copy to prevent external modification
    return rm.copyScore(score), nil
}

// GetProviderRanking returns providers ranked by reputation
func (rm *ReputationManager) GetProviderRanking(limit int) ([]*ReputationScore, error) {
    rm.mu.RLock()
    defer rm.mu.RUnlock()
    
    scores := make([]*ReputationScore, 0, len(rm.scores))
    for _, score := range rm.scores {
        scores = append(scores, rm.copyScore(score))
    }
    
    // Sort by overall score descending
    sort.Slice(scores, func(i, j int) bool {
        return scores[i].OverallScore > scores[j].OverallScore
    })
    
    if limit > 0 && limit < len(scores) {
        scores = scores[:limit]
    }
    
    return scores, nil
}

// processEvents processes reputation events
func (rm *ReputationManager) processEvents(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case event := <-rm.eventChan:
            rm.handleEvent(event)
        }
    }
}

// handleEvent handles a single reputation event
func (rm *ReputationManager) handleEvent(event ReputationEvent) {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    score, exists := rm.scores[event.ProviderID]
    if !exists {
        score = rm.initializeProvider(event.ProviderID)
        rm.scores[event.ProviderID] = score
    }
    
    oldScore := score.OverallScore
    
    switch event.Type {
    case EventMetricUpdate:
        metric := event.Data.(PerformanceMetric)
        rm.updateScoreFromMetric(score, metric)
    case EventPenaltyApplied:
        penalty := event.Data.(Penalty)
        rm.applyPenaltyToScore(score, penalty)
    case EventRewardGranted:
        reward := event.Data.(Reward)
        rm.applyRewardToScore(score, reward)
    }
    
    // Recalculate overall score
    score.OverallScore = rm.calculator.CalculateOverallScore(score)
    score.LastUpdated = time.Now()
    
    // Add to history
    rm.addScoreSnapshot(score)
    
    // Notify subscribers
    if oldScore != score.OverallScore {
        rm.notifyScoreChange(ReputationUpdate{
            ProviderID: event.ProviderID,
            OldScore:   oldScore,
            NewScore:   score.OverallScore,
            Change:     score.OverallScore - oldScore,
            Reason:     rm.getChangeReason(event.Type),
            Timestamp:  time.Now(),
            ScoreBreakdown: map[string]float64{
                "reliability":  score.ReliabilityScore,
                "performance":  score.PerformanceScore,
                "uptime":       score.UptimeScore,
                "response":     score.ResponseScore,
                "trust":        score.TrustScore,
            },
        })
    }
    
    // Persist changes
    rm.storage.SaveScore(score)
}
```

### Score Calculator

```go
// ScoreCalculator calculates reputation scores
type ScoreCalculator struct {
    config ReputationConfig
}

// NewScoreCalculator creates a new score calculator
func NewScoreCalculator(config ReputationConfig) *ScoreCalculator {
    return &ScoreCalculator{config: config}
}

// CalculateOverallScore calculates the overall reputation score
func (sc *ScoreCalculator) CalculateOverallScore(score *ReputationScore) float64 {
    // Weighted average of component scores
    weights := map[string]float64{
        "reliability": 0.25,
        "performance": 0.20,
        "uptime":      0.20,
        "response":    0.15,
        "trust":       0.20,
    }
    
    overall := weights["reliability"]*score.ReliabilityScore +
               weights["performance"]*score.PerformanceScore +
               weights["uptime"]*score.UptimeScore +
               weights["response"]*score.ResponseScore +
               weights["trust"]*score.TrustScore
    
    // Apply penalties
    for _, penalty := range score.Penalties {
        if sc.isPenaltyActive(penalty) {
            overall -= penalty.Points * sc.getPenaltyMultiplier(penalty.Severity)
        }
    }
    
    // Apply rewards
    for _, reward := range score.Rewards {
        if sc.isRewardActive(reward) {
            overall += reward.Points * sc.getRewardMultiplier(reward.Type)
        }
    }
    
    // Ensure bounds
    overall = math.Max(sc.config.MinScore, math.Min(sc.config.MaxScore, overall))
    
    return overall
}

// CalculateReliabilityScore calculates reliability score
func (sc *ScoreCalculator) CalculateReliabilityScore(metrics []PerformanceMetric) float64 {
    if len(metrics) == 0 {
        return sc.config.InitialScore
    }
    
    // Calculate based on data integrity and storage reliability metrics
    var totalWeight, weightedSum float64
    
    for _, metric := range metrics {
        if metric.MetricType == MetricDataIntegrity || metric.MetricType == MetricStorageReliability {
            weight := sc.getMetricWeight(metric.MetricType, metric.Timestamp)
            weightedSum += metric.Value * weight
            totalWeight += weight
        }
    }
    
    if totalWeight == 0 {
        return sc.config.InitialScore
    }
    
    return (weightedSum / totalWeight) * sc.config.MaxScore
}

// CalculatePerformanceScore calculates performance score
func (sc *ScoreCalculator) CalculatePerformanceScore(metrics []PerformanceMetric) float64 {
    if len(metrics) == 0 {
        return sc.config.InitialScore
    }
    
    // Calculate based on throughput and response time metrics
    var totalWeight, weightedSum float64
    
    for _, metric := range metrics {
        if metric.MetricType == MetricThroughput || metric.MetricType == MetricResponseTime {
            weight := sc.getMetricWeight(metric.MetricType, metric.Timestamp)
            value := metric.Value
            
            // Invert response time (lower is better)
            if metric.MetricType == MetricResponseTime {
                value = 1.0 / (1.0 + value)
            }
            
            weightedSum += value * weight
            totalWeight += weight
        }
    }
    
    if totalWeight == 0 {
        return sc.config.InitialScore
    }
    
    return (weightedSum / totalWeight) * sc.config.MaxScore
}

// CalculateUptimeScore calculates uptime score
func (sc *ScoreCalculator) CalculateUptimeScore(metrics []PerformanceMetric) float64 {
    if len(metrics) == 0 {
        return sc.config.InitialScore
    }
    
    // Calculate based on uptime and availability metrics
    var totalWeight, weightedSum float64
    
    for _, metric := range metrics {
        if metric.MetricType == MetricUptime || metric.MetricType == MetricAvailability {
            weight := sc.getMetricWeight(metric.MetricType, metric.Timestamp)
            weightedSum += metric.Value * weight
            totalWeight += weight
        }
    }
    
    if totalWeight == 0 {
        return sc.config.InitialScore
    }
    
    return (weightedSum / totalWeight) * sc.config.MaxScore
}

// CalculateResponseScore calculates response score
func (sc *ScoreCalculator) CalculateResponseScore(metrics []PerformanceMetric) float64 {
    if len(metrics) == 0 {
        return sc.config.InitialScore
    }
    
    // Calculate based on network latency and response time
    var totalWeight, weightedSum float64
    
    for _, metric := range metrics {
        if metric.MetricType == MetricNetworkLatency || metric.MetricType == MetricResponseTime {
            weight := sc.getMetricWeight(metric.MetricType, metric.Timestamp)
            // Lower latency/response time is better
            value := 1.0 / (1.0 + metric.Value)
            weightedSum += value * weight
            totalWeight += weight
        }
    }
    
    if totalWeight == 0 {
        return sc.config.InitialScore
    }
    
    return (weightedSum / totalWeight) * sc.config.MaxScore
}

// CalculateTrustScore calculates trust score based on historical behavior
func (sc *ScoreCalculator) CalculateTrustScore(score *ReputationScore) float64 {
    baseScore := sc.config.InitialScore
    
    // Increase trust over time with good behavior
    serviceTime := time.Since(score.ScoreHistory[0].Timestamp)
    timeFactor := math.Min(1.0, serviceTime.Hours()/(24*30)) // Max boost after 30 days
    
    // Calculate average historical performance
    var avgScore float64
    if len(score.ScoreHistory) > 0 {
        var sum float64
        for _, snapshot := range score.ScoreHistory {
            sum += snapshot.OverallScore
        }
        avgScore = sum / float64(len(score.ScoreHistory))
    }
    
    // Reduce trust for penalties
    penaltyImpact := 0.0
    for _, penalty := range score.Penalties {
        if sc.isPenaltyActive(penalty) {
            penaltyImpact += penalty.Points * sc.getPenaltyTrustImpact(penalty.Type)
        }
    }
    
    trustScore := baseScore + 
                  (avgScore-baseScore)*timeFactor + 
                  timeFactor*0.2*sc.config.MaxScore -
                  penaltyImpact
    
    return math.Max(0, math.Min(sc.config.MaxScore, trustScore))
}

// getMetricWeight calculates weight for a metric based on type and age
func (sc *ScoreCalculator) getMetricWeight(metricType MetricType, timestamp time.Time) float64 {
    baseWeight := sc.config.MetricWeights[metricType]
    if baseWeight == 0 {
        baseWeight = 1.0
    }
    
    // Apply time decay
    age := time.Since(timestamp)
    decayFactor := math.Exp(-age.Hours() / 24 * sc.config.DecayRate)
    
    return baseWeight * decayFactor
}

// getPenaltyMultiplier returns penalty multiplier based on severity
func (sc *ScoreCalculator) getPenaltyMultiplier(severity PenaltySeverity) float64 {
    switch severity {
    case SeverityMinor:
        return 1.0
    case SeverityModerate:
        return 2.0
    case SeverityMajor:
        return 4.0
    case SeverityCritical:
        return 8.0
    default:
        return 1.0
    }
}

// getRewardMultiplier returns reward multiplier based on type
func (sc *ScoreCalculator) getRewardMultiplier(rewardType RewardType) float64 {
    switch rewardType {
    case RewardHighUptime:
        return 1.2
    case RewardFastResponse:
        return 1.1
    case RewardDataIntegrity:
        return 1.5
    case RewardLongTermService:
        return 1.3
    case RewardExceptionalPerformance:
        return 1.4
    case RewardCommunityContribution:
        return 1.1
    default:
        return 1.0
    }
}

// getPenaltyTrustImpact returns trust impact for penalty types
func (sc *ScoreCalculator) getPenaltyTrustImpact(penaltyType PenaltyType) float64 {
    switch penaltyType {
    case PenaltyFraud:
        return 0.8
    case PenaltyMaliciousBehavior:
        return 0.7
    case PenaltyDataLoss:
        return 0.6
    case PenaltyContractBreach:
        return 0.5
    case PenaltyDowntime:
        return 0.3
    case PenaltySlowResponse:
        return 0.2
    case PenaltyUnavailability:
        return 0.4
    case PenaltyPoorPerformance:
        return 0.3
    default:
        return 0.1
    }
}

// isPenaltyActive checks if a penalty is currently active
func (sc *ScoreCalculator) isPenaltyActive(penalty Penalty) bool {
    return penalty.Applied && (penalty.Expiry.IsZero() || time.Now().Before(penalty.Expiry))
}

// isRewardActive checks if a reward is currently active
func (sc *ScoreCalculator) isRewardActive(reward Reward) bool {
    // Rewards typically don't expire but could have time-based decay
    age := time.Since(reward.Timestamp)
    return age < sc.config.HistoryRetention
}
```

### Performance Tracking

```go
// PerformanceTracker tracks provider performance metrics
type PerformanceTracker struct {
    metrics    map[string][]PerformanceMetric
    aggregates map[string]PerformanceAggregate
    config     TrackerConfig
    reputationMgr *ReputationManager
    mu         sync.RWMutex
}

// TrackerConfig configures the performance tracker
type TrackerConfig struct {
    MetricRetention   time.Duration
    AggregateInterval time.Duration
    AlertThresholds   map[MetricType]float64
    SampleSize        int
}

// PerformanceAggregate represents aggregated performance data
type PerformanceAggregate struct {
    ProviderID    string
    MetricType    MetricType
    Count         int
    Sum           float64
    Average       float64
    Min           float64
    Max           float64
    StdDev        float64
    Percentiles   map[int]float64
    Period        time.Duration
    StartTime     time.Time
    EndTime       time.Time
}

// NewPerformanceTracker creates a new performance tracker
func NewPerformanceTracker(config TrackerConfig, reputationMgr *ReputationManager) *PerformanceTracker {
    return &PerformanceTracker{
        metrics:       make(map[string][]PerformanceMetric),
        aggregates:    make(map[string]PerformanceAggregate),
        config:        config,
        reputationMgr: reputationMgr,
    }
}

// RecordMetric records a performance metric
func (pt *PerformanceTracker) RecordMetric(metric PerformanceMetric) error {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    key := fmt.Sprintf("%s_%d", metric.ProviderID, metric.MetricType)
    pt.metrics[key] = append(pt.metrics[key], metric)
    
    // Trim old metrics
    pt.trimOldMetrics(key)
    
    // Update aggregates
    pt.updateAggregate(metric)
    
    // Check for alerts
    if alert := pt.checkAlert(metric); alert != nil {
        pt.handleAlert(alert)
    }
    
    // Forward to reputation manager
    return pt.reputationMgr.RecordMetric(metric)
}

// GetMetrics returns metrics for a provider
func (pt *PerformanceTracker) GetMetrics(providerID string, metricType MetricType, since time.Time) []PerformanceMetric {
    pt.mu.RLock()
    defer pt.mu.RUnlock()
    
    key := fmt.Sprintf("%s_%d", providerID, metricType)
    metrics := pt.metrics[key]
    
    filtered := make([]PerformanceMetric, 0)
    for _, metric := range metrics {
        if metric.Timestamp.After(since) {
            filtered = append(filtered, metric)
        }
    }
    
    return filtered
}

// GetAggregate returns aggregated performance data
func (pt *PerformanceTracker) GetAggregate(providerID string, metricType MetricType) (*PerformanceAggregate, error) {
    pt.mu.RLock()
    defer pt.mu.RUnlock()
    
    key := fmt.Sprintf("%s_%d", providerID, metricType)
    aggregate, exists := pt.aggregates[key]
    if !exists {
        return nil, ErrAggregateNotFound
    }
    
    return &aggregate, nil
}

// updateAggregate updates aggregate statistics
func (pt *PerformanceTracker) updateAggregate(metric PerformanceMetric) {
    key := fmt.Sprintf("%s_%d", metric.ProviderID, metric.MetricType)
    
    aggregate, exists := pt.aggregates[key]
    if !exists {
        aggregate = PerformanceAggregate{
            ProviderID:  metric.ProviderID,
            MetricType:  metric.MetricType,
            Min:         metric.Value,
            Max:         metric.Value,
            StartTime:   metric.Timestamp,
            Percentiles: make(map[int]float64),
        }
    }
    
    // Update statistics
    aggregate.Count++
    aggregate.Sum += metric.Value
    aggregate.Average = aggregate.Sum / float64(aggregate.Count)
    aggregate.Min = math.Min(aggregate.Min, metric.Value)
    aggregate.Max = math.Max(aggregate.Max, metric.Value)
    aggregate.EndTime = metric.Timestamp
    
    // Calculate standard deviation (simplified)
    if aggregate.Count > 1 {
        metrics := pt.metrics[key]
        variance := 0.0
        for _, m := range metrics {
            diff := m.Value - aggregate.Average
            variance += diff * diff
        }
        aggregate.StdDev = math.Sqrt(variance / float64(aggregate.Count))
    }
    
    // Update percentiles
    pt.updatePercentiles(&aggregate, key)
    
    pt.aggregates[key] = aggregate
}

// updatePercentiles calculates percentile values
func (pt *PerformanceTracker) updatePercentiles(aggregate *PerformanceAggregate, key string) {
    metrics := pt.metrics[key]
    if len(metrics) == 0 {
        return
    }
    
    // Sort values
    values := make([]float64, len(metrics))
    for i, metric := range metrics {
        values[i] = metric.Value
    }
    sort.Float64s(values)
    
    // Calculate percentiles
    percentiles := []int{50, 90, 95, 99}
    for _, p := range percentiles {
        index := int(float64(p)/100.0 * float64(len(values)))
        if index >= len(values) {
            index = len(values) - 1
        }
        aggregate.Percentiles[p] = values[index]
    }
}

// trimOldMetrics removes old metrics to save memory
func (pt *PerformanceTracker) trimOldMetrics(key string) {
    metrics := pt.metrics[key]
    cutoff := time.Now().Add(-pt.config.MetricRetention)
    
    filtered := make([]PerformanceMetric, 0)
    for _, metric := range metrics {
        if metric.Timestamp.After(cutoff) {
            filtered = append(filtered, metric)
        }
    }
    
    pt.metrics[key] = filtered
}

// checkAlert checks if metric triggers an alert
func (pt *PerformanceTracker) checkAlert(metric PerformanceMetric) *PerformanceAlert {
    threshold, exists := pt.config.AlertThresholds[metric.MetricType]
    if !exists {
        return nil
    }
    
    var triggered bool
    var severity AlertSeverity
    
    switch metric.MetricType {
    case MetricUptime, MetricAvailability, MetricDataIntegrity:
        // Lower values are bad
        if metric.Value < threshold {
            triggered = true
            severity = pt.getSeverityFromValue(metric.Value, threshold, false)
        }
    case MetricResponseTime, MetricNetworkLatency:
        // Higher values are bad
        if metric.Value > threshold {
            triggered = true
            severity = pt.getSeverityFromValue(metric.Value, threshold, true)
        }
    }
    
    if !triggered {
        return nil
    }
    
    return &PerformanceAlert{
        ProviderID:  metric.ProviderID,
        MetricType:  metric.MetricType,
        Value:       metric.Value,
        Threshold:   threshold,
        Severity:    severity,
        Timestamp:   metric.Timestamp,
        Message:     pt.generateAlertMessage(metric, threshold),
    }
}

// PerformanceAlert represents a performance alert
type PerformanceAlert struct {
    ProviderID  string
    MetricType  MetricType
    Value       float64
    Threshold   float64
    Severity    AlertSeverity
    Timestamp   time.Time
    Message     string
}

// AlertSeverity defines alert severity levels
type AlertSeverity int

const (
    AlertLow AlertSeverity = iota
    AlertMedium
    AlertHigh
    AlertCritical
)

// handleAlert handles a performance alert
func (pt *PerformanceTracker) handleAlert(alert *PerformanceAlert) {
    // Create penalty based on alert severity
    penalty := Penalty{
        ProviderID: alert.ProviderID,
        Type:       pt.mapMetricToPenalty(alert.MetricType),
        Severity:   pt.mapAlertToPenalty(alert.Severity),
        Points:     pt.calculatePenaltyPoints(alert),
        Reason:     alert.Message,
        Expiry:     time.Now().Add(24 * time.Hour), // 24 hour penalty
        Context: map[string]interface{}{
            "metric_type":  alert.MetricType,
            "metric_value": alert.Value,
            "threshold":    alert.Threshold,
        },
    }
    
    pt.reputationMgr.ApplyPenalty(penalty)
}

// mapMetricToPenalty maps metric types to penalty types
func (pt *PerformanceTracker) mapMetricToPenalty(metricType MetricType) PenaltyType {
    switch metricType {
    case MetricUptime, MetricAvailability:
        return PenaltyDowntime
    case MetricResponseTime, MetricNetworkLatency:
        return PenaltySlowResponse
    case MetricDataIntegrity:
        return PenaltyDataLoss
    case MetricStorageReliability:
        return PenaltyPoorPerformance
    default:
        return PenaltyPoorPerformance
    }
}

// mapAlertToPenalty maps alert severity to penalty severity
func (pt *PerformanceTracker) mapAlertToPenalty(alertSeverity AlertSeverity) PenaltySeverity {
    switch alertSeverity {
    case AlertLow:
        return SeverityMinor
    case AlertMedium:
        return SeverityModerate
    case AlertHigh:
        return SeverityMajor
    case AlertCritical:
        return SeverityCritical
    default:
        return SeverityMinor
    }
}

// calculatePenaltyPoints calculates penalty points from alert
func (pt *PerformanceTracker) calculatePenaltyPoints(alert *PerformanceAlert) float64 {
    basePoints := 10.0
    
    switch alert.Severity {
    case AlertLow:
        return basePoints * 0.5
    case AlertMedium:
        return basePoints * 1.0
    case AlertHigh:
        return basePoints * 2.0
    case AlertCritical:
        return basePoints * 4.0
    default:
        return basePoints
    }
}

// getSeverityFromValue determines alert severity from metric value
func (pt *PerformanceTracker) getSeverityFromValue(value, threshold float64, higherIsBad bool) AlertSeverity {
    var ratio float64
    
    if higherIsBad {
        ratio = value / threshold
    } else {
        ratio = threshold / value
    }
    
    if ratio <= 1.2 {
        return AlertLow
    } else if ratio <= 2.0 {
        return AlertMedium
    } else if ratio <= 4.0 {
        return AlertHigh
    } else {
        return AlertCritical
    }
}

// generateAlertMessage generates a human-readable alert message
func (pt *PerformanceTracker) generateAlertMessage(metric PerformanceMetric, threshold float64) string {
    metricName := pt.getMetricName(metric.MetricType)
    return fmt.Sprintf("Provider %s %s %s threshold: %.2f (threshold: %.2f)",
        metric.ProviderID, metricName, pt.getComparisonWord(metric.MetricType), metric.Value, threshold)
}

// getMetricName returns human-readable metric name
func (pt *PerformanceTracker) getMetricName(metricType MetricType) string {
    switch metricType {
    case MetricUptime:
        return "uptime"
    case MetricResponseTime:
        return "response time"
    case MetricThroughput:
        return "throughput"
    case MetricAvailability:
        return "availability"
    case MetricDataIntegrity:
        return "data integrity"
    case MetricNetworkLatency:
        return "network latency"
    case MetricStorageReliability:
        return "storage reliability"
    case MetricServiceQuality:
        return "service quality"
    default:
        return "unknown metric"
    }
}

// getComparisonWord returns appropriate comparison word
func (pt *PerformanceTracker) getComparisonWord(metricType MetricType) string {
    switch metricType {
    case MetricUptime, MetricAvailability, MetricDataIntegrity:
        return "below"
    case MetricResponseTime, MetricNetworkLatency:
        return "above"
    default:
        return "outside"
    }
}
```

### Helper Functions

```go
// generatePenaltyID generates a unique penalty ID
func generatePenaltyID() string {
    return fmt.Sprintf("penalty_%d_%s", time.Now().UnixNano(), randomString(8))
}

// generateRewardID generates a unique reward ID
func generateRewardID() string {
    return fmt.Sprintf("reward_%d_%s", time.Now().UnixNano(), randomString(8))
}

// initializeProvider creates a new provider score
func (rm *ReputationManager) initializeProvider(providerID string) *ReputationScore {
    return &ReputationScore{
        ProviderID:       providerID,
        OverallScore:     rm.config.InitialScore,
        ReliabilityScore: rm.config.InitialScore,
        PerformanceScore: rm.config.InitialScore,
        UptimeScore:      rm.config.InitialScore,
        ResponseScore:    rm.config.InitialScore,
        TrustScore:       rm.config.InitialScore,
        LastUpdated:      time.Now(),
        ScoreHistory:     make([]ScoreSnapshot, 0),
        Penalties:        make([]Penalty, 0),
        Rewards:          make([]Reward, 0),
    }
}

// copyScore creates a copy of a reputation score
func (rm *ReputationManager) copyScore(score *ReputationScore) *ReputationScore {
    copy := *score
    copy.ScoreHistory = make([]ScoreSnapshot, len(score.ScoreHistory))
    copy.Penalties = make([]Penalty, len(score.Penalties))
    copy.Rewards = make([]Reward, len(score.Rewards))
    
    copy(copy.ScoreHistory, score.ScoreHistory)
    copy(copy.Penalties, score.Penalties)
    copy(copy.Rewards, score.Rewards)
    
    return &copy
}

// addScoreSnapshot adds a score snapshot to history
func (rm *ReputationManager) addScoreSnapshot(score *ReputationScore) {
    snapshot := ScoreSnapshot{
        Timestamp:        time.Now(),
        OverallScore:     score.OverallScore,
        ReliabilityScore: score.ReliabilityScore,
        PerformanceScore: score.PerformanceScore,
        UptimeScore:      score.UptimeScore,
        ResponseScore:    score.ResponseScore,
        TrustScore:       score.TrustScore,
        EventCount:       len(score.Penalties) + len(score.Rewards),
    }
    
    score.ScoreHistory = append(score.ScoreHistory, snapshot)
    
    // Trim old history
    cutoff := time.Now().Add(-rm.config.HistoryRetention)
    filtered := make([]ScoreSnapshot, 0)
    for _, snap := range score.ScoreHistory {
        if snap.Timestamp.After(cutoff) {
            filtered = append(filtered, snap)
        }
    }
    score.ScoreHistory = filtered
}

// Subscribe subscribes to reputation updates
func (rm *ReputationManager) Subscribe() <-chan ReputationUpdate {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    ch := make(chan ReputationUpdate, 10)
    rm.subscribers = append(rm.subscribers, ch)
    return ch
}

// notifyScoreChange notifies subscribers of score changes
func (rm *ReputationManager) notifyScoreChange(update ReputationUpdate) {
    for _, ch := range rm.subscribers {
        select {
        case ch <- update:
        default:
            // Channel full, skip
        }
    }
}

// getChangeReason returns reason for score change
func (rm *ReputationManager) getChangeReason(eventType EventType) string {
    switch eventType {
    case EventMetricUpdate:
        return "Performance metric update"
    case EventPenaltyApplied:
        return "Penalty applied"
    case EventRewardGranted:
        return "Reward granted"
    case EventScoreDecay:
        return "Score decay"
    case EventScoreRecovery:
        return "Score recovery"
    default:
        return "Score update"
    }
}

// performPeriodicUpdate performs periodic score updates
func (rm *ReputationManager) performPeriodicUpdate() {
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    for _, score := range rm.scores {
        // Apply decay
        if rm.config.DecayRate > 0 {
            rm.applyScoreDecay(score)
        }
        
        // Apply recovery
        if rm.config.RecoveryEnabled {
            rm.applyScoreRecovery(score)
        }
        
        // Clean up expired penalties
        rm.cleanupExpiredPenalties(score)
    }
}

// applyScoreDecay applies natural score decay over time
func (rm *ReputationManager) applyScoreDecay(score *ReputationScore) {
    decayAmount := rm.config.DecayRate * rm.config.UpdateInterval.Hours() / 24
    
    score.ReliabilityScore = math.Max(rm.config.MinScore, score.ReliabilityScore-decayAmount)
    score.PerformanceScore = math.Max(rm.config.MinScore, score.PerformanceScore-decayAmount)
    score.UptimeScore = math.Max(rm.config.MinScore, score.UptimeScore-decayAmount)
    score.ResponseScore = math.Max(rm.config.MinScore, score.ResponseScore-decayAmount)
    
    score.OverallScore = rm.calculator.CalculateOverallScore(score)
}

// applyScoreRecovery applies score recovery for good behavior
func (rm *ReputationManager) applyScoreRecovery(score *ReputationScore) {
    if score.OverallScore >= rm.config.PerformanceThreshold {
        recoveryAmount := rm.config.RecoveryRate * rm.config.UpdateInterval.Hours() / 24
        
        score.TrustScore = math.Min(rm.config.MaxScore, score.TrustScore+recoveryAmount)
        score.OverallScore = rm.calculator.CalculateOverallScore(score)
    }
}

// cleanupExpiredPenalties removes expired penalties
func (rm *ReputationManager) cleanupExpiredPenalties(score *ReputationScore) {
    filtered := make([]Penalty, 0)
    for _, penalty := range score.Penalties {
        if penalty.Expiry.IsZero() || time.Now().Before(penalty.Expiry) {
            filtered = append(filtered, penalty)
        }
    }
    score.Penalties = filtered
}

// loadScores loads existing scores from storage
func (rm *ReputationManager) loadScores() error {
    scores, err := rm.storage.LoadAllScores()
    if err != nil {
        return err
    }
    
    rm.mu.Lock()
    defer rm.mu.Unlock()
    
    for _, score := range scores {
        rm.scores[score.ProviderID] = score
    }
    
    return nil
}
```

## Testing

```go
package reputation

import (
    "testing"
    "time"
)

func TestReputationManager(t *testing.T) {
    config := ReputationConfig{
        InitialScore:     75.0,
        MaxScore:         100.0,
        MinScore:         0.0,
        DecayRate:        0.1,
        UpdateInterval:   time.Minute,
        HistoryRetention: 30 * 24 * time.Hour,
        PenaltyWeights:   make(map[PenaltyType]float64),
        RewardWeights:    make(map[RewardType]float64),
        MetricWeights:    make(map[MetricType]float64),
        RecoveryEnabled:  true,
        RecoveryRate:     0.5,
        TrustThreshold:   80.0,
        PerformanceThreshold: 85.0,
    }
    
    storage := NewMockReputationStorage()
    rm := NewReputationManager(config, storage)
    
    providerID := "test_provider"
    
    // Record positive metric
    metric := PerformanceMetric{
        ProviderID: providerID,
        MetricType: MetricUptime,
        Value:      0.99,
        Timestamp:  time.Now(),
        Weight:     1.0,
    }
    
    err := rm.RecordMetric(metric)
    if err != nil {
        t.Fatalf("Failed to record metric: %v", err)
    }
    
    // Get score
    score, err := rm.GetScore(providerID)
    if err != nil {
        t.Fatalf("Failed to get score: %v", err)
    }
    
    if score.UptimeScore <= config.InitialScore {
        t.Error("Uptime score should increase with good metric")
    }
    
    // Apply penalty
    penalty := Penalty{
        ProviderID: providerID,
        Type:       PenaltyDowntime,
        Severity:   SeverityMajor,
        Points:     20.0,
        Reason:     "Extended downtime",
    }
    
    err = rm.ApplyPenalty(penalty)
    if err != nil {
        t.Fatalf("Failed to apply penalty: %v", err)
    }
    
    // Score should decrease
    newScore, _ := rm.GetScore(providerID)
    if newScore.OverallScore >= score.OverallScore {
        t.Error("Score should decrease after penalty")
    }
}

func TestScoreCalculator(t *testing.T) {
    config := ReputationConfig{
        InitialScore: 75.0,
        MaxScore:     100.0,
        MinScore:     0.0,
        MetricWeights: map[MetricType]float64{
            MetricUptime: 1.0,
        },
    }
    
    calc := NewScoreCalculator(config)
    
    // Test uptime score calculation
    metrics := []PerformanceMetric{
        {MetricType: MetricUptime, Value: 0.99, Timestamp: time.Now()},
        {MetricType: MetricUptime, Value: 0.98, Timestamp: time.Now()},
        {MetricType: MetricUptime, Value: 0.995, Timestamp: time.Now()},
    }
    
    score := calc.CalculateUptimeScore(metrics)
    if score <= config.InitialScore {
        t.Error("High uptime should result in score above initial")
    }
    
    // Test with poor uptime
    poorMetrics := []PerformanceMetric{
        {MetricType: MetricUptime, Value: 0.5, Timestamp: time.Now()},
        {MetricType: MetricUptime, Value: 0.6, Timestamp: time.Now()},
    }
    
    poorScore := calc.CalculateUptimeScore(poorMetrics)
    if poorScore >= score {
        t.Error("Poor uptime should result in lower score")
    }
}

func TestPerformanceTracker(t *testing.T) {
    config := TrackerConfig{
        MetricRetention:   24 * time.Hour,
        AggregateInterval: time.Hour,
        AlertThresholds: map[MetricType]float64{
            MetricUptime: 0.95,
        },
        SampleSize: 100,
    }
    
    rm := NewReputationManager(ReputationConfig{}, NewMockReputationStorage())
    tracker := NewPerformanceTracker(config, rm)
    
    providerID := "test_provider"
    
    // Record metrics
    for i := 0; i < 10; i++ {
        metric := PerformanceMetric{
            ProviderID: providerID,
            MetricType: MetricUptime,
            Value:      0.98 + float64(i)*0.001,
            Timestamp:  time.Now().Add(-time.Duration(i) * time.Minute),
        }
        
        err := tracker.RecordMetric(metric)
        if err != nil {
            t.Fatalf("Failed to record metric: %v", err)
        }
    }
    
    // Get aggregate
    aggregate, err := tracker.GetAggregate(providerID, MetricUptime)
    if err != nil {
        t.Fatalf("Failed to get aggregate: %v", err)
    }
    
    if aggregate.Count != 10 {
        t.Errorf("Expected 10 metrics, got %d", aggregate.Count)
    }
    
    if aggregate.Average < 0.98 {
        t.Errorf("Average should be around 0.98, got %f", aggregate.Average)
    }
    
    // Test alert
    lowMetric := PerformanceMetric{
        ProviderID: providerID,
        MetricType: MetricUptime,
        Value:      0.8, // Below threshold
        Timestamp:  time.Now(),
    }
    
    err = tracker.RecordMetric(lowMetric)
    if err != nil {
        t.Fatalf("Failed to record low metric: %v", err)
    }
    
    // Should have triggered penalty through reputation manager
    score, err := rm.GetScore(providerID)
    if err != nil {
        t.Fatalf("Failed to get score: %v", err)
    }
    
    if len(score.Penalties) == 0 {
        t.Error("Expected penalty to be applied for low uptime")
    }
}
```

## Integration

1. **Storage Integration**: Connect to storage nodes for performance monitoring
2. **Network Integration**: Monitor network performance metrics
3. **Payment Integration**: Link reputation to pricing and payments
4. **Analytics Integration**: Export reputation data for analysis

## Configuration

```yaml
reputation:
  initial_score: 75.0
  max_score: 100.0
  min_score: 0.0
  decay_rate: 0.1
  update_interval: 1m
  history_retention: 720h
  recovery_enabled: true
  recovery_rate: 0.5
  trust_threshold: 80.0
  performance_threshold: 85.0
  
  metric_weights:
    uptime: 1.0
    response_time: 0.8
    throughput: 0.9
    availability: 1.0
    data_integrity: 1.2
    network_latency: 0.7
    storage_reliability: 1.1
    service_quality: 0.9
    
  penalty_weights:
    downtime: 1.0
    slow_response: 0.5
    data_loss: 2.0
    unavailability: 1.5
    contract_breach: 3.0
    fraud: 5.0
    malicious_behavior: 4.0
    poor_performance: 0.8
    
  reward_weights:
    high_uptime: 1.2
    fast_response: 1.1
    data_integrity: 1.5
    long_term_service: 1.3
    exceptional_performance: 1.4
    community_contribution: 1.1

tracking:
  metric_retention: 24h
  aggregate_interval: 1h
  sample_size: 1000
  
  alert_thresholds:
    uptime: 0.95
    response_time: 1000
    availability: 0.98
    data_integrity: 0.999
    network_latency: 500
```