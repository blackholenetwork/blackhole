# Unit 35: Bandwidth Accounting

## Overview
Comprehensive bandwidth accounting system for the BlackHole network, tracking usage, implementing fair sharing algorithms, QoS policies, and integrating with the billing system.

## Implementation

### Core Bandwidth Accounting

```go
package bandwidth

import (
    "encoding/binary"
    "errors"
    "math"
    "sync"
    "sync/atomic"
    "time"
)

// AccountingManager manages bandwidth accounting
type AccountingManager struct {
    nodeID         string
    accounts       map[string]*BandwidthAccount
    meters         map[string]*BandwidthMeter
    fairShare      *FairShareAllocator
    qos            *QoSManager
    billing        *BillingIntegration
    storage        *AccountingStorage
    mu             sync.RWMutex
}

// BandwidthAccount tracks usage for a peer/circuit
type BandwidthAccount struct {
    AccountID      string
    NodeID         string
    BytesSent      uint64
    BytesReceived  uint64
    PacketsSent    uint64
    PacketsReceived uint64
    CreatedAt      time.Time
    LastActivity   time.Time
    Credits        int64
    Debits         int64
    Balance        int64
    RateLimit      *RateLimit
}

// BandwidthMeter measures real-time bandwidth
type BandwidthMeter struct {
    ID              string
    bytesSent       atomic.Uint64
    bytesReceived   atomic.Uint64
    packetsSent     atomic.Uint64
    packetsReceived atomic.Uint64
    startTime       time.Time
    samples         *RingBuffer
    mu              sync.RWMutex
}

// NewAccountingManager creates accounting manager
func NewAccountingManager(nodeID string, storage *AccountingStorage) *AccountingManager {
    am := &AccountingManager{
        nodeID:    nodeID,
        accounts:  make(map[string]*BandwidthAccount),
        meters:    make(map[string]*BandwidthMeter),
        fairShare: NewFairShareAllocator(),
        qos:       NewQoSManager(),
        billing:   NewBillingIntegration(),
        storage:   storage,
    }
    
    // Start background tasks
    go am.runAccountingLoop()
    go am.runSettlementLoop()
    
    return am
}

// RecordTraffic records bandwidth usage
func (am *AccountingManager) RecordTraffic(accountID string, sent, received uint64) error {
    am.mu.Lock()
    defer am.mu.Unlock()
    
    account, exists := am.accounts[accountID]
    if !exists {
        account = am.createAccount(accountID)
        am.accounts[accountID] = account
    }
    
    // Update counters
    atomic.AddUint64(&account.BytesSent, sent)
    atomic.AddUint64(&account.BytesReceived, received)
    account.LastActivity = time.Now()
    
    // Update meter
    meter := am.getMeter(accountID)
    meter.recordBytes(sent, received)
    
    // Check rate limits
    if account.RateLimit != nil {
        if !account.RateLimit.AllowBytes(sent + received) {
            return errors.New("rate limit exceeded")
        }
    }
    
    // Update billing
    am.billing.RecordUsage(accountID, sent, received)
    
    return nil
}

// Fair sharing implementation
type FairShareAllocator struct {
    totalBandwidth   uint64
    activePeers      map[string]*PeerShare
    shares           map[string]float64
    algorithm        FairShareAlgorithm
    updateInterval   time.Duration
    mu               sync.RWMutex
}

// PeerShare represents a peer's bandwidth allocation
type PeerShare struct {
    PeerID          string
    Weight          float64
    MinGuaranteed   uint64
    MaxAllowed      uint64
    CurrentUsage    uint64
    AllocationTime  time.Time
    Priority        int
    BurstAllowance  uint64
}

// FairShareAlgorithm interface for different algorithms
type FairShareAlgorithm interface {
    CalculateShares(peers []*PeerShare, totalBandwidth uint64) map[string]uint64
    UpdateWeights(usage map[string]*UsageStats)
    GetName() string
}

// MaxMinFairShare implements max-min fair sharing
type MaxMinFairShare struct {
    config *FairShareConfig
}

// CalculateShares using max-min fairness
func (mmfs *MaxMinFairShare) CalculateShares(peers []*PeerShare, totalBandwidth uint64) map[string]uint64 {
    shares := make(map[string]uint64)
    remaining := totalBandwidth
    unsatisfied := make([]*PeerShare, len(peers))
    copy(unsatisfied, peers)
    
    // First, allocate minimum guaranteed
    for _, peer := range peers {
        if peer.MinGuaranteed > 0 {
            allocated := min(peer.MinGuaranteed, remaining)
            shares[peer.PeerID] = allocated
            remaining -= allocated
        }
    }
    
    // Then apply max-min fairness to remaining
    for len(unsatisfied) > 0 && remaining > 0 {
        fairShare := remaining / uint64(len(unsatisfied))
        newUnsatisfied := make([]*PeerShare, 0)
        
        for _, peer := range unsatisfied {
            current := shares[peer.PeerID]
            demand := peer.MaxAllowed - current
            
            if demand <= fairShare {
                // Peer is satisfied
                shares[peer.PeerID] = current + demand
                remaining -= demand
            } else {
                // Peer wants more
                shares[peer.PeerID] = current + fairShare
                remaining -= fairShare
                newUnsatisfied = append(newUnsatisfied, peer)
            }
        }
        
        unsatisfied = newUnsatisfied
    }
    
    return shares
}

// WeightedFairQueue implements WFQ algorithm
type WeightedFairQueue struct {
    queues    map[string]*PacketQueue
    weights   map[string]float64
    scheduler *PacketScheduler
}

// Schedule packets using WFQ
func (wfq *WeightedFairQueue) Schedule() *Packet {
    var selected *PacketQueue
    minFinishTime := math.MaxFloat64
    
    // Find queue with minimum virtual finish time
    for peerID, queue := range wfq.queues {
        if queue.IsEmpty() {
            continue
        }
        
        weight := wfq.weights[peerID]
        packet := queue.Peek()
        finishTime := queue.VirtualTime + float64(packet.Size)/weight
        
        if finishTime < minFinishTime {
            minFinishTime = finishTime
            selected = queue
        }
    }
    
    if selected != nil {
        packet := selected.Dequeue()
        selected.VirtualTime = minFinishTime
        return packet
    }
    
    return nil
}

// QoS Manager implementation
type QoSManager struct {
    classes      map[string]*TrafficClass
    policies     map[string]*QoSPolicy
    shapers      map[string]*TrafficShaper
    markers      *PacketMarker
    dropper      *PacketDropper
    scheduler    *HierarchicalScheduler
}

// TrafficClass defines QoS class
type TrafficClass struct {
    Name           string
    Priority       int
    MinBandwidth   uint64
    MaxBandwidth   uint64
    BurstSize      uint64
    Latency        time.Duration
    Jitter         time.Duration
    PacketLoss     float64
}

// QoSPolicy defines traffic handling policy
type QoSPolicy struct {
    Name         string
    Classes      []string
    DefaultClass string
    Classifier   TrafficClassifier
    Actions      []QoSAction
}

// ApplyQoS applies QoS policies to traffic
func (qm *QoSManager) ApplyQoS(packet *Packet) error {
    // Classify packet
    class := qm.classifyPacket(packet)
    
    // Mark packet with class
    qm.markers.MarkPacket(packet, class)
    
    // Apply traffic shaping
    shaper := qm.shapers[class.Name]
    if shaper != nil {
        if !shaper.ConformsToBucket(packet.Size) {
            // Apply drop policy
            if qm.dropper.ShouldDrop(packet, class) {
                return errors.New("packet dropped by QoS")
            }
            // Delay packet
            shaper.DelayPacket(packet)
        }
    }
    
    // Schedule packet
    return qm.scheduler.Enqueue(packet, class)
}

// Token bucket for rate limiting
type TokenBucket struct {
    capacity     uint64
    tokens       atomic.Int64
    refillRate   uint64
    lastRefill   atomic.Int64
    mu           sync.Mutex
}

// NewTokenBucket creates token bucket
func NewTokenBucket(capacity, refillRate uint64) *TokenBucket {
    tb := &TokenBucket{
        capacity:   capacity,
        refillRate: refillRate,
    }
    tb.tokens.Store(int64(capacity))
    tb.lastRefill.Store(time.Now().UnixNano())
    return tb
}

// TakeTokens attempts to take tokens
func (tb *TokenBucket) TakeTokens(count uint64) bool {
    tb.mu.Lock()
    defer tb.mu.Unlock()
    
    // Refill tokens
    now := time.Now().UnixNano()
    elapsed := now - tb.lastRefill.Load()
    refill := uint64(elapsed) * tb.refillRate / uint64(time.Second)
    
    current := tb.tokens.Load()
    newTokens := min(int64(tb.capacity), current+int64(refill))
    tb.tokens.Store(newTokens)
    tb.lastRefill.Store(now)
    
    // Try to take tokens
    if newTokens >= int64(count) {
        tb.tokens.Add(-int64(count))
        return true
    }
    
    return false
}

// Hierarchical Token Bucket (HTB) scheduler
type HTBScheduler struct {
    root      *HTBClass
    classes   map[string]*HTBClass
    active    map[int][]*HTBClass  // Priority queues
    mu        sync.RWMutex
}

// HTBClass represents HTB class
type HTBClass struct {
    ID           string
    Parent       *HTBClass
    Children     []*HTBClass
    Rate         uint64
    Ceil         uint64
    Burst        uint64
    Priority     int
    Quantum      uint64
    TokenBucket  *TokenBucket
    CeilBucket   *TokenBucket
    Queue        *PacketQueue
}

// Billing integration
type BillingIntegration struct {
    nodeID       string
    rates        *RateTable
    settlements  *SettlementEngine
    ledger       *BillingLedger
    reconciler   *Reconciler
    mu           sync.RWMutex
}

// RateTable stores bandwidth rates
type RateTable struct {
    baseRate      float64
    peakRate      float64
    offPeakRate   float64
    tiers         []RateTier
    specialRates  map[string]float64
}

// RateTier defines volume-based pricing
type RateTier struct {
    MinBytes  uint64
    MaxBytes  uint64
    RatePerGB float64
}

// CalculateCost calculates bandwidth cost
func (bi *BillingIntegration) CalculateCost(usage *UsageRecord) (*Cost, error) {
    bi.mu.RLock()
    defer bi.mu.RUnlock()
    
    // Get applicable rate
    rate := bi.getApplicableRate(usage)
    
    // Calculate base cost
    totalBytes := usage.BytesSent + usage.BytesReceived
    gbUsed := float64(totalBytes) / (1024 * 1024 * 1024)
    baseCost := gbUsed * rate
    
    // Apply tier pricing
    tierCost := bi.calculateTierCost(totalBytes)
    
    // Apply time-of-day pricing
    todMultiplier := bi.getTimeOfDayMultiplier(usage.Period)
    
    // Calculate final cost
    finalCost := (baseCost + tierCost) * todMultiplier
    
    return &Cost{
        Amount:      finalCost,
        Currency:    "USD",
        Period:      usage.Period,
        Breakdown:   bi.createCostBreakdown(baseCost, tierCost, todMultiplier),
        TotalBytes:  totalBytes,
    }, nil
}

// Settlement engine for peer payments
type SettlementEngine struct {
    settlements  map[string]*Settlement
    pending      []*Settlement
    threshold    float64
    interval     time.Duration
    paymentGW    PaymentGateway
}

// Settlement represents bandwidth payment settlement
type Settlement struct {
    ID            string
    PeerID        string
    Amount        float64
    Currency      string
    Period        TimePeriod
    Usage         *UsageRecord
    Status        SettlementStatus
    CreatedAt     time.Time
    SettledAt     *time.Time
    TransactionID string
}

// ProcessSettlement processes pending settlement
func (se *SettlementEngine) ProcessSettlement(settlement *Settlement) error {
    // Validate settlement
    if err := se.validateSettlement(settlement); err != nil {
        return err
    }
    
    // Check if meets threshold
    if settlement.Amount < se.threshold {
        se.pending = append(se.pending, settlement)
        return nil
    }
    
    // Process payment
    txID, err := se.paymentGW.ProcessPayment(
        settlement.PeerID,
        settlement.Amount,
        settlement.Currency,
    )
    if err != nil {
        settlement.Status = SettlementFailed
        return err
    }
    
    // Update settlement
    settlement.Status = SettlementCompleted
    settlement.SettledAt = timePtr(time.Now())
    settlement.TransactionID = txID
    
    return nil
}

// Real-time usage tracking
type UsageTracker struct {
    current      map[string]*RealtimeUsage
    history      *UsageHistory
    aggregator   *UsageAggregator
    mu           sync.RWMutex
}

// RealtimeUsage tracks current usage
type RealtimeUsage struct {
    AccountID        string
    CurrentSecond    uint64
    CurrentMinute    uint64
    CurrentHour      uint64
    CurrentDay       uint64
    LastUpdate       time.Time
    RollingAverage   float64
}

// UpdateUsage updates real-time usage
func (ut *UsageTracker) UpdateUsage(accountID string, bytes uint64) {
    ut.mu.Lock()
    defer ut.mu.Unlock()
    
    usage, exists := ut.current[accountID]
    if !exists {
        usage = &RealtimeUsage{AccountID: accountID}
        ut.current[accountID] = usage
    }
    
    now := time.Now()
    
    // Update counters
    usage.CurrentSecond += bytes
    usage.CurrentMinute += bytes
    usage.CurrentHour += bytes
    usage.CurrentDay += bytes
    usage.LastUpdate = now
    
    // Update rolling average
    alpha := 0.1
    usage.RollingAverage = alpha*float64(bytes) + (1-alpha)*usage.RollingAverage
    
    // Check for period boundaries
    ut.checkPeriodBoundaries(usage, now)
}

// Bandwidth prediction using ML
type BandwidthPredictor struct {
    model       *PredictionModel
    history     *UsageHistory
    features    *FeatureExtractor
}

// PredictUsage predicts future bandwidth usage
func (bp *BandwidthPredictor) PredictUsage(accountID string, duration time.Duration) (*UsagePrediction, error) {
    // Extract features from history
    features := bp.features.ExtractFeatures(accountID, bp.history)
    
    // Run prediction model
    prediction := bp.model.Predict(features)
    
    return &UsagePrediction{
        AccountID:    accountID,
        Duration:     duration,
        PredictedBytes: prediction.Bytes,
        Confidence:   prediction.Confidence,
        PeakTime:     prediction.PeakTime,
        Pattern:      prediction.Pattern,
    }, nil
}

// Accounting storage
type AccountingStorage struct {
    db          *sql.DB
    cache       *AccountingCache
    compressor  *DataCompressor
}

// StoreAccountingRecord stores accounting data
func (as *AccountingStorage) StoreAccountingRecord(record *AccountingRecord) error {
    // Compress data
    compressed, err := as.compressor.Compress(record)
    if err != nil {
        return err
    }
    
    // Store in database
    query := `
        INSERT INTO bandwidth_accounting 
        (account_id, timestamp, bytes_sent, bytes_received, 
         packets_sent, packets_received, compressed_data)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
    
    _, err = as.db.Exec(query,
        record.AccountID,
        record.Timestamp,
        record.BytesSent,
        record.BytesReceived,
        record.PacketsSent,
        record.PacketsReceived,
        compressed,
    )
    
    if err != nil {
        return err
    }
    
    // Update cache
    as.cache.Update(record)
    
    return nil
}

// Helper functions
func min(a, b uint64) uint64 {
    if a < b {
        return a
    }
    return b
}

func timePtr(t time.Time) *time.Time {
    return &t
}
```

### Advanced Accounting Features

```go
package bandwidth

import (
    "context"
    "encoding/json"
    "math"
    "sort"
)

// DynamicPricingEngine adjusts rates based on network conditions
type DynamicPricingEngine struct {
    baseRates       *RateTable
    utilization     *NetworkUtilization
    demand          *DemandAnalyzer
    optimizer       *PriceOptimizer
    constraints     *PricingConstraints
}

// PricingConstraints defines pricing boundaries
type PricingConstraints struct {
    MinRate      float64
    MaxRate      float64
    MaxIncrease  float64  // Max % increase per period
    MaxDecrease  float64  // Max % decrease per period
    SmoothFactor float64  // Smoothing factor for changes
}

// CalculateDynamicRate calculates current rate
func (dpe *DynamicPricingEngine) CalculateDynamicRate() float64 {
    // Get current network utilization
    utilization := dpe.utilization.GetCurrent()
    
    // Get demand metrics
    demand := dpe.demand.GetDemandMetrics()
    
    // Calculate optimal price
    optimalPrice := dpe.optimizer.FindOptimalPrice(
        utilization,
        demand,
        dpe.baseRates,
    )
    
    // Apply constraints
    return dpe.applyConstraints(optimalPrice)
}

// CongestionPricing implements congestion-based pricing
type CongestionPricing struct {
    zones          map[string]*CongestionZone
    monitor        *CongestionMonitor
    priceAdjuster  *PriceAdjuster
}

// CongestionZone represents network zone
type CongestionZone struct {
    ID              string
    CurrentLoad     float64
    Capacity        uint64
    CongestionLevel float64
    PriceMultiplier float64
}

// GetCongestionPrice returns congestion-adjusted price
func (cp *CongestionPricing) GetCongestionPrice(zoneID string, basePrice float64) float64 {
    zone, exists := cp.zones[zoneID]
    if !exists {
        return basePrice
    }
    
    // Calculate congestion multiplier
    multiplier := 1.0 + (zone.CongestionLevel * zone.PriceMultiplier)
    
    return basePrice * multiplier
}

// BandwidthMarket implements market-based allocation
type BandwidthMarket struct {
    orderBook      *OrderBook
    matcher        *OrderMatcher
    clearingHouse  *ClearingHouse
    priceDiscovery *PriceDiscovery
}

// Order represents bandwidth buy/sell order
type Order struct {
    ID         string
    Type       OrderType
    NodeID     string
    Bandwidth  uint64
    Price      float64
    Duration   time.Duration
    Expiry     time.Time
    Status     OrderStatus
}

// OrderBook maintains buy/sell orders
type OrderBook struct {
    buyOrders  *OrderHeap
    sellOrders *OrderHeap
    mu         sync.RWMutex
}

// MatchOrders matches buy and sell orders
func (om *OrderMatcher) MatchOrders(book *OrderBook) []*Match {
    matches := make([]*Match, 0)
    
    for !book.buyOrders.Empty() && !book.sellOrders.Empty() {
        buy := book.buyOrders.Peek()
        sell := book.sellOrders.Peek()
        
        // Check if orders match
        if buy.Price >= sell.Price {
            // Create match
            match := &Match{
                BuyOrder:  buy,
                SellOrder: sell,
                Price:     (buy.Price + sell.Price) / 2,
                Bandwidth: min(buy.Bandwidth, sell.Bandwidth),
                Timestamp: time.Now(),
            }
            
            matches = append(matches, match)
            
            // Update orders
            om.updateOrders(book, match)
        } else {
            break
        }
    }
    
    return matches
}

// ReputationBasedAccounting factors in node reputation
type ReputationBasedAccounting struct {
    reputation     *ReputationSystem
    discounts      *DiscountCalculator
    penalties      *PenaltyCalculator
}

// ApplyReputationAdjustment adjusts cost based on reputation
func (rba *ReputationBasedAccounting) ApplyReputationAdjustment(nodeID string, baseCost float64) float64 {
    rep := rba.reputation.GetReputation(nodeID)
    
    // High reputation gets discount
    if rep.Score > 0.8 {
        discount := rba.discounts.CalculateDiscount(rep)
        return baseCost * (1 - discount)
    }
    
    // Low reputation pays penalty
    if rep.Score < 0.3 {
        penalty := rba.penalties.CalculatePenalty(rep)
        return baseCost * (1 + penalty)
    }
    
    return baseCost
}

// BandwidthInsurance provides SLA guarantees
type BandwidthInsurance struct {
    policies      map[string]*InsurancePolicy
    claims        *ClaimsProcessor
    underwriter   *Underwriter
}

// InsurancePolicy defines bandwidth guarantee
type InsurancePolicy struct {
    ID              string
    NodeID          string
    GuaranteedBW    uint64
    Availability    float64  // e.g., 99.9%
    CompensationRate float64
    Premium         float64
    Active          bool
}

// ProcessClaim handles SLA violation claims
func (bi *BandwidthInsurance) ProcessClaim(claim *InsuranceClaim) (*ClaimResult, error) {
    // Verify claim
    valid, metrics := bi.verifyClaim(claim)
    if !valid {
        return &ClaimResult{
            Approved: false,
            Reason:   "Claim verification failed",
        }, nil
    }
    
    // Calculate compensation
    compensation := bi.calculateCompensation(claim.Policy, metrics)
    
    // Process payment
    return bi.claims.ProcessPayment(claim, compensation)
}

// CrossChainSettlement enables multi-chain settlements
type CrossChainSettlement struct {
    chains         map[string]ChainConnector
    router         *SettlementRouter
    escrow         *EscrowManager
    atomic         *AtomicSwapEngine
}

// SettleAcrossChains settles bandwidth payments across chains
func (ccs *CrossChainSettlement) SettleAcrossChains(
    settlement *Settlement,
    sourceChain string,
    targetChain string,
) error {
    // Lock funds in escrow
    escrowID, err := ccs.escrow.LockFunds(
        settlement.Amount,
        sourceChain,
        settlement.PeerID,
    )
    if err != nil {
        return err
    }
    
    // Create atomic swap
    swap := ccs.atomic.CreateSwap(
        escrowID,
        sourceChain,
        targetChain,
        settlement.Amount,
    )
    
    // Execute swap
    return ccs.atomic.ExecuteSwap(swap)
}

// PredictiveAccounting anticipates future usage
type PredictiveAccounting struct {
    predictor      *UsagePredictor
    preAllocator   *ResourcePreAllocator
    optimizer      *AllocationOptimizer
}

// PreAllocateResources allocates based on predictions
func (pa *PredictiveAccounting) PreAllocateResources(nodeID string) (*PreAllocation, error) {
    // Predict future usage
    prediction, err := pa.predictor.PredictNextPeriod(nodeID)
    if err != nil {
        return nil, err
    }
    
    // Optimize allocation
    allocation := pa.optimizer.OptimizeAllocation(prediction)
    
    // Pre-allocate resources
    return pa.preAllocator.Allocate(nodeID, allocation)
}

// ComplianceEngine ensures regulatory compliance
type ComplianceEngine struct {
    rules         *ComplianceRules
    auditor       *AuditLogger
    reporter      *ComplianceReporter
    validator     *TransactionValidator
}

// ValidateTransaction ensures compliance
func (ce *ComplianceEngine) ValidateTransaction(tx *BandwidthTransaction) error {
    // Check against rules
    violations := ce.rules.CheckViolations(tx)
    if len(violations) > 0 {
        ce.auditor.LogViolations(tx, violations)
        return errors.New("compliance violations detected")
    }
    
    // Validate amounts
    if err := ce.validator.ValidateAmounts(tx); err != nil {
        return err
    }
    
    // Log for audit
    ce.auditor.LogTransaction(tx)
    
    return nil
}

// AnalyticsEngine provides accounting insights
type AnalyticsEngine struct {
    collector     *DataCollector
    analyzer      *UsageAnalyzer
    visualizer    *DataVisualizer
    alerter       *AlertManager
}

// GenerateInsights creates usage insights
func (ae *AnalyticsEngine) GenerateInsights(period TimePeriod) (*UsageInsights, error) {
    // Collect data
    data, err := ae.collector.CollectForPeriod(period)
    if err != nil {
        return nil, err
    }
    
    // Analyze patterns
    patterns := ae.analyzer.FindPatterns(data)
    
    // Generate insights
    insights := &UsageInsights{
        Period:          period,
        TotalUsage:      ae.analyzer.CalculateTotalUsage(data),
        PeakUsage:       ae.analyzer.FindPeakUsage(data),
        CostTrends:      ae.analyzer.AnalyzeCostTrends(data),
        Anomalies:       ae.analyzer.DetectAnomalies(data),
        Predictions:     ae.analyzer.PredictFuture(data),
        Recommendations: ae.generateRecommendations(patterns),
    }
    
    // Check for alerts
    ae.checkAlerts(insights)
    
    return insights, nil
}
```

## Dependencies
- Time-series database for usage data
- Payment gateway integration
- Machine learning libraries for prediction
- Blockchain connectors for settlements

## Configuration
```yaml
bandwidth_accounting:
  storage:
    type: "timeseries"
    retention_days: 90
    compression: true
  
  fair_sharing:
    algorithm: "max_min_fairness"
    update_interval: "1s"
    min_guarantee_mbps: 1
    burst_allowance_mb: 100
  
  qos:
    classes:
      - name: "premium"
        priority: 1
        min_bandwidth_mbps: 10
        max_bandwidth_mbps: 100
        latency_ms: 10
      - name: "standard"
        priority: 2
        min_bandwidth_mbps: 1
        max_bandwidth_mbps: 50
        latency_ms: 50
      - name: "economy"
        priority: 3
        min_bandwidth_mbps: 0.1
        max_bandwidth_mbps: 10
        latency_ms: 100
  
  billing:
    base_rate_per_gb: 0.01
    peak_multiplier: 1.5
    off_peak_multiplier: 0.7
    settlement_threshold: 10.0
    settlement_interval: "24h"
    payment_methods:
      - "crypto"
      - "lightning"
      - "channel"
  
  dynamic_pricing:
    enabled: true
    min_rate: 0.005
    max_rate: 0.05
    max_increase_percent: 20
    max_decrease_percent: 30
    update_interval: "1h"
```

## Security Considerations
1. **Usage Verification**: Cryptographic proofs of bandwidth usage
2. **Double Spending**: Prevent bandwidth credit double spending
3. **Rate Limit Bypass**: Secure rate limiting implementation
4. **Settlement Security**: Atomic swaps for settlements
5. **Privacy**: Anonymous accounting options

## Performance Metrics
- Accounting overhead < 1% of bandwidth
- Real-time tracking latency < 1ms
- Settlement processing < 100ms
- Storage efficiency > 10:1 compression
- QoS scheduling < 10μs per packet