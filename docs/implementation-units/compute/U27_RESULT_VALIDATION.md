# U27: Result Validation System

## Overview
This unit implements the result verification system for distributed computing tasks, including consensus mechanisms, fraud detection, and dispute resolution.

## Implementation

### Core Types

```go
package validation

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "sync"
    "time"
)

// ValidationResult represents the outcome of result validation
type ValidationResult struct {
    TaskID       string
    ResultID     string
    IsValid      bool
    Confidence   float64
    Validators   []ValidatorVote
    Timestamp    time.Time
    ConsensusType ConsensusType
}

// ValidatorVote represents a single validator's decision
type ValidatorVote struct {
    NodeID       string
    Vote         VoteType
    ResultHash   string
    Timestamp    time.Time
    Signature    []byte
    Reputation   float64
}

// VoteType represents the type of vote
type VoteType int

const (
    VoteApprove VoteType = iota
    VoteReject
    VoteAbstain
)

// ConsensusType represents the consensus mechanism used
type ConsensusType int

const (
    ConsensusSimpleMajority ConsensusType = iota
    ConsensusWeightedMajority
    ConsensusByzantine
    ConsensusProofOfWork
)

// DisputeCase represents a dispute over computation results
type DisputeCase struct {
    ID              string
    TaskID          string
    DisputedResults []string
    Challenger      string
    Defendant       string
    Evidence        []Evidence
    Status          DisputeStatus
    Resolution      *DisputeResolution
    CreatedAt       time.Time
    UpdatedAt       time.Time
}

// Evidence represents evidence in a dispute
type Evidence struct {
    ID          string
    Type        EvidenceType
    Data        []byte
    SubmittedBy string
    Timestamp   time.Time
    Hash        string
}

// EvidenceType represents the type of evidence
type EvidenceType int

const (
    EvidenceComputationLog EvidenceType = iota
    EvidenceIntermediateResult
    EvidenceResourceUsage
    EvidenceReproduction
)

// DisputeStatus represents the status of a dispute
type DisputeStatus int

const (
    DisputePending DisputeStatus = iota
    DisputeUnderReview
    DisputeResolved
    DisputeEscalated
)

// DisputeResolution represents the resolution of a dispute
type DisputeResolution struct {
    Decision      Decision
    Winner        string
    Penalty       float64
    Compensation  float64
    Arbitrators   []string
    Justification string
    Timestamp     time.Time
}

// Decision represents the dispute decision
type Decision int

const (
    DecisionInFavorOfChallenger Decision = iota
    DecisionInFavorOfDefendant
    DecisionSplit
    DecisionInconclusive
)
```

### Validation Service

```go
// ValidationService handles result validation
type ValidationService struct {
    validators      map[string]*Validator
    consensusEngine ConsensusEngine
    fraudDetector   *FraudDetector
    disputeManager  *DisputeManager
    reputationMgr   *ReputationManager
    mu              sync.RWMutex
}

// NewValidationService creates a new validation service
func NewValidationService(
    consensusEngine ConsensusEngine,
    fraudDetector *FraudDetector,
    disputeManager *DisputeManager,
    reputationMgr *ReputationManager,
) *ValidationService {
    return &ValidationService{
        validators:      make(map[string]*Validator),
        consensusEngine: consensusEngine,
        fraudDetector:   fraudDetector,
        disputeManager:  disputeManager,
        reputationMgr:   reputationMgr,
    }
}

// ValidateResult validates a computation result
func (vs *ValidationService) ValidateResult(
    ctx context.Context,
    taskID string,
    result *ComputeResult,
) (*ValidationResult, error) {
    vs.mu.RLock()
    defer vs.mu.RUnlock()

    // Check for fraud indicators
    fraudIndicators, err := vs.fraudDetector.CheckResult(ctx, result)
    if err != nil {
        return nil, err
    }

    if len(fraudIndicators) > 0 {
        // Initiate dispute if fraud is suspected
        dispute, err := vs.disputeManager.CreateDispute(ctx, taskID, result.ID, fraudIndicators)
        if err != nil {
            return nil, err
        }
        return nil, errors.New("fraud suspected, dispute initiated: " + dispute.ID)
    }

    // Select validators based on reputation and availability
    validators, err := vs.selectValidators(ctx, taskID)
    if err != nil {
        return nil, err
    }

    // Collect validator votes
    votes := make([]ValidatorVote, 0, len(validators))
    var wg sync.WaitGroup
    voteChan := make(chan ValidatorVote, len(validators))

    for _, validator := range validators {
        wg.Add(1)
        go func(v *Validator) {
            defer wg.Done()
            vote, err := v.ValidateResult(ctx, taskID, result)
            if err == nil {
                voteChan <- vote
            }
        }(validator)
    }

    go func() {
        wg.Wait()
        close(voteChan)
    }()

    for vote := range voteChan {
        votes = append(votes, vote)
    }

    // Apply consensus mechanism
    consensus, err := vs.consensusEngine.ReachConsensus(ctx, votes)
    if err != nil {
        return nil, err
    }

    // Update validator reputations based on consensus
    vs.updateReputations(ctx, votes, consensus)

    return &ValidationResult{
        TaskID:        taskID,
        ResultID:      result.ID,
        IsValid:       consensus.IsValid,
        Confidence:    consensus.Confidence,
        Validators:    votes,
        Timestamp:     time.Now(),
        ConsensusType: consensus.Type,
    }, nil
}

// selectValidators selects validators for a task
func (vs *ValidationService) selectValidators(ctx context.Context, taskID string) ([]*Validator, error) {
    // Implementation would select validators based on:
    // - Reputation score
    // - Availability
    // - Specialization in task type
    // - Geographic distribution
    // - Stake amount
    
    var selected []*Validator
    requiredCount := 5 // Minimum validators needed

    for _, v := range vs.validators {
        if v.IsAvailable() && v.Reputation > 0.7 {
            selected = append(selected, v)
            if len(selected) >= requiredCount {
                break
            }
        }
    }

    if len(selected) < requiredCount {
        return nil, errors.New("insufficient validators available")
    }

    return selected, nil
}

// updateReputations updates validator reputations based on consensus
func (vs *ValidationService) updateReputations(
    ctx context.Context,
    votes []ValidatorVote,
    consensus *ConsensusResult,
) {
    for _, vote := range votes {
        if vote.Vote == VoteApprove && consensus.IsValid ||
           vote.Vote == VoteReject && !consensus.IsValid {
            // Validator agreed with consensus
            vs.reputationMgr.IncreaseReputation(vote.NodeID, 0.01)
        } else if vote.Vote != VoteAbstain {
            // Validator disagreed with consensus
            vs.reputationMgr.DecreaseReputation(vote.NodeID, 0.02)
        }
    }
}
```

### Consensus Engine

```go
// ConsensusEngine defines the interface for consensus mechanisms
type ConsensusEngine interface {
    ReachConsensus(ctx context.Context, votes []ValidatorVote) (*ConsensusResult, error)
    GetType() ConsensusType
}

// ConsensusResult represents the result of consensus
type ConsensusResult struct {
    IsValid    bool
    Confidence float64
    Type       ConsensusType
    Details    map[string]interface{}
}

// WeightedMajorityConsensus implements weighted majority voting
type WeightedMajorityConsensus struct {
    threshold float64
}

// NewWeightedMajorityConsensus creates a new weighted majority consensus engine
func NewWeightedMajorityConsensus(threshold float64) *WeightedMajorityConsensus {
    return &WeightedMajorityConsensus{
        threshold: threshold,
    }
}

// ReachConsensus reaches consensus using weighted majority
func (wmc *WeightedMajorityConsensus) ReachConsensus(
    ctx context.Context,
    votes []ValidatorVote,
) (*ConsensusResult, error) {
    if len(votes) == 0 {
        return nil, errors.New("no votes to process")
    }

    totalWeight := 0.0
    approveWeight := 0.0
    rejectWeight := 0.0

    for _, vote := range votes {
        weight := vote.Reputation
        totalWeight += weight

        switch vote.Vote {
        case VoteApprove:
            approveWeight += weight
        case VoteReject:
            rejectWeight += weight
        }
    }

    if totalWeight == 0 {
        return nil, errors.New("total weight is zero")
    }

    approveRatio := approveWeight / totalWeight
    isValid := approveRatio >= wmc.threshold

    confidence := approveRatio
    if !isValid {
        confidence = rejectWeight / totalWeight
    }

    return &ConsensusResult{
        IsValid:    isValid,
        Confidence: confidence,
        Type:       ConsensusWeightedMajority,
        Details: map[string]interface{}{
            "approveWeight": approveWeight,
            "rejectWeight":  rejectWeight,
            "totalWeight":   totalWeight,
            "threshold":     wmc.threshold,
        },
    }, nil
}

// GetType returns the consensus type
func (wmc *WeightedMajorityConsensus) GetType() ConsensusType {
    return ConsensusWeightedMajority
}
```

### Fraud Detector

```go
// FraudDetector detects potential fraud in computation results
type FraudDetector struct {
    patterns      []FraudPattern
    anomalyEngine *AnomalyDetector
    history       *ResultHistory
    mu            sync.RWMutex
}

// FraudPattern represents a pattern that indicates potential fraud
type FraudPattern struct {
    ID          string
    Name        string
    Description string
    Detector    func(*ComputeResult) (bool, float64)
}

// FraudIndicator represents an indicator of potential fraud
type FraudIndicator struct {
    PatternID   string
    Confidence  float64
    Description string
    Evidence    []byte
}

// NewFraudDetector creates a new fraud detector
func NewFraudDetector(anomalyEngine *AnomalyDetector, history *ResultHistory) *FraudDetector {
    fd := &FraudDetector{
        anomalyEngine: anomalyEngine,
        history:       history,
        patterns:      make([]FraudPattern, 0),
    }

    // Register default fraud patterns
    fd.registerDefaultPatterns()
    return fd
}

// CheckResult checks a result for fraud indicators
func (fd *FraudDetector) CheckResult(
    ctx context.Context,
    result *ComputeResult,
) ([]FraudIndicator, error) {
    fd.mu.RLock()
    defer fd.mu.RUnlock()

    indicators := make([]FraudIndicator, 0)

    // Check against known patterns
    for _, pattern := range fd.patterns {
        matches, confidence := pattern.Detector(result)
        if matches {
            indicators = append(indicators, FraudIndicator{
                PatternID:   pattern.ID,
                Confidence:  confidence,
                Description: pattern.Description,
            })
        }
    }

    // Check for anomalies
    anomalies, err := fd.anomalyEngine.DetectAnomalies(ctx, result)
    if err != nil {
        return nil, err
    }

    for _, anomaly := range anomalies {
        indicators = append(indicators, FraudIndicator{
            PatternID:   "anomaly",
            Confidence:  anomaly.Score,
            Description: anomaly.Description,
            Evidence:    anomaly.Data,
        })
    }

    return indicators, nil
}

// registerDefaultPatterns registers default fraud detection patterns
func (fd *FraudDetector) registerDefaultPatterns() {
    fd.patterns = append(fd.patterns, FraudPattern{
        ID:          "impossible_speed",
        Name:        "Impossible Computation Speed",
        Description: "Result returned faster than theoretically possible",
        Detector: func(result *ComputeResult) (bool, float64) {
            // Check if computation time is impossibly fast
            minTime := estimateMinimumTime(result.Task)
            actualTime := result.CompletedAt.Sub(result.StartedAt)
            if actualTime < minTime*0.5 {
                return true, 0.9
            }
            return false, 0.0
        },
    })

    fd.patterns = append(fd.patterns, FraudPattern{
        ID:          "duplicate_result",
        Name:        "Duplicate Result",
        Description: "Result identical to previous submission",
        Detector: func(result *ComputeResult) (bool, float64) {
            // Check if result hash matches previous submissions
            hash := hashResult(result)
            if fd.history.HasIdenticalResult(hash) {
                return true, 0.95
            }
            return false, 0.0
        },
    })

    fd.patterns = append(fd.patterns, FraudPattern{
        ID:          "resource_mismatch",
        Name:        "Resource Usage Mismatch",
        Description: "Reported resource usage doesn't match result complexity",
        Detector: func(result *ComputeResult) (bool, float64) {
            // Check if resource usage matches expected patterns
            expected := estimateResourceUsage(result.Task)
            actual := result.ResourceUsage
            
            cpuDiff := abs(expected.CPUSeconds-actual.CPUSeconds) / expected.CPUSeconds
            memDiff := abs(float64(expected.MemoryBytes-actual.MemoryBytes)) / float64(expected.MemoryBytes)
            
            if cpuDiff > 0.5 || memDiff > 0.5 {
                return true, (cpuDiff + memDiff) / 2
            }
            return false, 0.0
        },
    })
}
```

### Dispute Manager

```go
// DisputeManager handles disputes over computation results
type DisputeManager struct {
    disputes      map[string]*DisputeCase
    arbitrators   map[string]*Arbitrator
    evidenceStore *EvidenceStore
    mu            sync.RWMutex
}

// NewDisputeManager creates a new dispute manager
func NewDisputeManager(evidenceStore *EvidenceStore) *DisputeManager {
    return &DisputeManager{
        disputes:      make(map[string]*DisputeCase),
        arbitrators:   make(map[string]*Arbitrator),
        evidenceStore: evidenceStore,
    }
}

// CreateDispute creates a new dispute case
func (dm *DisputeManager) CreateDispute(
    ctx context.Context,
    taskID string,
    resultID string,
    indicators []FraudIndicator,
) (*DisputeCase, error) {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    disputeID := generateDisputeID()
    
    // Convert fraud indicators to evidence
    evidence := make([]Evidence, 0, len(indicators))
    for _, indicator := range indicators {
        ev := Evidence{
            ID:          generateEvidenceID(),
            Type:        EvidenceComputationLog,
            Data:        indicator.Evidence,
            SubmittedBy: "system",
            Timestamp:   time.Now(),
        }
        ev.Hash = hashEvidence(ev)
        evidence = append(evidence, ev)
    }

    dispute := &DisputeCase{
        ID:              disputeID,
        TaskID:          taskID,
        DisputedResults: []string{resultID},
        Status:          DisputePending,
        Evidence:        evidence,
        CreatedAt:       time.Now(),
        UpdatedAt:       time.Now(),
    }

    dm.disputes[disputeID] = dispute

    // Store evidence
    for _, ev := range evidence {
        if err := dm.evidenceStore.StoreEvidence(ctx, &ev); err != nil {
            return nil, err
        }
    }

    // Notify arbitrators
    go dm.notifyArbitrators(ctx, dispute)

    return dispute, nil
}

// SubmitEvidence submits evidence for a dispute
func (dm *DisputeManager) SubmitEvidence(
    ctx context.Context,
    disputeID string,
    evidence *Evidence,
) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    dispute, exists := dm.disputes[disputeID]
    if !exists {
        return errors.New("dispute not found")
    }

    if dispute.Status != DisputePending && dispute.Status != DisputeUnderReview {
        return errors.New("dispute not accepting evidence")
    }

    evidence.ID = generateEvidenceID()
    evidence.Timestamp = time.Now()
    evidence.Hash = hashEvidence(*evidence)

    dispute.Evidence = append(dispute.Evidence, *evidence)
    dispute.UpdatedAt = time.Now()

    return dm.evidenceStore.StoreEvidence(ctx, evidence)
}

// ResolveDispute resolves a dispute case
func (dm *DisputeManager) ResolveDispute(
    ctx context.Context,
    disputeID string,
    resolution *DisputeResolution,
) error {
    dm.mu.Lock()
    defer dm.mu.Unlock()

    dispute, exists := dm.disputes[disputeID]
    if !exists {
        return errors.New("dispute not found")
    }

    if dispute.Status == DisputeResolved {
        return errors.New("dispute already resolved")
    }

    dispute.Resolution = resolution
    dispute.Status = DisputeResolved
    dispute.UpdatedAt = time.Now()

    // Apply penalties and compensations
    if err := dm.applyResolution(ctx, dispute, resolution); err != nil {
        return err
    }

    return nil
}

// applyResolution applies the resolution of a dispute
func (dm *DisputeManager) applyResolution(
    ctx context.Context,
    dispute *DisputeCase,
    resolution *DisputeResolution,
) error {
    // Implementation would:
    // - Apply penalties to the losing party
    // - Award compensation to the winning party
    // - Update reputation scores
    // - Record the resolution on-chain if necessary
    return nil
}

// notifyArbitrators notifies arbitrators of a new dispute
func (dm *DisputeManager) notifyArbitrators(ctx context.Context, dispute *DisputeCase) {
    for _, arbitrator := range dm.arbitrators {
        if arbitrator.IsAvailable() && arbitrator.CanArbitrate(dispute) {
            arbitrator.NotifyDispute(dispute)
        }
    }
}
```

### Helper Functions

```go
// hashResult generates a hash of computation result
func hashResult(result *ComputeResult) string {
    h := sha256.New()
    h.Write([]byte(result.ID))
    h.Write(result.Output)
    h.Write([]byte(result.NodeID))
    return hex.EncodeToString(h.Sum(nil))
}

// hashEvidence generates a hash of evidence
func hashEvidence(ev Evidence) string {
    h := sha256.New()
    h.Write([]byte(ev.ID))
    h.Write([]byte(ev.Type))
    h.Write(ev.Data)
    h.Write([]byte(ev.SubmittedBy))
    return hex.EncodeToString(h.Sum(nil))
}

// estimateMinimumTime estimates minimum time for task completion
func estimateMinimumTime(task *ComputeTask) time.Duration {
    // Simple estimation based on task complexity
    baseTime := time.Second
    complexity := float64(len(task.Input)) / 1000.0 // KB of input
    return time.Duration(float64(baseTime) * complexity)
}

// estimateResourceUsage estimates expected resource usage
func estimateResourceUsage(task *ComputeTask) ResourceMetrics {
    // Simple estimation based on task type and size
    return ResourceMetrics{
        CPUSeconds:  float64(len(task.Input)) / 100.0,
        MemoryBytes: uint64(len(task.Input) * 10),
    }
}

// abs returns absolute value
func abs(x float64) float64 {
    if x < 0 {
        return -x
    }
    return x
}

// generateDisputeID generates a unique dispute ID
func generateDisputeID() string {
    return "dispute_" + generateID()
}

// generateEvidenceID generates a unique evidence ID
func generateEvidenceID() string {
    return "evidence_" + generateID()
}

// generateID generates a unique ID
func generateID() string {
    // Implementation would generate a unique ID
    return hex.EncodeToString([]byte(time.Now().String()))[:16]
}
```

## Integration

The result validation system integrates with:
- **Compute orchestrator**: Validates completed tasks
- **Reputation system**: Updates node reputations
- **Payment system**: Triggers payments for valid results
- **Network layer**: Communicates with validators
- **Storage system**: Stores validation records and evidence

## Security Considerations

1. **Sybil attacks**: Use reputation and stake requirements
2. **Collusion**: Random validator selection and monitoring
3. **Result manipulation**: Cryptographic verification
4. **Dispute spam**: Require stake for dispute initiation
5. **Evidence tampering**: Immutable evidence storage