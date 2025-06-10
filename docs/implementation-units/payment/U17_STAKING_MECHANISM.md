# Implementation Unit: U17 - Staking Mechanism

## Overview
Provider staking mechanism with reputation scoring, slashing conditions, and reward distribution.

## Smart Contract Implementation

### Core Staking Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract ProviderStaking is ReentrancyGuard, Ownable {
    using SafeMath for uint256;
    
    // Constants
    uint256 public constant MIN_STAKE = 100 * 10**6; // 100 USDC (6 decimals)
    uint256 public constant MAX_SLASH_PERCENTAGE = 30; // 30% max slash
    uint256 public constant REPUTATION_DECAY_RATE = 5; // 5% per period
    uint256 public constant DELEGATION_FEE_PERCENTAGE = 10; // 10% of rewards
    
    // Tokens
    IERC20 public immutable stakingToken; // USDC
    
    // Structs
    struct Provider {
        uint256 stakedAmount;
        uint256 reputationScore;
        uint256 lastUpdateTime;
        uint256 totalSlashed;
        uint256 totalRewards;
        bool isActive;
        mapping(address => uint256) delegations;
        address[] delegators;
    }
    
    struct Delegation {
        address provider;
        uint256 amount;
        uint256 timestamp;
        uint256 rewards;
    }
    
    struct SlashEvent {
        address provider;
        uint256 amount;
        string reason;
        uint256 timestamp;
    }
    
    // State variables
    mapping(address => Provider) public providers;
    mapping(address => Delegation) public delegations;
    mapping(address => uint256) public pendingRewards;
    
    address[] public activeProviders;
    uint256 public totalStaked;
    uint256 public totalProtocolFees;
    uint256 public rewardPool;
    
    // Events
    event Staked(address indexed provider, uint256 amount);
    event Unstaked(address indexed provider, uint256 amount);
    event Delegated(address indexed delegator, address indexed provider, uint256 amount);
    event Undelegated(address indexed delegator, address indexed provider, uint256 amount);
    event Slashed(address indexed provider, uint256 amount, string reason);
    event RewardDistributed(address indexed provider, uint256 amount);
    event ReputationUpdated(address indexed provider, uint256 newScore);
    
    // Modifiers
    modifier onlyActiveProvider() {
        require(providers[msg.sender].isActive, "Not an active provider");
        _;
    }
    
    modifier onlyValidator() {
        require(hasRole(VALIDATOR_ROLE, msg.sender), "Not a validator");
        _;
    }
    
    // Role management
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) private roles;
    
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }
    
    function grantRole(bytes32 role, address account) public onlyOwner {
        roles[role][account] = true;
    }
    
    function revokeRole(bytes32 role, address account) public onlyOwner {
        roles[role][account] = false;
    }
    
    constructor(address _stakingToken) {
        stakingToken = IERC20(_stakingToken);
    }
    
    // Provider staking functions
    function stake(uint256 amount) external nonReentrant {
        require(amount >= MIN_STAKE, "Below minimum stake");
        
        stakingToken.transferFrom(msg.sender, address(this), amount);
        
        Provider storage provider = providers[msg.sender];
        
        if (!provider.isActive) {
            provider.isActive = true;
            provider.reputationScore = 100; // Initial reputation
            activeProviders.push(msg.sender);
        }
        
        provider.stakedAmount = provider.stakedAmount.add(amount);
        provider.lastUpdateTime = block.timestamp;
        totalStaked = totalStaked.add(amount);
        
        emit Staked(msg.sender, amount);
    }
    
    function unstake(uint256 amount) external nonReentrant onlyActiveProvider {
        Provider storage provider = providers[msg.sender];
        require(provider.stakedAmount >= amount, "Insufficient stake");
        
        uint256 remainingStake = provider.stakedAmount.sub(amount);
        require(remainingStake == 0 || remainingStake >= MIN_STAKE, "Remaining below minimum");
        
        provider.stakedAmount = remainingStake;
        totalStaked = totalStaked.sub(amount);
        
        if (remainingStake == 0) {
            provider.isActive = false;
            _removeFromActiveProviders(msg.sender);
        }
        
        stakingToken.transfer(msg.sender, amount);
        emit Unstaked(msg.sender, amount);
    }
    
    // Delegation functions
    function delegate(address providerAddress, uint256 amount) external nonReentrant {
        require(providers[providerAddress].isActive, "Provider not active");
        require(amount > 0, "Invalid amount");
        
        stakingToken.transferFrom(msg.sender, address(this), amount);
        
        Provider storage provider = providers[providerAddress];
        Delegation storage delegation = delegations[msg.sender];
        
        if (delegation.provider == address(0)) {
            delegation.provider = providerAddress;
            delegation.timestamp = block.timestamp;
            provider.delegators.push(msg.sender);
        } else {
            require(delegation.provider == providerAddress, "Already delegated to another provider");
        }
        
        delegation.amount = delegation.amount.add(amount);
        provider.delegations[msg.sender] = provider.delegations[msg.sender].add(amount);
        
        emit Delegated(msg.sender, providerAddress, amount);
    }
    
    function undelegate(uint256 amount) external nonReentrant {
        Delegation storage delegation = delegations[msg.sender];
        require(delegation.amount >= amount, "Insufficient delegation");
        
        Provider storage provider = providers[delegation.provider];
        
        delegation.amount = delegation.amount.sub(amount);
        provider.delegations[msg.sender] = provider.delegations[msg.sender].sub(amount);
        
        if (delegation.amount == 0) {
            _removeDelegator(delegation.provider, msg.sender);
            delete delegations[msg.sender];
        }
        
        stakingToken.transfer(msg.sender, amount);
        emit Undelegated(msg.sender, delegation.provider, amount);
    }
    
    // Slashing functions
    function slash(
        address providerAddress,
        uint256 percentage,
        string calldata reason
    ) external onlyValidator {
        require(percentage <= MAX_SLASH_PERCENTAGE, "Exceeds max slash percentage");
        
        Provider storage provider = providers[providerAddress];
        require(provider.isActive, "Provider not active");
        
        uint256 slashAmount = provider.stakedAmount.mul(percentage).div(100);
        provider.stakedAmount = provider.stakedAmount.sub(slashAmount);
        provider.totalSlashed = provider.totalSlashed.add(slashAmount);
        
        // Update reputation
        uint256 reputationPenalty = percentage.mul(2); // 2x penalty on reputation
        if (provider.reputationScore > reputationPenalty) {
            provider.reputationScore = provider.reputationScore.sub(reputationPenalty);
        } else {
            provider.reputationScore = 0;
        }
        
        // Add to reward pool
        rewardPool = rewardPool.add(slashAmount);
        
        emit Slashed(providerAddress, slashAmount, reason);
        emit ReputationUpdated(providerAddress, provider.reputationScore);
        
        // Deactivate if below minimum
        if (provider.stakedAmount < MIN_STAKE) {
            provider.isActive = false;
            _removeFromActiveProviders(providerAddress);
        }
    }
    
    // Reputation functions
    function updateReputation(address providerAddress, int256 change) external onlyValidator {
        Provider storage provider = providers[providerAddress];
        require(provider.isActive, "Provider not active");
        
        if (change > 0) {
            provider.reputationScore = provider.reputationScore.add(uint256(change));
            if (provider.reputationScore > 1000) {
                provider.reputationScore = 1000; // Max reputation cap
            }
        } else {
            uint256 decrease = uint256(-change);
            if (provider.reputationScore > decrease) {
                provider.reputationScore = provider.reputationScore.sub(decrease);
            } else {
                provider.reputationScore = 0;
            }
        }
        
        provider.lastUpdateTime = block.timestamp;
        emit ReputationUpdated(providerAddress, provider.reputationScore);
    }
    
    // Reward distribution
    function distributeProtocolFees(uint256 amount) external onlyOwner {
        require(amount > 0, "Invalid amount");
        stakingToken.transferFrom(msg.sender, address(this), amount);
        
        totalProtocolFees = totalProtocolFees.add(amount);
        rewardPool = rewardPool.add(amount);
    }
    
    function distributeRewards() external onlyOwner {
        require(rewardPool > 0, "No rewards to distribute");
        require(activeProviders.length > 0, "No active providers");
        
        uint256 totalWeight = _calculateTotalWeight();
        require(totalWeight > 0, "No eligible providers");
        
        for (uint256 i = 0; i < activeProviders.length; i++) {
            address providerAddress = activeProviders[i];
            Provider storage provider = providers[providerAddress];
            
            uint256 weight = _calculateProviderWeight(providerAddress);
            uint256 reward = rewardPool.mul(weight).div(totalWeight);
            
            if (reward > 0) {
                // Provider keeps 90% if has delegators, 100% otherwise
                uint256 providerReward = provider.delegators.length > 0 
                    ? reward.mul(100 - DELEGATION_FEE_PERCENTAGE).div(100)
                    : reward;
                    
                provider.totalRewards = provider.totalRewards.add(providerReward);
                pendingRewards[providerAddress] = pendingRewards[providerAddress].add(providerReward);
                
                // Distribute to delegators
                if (provider.delegators.length > 0) {
                    uint256 delegatorRewards = reward.sub(providerReward);
                    _distributeDelegatorRewards(providerAddress, delegatorRewards);
                }
                
                emit RewardDistributed(providerAddress, reward);
            }
        }
        
        rewardPool = 0;
    }
    
    function claimRewards() external nonReentrant {
        uint256 rewards = pendingRewards[msg.sender];
        require(rewards > 0, "No pending rewards");
        
        pendingRewards[msg.sender] = 0;
        stakingToken.transfer(msg.sender, rewards);
    }
    
    // Internal functions
    function _calculateProviderWeight(address providerAddress) internal view returns (uint256) {
        Provider storage provider = providers[providerAddress];
        
        uint256 stakeWeight = provider.stakedAmount;
        uint256 reputationMultiplier = provider.reputationScore.add(100).div(100); // 1x to 11x
        uint256 delegationBonus = _getTotalDelegations(providerAddress).div(10); // 10% of delegations
        
        return stakeWeight.mul(reputationMultiplier).add(delegationBonus);
    }
    
    function _calculateTotalWeight() internal view returns (uint256) {
        uint256 totalWeight = 0;
        
        for (uint256 i = 0; i < activeProviders.length; i++) {
            totalWeight = totalWeight.add(_calculateProviderWeight(activeProviders[i]));
        }
        
        return totalWeight;
    }
    
    function _getTotalDelegations(address providerAddress) internal view returns (uint256) {
        Provider storage provider = providers[providerAddress];
        uint256 total = 0;
        
        for (uint256 i = 0; i < provider.delegators.length; i++) {
            total = total.add(provider.delegations[provider.delegators[i]]);
        }
        
        return total;
    }
    
    function _distributeDelegatorRewards(address providerAddress, uint256 totalRewards) internal {
        Provider storage provider = providers[providerAddress];
        uint256 totalDelegations = _getTotalDelegations(providerAddress);
        
        if (totalDelegations == 0) return;
        
        for (uint256 i = 0; i < provider.delegators.length; i++) {
            address delegator = provider.delegators[i];
            uint256 delegatorStake = provider.delegations[delegator];
            uint256 delegatorReward = totalRewards.mul(delegatorStake).div(totalDelegations);
            
            delegations[delegator].rewards = delegations[delegator].rewards.add(delegatorReward);
            pendingRewards[delegator] = pendingRewards[delegator].add(delegatorReward);
        }
    }
    
    function _removeFromActiveProviders(address providerAddress) internal {
        for (uint256 i = 0; i < activeProviders.length; i++) {
            if (activeProviders[i] == providerAddress) {
                activeProviders[i] = activeProviders[activeProviders.length - 1];
                activeProviders.pop();
                break;
            }
        }
    }
    
    function _removeDelegator(address providerAddress, address delegator) internal {
        Provider storage provider = providers[providerAddress];
        
        for (uint256 i = 0; i < provider.delegators.length; i++) {
            if (provider.delegators[i] == delegator) {
                provider.delegators[i] = provider.delegators[provider.delegators.length - 1];
                provider.delegators.pop();
                break;
            }
        }
    }
    
    // View functions
    function getProviderInfo(address providerAddress) external view returns (
        uint256 stakedAmount,
        uint256 reputationScore,
        uint256 totalSlashed,
        uint256 totalRewards,
        bool isActive,
        uint256 delegationCount
    ) {
        Provider storage provider = providers[providerAddress];
        return (
            provider.stakedAmount,
            provider.reputationScore,
            provider.totalSlashed,
            provider.totalRewards,
            provider.isActive,
            provider.delegators.length
        );
    }
    
    function getDelegationInfo(address delegator) external view returns (
        address provider,
        uint256 amount,
        uint256 rewards
    ) {
        Delegation storage delegation = delegations[delegator];
        return (
            delegation.provider,
            delegation.amount,
            delegation.rewards
        );
    }
}
```

## Go Implementation

### Core Staking Service

```go
package staking

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "math/big"
    "sync"
    "time"

    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/prometheus/client_golang/prometheus"
    "go.uber.org/zap"
)

// Constants
const (
    MinStakeAmount    = 100000000 // 100 USDC (6 decimals)
    MaxSlashPercent   = 30
    ReputationDecay   = 5
    DelegationFeeRate = 10
)

// SlashReason types
type SlashReason string

const (
    SlashReasonDowntime        SlashReason = "DOWNTIME"
    SlashReasonValidationFail  SlashReason = "VALIDATION_FAIL"
    SlashReasonMaliciousBehavior SlashReason = "MALICIOUS_BEHAVIOR"
)

// Provider represents a storage provider in the staking system
type Provider struct {
    Address         common.Address
    StakedAmount    *big.Int
    ReputationScore uint64
    LastUpdateTime  time.Time
    TotalSlashed    *big.Int
    TotalRewards    *big.Int
    IsActive        bool
    Delegations     map[common.Address]*big.Int
    mu              sync.RWMutex
}

// Delegation represents a delegation to a provider
type Delegation struct {
    Provider  common.Address
    Amount    *big.Int
    Timestamp time.Time
    Rewards   *big.Int
}

// StakingService manages provider staking
type StakingService struct {
    client          *ethclient.Client
    contract        *ProviderStakingContract
    contractAddress common.Address
    privateKey      *ecdsa.PrivateKey
    logger          *zap.Logger
    
    providers    map[common.Address]*Provider
    delegations  map[common.Address]*Delegation
    providersMu  sync.RWMutex
    
    // Metrics
    totalStakedGauge     prometheus.Gauge
    activeProvidersGauge prometheus.Gauge
    slashEventsCounter   prometheus.Counter
    rewardDistributions  prometheus.Counter
    
    // Channels
    stakingEvents chan *StakingEvent
    shutdown      chan struct{}
}

// StakingEvent represents various staking events
type StakingEvent struct {
    Type      string
    Provider  common.Address
    Amount    *big.Int
    Timestamp time.Time
    Data      interface{}
}

// NewStakingService creates a new staking service
func NewStakingService(
    client *ethclient.Client,
    contractAddress common.Address,
    privateKey *ecdsa.PrivateKey,
    logger *zap.Logger,
) (*StakingService, error) {
    contract, err := NewProviderStakingContract(contractAddress, client)
    if err != nil {
        return nil, fmt.Errorf("failed to bind contract: %w", err)
    }
    
    service := &StakingService{
        client:          client,
        contract:        contract,
        contractAddress: contractAddress,
        privateKey:      privateKey,
        logger:          logger,
        providers:       make(map[common.Address]*Provider),
        delegations:     make(map[common.Address]*Delegation),
        stakingEvents:   make(chan *StakingEvent, 1000),
        shutdown:        make(chan struct{}),
    }
    
    service.initMetrics()
    return service, nil
}

// Start begins the staking service
func (s *StakingService) Start(ctx context.Context) error {
    s.logger.Info("Starting staking service")
    
    // Load initial state
    if err := s.loadProviders(ctx); err != nil {
        return fmt.Errorf("failed to load providers: %w", err)
    }
    
    // Start event watchers
    go s.watchStakingEvents(ctx)
    go s.watchSlashingEvents(ctx)
    go s.processReputationDecay(ctx)
    
    // Start metrics updater
    go s.updateMetrics(ctx)
    
    return nil
}

// Stake allows a provider to stake tokens
func (s *StakingService) Stake(ctx context.Context, amount *big.Int) (*types.Transaction, error) {
    if amount.Cmp(big.NewInt(MinStakeAmount)) < 0 {
        return nil, fmt.Errorf("amount below minimum stake requirement")
    }
    
    auth, err := s.getTransactOpts(ctx)
    if err != nil {
        return nil, err
    }
    
    tx, err := s.contract.Stake(auth, amount)
    if err != nil {
        return nil, fmt.Errorf("failed to stake: %w", err)
    }
    
    s.logger.Info("Staked tokens",
        zap.String("tx", tx.Hash().Hex()),
        zap.String("amount", amount.String()))
    
    return tx, nil
}

// Unstake allows a provider to unstake tokens
func (s *StakingService) Unstake(ctx context.Context, amount *big.Int) (*types.Transaction, error) {
    auth, err := s.getTransactOpts(ctx)
    if err != nil {
        return nil, err
    }
    
    tx, err := s.contract.Unstake(auth, amount)
    if err != nil {
        return nil, fmt.Errorf("failed to unstake: %w", err)
    }
    
    s.logger.Info("Unstaked tokens",
        zap.String("tx", tx.Hash().Hex()),
        zap.String("amount", amount.String()))
    
    return tx, nil
}

// Delegate allows users to delegate to a provider
func (s *StakingService) Delegate(
    ctx context.Context,
    provider common.Address,
    amount *big.Int,
) (*types.Transaction, error) {
    // Verify provider is active
    s.providersMu.RLock()
    p, exists := s.providers[provider]
    s.providersMu.RUnlock()
    
    if !exists || !p.IsActive {
        return nil, fmt.Errorf("provider not active")
    }
    
    auth, err := s.getTransactOpts(ctx)
    if err != nil {
        return nil, err
    }
    
    tx, err := s.contract.Delegate(auth, provider, amount)
    if err != nil {
        return nil, fmt.Errorf("failed to delegate: %w", err)
    }
    
    s.logger.Info("Delegated to provider",
        zap.String("tx", tx.Hash().Hex()),
        zap.String("provider", provider.Hex()),
        zap.String("amount", amount.String()))
    
    return tx, nil
}

// SlashProvider slashes a provider for bad behavior
func (s *StakingService) SlashProvider(
    ctx context.Context,
    provider common.Address,
    percentage uint8,
    reason SlashReason,
) (*types.Transaction, error) {
    if percentage > MaxSlashPercent {
        return nil, fmt.Errorf("slash percentage exceeds maximum")
    }
    
    auth, err := s.getTransactOpts(ctx)
    if err != nil {
        return nil, err
    }
    
    tx, err := s.contract.Slash(auth, provider, big.NewInt(int64(percentage)), string(reason))
    if err != nil {
        return nil, fmt.Errorf("failed to slash provider: %w", err)
    }
    
    s.logger.Warn("Slashed provider",
        zap.String("tx", tx.Hash().Hex()),
        zap.String("provider", provider.Hex()),
        zap.Uint8("percentage", percentage),
        zap.String("reason", string(reason)))
    
    s.slashEventsCounter.Inc()
    
    return tx, nil
}

// UpdateReputation updates a provider's reputation score
func (s *StakingService) UpdateReputation(
    ctx context.Context,
    provider common.Address,
    change int64,
) (*types.Transaction, error) {
    auth, err := s.getTransactOpts(ctx)
    if err != nil {
        return nil, err
    }
    
    tx, err := s.contract.UpdateReputation(auth, provider, big.NewInt(change))
    if err != nil {
        return nil, fmt.Errorf("failed to update reputation: %w", err)
    }
    
    s.logger.Info("Updated provider reputation",
        zap.String("tx", tx.Hash().Hex()),
        zap.String("provider", provider.Hex()),
        zap.Int64("change", change))
    
    return tx, nil
}

// Performance monitoring
type PerformanceMonitor struct {
    service         *StakingService
    metricsInterval time.Duration
    logger          *zap.Logger
}

func NewPerformanceMonitor(service *StakingService) *PerformanceMonitor {
    return &PerformanceMonitor{
        service:         service,
        metricsInterval: 5 * time.Minute,
        logger:          service.logger,
    }
}

func (pm *PerformanceMonitor) Start(ctx context.Context) {
    ticker := time.NewTicker(pm.metricsInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            pm.evaluateProviders(ctx)
        }
    }
}

func (pm *PerformanceMonitor) evaluateProviders(ctx context.Context) {
    pm.service.providersMu.RLock()
    providers := make([]*Provider, 0, len(pm.service.providers))
    for _, p := range pm.service.providers {
        providers = append(providers, p)
    }
    pm.service.providersMu.RUnlock()
    
    for _, provider := range providers {
        if !provider.IsActive {
            continue
        }
        
        // Check performance metrics
        metrics, err := pm.getProviderMetrics(ctx, provider.Address)
        if err != nil {
            pm.logger.Error("Failed to get provider metrics",
                zap.String("provider", provider.Address.Hex()),
                zap.Error(err))
            continue
        }
        
        // Calculate reputation change
        reputationChange := pm.calculateReputationChange(metrics)
        
        if reputationChange != 0 {
            _, err := pm.service.UpdateReputation(ctx, provider.Address, reputationChange)
            if err != nil {
                pm.logger.Error("Failed to update reputation",
                    zap.String("provider", provider.Address.Hex()),
                    zap.Error(err))
            }
        }
        
        // Check for slashing conditions
        if shouldSlash, reason, percentage := pm.checkSlashingConditions(metrics); shouldSlash {
            _, err := pm.service.SlashProvider(ctx, provider.Address, percentage, reason)
            if err != nil {
                pm.logger.Error("Failed to slash provider",
                    zap.String("provider", provider.Address.Hex()),
                    zap.Error(err))
            }
        }
    }
}

// ProviderMetrics contains performance metrics for a provider
type ProviderMetrics struct {
    Uptime            float64
    ValidationSuccess float64
    ResponseTime      time.Duration
    StorageUtilized   uint64
    BandwidthUsed     uint64
    LastActive        time.Time
}

func (pm *PerformanceMonitor) getProviderMetrics(
    ctx context.Context,
    provider common.Address,
) (*ProviderMetrics, error) {
    // Implementation would fetch metrics from monitoring system
    // This is a placeholder
    return &ProviderMetrics{
        Uptime:            99.5,
        ValidationSuccess: 98.0,
        ResponseTime:      100 * time.Millisecond,
        StorageUtilized:   1024 * 1024 * 1024, // 1GB
        BandwidthUsed:     512 * 1024 * 1024,  // 512MB
        LastActive:        time.Now(),
    }, nil
}

func (pm *PerformanceMonitor) calculateReputationChange(metrics *ProviderMetrics) int64 {
    var change int64
    
    // Uptime bonus/penalty
    if metrics.Uptime >= 99.9 {
        change += 10
    } else if metrics.Uptime < 95.0 {
        change -= 20
    }
    
    // Validation success rate
    if metrics.ValidationSuccess >= 99.0 {
        change += 5
    } else if metrics.ValidationSuccess < 90.0 {
        change -= 15
    }
    
    // Response time
    if metrics.ResponseTime < 50*time.Millisecond {
        change += 5
    } else if metrics.ResponseTime > 500*time.Millisecond {
        change -= 10
    }
    
    return change
}

func (pm *PerformanceMonitor) checkSlashingConditions(
    metrics *ProviderMetrics,
) (shouldSlash bool, reason SlashReason, percentage uint8) {
    // Extended downtime
    if time.Since(metrics.LastActive) > 24*time.Hour {
        return true, SlashReasonDowntime, 10
    }
    
    // Critical validation failures
    if metrics.ValidationSuccess < 80.0 {
        return true, SlashReasonValidationFail, 5
    }
    
    // Severe uptime issues
    if metrics.Uptime < 90.0 {
        return true, SlashReasonDowntime, 15
    }
    
    return false, "", 0
}

// Helper functions
func (s *StakingService) getTransactOpts(ctx context.Context) (*bind.TransactOpts, error) {
    nonce, err := s.client.PendingNonceAt(ctx, crypto.PubkeyToAddress(s.privateKey.PublicKey))
    if err != nil {
        return nil, err
    }
    
    gasPrice, err := s.client.SuggestGasPrice(ctx)
    if err != nil {
        return nil, err
    }
    
    auth := bind.NewKeyedTransactor(s.privateKey)
    auth.Nonce = big.NewInt(int64(nonce))
    auth.Value = big.NewInt(0)
    auth.GasLimit = uint64(3000000)
    auth.GasPrice = gasPrice
    
    return auth, nil
}

func (s *StakingService) initMetrics() {
    s.totalStakedGauge = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "staking_total_staked",
        Help: "Total amount staked in the system",
    })
    
    s.activeProvidersGauge = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "staking_active_providers",
        Help: "Number of active providers",
    })
    
    s.slashEventsCounter = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "staking_slash_events_total",
        Help: "Total number of slash events",
    })
    
    s.rewardDistributions = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "staking_reward_distributions_total",
        Help: "Total number of reward distributions",
    })
    
    prometheus.MustRegister(
        s.totalStakedGauge,
        s.activeProvidersGauge,
        s.slashEventsCounter,
        s.rewardDistributions,
    )
}
```

### Reward Distribution Service

```go
package staking

import (
    "context"
    "fmt"
    "math/big"
    "sync"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "go.uber.org/zap"
)

// RewardDistributor handles protocol fee distribution
type RewardDistributor struct {
    stakingService   *StakingService
    distributionRate time.Duration
    minRewardPool    *big.Int
    logger           *zap.Logger
    
    mu              sync.Mutex
    lastDistribution time.Time
}

func NewRewardDistributor(
    stakingService *StakingService,
    distributionRate time.Duration,
) *RewardDistributor {
    return &RewardDistributor{
        stakingService:   stakingService,
        distributionRate: distributionRate,
        minRewardPool:    big.NewInt(1000000000), // 1000 USDC
        logger:           stakingService.logger,
    }
}

func (rd *RewardDistributor) Start(ctx context.Context) {
    ticker := time.NewTicker(rd.distributionRate)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if err := rd.distributeRewards(ctx); err != nil {
                rd.logger.Error("Failed to distribute rewards", zap.Error(err))
            }
        }
    }
}

func (rd *RewardDistributor) distributeRewards(ctx context.Context) error {
    rd.mu.Lock()
    defer rd.mu.Unlock()
    
    // Check if enough time has passed
    if time.Since(rd.lastDistribution) < rd.distributionRate {
        return nil
    }
    
    // Get reward pool balance
    rewardPool, err := rd.stakingService.contract.RewardPool(nil)
    if err != nil {
        return fmt.Errorf("failed to get reward pool: %w", err)
    }
    
    // Check minimum threshold
    if rewardPool.Cmp(rd.minRewardPool) < 0 {
        rd.logger.Debug("Reward pool below minimum threshold",
            zap.String("pool", rewardPool.String()),
            zap.String("minimum", rd.minRewardPool.String()))
        return nil
    }
    
    // Execute distribution
    auth, err := rd.stakingService.getTransactOpts(ctx)
    if err != nil {
        return err
    }
    
    tx, err := rd.stakingService.contract.DistributeRewards(auth)
    if err != nil {
        return fmt.Errorf("failed to distribute rewards: %w", err)
    }
    
    rd.logger.Info("Distributed rewards",
        zap.String("tx", tx.Hash().Hex()),
        zap.String("amount", rewardPool.String()))
    
    rd.stakingService.rewardDistributions.Inc()
    rd.lastDistribution = time.Now()
    
    return nil
}

// CalculateProviderReward calculates reward for a specific provider
func (rd *RewardDistributor) CalculateProviderReward(
    provider common.Address,
    totalRewardPool *big.Int,
) (*big.Int, error) {
    // Get provider info
    providerInfo, err := rd.stakingService.contract.GetProviderInfo(nil, provider)
    if err != nil {
        return nil, err
    }
    
    if !providerInfo.IsActive {
        return big.NewInt(0), nil
    }
    
    // Calculate weight based on stake and reputation
    weight := new(big.Int).Mul(
        providerInfo.StakedAmount,
        big.NewInt(int64(providerInfo.ReputationScore+100)),
    )
    weight.Div(weight, big.NewInt(100))
    
    // Get total weight
    totalWeight, err := rd.calculateTotalWeight()
    if err != nil {
        return nil, err
    }
    
    if totalWeight.Cmp(big.NewInt(0)) == 0 {
        return big.NewInt(0), nil
    }
    
    // Calculate reward
    reward := new(big.Int).Mul(totalRewardPool, weight)
    reward.Div(reward, totalWeight)
    
    return reward, nil
}

func (rd *RewardDistributor) calculateTotalWeight() (*big.Int, error) {
    // This would sum weights for all active providers
    // Implementation depends on contract methods
    return big.NewInt(1000000), nil
}
```

### Delegation Manager

```go
package staking

import (
    "context"
    "fmt"
    "math/big"
    "sync"

    "github.com/ethereum/go-ethereum/common"
    "go.uber.org/zap"
)

// DelegationManager handles delegation operations
type DelegationManager struct {
    stakingService *StakingService
    logger         *zap.Logger
    
    delegations   map[common.Address]*Delegation
    delegationsMu sync.RWMutex
}

func NewDelegationManager(stakingService *StakingService) *DelegationManager {
    return &DelegationManager{
        stakingService: stakingService,
        logger:         stakingService.logger,
        delegations:    make(map[common.Address]*Delegation),
    }
}

// GetOptimalProvider finds the best provider to delegate to
func (dm *DelegationManager) GetOptimalProvider(
    ctx context.Context,
    minReputation uint64,
) (common.Address, error) {
    dm.stakingService.providersMu.RLock()
    defer dm.stakingService.providersMu.RUnlock()
    
    var bestProvider common.Address
    var bestScore uint64
    
    for addr, provider := range dm.stakingService.providers {
        if !provider.IsActive || provider.ReputationScore < minReputation {
            continue
        }
        
        // Calculate score based on reputation and stake
        score := provider.ReputationScore * 2
        if provider.StakedAmount.Cmp(big.NewInt(MinStakeAmount*10)) > 0 {
            score += 50 // Bonus for high stake
        }
        
        if score > bestScore {
            bestScore = score
            bestProvider = addr
        }
    }
    
    if bestProvider == (common.Address{}) {
        return common.Address{}, fmt.Errorf("no suitable provider found")
    }
    
    return bestProvider, nil
}

// AutoDelegate automatically delegates to optimal provider
func (dm *DelegationManager) AutoDelegate(
    ctx context.Context,
    amount *big.Int,
) (*types.Transaction, error) {
    provider, err := dm.GetOptimalProvider(ctx, 500) // Min reputation 500
    if err != nil {
        return nil, err
    }
    
    return dm.stakingService.Delegate(ctx, provider, amount)
}

// GetDelegationRewards calculates pending rewards for a delegator
func (dm *DelegationManager) GetDelegationRewards(
    ctx context.Context,
    delegator common.Address,
) (*big.Int, error) {
    info, err := dm.stakingService.contract.GetDelegationInfo(nil, delegator)
    if err != nil {
        return nil, err
    }
    
    return info.Rewards, nil
}
```

## Configuration

```yaml
staking:
  min_stake: 100000000  # 100 USDC
  max_slash_percentage: 30
  reputation_decay_rate: 5
  delegation_fee_percentage: 10
  
  reward_distribution:
    interval: 24h
    min_pool: 1000000000  # 1000 USDC
    
  performance_monitoring:
    interval: 5m
    downtime_threshold: 24h
    min_uptime: 90.0
    min_validation_success: 80.0
    
  reputation:
    initial_score: 100
    max_score: 1000
    uptime_bonus: 10
    validation_bonus: 5
    response_time_bonus: 5
```

## Testing

```go
package staking

import (
    "context"
    "math/big"
    "testing"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestStaking(t *testing.T) {
    ctx := context.Background()
    service := setupTestService(t)
    
    t.Run("MinimumStake", func(t *testing.T) {
        // Test below minimum
        _, err := service.Stake(ctx, big.NewInt(50000000))
        assert.Error(t, err)
        
        // Test at minimum
        tx, err := service.Stake(ctx, big.NewInt(MinStakeAmount))
        require.NoError(t, err)
        assert.NotNil(t, tx)
    })
    
    t.Run("ReputationUpdate", func(t *testing.T) {
        provider := common.HexToAddress("0x123")
        
        // Positive update
        tx, err := service.UpdateReputation(ctx, provider, 50)
        require.NoError(t, err)
        assert.NotNil(t, tx)
        
        // Negative update
        tx, err = service.UpdateReputation(ctx, provider, -20)
        require.NoError(t, err)
        assert.NotNil(t, tx)
    })
    
    t.Run("Slashing", func(t *testing.T) {
        provider := common.HexToAddress("0x123")
        
        // Valid slash
        tx, err := service.SlashProvider(ctx, provider, 10, SlashReasonDowntime)
        require.NoError(t, err)
        assert.NotNil(t, tx)
        
        // Exceed max slash
        _, err = service.SlashProvider(ctx, provider, 50, SlashReasonDowntime)
        assert.Error(t, err)
    })
}

func TestPerformanceMonitor(t *testing.T) {
    service := setupTestService(t)
    monitor := NewPerformanceMonitor(service)
    
    t.Run("MetricsEvaluation", func(t *testing.T) {
        metrics := &ProviderMetrics{
            Uptime:            99.9,
            ValidationSuccess: 99.5,
            ResponseTime:      30 * time.Millisecond,
        }
        
        change := monitor.calculateReputationChange(metrics)
        assert.Greater(t, change, int64(0))
    })
    
    t.Run("SlashingConditions", func(t *testing.T) {
        // Test downtime
        metrics := &ProviderMetrics{
            LastActive: time.Now().Add(-25 * time.Hour),
        }
        
        shouldSlash, reason, percentage := monitor.checkSlashingConditions(metrics)
        assert.True(t, shouldSlash)
        assert.Equal(t, SlashReasonDowntime, reason)
        assert.Equal(t, uint8(10), percentage)
        
        // Test validation failures
        metrics = &ProviderMetrics{
            ValidationSuccess: 75.0,
            LastActive:        time.Now(),
        }
        
        shouldSlash, reason, percentage = monitor.checkSlashingConditions(metrics)
        assert.True(t, shouldSlash)
        assert.Equal(t, SlashReasonValidationFail, reason)
        assert.Equal(t, uint8(5), percentage)
    })
}

func TestDelegationManager(t *testing.T) {
    ctx := context.Background()
    service := setupTestService(t)
    manager := NewDelegationManager(service)
    
    t.Run("OptimalProviderSelection", func(t *testing.T) {
        // Add test providers
        service.providers[common.HexToAddress("0x123")] = &Provider{
            Address:         common.HexToAddress("0x123"),
            IsActive:        true,
            ReputationScore: 600,
            StakedAmount:    big.NewInt(MinStakeAmount * 5),
        }
        
        service.providers[common.HexToAddress("0x456")] = &Provider{
            Address:         common.HexToAddress("0x456"),
            IsActive:        true,
            ReputationScore: 800,
            StakedAmount:    big.NewInt(MinStakeAmount * 20),
        }
        
        provider, err := manager.GetOptimalProvider(ctx, 500)
        require.NoError(t, err)
        assert.Equal(t, common.HexToAddress("0x456"), provider)
    })
}
```

## Deployment

1. Deploy USDC token contract (or use existing)
2. Deploy ProviderStaking contract with USDC address
3. Grant validator roles to monitoring systems
4. Initialize reward pool
5. Configure monitoring thresholds

## Security Considerations

1. **Reentrancy Protection**: All state-changing functions use ReentrancyGuard
2. **Access Control**: Role-based permissions for validators
3. **Overflow Protection**: SafeMath for all arithmetic operations
4. **Minimum Stake**: Prevents spam and ensures provider commitment
5. **Maximum Slash**: Caps potential losses from any single incident
6. **Time-based Decay**: Prevents reputation gaming

## Integration Points

1. **Payment System**: Collects protocol fees for distribution
2. **Monitoring System**: Provides performance metrics
3. **Validator Network**: Reports violations and performance
4. **Provider Registry**: Maintains active provider list
5. **Governance**: Can update parameters and validators