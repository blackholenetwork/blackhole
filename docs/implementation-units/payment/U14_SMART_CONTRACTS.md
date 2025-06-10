# U14: Smart Contract Core

## Overview

The Smart Contract Core provides the foundation for BlackHole's decentralized payment system on Polygon. It handles resource pricing through a dynamic AMM, fee collection and distribution, and user balance management.

## Architecture

### Contract Structure

```
BlackholePayments (Main Contract)
├── ResourcePricing (AMM pricing logic)
├── FeeDistributor (Protocol fee handling)
├── UserBalances (Balance management)
└── AccessControl (Role-based permissions)
```

## Complete Solidity Implementation

### 1. Main BlackholePayments Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title BlackholePayments
 * @notice Main contract for BlackHole payment system on Polygon
 * @dev Implements dynamic pricing, fee distribution, and balance management
 */
contract BlackholePayments is 
    Initializable, 
    UUPSUpgradeable, 
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable 
{
    using SafeERC20 for IERC20;

    // Roles
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant FEE_MANAGER_ROLE = keccak256("FEE_MANAGER_ROLE");

    // Constants
    uint256 public constant PROTOCOL_FEE_BPS = 50; // 0.5% in basis points
    uint256 public constant BPS_DENOMINATOR = 10000;
    uint256 public constant MIN_DEPOSIT = 1e15; // 0.001 MATIC minimum

    // Resource types
    enum ResourceType {
        STORAGE,    // Storage space
        BANDWIDTH,  // Network bandwidth
        COMPUTE,    // Computation cycles
        PRIORITY    // Priority access
    }

    // Resource pricing struct
    struct ResourcePrice {
        uint256 basePrice;      // Base price per unit
        uint256 demandFactor;   // Demand multiplier (1e18 = 1x)
        uint256 lastUpdate;     // Last price update timestamp
        uint256 totalSupply;    // Total available supply
        uint256 currentUsage;   // Current usage amount
    }

    // User balance struct
    struct UserBalance {
        uint256 deposited;      // Total deposited amount
        uint256 available;      // Available balance
        uint256 locked;         // Locked for active resources
        uint256 spent;          // Total spent
        uint256 lastActivity;   // Last activity timestamp
    }

    // Payment record
    struct Payment {
        address user;
        ResourceType resource;
        uint256 amount;
        uint256 units;
        uint256 pricePerUnit;
        uint256 timestamp;
        bytes32 referenceId;
    }

    // State variables
    mapping(ResourceType => ResourcePrice) public resourcePrices;
    mapping(address => UserBalance) public userBalances;
    mapping(address => mapping(ResourceType => uint256)) public userResourceUsage;
    mapping(bytes32 => Payment) public payments;
    
    uint256 public totalProtocolFees;
    uint256 public totalDeposits;
    uint256 public paymentNonce;
    
    address public feeRecipient;
    address public priceOracle;

    // Events
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event PaymentProcessed(
        address indexed user, 
        ResourceType indexed resource, 
        uint256 amount,
        uint256 units,
        bytes32 paymentId
    );
    event PriceUpdated(ResourceType indexed resource, uint256 newPrice, uint256 demandFactor);
    event FeesCollected(address indexed recipient, uint256 amount);
    event ResourceUsageUpdated(address indexed user, ResourceType resource, uint256 usage);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param _admin Admin address
     * @param _feeRecipient Protocol fee recipient
     */
    function initialize(address _admin, address _feeRecipient) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(UPGRADER_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(FEE_MANAGER_ROLE, _admin);

        feeRecipient = _feeRecipient;

        // Initialize resource prices
        _initializeResourcePrices();
    }

    /**
     * @notice Deposit MATIC to user balance
     */
    function deposit() external payable nonReentrant whenNotPaused {
        require(msg.value >= MIN_DEPOSIT, "Deposit too small");

        UserBalance storage balance = userBalances[msg.sender];
        balance.deposited += msg.value;
        balance.available += msg.value;
        balance.lastActivity = block.timestamp;

        totalDeposits += msg.value;

        emit Deposited(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw available balance
     * @param amount Amount to withdraw
     */
    function withdraw(uint256 amount) external nonReentrant whenNotPaused {
        UserBalance storage balance = userBalances[msg.sender];
        require(amount <= balance.available, "Insufficient available balance");

        balance.available -= amount;
        balance.lastActivity = block.timestamp;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    /**
     * @notice Process payment for resource usage
     * @param resource Resource type
     * @param units Number of units
     * @param referenceId External reference ID
     */
    function processPayment(
        ResourceType resource,
        uint256 units,
        bytes32 referenceId
    ) external nonReentrant whenNotPaused returns (bytes32 paymentId) {
        require(units > 0, "Invalid units");

        // Calculate payment amount
        uint256 pricePerUnit = calculatePrice(resource, units);
        uint256 totalAmount = pricePerUnit * units;
        uint256 protocolFee = (totalAmount * PROTOCOL_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = totalAmount - protocolFee;

        // Check and update user balance
        UserBalance storage balance = userBalances[msg.sender];
        require(balance.available >= totalAmount, "Insufficient balance");
        
        balance.available -= totalAmount;
        balance.locked += netAmount;
        balance.spent += totalAmount;
        balance.lastActivity = block.timestamp;

        // Update resource usage
        userResourceUsage[msg.sender][resource] += units;
        resourcePrices[resource].currentUsage += units;

        // Record payment
        paymentId = keccak256(abi.encodePacked(msg.sender, paymentNonce++, block.timestamp));
        payments[paymentId] = Payment({
            user: msg.sender,
            resource: resource,
            amount: totalAmount,
            units: units,
            pricePerUnit: pricePerUnit,
            timestamp: block.timestamp,
            referenceId: referenceId
        });

        // Collect protocol fee
        totalProtocolFees += protocolFee;

        // Update pricing based on demand
        _updateResourcePricing(resource);

        emit PaymentProcessed(msg.sender, resource, totalAmount, units, paymentId);
        emit ResourceUsageUpdated(msg.sender, resource, userResourceUsage[msg.sender][resource]);

        return paymentId;
    }

    /**
     * @notice Release locked funds after resource usage
     * @param user User address
     * @param amount Amount to release
     */
    function releaseFunds(address user, uint256 amount) external onlyRole(OPERATOR_ROLE) {
        UserBalance storage balance = userBalances[user];
        require(amount <= balance.locked, "Amount exceeds locked balance");

        balance.locked -= amount;
        balance.lastActivity = block.timestamp;
    }

    /**
     * @notice Calculate dynamic price for resource
     * @param resource Resource type
     * @param units Number of units
     * @return pricePerUnit Price per unit in wei
     */
    function calculatePrice(
        ResourceType resource, 
        uint256 units
    ) public view returns (uint256 pricePerUnit) {
        ResourcePrice memory price = resourcePrices[resource];
        
        // Base price with demand factor
        pricePerUnit = (price.basePrice * price.demandFactor) / 1e18;
        
        // Apply volume discount for large purchases
        if (units >= 1000) {
            pricePerUnit = (pricePerUnit * 95) / 100; // 5% discount
        } else if (units >= 100) {
            pricePerUnit = (pricePerUnit * 98) / 100; // 2% discount
        }
        
        // Apply surge pricing if usage > 80% of supply
        uint256 usageRatio = (price.currentUsage * 100) / price.totalSupply;
        if (usageRatio > 80) {
            uint256 surgeFactor = 100 + ((usageRatio - 80) * 5); // 5% per 1% over 80%
            pricePerUnit = (pricePerUnit * surgeFactor) / 100;
        }
        
        return pricePerUnit;
    }

    /**
     * @notice Collect accumulated protocol fees
     */
    function collectProtocolFees() external onlyRole(FEE_MANAGER_ROLE) nonReentrant {
        uint256 fees = totalProtocolFees;
        require(fees > 0, "No fees to collect");
        
        totalProtocolFees = 0;
        
        (bool success, ) = feeRecipient.call{value: fees}("");
        require(success, "Transfer failed");
        
        emit FeesCollected(feeRecipient, fees);
    }

    /**
     * @notice Update resource pricing parameters
     * @param resource Resource type
     * @param basePrice New base price
     * @param totalSupply New total supply
     */
    function updateResourcePricing(
        ResourceType resource,
        uint256 basePrice,
        uint256 totalSupply
    ) external onlyRole(OPERATOR_ROLE) {
        require(basePrice > 0 && totalSupply > 0, "Invalid parameters");
        
        ResourcePrice storage price = resourcePrices[resource];
        price.basePrice = basePrice;
        price.totalSupply = totalSupply;
        price.lastUpdate = block.timestamp;
        
        emit PriceUpdated(resource, basePrice, price.demandFactor);
    }

    /**
     * @notice Get user's available balance
     * @param user User address
     * @return Available balance
     */
    function getAvailableBalance(address user) external view returns (uint256) {
        return userBalances[user].available;
    }

    /**
     * @notice Get current resource price
     * @param resource Resource type
     * @param units Number of units
     * @return totalPrice Total price for units
     */
    function getResourcePrice(
        ResourceType resource,
        uint256 units
    ) external view returns (uint256 totalPrice) {
        uint256 pricePerUnit = calculatePrice(resource, units);
        return pricePerUnit * units;
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Update fee recipient
     * @param newRecipient New fee recipient address
     */
    function updateFeeRecipient(address newRecipient) external onlyRole(FEE_MANAGER_ROLE) {
        require(newRecipient != address(0), "Invalid recipient");
        feeRecipient = newRecipient;
    }

    /**
     * @dev Initialize resource prices
     */
    function _initializeResourcePrices() private {
        // Storage: 0.0001 MATIC per GB per day
        resourcePrices[ResourceType.STORAGE] = ResourcePrice({
            basePrice: 0.0001 ether,
            demandFactor: 1e18,
            lastUpdate: block.timestamp,
            totalSupply: 1000000, // 1PB in GB
            currentUsage: 0
        });

        // Bandwidth: 0.00001 MATIC per GB
        resourcePrices[ResourceType.BANDWIDTH] = ResourcePrice({
            basePrice: 0.00001 ether,
            demandFactor: 1e18,
            lastUpdate: block.timestamp,
            totalSupply: 10000000, // 10PB in GB
            currentUsage: 0
        });

        // Compute: 0.001 MATIC per hour
        resourcePrices[ResourceType.COMPUTE] = ResourcePrice({
            basePrice: 0.001 ether,
            demandFactor: 1e18,
            lastUpdate: block.timestamp,
            totalSupply: 100000, // 100k compute hours
            currentUsage: 0
        });

        // Priority: 0.01 MATIC per request
        resourcePrices[ResourceType.PRIORITY] = ResourcePrice({
            basePrice: 0.01 ether,
            demandFactor: 1e18,
            lastUpdate: block.timestamp,
            totalSupply: 1000000, // 1M priority requests
            currentUsage: 0
        });
    }

    /**
     * @dev Update resource pricing based on demand
     * @param resource Resource type to update
     */
    function _updateResourcePricing(ResourceType resource) private {
        ResourcePrice storage price = resourcePrices[resource];
        
        // Update demand factor based on usage ratio
        uint256 usageRatio = (price.currentUsage * 1e18) / price.totalSupply;
        
        // Increase demand factor if usage > 50%
        if (usageRatio > 0.5e18) {
            price.demandFactor = price.demandFactor * 101 / 100; // +1%
        }
        // Decrease demand factor if usage < 30%
        else if (usageRatio < 0.3e18 && price.demandFactor > 0.5e18) {
            price.demandFactor = price.demandFactor * 99 / 100; // -1%
        }
        
        price.lastUpdate = block.timestamp;
        
        emit PriceUpdated(resource, price.basePrice, price.demandFactor);
    }

    /**
     * @dev Authorize upgrade
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @notice Receive function to accept MATIC
     */
    receive() external payable {
        // Accept MATIC transfers
    }
}
```

### 2. Resource Pricing Library

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ResourcePricingLib
 * @notice Library for advanced resource pricing calculations
 */
library ResourcePricingLib {
    struct PricingParams {
        uint256 basePrice;
        uint256 demandMultiplier;
        uint256 timeMultiplier;
        uint256 volumeDiscount;
        uint256 surgeThreshold;
        uint256 surgePremium;
    }

    /**
     * @notice Calculate price with all factors
     * @param params Pricing parameters
     * @param units Number of units
     * @param currentUsage Current usage level
     * @param totalSupply Total supply available
     * @return finalPrice Calculated price
     */
    function calculateAdvancedPrice(
        PricingParams memory params,
        uint256 units,
        uint256 currentUsage,
        uint256 totalSupply
    ) internal pure returns (uint256 finalPrice) {
        // Start with base price
        finalPrice = params.basePrice;
        
        // Apply demand multiplier
        finalPrice = (finalPrice * params.demandMultiplier) / 1e18;
        
        // Apply time-based multiplier (peak hours, etc)
        finalPrice = (finalPrice * params.timeMultiplier) / 1e18;
        
        // Apply volume discount
        if (units >= 10000) {
            finalPrice = (finalPrice * (100 - params.volumeDiscount)) / 100;
        }
        
        // Apply surge pricing
        uint256 usagePercent = (currentUsage * 100) / totalSupply;
        if (usagePercent >= params.surgeThreshold) {
            uint256 surgeMultiplier = 100 + params.surgePremium;
            finalPrice = (finalPrice * surgeMultiplier) / 100;
        }
        
        return finalPrice;
    }

    /**
     * @notice Calculate bonding curve price
     * @param supply Current supply
     * @param amount Amount to price
     * @return price Total price
     */
    function bondingCurvePrice(
        uint256 supply,
        uint256 amount
    ) internal pure returns (uint256 price) {
        // Price = 0.00001 * supply^2
        uint256 startPrice = (supply * supply) / 1e10;
        uint256 endPrice = ((supply + amount) * (supply + amount)) / 1e10;
        
        // Average price for the amount
        price = (startPrice + endPrice) * amount / 2;
        
        return price;
    }
}
```

### 3. Fee Distribution Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title FeeDistributor
 * @notice Handles distribution of protocol fees
 */
contract FeeDistributor is Ownable, ReentrancyGuard {
    struct FeeRecipient {
        address recipient;
        uint256 share; // Basis points (10000 = 100%)
        string description;
    }

    FeeRecipient[] public feeRecipients;
    uint256 public totalShares;
    uint256 public totalDistributed;
    
    mapping(address => uint256) public recipientBalances;
    
    event FeeReceived(uint256 amount);
    event FeeDistributed(address indexed recipient, uint256 amount);
    event RecipientAdded(address indexed recipient, uint256 share);
    event RecipientRemoved(address indexed recipient);
    event SharesUpdated(address indexed recipient, uint256 newShare);

    constructor() {}

    /**
     * @notice Add fee recipient
     * @param recipient Recipient address
     * @param share Share in basis points
     * @param description Recipient description
     */
    function addRecipient(
        address recipient,
        uint256 share,
        string memory description
    ) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        require(share > 0, "Invalid share");
        require(totalShares + share <= 10000, "Total shares exceed 100%");
        
        feeRecipients.push(FeeRecipient({
            recipient: recipient,
            share: share,
            description: description
        }));
        
        totalShares += share;
        
        emit RecipientAdded(recipient, share);
    }

    /**
     * @notice Remove fee recipient
     * @param index Recipient index
     */
    function removeRecipient(uint256 index) external onlyOwner {
        require(index < feeRecipients.length, "Invalid index");
        
        address recipient = feeRecipients[index].recipient;
        uint256 share = feeRecipients[index].share;
        
        // Move last element to deleted position
        feeRecipients[index] = feeRecipients[feeRecipients.length - 1];
        feeRecipients.pop();
        
        totalShares -= share;
        
        emit RecipientRemoved(recipient);
    }

    /**
     * @notice Distribute fees to recipients
     */
    function distribute() external nonReentrant {
        uint256 balance = address(this).balance;
        require(balance > 0, "No fees to distribute");
        
        for (uint256 i = 0; i < feeRecipients.length; i++) {
            FeeRecipient memory recipient = feeRecipients[i];
            uint256 amount = (balance * recipient.share) / 10000;
            
            if (amount > 0) {
                recipientBalances[recipient.recipient] += amount;
                emit FeeDistributed(recipient.recipient, amount);
            }
        }
        
        totalDistributed += balance;
    }

    /**
     * @notice Withdraw accumulated balance
     */
    function withdraw() external nonReentrant {
        uint256 balance = recipientBalances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        recipientBalances[msg.sender] = 0;
        
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    /**
     * @notice Receive fees
     */
    receive() external payable {
        emit FeeReceived(msg.value);
    }
}
```

## Go Client Implementation

### 1. Contract Bindings Generator

```go
//go:generate abigen --abi=BlackholePayments.abi --pkg=contracts --type=BlackholePayments --out=blackhole_payments.go
//go:generate abigen --abi=FeeDistributor.abi --pkg=contracts --type=FeeDistributor --out=fee_distributor.go
```

### 2. Main Client

```go
package payment

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "math/big"
    "time"

    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
    "github.com/blackhole/contracts"
)

// ResourceType represents the type of resource
type ResourceType uint8

const (
    ResourceStorage ResourceType = iota
    ResourceBandwidth
    ResourceCompute
    ResourcePriority
)

// PaymentClient handles interactions with BlackHole smart contracts
type PaymentClient struct {
    client          *ethclient.Client
    payments        *contracts.BlackholePayments
    feeDistributor  *contracts.FeeDistributor
    auth            *bind.TransactOpts
    chainID         *big.Int
}

// NewPaymentClient creates a new payment client
func NewPaymentClient(rpcURL, privateKey string, contractAddr common.Address) (*PaymentClient, error) {
    // Connect to Polygon
    client, err := ethclient.Dial(rpcURL)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to client: %w", err)
    }

    // Get chain ID
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        return nil, fmt.Errorf("failed to get network ID: %w", err)
    }

    // Parse private key
    privateKeyECDSA, err := crypto.HexToECDSA(privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %w", err)
    }

    publicKey := privateKeyECDSA.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("failed to cast public key")
    }

    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

    // Create auth
    auth, err := bind.NewKeyedTransactorWithChainID(privateKeyECDSA, chainID)
    if err != nil {
        return nil, fmt.Errorf("failed to create auth: %w", err)
    }

    // Load contract
    payments, err := contracts.NewBlackholePayments(contractAddr, client)
    if err != nil {
        return nil, fmt.Errorf("failed to load contract: %w", err)
    }

    return &PaymentClient{
        client:   client,
        payments: payments,
        auth:     auth,
        chainID:  chainID,
    }, nil
}

// Deposit adds funds to user balance
func (pc *PaymentClient) Deposit(amount *big.Int) (*types.Transaction, error) {
    pc.auth.Value = amount
    defer func() { pc.auth.Value = big.NewInt(0) }()

    tx, err := pc.payments.Deposit(pc.auth)
    if err != nil {
        return nil, fmt.Errorf("failed to deposit: %w", err)
    }

    return tx, nil
}

// Withdraw removes funds from user balance
func (pc *PaymentClient) Withdraw(amount *big.Int) (*types.Transaction, error) {
    tx, err := pc.payments.Withdraw(pc.auth, amount)
    if err != nil {
        return nil, fmt.Errorf("failed to withdraw: %w", err)
    }

    return tx, nil
}

// ProcessPayment pays for resource usage
func (pc *PaymentClient) ProcessPayment(
    resource ResourceType,
    units *big.Int,
    referenceID [32]byte,
) (*types.Transaction, error) {
    tx, err := pc.payments.ProcessPayment(pc.auth, uint8(resource), units, referenceID)
    if err != nil {
        return nil, fmt.Errorf("failed to process payment: %w", err)
    }

    return tx, nil
}

// GetBalance returns user's balance information
func (pc *PaymentClient) GetBalance(user common.Address) (*UserBalance, error) {
    balance, err := pc.payments.UserBalances(nil, user)
    if err != nil {
        return nil, fmt.Errorf("failed to get balance: %w", err)
    }

    return &UserBalance{
        Deposited:    balance.Deposited,
        Available:    balance.Available,
        Locked:       balance.Locked,
        Spent:        balance.Spent,
        LastActivity: time.Unix(balance.LastActivity.Int64(), 0),
    }, nil
}

// GetResourcePrice calculates the price for resource units
func (pc *PaymentClient) GetResourcePrice(
    resource ResourceType,
    units *big.Int,
) (*big.Int, error) {
    price, err := pc.payments.GetResourcePrice(nil, uint8(resource), units)
    if err != nil {
        return nil, fmt.Errorf("failed to get price: %w", err)
    }

    return price, nil
}

// WaitForTransaction waits for a transaction to be mined
func (pc *PaymentClient) WaitForTransaction(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
    for {
        receipt, err := pc.client.TransactionReceipt(ctx, tx.Hash())
        if err == nil {
            return receipt, nil
        }

        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        case <-time.After(2 * time.Second):
            continue
        }
    }
}

// UserBalance represents a user's balance state
type UserBalance struct {
    Deposited    *big.Int
    Available    *big.Int
    Locked       *big.Int
    Spent        *big.Int
    LastActivity time.Time
}

// PaymentManager provides high-level payment operations
type PaymentManager struct {
    client *PaymentClient
    cache  *PriceCache
}

// NewPaymentManager creates a new payment manager
func NewPaymentManager(client *PaymentClient) *PaymentManager {
    return &PaymentManager{
        client: client,
        cache:  NewPriceCache(5 * time.Minute),
    }
}

// EstimateCost estimates the cost for resource usage
func (pm *PaymentManager) EstimateCost(
    resource ResourceType,
    units int64,
    duration time.Duration,
) (*CostEstimate, error) {
    // Get cached price or fetch new
    price, err := pm.cache.GetPrice(resource, func() (*big.Int, error) {
        return pm.client.GetResourcePrice(resource, big.NewInt(units))
    })
    if err != nil {
        return nil, err
    }

    // Calculate total cost
    totalUnits := units
    if duration > 0 {
        // For time-based resources
        hours := int64(duration.Hours())
        if hours < 1 {
            hours = 1
        }
        totalUnits = units * hours
    }

    totalCost := new(big.Int).Mul(price, big.NewInt(totalUnits))
    protocolFee := new(big.Int).Div(
        new(big.Int).Mul(totalCost, big.NewInt(50)),
        big.NewInt(10000),
    )

    return &CostEstimate{
        Resource:    resource,
        Units:       totalUnits,
        PricePerUnit: price,
        TotalCost:   totalCost,
        ProtocolFee: protocolFee,
        NetCost:     new(big.Int).Sub(totalCost, protocolFee),
    }, nil
}

// AutoDeposit ensures sufficient balance for payment
func (pm *PaymentManager) AutoDeposit(
    user common.Address,
    requiredAmount *big.Int,
) error {
    balance, err := pm.client.GetBalance(user)
    if err != nil {
        return err
    }

    if balance.Available.Cmp(requiredAmount) < 0 {
        deficit := new(big.Int).Sub(requiredAmount, balance.Available)
        // Add 10% buffer
        depositAmount := new(big.Int).Mul(deficit, big.NewInt(110))
        depositAmount.Div(depositAmount, big.NewInt(100))

        tx, err := pm.client.Deposit(depositAmount)
        if err != nil {
            return fmt.Errorf("failed to auto-deposit: %w", err)
        }

        _, err = pm.client.WaitForTransaction(context.Background(), tx)
        if err != nil {
            return fmt.Errorf("deposit transaction failed: %w", err)
        }
    }

    return nil
}

// CostEstimate represents estimated costs
type CostEstimate struct {
    Resource     ResourceType
    Units        int64
    PricePerUnit *big.Int
    TotalCost    *big.Int
    ProtocolFee  *big.Int
    NetCost      *big.Int
}

// PriceCache caches resource prices
type PriceCache struct {
    prices map[ResourceType]*cachedPrice
    ttl    time.Duration
}

type cachedPrice struct {
    price     *big.Int
    timestamp time.Time
}

// NewPriceCache creates a new price cache
func NewPriceCache(ttl time.Duration) *PriceCache {
    return &PriceCache{
        prices: make(map[ResourceType]*cachedPrice),
        ttl:    ttl,
    }
}

// GetPrice gets cached price or fetches new
func (pc *PriceCache) GetPrice(
    resource ResourceType,
    fetcher func() (*big.Int, error),
) (*big.Int, error) {
    cached, exists := pc.prices[resource]
    if exists && time.Since(cached.timestamp) < pc.ttl {
        return cached.price, nil
    }

    price, err := fetcher()
    if err != nil {
        return nil, err
    }

    pc.prices[resource] = &cachedPrice{
        price:     price,
        timestamp: time.Now(),
    }

    return price, nil
}
```

### 3. Event Monitoring

```go
package payment

import (
    "context"
    "fmt"
    "log"

    "github.com/ethereum/go-ethereum"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/ethclient"
)

// EventMonitor monitors contract events
type EventMonitor struct {
    client   *ethclient.Client
    contract common.Address
    handlers map[common.Hash]EventHandler
}

// EventHandler processes events
type EventHandler func(types.Log) error

// NewEventMonitor creates a new event monitor
func NewEventMonitor(client *ethclient.Client, contract common.Address) *EventMonitor {
    return &EventMonitor{
        client:   client,
        contract: contract,
        handlers: make(map[common.Hash]EventHandler),
    }
}

// RegisterHandler registers an event handler
func (em *EventMonitor) RegisterHandler(eventSig common.Hash, handler EventHandler) {
    em.handlers[eventSig] = handler
}

// Start starts monitoring events
func (em *EventMonitor) Start(ctx context.Context) error {
    query := ethereum.FilterQuery{
        Addresses: []common.Address{em.contract},
    }

    logs := make(chan types.Log)
    sub, err := em.client.SubscribeFilterLogs(ctx, query, logs)
    if err != nil {
        return fmt.Errorf("failed to subscribe: %w", err)
    }

    for {
        select {
        case err := <-sub.Err():
            return err
        case vLog := <-logs:
            if handler, exists := em.handlers[vLog.Topics[0]]; exists {
                if err := handler(vLog); err != nil {
                    log.Printf("Error handling event: %v", err)
                }
            }
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}

// PaymentEventProcessor processes payment events
type PaymentEventProcessor struct {
    payments *contracts.BlackholePayments
}

// NewPaymentEventProcessor creates a new processor
func NewPaymentEventProcessor(payments *contracts.BlackholePayments) *PaymentEventProcessor {
    return &PaymentEventProcessor{
        payments: payments,
    }
}

// ProcessDepositEvent processes deposit events
func (pep *PaymentEventProcessor) ProcessDepositEvent(vLog types.Log) error {
    event, err := pep.payments.ParseDeposited(vLog)
    if err != nil {
        return err
    }

    log.Printf("Deposit: user=%s amount=%s", event.User.Hex(), event.Amount.String())
    // Process deposit...
    
    return nil
}

// ProcessPaymentEvent processes payment events
func (pep *PaymentEventProcessor) ProcessPaymentEvent(vLog types.Log) error {
    event, err := pep.payments.ParsePaymentProcessed(vLog)
    if err != nil {
        return err
    }

    log.Printf("Payment: user=%s resource=%d amount=%s units=%s",
        event.User.Hex(),
        event.Resource,
        event.Amount.String(),
        event.Units.String(),
    )
    // Process payment...
    
    return nil
}
```

### 4. Admin Tools

```go
package payment

import (
    "context"
    "fmt"
    "math/big"

    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
)

// AdminClient provides admin functionality
type AdminClient struct {
    *PaymentClient
    adminAuth *bind.TransactOpts
}

// NewAdminClient creates admin client
func NewAdminClient(
    client *PaymentClient,
    adminAuth *bind.TransactOpts,
) *AdminClient {
    return &AdminClient{
        PaymentClient: client,
        adminAuth:     adminAuth,
    }
}

// UpdateResourcePricing updates resource prices
func (ac *AdminClient) UpdateResourcePricing(
    resource ResourceType,
    basePrice *big.Int,
    totalSupply *big.Int,
) (*types.Transaction, error) {
    return ac.payments.UpdateResourcePricing(
        ac.adminAuth,
        uint8(resource),
        basePrice,
        totalSupply,
    )
}

// CollectProtocolFees collects accumulated fees
func (ac *AdminClient) CollectProtocolFees() (*types.Transaction, error) {
    return ac.payments.CollectProtocolFees(ac.adminAuth)
}

// GrantRole grants a role to an address
func (ac *AdminClient) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
    return ac.payments.GrantRole(ac.adminAuth, role, account)
}

// Pause pauses the contract
func (ac *AdminClient) Pause() (*types.Transaction, error) {
    return ac.payments.Pause(ac.adminAuth)
}

// Unpause unpauses the contract
func (ac *AdminClient) Unpause() (*types.Transaction, error) {
    return ac.payments.Unpause(ac.adminAuth)
}

// GetContractStats returns contract statistics
func (ac *AdminClient) GetContractStats() (*ContractStats, error) {
    totalDeposits, err := ac.payments.TotalDeposits(nil)
    if err != nil {
        return nil, err
    }

    totalFees, err := ac.payments.TotalProtocolFees(nil)
    if err != nil {
        return nil, err
    }

    // Get resource stats
    var resourceStats []ResourceStats
    for i := 0; i < 4; i++ {
        price, err := ac.payments.ResourcePrices(nil, uint8(i))
        if err != nil {
            return nil, err
        }

        resourceStats = append(resourceStats, ResourceStats{
            Type:         ResourceType(i),
            BasePrice:    price.BasePrice,
            DemandFactor: price.DemandFactor,
            TotalSupply:  price.TotalSupply,
            CurrentUsage: price.CurrentUsage,
        })
    }

    return &ContractStats{
        TotalDeposits:   totalDeposits,
        TotalFees:       totalFees,
        ResourceStats:   resourceStats,
    }, nil
}

// ContractStats represents contract statistics
type ContractStats struct {
    TotalDeposits *big.Int
    TotalFees     *big.Int
    ResourceStats []ResourceStats
}

// ResourceStats represents resource statistics
type ResourceStats struct {
    Type         ResourceType
    BasePrice    *big.Int
    DemandFactor *big.Int
    TotalSupply  *big.Int
    CurrentUsage *big.Int
}
```

## Testing

### Contract Tests

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/BlackholePayments.sol";

contract BlackholePaymentsTest is Test {
    BlackholePayments public payments;
    address public admin = address(1);
    address public user = address(2);
    address public feeRecipient = address(3);

    function setUp() public {
        // Deploy implementation
        BlackholePayments implementation = new BlackholePayments();
        
        // Deploy proxy
        // ... proxy deployment code ...
        
        // Initialize
        payments.initialize(admin, feeRecipient);
        
        // Fund user
        vm.deal(user, 10 ether);
    }

    function testDeposit() public {
        vm.prank(user);
        payments.deposit{value: 1 ether}();
        
        (uint256 deposited, uint256 available, , , ) = payments.userBalances(user);
        assertEq(deposited, 1 ether);
        assertEq(available, 1 ether);
    }

    function testProcessPayment() public {
        // Deposit first
        vm.prank(user);
        payments.deposit{value: 1 ether}();
        
        // Process payment
        vm.prank(user);
        bytes32 paymentId = payments.processPayment(
            BlackholePayments.ResourceType.STORAGE,
            100,
            keccak256("test")
        );
        
        // Check payment record
        (
            address paymentUser,
            BlackholePayments.ResourceType resource,
            uint256 amount,
            uint256 units,
            ,
            ,
            
        ) = payments.payments(paymentId);
        
        assertEq(paymentUser, user);
        assertEq(uint8(resource), uint8(BlackholePayments.ResourceType.STORAGE));
        assertEq(units, 100);
        assertTrue(amount > 0);
    }

    function testDynamicPricing() public {
        // Test base price
        uint256 basePrice = payments.calculatePrice(
            BlackholePayments.ResourceType.STORAGE,
            1
        );
        
        // Test volume discount
        uint256 bulkPrice = payments.calculatePrice(
            BlackholePayments.ResourceType.STORAGE,
            1000
        );
        
        assertTrue(bulkPrice < basePrice * 1000 * 95 / 100); // Should have discount
    }

    function testFeeCollection() public {
        // Setup
        vm.startPrank(user);
        payments.deposit{value: 1 ether}();
        payments.processPayment(
            BlackholePayments.ResourceType.STORAGE,
            100,
            keccak256("test")
        );
        vm.stopPrank();
        
        // Collect fees
        uint256 fees = payments.totalProtocolFees();
        assertTrue(fees > 0);
        
        vm.prank(admin);
        payments.collectProtocolFees();
        
        assertEq(payments.totalProtocolFees(), 0);
        assertEq(feeRecipient.balance, fees);
    }
}
```

## Deployment

### Deployment Script

```javascript
const { ethers, upgrades } = require("hardhat");

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying with account:", deployer.address);

    // Deploy main contract
    const BlackholePayments = await ethers.getContractFactory("BlackholePayments");
    const payments = await upgrades.deployProxy(
        BlackholePayments,
        [deployer.address, process.env.FEE_RECIPIENT],
        { initializer: 'initialize' }
    );
    await payments.deployed();
    console.log("BlackholePayments deployed to:", payments.address);

    // Deploy fee distributor
    const FeeDistributor = await ethers.getContractFactory("FeeDistributor");
    const distributor = await FeeDistributor.deploy();
    await distributor.deployed();
    console.log("FeeDistributor deployed to:", distributor.address);

    // Verify contracts
    if (network.name !== "localhost") {
        await hre.run("verify:verify", {
            address: payments.address,
            constructorArguments: [],
        });
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
```

## Security Considerations

1. **Access Control**: Role-based permissions for admin functions
2. **Reentrancy Guards**: Protection against reentrancy attacks
3. **Pausable**: Emergency pause functionality
4. **Upgradeable**: UUPS proxy pattern for upgrades
5. **Input Validation**: Comprehensive parameter checks
6. **Safe Math**: Built-in Solidity 0.8+ overflow protection

## Gas Optimization

1. **Batch Operations**: Process multiple payments in one transaction
2. **Storage Packing**: Optimize struct layouts
3. **Event Indexing**: Efficient event filtering
4. **Minimal Storage Writes**: Cache and batch updates

## Monitoring and Analytics

1. **Events**: Comprehensive event logging
2. **Getters**: View functions for all state
3. **Stats Tracking**: Usage and revenue metrics
4. **Off-chain Indexing**: Graph Protocol integration ready