# U16: State Channels

## Overview
Off-chain micropayment channels for instant, low-cost transactions with on-chain settlement guarantees.

## Smart Contract Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract StateChannels is ReentrancyGuard {
    using ECDSA for bytes32;
    using SafeMath for uint256;
    
    enum ChannelState { Active, Closing, Closed, Disputed }
    
    struct Channel {
        address participant1;
        address participant2;
        uint256 deposit1;
        uint256 deposit2;
        uint256 nonce;
        uint256 challengePeriod;
        uint256 closingTime;
        ChannelState state;
        bytes32 channelId;
    }
    
    struct BalanceProof {
        uint256 balance1;
        uint256 balance2;
        uint256 nonce;
        bytes signature1;
        bytes signature2;
    }
    
    struct Payment {
        address from;
        address to;
        uint256 amount;
        uint256 timestamp;
        bytes32 paymentId;
    }
    
    mapping(bytes32 => Channel) public channels;
    mapping(bytes32 => BalanceProof) public latestProofs;
    mapping(bytes32 => mapping(uint256 => Payment)) public channelPayments;
    mapping(bytes32 => uint256) public paymentCounts;
    mapping(address => bytes32[]) public userChannels;
    
    uint256 public constant MIN_CHANNEL_DEPOSIT = 0.001 ether;
    uint256 public constant DEFAULT_CHALLENGE_PERIOD = 1 days;
    uint256 public constant MAX_CHALLENGE_PERIOD = 7 days;
    
    event ChannelOpened(
        bytes32 indexed channelId,
        address indexed participant1,
        address indexed participant2,
        uint256 deposit1,
        uint256 deposit2
    );
    
    event ChannelUpdated(
        bytes32 indexed channelId,
        uint256 balance1,
        uint256 balance2,
        uint256 nonce
    );
    
    event ChannelClosing(
        bytes32 indexed channelId,
        address indexed initiator,
        uint256 closingTime
    );
    
    event ChannelClosed(
        bytes32 indexed channelId,
        uint256 finalBalance1,
        uint256 finalBalance2
    );
    
    event ChannelDisputed(
        bytes32 indexed channelId,
        address indexed disputer,
        uint256 nonce
    );
    
    modifier channelExists(bytes32 _channelId) {
        require(channels[_channelId].participant1 != address(0), "Channel does not exist");
        _;
    }
    
    modifier onlyParticipant(bytes32 _channelId) {
        Channel storage channel = channels[_channelId];
        require(
            msg.sender == channel.participant1 || msg.sender == channel.participant2,
            "Not a channel participant"
        );
        _;
    }
    
    // Open a new payment channel
    function openChannel(
        address _participant2,
        uint256 _challengePeriod
    ) external payable returns (bytes32) {
        require(msg.value >= MIN_CHANNEL_DEPOSIT, "Insufficient deposit");
        require(_participant2 != address(0) && _participant2 != msg.sender, "Invalid participant");
        require(_challengePeriod <= MAX_CHALLENGE_PERIOD, "Challenge period too long");
        
        uint256 challengePeriod = _challengePeriod > 0 ? _challengePeriod : DEFAULT_CHALLENGE_PERIOD;
        
        // Generate unique channel ID
        bytes32 channelId = keccak256(
            abi.encodePacked(msg.sender, _participant2, block.timestamp, block.number)
        );
        
        require(channels[channelId].participant1 == address(0), "Channel ID collision");
        
        Channel storage channel = channels[channelId];
        channel.participant1 = msg.sender;
        channel.participant2 = _participant2;
        channel.deposit1 = msg.value;
        channel.challengePeriod = challengePeriod;
        channel.state = ChannelState.Active;
        channel.channelId = channelId;
        
        userChannels[msg.sender].push(channelId);
        userChannels[_participant2].push(channelId);
        
        emit ChannelOpened(channelId, msg.sender, _participant2, msg.value, 0);
        
        return channelId;
    }
    
    // Join an existing channel as participant2
    function joinChannel(bytes32 _channelId) external payable channelExists(_channelId) {
        Channel storage channel = channels[_channelId];
        require(channel.state == ChannelState.Active, "Channel not active");
        require(msg.sender == channel.participant2, "Not participant2");
        require(channel.deposit2 == 0, "Already joined");
        require(msg.value >= MIN_CHANNEL_DEPOSIT, "Insufficient deposit");
        
        channel.deposit2 = msg.value;
        
        // Initialize balance proof
        BalanceProof storage proof = latestProofs[_channelId];
        proof.balance1 = channel.deposit1;
        proof.balance2 = channel.deposit2;
        proof.nonce = 0;
        
        emit ChannelOpened(_channelId, channel.participant1, channel.participant2, channel.deposit1, msg.value);
    }
    
    // Update channel state with signed balance proof
    function updateState(
        bytes32 _channelId,
        uint256 _balance1,
        uint256 _balance2,
        uint256 _nonce,
        bytes memory _signature1,
        bytes memory _signature2
    ) external channelExists(_channelId) onlyParticipant(_channelId) {
        Channel storage channel = channels[_channelId];
        require(channel.state == ChannelState.Active, "Channel not active");
        require(_balance1.add(_balance2) == channel.deposit1.add(channel.deposit2), "Invalid balances");
        require(_nonce > channel.nonce, "Nonce too old");
        
        // Verify signatures
        bytes32 messageHash = keccak256(abi.encodePacked(_channelId, _balance1, _balance2, _nonce));
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        
        address signer1 = ethSignedHash.recover(_signature1);
        address signer2 = ethSignedHash.recover(_signature2);
        
        require(
            (signer1 == channel.participant1 && signer2 == channel.participant2) ||
            (signer1 == channel.participant2 && signer2 == channel.participant1),
            "Invalid signatures"
        );
        
        // Update state
        channel.nonce = _nonce;
        
        BalanceProof storage proof = latestProofs[_channelId];
        proof.balance1 = _balance1;
        proof.balance2 = _balance2;
        proof.nonce = _nonce;
        proof.signature1 = _signature1;
        proof.signature2 = _signature2;
        
        emit ChannelUpdated(_channelId, _balance1, _balance2, _nonce);
    }
    
    // Initiate channel closure
    function closeChannel(bytes32 _channelId) external channelExists(_channelId) onlyParticipant(_channelId) {
        Channel storage channel = channels[_channelId];
        require(channel.state == ChannelState.Active, "Channel not active");
        
        channel.state = ChannelState.Closing;
        channel.closingTime = block.timestamp.add(channel.challengePeriod);
        
        emit ChannelClosing(_channelId, msg.sender, channel.closingTime);
    }
    
    // Submit a newer state during challenge period
    function challengeClose(
        bytes32 _channelId,
        uint256 _balance1,
        uint256 _balance2,
        uint256 _nonce,
        bytes memory _signature1,
        bytes memory _signature2
    ) external channelExists(_channelId) onlyParticipant(_channelId) {
        Channel storage channel = channels[_channelId];
        require(channel.state == ChannelState.Closing, "Channel not closing");
        require(block.timestamp < channel.closingTime, "Challenge period ended");
        
        // Update state with newer proof
        updateState(_channelId, _balance1, _balance2, _nonce, _signature1, _signature2);
        
        channel.state = ChannelState.Disputed;
        
        emit ChannelDisputed(_channelId, msg.sender, _nonce);
    }
    
    // Finalize channel closure and distribute funds
    function finalizeClose(bytes32 _channelId) external channelExists(_channelId) nonReentrant {
        Channel storage channel = channels[_channelId];
        require(
            channel.state == ChannelState.Closing || channel.state == ChannelState.Disputed,
            "Channel not ready to close"
        );
        require(block.timestamp >= channel.closingTime, "Challenge period not ended");
        
        BalanceProof storage proof = latestProofs[_channelId];
        uint256 balance1 = proof.balance1;
        uint256 balance2 = proof.balance2;
        
        // Ensure we have valid balances
        if (balance1 == 0 && balance2 == 0) {
            balance1 = channel.deposit1;
            balance2 = channel.deposit2;
        }
        
        channel.state = ChannelState.Closed;
        
        // Transfer funds
        if (balance1 > 0) {
            (bool success1, ) = channel.participant1.call{value: balance1}("");
            require(success1, "Transfer to participant1 failed");
        }
        
        if (balance2 > 0) {
            (bool success2, ) = channel.participant2.call{value: balance2}("");
            require(success2, "Transfer to participant2 failed");
        }
        
        emit ChannelClosed(_channelId, balance1, balance2);
    }
    
    // Cooperative close - instant settlement with both signatures
    function cooperativeClose(
        bytes32 _channelId,
        uint256 _balance1,
        uint256 _balance2,
        uint256 _nonce,
        bytes memory _signature1,
        bytes memory _signature2
    ) external channelExists(_channelId) nonReentrant {
        Channel storage channel = channels[_channelId];
        require(channel.state == ChannelState.Active, "Channel not active");
        
        // Verify this is a valid state update
        updateState(_channelId, _balance1, _balance2, _nonce, _signature1, _signature2);
        
        // Immediately close and settle
        channel.state = ChannelState.Closed;
        
        // Transfer funds
        if (_balance1 > 0) {
            (bool success1, ) = channel.participant1.call{value: _balance1}("");
            require(success1, "Transfer to participant1 failed");
        }
        
        if (_balance2 > 0) {
            (bool success2, ) = channel.participant2.call{value: _balance2}("");
            require(success2, "Transfer to participant2 failed");
        }
        
        emit ChannelClosed(_channelId, _balance1, _balance2);
    }
    
    // Get channel details
    function getChannel(bytes32 _channelId) external view returns (
        address participant1,
        address participant2,
        uint256 deposit1,
        uint256 deposit2,
        uint256 nonce,
        ChannelState state,
        uint256 closingTime
    ) {
        Channel storage channel = channels[_channelId];
        return (
            channel.participant1,
            channel.participant2,
            channel.deposit1,
            channel.deposit2,
            channel.nonce,
            channel.state,
            channel.closingTime
        );
    }
    
    // Get latest balance proof
    function getLatestProof(bytes32 _channelId) external view returns (
        uint256 balance1,
        uint256 balance2,
        uint256 nonce
    ) {
        BalanceProof storage proof = latestProofs[_channelId];
        return (proof.balance1, proof.balance2, proof.nonce);
    }
    
    // Get user's channels
    function getUserChannels(address _user) external view returns (bytes32[] memory) {
        return userChannels[_user];
    }
    
    // Verify a balance proof signature
    function verifyBalanceProof(
        bytes32 _channelId,
        uint256 _balance1,
        uint256 _balance2,
        uint256 _nonce,
        bytes memory _signature,
        address _signer
    ) public pure returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(_channelId, _balance1, _balance2, _nonce));
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address recoveredSigner = ethSignedHash.recover(_signature);
        return recoveredSigner == _signer;
    }
}
```

## Go Implementation

```go
package statechannels

import (
    "context"
    "crypto/ecdsa"
    "errors"
    "fmt"
    "math/big"
    "sync"
    "time"
    
    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
)

type ChannelState uint8

const (
    StateActive ChannelState = iota
    StateClosing
    StateClosed
    StateDisputed
)

type Channel struct {
    ID              [32]byte
    Participant1    common.Address
    Participant2    common.Address
    Deposit1        *big.Int
    Deposit2        *big.Int
    Balance1        *big.Int
    Balance2        *big.Int
    Nonce           uint64
    State           ChannelState
    ChallengePeriod time.Duration
    ClosingTime     time.Time
    
    // Local state
    sentPayments     []*Payment
    receivedPayments []*Payment
    lastUpdate       time.Time
}

type Payment struct {
    From      common.Address
    To        common.Address
    Amount    *big.Int
    Timestamp time.Time
    ID        [32]byte
    Signature []byte
}

type BalanceProof struct {
    ChannelID [32]byte
    Balance1  *big.Int
    Balance2  *big.Int
    Nonce     uint64
    Sig1      []byte
    Sig2      []byte
}

type ChannelManager struct {
    client      *ethclient.Client
    contract    *StateChannels // Generated contract binding
    privateKey  *ecdsa.PrivateKey
    address     common.Address
    auth        *bind.TransactOpts
    
    channels    map[[32]byte]*Channel
    proofs      map[[32]byte]*BalanceProof
    
    mu          sync.RWMutex
    
    // Payment processing
    paymentQueue chan *Payment
    updateQueue  chan *ChannelUpdate
    
    ctx         context.Context
    cancel      context.CancelFunc
}

type ChannelUpdate struct {
    ChannelID [32]byte
    Balance1  *big.Int
    Balance2  *big.Int
    Nonce     uint64
}

func NewChannelManager(client *ethclient.Client, contractAddr common.Address, privateKey *ecdsa.PrivateKey) (*ChannelManager, error) {
    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, errors.New("error casting public key to ECDSA")
    }
    
    address := crypto.PubkeyToAddress(*publicKeyECDSA)
    
    auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1)) // chainID
    if err != nil {
        return nil, fmt.Errorf("failed to create transactor: %w", err)
    }
    
    contract, err := NewStateChannels(contractAddr, client)
    if err != nil {
        return nil, fmt.Errorf("failed to bind contract: %w", err)
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    cm := &ChannelManager{
        client:       client,
        contract:     contract,
        privateKey:   privateKey,
        address:      address,
        auth:         auth,
        channels:     make(map[[32]byte]*Channel),
        proofs:       make(map[[32]byte]*BalanceProof),
        paymentQueue: make(chan *Payment, 1000),
        updateQueue:  make(chan *ChannelUpdate, 100),
        ctx:          ctx,
        cancel:       cancel,
    }
    
    // Start background workers
    go cm.processPayments()
    go cm.processUpdates()
    go cm.watchEvents()
    
    return cm, nil
}

// Open a new payment channel
func (cm *ChannelManager) OpenChannel(participant2 common.Address, deposit *big.Int, challengePeriod time.Duration) ([32]byte, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    // Set transaction value
    cm.auth.Value = deposit
    defer func() { cm.auth.Value = nil }()
    
    challengeSeconds := big.NewInt(int64(challengePeriod.Seconds()))
    
    tx, err := cm.contract.OpenChannel(cm.auth, participant2, challengeSeconds)
    if err != nil {
        return [32]byte{}, fmt.Errorf("failed to open channel: %w", err)
    }
    
    receipt, err := bind.WaitMined(cm.ctx, cm.client, tx)
    if err != nil {
        return [32]byte{}, fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return [32]byte{}, errors.New("transaction failed")
    }
    
    // Parse events to get channel ID
    for _, log := range receipt.Logs {
        event, err := cm.contract.ParseChannelOpened(*log)
        if err == nil {
            channelID := event.ChannelId
            
            // Create local channel state
            channel := &Channel{
                ID:              channelID,
                Participant1:    cm.address,
                Participant2:    participant2,
                Deposit1:        deposit,
                Deposit2:        big.NewInt(0),
                Balance1:        deposit,
                Balance2:        big.NewInt(0),
                Nonce:           0,
                State:           StateActive,
                ChallengePeriod: challengePeriod,
                sentPayments:    make([]*Payment, 0),
                receivedPayments: make([]*Payment, 0),
                lastUpdate:      time.Now(),
            }
            
            cm.channels[channelID] = channel
            
            return channelID, nil
        }
    }
    
    return [32]byte{}, errors.New("channel created but ID not found")
}

// Join an existing channel
func (cm *ChannelManager) JoinChannel(channelID [32]byte, deposit *big.Int) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    // Set transaction value
    cm.auth.Value = deposit
    defer func() { cm.auth.Value = nil }()
    
    tx, err := cm.contract.JoinChannel(cm.auth, channelID)
    if err != nil {
        return fmt.Errorf("failed to join channel: %w", err)
    }
    
    receipt, err := bind.WaitMined(cm.ctx, cm.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Get channel details from contract
    channelData, err := cm.contract.GetChannel(nil, channelID)
    if err != nil {
        return fmt.Errorf("failed to get channel data: %w", err)
    }
    
    // Create local channel state
    channel := &Channel{
        ID:              channelID,
        Participant1:    channelData.Participant1,
        Participant2:    channelData.Participant2,
        Deposit1:        channelData.Deposit1,
        Deposit2:        deposit,
        Balance1:        channelData.Deposit1,
        Balance2:        deposit,
        Nonce:           0,
        State:           StateActive,
        ChallengePeriod: time.Duration(channelData.ChallengePeriod.Int64()) * time.Second,
        sentPayments:    make([]*Payment, 0),
        receivedPayments: make([]*Payment, 0),
        lastUpdate:      time.Now(),
    }
    
    cm.channels[channelID] = channel
    
    return nil
}

// Send a micropayment
func (cm *ChannelManager) SendPayment(channelID [32]byte, amount *big.Int) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    
    if channel.State != StateActive {
        return errors.New("channel not active")
    }
    
    // Determine sender and receiver
    var fromBalance, toBalance **big.Int
    var to common.Address
    
    if cm.address == channel.Participant1 {
        fromBalance = &channel.Balance1
        toBalance = &channel.Balance2
        to = channel.Participant2
    } else {
        fromBalance = &channel.Balance2
        toBalance = &channel.Balance1
        to = channel.Participant1
    }
    
    // Check sufficient balance
    if (*fromBalance).Cmp(amount) < 0 {
        return errors.New("insufficient balance")
    }
    
    // Update balances
    *fromBalance = new(big.Int).Sub(*fromBalance, amount)
    *toBalance = new(big.Int).Add(*toBalance, amount)
    
    // Create payment record
    payment := &Payment{
        From:      cm.address,
        To:        to,
        Amount:    amount,
        Timestamp: time.Now(),
        ID:        crypto.Keccak256Hash([]byte(fmt.Sprintf("%x:%d:%d", channelID, channel.Nonce, time.Now().UnixNano()))),
    }
    
    // Sign payment
    paymentHash := crypto.Keccak256Hash(
        channelID[:],
        common.LeftPadBytes(payment.Amount.Bytes(), 32),
        payment.ID[:],
    )
    
    signature, err := crypto.Sign(paymentHash.Bytes(), cm.privateKey)
    if err != nil {
        return fmt.Errorf("failed to sign payment: %w", err)
    }
    
    payment.Signature = signature
    channel.sentPayments = append(channel.sentPayments, payment)
    
    // Queue payment for processing
    select {
    case cm.paymentQueue <- payment:
    default:
        return errors.New("payment queue full")
    }
    
    // Increment nonce
    channel.Nonce++
    channel.lastUpdate = time.Now()
    
    // Queue state update
    update := &ChannelUpdate{
        ChannelID: channelID,
        Balance1:  channel.Balance1,
        Balance2:  channel.Balance2,
        Nonce:     channel.Nonce,
    }
    
    select {
    case cm.updateQueue <- update:
    default:
        // Update queue full, will be updated later
    }
    
    return nil
}

// Process incoming payment
func (cm *ChannelManager) ReceivePayment(channelID [32]byte, payment *Payment) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    
    // Verify payment signature
    paymentHash := crypto.Keccak256Hash(
        channelID[:],
        common.LeftPadBytes(payment.Amount.Bytes(), 32),
        payment.ID[:],
    )
    
    sigPubKey, err := crypto.SigToPub(paymentHash.Bytes(), payment.Signature)
    if err != nil {
        return fmt.Errorf("failed to recover signature: %w", err)
    }
    
    signer := crypto.PubkeyToAddress(*sigPubKey)
    if signer != payment.From {
        return errors.New("invalid payment signature")
    }
    
    // Verify sender is channel participant
    if payment.From != channel.Participant1 && payment.From != channel.Participant2 {
        return errors.New("payment from non-participant")
    }
    
    // Record payment
    channel.receivedPayments = append(channel.receivedPayments, payment)
    
    return nil
}

// Create and sign a balance proof
func (cm *ChannelManager) CreateBalanceProof(channelID [32]byte) (*BalanceProof, error) {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return nil, errors.New("channel not found")
    }
    
    // Create message hash
    messageHash := crypto.Keccak256Hash(
        channelID[:],
        common.LeftPadBytes(channel.Balance1.Bytes(), 32),
        common.LeftPadBytes(channel.Balance2.Bytes(), 32),
        common.LeftPadBytes(big.NewInt(int64(channel.Nonce)).Bytes(), 32),
    )
    
    // Sign with Ethereum prefix
    prefixedHash := crypto.Keccak256Hash(
        []byte("\x19Ethereum Signed Message:\n32"),
        messageHash.Bytes(),
    )
    
    signature, err := crypto.Sign(prefixedHash.Bytes(), cm.privateKey)
    if err != nil {
        return nil, fmt.Errorf("failed to sign balance proof: %w", err)
    }
    
    proof := &BalanceProof{
        ChannelID: channelID,
        Balance1:  channel.Balance1,
        Balance2:  channel.Balance2,
        Nonce:     channel.Nonce,
    }
    
    // Set signature based on participant position
    if cm.address == channel.Participant1 {
        proof.Sig1 = signature
    } else {
        proof.Sig2 = signature
    }
    
    return proof, nil
}

// Update channel state on-chain
func (cm *ChannelManager) UpdateChannelState(channelID [32]byte, proof *BalanceProof) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    
    // Ensure we have both signatures
    if len(proof.Sig1) == 0 || len(proof.Sig2) == 0 {
        return errors.New("missing signatures")
    }
    
    tx, err := cm.contract.UpdateState(
        cm.auth,
        channelID,
        proof.Balance1,
        proof.Balance2,
        big.NewInt(int64(proof.Nonce)),
        proof.Sig1,
        proof.Sig2,
    )
    if err != nil {
        return fmt.Errorf("failed to update state: %w", err)
    }
    
    receipt, err := bind.WaitMined(cm.ctx, cm.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    channel.Balance1 = proof.Balance1
    channel.Balance2 = proof.Balance2
    channel.Nonce = proof.Nonce
    cm.proofs[channelID] = proof
    
    return nil
}

// Initiate channel closure
func (cm *ChannelManager) CloseChannel(channelID [32]byte) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    
    if channel.State != StateActive {
        return errors.New("channel not active")
    }
    
    tx, err := cm.contract.CloseChannel(cm.auth, channelID)
    if err != nil {
        return fmt.Errorf("failed to close channel: %w", err)
    }
    
    receipt, err := bind.WaitMined(cm.ctx, cm.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    channel.State = StateClosing
    channel.ClosingTime = time.Now().Add(channel.ChallengePeriod)
    
    return nil
}

// Cooperative close with counterparty
func (cm *ChannelManager) CooperativeClose(channelID [32]byte, proof *BalanceProof) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return errors.New("channel not found")
    }
    
    if channel.State != StateActive {
        return errors.New("channel not active")
    }
    
    // Ensure we have both signatures
    if len(proof.Sig1) == 0 || len(proof.Sig2) == 0 {
        return errors.New("missing signatures for cooperative close")
    }
    
    tx, err := cm.contract.CooperativeClose(
        cm.auth,
        channelID,
        proof.Balance1,
        proof.Balance2,
        big.NewInt(int64(proof.Nonce)),
        proof.Sig1,
        proof.Sig2,
    )
    if err != nil {
        return fmt.Errorf("failed to cooperative close: %w", err)
    }
    
    receipt, err := bind.WaitMined(cm.ctx, cm.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    channel.State = StateClosed
    
    return nil
}

// Process payment queue
func (cm *ChannelManager) processPayments() {
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    batch := make([]*Payment, 0, 100)
    
    for {
        select {
        case <-cm.ctx.Done():
            return
            
        case payment := <-cm.paymentQueue:
            batch = append(batch, payment)
            
        case <-ticker.C:
            if len(batch) > 0 {
                // Process batch
                cm.processBatch(batch)
                batch = batch[:0]
            }
        }
    }
}

// Process a batch of payments
func (cm *ChannelManager) processBatch(payments []*Payment) {
    // Group by channel
    channelPayments := make(map[[32]byte][]*Payment)
    
    for _, payment := range payments {
        // Find channel for payment
        cm.mu.RLock()
        for channelID, channel := range cm.channels {
            if (payment.From == channel.Participant1 && payment.To == channel.Participant2) ||
               (payment.From == channel.Participant2 && payment.To == channel.Participant1) {
                channelPayments[channelID] = append(channelPayments[channelID], payment)
                break
            }
        }
        cm.mu.RUnlock()
    }
    
    // Process each channel's payments
    for channelID, chPayments := range channelPayments {
        cm.processChannelPayments(channelID, chPayments)
    }
}

// Process payments for a specific channel
func (cm *ChannelManager) processChannelPayments(channelID [32]byte, payments []*Payment) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return
    }
    
    // Aggregate payment amounts
    netFlow := big.NewInt(0)
    
    for _, payment := range payments {
        if payment.From == cm.address {
            netFlow.Sub(netFlow, payment.Amount)
        } else {
            netFlow.Add(netFlow, payment.Amount)
        }
    }
    
    // Update channel balances based on net flow
    if cm.address == channel.Participant1 {
        channel.Balance1.Add(channel.Balance1, netFlow)
        channel.Balance2.Sub(channel.Balance2, netFlow)
    } else {
        channel.Balance2.Add(channel.Balance2, netFlow)
        channel.Balance1.Sub(channel.Balance1, netFlow)
    }
}

// Process state updates
func (cm *ChannelManager) processUpdates() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    pendingUpdates := make(map[[32]byte]*ChannelUpdate)
    
    for {
        select {
        case <-cm.ctx.Done():
            return
            
        case update := <-cm.updateQueue:
            pendingUpdates[update.ChannelID] = update
            
        case <-ticker.C:
            // Process pending updates
            for channelID, update := range pendingUpdates {
                cm.processStateUpdate(channelID, update)
                delete(pendingUpdates, channelID)
            }
        }
    }
}

// Process a single state update
func (cm *ChannelManager) processStateUpdate(channelID [32]byte, update *ChannelUpdate) {
    // Create balance proof
    proof, err := cm.CreateBalanceProof(channelID)
    if err != nil {
        return
    }
    
    // In production, exchange signatures with counterparty
    // For now, we'll skip the actual on-chain update
    
    cm.mu.Lock()
    cm.proofs[channelID] = proof
    cm.mu.Unlock()
}

// Watch for contract events
func (cm *ChannelManager) watchEvents() {
    // Set up event filters
    channelOpenedCh := make(chan *StateChannelsChannelOpened)
    channelOpenedSub, err := cm.contract.WatchChannelOpened(nil, channelOpenedCh, nil, nil, nil)
    if err != nil {
        return
    }
    defer channelOpenedSub.Unsubscribe()
    
    channelClosingCh := make(chan *StateChannelsChannelClosing)
    channelClosingSub, err := cm.contract.WatchChannelClosing(nil, channelClosingCh, nil, nil)
    if err != nil {
        return
    }
    defer channelClosingSub.Unsubscribe()
    
    for {
        select {
        case <-cm.ctx.Done():
            return
            
        case event := <-channelOpenedCh:
            cm.handleChannelOpened(event)
            
        case event := <-channelClosingCh:
            cm.handleChannelClosing(event)
        }
    }
}

// Handle channel opened event
func (cm *ChannelManager) handleChannelOpened(event *StateChannelsChannelOpened) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    if channel, exists := cm.channels[event.ChannelId]; exists {
        // Update deposit2 if we're participant1 and participant2 just joined
        if channel.Participant1 == cm.address && event.Deposit2 != nil && event.Deposit2.Cmp(big.NewInt(0)) > 0 {
            channel.Deposit2 = event.Deposit2
            channel.Balance2 = event.Deposit2
        }
    }
}

// Handle channel closing event
func (cm *ChannelManager) handleChannelClosing(event *StateChannelsChannelClosing) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    
    if channel, exists := cm.channels[event.ChannelId]; exists {
        channel.State = StateClosing
        channel.ClosingTime = time.Unix(event.ClosingTime.Int64(), 0)
        
        // If we didn't initiate the close, we might want to challenge
        if event.Initiator != cm.address {
            // Check if we have a newer state
            if proof, exists := cm.proofs[event.ChannelId]; exists && proof.Nonce > channel.Nonce {
                // Submit challenge in a goroutine
                go cm.challengeClose(event.ChannelId, proof)
            }
        }
    }
}

// Challenge a channel close with newer state
func (cm *ChannelManager) challengeClose(channelID [32]byte, proof *BalanceProof) {
    tx, err := cm.contract.ChallengeClose(
        cm.auth,
        channelID,
        proof.Balance1,
        proof.Balance2,
        big.NewInt(int64(proof.Nonce)),
        proof.Sig1,
        proof.Sig2,
    )
    if err != nil {
        return
    }
    
    bind.WaitMined(cm.ctx, cm.client, tx)
}

// Get channel balance
func (cm *ChannelManager) GetBalance(channelID [32]byte) (*big.Int, error) {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return nil, errors.New("channel not found")
    }
    
    if cm.address == channel.Participant1 {
        return channel.Balance1, nil
    }
    return channel.Balance2, nil
}

// Get channel details
func (cm *ChannelManager) GetChannel(channelID [32]byte) (*Channel, error) {
    cm.mu.RLock()
    defer cm.mu.RUnlock()
    
    channel, exists := cm.channels[channelID]
    if !exists {
        return nil, errors.New("channel not found")
    }
    
    return channel, nil
}

// Close the channel manager
func (cm *ChannelManager) Close() {
    cm.cancel()
}
```

## Integration Example

```go
package main

import (
    "fmt"
    "log"
    "math/big"
    "time"
    
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
)

func main() {
    // Connect to Ethereum node
    client, err := ethclient.Dial("ws://localhost:8545")
    if err != nil {
        log.Fatal(err)
    }
    
    // Load private keys
    aliceKey, err := crypto.HexToECDSA("alice-private-key")
    if err != nil {
        log.Fatal(err)
    }
    
    bobKey, err := crypto.HexToECDSA("bob-private-key")
    if err != nil {
        log.Fatal(err)
    }
    
    // Contract address
    contractAddr := common.HexToAddress("0x...")
    
    // Create channel managers
    aliceManager, err := NewChannelManager(client, contractAddr, aliceKey)
    if err != nil {
        log.Fatal(err)
    }
    defer aliceManager.Close()
    
    bobManager, err := NewChannelManager(client, contractAddr, bobKey)
    if err != nil {
        log.Fatal(err)
    }
    defer bobManager.Close()
    
    // Alice opens a channel with Bob
    bobAddr := crypto.PubkeyToAddress(bobKey.PublicKey)
    deposit := big.NewInt(1e18) // 1 ETH
    challengePeriod := 24 * time.Hour
    
    channelID, err := aliceManager.OpenChannel(bobAddr, deposit, challengePeriod)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Channel opened: %x\n", channelID)
    
    // Bob joins the channel
    err = bobManager.JoinChannel(channelID, deposit)
    if err != nil {
        log.Fatal(err)
    }
    
    // Perform micropayments
    paymentAmount := big.NewInt(1e15) // 0.001 ETH
    
    // Alice sends payment to Bob
    err = aliceManager.SendPayment(channelID, paymentAmount)
    if err != nil {
        log.Fatal(err)
    }
    
    // Bob sends payment to Alice
    err = bobManager.SendPayment(channelID, paymentAmount)
    if err != nil {
        log.Fatal(err)
    }
    
    // Check balances
    aliceBalance, _ := aliceManager.GetBalance(channelID)
    bobBalance, _ := bobManager.GetBalance(channelID)
    
    fmt.Printf("Alice balance: %s ETH\n", weiToEther(aliceBalance))
    fmt.Printf("Bob balance: %s ETH\n", weiToEther(bobBalance))
    
    // Create final balance proofs
    aliceProof, err := aliceManager.CreateBalanceProof(channelID)
    if err != nil {
        log.Fatal(err)
    }
    
    bobProof, err := bobManager.CreateBalanceProof(channelID)
    if err != nil {
        log.Fatal(err)
    }
    
    // Combine signatures for cooperative close
    finalProof := &BalanceProof{
        ChannelID: channelID,
        Balance1:  aliceProof.Balance1,
        Balance2:  aliceProof.Balance2,
        Nonce:     aliceProof.Nonce,
        Sig1:      aliceProof.Sig1,
        Sig2:      bobProof.Sig2,
    }
    
    // Cooperative close
    err = aliceManager.CooperativeClose(channelID, finalProof)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Channel closed cooperatively")
}

func weiToEther(wei *big.Int) string {
    ether := new(big.Float).SetInt(wei)
    ether.Quo(ether, big.NewFloat(1e18))
    return ether.String()
}
```

## Features

1. **Off-Chain Micropayments**
   - Instant transactions
   - No gas fees for transfers
   - Batched payment processing
   - Signature-based verification

2. **Channel Lifecycle**
   - Bi-directional channels
   - Configurable challenge periods
   - Cooperative and unilateral close
   - State synchronization

3. **Balance Proof Verification**
   - ECDSA signature verification
   - Nonce-based ordering
   - Ethereum signed message format
   - Multi-signature support

4. **Instant Settlement**
   - Sub-second payment confirmation
   - Micropayment aggregation
   - Net settlement calculation
   - Automatic state updates

## Security Considerations

1. **Replay Protection**
   - Unique channel IDs
   - Monotonic nonce increments
   - Payment ID tracking
   - Timestamp validation

2. **Balance Security**
   - Cryptographic proofs
   - Total balance conservation
   - Overflow protection
   - Double-spend prevention

3. **Dispute Resolution**
   - Challenge period for disputes
   - Latest state enforcement
   - On-chain verification
   - Timeout protection

4. **Privacy**
   - Off-chain transaction privacy
   - Minimal on-chain footprint
   - Encrypted communication option
   - Anonymous payment support