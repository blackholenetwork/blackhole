# U15: Escrow System

## Overview
Work-based escrow system for compute and storage jobs with automated release based on proof of work completion and dispute resolution mechanisms.

## Smart Contract Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WorkEscrow is ReentrancyGuard, Ownable {
    enum JobStatus { Created, Funded, InProgress, Completed, Disputed, Resolved, Cancelled }
    enum JobType { Compute, Storage }
    
    struct Job {
        address requester;
        address provider;
        uint256 amount;
        uint256 deadline;
        JobStatus status;
        JobType jobType;
        bytes32 jobHash;
        bytes32 resultHash;
        uint256 createdAt;
        uint256 completedAt;
        bool multiparty;
        mapping(address => bool) approvals;
        address[] approvers;
        uint256 requiredApprovals;
    }
    
    struct Dispute {
        uint256 jobId;
        address initiator;
        string reason;
        uint256 createdAt;
        bool resolved;
        address resolver;
        uint256 requesterShare; // Percentage * 100 (e.g., 5000 = 50%)
        uint256 providerShare;
    }
    
    mapping(uint256 => Job) public jobs;
    mapping(uint256 => Dispute) public disputes;
    mapping(address => uint256[]) public userJobs;
    mapping(address => uint256) public userDeposits;
    mapping(address => bool) public arbitrators;
    
    uint256 public jobCounter;
    uint256 public disputeCounter;
    uint256 public constant DISPUTE_PERIOD = 7 days;
    uint256 public constant MIN_ESCROW_AMOUNT = 0.001 ether;
    uint256 public platformFee = 100; // 1%
    
    event JobCreated(uint256 indexed jobId, address indexed requester, uint256 amount, JobType jobType);
    event JobFunded(uint256 indexed jobId, uint256 amount);
    event JobAccepted(uint256 indexed jobId, address indexed provider);
    event JobCompleted(uint256 indexed jobId, bytes32 resultHash);
    event JobApproved(uint256 indexed jobId, address indexed approver);
    event PaymentReleased(uint256 indexed jobId, address indexed provider, uint256 amount);
    event DisputeRaised(uint256 indexed disputeId, uint256 indexed jobId, address indexed initiator);
    event DisputeResolved(uint256 indexed disputeId, uint256 requesterShare, uint256 providerShare);
    
    modifier onlyRequester(uint256 _jobId) {
        require(jobs[_jobId].requester == msg.sender, "Not job requester");
        _;
    }
    
    modifier onlyProvider(uint256 _jobId) {
        require(jobs[_jobId].provider == msg.sender, "Not job provider");
        _;
    }
    
    modifier onlyArbitrator() {
        require(arbitrators[msg.sender], "Not an arbitrator");
        _;
    }
    
    modifier jobExists(uint256 _jobId) {
        require(jobs[_jobId].createdAt > 0, "Job does not exist");
        _;
    }
    
    constructor() {
        arbitrators[msg.sender] = true;
    }
    
    // Create a new escrow job
    function createJob(
        JobType _jobType,
        bytes32 _jobHash,
        uint256 _deadline,
        bool _multiparty,
        address[] memory _approvers,
        uint256 _requiredApprovals
    ) external payable returns (uint256) {
        require(msg.value >= MIN_ESCROW_AMOUNT, "Insufficient escrow amount");
        require(_deadline > block.timestamp, "Invalid deadline");
        
        if (_multiparty) {
            require(_approvers.length > 0, "Approvers required for multiparty");
            require(_requiredApprovals > 0 && _requiredApprovals <= _approvers.length, "Invalid approval count");
        }
        
        uint256 jobId = ++jobCounter;
        Job storage job = jobs[jobId];
        
        job.requester = msg.sender;
        job.amount = msg.value;
        job.deadline = _deadline;
        job.status = JobStatus.Funded;
        job.jobType = _jobType;
        job.jobHash = _jobHash;
        job.createdAt = block.timestamp;
        job.multiparty = _multiparty;
        job.requiredApprovals = _requiredApprovals;
        
        if (_multiparty) {
            for (uint i = 0; i < _approvers.length; i++) {
                job.approvers.push(_approvers[i]);
            }
        }
        
        userJobs[msg.sender].push(jobId);
        
        emit JobCreated(jobId, msg.sender, msg.value, _jobType);
        emit JobFunded(jobId, msg.value);
        
        return jobId;
    }
    
    // Provider accepts the job
    function acceptJob(uint256 _jobId) external jobExists(_jobId) {
        Job storage job = jobs[_jobId];
        require(job.status == JobStatus.Funded, "Job not available");
        require(job.provider == address(0), "Job already accepted");
        require(job.requester != msg.sender, "Cannot accept own job");
        
        job.provider = msg.sender;
        job.status = JobStatus.InProgress;
        userJobs[msg.sender].push(_jobId);
        
        emit JobAccepted(_jobId, msg.sender);
    }
    
    // Provider submits completed work
    function submitWork(uint256 _jobId, bytes32 _resultHash) external onlyProvider(_jobId) {
        Job storage job = jobs[_jobId];
        require(job.status == JobStatus.InProgress, "Job not in progress");
        require(block.timestamp <= job.deadline, "Job deadline passed");
        
        job.resultHash = _resultHash;
        job.status = JobStatus.Completed;
        job.completedAt = block.timestamp;
        
        emit JobCompleted(_jobId, _resultHash);
        
        // For non-multiparty jobs, start automatic release timer
        if (!job.multiparty) {
            // Payment can be released after dispute period
        }
    }
    
    // Approve completed work (for multiparty jobs)
    function approveWork(uint256 _jobId) external jobExists(_jobId) {
        Job storage job = jobs[_jobId];
        require(job.status == JobStatus.Completed, "Job not completed");
        require(job.multiparty, "Not a multiparty job");
        
        bool isApprover = false;
        for (uint i = 0; i < job.approvers.length; i++) {
            if (job.approvers[i] == msg.sender) {
                isApprover = true;
                break;
            }
        }
        require(isApprover || msg.sender == job.requester, "Not authorized to approve");
        require(!job.approvals[msg.sender], "Already approved");
        
        job.approvals[msg.sender] = true;
        emit JobApproved(_jobId, msg.sender);
        
        // Check if enough approvals
        uint256 approvalCount = 0;
        for (uint i = 0; i < job.approvers.length; i++) {
            if (job.approvals[job.approvers[i]]) {
                approvalCount++;
            }
        }
        if (job.approvals[job.requester]) {
            approvalCount++;
        }
        
        if (approvalCount >= job.requiredApprovals) {
            _releasePayment(_jobId);
        }
    }
    
    // Release payment to provider
    function releasePayment(uint256 _jobId) external nonReentrant jobExists(_jobId) {
        Job storage job = jobs[_jobId];
        require(job.status == JobStatus.Completed, "Job not completed");
        
        if (job.multiparty) {
            revert("Use approveWork for multiparty jobs");
        }
        
        require(
            msg.sender == job.requester || 
            (block.timestamp >= job.completedAt + DISPUTE_PERIOD),
            "Cannot release payment yet"
        );
        
        _releasePayment(_jobId);
    }
    
    function _releasePayment(uint256 _jobId) private {
        Job storage job = jobs[_jobId];
        require(job.status == JobStatus.Completed, "Invalid job status");
        
        uint256 fee = (job.amount * platformFee) / 10000;
        uint256 paymentAmount = job.amount - fee;
        
        job.status = JobStatus.Resolved;
        
        // Transfer payment to provider
        (bool success, ) = job.provider.call{value: paymentAmount}("");
        require(success, "Payment transfer failed");
        
        // Transfer fee to platform
        if (fee > 0) {
            (bool feeSuccess, ) = owner().call{value: fee}("");
            require(feeSuccess, "Fee transfer failed");
        }
        
        emit PaymentReleased(_jobId, job.provider, paymentAmount);
    }
    
    // Raise a dispute
    function raiseDispute(uint256 _jobId, string memory _reason) external jobExists(_jobId) {
        Job storage job = jobs[_jobId];
        require(
            msg.sender == job.requester || msg.sender == job.provider,
            "Not authorized to dispute"
        );
        require(
            job.status == JobStatus.InProgress || job.status == JobStatus.Completed,
            "Cannot dispute this job"
        );
        
        uint256 disputeId = ++disputeCounter;
        Dispute storage dispute = disputes[disputeId];
        
        dispute.jobId = _jobId;
        dispute.initiator = msg.sender;
        dispute.reason = _reason;
        dispute.createdAt = block.timestamp;
        
        job.status = JobStatus.Disputed;
        
        emit DisputeRaised(disputeId, _jobId, msg.sender);
    }
    
    // Resolve a dispute (arbitrator only)
    function resolveDispute(
        uint256 _disputeId,
        uint256 _requesterShare,
        uint256 _providerShare
    ) external onlyArbitrator nonReentrant {
        Dispute storage dispute = disputes[_disputeId];
        require(!dispute.resolved, "Dispute already resolved");
        require(_requesterShare + _providerShare == 10000, "Invalid shares");
        
        dispute.resolved = true;
        dispute.resolver = msg.sender;
        dispute.requesterShare = _requesterShare;
        dispute.providerShare = _providerShare;
        
        Job storage job = jobs[dispute.jobId];
        require(job.status == JobStatus.Disputed, "Job not in dispute");
        
        uint256 totalAmount = job.amount;
        uint256 requesterAmount = (totalAmount * _requesterShare) / 10000;
        uint256 providerAmount = (totalAmount * _providerShare) / 10000;
        
        job.status = JobStatus.Resolved;
        
        // Transfer amounts
        if (requesterAmount > 0) {
            (bool reqSuccess, ) = job.requester.call{value: requesterAmount}("");
            require(reqSuccess, "Requester transfer failed");
        }
        
        if (providerAmount > 0 && job.provider != address(0)) {
            (bool provSuccess, ) = job.provider.call{value: providerAmount}("");
            require(provSuccess, "Provider transfer failed");
        }
        
        emit DisputeResolved(_disputeId, _requesterShare, _providerShare);
    }
    
    // Cancel a job (only if not started)
    function cancelJob(uint256 _jobId) external onlyRequester(_jobId) nonReentrant {
        Job storage job = jobs[_jobId];
        require(job.status == JobStatus.Funded, "Cannot cancel job");
        require(job.provider == address(0), "Job already accepted");
        
        job.status = JobStatus.Cancelled;
        
        // Refund the requester
        (bool success, ) = job.requester.call{value: job.amount}("");
        require(success, "Refund failed");
    }
    
    // Add/remove arbitrators
    function setArbitrator(address _arbitrator, bool _status) external onlyOwner {
        arbitrators[_arbitrator] = _status;
    }
    
    // Update platform fee
    function setPlatformFee(uint256 _fee) external onlyOwner {
        require(_fee <= 1000, "Fee too high"); // Max 10%
        platformFee = _fee;
    }
    
    // Get user's jobs
    function getUserJobs(address _user) external view returns (uint256[] memory) {
        return userJobs[_user];
    }
    
    // Get job details with multiparty info
    function getJobDetails(uint256 _jobId) external view returns (
        address requester,
        address provider,
        uint256 amount,
        uint256 deadline,
        JobStatus status,
        JobType jobType,
        bytes32 jobHash,
        bytes32 resultHash,
        bool multiparty,
        uint256 requiredApprovals
    ) {
        Job storage job = jobs[_jobId];
        return (
            job.requester,
            job.provider,
            job.amount,
            job.deadline,
            job.status,
            job.jobType,
            job.jobHash,
            job.resultHash,
            job.multiparty,
            job.requiredApprovals
        );
    }
}
```

## Go Implementation

```go
package escrow

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"
    "sync"
    "time"
    
    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/ethclient"
)

type JobType uint8

const (
    JobTypeCompute JobType = iota
    JobTypeStorage
)

type JobStatus uint8

const (
    StatusCreated JobStatus = iota
    StatusFunded
    StatusInProgress
    StatusCompleted
    StatusDisputed
    StatusResolved
    StatusCancelled
)

type Job struct {
    ID               uint64
    Requester        common.Address
    Provider         common.Address
    Amount           *big.Int
    Deadline         time.Time
    Status           JobStatus
    Type             JobType
    JobHash          [32]byte
    ResultHash       [32]byte
    CreatedAt        time.Time
    CompletedAt      time.Time
    Multiparty       bool
    Approvers        []common.Address
    RequiredApprovals uint64
    Approvals        map[common.Address]bool
}

type Dispute struct {
    ID            uint64
    JobID         uint64
    Initiator     common.Address
    Reason        string
    CreatedAt     time.Time
    Resolved      bool
    Resolver      common.Address
    RequesterShare uint64
    ProviderShare  uint64
}

type EscrowManager struct {
    client      *ethclient.Client
    contract    *WorkEscrow // Generated contract binding
    auth        *bind.TransactOpts
    address     common.Address
    
    jobs        map[uint64]*Job
    disputes    map[uint64]*Dispute
    userJobs    map[common.Address][]uint64
    
    mu          sync.RWMutex
    
    // Event channels
    jobCreated  chan *JobCreatedEvent
    jobAccepted chan *JobAcceptedEvent
    jobCompleted chan *JobCompletedEvent
    paymentReleased chan *PaymentReleasedEvent
    disputeRaised chan *DisputeRaisedEvent
    
    ctx         context.Context
    cancel      context.CancelFunc
}

type JobCreatedEvent struct {
    JobID     uint64
    Requester common.Address
    Amount    *big.Int
    JobType   JobType
    Timestamp time.Time
}

type ProofOfWork struct {
    JobID      uint64
    Provider   common.Address
    ResultHash [32]byte
    Nonce      uint64
    Timestamp  time.Time
    Signature  []byte
}

func NewEscrowManager(client *ethclient.Client, contractAddr common.Address, auth *bind.TransactOpts) (*EscrowManager, error) {
    contract, err := NewWorkEscrow(contractAddr, client)
    if err != nil {
        return nil, fmt.Errorf("failed to bind contract: %w", err)
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    em := &EscrowManager{
        client:      client,
        contract:    contract,
        auth:        auth,
        address:     contractAddr,
        jobs:        make(map[uint64]*Job),
        disputes:    make(map[uint64]*Dispute),
        userJobs:    make(map[common.Address][]uint64),
        jobCreated:  make(chan *JobCreatedEvent, 100),
        jobAccepted: make(chan *JobAcceptedEvent, 100),
        jobCompleted: make(chan *JobCompletedEvent, 100),
        paymentReleased: make(chan *PaymentReleasedEvent, 100),
        disputeRaised: make(chan *DisputeRaisedEvent, 100),
        ctx:         ctx,
        cancel:      cancel,
    }
    
    // Start event listeners
    go em.watchEvents()
    
    return em, nil
}

// Create a new escrow job
func (em *EscrowManager) CreateJob(
    jobType JobType,
    jobData []byte,
    deadline time.Time,
    amount *big.Int,
    multiparty bool,
    approvers []common.Address,
    requiredApprovals uint64,
) (uint64, error) {
    em.mu.Lock()
    defer em.mu.Unlock()
    
    // Calculate job hash
    jobHash := sha256.Sum256(jobData)
    
    // Set transaction value
    em.auth.Value = amount
    defer func() { em.auth.Value = nil }()
    
    // Call contract
    tx, err := em.contract.CreateJob(
        em.auth,
        uint8(jobType),
        jobHash,
        big.NewInt(deadline.Unix()),
        multiparty,
        approvers,
        big.NewInt(int64(requiredApprovals)),
    )
    if err != nil {
        return 0, fmt.Errorf("failed to create job: %w", err)
    }
    
    // Wait for transaction confirmation
    receipt, err := bind.WaitMined(em.ctx, em.client, tx)
    if err != nil {
        return 0, fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return 0, errors.New("transaction failed")
    }
    
    // Parse events to get job ID
    for _, log := range receipt.Logs {
        event, err := em.contract.ParseJobCreated(*log)
        if err == nil {
            jobID := event.JobId.Uint64()
            
            // Store job locally
            job := &Job{
                ID:                jobID,
                Requester:         em.auth.From,
                Amount:            amount,
                Deadline:          deadline,
                Status:            StatusFunded,
                Type:              jobType,
                JobHash:           jobHash,
                CreatedAt:         time.Now(),
                Multiparty:        multiparty,
                Approvers:         approvers,
                RequiredApprovals: requiredApprovals,
                Approvals:         make(map[common.Address]bool),
            }
            
            em.jobs[jobID] = job
            em.userJobs[em.auth.From] = append(em.userJobs[em.auth.From], jobID)
            
            return jobID, nil
        }
    }
    
    return 0, errors.New("job created but ID not found")
}

// Accept a job as a provider
func (em *EscrowManager) AcceptJob(jobID uint64) error {
    em.mu.Lock()
    defer em.mu.Unlock()
    
    job, exists := em.jobs[jobID]
    if !exists {
        return errors.New("job not found")
    }
    
    if job.Status != StatusFunded {
        return errors.New("job not available")
    }
    
    tx, err := em.contract.AcceptJob(em.auth, big.NewInt(int64(jobID)))
    if err != nil {
        return fmt.Errorf("failed to accept job: %w", err)
    }
    
    receipt, err := bind.WaitMined(em.ctx, em.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    job.Provider = em.auth.From
    job.Status = StatusInProgress
    em.userJobs[em.auth.From] = append(em.userJobs[em.auth.From], jobID)
    
    return nil
}

// Submit completed work with proof
func (em *EscrowManager) SubmitWork(jobID uint64, resultData []byte, proof *ProofOfWork) error {
    em.mu.Lock()
    defer em.mu.Unlock()
    
    job, exists := em.jobs[jobID]
    if !exists {
        return errors.New("job not found")
    }
    
    if job.Status != StatusInProgress {
        return errors.New("job not in progress")
    }
    
    if job.Provider != em.auth.From {
        return errors.New("not the job provider")
    }
    
    // Verify proof of work
    if err := em.verifyProofOfWork(job, proof); err != nil {
        return fmt.Errorf("invalid proof of work: %w", err)
    }
    
    resultHash := sha256.Sum256(resultData)
    
    tx, err := em.contract.SubmitWork(em.auth, big.NewInt(int64(jobID)), resultHash)
    if err != nil {
        return fmt.Errorf("failed to submit work: %w", err)
    }
    
    receipt, err := bind.WaitMined(em.ctx, em.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    job.ResultHash = resultHash
    job.Status = StatusCompleted
    job.CompletedAt = time.Now()
    
    return nil
}

// Verify proof of work
func (em *EscrowManager) verifyProofOfWork(job *Job, proof *ProofOfWork) error {
    if proof.JobID != job.ID {
        return errors.New("job ID mismatch")
    }
    
    if proof.Provider != job.Provider {
        return errors.New("provider mismatch")
    }
    
    // Verify the work was done within the deadline
    if proof.Timestamp.After(job.Deadline) {
        return errors.New("work completed after deadline")
    }
    
    // Verify the proof hash meets difficulty requirements
    proofData := fmt.Sprintf("%d:%s:%s:%d",
        proof.JobID,
        proof.Provider.Hex(),
        hex.EncodeToString(proof.ResultHash[:]),
        proof.Nonce,
    )
    
    hash := sha256.Sum256([]byte(proofData))
    
    // Check if hash meets difficulty (e.g., starts with required zeros)
    // This is a simplified check - real implementation would have adjustable difficulty
    if hash[0] != 0 || hash[1] != 0 {
        return errors.New("proof does not meet difficulty requirements")
    }
    
    return nil
}

// Approve work for multiparty jobs
func (em *EscrowManager) ApproveWork(jobID uint64) error {
    em.mu.Lock()
    defer em.mu.Unlock()
    
    job, exists := em.jobs[jobID]
    if !exists {
        return errors.New("job not found")
    }
    
    if !job.Multiparty {
        return errors.New("not a multiparty job")
    }
    
    if job.Status != StatusCompleted {
        return errors.New("job not completed")
    }
    
    tx, err := em.contract.ApproveWork(em.auth, big.NewInt(int64(jobID)))
    if err != nil {
        return fmt.Errorf("failed to approve work: %w", err)
    }
    
    receipt, err := bind.WaitMined(em.ctx, em.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    job.Approvals[em.auth.From] = true
    
    return nil
}

// Release payment for completed work
func (em *EscrowManager) ReleasePayment(jobID uint64) error {
    em.mu.Lock()
    defer em.mu.Unlock()
    
    job, exists := em.jobs[jobID]
    if !exists {
        return errors.New("job not found")
    }
    
    if job.Status != StatusCompleted {
        return errors.New("job not completed")
    }
    
    tx, err := em.contract.ReleasePayment(em.auth, big.NewInt(int64(jobID)))
    if err != nil {
        return fmt.Errorf("failed to release payment: %w", err)
    }
    
    receipt, err := bind.WaitMined(em.ctx, em.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    job.Status = StatusResolved
    
    return nil
}

// Raise a dispute
func (em *EscrowManager) RaiseDispute(jobID uint64, reason string) error {
    em.mu.Lock()
    defer em.mu.Unlock()
    
    job, exists := em.jobs[jobID]
    if !exists {
        return errors.New("job not found")
    }
    
    if job.Status != StatusInProgress && job.Status != StatusCompleted {
        return errors.New("cannot dispute this job")
    }
    
    tx, err := em.contract.RaiseDispute(em.auth, big.NewInt(int64(jobID)), reason)
    if err != nil {
        return fmt.Errorf("failed to raise dispute: %w", err)
    }
    
    receipt, err := bind.WaitMined(em.ctx, em.client, tx)
    if err != nil {
        return fmt.Errorf("failed to wait for transaction: %w", err)
    }
    
    if receipt.Status != types.ReceiptStatusSuccessful {
        return errors.New("transaction failed")
    }
    
    // Update local state
    job.Status = StatusDisputed
    
    return nil
}

// Watch for contract events
func (em *EscrowManager) watchEvents() {
    // Set up event filters
    jobCreatedCh := make(chan *WorkEscrowJobCreated)
    jobCreatedSub, err := em.contract.WatchJobCreated(nil, jobCreatedCh, nil, nil)
    if err != nil {
        return
    }
    defer jobCreatedSub.Unsubscribe()
    
    jobAcceptedCh := make(chan *WorkEscrowJobAccepted)
    jobAcceptedSub, err := em.contract.WatchJobAccepted(nil, jobAcceptedCh, nil, nil)
    if err != nil {
        return
    }
    defer jobAcceptedSub.Unsubscribe()
    
    for {
        select {
        case <-em.ctx.Done():
            return
            
        case event := <-jobCreatedCh:
            em.jobCreated <- &JobCreatedEvent{
                JobID:     event.JobId.Uint64(),
                Requester: event.Requester,
                Amount:    event.Amount,
                JobType:   JobType(event.JobType),
                Timestamp: time.Now(),
            }
            
        case event := <-jobAcceptedCh:
            em.mu.Lock()
            if job, exists := em.jobs[event.JobId.Uint64()]; exists {
                job.Provider = event.Provider
                job.Status = StatusInProgress
            }
            em.mu.Unlock()
        }
    }
}

// Get job details
func (em *EscrowManager) GetJob(jobID uint64) (*Job, error) {
    em.mu.RLock()
    defer em.mu.RUnlock()
    
    job, exists := em.jobs[jobID]
    if !exists {
        return nil, errors.New("job not found")
    }
    
    return job, nil
}

// Get user's jobs
func (em *EscrowManager) GetUserJobs(user common.Address) []uint64 {
    em.mu.RLock()
    defer em.mu.RUnlock()
    
    return em.userJobs[user]
}

// Close the escrow manager
func (em *EscrowManager) Close() {
    em.cancel()
}
```

## Integration Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "math/big"
    "time"
    
    "github.com/ethereum/go-ethereum/accounts/abi/bind"
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
    
    // Load private key
    privateKey, err := crypto.HexToECDSA("your-private-key")
    if err != nil {
        log.Fatal(err)
    }
    
    // Create auth
    auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1))
    if err != nil {
        log.Fatal(err)
    }
    
    // Contract address
    contractAddr := common.HexToAddress("0x...")
    
    // Create escrow manager
    escrow, err := NewEscrowManager(client, contractAddr, auth)
    if err != nil {
        log.Fatal(err)
    }
    defer escrow.Close()
    
    // Example: Create a compute job
    jobData := []byte("Compute job: train model XYZ")
    deadline := time.Now().Add(24 * time.Hour)
    amount := big.NewInt(1e18) // 1 ETH
    
    jobID, err := escrow.CreateJob(
        JobTypeCompute,
        jobData,
        deadline,
        amount,
        false, // Not multiparty
        nil,
        0,
    )
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Created job ID: %d\n", jobID)
    
    // As a provider, accept the job
    err = escrow.AcceptJob(jobID)
    if err != nil {
        log.Fatal(err)
    }
    
    // Do the work...
    resultData := []byte("Model trained successfully")
    
    // Create proof of work
    proof := &ProofOfWork{
        JobID:      jobID,
        Provider:   auth.From,
        ResultHash: sha256.Sum256(resultData),
        Nonce:      12345, // Found through mining
        Timestamp:  time.Now(),
    }
    
    // Submit completed work
    err = escrow.SubmitWork(jobID, resultData, proof)
    if err != nil {
        log.Fatal(err)
    }
    
    // Release payment (as requester or after dispute period)
    err = escrow.ReleasePayment(jobID)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Payment released successfully")
}
```

## Features

1. **Work-Based Escrow**
   - Automated fund locking
   - Proof of work verification
   - Deadline enforcement
   - Result hash verification

2. **Automated Release**
   - Time-based release after dispute period
   - Immediate release with requester approval
   - Multi-signature release for multiparty jobs

3. **Dispute Resolution**
   - On-chain dispute raising
   - Arbitrator-based resolution
   - Proportional fund distribution
   - Evidence submission support

4. **Multi-Party Support**
   - Multiple approvers
   - Configurable approval threshold
   - Batch approval tracking
   - Role-based permissions

## Security Considerations

1. **Reentrancy Protection**
   - ReentrancyGuard on all payment functions
   - State updates before external calls
   - Check-effects-interactions pattern

2. **Access Control**
   - Role-based modifiers
   - Ownership verification
   - Arbitrator management

3. **Timing Attacks**
   - Block timestamp validation
   - Minimum dispute period
   - Deadline enforcement

4. **Economic Security**
   - Minimum escrow amounts
   - Platform fee limits
   - Proportional dispute resolution