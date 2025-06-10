# U18: Payment Gateway Service

## Overview
Unified payment API supporting all payment methods with multi-currency capabilities, USDC as base currency, and integration with contracts, escrow, and channels.

## Database Schema

```sql
-- Payment methods configuration
CREATE TABLE payment_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE,
    type VARCHAR(20) NOT NULL CHECK (type IN ('crypto', 'fiat', 'token')),
    network VARCHAR(50),
    contract_address VARCHAR(255),
    decimals INT DEFAULT 18,
    min_amount DECIMAL(36,18) NOT NULL,
    max_amount DECIMAL(36,18) NOT NULL,
    fee_percentage DECIMAL(5,4) DEFAULT 0,
    fee_fixed DECIMAL(36,18) DEFAULT 0,
    confirmation_blocks INT DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Currency exchange rates
CREATE TABLE exchange_rates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_currency VARCHAR(10) NOT NULL,
    to_currency VARCHAR(10) NOT NULL,
    rate DECIMAL(36,18) NOT NULL,
    source VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(from_currency, to_currency, source, timestamp)
);

-- Payment transactions
CREATE TABLE payment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reference_id VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(20) NOT NULL CHECK (type IN ('deposit', 'withdrawal', 'transfer', 'escrow', 'channel')),
    from_address VARCHAR(255),
    to_address VARCHAR(255),
    method_id UUID REFERENCES payment_methods(id),
    amount DECIMAL(36,18) NOT NULL,
    currency VARCHAR(10) NOT NULL,
    usdc_amount DECIMAL(36,18) NOT NULL,
    exchange_rate DECIMAL(36,18),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    blockchain_tx_hash VARCHAR(255),
    blockchain_status VARCHAR(20),
    confirmations INT DEFAULT 0,
    gas_used DECIMAL(36,18),
    gas_price DECIMAL(36,18),
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

-- Payment routing rules
CREATE TABLE payment_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_method_id UUID REFERENCES payment_methods(id),
    target_method_id UUID REFERENCES payment_methods(id),
    min_amount DECIMAL(36,18) NOT NULL,
    max_amount DECIMAL(36,18) NOT NULL,
    fee_percentage DECIMAL(5,4) DEFAULT 0,
    fee_fixed DECIMAL(36,18) DEFAULT 0,
    priority INT DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_method_id, target_method_id)
);

-- Payment webhooks
CREATE TABLE payment_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID REFERENCES payment_transactions(id),
    event_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    signature VARCHAR(255),
    source VARCHAR(50) NOT NULL,
    processed BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_payment_transactions_reference ON payment_transactions(reference_id);
CREATE INDEX idx_payment_transactions_status ON payment_transactions(status);
CREATE INDEX idx_payment_transactions_from ON payment_transactions(from_address);
CREATE INDEX idx_payment_transactions_to ON payment_transactions(to_address);
CREATE INDEX idx_payment_transactions_created ON payment_transactions(created_at);
CREATE INDEX idx_exchange_rates_lookup ON exchange_rates(from_currency, to_currency, timestamp DESC);
CREATE INDEX idx_payment_webhooks_transaction ON payment_webhooks(transaction_id);
CREATE INDEX idx_payment_webhooks_processed ON payment_webhooks(processed, created_at);
```

## Go Implementation

```go
package payment

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "math/big"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/shopspring/decimal"
)

// PaymentMethod represents a supported payment method
type PaymentMethod struct {
    ID               uuid.UUID              `json:"id"`
    Name             string                 `json:"name"`
    Type             string                 `json:"type"`
    Network          string                 `json:"network,omitempty"`
    ContractAddress  string                 `json:"contract_address,omitempty"`
    Decimals         int                    `json:"decimals"`
    MinAmount        decimal.Decimal        `json:"min_amount"`
    MaxAmount        decimal.Decimal        `json:"max_amount"`
    FeePercentage    decimal.Decimal        `json:"fee_percentage"`
    FeeFixed         decimal.Decimal        `json:"fee_fixed"`
    ConfirmationBlocks int                  `json:"confirmation_blocks"`
    IsActive         bool                   `json:"is_active"`
    Metadata         map[string]interface{} `json:"metadata"`
    CreatedAt        time.Time              `json:"created_at"`
    UpdatedAt        time.Time              `json:"updated_at"`
}

// Transaction represents a payment transaction
type Transaction struct {
    ID               uuid.UUID              `json:"id"`
    ReferenceID      string                 `json:"reference_id"`
    Type             string                 `json:"type"`
    FromAddress      string                 `json:"from_address,omitempty"`
    ToAddress        string                 `json:"to_address,omitempty"`
    MethodID         uuid.UUID              `json:"method_id"`
    Amount           decimal.Decimal        `json:"amount"`
    Currency         string                 `json:"currency"`
    USDCAmount       decimal.Decimal        `json:"usdc_amount"`
    ExchangeRate     decimal.Decimal        `json:"exchange_rate,omitempty"`
    Status           string                 `json:"status"`
    BlockchainTxHash string                 `json:"blockchain_tx_hash,omitempty"`
    BlockchainStatus string                 `json:"blockchain_status,omitempty"`
    Confirmations    int                    `json:"confirmations"`
    GasUsed          decimal.Decimal        `json:"gas_used,omitempty"`
    GasPrice         decimal.Decimal        `json:"gas_price,omitempty"`
    ErrorMessage     string                 `json:"error_message,omitempty"`
    Metadata         map[string]interface{} `json:"metadata"`
    CreatedAt        time.Time              `json:"created_at"`
    UpdatedAt        time.Time              `json:"updated_at"`
    CompletedAt      *time.Time             `json:"completed_at,omitempty"`
}

// ExchangeRate represents a currency exchange rate
type ExchangeRate struct {
    ID           uuid.UUID       `json:"id"`
    FromCurrency string          `json:"from_currency"`
    ToCurrency   string          `json:"to_currency"`
    Rate         decimal.Decimal `json:"rate"`
    Source       string          `json:"source"`
    Timestamp    time.Time       `json:"timestamp"`
}

// PaymentRoute represents a routing rule between payment methods
type PaymentRoute struct {
    ID             uuid.UUID       `json:"id"`
    SourceMethodID uuid.UUID       `json:"source_method_id"`
    TargetMethodID uuid.UUID       `json:"target_method_id"`
    MinAmount      decimal.Decimal `json:"min_amount"`
    MaxAmount      decimal.Decimal `json:"max_amount"`
    FeePercentage  decimal.Decimal `json:"fee_percentage"`
    FeeFixed       decimal.Decimal `json:"fee_fixed"`
    Priority       int             `json:"priority"`
    IsActive       bool            `json:"is_active"`
}

// PaymentGateway manages all payment operations
type PaymentGateway struct {
    db              *sql.DB
    rateProvider    ExchangeRateProvider
    blockchainClient BlockchainClient
    webhookHandler  WebhookHandler
    mu              sync.RWMutex
    methodCache     map[uuid.UUID]*PaymentMethod
    rateCache       map[string]*ExchangeRate
    rateCacheTTL    time.Duration
}

// ExchangeRateProvider interface for rate sources
type ExchangeRateProvider interface {
    GetRate(ctx context.Context, from, to string) (decimal.Decimal, error)
}

// BlockchainClient interface for blockchain operations
type BlockchainClient interface {
    SendTransaction(ctx context.Context, tx *Transaction) (string, error)
    GetTransactionStatus(ctx context.Context, txHash string) (string, int, error)
    EstimateGas(ctx context.Context, tx *Transaction) (decimal.Decimal, error)
}

// WebhookHandler interface for webhook processing
type WebhookHandler interface {
    HandleWebhook(ctx context.Context, event string, payload []byte) error
}

// NewPaymentGateway creates a new payment gateway instance
func NewPaymentGateway(db *sql.DB, rateProvider ExchangeRateProvider, 
    blockchainClient BlockchainClient, webhookHandler WebhookHandler) *PaymentGateway {
    pg := &PaymentGateway{
        db:              db,
        rateProvider:    rateProvider,
        blockchainClient: blockchainClient,
        webhookHandler:  webhookHandler,
        methodCache:     make(map[uuid.UUID]*PaymentMethod),
        rateCache:       make(map[string]*ExchangeRate),
        rateCacheTTL:    5 * time.Minute,
    }
    
    // Load payment methods into cache
    pg.loadPaymentMethods()
    
    // Start background tasks
    go pg.processMonitor()
    go pg.rateUpdater()
    
    return pg
}

// CreateTransaction creates a new payment transaction
func (pg *PaymentGateway) CreateTransaction(ctx context.Context, req TransactionRequest) (*Transaction, error) {
    // Validate payment method
    method, err := pg.GetPaymentMethod(ctx, req.MethodID)
    if err != nil {
        return nil, fmt.Errorf("invalid payment method: %w", err)
    }
    
    if !method.IsActive {
        return nil, errors.New("payment method is not active")
    }
    
    // Validate amount
    if req.Amount.LessThan(method.MinAmount) || req.Amount.GreaterThan(method.MaxAmount) {
        return nil, fmt.Errorf("amount out of range: min=%s, max=%s", 
            method.MinAmount.String(), method.MaxAmount.String())
    }
    
    // Convert to USDC
    usdcAmount, exchangeRate, err := pg.convertToUSDC(ctx, req.Amount, req.Currency)
    if err != nil {
        return nil, fmt.Errorf("currency conversion failed: %w", err)
    }
    
    // Calculate fees
    fee := pg.calculateFee(req.Amount, method)
    netAmount := req.Amount.Sub(fee)
    
    // Create transaction
    tx := &Transaction{
        ID:           uuid.New(),
        ReferenceID:  pg.generateReferenceID(),
        Type:         req.Type,
        FromAddress:  req.FromAddress,
        ToAddress:    req.ToAddress,
        MethodID:     req.MethodID,
        Amount:       req.Amount,
        Currency:     req.Currency,
        USDCAmount:   usdcAmount,
        ExchangeRate: exchangeRate,
        Status:       "pending",
        Metadata:     req.Metadata,
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
    }
    
    // Store transaction
    err = pg.storeTransaction(ctx, tx)
    if err != nil {
        return nil, fmt.Errorf("failed to store transaction: %w", err)
    }
    
    // Process transaction asynchronously
    go pg.processTransaction(context.Background(), tx)
    
    return tx, nil
}

// GetTransaction retrieves a transaction by ID or reference
func (pg *PaymentGateway) GetTransaction(ctx context.Context, idOrRef string) (*Transaction, error) {
    var tx Transaction
    var err error
    
    // Try as UUID first
    if id, parseErr := uuid.Parse(idOrRef); parseErr == nil {
        err = pg.db.QueryRowContext(ctx, `
            SELECT id, reference_id, type, from_address, to_address, method_id,
                   amount, currency, usdc_amount, exchange_rate, status,
                   blockchain_tx_hash, blockchain_status, confirmations,
                   gas_used, gas_price, error_message, metadata,
                   created_at, updated_at, completed_at
            FROM payment_transactions
            WHERE id = $1
        `, id).Scan(
            &tx.ID, &tx.ReferenceID, &tx.Type, &tx.FromAddress, &tx.ToAddress,
            &tx.MethodID, &tx.Amount, &tx.Currency, &tx.USDCAmount, &tx.ExchangeRate,
            &tx.Status, &tx.BlockchainTxHash, &tx.BlockchainStatus, &tx.Confirmations,
            &tx.GasUsed, &tx.GasPrice, &tx.ErrorMessage, &tx.Metadata,
            &tx.CreatedAt, &tx.UpdatedAt, &tx.CompletedAt,
        )
    } else {
        // Try as reference ID
        err = pg.db.QueryRowContext(ctx, `
            SELECT id, reference_id, type, from_address, to_address, method_id,
                   amount, currency, usdc_amount, exchange_rate, status,
                   blockchain_tx_hash, blockchain_status, confirmations,
                   gas_used, gas_price, error_message, metadata,
                   created_at, updated_at, completed_at
            FROM payment_transactions
            WHERE reference_id = $1
        `, idOrRef).Scan(
            &tx.ID, &tx.ReferenceID, &tx.Type, &tx.FromAddress, &tx.ToAddress,
            &tx.MethodID, &tx.Amount, &tx.Currency, &tx.USDCAmount, &tx.ExchangeRate,
            &tx.Status, &tx.BlockchainTxHash, &tx.BlockchainStatus, &tx.Confirmations,
            &tx.GasUsed, &tx.GasPrice, &tx.ErrorMessage, &tx.Metadata,
            &tx.CreatedAt, &tx.UpdatedAt, &tx.CompletedAt,
        )
    }
    
    if err != nil {
        return nil, err
    }
    
    return &tx, nil
}

// GetOptimalRoute finds the best payment route for a transaction
func (pg *PaymentGateway) GetOptimalRoute(ctx context.Context, 
    sourceMethod, targetMethod uuid.UUID, amount decimal.Decimal) (*PaymentRoute, error) {
    
    var routes []PaymentRoute
    
    err := pg.db.SelectContext(ctx, &routes, `
        SELECT id, source_method_id, target_method_id, min_amount, max_amount,
               fee_percentage, fee_fixed, priority, is_active
        FROM payment_routes
        WHERE source_method_id = $1 
          AND target_method_id = $2
          AND is_active = true
          AND $3 >= min_amount 
          AND $3 <= max_amount
        ORDER BY priority DESC, (fee_percentage + (fee_fixed / $3)) ASC
        LIMIT 1
    `, sourceMethod, targetMethod, amount)
    
    if err != nil {
        return nil, err
    }
    
    if len(routes) == 0 {
        return nil, errors.New("no available route")
    }
    
    return &routes[0], nil
}

// convertToUSDC converts amount to USDC using current exchange rates
func (pg *PaymentGateway) convertToUSDC(ctx context.Context, 
    amount decimal.Decimal, currency string) (decimal.Decimal, decimal.Decimal, error) {
    
    if currency == "USDC" {
        return amount, decimal.NewFromInt(1), nil
    }
    
    // Check cache first
    pg.mu.RLock()
    cacheKey := fmt.Sprintf("%s-USDC", currency)
    if rate, exists := pg.rateCache[cacheKey]; exists && 
        time.Since(rate.Timestamp) < pg.rateCacheTTL {
        pg.mu.RUnlock()
        usdcAmount := amount.Mul(rate.Rate)
        return usdcAmount, rate.Rate, nil
    }
    pg.mu.RUnlock()
    
    // Get fresh rate
    rate, err := pg.rateProvider.GetRate(ctx, currency, "USDC")
    if err != nil {
        return decimal.Zero, decimal.Zero, err
    }
    
    // Update cache
    pg.mu.Lock()
    pg.rateCache[cacheKey] = &ExchangeRate{
        FromCurrency: currency,
        ToCurrency:   "USDC",
        Rate:         rate,
        Source:       "provider",
        Timestamp:    time.Now(),
    }
    pg.mu.Unlock()
    
    // Store rate in database
    pg.storeExchangeRate(ctx, currency, "USDC", rate)
    
    usdcAmount := amount.Mul(rate)
    return usdcAmount, rate, nil
}

// calculateFee calculates transaction fee
func (pg *PaymentGateway) calculateFee(amount decimal.Decimal, method *PaymentMethod) decimal.Decimal {
    percentageFee := amount.Mul(method.FeePercentage).Div(decimal.NewFromInt(100))
    totalFee := percentageFee.Add(method.FeeFixed)
    return totalFee
}

// processTransaction handles transaction processing
func (pg *PaymentGateway) processTransaction(ctx context.Context, tx *Transaction) {
    // Estimate gas if blockchain transaction
    method, _ := pg.GetPaymentMethod(ctx, tx.MethodID)
    if method.Type == "crypto" {
        gasEstimate, err := pg.blockchainClient.EstimateGas(ctx, tx)
        if err != nil {
            pg.updateTransactionStatus(ctx, tx.ID, "failed", err.Error())
            return
        }
        tx.GasPrice = gasEstimate
    }
    
    // Send transaction
    txHash, err := pg.blockchainClient.SendTransaction(ctx, tx)
    if err != nil {
        pg.updateTransactionStatus(ctx, tx.ID, "failed", err.Error())
        return
    }
    
    // Update with transaction hash
    pg.updateTransactionHash(ctx, tx.ID, txHash)
    
    // Monitor transaction
    pg.monitorTransaction(ctx, tx.ID, txHash)
}

// monitorTransaction monitors blockchain transaction status
func (pg *PaymentGateway) monitorTransaction(ctx context.Context, txID uuid.UUID, txHash string) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    timeout := time.After(30 * time.Minute)
    
    for {
        select {
        case <-ticker.C:
            status, confirmations, err := pg.blockchainClient.GetTransactionStatus(ctx, txHash)
            if err != nil {
                log.Printf("Error checking transaction status: %v", err)
                continue
            }
            
            pg.updateBlockchainStatus(ctx, txID, status, confirmations)
            
            if status == "confirmed" {
                pg.updateTransactionStatus(ctx, txID, "completed", "")
                return
            } else if status == "failed" {
                pg.updateTransactionStatus(ctx, txID, "failed", "blockchain transaction failed")
                return
            }
            
        case <-timeout:
            pg.updateTransactionStatus(ctx, txID, "timeout", "transaction timeout")
            return
            
        case <-ctx.Done():
            return
        }
    }
}

// WebhookProcessor handles incoming webhooks
func (pg *PaymentGateway) ProcessWebhook(ctx context.Context, 
    source string, eventType string, payload []byte, signature string) error {
    
    // Store webhook
    webhookID := uuid.New()
    _, err := pg.db.ExecContext(ctx, `
        INSERT INTO payment_webhooks (id, event_type, payload, signature, source, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, webhookID, eventType, payload, signature, source, time.Now())
    
    if err != nil {
        return err
    }
    
    // Process webhook
    err = pg.webhookHandler.HandleWebhook(ctx, eventType, payload)
    if err != nil {
        return err
    }
    
    // Mark as processed
    _, err = pg.db.ExecContext(ctx, `
        UPDATE payment_webhooks SET processed = true WHERE id = $1
    `, webhookID)
    
    return err
}

// Helper methods

func (pg *PaymentGateway) loadPaymentMethods() {
    rows, err := pg.db.Query(`
        SELECT id, name, type, network, contract_address, decimals,
               min_amount, max_amount, fee_percentage, fee_fixed,
               confirmation_blocks, is_active, metadata
        FROM payment_methods
        WHERE is_active = true
    `)
    if err != nil {
        log.Printf("Error loading payment methods: %v", err)
        return
    }
    defer rows.Close()
    
    pg.mu.Lock()
    defer pg.mu.Unlock()
    
    for rows.Next() {
        var method PaymentMethod
        var metadata json.RawMessage
        
        err := rows.Scan(
            &method.ID, &method.Name, &method.Type, &method.Network,
            &method.ContractAddress, &method.Decimals, &method.MinAmount,
            &method.MaxAmount, &method.FeePercentage, &method.FeeFixed,
            &method.ConfirmationBlocks, &method.IsActive, &metadata,
        )
        if err != nil {
            log.Printf("Error scanning payment method: %v", err)
            continue
        }
        
        json.Unmarshal(metadata, &method.Metadata)
        pg.methodCache[method.ID] = &method
    }
}

func (pg *PaymentGateway) generateReferenceID() string {
    return fmt.Sprintf("PAY-%d-%s", time.Now().Unix(), uuid.New().String()[:8])
}

func (pg *PaymentGateway) storeTransaction(ctx context.Context, tx *Transaction) error {
    metadata, _ := json.Marshal(tx.Metadata)
    
    _, err := pg.db.ExecContext(ctx, `
        INSERT INTO payment_transactions (
            id, reference_id, type, from_address, to_address, method_id,
            amount, currency, usdc_amount, exchange_rate, status, metadata,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
    `, tx.ID, tx.ReferenceID, tx.Type, tx.FromAddress, tx.ToAddress, tx.MethodID,
       tx.Amount, tx.Currency, tx.USDCAmount, tx.ExchangeRate, tx.Status, metadata,
       tx.CreatedAt, tx.UpdatedAt)
    
    return err
}

func (pg *PaymentGateway) updateTransactionStatus(ctx context.Context, 
    txID uuid.UUID, status, errorMsg string) error {
    
    query := `
        UPDATE payment_transactions 
        SET status = $1, error_message = $2, updated_at = $3
    `
    args := []interface{}{status, errorMsg, time.Now()}
    
    if status == "completed" {
        query += ", completed_at = $4 WHERE id = $5"
        args = append(args, time.Now(), txID)
    } else {
        query += " WHERE id = $4"
        args = append(args, txID)
    }
    
    _, err := pg.db.ExecContext(ctx, query, args...)
    return err
}

func (pg *PaymentGateway) updateTransactionHash(ctx context.Context, 
    txID uuid.UUID, txHash string) error {
    
    _, err := pg.db.ExecContext(ctx, `
        UPDATE payment_transactions 
        SET blockchain_tx_hash = $1, updated_at = $2
        WHERE id = $3
    `, txHash, time.Now(), txID)
    
    return err
}

func (pg *PaymentGateway) updateBlockchainStatus(ctx context.Context, 
    txID uuid.UUID, status string, confirmations int) error {
    
    _, err := pg.db.ExecContext(ctx, `
        UPDATE payment_transactions 
        SET blockchain_status = $1, confirmations = $2, updated_at = $3
        WHERE id = $4
    `, status, confirmations, time.Now(), txID)
    
    return err
}

func (pg *PaymentGateway) storeExchangeRate(ctx context.Context, 
    from, to string, rate decimal.Decimal) {
    
    _, err := pg.db.ExecContext(ctx, `
        INSERT INTO exchange_rates (id, from_currency, to_currency, rate, source, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, uuid.New(), from, to, rate, "provider", time.Now())
    
    if err != nil {
        log.Printf("Error storing exchange rate: %v", err)
    }
}

// Background processes

func (pg *PaymentGateway) processMonitor() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        ctx := context.Background()
        
        // Check pending transactions
        rows, err := pg.db.QueryContext(ctx, `
            SELECT id, blockchain_tx_hash 
            FROM payment_transactions
            WHERE status = 'pending' 
              AND blockchain_tx_hash IS NOT NULL
              AND created_at > NOW() - INTERVAL '1 hour'
        `)
        if err != nil {
            log.Printf("Error querying pending transactions: %v", err)
            continue
        }
        
        for rows.Next() {
            var txID uuid.UUID
            var txHash string
            
            if err := rows.Scan(&txID, &txHash); err != nil {
                continue
            }
            
            go pg.monitorTransaction(ctx, txID, txHash)
        }
        rows.Close()
    }
}

func (pg *PaymentGateway) rateUpdater() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    currencies := []string{"ETH", "BTC", "MATIC", "BNB"}
    
    for range ticker.C {
        ctx := context.Background()
        
        for _, currency := range currencies {
            rate, err := pg.rateProvider.GetRate(ctx, currency, "USDC")
            if err != nil {
                log.Printf("Error fetching rate for %s: %v", currency, err)
                continue
            }
            
            pg.mu.Lock()
            cacheKey := fmt.Sprintf("%s-USDC", currency)
            pg.rateCache[cacheKey] = &ExchangeRate{
                FromCurrency: currency,
                ToCurrency:   "USDC",
                Rate:         rate,
                Source:       "provider",
                Timestamp:    time.Now(),
            }
            pg.mu.Unlock()
            
            pg.storeExchangeRate(ctx, currency, "USDC", rate)
        }
    }
}

// TransactionRequest represents a payment request
type TransactionRequest struct {
    Type        string                 `json:"type"`
    MethodID    uuid.UUID              `json:"method_id"`
    FromAddress string                 `json:"from_address,omitempty"`
    ToAddress   string                 `json:"to_address,omitempty"`
    Amount      decimal.Decimal        `json:"amount"`
    Currency    string                 `json:"currency"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GetPaymentMethod retrieves a payment method by ID
func (pg *PaymentGateway) GetPaymentMethod(ctx context.Context, id uuid.UUID) (*PaymentMethod, error) {
    pg.mu.RLock()
    if method, exists := pg.methodCache[id]; exists {
        pg.mu.RUnlock()
        return method, nil
    }
    pg.mu.RUnlock()
    
    var method PaymentMethod
    var metadata json.RawMessage
    
    err := pg.db.QueryRowContext(ctx, `
        SELECT id, name, type, network, contract_address, decimals,
               min_amount, max_amount, fee_percentage, fee_fixed,
               confirmation_blocks, is_active, metadata, created_at, updated_at
        FROM payment_methods
        WHERE id = $1
    `, id).Scan(
        &method.ID, &method.Name, &method.Type, &method.Network,
        &method.ContractAddress, &method.Decimals, &method.MinAmount,
        &method.MaxAmount, &method.FeePercentage, &method.FeeFixed,
        &method.ConfirmationBlocks, &method.IsActive, &metadata,
        &method.CreatedAt, &method.UpdatedAt,
    )
    
    if err != nil {
        return nil, err
    }
    
    json.Unmarshal(metadata, &method.Metadata)
    
    // Update cache
    pg.mu.Lock()
    pg.methodCache[id] = &method
    pg.mu.Unlock()
    
    return &method, nil
}
```

## Integration Points

### Contract Service Integration
```go
// Link payment to contract
func (pg *PaymentGateway) LinkToContract(ctx context.Context, 
    paymentID, contractID uuid.UUID) error {
    
    // Update payment metadata
    _, err := pg.db.ExecContext(ctx, `
        UPDATE payment_transactions 
        SET metadata = jsonb_set(metadata, '{contract_id}', to_jsonb($1::text))
        WHERE id = $2
    `, contractID.String(), paymentID)
    
    return err
}
```

### Escrow Service Integration
```go
// Create escrow payment
func (pg *PaymentGateway) CreateEscrowPayment(ctx context.Context, 
    escrowID uuid.UUID, amount decimal.Decimal, currency string) (*Transaction, error) {
    
    req := TransactionRequest{
        Type:     "escrow",
        Amount:   amount,
        Currency: currency,
        Metadata: map[string]interface{}{
            "escrow_id": escrowID.String(),
        },
    }
    
    return pg.CreateTransaction(ctx, req)
}
```

### Channel Service Integration
```go
// Process channel payment
func (pg *PaymentGateway) ProcessChannelPayment(ctx context.Context, 
    channelID uuid.UUID, payment *ChannelPayment) (*Transaction, error) {
    
    req := TransactionRequest{
        Type:        "channel",
        FromAddress: payment.From,
        ToAddress:   payment.To,
        Amount:      payment.Amount,
        Currency:    payment.Currency,
        Metadata: map[string]interface{}{
            "channel_id": channelID.String(),
            "sequence":   payment.Sequence,
        },
    }
    
    return pg.CreateTransaction(ctx, req)
}
```

## API Endpoints

```go
// HTTP handlers
func (pg *PaymentGateway) RegisterHandlers(router *mux.Router) {
    router.HandleFunc("/payments", pg.handleCreatePayment).Methods("POST")
    router.HandleFunc("/payments/{id}", pg.handleGetPayment).Methods("GET")
    router.HandleFunc("/payments/{id}/status", pg.handleGetStatus).Methods("GET")
    router.HandleFunc("/payment-methods", pg.handleListMethods).Methods("GET")
    router.HandleFunc("/exchange-rates", pg.handleGetRates).Methods("GET")
    router.HandleFunc("/webhooks/{source}", pg.handleWebhook).Methods("POST")
}
```