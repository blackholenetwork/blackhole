# U19: Accounting Service

## Overview
Comprehensive transaction logging, real-time balance tracking, financial reporting and analytics, with export capabilities for tax compliance.

## Database Schema

```sql
-- Account ledger
CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    account_type VARCHAR(20) NOT NULL CHECK (account_type IN ('user', 'escrow', 'system', 'fee')),
    currency VARCHAR(10) NOT NULL,
    balance DECIMAL(36,18) NOT NULL DEFAULT 0,
    available_balance DECIMAL(36,18) NOT NULL DEFAULT 0,
    locked_balance DECIMAL(36,18) NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, account_type, currency)
);

-- Double-entry bookkeeping journal
CREATE TABLE journal_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL,
    entry_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL,
    reference_type VARCHAR(50),
    reference_id UUID,
    status VARCHAR(20) DEFAULT 'pending',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    posted_at TIMESTAMPTZ
);

-- Journal entry lines (debits and credits)
CREATE TABLE journal_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_id UUID NOT NULL REFERENCES journal_entries(id),
    account_id UUID NOT NULL REFERENCES accounts(id),
    debit_amount DECIMAL(36,18) DEFAULT 0,
    credit_amount DECIMAL(36,18) DEFAULT 0,
    currency VARCHAR(10) NOT NULL,
    exchange_rate DECIMAL(36,18) DEFAULT 1,
    base_debit_amount DECIMAL(36,18) DEFAULT 0,
    base_credit_amount DECIMAL(36,18) DEFAULT 0,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_amounts CHECK (
        (debit_amount > 0 AND credit_amount = 0) OR 
        (debit_amount = 0 AND credit_amount > 0)
    )
);

-- Account balances history
CREATE TABLE balance_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    balance DECIMAL(36,18) NOT NULL,
    available_balance DECIMAL(36,18) NOT NULL,
    locked_balance DECIMAL(36,18) NOT NULL,
    change_amount DECIMAL(36,18) NOT NULL,
    change_type VARCHAR(20) NOT NULL,
    journal_entry_id UUID REFERENCES journal_entries(id),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Financial reports
CREATE TABLE financial_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type VARCHAR(50) NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    currency VARCHAR(10) NOT NULL,
    data JSONB NOT NULL,
    metadata JSONB DEFAULT '{}',
    generated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    generated_by UUID
);

-- Tax reports
CREATE TABLE tax_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    tax_year INT NOT NULL,
    jurisdiction VARCHAR(10) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    gross_income DECIMAL(36,18) NOT NULL DEFAULT 0,
    deductible_fees DECIMAL(36,18) NOT NULL DEFAULT 0,
    net_income DECIMAL(36,18) NOT NULL DEFAULT 0,
    transactions JSONB NOT NULL DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    generated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, tax_year, jurisdiction, report_type)
);

-- Audit trail
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    action VARCHAR(50) NOT NULL,
    user_id UUID,
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_accounts_user ON accounts(user_id);
CREATE INDEX idx_accounts_balance ON accounts(balance) WHERE balance > 0;
CREATE INDEX idx_journal_entries_date ON journal_entries(entry_date);
CREATE INDEX idx_journal_entries_reference ON journal_entries(reference_type, reference_id);
CREATE INDEX idx_journal_lines_account ON journal_lines(account_id);
CREATE INDEX idx_balance_history_account ON balance_history(account_id, timestamp DESC);
CREATE INDEX idx_financial_reports_period ON financial_reports(period_start, period_end);
CREATE INDEX idx_tax_reports_user ON tax_reports(user_id, tax_year);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id, created_at DESC);

-- Constraints to ensure double-entry balance
CREATE OR REPLACE FUNCTION check_journal_balance() RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT SUM(debit_amount) != SUM(credit_amount) 
        FROM journal_lines 
        WHERE entry_id = NEW.entry_id) THEN
        RAISE EXCEPTION 'Journal entry must balance (debits = credits)';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ensure_journal_balance
    AFTER INSERT OR UPDATE ON journal_lines
    FOR EACH ROW
    EXECUTE FUNCTION check_journal_balance();
```

## Go Implementation

```go
package accounting

import (
    "context"
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/shopspring/decimal"
)

// Account represents a financial account
type Account struct {
    ID               uuid.UUID              `json:"id"`
    UserID           uuid.UUID              `json:"user_id"`
    AccountType      string                 `json:"account_type"`
    Currency         string                 `json:"currency"`
    Balance          decimal.Decimal        `json:"balance"`
    AvailableBalance decimal.Decimal        `json:"available_balance"`
    LockedBalance    decimal.Decimal        `json:"locked_balance"`
    Metadata         map[string]interface{} `json:"metadata"`
    CreatedAt        time.Time              `json:"created_at"`
    UpdatedAt        time.Time              `json:"updated_at"`
}

// JournalEntry represents a double-entry bookkeeping entry
type JournalEntry struct {
    ID            uuid.UUID              `json:"id"`
    TransactionID uuid.UUID              `json:"transaction_id"`
    EntryDate     time.Time              `json:"entry_date"`
    Description   string                 `json:"description"`
    ReferenceType string                 `json:"reference_type,omitempty"`
    ReferenceID   uuid.UUID              `json:"reference_id,omitempty"`
    Status        string                 `json:"status"`
    Lines         []JournalLine          `json:"lines"`
    Metadata      map[string]interface{} `json:"metadata"`
    CreatedAt     time.Time              `json:"created_at"`
    PostedAt      *time.Time             `json:"posted_at,omitempty"`
}

// JournalLine represents a debit or credit line
type JournalLine struct {
    ID              uuid.UUID       `json:"id"`
    EntryID         uuid.UUID       `json:"entry_id"`
    AccountID       uuid.UUID       `json:"account_id"`
    DebitAmount     decimal.Decimal `json:"debit_amount"`
    CreditAmount    decimal.Decimal `json:"credit_amount"`
    Currency        string          `json:"currency"`
    ExchangeRate    decimal.Decimal `json:"exchange_rate"`
    BaseDebitAmount decimal.Decimal `json:"base_debit_amount"`
    BaseCreditAmount decimal.Decimal `json:"base_credit_amount"`
    Description     string          `json:"description"`
}

// BalanceChange represents a change in account balance
type BalanceChange struct {
    AccountID      uuid.UUID       `json:"account_id"`
    Amount         decimal.Decimal `json:"amount"`
    ChangeType     string          `json:"change_type"`
    JournalEntryID uuid.UUID       `json:"journal_entry_id"`
}

// FinancialReport represents a generated financial report
type FinancialReport struct {
    ID          uuid.UUID              `json:"id"`
    ReportType  string                 `json:"report_type"`
    PeriodStart time.Time              `json:"period_start"`
    PeriodEnd   time.Time              `json:"period_end"`
    Currency    string                 `json:"currency"`
    Data        map[string]interface{} `json:"data"`
    Metadata    map[string]interface{} `json:"metadata"`
    GeneratedAt time.Time              `json:"generated_at"`
    GeneratedBy uuid.UUID              `json:"generated_by,omitempty"`
}

// TaxReport represents a tax compliance report
type TaxReport struct {
    ID             uuid.UUID       `json:"id"`
    UserID         uuid.UUID       `json:"user_id"`
    TaxYear        int             `json:"tax_year"`
    Jurisdiction   string          `json:"jurisdiction"`
    ReportType     string          `json:"report_type"`
    GrossIncome    decimal.Decimal `json:"gross_income"`
    DeductibleFees decimal.Decimal `json:"deductible_fees"`
    NetIncome      decimal.Decimal `json:"net_income"`
    Transactions   []interface{}   `json:"transactions"`
    Metadata       map[string]interface{} `json:"metadata"`
    GeneratedAt    time.Time       `json:"generated_at"`
}

// AccountingService manages all accounting operations
type AccountingService struct {
    db            *sql.DB
    baseCurrency  string
    mu            sync.RWMutex
    accountCache  map[uuid.UUID]*Account
    balanceLocks  map[uuid.UUID]*sync.Mutex
}

// NewAccountingService creates a new accounting service
func NewAccountingService(db *sql.DB, baseCurrency string) *AccountingService {
    as := &AccountingService{
        db:           db,
        baseCurrency: baseCurrency,
        accountCache: make(map[uuid.UUID]*Account),
        balanceLocks: make(map[uuid.UUID]*sync.Mutex),
    }
    
    // Start periodic tasks
    go as.balanceReconciliation()
    go as.reportGenerator()
    
    return as
}

// CreateAccount creates a new account
func (as *AccountingService) CreateAccount(ctx context.Context, 
    userID uuid.UUID, accountType, currency string) (*Account, error) {
    
    // Validate account type
    validTypes := map[string]bool{
        "user": true, "escrow": true, "system": true, "fee": true,
    }
    if !validTypes[accountType] {
        return nil, errors.New("invalid account type")
    }
    
    account := &Account{
        ID:               uuid.New(),
        UserID:           userID,
        AccountType:      accountType,
        Currency:         currency,
        Balance:          decimal.Zero,
        AvailableBalance: decimal.Zero,
        LockedBalance:    decimal.Zero,
        CreatedAt:        time.Now(),
        UpdatedAt:        time.Now(),
    }
    
    // Insert account
    _, err := as.db.ExecContext(ctx, `
        INSERT INTO accounts (
            id, user_id, account_type, currency, balance, 
            available_balance, locked_balance, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, account.ID, account.UserID, account.AccountType, account.Currency,
       account.Balance, account.AvailableBalance, account.LockedBalance,
       account.CreatedAt, account.UpdatedAt)
    
    if err != nil {
        return nil, fmt.Errorf("failed to create account: %w", err)
    }
    
    // Initialize balance lock
    as.mu.Lock()
    as.balanceLocks[account.ID] = &sync.Mutex{}
    as.mu.Unlock()
    
    return account, nil
}

// GetAccount retrieves an account by ID
func (as *AccountingService) GetAccount(ctx context.Context, accountID uuid.UUID) (*Account, error) {
    // Check cache
    as.mu.RLock()
    if account, exists := as.accountCache[accountID]; exists {
        as.mu.RUnlock()
        return account, nil
    }
    as.mu.RUnlock()
    
    var account Account
    var metadata json.RawMessage
    
    err := as.db.QueryRowContext(ctx, `
        SELECT id, user_id, account_type, currency, balance,
               available_balance, locked_balance, metadata, created_at, updated_at
        FROM accounts
        WHERE id = $1
    `, accountID).Scan(
        &account.ID, &account.UserID, &account.AccountType, &account.Currency,
        &account.Balance, &account.AvailableBalance, &account.LockedBalance,
        &metadata, &account.CreatedAt, &account.UpdatedAt,
    )
    
    if err != nil {
        return nil, err
    }
    
    json.Unmarshal(metadata, &account.Metadata)
    
    // Update cache
    as.mu.Lock()
    as.accountCache[accountID] = &account
    as.mu.Unlock()
    
    return &account, nil
}

// CreateJournalEntry creates a new journal entry with balanced debits and credits
func (as *AccountingService) CreateJournalEntry(ctx context.Context, 
    entry *JournalEntry) error {
    
    // Validate entry balance
    var totalDebits, totalCredits decimal.Decimal
    for _, line := range entry.Lines {
        totalDebits = totalDebits.Add(line.DebitAmount)
        totalCredits = totalCredits.Add(line.CreditAmount)
    }
    
    if !totalDebits.Equal(totalCredits) {
        return fmt.Errorf("journal entry not balanced: debits=%s, credits=%s", 
            totalDebits.String(), totalCredits.String())
    }
    
    // Begin transaction
    tx, err := as.db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    // Create journal entry
    entry.ID = uuid.New()
    entry.CreatedAt = time.Now()
    entry.Status = "pending"
    
    metadata, _ := json.Marshal(entry.Metadata)
    
    _, err = tx.ExecContext(ctx, `
        INSERT INTO journal_entries (
            id, transaction_id, entry_date, description,
            reference_type, reference_id, status, metadata, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, entry.ID, entry.TransactionID, entry.EntryDate, entry.Description,
       entry.ReferenceType, entry.ReferenceID, entry.Status, metadata, entry.CreatedAt)
    
    if err != nil {
        return fmt.Errorf("failed to create journal entry: %w", err)
    }
    
    // Create journal lines
    for _, line := range entry.Lines {
        line.ID = uuid.New()
        line.EntryID = entry.ID
        
        // Calculate base amounts
        if line.ExchangeRate.IsZero() {
            line.ExchangeRate = decimal.NewFromInt(1)
        }
        line.BaseDebitAmount = line.DebitAmount.Mul(line.ExchangeRate)
        line.BaseCreditAmount = line.CreditAmount.Mul(line.ExchangeRate)
        
        _, err = tx.ExecContext(ctx, `
            INSERT INTO journal_lines (
                id, entry_id, account_id, debit_amount, credit_amount,
                currency, exchange_rate, base_debit_amount, base_credit_amount, description
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `, line.ID, line.EntryID, line.AccountID, line.DebitAmount, line.CreditAmount,
           line.Currency, line.ExchangeRate, line.BaseDebitAmount, line.BaseCreditAmount, 
           line.Description)
        
        if err != nil {
            return fmt.Errorf("failed to create journal line: %w", err)
        }
    }
    
    // Post entry immediately
    err = as.postJournalEntry(ctx, tx, entry.ID)
    if err != nil {
        return fmt.Errorf("failed to post journal entry: %w", err)
    }
    
    return tx.Commit()
}

// postJournalEntry posts a journal entry and updates account balances
func (as *AccountingService) postJournalEntry(ctx context.Context, 
    tx *sql.Tx, entryID uuid.UUID) error {
    
    // Get all lines for this entry
    rows, err := tx.QueryContext(ctx, `
        SELECT account_id, debit_amount, credit_amount
        FROM journal_lines
        WHERE entry_id = $1
    `, entryID)
    if err != nil {
        return err
    }
    defer rows.Close()
    
    balanceChanges := make(map[uuid.UUID]decimal.Decimal)
    
    for rows.Next() {
        var accountID uuid.UUID
        var debit, credit decimal.Decimal
        
        err := rows.Scan(&accountID, &debit, &credit)
        if err != nil {
            return err
        }
        
        // Calculate net change (debits increase, credits decrease)
        change := debit.Sub(credit)
        balanceChanges[accountID] = balanceChanges[accountID].Add(change)
    }
    
    // Update account balances
    for accountID, change := range balanceChanges {
        // Lock account for balance update
        as.mu.RLock()
        lock, exists := as.balanceLocks[accountID]
        as.mu.RUnlock()
        
        if !exists {
            lock = &sync.Mutex{}
            as.mu.Lock()
            as.balanceLocks[accountID] = lock
            as.mu.Unlock()
        }
        
        lock.Lock()
        defer lock.Unlock()
        
        // Update balance
        _, err := tx.ExecContext(ctx, `
            UPDATE accounts
            SET balance = balance + $1,
                available_balance = available_balance + $1,
                updated_at = $2
            WHERE id = $3
        `, change, time.Now(), accountID)
        
        if err != nil {
            return fmt.Errorf("failed to update account balance: %w", err)
        }
        
        // Record balance history
        _, err = tx.ExecContext(ctx, `
            INSERT INTO balance_history (
                id, account_id, balance, available_balance, locked_balance,
                change_amount, change_type, journal_entry_id, timestamp
            )
            SELECT 
                $1, id, balance, available_balance, locked_balance,
                $2, $3, $4, $5
            FROM accounts
            WHERE id = $6
        `, uuid.New(), change, "journal", entryID, time.Now(), accountID)
        
        if err != nil {
            return fmt.Errorf("failed to record balance history: %w", err)
        }
        
        // Clear cache
        as.mu.Lock()
        delete(as.accountCache, accountID)
        as.mu.Unlock()
    }
    
    // Mark entry as posted
    _, err = tx.ExecContext(ctx, `
        UPDATE journal_entries
        SET status = 'posted', posted_at = $1
        WHERE id = $2
    `, time.Now(), entryID)
    
    return err
}

// LockFunds locks funds in an account
func (as *AccountingService) LockFunds(ctx context.Context, 
    accountID uuid.UUID, amount decimal.Decimal, reason string) error {
    
    // Get lock for account
    as.mu.RLock()
    lock, exists := as.balanceLocks[accountID]
    as.mu.RUnlock()
    
    if !exists {
        return errors.New("account not found")
    }
    
    lock.Lock()
    defer lock.Unlock()
    
    // Check available balance
    var availableBalance decimal.Decimal
    err := as.db.QueryRowContext(ctx, `
        SELECT available_balance FROM accounts WHERE id = $1
    `, accountID).Scan(&availableBalance)
    
    if err != nil {
        return err
    }
    
    if availableBalance.LessThan(amount) {
        return errors.New("insufficient available balance")
    }
    
    // Update balances
    _, err = as.db.ExecContext(ctx, `
        UPDATE accounts
        SET available_balance = available_balance - $1,
            locked_balance = locked_balance + $1,
            updated_at = $2
        WHERE id = $3
    `, amount, time.Now(), accountID)
    
    if err != nil {
        return err
    }
    
    // Record in balance history
    _, err = as.db.ExecContext(ctx, `
        INSERT INTO balance_history (
            id, account_id, balance, available_balance, locked_balance,
            change_amount, change_type, timestamp
        )
        SELECT 
            $1, id, balance, available_balance, locked_balance,
            $2, $3, $4
        FROM accounts
        WHERE id = $5
    `, uuid.New(), amount, "lock:"+reason, time.Now(), accountID)
    
    // Clear cache
    as.mu.Lock()
    delete(as.accountCache, accountID)
    as.mu.Unlock()
    
    return err
}

// UnlockFunds unlocks funds in an account
func (as *AccountingService) UnlockFunds(ctx context.Context, 
    accountID uuid.UUID, amount decimal.Decimal, reason string) error {
    
    // Get lock for account
    as.mu.RLock()
    lock, exists := as.balanceLocks[accountID]
    as.mu.RUnlock()
    
    if !exists {
        return errors.New("account not found")
    }
    
    lock.Lock()
    defer lock.Unlock()
    
    // Check locked balance
    var lockedBalance decimal.Decimal
    err := as.db.QueryRowContext(ctx, `
        SELECT locked_balance FROM accounts WHERE id = $1
    `, accountID).Scan(&lockedBalance)
    
    if err != nil {
        return err
    }
    
    if lockedBalance.LessThan(amount) {
        return errors.New("insufficient locked balance")
    }
    
    // Update balances
    _, err = as.db.ExecContext(ctx, `
        UPDATE accounts
        SET available_balance = available_balance + $1,
            locked_balance = locked_balance - $1,
            updated_at = $2
        WHERE id = $3
    `, amount, time.Now(), accountID)
    
    if err != nil {
        return err
    }
    
    // Record in balance history
    _, err = as.db.ExecContext(ctx, `
        INSERT INTO balance_history (
            id, account_id, balance, available_balance, locked_balance,
            change_amount, change_type, timestamp
        )
        SELECT 
            $1, id, balance, available_balance, locked_balance,
            $2, $3, $4
        FROM accounts
        WHERE id = $5
    `, uuid.New(), amount, "unlock:"+reason, time.Now(), accountID)
    
    // Clear cache
    as.mu.Lock()
    delete(as.accountCache, accountID)
    as.mu.Unlock()
    
    return err
}

// GenerateFinancialReport generates a financial report
func (as *AccountingService) GenerateFinancialReport(ctx context.Context, 
    reportType string, periodStart, periodEnd time.Time, currency string) (*FinancialReport, error) {
    
    report := &FinancialReport{
        ID:          uuid.New(),
        ReportType:  reportType,
        PeriodStart: periodStart,
        PeriodEnd:   periodEnd,
        Currency:    currency,
        Data:        make(map[string]interface{}),
        GeneratedAt: time.Now(),
    }
    
    switch reportType {
    case "income_statement":
        data, err := as.generateIncomeStatement(ctx, periodStart, periodEnd, currency)
        if err != nil {
            return nil, err
        }
        report.Data = data
        
    case "balance_sheet":
        data, err := as.generateBalanceSheet(ctx, periodEnd, currency)
        if err != nil {
            return nil, err
        }
        report.Data = data
        
    case "cash_flow":
        data, err := as.generateCashFlow(ctx, periodStart, periodEnd, currency)
        if err != nil {
            return nil, err
        }
        report.Data = data
        
    default:
        return nil, errors.New("unsupported report type")
    }
    
    // Store report
    reportData, _ := json.Marshal(report.Data)
    metadata, _ := json.Marshal(report.Metadata)
    
    _, err := as.db.ExecContext(ctx, `
        INSERT INTO financial_reports (
            id, report_type, period_start, period_end, currency,
            data, metadata, generated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, report.ID, report.ReportType, report.PeriodStart, report.PeriodEnd,
       report.Currency, reportData, metadata, report.GeneratedAt)
    
    if err != nil {
        return nil, err
    }
    
    return report, nil
}

// GenerateTaxReport generates a tax compliance report
func (as *AccountingService) GenerateTaxReport(ctx context.Context, 
    userID uuid.UUID, taxYear int, jurisdiction string) (*TaxReport, error) {
    
    // Get all transactions for the tax year
    startDate := time.Date(taxYear, 1, 1, 0, 0, 0, 0, time.UTC)
    endDate := time.Date(taxYear+1, 1, 1, 0, 0, 0, 0, time.UTC)
    
    rows, err := as.db.QueryContext(ctx, `
        SELECT 
            je.id, je.transaction_id, je.entry_date, je.description,
            jl.debit_amount, jl.credit_amount, jl.currency, jl.exchange_rate,
            a.account_type
        FROM journal_entries je
        JOIN journal_lines jl ON jl.entry_id = je.id
        JOIN accounts a ON a.id = jl.account_id
        WHERE a.user_id = $1
          AND je.entry_date >= $2
          AND je.entry_date < $3
          AND je.status = 'posted'
        ORDER BY je.entry_date
    `, userID, startDate, endDate)
    
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var grossIncome, deductibleFees decimal.Decimal
    var transactions []interface{}
    
    for rows.Next() {
        var tx struct {
            ID           uuid.UUID       `json:"id"`
            Date         time.Time       `json:"date"`
            Description  string          `json:"description"`
            Amount       decimal.Decimal `json:"amount"`
            Currency     string          `json:"currency"`
            ExchangeRate decimal.Decimal `json:"exchange_rate"`
            Type         string          `json:"type"`
        }
        
        var debit, credit decimal.Decimal
        var accountType string
        
        err := rows.Scan(
            &tx.ID, &tx.ID, &tx.Date, &tx.Description,
            &debit, &credit, &tx.Currency, &tx.ExchangeRate,
            &accountType,
        )
        if err != nil {
            continue
        }
        
        // Calculate income and fees
        if accountType == "user" {
            if credit.GreaterThan(decimal.Zero) {
                // Income
                tx.Amount = credit
                tx.Type = "income"
                baseAmount := credit.Mul(tx.ExchangeRate)
                grossIncome = grossIncome.Add(baseAmount)
            } else if debit.GreaterThan(decimal.Zero) {
                // Fee/expense
                tx.Amount = debit
                tx.Type = "fee"
                baseAmount := debit.Mul(tx.ExchangeRate)
                deductibleFees = deductibleFees.Add(baseAmount)
            }
            
            transactions = append(transactions, tx)
        }
    }
    
    netIncome := grossIncome.Sub(deductibleFees)
    
    report := &TaxReport{
        ID:             uuid.New(),
        UserID:         userID,
        TaxYear:        taxYear,
        Jurisdiction:   jurisdiction,
        ReportType:     "annual",
        GrossIncome:    grossIncome,
        DeductibleFees: deductibleFees,
        NetIncome:      netIncome,
        Transactions:   transactions,
        GeneratedAt:    time.Now(),
    }
    
    // Store report
    txData, _ := json.Marshal(transactions)
    metadata, _ := json.Marshal(report.Metadata)
    
    _, err = as.db.ExecContext(ctx, `
        INSERT INTO tax_reports (
            id, user_id, tax_year, jurisdiction, report_type,
            gross_income, deductible_fees, net_income, transactions,
            metadata, generated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (user_id, tax_year, jurisdiction, report_type)
        DO UPDATE SET
            gross_income = $6,
            deductible_fees = $7,
            net_income = $8,
            transactions = $9,
            metadata = $10,
            generated_at = $11
    `, report.ID, report.UserID, report.TaxYear, report.Jurisdiction,
       report.ReportType, report.GrossIncome, report.DeductibleFees,
       report.NetIncome, txData, metadata, report.GeneratedAt)
    
    if err != nil {
        return nil, err
    }
    
    return report, nil
}

// Helper methods for report generation

func (as *AccountingService) generateIncomeStatement(ctx context.Context, 
    periodStart, periodEnd time.Time, currency string) (map[string]interface{}, error) {
    
    // Query revenue and expenses
    var revenue, expenses decimal.Decimal
    
    err := as.db.QueryRowContext(ctx, `
        SELECT 
            COALESCE(SUM(CASE WHEN a.account_type = 'user' THEN jl.credit_amount ELSE 0 END), 0) as revenue,
            COALESCE(SUM(CASE WHEN a.account_type = 'fee' THEN jl.debit_amount ELSE 0 END), 0) as expenses
        FROM journal_entries je
        JOIN journal_lines jl ON jl.entry_id = je.id
        JOIN accounts a ON a.id = jl.account_id
        WHERE je.entry_date >= $1 
          AND je.entry_date <= $2
          AND je.status = 'posted'
          AND jl.currency = $3
    `, periodStart, periodEnd, currency).Scan(&revenue, &expenses)
    
    if err != nil {
        return nil, err
    }
    
    netIncome := revenue.Sub(expenses)
    
    return map[string]interface{}{
        "revenue":    revenue,
        "expenses":   expenses,
        "net_income": netIncome,
        "period": map[string]interface{}{
            "start": periodStart,
            "end":   periodEnd,
        },
    }, nil
}

func (as *AccountingService) generateBalanceSheet(ctx context.Context, 
    asOfDate time.Time, currency string) (map[string]interface{}, error) {
    
    // Query account balances by type
    rows, err := as.db.QueryContext(ctx, `
        SELECT 
            account_type,
            SUM(balance) as total_balance
        FROM accounts
        WHERE currency = $1
          AND created_at <= $2
        GROUP BY account_type
    `, currency, asOfDate)
    
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    balances := make(map[string]decimal.Decimal)
    var totalAssets, totalLiabilities decimal.Decimal
    
    for rows.Next() {
        var accountType string
        var balance decimal.Decimal
        
        err := rows.Scan(&accountType, &balance)
        if err != nil {
            continue
        }
        
        balances[accountType] = balance
        
        switch accountType {
        case "user", "fee":
            totalAssets = totalAssets.Add(balance)
        case "escrow":
            totalLiabilities = totalLiabilities.Add(balance)
        }
    }
    
    equity := totalAssets.Sub(totalLiabilities)
    
    return map[string]interface{}{
        "assets": map[string]interface{}{
            "user_accounts": balances["user"],
            "fee_accounts":  balances["fee"],
            "total":         totalAssets,
        },
        "liabilities": map[string]interface{}{
            "escrow_accounts": balances["escrow"],
            "total":           totalLiabilities,
        },
        "equity": equity,
        "as_of_date": asOfDate,
    }, nil
}

func (as *AccountingService) generateCashFlow(ctx context.Context, 
    periodStart, periodEnd time.Time, currency string) (map[string]interface{}, error) {
    
    // Query cash flows by activity type
    rows, err := as.db.QueryContext(ctx, `
        SELECT 
            je.reference_type,
            SUM(CASE WHEN jl.debit_amount > 0 THEN jl.debit_amount ELSE -jl.credit_amount END) as net_flow
        FROM journal_entries je
        JOIN journal_lines jl ON jl.entry_id = je.id
        JOIN accounts a ON a.id = jl.account_id
        WHERE je.entry_date >= $1 
          AND je.entry_date <= $2
          AND je.status = 'posted'
          AND jl.currency = $3
          AND a.account_type = 'user'
        GROUP BY je.reference_type
    `, periodStart, periodEnd, currency)
    
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    flows := make(map[string]decimal.Decimal)
    var totalInflow, totalOutflow decimal.Decimal
    
    for rows.Next() {
        var refType string
        var netFlow decimal.Decimal
        
        err := rows.Scan(&refType, &netFlow)
        if err != nil {
            continue
        }
        
        flows[refType] = netFlow
        
        if netFlow.GreaterThan(decimal.Zero) {
            totalInflow = totalInflow.Add(netFlow)
        } else {
            totalOutflow = totalOutflow.Add(netFlow.Abs())
        }
    }
    
    netCashFlow := totalInflow.Sub(totalOutflow)
    
    return map[string]interface{}{
        "operating_activities": flows,
        "total_inflow":         totalInflow,
        "total_outflow":        totalOutflow,
        "net_cash_flow":        netCashFlow,
        "period": map[string]interface{}{
            "start": periodStart,
            "end":   periodEnd,
        },
    }, nil
}

// Background processes

func (as *AccountingService) balanceReconciliation() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        ctx := context.Background()
        
        // Reconcile account balances
        rows, err := as.db.QueryContext(ctx, `
            SELECT 
                a.id,
                a.balance,
                COALESCE(SUM(
                    CASE 
                        WHEN jl.debit_amount > 0 THEN jl.debit_amount 
                        ELSE -jl.credit_amount 
                    END
                ), 0) as calculated_balance
            FROM accounts a
            LEFT JOIN journal_lines jl ON jl.account_id = a.id
            LEFT JOIN journal_entries je ON je.id = jl.entry_id AND je.status = 'posted'
            GROUP BY a.id, a.balance
            HAVING a.balance != COALESCE(SUM(
                CASE 
                    WHEN jl.debit_amount > 0 THEN jl.debit_amount 
                    ELSE -jl.credit_amount 
                END
            ), 0)
        `)
        
        if err != nil {
            continue
        }
        
        for rows.Next() {
            var accountID uuid.UUID
            var currentBalance, calculatedBalance decimal.Decimal
            
            rows.Scan(&accountID, &currentBalance, &calculatedBalance)
            
            // Log discrepancy
            as.logAudit(ctx, "balance_discrepancy", accountID, map[string]interface{}{
                "current_balance":    currentBalance,
                "calculated_balance": calculatedBalance,
                "difference":         currentBalance.Sub(calculatedBalance),
            })
        }
        rows.Close()
    }
}

func (as *AccountingService) reportGenerator() {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        ctx := context.Background()
        
        // Generate daily reports
        now := time.Now()
        yesterday := now.AddDate(0, 0, -1)
        
        // Generate income statement
        as.GenerateFinancialReport(ctx, "income_statement", 
            yesterday.Truncate(24*time.Hour), 
            now.Truncate(24*time.Hour), 
            as.baseCurrency)
        
        // Generate balance sheet
        as.GenerateFinancialReport(ctx, "balance_sheet", 
            time.Time{}, now, as.baseCurrency)
    }
}

func (as *AccountingService) logAudit(ctx context.Context, 
    action string, entityID uuid.UUID, data map[string]interface{}) {
    
    value, _ := json.Marshal(data)
    
    as.db.ExecContext(ctx, `
        INSERT INTO audit_log (id, entity_type, entity_id, action, new_value, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, uuid.New(), "account", entityID, action, value, time.Now())
}

// Export functions for tax compliance

// ExportTransactionsCSV exports transactions in CSV format
func (as *AccountingService) ExportTransactionsCSV(ctx context.Context, 
    userID uuid.UUID, startDate, endDate time.Time) ([]byte, error) {
    
    // Implementation for CSV export
    // Returns CSV data suitable for tax software import
    return nil, nil
}

// ExportTaxReportPDF exports tax report in PDF format
func (as *AccountingService) ExportTaxReportPDF(ctx context.Context, 
    reportID uuid.UUID) ([]byte, error) {
    
    // Implementation for PDF generation
    // Returns PDF document for tax filing
    return nil, nil
}
```

## Integration Points

### Payment Gateway Integration
```go
// Record payment transaction
func (as *AccountingService) RecordPayment(ctx context.Context, 
    payment *PaymentTransaction) error {
    
    // Create journal entry for payment
    entry := &JournalEntry{
        TransactionID: payment.ID,
        EntryDate:     payment.CreatedAt,
        Description:   fmt.Sprintf("Payment: %s", payment.Type),
        ReferenceType: "payment",
        ReferenceID:   payment.ID,
        Lines: []JournalLine{
            {
                AccountID:    payment.FromAccountID,
                DebitAmount:  payment.Amount,
                Currency:     payment.Currency,
                ExchangeRate: payment.ExchangeRate,
            },
            {
                AccountID:    payment.ToAccountID,
                CreditAmount: payment.Amount,
                Currency:     payment.Currency,
                ExchangeRate: payment.ExchangeRate,
            },
        },
    }
    
    return as.CreateJournalEntry(ctx, entry)
}
```

### Contract Service Integration
```go
// Record contract creation with escrow
func (as *AccountingService) RecordContractEscrow(ctx context.Context, 
    contractID, buyerAccountID, escrowAccountID uuid.UUID, 
    amount decimal.Decimal, currency string) error {
    
    entry := &JournalEntry{
        TransactionID: contractID,
        EntryDate:     time.Now(),
        Description:   "Contract escrow deposit",
        ReferenceType: "contract",
        ReferenceID:   contractID,
        Lines: []JournalLine{
            {
                AccountID:    buyerAccountID,
                DebitAmount:  amount,
                Currency:     currency,
                Description:  "Escrow deposit",
            },
            {
                AccountID:    escrowAccountID,
                CreditAmount: amount,
                Currency:     currency,
                Description:  "Escrow received",
            },
        },
    }
    
    return as.CreateJournalEntry(ctx, entry)
}
```

### Analytics Integration
```go
// Get financial metrics for analytics
func (as *AccountingService) GetFinancialMetrics(ctx context.Context, 
    userID uuid.UUID, period string) (map[string]interface{}, error) {
    
    // Calculate various financial metrics
    // Revenue, expenses, profit margins, etc.
    return nil, nil
}
```

## API Endpoints

```go
// HTTP handlers
func (as *AccountingService) RegisterHandlers(router *mux.Router) {
    router.HandleFunc("/accounts", as.handleCreateAccount).Methods("POST")
    router.HandleFunc("/accounts/{id}", as.handleGetAccount).Methods("GET")
    router.HandleFunc("/accounts/{id}/balance", as.handleGetBalance).Methods("GET")
    router.HandleFunc("/accounts/{id}/history", as.handleGetHistory).Methods("GET")
    router.HandleFunc("/accounts/{id}/lock", as.handleLockFunds).Methods("POST")
    router.HandleFunc("/accounts/{id}/unlock", as.handleUnlockFunds).Methods("POST")
    router.HandleFunc("/journal/entries", as.handleCreateEntry).Methods("POST")
    router.HandleFunc("/reports/financial", as.handleGenerateReport).Methods("POST")
    router.HandleFunc("/reports/tax", as.handleGenerateTaxReport).Methods("POST")
    router.HandleFunc("/reports/export", as.handleExportReport).Methods("GET")
}
```