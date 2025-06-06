# Economic System Integration Examples

This document provides practical code examples for integrating with the economic system, based on the actual implementation.

## Basic Service Integration

### Recording Resource Usage

```go
package myservice

import (
    "context"
    "time"

    "github.com/blackhole/pkg/economic/incentive"
)

type MyService struct {
    economicTracker incentive.EconomicTracker
}

func (s *MyService) ProcessUserFile(ctx context.Context, userID string, fileData []byte) error {
    // Process the file
    processed, err := s.processFile(fileData)
    if err != nil {
        return err
    }

    // Record storage usage
    storageEvent := incentive.ResourceUsageEvent{
        EventID:      generateEventID(),
        UserID:       userID,
        ProviderID:   s.getProviderID(),
        ResourceType: incentive.ResourceStorage,
        Operation:    "put",
        Amount:       float64(len(processed)) / (1024 * 1024), // Convert to MB
        Unit:         "MB",
        Timestamp:    time.Now(),
        Context: incentive.OperationContext{
            UserInitiated: true,
            Chargeable:    true,
        },
    }

    if err := s.economicTracker.TrackResourceUsage(ctx, storageEvent); err != nil {
        log.Printf("Failed to track storage usage: %v", err)
        // Don't fail the operation, just log the error
    }

    return s.storeFile(processed)
}
```

### Content Economy Integration

```go
package content

import (
    "context"
    "github.com/blackhole/pkg/economic/incentive"
)

type ContentService struct {
    economicService *incentive.Service
}

func (cs *ContentService) ViewContent(ctx context.Context, contentID, userID string) error {
    // Record content view
    contentEvent := incentive.ContentActivityEvent{
        EventID:     generateEventID(),
        ContentID:   contentID,
        UserID:     userID,
        ActivityType: "view",
        Timestamp:   time.Now(),
        Value:       0.01, // $0.01 per view
    }

    if err := cs.economicService.TrackContentActivity(ctx, contentEvent); err != nil {
        log.Printf("Failed to track content activity: %v", err)
    }

    return cs.serveContent(contentID)
}

func (cs *ContentService) InvestInContent(ctx context.Context, contentID, investorID string, amount float64) error {
    // Validate minimum investment
    if amount < 10.00 {
        return errors.New("minimum investment is $10.00")
    }

    // Create investment
    investment := &incentive.ContentInvestment{
        InvestmentID:    generateInvestmentID(),
        ContentID:       contentID,
        InvestorID:      investorID,
        InvestmentAmount: amount,
        PurchaseDate:    time.Now(),
        IsActive:        true,
    }

    // Process through economic system
    return cs.economicService.ProcessContentInvestment(ctx, investment)
}
```

## Payment Processing Integration

### Subscription Management

```go
package subscription

import (
    "context"
    "github.com/blackhole/pkg/economic/contract"
)

type SubscriptionManager struct {
    contractService *contract.Service
}

func (sm *SubscriptionManager) UpgradeSubscription(ctx context.Context, userID string, newTier contract.SubscriptionTier) error {
    // Get current subscription
    currentSub, err := sm.contractService.GetUserSubscription(ctx, userID)
    if err != nil {
        return fmt.Errorf("failed to get current subscription: %w", err)
    }

    // Calculate prorated amount
    proratedAmount, err := sm.calculateProratedUpgrade(currentSub, newTier)
    if err != nil {
        return fmt.Errorf("failed to calculate prorated amount: %w", err)
    }

    // Process payment
    paymentReq := &contract.PaymentRequest{
        UserID:        userID,
        Amount:        proratedAmount,
        Currency:      "USD",
        Description:   fmt.Sprintf("Upgrade to %s tier", newTier),
        PaymentMethod: currentSub.PaymentMethod,
    }

    if err := sm.contractService.ProcessPayment(ctx, paymentReq); err != nil {
        return fmt.Errorf("payment failed: %w", err)
    }

    // Update subscription
    return sm.contractService.UpdateSubscriptionTier(ctx, userID, newTier)
}

func (sm *SubscriptionManager) calculateProratedUpgrade(current *contract.Subscription, newTier contract.SubscriptionTier) (float64, error) {
    newPrice := sm.contractService.GetTierPrice(newTier)
    currentPrice := current.Price

    // Calculate remaining days in current billing cycle
    now := time.Now()
    daysRemaining := int(current.EndDate.Sub(now).Hours() / 24)
    daysInCycle := 30 // Assuming monthly billing

    // Calculate prorated difference
    dailyDifference := (newPrice - currentPrice) / float64(daysInCycle)
    return dailyDifference * float64(daysRemaining), nil
}
```

### Payment Webhook Handling

```go
package webhooks

import (
    "encoding/json"
    "net/http"
    "github.com/blackhole/pkg/economic/contract"
)

type PaymentWebhookHandler struct {
    contractService *contract.Service
}

func (h *PaymentWebhookHandler) HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
    payload, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read body", http.StatusBadRequest)
        return
    }

    // Verify webhook signature
    if !h.verifyStripeSignature(payload, r.Header.Get("Stripe-Signature")) {
        http.Error(w, "Invalid signature", http.StatusUnauthorized)
        return
    }

    var event contract.StripeEvent
    if err := json.Unmarshal(payload, &event); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    switch event.Type {
    case "payment_intent.succeeded":
        if err := h.handlePaymentSuccess(event.Data); err != nil {
            log.Printf("Failed to handle payment success: %v", err)
            http.Error(w, "Internal error", http.StatusInternalServerError)
            return
        }
    case "payment_intent.payment_failed":
        if err := h.handlePaymentFailure(event.Data); err != nil {
            log.Printf("Failed to handle payment failure: %v", err)
            http.Error(w, "Internal error", http.StatusInternalServerError)
            return
        }
    }

    w.WriteHeader(http.StatusOK)
}

func (h *PaymentWebhookHandler) handlePaymentSuccess(data json.RawMessage) error {
    var paymentIntent contract.PaymentIntent
    if err := json.Unmarshal(data, &paymentIntent); err != nil {
        return err
    }

    // Update subscription status
    return h.contractService.ActivateSubscription(context.Background(), paymentIntent.Metadata.UserID)
}
```

## Dashboard Integration

### Real-Time Dashboard Updates

```go
package dashboard

import (
    "context"
    "encoding/json"
    "log"

    "github.com/gofiber/websocket/v2"
    "github.com/blackhole/pkg/economic/incentive"
)

type DashboardHandler struct {
    incentiveService *incentive.Service
    activeConnections map[string]*websocket.Conn
}

func (d *DashboardHandler) StreamEconomicUpdates(c *websocket.Conn) {
    userID := c.Locals("user_id").(string)

    // Register connection
    d.activeConnections[userID] = c
    defer delete(d.activeConnections, userID)

    // Subscribe to user's economic events
    eventChan := d.incentiveService.SubscribeToUserEvents(userID)
    defer d.incentiveService.UnsubscribeFromUserEvents(userID)

    for {
        select {
        case event := <-eventChan:
            update := d.formatDashboardUpdate(event)
            if err := c.WriteJSON(update); err != nil {
                log.Printf("WebSocket write error for user %s: %v", userID, err)
                return
            }

        case <-c.Context().Done():
            return
        }
    }
}

func (d *DashboardHandler) formatDashboardUpdate(event incentive.EconomicEvent) map[string]interface{} {
    return map[string]interface{}{
        "type":      event.Type,
        "timestamp": event.Timestamp,
        "data": map[string]interface{}{
            "amount":        event.Amount,
            "resource_type": event.ResourceType,
            "description":   event.Description,
        },
    }
}

// Broadcast updates to all connected users
func (d *DashboardHandler) BroadcastSystemUpdate(update interface{}) {
    for userID, conn := range d.activeConnections {
        if err := conn.WriteJSON(update); err != nil {
            log.Printf("Failed to send update to user %s: %v", userID, err)
            delete(d.activeConnections, userID)
        }
    }
}
```

### REST API Integration

```go
package api

import (
    "github.com/gofiber/fiber/v2"
    "github.com/blackhole/pkg/economic/incentive"
)

type EconomicsAPIHandler struct {
    incentiveService *incentive.Service
}

func (h *EconomicsAPIHandler) GetUserDashboard(c *fiber.Ctx) error {
    userID := c.Locals("user_id").(string)
    userType := c.Locals("user_type").(string)

    switch userType {
    case "subscriber":
        dashboard, err := h.getSubscriberDashboard(userID)
        if err != nil {
            return c.Status(500).JSON(fiber.Map{"error": err.Error()})
        }
        return c.JSON(dashboard)

    case "content_creator":
        dashboard, err := h.getContentCreatorDashboard(userID)
        if err != nil {
            return c.Status(500).JSON(fiber.Map{"error": err.Error()})
        }
        return c.JSON(dashboard)

    case "infrastructure_provider":
        dashboard, err := h.getInfrastructureProviderDashboard(userID)
        if err != nil {
            return c.Status(500).JSON(fiber.Map{"error": err.Error()})
        }
        return c.JSON(dashboard)

    default:
        return c.Status(400).JSON(fiber.Map{"error": "Unknown user type"})
    }
}

func (h *EconomicsAPIHandler) getSubscriberDashboard(userID string) (*SubscriberDashboard, error) {
    subscription, err := h.incentiveService.GetUserSubscription(userID)
    if err != nil {
        return nil, err
    }

    usage, err := h.incentiveService.GetCurrentUsage(userID)
    if err != nil {
        return nil, err
    }

    distribution, err := h.incentiveService.GetRevenueDistribution(userID)
    if err != nil {
        return nil, err
    }

    return &SubscriberDashboard{
        UserType:             "subscriber",
        Subscription:         subscription,
        UsageStats:          usage,
        RevenueDistribution: distribution,
    }, nil
}
```

## Resource Provider Integration

### Infrastructure Provider Setup

```go
package provider

import (
    "context"
    "time"

    "github.com/blackhole/pkg/economic/incentive"
    "github.com/blackhole/pkg/resources/storage"
)

type InfrastructureProvider struct {
    providerID       string
    storageService   *storage.Service
    economicService  *incentive.Service
    usageReporter    *UsageReporter
}

func (p *InfrastructureProvider) Start(ctx context.Context) error {
    // Start usage reporting
    go p.startUsageReporting(ctx)

    // Register as infrastructure provider
    return p.economicService.RegisterInfrastructureProvider(ctx, &incentive.ProviderRegistration{
        ProviderID:   p.providerID,
        ResourceTypes: []incentive.ResourceType{
            incentive.ResourceStorage,
            incentive.ResourceBandwidth,
        },
        Capabilities: map[string]interface{}{
            "storage_capacity_gb": 1000,
            "bandwidth_mbps":     100,
        },
    })
}

func (p *InfrastructureProvider) startUsageReporting(ctx context.Context) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if err := p.reportCurrentUsage(ctx); err != nil {
                log.Printf("Failed to report usage: %v", err)
            }
        case <-ctx.Done():
            return
        }
    }
}

func (p *InfrastructureProvider) reportCurrentUsage(ctx context.Context) error {
    // Get current storage usage
    storageUsage, err := p.storageService.GetCurrentUsage()
    if err != nil {
        return err
    }

    // Report to economic system
    usageEvent := &incentive.ProviderUsageReport{
        ProviderID:   p.providerID,
        Timestamp:    time.Now(),
        Resources: []incentive.ResourceUsage{
            {
                ResourceType: incentive.ResourceStorage,
                Amount:       storageUsage.TotalGB,
                Unit:         "GB",
                Efficiency:   storageUsage.EfficiencyScore,
            },
        },
    }

    return p.economicService.ReportProviderUsage(ctx, usageEvent)
}
```

## Testing Integration

### Mock Economic Service

```go
package testing

import (
    "context"
    "github.com/blackhole/pkg/economic/incentive"
)

type MockEconomicService struct {
    recordedEvents []incentive.ResourceUsageEvent
    balances      map[string]float64
}

func NewMockEconomicService() *MockEconomicService {
    return &MockEconomicService{
        recordedEvents: make([]incentive.ResourceUsageEvent, 0),
        balances:      make(map[string]float64),
    }
}

func (m *MockEconomicService) TrackResourceUsage(ctx context.Context, event incentive.ResourceUsageEvent) error {
    m.recordedEvents = append(m.recordedEvents, event)
    return nil
}

func (m *MockEconomicService) GetUserBalance(ctx context.Context, userID string) (*incentive.UserBalance, error) {
    balance := m.balances[userID]
    return &incentive.UserBalance{
        UserID:        userID,
        TotalBalance:  balance,
        PendingCredits: 0,
        LastUpdated:   time.Now(),
    }, nil
}

func (m *MockEconomicService) SetUserBalance(userID string, balance float64) {
    m.balances[userID] = balance
}

func (m *MockEconomicService) GetRecordedEvents() []incentive.ResourceUsageEvent {
    return m.recordedEvents
}

func (m *MockEconomicService) ClearRecordedEvents() {
    m.recordedEvents = make([]incentive.ResourceUsageEvent, 0)
}
```

### Integration Test Example

```go
package integration_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/blackhole/pkg/economic/incentive"
    "github.com/blackhole/pkg/economic/contract"
)

func TestSubscriptionAndUsageFlow(t *testing.T) {
    // Setup
    ctx := context.Background()
    economicService := setupTestEconomicService(t)
    contractService := setupTestContractService(t)

    userID := "test_user_123"

    // Test subscription creation
    subscription := &contract.Subscription{
        UserID:    userID,
        Tier:      contract.TierNormal,
        Price:     10.00,
        Currency:  "USD",
        AutoRenew: true,
    }

    err := contractService.CreateSubscription(ctx, subscription)
    assert.NoError(t, err)

    // Test usage tracking
    usageEvent := incentive.ResourceUsageEvent{
        UserID:       userID,
        ResourceType: incentive.ResourceStorage,
        Operation:    "put",
        Amount:       1.5, // 1.5 GB
        Unit:         "GB",
        Timestamp:    time.Now(),
    }

    err = economicService.TrackResourceUsage(ctx, usageEvent)
    assert.NoError(t, err)

    // Verify billing calculation
    time.Sleep(100 * time.Millisecond) // Allow async processing

    usage, err := economicService.GetCurrentUsage(userID)
    assert.NoError(t, err)
    assert.Equal(t, 1.5, usage.StorageGB)

    // Test monthly billing
    err = economicService.ProcessMonthlyBilling(ctx)
    assert.NoError(t, err)

    // Verify charges
    charges, err := contractService.GetUserCharges(ctx, userID)
    assert.NoError(t, err)
    assert.Len(t, charges, 1)
    assert.Equal(t, 10.00, charges[0].Amount) // Monthly subscription
}
```

## Error Handling Patterns

### Graceful Economic Failures

```go
package service

import (
    "context"
    "log"
    "github.com/blackhole/pkg/economic/incentive"
)

type ServiceWithEconomics struct {
    economicService *incentive.Service
    fallbackMode    bool
}

func (s *ServiceWithEconomics) ProcessRequest(ctx context.Context, req *Request) (*Response, error) {
    // Process the core functionality first
    response, err := s.processCoreLogic(req)
    if err != nil {
        return nil, err
    }

    // Try to record economic activity
    if err := s.recordEconomicActivity(ctx, req, response); err != nil {
        // Log the error but don't fail the request
        log.Printf("Economic tracking failed: %v", err)

        // Optionally enter fallback mode
        s.fallbackMode = true

        // Could also queue for retry
        s.queueEconomicEvent(req, response)
    }

    return response, nil
}

func (s *ServiceWithEconomics) recordEconomicActivity(ctx context.Context, req *Request, resp *Response) error {
    if s.fallbackMode {
        // Skip economic tracking in fallback mode
        return nil
    }

    event := s.createEconomicEvent(req, resp)
    return s.economicService.TrackResourceUsage(ctx, event)
}
```

This comprehensive set of integration examples demonstrates how to properly integrate with the economic system while maintaining robustness and proper error handling.
