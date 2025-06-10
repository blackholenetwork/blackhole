# U45: Pricing Engine

## Overview
Dynamic pricing algorithms for market-based storage pricing, including market maker functionality, supply/demand matching, and price discovery mechanisms.

## Implementation

### Core Types

```go
package pricing

import (
    "context"
    "math"
    "sync"
    "time"
)

// PricePoint represents a price at a specific time
type PricePoint struct {
    Price     float64
    Timestamp time.Time
    Volume    int64
    Supply    int64
    Demand    int64
}

// MarketData represents current market conditions
type MarketData struct {
    BasePrice      float64
    CurrentPrice   float64
    Volatility     float64
    SupplyLevel    float64  // 0-1 normalized
    DemandLevel    float64  // 0-1 normalized
    LastUpdate     time.Time
    HistoricalData []PricePoint
}

// PricingConfig configures the pricing engine
type PricingConfig struct {
    BasePrice           float64
    MinPrice            float64
    MaxPrice            float64
    VolatilityFactor    float64
    SupplyWeight        float64
    DemandWeight        float64
    HistoryWindow       time.Duration
    UpdateInterval      time.Duration
    SmoothingFactor     float64
    MarketMakerSpread   float64
}

// OrderBook represents buy/sell orders
type OrderBook struct {
    BuyOrders  []Order
    SellOrders []Order
    mu         sync.RWMutex
}

// Order represents a buy or sell order
type Order struct {
    ID        string
    Type      OrderType
    Price     float64
    Quantity  int64
    UserID    string
    Timestamp time.Time
    Expiry    time.Time
}

// OrderType defines order types
type OrderType int

const (
    OrderTypeBuy OrderType = iota
    OrderTypeSell
)
```

### Pricing Engine

```go
// PricingEngine handles dynamic pricing
type PricingEngine struct {
    config      PricingConfig
    marketData  *MarketData
    orderBook   *OrderBook
    priceHistory []PricePoint
    subscribers []chan PriceUpdate
    mu          sync.RWMutex
    stopCh      chan struct{}
}

// PriceUpdate represents a price change event
type PriceUpdate struct {
    OldPrice   float64
    NewPrice   float64
    Reason     string
    Timestamp  time.Time
    MarketData MarketData
}

// NewPricingEngine creates a new pricing engine
func NewPricingEngine(config PricingConfig) *PricingEngine {
    return &PricingEngine{
        config: config,
        marketData: &MarketData{
            BasePrice:    config.BasePrice,
            CurrentPrice: config.BasePrice,
            LastUpdate:   time.Now(),
        },
        orderBook:    &OrderBook{},
        priceHistory: make([]PricePoint, 0),
        subscribers:  make([]chan PriceUpdate, 0),
        stopCh:       make(chan struct{}),
    }
}

// Start begins the pricing engine
func (pe *PricingEngine) Start(ctx context.Context) error {
    ticker := time.NewTicker(pe.config.UpdateInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-pe.stopCh:
            return nil
        case <-ticker.C:
            if err := pe.updatePrice(); err != nil {
                // Log error but continue
                continue
            }
        }
    }
}

// updatePrice recalculates the current price
func (pe *PricingEngine) updatePrice() error {
    pe.mu.Lock()
    defer pe.mu.Unlock()

    oldPrice := pe.marketData.CurrentPrice
    
    // Calculate new price based on multiple factors
    supplyDemandPrice := pe.calculateSupplyDemandPrice()
    orderBookPrice := pe.calculateOrderBookPrice()
    volatilityAdjustedPrice := pe.applyVolatility(supplyDemandPrice)
    
    // Weighted average of different pricing methods
    newPrice := 0.4*supplyDemandPrice + 0.4*orderBookPrice + 0.2*volatilityAdjustedPrice
    
    // Apply smoothing
    newPrice = pe.smoothPrice(oldPrice, newPrice)
    
    // Enforce bounds
    newPrice = math.Max(pe.config.MinPrice, math.Min(pe.config.MaxPrice, newPrice))
    
    // Update market data
    pe.marketData.CurrentPrice = newPrice
    pe.marketData.LastUpdate = time.Now()
    
    // Record history
    pe.addPricePoint(PricePoint{
        Price:     newPrice,
        Timestamp: time.Now(),
        Supply:    pe.calculateTotalSupply(),
        Demand:    pe.calculateTotalDemand(),
    })
    
    // Notify subscribers
    if oldPrice != newPrice {
        pe.notifyPriceChange(PriceUpdate{
            OldPrice:   oldPrice,
            NewPrice:   newPrice,
            Reason:     "Market dynamics",
            Timestamp:  time.Now(),
            MarketData: *pe.marketData,
        })
    }
    
    return nil
}

// calculateSupplyDemandPrice calculates price based on supply and demand
func (pe *PricingEngine) calculateSupplyDemandPrice() float64 {
    supply := pe.marketData.SupplyLevel
    demand := pe.marketData.DemandLevel
    
    // Basic supply/demand curve
    ratio := (demand + 0.1) / (supply + 0.1) // Add small value to avoid division by zero
    
    // Apply weights
    adjustment := math.Log(ratio) * pe.config.SupplyWeight
    
    return pe.config.BasePrice * (1 + adjustment)
}

// calculateOrderBookPrice calculates price from order book
func (pe *PricingEngine) calculateOrderBookPrice() float64 {
    pe.orderBook.mu.RLock()
    defer pe.orderBook.mu.RUnlock()
    
    if len(pe.orderBook.BuyOrders) == 0 || len(pe.orderBook.SellOrders) == 0 {
        return pe.marketData.CurrentPrice
    }
    
    // Get best bid and ask
    bestBid := pe.getBestBid()
    bestAsk := pe.getBestAsk()
    
    if bestBid == 0 || bestAsk == 0 {
        return pe.marketData.CurrentPrice
    }
    
    // Mid-market price
    return (bestBid + bestAsk) / 2
}

// applyVolatility adds volatility to the price
func (pe *PricingEngine) applyVolatility(basePrice float64) float64 {
    volatility := pe.calculateVolatility()
    pe.marketData.Volatility = volatility
    
    // Random walk with bounds
    randomFactor := (math.Sin(float64(time.Now().UnixNano())) + 1) / 2 // 0-1
    volatilityAdjustment := (randomFactor - 0.5) * volatility * pe.config.VolatilityFactor
    
    return basePrice * (1 + volatilityAdjustment)
}

// smoothPrice applies exponential smoothing
func (pe *PricingEngine) smoothPrice(oldPrice, newPrice float64) float64 {
    return oldPrice*pe.config.SmoothingFactor + newPrice*(1-pe.config.SmoothingFactor)
}

// calculateVolatility calculates price volatility
func (pe *PricingEngine) calculateVolatility() float64 {
    if len(pe.priceHistory) < 2 {
        return 0.01 // Default low volatility
    }
    
    // Calculate standard deviation of recent price changes
    var sum, sumSquares float64
    count := 0
    
    cutoff := time.Now().Add(-pe.config.HistoryWindow)
    for i := 1; i < len(pe.priceHistory); i++ {
        if pe.priceHistory[i].Timestamp.Before(cutoff) {
            continue
        }
        
        change := (pe.priceHistory[i].Price - pe.priceHistory[i-1].Price) / pe.priceHistory[i-1].Price
        sum += change
        sumSquares += change * change
        count++
    }
    
    if count == 0 {
        return 0.01
    }
    
    mean := sum / float64(count)
    variance := sumSquares/float64(count) - mean*mean
    
    return math.Sqrt(variance)
}
```

### Market Maker

```go
// MarketMaker provides liquidity to the market
type MarketMaker struct {
    engine        *PricingEngine
    config        MarketMakerConfig
    position      Position
    orderManager  *OrderManager
    riskManager   *RiskManager
    mu            sync.RWMutex
}

// MarketMakerConfig configures the market maker
type MarketMakerConfig struct {
    SpreadPercent    float64
    MaxPosition      int64
    OrderSize        int64
    RebalanceInterval time.Duration
    MaxRisk          float64
}

// Position tracks market maker inventory
type Position struct {
    Quantity    int64
    AveragePrice float64
    UnrealizedPnL float64
    RealizedPnL   float64
}

// NewMarketMaker creates a new market maker
func NewMarketMaker(engine *PricingEngine, config MarketMakerConfig) *MarketMaker {
    return &MarketMaker{
        engine:       engine,
        config:       config,
        orderManager: NewOrderManager(engine),
        riskManager:  NewRiskManager(config.MaxRisk),
    }
}

// Start begins market making activities
func (mm *MarketMaker) Start(ctx context.Context) error {
    ticker := time.NewTicker(mm.config.RebalanceInterval)
    defer ticker.Stop()
    
    // Place initial orders
    if err := mm.placeOrders(); err != nil {
        return err
    }
    
    for {
        select {
        case <-ctx.Done():
            return mm.cancelAllOrders()
        case <-ticker.C:
            if err := mm.rebalance(); err != nil {
                // Log error but continue
                continue
            }
        }
    }
}

// placeOrders places buy and sell orders
func (mm *MarketMaker) placeOrders() error {
    mm.mu.Lock()
    defer mm.mu.Unlock()
    
    currentPrice := mm.engine.GetCurrentPrice()
    spread := currentPrice * mm.config.SpreadPercent / 100
    
    // Calculate bid and ask prices
    bidPrice := currentPrice - spread/2
    askPrice := currentPrice + spread/2
    
    // Check risk limits
    if !mm.riskManager.CanTrade(mm.position, mm.config.OrderSize) {
        return nil // Skip placing orders if risk limit reached
    }
    
    // Place buy order
    buyOrder := Order{
        ID:        generateOrderID(),
        Type:      OrderTypeBuy,
        Price:     bidPrice,
        Quantity:  mm.config.OrderSize,
        UserID:    "market_maker",
        Timestamp: time.Now(),
        Expiry:    time.Now().Add(mm.config.RebalanceInterval),
    }
    
    if err := mm.orderManager.PlaceOrder(buyOrder); err != nil {
        return err
    }
    
    // Place sell order
    sellOrder := Order{
        ID:        generateOrderID(),
        Type:      OrderTypeSell,
        Price:     askPrice,
        Quantity:  mm.config.OrderSize,
        UserID:    "market_maker",
        Timestamp: time.Now(),
        Expiry:    time.Now().Add(mm.config.RebalanceInterval),
    }
    
    return mm.orderManager.PlaceOrder(sellOrder)
}

// rebalance adjusts market maker position
func (mm *MarketMaker) rebalance() error {
    mm.mu.Lock()
    defer mm.mu.Unlock()
    
    // Cancel existing orders
    if err := mm.cancelAllOrders(); err != nil {
        return err
    }
    
    // Update position valuation
    currentPrice := mm.engine.GetCurrentPrice()
    mm.position.UnrealizedPnL = float64(mm.position.Quantity) * (currentPrice - mm.position.AveragePrice)
    
    // Check if we need to reduce position
    if math.Abs(float64(mm.position.Quantity)) > float64(mm.config.MaxPosition) {
        if err := mm.reducePosition(); err != nil {
            return err
        }
    }
    
    // Place new orders
    return mm.placeOrders()
}

// reducePosition reduces market maker inventory
func (mm *MarketMaker) reducePosition() error {
    targetReduction := mm.position.Quantity - mm.config.MaxPosition
    if mm.position.Quantity < -mm.config.MaxPosition {
        targetReduction = mm.position.Quantity + mm.config.MaxPosition
    }
    
    currentPrice := mm.engine.GetCurrentPrice()
    
    order := Order{
        ID:        generateOrderID(),
        Type:      OrderTypeSell,
        Price:     currentPrice * 0.99, // Slightly below market for quick execution
        Quantity:  int64(math.Abs(float64(targetReduction))),
        UserID:    "market_maker",
        Timestamp: time.Now(),
        Expiry:    time.Now().Add(time.Minute),
    }
    
    if targetReduction < 0 {
        order.Type = OrderTypeBuy
        order.Price = currentPrice * 1.01 // Slightly above market
    }
    
    return mm.orderManager.PlaceOrder(order)
}
```

### Price Discovery

```go
// PriceDiscovery handles price discovery mechanisms
type PriceDiscovery struct {
    engine      *PricingEngine
    auctionMode bool
    submissions []PriceSubmission
    mu          sync.RWMutex
}

// PriceSubmission represents a price submission
type PriceSubmission struct {
    UserID    string
    Price     float64
    Quantity  int64
    Timestamp time.Time
    Type      OrderType
}

// NewPriceDiscovery creates a new price discovery mechanism
func NewPriceDiscovery(engine *PricingEngine) *PriceDiscovery {
    return &PriceDiscovery{
        engine:      engine,
        submissions: make([]PriceSubmission, 0),
    }
}

// StartAuction begins a price discovery auction
func (pd *PriceDiscovery) StartAuction(duration time.Duration) error {
    pd.mu.Lock()
    pd.auctionMode = true
    pd.submissions = make([]PriceSubmission, 0)
    pd.mu.Unlock()
    
    // Wait for submissions
    time.Sleep(duration)
    
    // Calculate clearing price
    clearingPrice, err := pd.calculateClearingPrice()
    if err != nil {
        return err
    }
    
    // Update market price
    pd.engine.SetPrice(clearingPrice)
    
    pd.mu.Lock()
    pd.auctionMode = false
    pd.mu.Unlock()
    
    return nil
}

// SubmitPrice submits a price during auction
func (pd *PriceDiscovery) SubmitPrice(submission PriceSubmission) error {
    pd.mu.Lock()
    defer pd.mu.Unlock()
    
    if !pd.auctionMode {
        return ErrAuctionNotActive
    }
    
    pd.submissions = append(pd.submissions, submission)
    return nil
}

// calculateClearingPrice calculates the market clearing price
func (pd *PriceDiscovery) calculateClearingPrice() (float64, error) {
    pd.mu.RLock()
    defer pd.mu.RUnlock()
    
    if len(pd.submissions) == 0 {
        return 0, ErrNoSubmissions
    }
    
    // Sort buy orders by price (descending)
    buyOrders := pd.filterOrders(OrderTypeBuy)
    sort.Slice(buyOrders, func(i, j int) bool {
        return buyOrders[i].Price > buyOrders[j].Price
    })
    
    // Sort sell orders by price (ascending)
    sellOrders := pd.filterOrders(OrderTypeSell)
    sort.Slice(sellOrders, func(i, j int) bool {
        return sellOrders[i].Price < sellOrders[j].Price
    })
    
    // Find crossing point
    var buyQuantity, sellQuantity int64
    var clearingPrice float64
    
    for _, buy := range buyOrders {
        buyQuantity += buy.Quantity
        
        for _, sell := range sellOrders {
            if sell.Price > buy.Price {
                break
            }
            
            sellQuantity += sell.Quantity
            
            if sellQuantity >= buyQuantity {
                clearingPrice = (buy.Price + sell.Price) / 2
                return clearingPrice, nil
            }
        }
    }
    
    // No crossing point found, use weighted average
    return pd.calculateWeightedAverage(), nil
}

// calculateWeightedAverage calculates volume-weighted average price
func (pd *PriceDiscovery) calculateWeightedAverage() float64 {
    var totalValue, totalQuantity float64
    
    for _, submission := range pd.submissions {
        totalValue += submission.Price * float64(submission.Quantity)
        totalQuantity += float64(submission.Quantity)
    }
    
    if totalQuantity == 0 {
        return pd.engine.GetCurrentPrice()
    }
    
    return totalValue / totalQuantity
}

// filterOrders filters submissions by type
func (pd *PriceDiscovery) filterOrders(orderType OrderType) []PriceSubmission {
    filtered := make([]PriceSubmission, 0)
    for _, submission := range pd.submissions {
        if submission.Type == orderType {
            filtered = append(filtered, submission)
        }
    }
    return filtered
}
```

### Helper Functions

```go
// generateOrderID generates a unique order ID
func generateOrderID() string {
    return fmt.Sprintf("order_%d_%s", time.Now().UnixNano(), randomString(8))
}

// randomString generates a random string
func randomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}

// GetCurrentPrice returns the current market price
func (pe *PricingEngine) GetCurrentPrice() float64 {
    pe.mu.RLock()
    defer pe.mu.RUnlock()
    return pe.marketData.CurrentPrice
}

// SetPrice sets the market price (used by price discovery)
func (pe *PricingEngine) SetPrice(price float64) {
    pe.mu.Lock()
    defer pe.mu.Unlock()
    
    oldPrice := pe.marketData.CurrentPrice
    pe.marketData.CurrentPrice = price
    pe.marketData.LastUpdate = time.Now()
    
    pe.notifyPriceChange(PriceUpdate{
        OldPrice:  oldPrice,
        NewPrice:  price,
        Reason:    "Price discovery",
        Timestamp: time.Now(),
        MarketData: *pe.marketData,
    })
}

// Subscribe subscribes to price updates
func (pe *PricingEngine) Subscribe() <-chan PriceUpdate {
    pe.mu.Lock()
    defer pe.mu.Unlock()
    
    ch := make(chan PriceUpdate, 10)
    pe.subscribers = append(pe.subscribers, ch)
    return ch
}

// notifyPriceChange notifies all subscribers of price changes
func (pe *PricingEngine) notifyPriceChange(update PriceUpdate) {
    for _, ch := range pe.subscribers {
        select {
        case ch <- update:
        default:
            // Channel full, skip
        }
    }
}

// addPricePoint adds a price point to history
func (pe *PricingEngine) addPricePoint(point PricePoint) {
    pe.priceHistory = append(pe.priceHistory, point)
    
    // Trim old history
    cutoff := time.Now().Add(-pe.config.HistoryWindow * 2)
    for len(pe.priceHistory) > 0 && pe.priceHistory[0].Timestamp.Before(cutoff) {
        pe.priceHistory = pe.priceHistory[1:]
    }
}

// calculateTotalSupply calculates total network supply
func (pe *PricingEngine) calculateTotalSupply() int64 {
    // This would integrate with the storage manager
    // For now, return a placeholder
    return 1000000
}

// calculateTotalDemand calculates total network demand  
func (pe *PricingEngine) calculateTotalDemand() int64 {
    // This would integrate with request tracking
    // For now, return a placeholder
    return 800000
}

// getBestBid returns the highest buy price
func (pe *PricingEngine) getBestBid() float64 {
    if len(pe.orderBook.BuyOrders) == 0 {
        return 0
    }
    
    best := pe.orderBook.BuyOrders[0].Price
    for _, order := range pe.orderBook.BuyOrders {
        if order.Price > best {
            best = order.Price
        }
    }
    return best
}

// getBestAsk returns the lowest sell price
func (pe *PricingEngine) getBestAsk() float64 {
    if len(pe.orderBook.SellOrders) == 0 {
        return 0
    }
    
    best := pe.orderBook.SellOrders[0].Price
    for _, order := range pe.orderBook.SellOrders {
        if order.Price < best {
            best = order.Price
        }
    }
    return best
}

// UpdateSupplyDemand updates supply and demand levels
func (pe *PricingEngine) UpdateSupplyDemand(supply, demand float64) {
    pe.mu.Lock()
    defer pe.mu.Unlock()
    
    pe.marketData.SupplyLevel = supply
    pe.marketData.DemandLevel = demand
}

// cancelAllOrders cancels all market maker orders
func (mm *MarketMaker) cancelAllOrders() error {
    return mm.orderManager.CancelUserOrders("market_maker")
}
```

## Testing

```go
package pricing

import (
    "context"
    "testing"
    "time"
)

func TestPricingEngine(t *testing.T) {
    config := PricingConfig{
        BasePrice:        0.01,
        MinPrice:         0.001,
        MaxPrice:         0.1,
        VolatilityFactor: 0.1,
        SupplyWeight:     0.5,
        DemandWeight:     0.5,
        HistoryWindow:    time.Hour,
        UpdateInterval:   time.Second,
        SmoothingFactor:  0.8,
    }
    
    engine := NewPricingEngine(config)
    
    // Test price updates
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    updates := engine.Subscribe()
    
    go engine.Start(ctx)
    
    // Simulate supply/demand changes
    engine.UpdateSupplyDemand(0.8, 0.3) // High supply, low demand
    
    select {
    case update := <-updates:
        if update.NewPrice >= update.OldPrice {
            t.Error("Price should decrease with high supply")
        }
    case <-time.After(2 * time.Second):
        t.Error("No price update received")
    }
}

func TestMarketMaker(t *testing.T) {
    engine := NewPricingEngine(PricingConfig{
        BasePrice:      0.01,
        UpdateInterval: time.Second,
    })
    
    mmConfig := MarketMakerConfig{
        SpreadPercent:     2.0,
        MaxPosition:       1000,
        OrderSize:         100,
        RebalanceInterval: 5 * time.Second,
        MaxRisk:           0.1,
    }
    
    mm := NewMarketMaker(engine, mmConfig)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    go mm.Start(ctx)
    
    // Verify orders are placed
    time.Sleep(time.Second)
    
    currentPrice := engine.GetCurrentPrice()
    orderBook := engine.orderBook
    
    orderBook.mu.RLock()
    defer orderBook.mu.RUnlock()
    
    if len(orderBook.BuyOrders) == 0 {
        t.Error("No buy orders placed")
    }
    
    if len(orderBook.SellOrders) == 0 {
        t.Error("No sell orders placed")
    }
    
    // Check spread
    bestBid := engine.getBestBid()
    bestAsk := engine.getBestAsk()
    
    expectedSpread := currentPrice * mmConfig.SpreadPercent / 100
    actualSpread := bestAsk - bestBid
    
    if math.Abs(actualSpread-expectedSpread) > 0.0001 {
        t.Errorf("Incorrect spread: expected %f, got %f", expectedSpread, actualSpread)
    }
}

func TestPriceDiscovery(t *testing.T) {
    engine := NewPricingEngine(PricingConfig{BasePrice: 0.01})
    pd := NewPriceDiscovery(engine)
    
    // Start auction
    go pd.StartAuction(2 * time.Second)
    
    // Submit orders
    submissions := []PriceSubmission{
        {UserID: "user1", Price: 0.012, Quantity: 100, Type: OrderTypeBuy},
        {UserID: "user2", Price: 0.011, Quantity: 200, Type: OrderTypeBuy},
        {UserID: "user3", Price: 0.010, Quantity: 150, Type: OrderTypeSell},
        {UserID: "user4", Price: 0.009, Quantity: 100, Type: OrderTypeSell},
    }
    
    for _, sub := range submissions {
        if err := pd.SubmitPrice(sub); err != nil {
            t.Errorf("Failed to submit price: %v", err)
        }
    }
    
    // Wait for auction to complete
    time.Sleep(3 * time.Second)
    
    // Check that price was updated
    newPrice := engine.GetCurrentPrice()
    if newPrice == 0.01 {
        t.Error("Price was not updated after auction")
    }
    
    // Price should be between highest sell and lowest buy
    if newPrice < 0.009 || newPrice > 0.012 {
        t.Errorf("Clearing price %f outside expected range", newPrice)
    }
}
```

## Integration

1. **Storage Integration**: Connect to storage manager for supply metrics
2. **Network Integration**: Monitor network demand and capacity
3. **Payment Integration**: Execute trades through payment system
4. **Analytics Integration**: Feed pricing data to analytics system

## Configuration

```yaml
pricing:
  base_price: 0.01
  min_price: 0.001
  max_price: 0.1
  volatility_factor: 0.1
  supply_weight: 0.5
  demand_weight: 0.5
  history_window: 1h
  update_interval: 10s
  smoothing_factor: 0.8
  
market_maker:
  spread_percent: 2.0
  max_position: 10000
  order_size: 100
  rebalance_interval: 30s
  max_risk: 0.1
```