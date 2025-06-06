# Code Design Principles

Beyond standards and patterns, these principles guide how we think about and structure code.

## 1. Composition Over Inheritance

```go
// ❌ AVOID: Deep inheritance hierarchies
type Animal struct { }
type Mammal struct { Animal }
type Dog struct { Mammal }

// ✅ PREFER: Composition
type Dog struct {
    Movement MovementBehavior
    Sound    SoundBehavior
    Diet     DietBehavior
}

// Behaviors can be mixed and matched
dog := Dog{
    Movement: &WalkingMovement{},
    Sound:    &BarkingSound{},
    Diet:     &OmnivoreDiet{},
}
```

## 2. Interface Segregation

```go
// ❌ AVOID: Fat interfaces
type Storage interface {
    Create(...)
    Read(...)
    Update(...)
    Delete(...)
    List(...)
    Search(...)
    Backup(...)
    Restore(...)
    Compress(...)
    // ... 20 more methods
}

// ✅ PREFER: Small, focused interfaces
type Reader interface {
    Read(ctx context.Context, id string) (Data, error)
}

type Writer interface {
    Write(ctx context.Context, data Data) error
}

type Searcher interface {
    Search(ctx context.Context, query Query) ([]Result, error)
}

// Compose as needed
type Storage interface {
    Reader
    Writer
}
```

## 3. Dependency Inversion

```go
// ❌ AVOID: High-level depends on low-level
package api

import "github.com/blackhole/pkg/database/postgres"

type API struct {
    db *postgres.DB  // Coupled to specific implementation
}

// ✅ PREFER: Depend on abstractions
package api

type Storage interface {
    GetUser(id string) (*User, error)
}

type API struct {
    storage Storage  // Depends on interface
}

// Wire up in main
func main() {
    db := postgres.New()
    api := api.New(db)  // postgres.DB implements Storage
}
```

## 4. Single Source of Truth

```go
// ❌ AVOID: Duplicate state
type Order struct {
    Items     []Item
    ItemCount int      // Duplicate - can get out of sync
    Total     float64  // Duplicate - should be calculated
}

// ✅ PREFER: Derive state
type Order struct {
    Items []Item
}

func (o *Order) ItemCount() int {
    return len(o.Items)
}

func (o *Order) Total() float64 {
    var total float64
    for _, item := range o.Items {
        total += item.Price * float64(item.Quantity)
    }
    return total
}
```

## 5. Explicit Over Implicit

```go
// ❌ AVOID: Magic values and implicit behavior
func Process(data []byte) {
    if len(data) > 1048576 { // What is this number?
        compress(data)
    }
}

// ✅ PREFER: Named constants and explicit configuration
const MaxUncompressedSize = 1 * MB

type ProcessConfig struct {
    CompressThreshold int64
    CompressionLevel  int
}

func Process(data []byte, config ProcessConfig) {
    if int64(len(data)) > config.CompressThreshold {
        compress(data, config.CompressionLevel)
    }
}
```

## 6. Fail Fast

```go
// ❌ AVOID: Continuing with invalid state
func ProcessFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        log.Printf("Warning: %v", err)
        // Continue anyway...
    }

    // Will panic later when file is nil
    defer file.Close()
    // ...
}

// ✅ PREFER: Return early on errors
func ProcessFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open file: %w", err)
    }
    defer file.Close()

    // Validate early
    stat, err := file.Stat()
    if err != nil {
        return fmt.Errorf("stat file: %w", err)
    }

    if stat.Size() == 0 {
        return errors.New("file is empty")
    }

    // Now safe to process
    return process(file)
}
```

## 7. Command-Query Separation

```go
// ❌ AVOID: Methods that both change state and return values
func (s *Stack) PopAndIsEmpty() (value int, isEmpty bool) {
    value = s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    isEmpty = len(s.items) == 0
    return
}

// ✅ PREFER: Separate commands and queries
func (s *Stack) Pop() int {
    value := s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    return value
}

func (s *Stack) IsEmpty() bool {
    return len(s.items) == 0
}
```

## 8. Idempotency by Design

```go
// ❌ AVOID: Non-idempotent operations
func IncrementCounter(key string) {
    value := cache.Get(key)
    cache.Set(key, value+1)  // Calling twice = different results
}

// ✅ PREFER: Idempotent operations
func SetCounter(key string, value int) {
    cache.Set(key, value)  // Calling multiple times = same result
}

func EnsureUserExists(user User) error {
    existing, err := db.GetUser(user.ID)
    if err == nil {
        return nil  // Already exists, nothing to do
    }

    if !errors.Is(err, ErrNotFound) {
        return err  // Real error
    }

    return db.CreateUser(user)  // Only create if not exists
}
```

## 9. Open/Closed Principle

```go
// ❌ AVOID: Modifying existing code for new features
func CalculatePrice(product Product) float64 {
    price := product.BasePrice

    switch product.Type {
    case "book":
        price *= 0.9  // 10% discount
    case "electronic":
        price *= 1.2  // 20% markup
    case "food":        // Adding new type requires modifying this
        price *= 0.8
    }

    return price
}

// ✅ PREFER: Extend through interfaces
type PriceCalculator interface {
    CalculatePrice(basePrice float64) float64
}

type BookPricing struct{}
func (b BookPricing) CalculatePrice(base float64) float64 {
    return base * 0.9
}

type ElectronicPricing struct{}
func (e ElectronicPricing) CalculatePrice(base float64) float64 {
    return base * 1.2
}

// Easy to add new types without changing existing code
type FoodPricing struct{}
func (f FoodPricing) CalculatePrice(base float64) float64 {
    return base * 0.8
}
```

## 10. Principle of Least Astonishment

```go
// ❌ AVOID: Surprising behavior
func SaveUser(user *User) error {
    // Surprising: modifies input
    user.UpdatedAt = time.Now()
    user.Version++

    return db.Save(user)
}

// ✅ PREFER: Predictable behavior
func SaveUser(user User) (User, error) {
    // Clear: returns modified copy
    user.UpdatedAt = time.Now()
    user.Version++

    err := db.Save(user)
    return user, err
}
```

## 11. Builder Pattern for Complex Objects

```go
// ❌ AVOID: Complex constructors
server := NewServer("localhost", 8080, true, false, 30, 100, nil, "", true)

// ✅ PREFER: Builder pattern
server := NewServerBuilder().
    WithHost("localhost").
    WithPort(8080).
    WithTLS(true).
    WithTimeout(30*time.Second).
    WithMaxConnections(100).
    Build()

// Implementation
type ServerBuilder struct {
    host string
    port int
    // ... other fields with defaults
}

func (b *ServerBuilder) WithHost(host string) *ServerBuilder {
    b.host = host
    return b
}

func (b *ServerBuilder) Build() *Server {
    // Apply defaults for missing values
    return &Server{
        host: b.host,
        port: b.port,
        // ...
    }
}
```

## 12. Functional Options Pattern

```go
// ❌ AVOID: Multiple constructors or breaking changes
func NewClient(timeout time.Duration) *Client
func NewClientWithRetry(timeout time.Duration, retries int) *Client
func NewClientWithRetryAndAuth(timeout time.Duration, retries int, token string) *Client

// ✅ PREFER: Functional options
type Option func(*Client)

func WithTimeout(d time.Duration) Option {
    return func(c *Client) {
        c.timeout = d
    }
}

func WithRetry(attempts int) Option {
    return func(c *Client) {
        c.retries = attempts
    }
}

func WithAuth(token string) Option {
    return func(c *Client) {
        c.token = token
    }
}

func NewClient(opts ...Option) *Client {
    // Defaults
    c := &Client{
        timeout: 30 * time.Second,
        retries: 3,
    }

    // Apply options
    for _, opt := range opts {
        opt(c)
    }

    return c
}

// Usage
client := NewClient(
    WithTimeout(60*time.Second),
    WithRetry(5),
    WithAuth("secret-token"),
)
```

## Applying These Principles

1. **During Design**: Consider these principles when designing new features
2. **During Code Review**: Check if code follows these principles
3. **During Refactoring**: Use these principles to guide improvements
4. **During Debugging**: Violations often lead to bugs

Remember: Principles are guidelines, not rules. Use judgment for when to apply them.
