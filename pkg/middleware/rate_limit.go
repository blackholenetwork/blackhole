package middleware

import (
    "fmt"
    "sync"
    "time"
    
    "github.com/gofiber/fiber/v2"
    "golang.org/x/time/rate"
)

// RateLimitConfig configures rate limiting
type RateLimitConfig struct {
    Rate       int           // Requests per window
    Window     time.Duration // Time window
    KeyFunc    func(*fiber.Ctx) string
    ErrorHandler fiber.ErrorHandler
}

// WithRateLimit creates rate limiting middleware
func WithRateLimit(requests int, window ...time.Duration) Handler {
    w := time.Minute
    if len(window) > 0 {
        w = window[0]
    }
    
    config := RateLimitConfig{
        Rate:   requests,
        Window: w,
        KeyFunc: func(c *fiber.Ctx) string {
            // Default to IP-based limiting
            return c.IP()
        },
    }
    
    return withRateLimitConfig(config)
}

// WithUserRateLimit creates per-user rate limiting
func WithUserRateLimit(requests int, window time.Duration) Handler {
    config := RateLimitConfig{
        Rate:   requests,
        Window: window,
        KeyFunc: func(c *fiber.Ctx) string {
            // Use user ID if authenticated
            if userID := c.Locals("user_id"); userID != nil {
                return fmt.Sprintf("user:%v", userID)
            }
            // Fall back to IP
            return c.IP()
        },
    }
    
    return withRateLimitConfig(config)
}

func withRateLimitConfig(config RateLimitConfig) Handler {
    // Store limiters per key
    limiters := &sync.Map{}
    
    // Cleanup old limiters periodically
    go func() {
        ticker := time.NewTicker(config.Window * 2)
        defer ticker.Stop()
        
        for range ticker.C {
            limiters.Range(func(key, value interface{}) bool {
                limiter := value.(*rateLimiter)
                if time.Since(limiter.lastSeen) > config.Window*2 {
                    limiters.Delete(key)
                }
                return true
            })
        }
    }()
    
    return func(c *fiber.Ctx) error {
        key := config.KeyFunc(c)
        
        // Get or create limiter
        val, _ := limiters.LoadOrStore(key, &rateLimiter{
            limiter:  rate.NewLimiter(rate.Every(config.Window/time.Duration(config.Rate)), config.Rate),
            lastSeen: time.Now(),
        })
        
        rl := val.(*rateLimiter)
        rl.mu.Lock()
        rl.lastSeen = time.Now()
        rl.mu.Unlock()
        
        // Check rate limit
        if !rl.limiter.Allow() {
            // Set rate limit headers
            c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", config.Rate))
            c.Set("X-RateLimit-Remaining", "0")
            c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(config.Window).Unix()))
            
            if config.ErrorHandler != nil {
                return config.ErrorHandler(c, fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded"))
            }
            
            return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
                "error": "rate limit exceeded",
                "retry_after": config.Window.Seconds(),
            })
        }
        
        // Set rate limit headers
        c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", config.Rate))
        c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", int(rl.limiter.Tokens())))
        
        return c.Next()
    }
}

type rateLimiter struct {
    limiter  *rate.Limiter
    lastSeen time.Time
    mu       sync.Mutex
}