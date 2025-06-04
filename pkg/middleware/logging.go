package middleware

import (
    "time"
    
    "github.com/gofiber/fiber/v2"
    "github.com/blackhole/pkg/common/logger"
)

// LogConfig configures logging middleware
type LogConfig struct {
    Logger        logger.Logger
    SkipPaths     []string
    IncludeBody   bool
    IncludeQuery  bool
}

// WithLogging creates logging middleware
func WithLogging(config ...LogConfig) Handler {
    cfg := LogConfig{
        Logger: logger.Default(),
    }
    
    if len(config) > 0 {
        cfg = config[0]
    }
    
    return func(c *fiber.Ctx) error {
        // Skip logging for certain paths
        for _, path := range cfg.SkipPaths {
            if c.Path() == path {
                return c.Next()
            }
        }
        
        start := time.Now()
        
        // Log request
        requestID := c.Locals("request_id")
        cfg.Logger.Info("request started",
            "request_id", requestID,
            "method", c.Method(),
            "path", c.Path(),
            "ip", c.IP(),
            "user_agent", c.Get("User-Agent"),
        )
        
        // Process request
        err := c.Next()
        
        // Calculate duration
        duration := time.Since(start)
        
        // Log response
        cfg.Logger.Info("request completed",
            "request_id", requestID,
            "method", c.Method(),
            "path", c.Path(),
            "status", c.Response().StatusCode(),
            "duration", duration,
            "error", err,
        )
        
        return err
    }
}