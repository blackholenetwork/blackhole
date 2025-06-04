package middleware

import (
    "github.com/gofiber/fiber/v2"
    "github.com/google/uuid"
)

// WithRequestID adds a unique request ID to each request
func WithRequestID() Handler {
    return func(c *fiber.Ctx) error {
        // Check if request ID exists in header
        requestID := c.Get("X-Request-ID")
        if requestID == "" {
            // Generate new request ID
            requestID = uuid.New().String()
        }
        
        // Set in context
        c.Locals("request_id", requestID)
        
        // Set in response header
        c.Set("X-Request-ID", requestID)
        
        // Continue
        return c.Next()
    }
}