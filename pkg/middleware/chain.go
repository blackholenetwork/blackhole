package middleware

import (
    "github.com/gofiber/fiber/v2"
)

// Handler is the Fiber middleware function signature
type Handler = fiber.Handler

// Chain creates a middleware chain
func Chain(middlewares ...Handler) Handler {
    return func(c *fiber.Ctx) error {
        // Create the chain in reverse order
        handler := middlewares[len(middlewares)-1]
        
        for i := len(middlewares) - 2; i >= 0; i-- {
            middleware := middlewares[i]
            next := handler
            handler = func(c *fiber.Ctx) error {
                // Set next handler
                c.Locals("next", next)
                return middleware(c)
            }
        }
        
        return handler(c)
    }
}

// Wrap converts a middleware function to Fiber handler
func Wrap(fn func(c *fiber.Ctx) error) Handler {
    return fn
}