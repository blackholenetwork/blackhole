package middleware

import (
    "strings"
    
    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
)

// AuthConfig configures auth middleware
type AuthConfig struct {
    Secret       []byte
    SkipPaths    []string
    ErrorHandler fiber.ErrorHandler
}

// Claims represents JWT claims
type Claims struct {
    jwt.RegisteredClaims
    UserID string   `json:"user_id"`
    Tier   string   `json:"tier"`
    Scopes []string `json:"scopes"`
}

// WithAuth creates JWT authentication middleware
func WithAuth(config AuthConfig) Handler {
    return func(c *fiber.Ctx) error {
        // Skip auth for certain paths
        for _, path := range config.SkipPaths {
            if c.Path() == path {
                return c.Next()
            }
        }
        
        // Get token from header
        auth := c.Get("Authorization")
        if auth == "" {
            return fiber.NewError(fiber.StatusUnauthorized, "missing authorization header")
        }
        
        // Extract token
        parts := strings.Split(auth, " ")
        if len(parts) != 2 || parts[0] != "Bearer" {
            return fiber.NewError(fiber.StatusUnauthorized, "invalid authorization format")
        }
        
        tokenString := parts[1]
        
        // Parse and validate token
        token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
            return config.Secret, nil
        })
        
        if err != nil || !token.Valid {
            return fiber.NewError(fiber.StatusUnauthorized, "invalid token")
        }
        
        // Extract claims
        claims, ok := token.Claims.(*Claims)
        if !ok {
            return fiber.NewError(fiber.StatusUnauthorized, "invalid claims")
        }
        
        // Store in context
        c.Locals("user_id", claims.UserID)
        c.Locals("tier", claims.Tier)
        c.Locals("scopes", claims.Scopes)
        
        return c.Next()
    }
}

// RequireScope checks if user has required scope
func RequireScope(scope string) Handler {
    return func(c *fiber.Ctx) error {
        scopes, ok := c.Locals("scopes").([]string)
        if !ok {
            return fiber.NewError(fiber.StatusForbidden, "no scopes found")
        }
        
        for _, s := range scopes {
            if s == scope {
                return c.Next()
            }
        }
        
        return fiber.NewError(fiber.StatusForbidden, "insufficient scope")
    }
}