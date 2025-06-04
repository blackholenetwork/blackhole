// Package validation provides common validation functions
package validation

import (
    "fmt"
    "net/mail"
    "regexp"
    "strings"
)

var (
    // Common regex patterns
    uuidRegex     = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
    alphanumRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
    usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`)
    hashRegex     = regexp.MustCompile(`^[a-f0-9]{64}$`) // SHA256
)

// ValidateEmail validates email format
func ValidateEmail(email string) error {
    if email == "" {
        return fmt.Errorf("email cannot be empty")
    }
    
    _, err := mail.ParseAddress(email)
    if err != nil {
        return fmt.Errorf("invalid email format: %w", err)
    }
    
    return nil
}

// ValidateUUID validates UUID format
func ValidateUUID(uuid string) error {
    if uuid == "" {
        return fmt.Errorf("UUID cannot be empty")
    }
    
    if !uuidRegex.MatchString(strings.ToLower(uuid)) {
        return fmt.Errorf("invalid UUID format")
    }
    
    return nil
}

// ValidateUsername validates username format
func ValidateUsername(username string) error {
    if username == "" {
        return fmt.Errorf("username cannot be empty")
    }
    
    if !usernameRegex.MatchString(username) {
        return fmt.Errorf("username must be 3-32 characters, alphanumeric with _ and -")
    }
    
    return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
    if len(password) < 12 {
        return fmt.Errorf("password must be at least 12 characters")
    }
    
    var (
        hasUpper   bool
        hasLower   bool
        hasNumber  bool
        hasSpecial bool
    )
    
    for _, char := range password {
        switch {
        case 'A' <= char && char <= 'Z':
            hasUpper = true
        case 'a' <= char && char <= 'z':
            hasLower = true
        case '0' <= char && char <= '9':
            hasNumber = true
        case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
            hasSpecial = true
        }
    }
    
    if !hasUpper {
        return fmt.Errorf("password must contain at least one uppercase letter")
    }
    if !hasLower {
        return fmt.Errorf("password must contain at least one lowercase letter")
    }
    if !hasNumber {
        return fmt.Errorf("password must contain at least one number")
    }
    if !hasSpecial {
        return fmt.Errorf("password must contain at least one special character")
    }
    
    return nil
}

// ValidateFilename validates filename safety
func ValidateFilename(filename string) error {
    if filename == "" {
        return fmt.Errorf("filename cannot be empty")
    }
    
    if len(filename) > 255 {
        return fmt.Errorf("filename too long (max 255 characters)")
    }
    
    // Prevent path traversal
    if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
        return fmt.Errorf("filename contains invalid characters")
    }
    
    // Check for null bytes
    if strings.Contains(filename, "\x00") {
        return fmt.Errorf("filename contains null bytes")
    }
    
    return nil
}

// ValidateHash validates SHA256 hash format
func ValidateHash(hash string) error {
    if hash == "" {
        return fmt.Errorf("hash cannot be empty")
    }
    
    if !hashRegex.MatchString(strings.ToLower(hash)) {
        return fmt.Errorf("invalid hash format (expected 64 hex characters)")
    }
    
    return nil
}

// ValidatePort validates port number
func ValidatePort(port int) error {
    if port < 1 || port > 65535 {
        return fmt.Errorf("port must be between 1 and 65535")
    }
    return nil
}

// ValidatePercentage validates percentage value
func ValidatePercentage(value float64) error {
    if value < 0 || value > 100 {
        return fmt.Errorf("percentage must be between 0 and 100")
    }
    return nil
}

// ValidateSize validates size constraints
func ValidateSize(size int64, min, max int64) error {
    if size < min {
        return fmt.Errorf("size %d is below minimum %d", size, min)
    }
    if max > 0 && size > max {
        return fmt.Errorf("size %d exceeds maximum %d", size, max)
    }
    return nil
}

// ValidateEnum validates value is in allowed set
func ValidateEnum[T comparable](value T, allowed []T) error {
    for _, a := range allowed {
        if value == a {
            return nil
        }
    }
    return fmt.Errorf("value must be one of: %v", allowed)
}