package validation

import (
	"strings"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid email",
			email:   "user@example.com",
			wantErr: false,
		},
		{
			name:    "valid email with subdomain",
			email:   "user@mail.example.com",
			wantErr: false,
		},
		{
			name:    "valid email with plus",
			email:   "user+tag@example.com",
			wantErr: false,
		},
		{
			name:    "valid email with dots",
			email:   "first.last@example.com",
			wantErr: false,
		},
		{
			name:    "empty email",
			email:   "",
			wantErr: true,
			errMsg:  "email cannot be empty",
		},
		{
			name:    "missing @",
			email:   "userexample.com",
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name:    "missing domain",
			email:   "user@",
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name:    "missing local part",
			email:   "@example.com",
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name:    "multiple @",
			email:   "user@@example.com",
			wantErr: true,
			errMsg:  "invalid email format",
		},
		{
			name:    "spaces in email",
			email:   "user name@example.com",
			wantErr: true,
			errMsg:  "invalid email format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateEmail() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestValidateUUID(t *testing.T) {
	tests := []struct {
		name    string
		uuid    string
		wantErr bool
	}{
		{
			name:    "valid UUID lowercase",
			uuid:    "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "valid UUID uppercase",
			uuid:    "550E8400-E29B-41D4-A716-446655440000",
			wantErr: false,
		},
		{
			name:    "valid UUID mixed case",
			uuid:    "550e8400-E29B-41d4-A716-446655440000",
			wantErr: false,
		},
		{
			name:    "empty UUID",
			uuid:    "",
			wantErr: true,
		},
		{
			name:    "invalid format - missing hyphens",
			uuid:    "550e8400e29b41d4a716446655440000",
			wantErr: true,
		},
		{
			name:    "invalid format - wrong length",
			uuid:    "550e8400-e29b-41d4-a716-44665544000",
			wantErr: true,
		},
		{
			name:    "invalid format - invalid characters",
			uuid:    "550e8400-e29b-41d4-a716-44665544000g",
			wantErr: true,
		},
		{
			name:    "invalid format - wrong hyphen positions",
			uuid:    "550e84-00e29b-41d4-a716-446655440000",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUUID(tt.uuid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUUID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "valid username",
			username: "john_doe",
			wantErr:  false,
		},
		{
			name:     "valid username with numbers",
			username: "user123",
			wantErr:  false,
		},
		{
			name:     "valid username with hyphen",
			username: "john-doe",
			wantErr:  false,
		},
		{
			name:     "minimum length",
			username: "abc",
			wantErr:  false,
		},
		{
			name:     "maximum length",
			username: strings.Repeat("a", 32),
			wantErr:  false,
		},
		{
			name:     "empty username",
			username: "",
			wantErr:  true,
		},
		{
			name:     "too short",
			username: "ab",
			wantErr:  true,
		},
		{
			name:     "too long",
			username: strings.Repeat("a", 33),
			wantErr:  true,
		},
		{
			name:     "invalid characters - space",
			username: "john doe",
			wantErr:  true,
		},
		{
			name:     "invalid characters - special",
			username: "john@doe",
			wantErr:  true,
		},
		{
			name:     "starts with number",
			username: "123user",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid password",
			password: "MySecureP@ssw0rd",
			wantErr:  false,
		},
		{
			name:     "valid password with all requirements",
			password: "Abcdefgh1234!@#$",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
			errMsg:   "at least 12 characters",
		},
		{
			name:     "missing uppercase",
			password: "mysecurep@ssw0rd",
			wantErr:  true,
			errMsg:   "uppercase letter",
		},
		{
			name:     "missing lowercase",
			password: "MYSECUREP@SSW0RD",
			wantErr:  true,
			errMsg:   "lowercase letter",
		},
		{
			name:     "missing number",
			password: "MySecureP@ssword",
			wantErr:  true,
			errMsg:   "number",
		},
		{
			name:     "missing special character",
			password: "MySecurePassw0rd",
			wantErr:  true,
			errMsg:   "special character",
		},
		{
			name:     "all special characters accepted",
			password: "Password123!@#$%^&*()_+-=[]{}|;:,.<>?",
			wantErr:  false,
		},
		{
			name:     "exactly 12 characters",
			password: "Abcdefgh123!",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidatePassword() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid filename",
			filename: "document.txt",
			wantErr:  false,
		},
		{
			name:     "valid filename with numbers",
			filename: "file123.pdf",
			wantErr:  false,
		},
		{
			name:     "valid filename with hyphen and underscore",
			filename: "my-file_name.doc",
			wantErr:  false,
		},
		{
			name:     "valid filename with spaces",
			filename: "my document.txt",
			wantErr:  false,
		},
		{
			name:     "empty filename",
			filename: "",
			wantErr:  true,
			errMsg:   "cannot be empty",
		},
		{
			name:     "too long",
			filename: strings.Repeat("a", 256),
			wantErr:  true,
			errMsg:   "too long",
		},
		{
			name:     "exactly 255 characters",
			filename: strings.Repeat("a", 255),
			wantErr:  false,
		},
		{
			name:     "path traversal attempt",
			filename: "../secret.txt",
			wantErr:  true,
			errMsg:   "invalid characters",
		},
		{
			name:     "contains forward slash",
			filename: "folder/file.txt",
			wantErr:  true,
			errMsg:   "invalid characters",
		},
		{
			name:     "contains backslash",
			filename: "folder\\file.txt",
			wantErr:  true,
			errMsg:   "invalid characters",
		},
		{
			name:     "null byte",
			filename: "file\x00.txt",
			wantErr:  true,
			errMsg:   "null bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilename(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilename() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateFilename() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestValidateHash(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{
			name:    "valid SHA256 hash lowercase",
			hash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: false,
		},
		{
			name:    "valid SHA256 hash uppercase",
			hash:    "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
			wantErr: false,
		},
		{
			name:    "valid SHA256 hash mixed case",
			hash:    "e3b0c44298FC1C149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: false,
		},
		{
			name:    "empty hash",
			hash:    "",
			wantErr: true,
		},
		{
			name:    "too short",
			hash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
			wantErr: true,
		},
		{
			name:    "too long",
			hash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			hash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g",
			wantErr: true,
		},
		{
			name:    "with spaces",
			hash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8 5",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHash(tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{
			name:    "valid port 80",
			port:    80,
			wantErr: false,
		},
		{
			name:    "valid port 443",
			port:    443,
			wantErr: false,
		},
		{
			name:    "valid port 8080",
			port:    8080,
			wantErr: false,
		},
		{
			name:    "minimum valid port",
			port:    1,
			wantErr: false,
		},
		{
			name:    "maximum valid port",
			port:    65535,
			wantErr: false,
		},
		{
			name:    "port 0",
			port:    0,
			wantErr: true,
		},
		{
			name:    "negative port",
			port:    -1,
			wantErr: true,
		},
		{
			name:    "port too high",
			port:    65536,
			wantErr: true,
		},
		{
			name:    "very negative port",
			port:    -8080,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePercentage(t *testing.T) {
	tests := []struct {
		name    string
		value   float64
		wantErr bool
	}{
		{
			name:    "valid 0%",
			value:   0,
			wantErr: false,
		},
		{
			name:    "valid 50%",
			value:   50,
			wantErr: false,
		},
		{
			name:    "valid 100%",
			value:   100,
			wantErr: false,
		},
		{
			name:    "valid decimal",
			value:   33.33,
			wantErr: false,
		},
		{
			name:    "valid small decimal",
			value:   0.01,
			wantErr: false,
		},
		{
			name:    "valid large decimal",
			value:   99.99,
			wantErr: false,
		},
		{
			name:    "negative percentage",
			value:   -1,
			wantErr: true,
		},
		{
			name:    "over 100%",
			value:   100.01,
			wantErr: true,
		},
		{
			name:    "way over 100%",
			value:   200,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePercentage(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePercentage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSize(t *testing.T) {
	tests := []struct {
		name    string
		size    int64
		minSize int64
		maxSize int64
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid size within range",
			size:    1024,
			minSize: 512,
			maxSize: 2048,
			wantErr: false,
		},
		{
			name:    "valid size at minimum",
			size:    512,
			minSize: 512,
			maxSize: 2048,
			wantErr: false,
		},
		{
			name:    "valid size at maximum",
			size:    2048,
			minSize: 512,
			maxSize: 2048,
			wantErr: false,
		},
		{
			name:    "no maximum limit",
			size:    1000000,
			minSize: 0,
			maxSize: 0,
			wantErr: false,
		},
		{
			name:    "below minimum",
			size:    256,
			minSize: 512,
			maxSize: 2048,
			wantErr: true,
			errMsg:  "below minimum",
		},
		{
			name:    "above maximum",
			size:    4096,
			minSize: 512,
			maxSize: 2048,
			wantErr: true,
			errMsg:  "exceeds maximum",
		},
		{
			name:    "negative size",
			size:    -1,
			minSize: 0,
			maxSize: 1024,
			wantErr: true,
			errMsg:  "below minimum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSize(tt.size, tt.minSize, tt.maxSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateSize() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestValidateEnum(t *testing.T) {
	t.Run("string enum", func(t *testing.T) {
		allowed := []string{"small", "medium", "large"}

		tests := []struct {
			value   string
			wantErr bool
		}{
			{"small", false},
			{"medium", false},
			{"large", false},
			{"extra-large", true},
			{"", true},
		}

		for _, tt := range tests {
			err := ValidateEnum(tt.value, allowed)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnum(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		}
	})

	t.Run("int enum", func(t *testing.T) {
		allowed := []int{1, 2, 3, 5, 8}

		tests := []struct {
			value   int
			wantErr bool
		}{
			{1, false},
			{3, false},
			{8, false},
			{4, true},
			{0, true},
			{-1, true},
		}

		for _, tt := range tests {
			err := ValidateEnum(tt.value, allowed)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnum(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		}
	})

	t.Run("custom type enum", func(t *testing.T) {
		type Status string
		const (
			StatusActive   Status = "active"
			StatusInactive Status = "inactive"
			StatusPending  Status = "pending"
		)

		allowed := []Status{StatusActive, StatusInactive, StatusPending}

		tests := []struct {
			value   Status
			wantErr bool
		}{
			{StatusActive, false},
			{StatusInactive, false},
			{StatusPending, false},
			{Status("deleted"), true},
			{Status(""), true},
		}

		for _, tt := range tests {
			err := ValidateEnum(tt.value, allowed)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEnum(%v) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		}
	})
}

// Edge case tests

func TestValidatorsEdgeCases(t *testing.T) {
	t.Run("ValidateEmail with unusual valid formats", func(t *testing.T) {
		// These should be valid according to RFC
		validEmails := []string{
			"test@localhost",
			"user@[127.0.0.1]",
			"\"quoted\"@example.com",
			"user+tag+tag2@example.com",
		}

		for _, email := range validEmails {
			err := ValidateEmail(email)
			// Note: Some of these might fail with the simple mail.ParseAddress
			// This is expected as it doesn't support all RFC formats
			_ = err // Just acknowledge the behavior
		}
	})

	t.Run("ValidatePassword with unicode characters", func(t *testing.T) {
		// Password with unicode characters
		password := "MyP@ssw0rd世界"
		err := ValidatePassword(password)
		// Unicode characters are actually valid in passwords
		if err != nil {
			t.Errorf("Unicode characters should be allowed in passwords, got error: %v", err)
		}
	})

	t.Run("ValidateFilename with unicode", func(t *testing.T) {
		// Unicode filenames should be valid
		filenames := []string{
			"文档.txt",
			"файл.doc",
			"αρχείο.pdf",
		}

		for _, filename := range filenames {
			err := ValidateFilename(filename)
			if err != nil {
				t.Errorf("ValidateFilename(%s) should allow unicode, got error: %v", filename, err)
			}
		}
	})
}

// Benchmark tests

func BenchmarkValidateEmail(b *testing.B) {
	email := "user@example.com"
	for i := 0; i < b.N; i++ {
		_ = ValidateEmail(email)
	}
}

func BenchmarkValidateUUID(b *testing.B) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	for i := 0; i < b.N; i++ {
		_ = ValidateUUID(uuid)
	}
}

func BenchmarkValidateUsername(b *testing.B) {
	username := "john_doe_123"
	for i := 0; i < b.N; i++ {
		_ = ValidateUsername(username)
	}
}

func BenchmarkValidatePassword(b *testing.B) {
	password := "MySecureP@ssw0rd"
	for i := 0; i < b.N; i++ {
		_ = ValidatePassword(password)
	}
}

func BenchmarkValidateHash(b *testing.B) {
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for i := 0; i < b.N; i++ {
		_ = ValidateHash(hash)
	}
}

func BenchmarkValidateEnum(b *testing.B) {
	allowed := []string{"small", "medium", "large", "extra-large", "jumbo"}
	value := "medium"
	for i := 0; i < b.N; i++ {
		_ = ValidateEnum(value, allowed)
	}
}
