package version

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestSet(t *testing.T) {
	// Save original version
	originalVersion := version
	defer func() {
		version = originalVersion
	}()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Set valid version",
			input:    "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "Set semantic version",
			input:    "v2.0.0-beta.1",
			expected: "v2.0.0-beta.1",
		},
		{
			name:     "Empty string does not change version",
			input:    "",
			expected: version, // Should remain unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to known state
			version = "test-version"

			Set(tt.input)

			if tt.input == "" {
				// When input is empty, version should remain unchanged
				if version != "test-version" {
					t.Errorf("Set(%q) changed version to %q, expected no change", tt.input, version)
				}
			} else {
				if version != tt.expected {
					t.Errorf("Set(%q) = %q, want %q", tt.input, version, tt.expected)
				}
			}
		})
	}
}

func TestSetBuildInfo(t *testing.T) {
	// Save original values
	originalBuildTime := buildTime
	originalGitCommit := gitCommit
	defer func() {
		buildTime = originalBuildTime
		gitCommit = originalGitCommit
	}()

	tests := []struct {
		name             string
		inputTime        string
		inputCommit      string
		expectedTime     string
		expectedCommit   string
	}{
		{
			name:           "Set both time and commit",
			inputTime:      "2024-01-15T10:30:00Z",
			inputCommit:    "abc123def456",
			expectedTime:   "2024-01-15T10:30:00Z",
			expectedCommit: "abc123def456",
		},
		{
			name:           "Set only time",
			inputTime:      "2024-02-20T15:45:00Z",
			inputCommit:    "",
			expectedTime:   "2024-02-20T15:45:00Z",
			expectedCommit: "test-commit", // Should remain unchanged
		},
		{
			name:           "Set only commit",
			inputTime:      "",
			inputCommit:    "xyz789abc123",
			expectedTime:   "test-time", // Should remain unchanged
			expectedCommit: "xyz789abc123",
		},
		{
			name:           "Empty strings do not change values",
			inputTime:      "",
			inputCommit:    "",
			expectedTime:   "test-time",   // Should remain unchanged
			expectedCommit: "test-commit", // Should remain unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to known state
			buildTime = "test-time"
			gitCommit = "test-commit"

			SetBuildInfo(tt.inputTime, tt.inputCommit)

			if buildTime != tt.expectedTime {
				t.Errorf("SetBuildInfo() buildTime = %q, want %q", buildTime, tt.expectedTime)
			}
			if gitCommit != tt.expectedCommit {
				t.Errorf("SetBuildInfo() gitCommit = %q, want %q", gitCommit, tt.expectedCommit)
			}
		})
	}
}

func TestGet(t *testing.T) {
	// Save original version
	originalVersion := version
	defer func() {
		version = originalVersion
	}()

	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "Get development version",
			version:  "dev",
			expected: "dev",
		},
		{
			name:     "Get release version",
			version:  "1.0.0",
			expected: "1.0.0",
		},
		{
			name:     "Get beta version",
			version:  "2.0.0-beta.1",
			expected: "2.0.0-beta.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version = tt.version
			result := Get()
			if result != tt.expected {
				t.Errorf("Get() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetInfo(t *testing.T) {
	// Save original values
	originalVersion := version
	originalBuildTime := buildTime
	originalGitCommit := gitCommit
	defer func() {
		version = originalVersion
		buildTime = originalBuildTime
		gitCommit = originalGitCommit
	}()

	// Set test values
	version = "1.2.3"
	buildTime = "2024-01-15T10:30:00Z"
	gitCommit = "abc123def456"

	info := GetInfo()

	// Verify basic fields
	if info.Version != "1.2.3" {
		t.Errorf("GetInfo().Version = %q, want %q", info.Version, "1.2.3")
	}
	if info.BuildTime != "2024-01-15T10:30:00Z" {
		t.Errorf("GetInfo().BuildTime = %q, want %q", info.BuildTime, "2024-01-15T10:30:00Z")
	}
	if info.GitCommit != "abc123def456" {
		t.Errorf("GetInfo().GitCommit = %q, want %q", info.GitCommit, "abc123def456")
	}

	// Verify runtime fields
	if info.GoVersion != runtime.Version() {
		t.Errorf("GetInfo().GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	expectedPlatform := runtime.GOOS + "/" + runtime.GOARCH
	if info.Platform != expectedPlatform {
		t.Errorf("GetInfo().Platform = %q, want %q", info.Platform, expectedPlatform)
	}
}

func TestGetInfoDefaults(t *testing.T) {
	// Save original values
	originalVersion := version
	originalBuildTime := buildTime
	originalGitCommit := gitCommit
	defer func() {
		version = originalVersion
		buildTime = originalBuildTime
		gitCommit = originalGitCommit
	}()

	// Reset to default values
	version = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"

	info := GetInfo()

	// Verify default values
	if info.Version != "dev" {
		t.Errorf("GetInfo().Version = %q, want %q", info.Version, "dev")
	}
	if info.BuildTime != "unknown" {
		t.Errorf("GetInfo().BuildTime = %q, want %q", info.BuildTime, "unknown")
	}
	if info.GitCommit != "unknown" {
		t.Errorf("GetInfo().GitCommit = %q, want %q", info.GitCommit, "unknown")
	}
}

func TestInfoJSON(t *testing.T) {
	// Save original values
	originalVersion := version
	originalBuildTime := buildTime
	originalGitCommit := gitCommit
	defer func() {
		version = originalVersion
		buildTime = originalBuildTime
		gitCommit = originalGitCommit
	}()

	// Set test values
	version = "1.0.0"
	buildTime = "2024-01-01T00:00:00Z"
	gitCommit = "1234567890abcdef"

	info := GetInfo()

	// Marshal to JSON
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Failed to marshal Info to JSON: %v", err)
	}

	// Unmarshal back
	var decoded Info
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal Info from JSON: %v", err)
	}

	// Verify all fields survived the round trip
	if decoded.Version != info.Version {
		t.Errorf("JSON round trip: Version = %q, want %q", decoded.Version, info.Version)
	}
	if decoded.BuildTime != info.BuildTime {
		t.Errorf("JSON round trip: BuildTime = %q, want %q", decoded.BuildTime, info.BuildTime)
	}
	if decoded.GitCommit != info.GitCommit {
		t.Errorf("JSON round trip: GitCommit = %q, want %q", decoded.GitCommit, info.GitCommit)
	}
	if decoded.GoVersion != info.GoVersion {
		t.Errorf("JSON round trip: GoVersion = %q, want %q", decoded.GoVersion, info.GoVersion)
	}
	if decoded.Platform != info.Platform {
		t.Errorf("JSON round trip: Platform = %q, want %q", decoded.Platform, info.Platform)
	}

	// Verify JSON contains expected fields
	jsonStr := string(data)
	expectedFields := []string{"version", "build_time", "git_commit", "go_version", "platform"}
	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, `"`+field+`"`) {
			t.Errorf("JSON output missing field %q", field)
		}
	}
}

func TestPlatformString(t *testing.T) {
	info := GetInfo()

	// Platform should be in format "os/arch"
	parts := strings.Split(info.Platform, "/")
	if len(parts) != 2 {
		t.Errorf("Platform format incorrect: %q, expected 'os/arch'", info.Platform)
	}

	// First part should be GOOS
	if parts[0] != runtime.GOOS {
		t.Errorf("Platform OS = %q, want %q", parts[0], runtime.GOOS)
	}

	// Second part should be GOARCH
	if parts[1] != runtime.GOARCH {
		t.Errorf("Platform arch = %q, want %q", parts[1], runtime.GOARCH)
	}
}

func TestGoVersionFormat(t *testing.T) {
	info := GetInfo()

	// Go version should start with "go"
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Errorf("GoVersion format incorrect: %q, expected to start with 'go'", info.GoVersion)
	}

	// Should match runtime version exactly
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
}

// Benchmark tests
func BenchmarkGet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Get()
	}
}

func BenchmarkGetInfo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = GetInfo()
	}
}

func BenchmarkInfoJSON(b *testing.B) {
	info := GetInfo()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(info)
	}
}
