package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// Test structs for configuration testing
type TestConfig struct {
	StringField  string        `yaml:"string_field" default:"default_value" required:"true"`
	IntField     int           `yaml:"int_field" default:"42" min:"1" max:"100"`
	BoolField    bool          `yaml:"bool_field" default:"true"`
	FloatField   float64       `yaml:"float_field" default:"3.14"`
	SliceField   []string      `yaml:"slice_field" default:"a,b,c"`
	Duration     time.Duration `yaml:"duration" default:"5s"`
	NoTagField   string        // Should use lowercase field name
	RequiredInt  int           `yaml:"required_int" required:"true" min:"10"`
	MaxValueInt  int           `yaml:"max_value" max:"50"`
}

type InvalidDefaultConfig struct {
	BadInt int `default:"not_an_int"`
}

func TestLoadConfig_Defaults(t *testing.T) {
	var config TestConfig
	pluginConfig := make(plugin.Config)

	err := LoadConfig("test", pluginConfig, &config)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check defaults were applied
	if config.StringField != "default_value" {
		t.Errorf("Expected 'default_value', got %s", config.StringField)
	}
	if config.IntField != 42 {
		t.Errorf("Expected 42, got %d", config.IntField)
	}
	if !config.BoolField {
		t.Error("Expected true, got false")
	}
	if config.FloatField != 3.14 {
		t.Errorf("Expected 3.14, got %f", config.FloatField)
	}
	if config.Duration != 5*time.Second {
		t.Errorf("Expected 5s, got %v", config.Duration)
	}
	if !reflect.DeepEqual(config.SliceField, []string{"a", "b", "c"}) {
		t.Errorf("Expected [a b c], got %v", config.SliceField)
	}
}

func TestLoadConfig_PluginOverrides(t *testing.T) {
	var config TestConfig
	pluginConfig := plugin.Config{
		"string_field": "override_value",
		"int_field":    99,
		"bool_field":   false,
		"notagfield":   "no_tag_override", // Should use lowercase field name
	}

	err := LoadConfig("test", pluginConfig, &config)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.StringField != "override_value" {
		t.Errorf("Expected 'override_value', got %s", config.StringField)
	}
	if config.IntField != 99 {
		t.Errorf("Expected 99, got %d", config.IntField)
	}
	if config.BoolField {
		t.Error("Expected false, got true")
	}
	if config.NoTagField != "no_tag_override" {
		t.Errorf("Expected 'no_tag_override', got %s", config.NoTagField)
	}
}

func TestLoadConfig_EnvironmentVariables(t *testing.T) {
	// Set environment variables before creating config (using correct field names)
	_ = os.Setenv("TEST_STRINGFIELD", "env_value")
	_ = os.Setenv("TEST_INTFIELD", "123")
	_ = os.Setenv("TEST_BOOLFIELD", "false")
	defer func() {
		_ = os.Unsetenv("TEST_STRINGFIELD")
		_ = os.Unsetenv("TEST_INTFIELD")
		_ = os.Unsetenv("TEST_BOOLFIELD")
	}()

	var config TestConfig
	pluginConfig := make(plugin.Config)

	err := LoadConfig("test", pluginConfig, &config)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Environment variables should override defaults
	if config.StringField != "env_value" {
		t.Errorf("Expected 'env_value', got %s", config.StringField)
	}
	if config.IntField != 123 {
		t.Errorf("Expected 123, got %d", config.IntField)
	}
	if config.BoolField {
		t.Error("Expected false, got true")
	}
}

func TestLoadConfig_ConfigFile(t *testing.T) {
	// Create config file in current directory (which is allowed)
	configContent := `
string_field: "file_value"
int_field: 77
bool_field: false
slice_field: ["x", "y", "z"]
`
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	configFile := filepath.Join(cwd, "test_config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}
	defer func() { _ = os.Remove(configFile) }() // Clean up

	var config TestConfig
	pluginConfig := plugin.Config{
		"config_file": configFile,
	}

	err = LoadConfig("test", pluginConfig, &config)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.StringField != "file_value" {
		t.Errorf("Expected 'file_value', got %s", config.StringField)
	}
	if config.IntField != 77 {
		t.Errorf("Expected 77, got %d", config.IntField)
	}
	if config.BoolField {
		t.Error("Expected false, got true")
	}
}

func TestLoadConfig_PriorityOrder(t *testing.T) {
	// Create config file in current directory
	configContent := `
string_field: "file_value"
int_field: 77
`
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	configFile := filepath.Join(cwd, "test_priority_config.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}
	defer func() { _ = os.Remove(configFile) }() // Clean up

	// Set environment variable (should have highest priority)
	_ = os.Setenv("TEST_STRINGFIELD", "env_value")
	defer func() { _ = os.Unsetenv("TEST_STRINGFIELD") }()

	var config TestConfig
	pluginConfig := plugin.Config{
		"config_file":  configFile,
		"string_field": "plugin_override", // Should be overridden by env var
		"int_field":    88,                // Should override file value
	}

	err = LoadConfig("test", pluginConfig, &config)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Environment variable should win
	if config.StringField != "env_value" {
		t.Errorf("Expected 'env_value' (env var), got %s", config.StringField)
	}
	// Plugin config should override file
	if config.IntField != 88 {
		t.Errorf("Expected 88 (plugin config), got %d", config.IntField)
	}
}

func TestApplyDefaults_InvalidDefault(t *testing.T) {
	var config InvalidDefaultConfig
	err := applyDefaults(&config)
	if err == nil {
		t.Error("Expected error for invalid default value")
	}
}

func TestSetFieldValue_AllTypes(t *testing.T) {
	var config TestConfig
	v := reflect.ValueOf(&config).Elem()

	// Test string
	stringField := v.FieldByName("StringField")
	err := setFieldValue(stringField, "test_string")
	if err != nil {
		t.Errorf("String field error: %v", err)
	}
	if config.StringField != "test_string" {
		t.Errorf("Expected 'test_string', got %s", config.StringField)
	}

	// Test int
	intField := v.FieldByName("IntField")
	err = setFieldValue(intField, "999")
	if err != nil {
		t.Errorf("Int field error: %v", err)
	}
	if config.IntField != 999 {
		t.Errorf("Expected 999, got %d", config.IntField)
	}

	// Test bool
	boolField := v.FieldByName("BoolField")
	err = setFieldValue(boolField, "false")
	if err != nil {
		t.Errorf("Bool field error: %v", err)
	}
	if config.BoolField {
		t.Error("Expected false, got true")
	}

	// Test float64
	floatField := v.FieldByName("FloatField")
	err = setFieldValue(floatField, "2.71")
	if err != nil {
		t.Errorf("Float field error: %v", err)
	}
	if config.FloatField != 2.71 {
		t.Errorf("Expected 2.71, got %f", config.FloatField)
	}

	// Test duration
	durationField := v.FieldByName("Duration")
	err = setFieldValue(durationField, "10m")
	if err != nil {
		t.Errorf("Duration field error: %v", err)
	}
	if config.Duration != 10*time.Minute {
		t.Errorf("Expected 10m, got %v", config.Duration)
	}

	// Test slice
	sliceField := v.FieldByName("SliceField")
	err = setFieldValue(sliceField, "one,two,three")
	if err != nil {
		t.Errorf("Slice field error: %v", err)
	}
	expected := []string{"one", "two", "three"}
	if !reflect.DeepEqual(config.SliceField, expected) {
		t.Errorf("Expected %v, got %v", expected, config.SliceField)
	}
}

func TestSetFieldValue_InvalidValues(t *testing.T) {
	var config TestConfig
	v := reflect.ValueOf(&config).Elem()

	// Test invalid int
	intField := v.FieldByName("IntField")
	err := setFieldValue(intField, "not_a_number")
	if err == nil {
		t.Error("Expected error for invalid int")
	}

	// Test invalid bool
	boolField := v.FieldByName("BoolField")
	err = setFieldValue(boolField, "not_a_bool")
	if err == nil {
		t.Error("Expected error for invalid bool")
	}

	// Test invalid float
	floatField := v.FieldByName("FloatField")
	err = setFieldValue(floatField, "not_a_float")
	if err == nil {
		t.Error("Expected error for invalid float")
	}

	// Test invalid duration
	durationField := v.FieldByName("Duration")
	err = setFieldValue(durationField, "not_a_duration")
	if err == nil {
		t.Error("Expected error for invalid duration")
	}
}

func TestSetFieldFromInterface(t *testing.T) {
	var config TestConfig
	v := reflect.ValueOf(&config).Elem()

	// Test direct type match
	stringField := v.FieldByName("StringField")
	err := setFieldFromInterface(stringField, "direct_string")
	if err != nil {
		t.Errorf("Direct string assignment failed: %v", err)
	}
	if config.StringField != "direct_string" {
		t.Errorf("Expected 'direct_string', got %s", config.StringField)
	}

	// Test type conversion
	intField := v.FieldByName("IntField")
	err = setFieldFromInterface(intField, 42.0) // float64 to int conversion
	if err != nil {
		t.Errorf("Type conversion failed: %v", err)
	}
	if config.IntField != 42 {
		t.Errorf("Expected 42, got %d", config.IntField)
	}
}

func TestValidateConfig(t *testing.T) {
	// Test valid config
	config := TestConfig{
		StringField: "valid",
		IntField:    42,  // Above minimum of 1
		RequiredInt: 15,  // Above minimum of 10
		MaxValueInt: 30,  // Below maximum of 50
	}
	err := ValidateConfig(&config)
	if err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	// Test missing required field
	config2 := TestConfig{
		// StringField is required but not set
		RequiredInt: 15,
	}
	err = ValidateConfig(&config2)
	if err == nil {
		t.Error("Expected error for missing required field")
	}

	// Test below minimum
	config3 := TestConfig{
		StringField: "valid",
		RequiredInt: 5, // Below minimum of 10
	}
	err = ValidateConfig(&config3)
	if err == nil {
		t.Error("Expected error for value below minimum")
	}

	// Test above maximum
	config4 := TestConfig{
		StringField: "valid",
		RequiredInt: 15,
		MaxValueInt: 60, // Above maximum of 50
	}
	err = ValidateConfig(&config4)
	if err == nil {
		t.Error("Expected error for value above maximum")
	}
}

func TestIsZeroValue(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		{"empty string", "", true},
		{"non-empty string", "test", false},
		{"zero int", 0, true},
		{"non-zero int", 42, false},
		{"false bool", false, true},
		{"true bool", true, false},
		{"zero float", 0.0, true},
		{"non-zero float", 3.14, false},
		{"empty slice", []string{}, true},
		{"non-empty slice", []string{"a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := reflect.ValueOf(tt.value)
			result := isZeroValue(v)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsValidConfigFile(t *testing.T) {
	// Test current directory file
	cwd, _ := os.Getwd()
	testFile := filepath.Join(cwd, "test.yaml")
	if !isValidConfigFile(testFile) {
		t.Error("File in current directory should be valid")
	}

	// Test relative path
	if !isValidConfigFile("./test.yaml") {
		t.Error("Relative path in current directory should be valid")
	}

	// Test home directory config
	home, _ := os.UserHomeDir()
	homeConfigFile := filepath.Join(home, ".blackhole", "config.yaml")
	if !isValidConfigFile(homeConfigFile) {
		t.Error("File in home .blackhole directory should be valid")
	}

	// Test system config directory
	systemConfigFile := "/etc/blackhole/config.yaml"
	if !isValidConfigFile(systemConfigFile) {
		t.Error("File in system config directory should be valid")
	}

	// Test invalid path (should be rejected for security)
	if isValidConfigFile("/etc/passwd") {
		t.Error("File outside allowed directories should be invalid")
	}

	// Test invalid path that doesn't exist
	if isValidConfigFile("/nonexistent/path/config.yaml") {
		t.Error("Nonexistent path should be invalid")
	}
}

func TestLoadFromFile_InvalidPath(t *testing.T) {
	var config TestConfig
	err := loadFromFile("/etc/passwd", &config) // Invalid config file path
	if err == nil {
		t.Error("Expected error for invalid config file path")
	}
}

func TestLoadFromFile_NonexistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	nonexistentFile := filepath.Join(tmpDir, "nonexistent.yaml")

	var config TestConfig
	err := loadFromFile(nonexistentFile, &config)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	// Create file with invalid YAML
	invalidYAML := `
invalid: yaml: content:
  - this is not
    valid yaml
`
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(configFile, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid YAML file: %v", err)
	}

	var config TestConfig
	err = loadFromFile(configFile, &config)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestCustomEnvTag(t *testing.T) {
	type CustomEnvConfig struct {
		Field1 string `env:"CUSTOM_FIELD_1"`
		Field2 string `env:"CUSTOM_FIELD_2"`
	}

	// Set custom environment variables
	_ = os.Setenv("CUSTOM_FIELD_1", "custom_value_1")
	_ = os.Setenv("CUSTOM_FIELD_2", "custom_value_2")
	defer func() {
		_ = os.Unsetenv("CUSTOM_FIELD_1")
		_ = os.Unsetenv("CUSTOM_FIELD_2")
	}()

	var config CustomEnvConfig
	pluginConfig := make(plugin.Config)

	err := LoadConfig("test", pluginConfig, &config)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Field1 != "custom_value_1" {
		t.Errorf("Expected 'custom_value_1', got %s", config.Field1)
	}
	if config.Field2 != "custom_value_2" {
		t.Errorf("Expected 'custom_value_2', got %s", config.Field2)
	}
}

func TestCheckMinMax_FloatValues(t *testing.T) {
	type FloatConfig struct {
		MinFloat float64 `min:"1.5"`
		MaxFloat float64 `max:"9.5"`
	}

	// Test valid values
	validConfig := FloatConfig{
		MinFloat: 2.0,
		MaxFloat: 8.0,
	}
	err := ValidateConfig(&validConfig)
	if err != nil {
		t.Errorf("Valid float config should not produce error: %v", err)
	}

	// Test below minimum
	belowMinConfig := FloatConfig{
		MinFloat: 1.0, // Below 1.5
		MaxFloat: 8.0,
	}
	err = ValidateConfig(&belowMinConfig)
	if err == nil {
		t.Error("Expected error for float value below minimum")
	}

	// Test above maximum
	aboveMaxConfig := FloatConfig{
		MinFloat: 2.0,
		MaxFloat: 10.0, // Above 9.5
	}
	err = ValidateConfig(&aboveMaxConfig)
	if err == nil {
		t.Error("Expected error for float value above maximum")
	}
}
