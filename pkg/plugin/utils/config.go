// Package utils provides utility functions for plugins
package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blackholenetwork/blackhole/pkg/plugin"
)

// LoadConfig loads configuration from various sources
func LoadConfig(pluginName string, config plugin.Config, target interface{}) error {
	// First, apply defaults from struct tags
	if err := applyDefaults(target); err != nil {
		return fmt.Errorf("failed to apply defaults: %w", err)
	}

	// Load from config file if specified
	if configFile, ok := config["config_file"]; ok {
		if filename, ok := configFile.(string); ok {
			if err := loadFromFile(filename, target); err != nil {
				return fmt.Errorf("failed to load config file: %w", err)
			}
		}
	}

	// Apply overrides from plugin config
	if err := applyOverrides(config, target); err != nil {
		return fmt.Errorf("failed to apply config overrides: %w", err)
	}

	// Apply environment variables (highest priority)
	if err := applyEnvVars(pluginName, target); err != nil {
		return fmt.Errorf("failed to apply env vars: %w", err)
	}

	return nil
}

// applyDefaults applies default values from struct tags
func applyDefaults(target interface{}) error {
	v := reflect.ValueOf(target).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		defaultTag := field.Tag.Get("default")
		if defaultTag == "" {
			continue
		}

		fieldValue := v.Field(i)
		if err := setFieldValue(fieldValue, defaultTag); err != nil {
			return fmt.Errorf("failed to set default for %s: %w", field.Name, err)
		}
	}

	return nil
}

// loadFromFile loads configuration from a YAML file
func loadFromFile(filename string, target interface{}) error {
	// Validate file path
	if !isValidConfigFile(filename) {
		return fmt.Errorf("invalid config file path: %s", filename)
	}
	data, err := os.ReadFile(filename) // #nosec G304 - path is validated
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, target)
}

// applyOverrides applies configuration overrides
func applyOverrides(config plugin.Config, target interface{}) error {
	v := reflect.ValueOf(target).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		yamlTag := field.Tag.Get("yaml")
		if yamlTag == "" {
			yamlTag = strings.ToLower(field.Name)
		}

		// Check if config has this field
		if value, ok := config[yamlTag]; ok {
			fieldValue := v.Field(i)
			if err := setFieldFromInterface(fieldValue, value); err != nil {
				return fmt.Errorf("failed to set %s: %w", field.Name, err)
			}
		}
	}

	return nil
}

// applyEnvVars applies environment variables
func applyEnvVars(pluginName string, target interface{}) error {
	v := reflect.ValueOf(target).Elem()
	t := v.Type()

	prefix := strings.ToUpper(pluginName) + "_"

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		envTag := field.Tag.Get("env")
		if envTag == "" {
			envTag = prefix + strings.ToUpper(field.Name)
		}

		if value := os.Getenv(envTag); value != "" {
			fieldValue := v.Field(i)
			if err := setFieldValue(fieldValue, value); err != nil {
				return fmt.Errorf("failed to set %s from env: %w", field.Name, err)
			}
		}
	}

	return nil
}

// setFieldValue sets a field value from a string
func setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)

	case reflect.Int, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(intVal)

	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(boolVal)

	case reflect.Float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		field.SetFloat(floatVal)

	case reflect.Slice:
		if field.Type().Elem().Kind() == reflect.String {
			// Split comma-separated values
			parts := strings.Split(value, ",")
			slice := reflect.MakeSlice(field.Type(), len(parts), len(parts))
			for i, part := range parts {
				slice.Index(i).SetString(strings.TrimSpace(part))
			}
			field.Set(slice)
		}

	default:
		// Special handling for time.Duration
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			duration, err := time.ParseDuration(value)
			if err != nil {
				return err
			}
			field.Set(reflect.ValueOf(duration))
			return nil
		}

		return fmt.Errorf("unsupported field type: %v", field.Type())
	}

	return nil
}

// setFieldFromInterface sets a field value from an interface{}
func setFieldFromInterface(field reflect.Value, value interface{}) error {
	// Direct assignment if types match
	if reflect.TypeOf(value) == field.Type() {
		field.Set(reflect.ValueOf(value))
		return nil
	}

	// Otherwise convert to string and use setFieldValue
	strValue := fmt.Sprintf("%v", value)
	return setFieldValue(field, strValue)
}

// ValidateConfig validates configuration against constraints
func ValidateConfig(config interface{}) error {
	v := reflect.ValueOf(config).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Check required fields
		if required := field.Tag.Get("required"); required == "true" {
			if isZeroValue(fieldValue) {
				return fmt.Errorf("required field %s is not set", field.Name)
			}
		}

		// Check min/max for numeric fields
		if minVal := field.Tag.Get("min"); minVal != "" {
			if err := checkMin(fieldValue, minVal); err != nil {
				return fmt.Errorf("field %s: %w", field.Name, err)
			}
		}

		if maxVal := field.Tag.Get("max"); maxVal != "" {
			if err := checkMax(fieldValue, maxVal); err != nil {
				return fmt.Errorf("field %s: %w", field.Name, err)
			}
		}
	}

	return nil
}

// isZeroValue checks if a value is the zero value for its type
func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Int, reflect.Int64:
		return v.Int() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Float64:
		return v.Float() == 0
	case reflect.Slice:
		return v.Len() == 0
	default:
		return false
	}
}

// checkMin validates minimum value constraint
func checkMin(field reflect.Value, minStr string) error {
	switch field.Kind() {
	case reflect.Int, reflect.Int64:
		minVal, err := strconv.ParseInt(minStr, 10, 64)
		if err != nil {
			return err
		}
		if field.Int() < minVal {
			return fmt.Errorf("value %d is less than minimum %d", field.Int(), minVal)
		}
	case reflect.Float64:
		minVal, err := strconv.ParseFloat(minStr, 64)
		if err != nil {
			return err
		}
		if field.Float() < minVal {
			return fmt.Errorf("value %f is less than minimum %f", field.Float(), minVal)
		}
	}
	return nil
}

// checkMax validates maximum value constraint
func checkMax(field reflect.Value, maxStr string) error {
	switch field.Kind() {
	case reflect.Int, reflect.Int64:
		maxVal, err := strconv.ParseInt(maxStr, 10, 64)
		if err != nil {
			return err
		}
		if field.Int() > maxVal {
			return fmt.Errorf("value %d is greater than maximum %d", field.Int(), maxVal)
		}
	case reflect.Float64:
		maxVal, err := strconv.ParseFloat(maxStr, 64)
		if err != nil {
			return err
		}
		if field.Float() > maxVal {
			return fmt.Errorf("value %f is greater than maximum %f", field.Float(), maxVal)
		}
	}
	return nil
}

// isValidConfigFile validates that the config file is in expected locations
func isValidConfigFile(filename string) bool {
	absPath, err := filepath.Abs(filename)
	if err != nil {
		return false
	}

	// Allow relative paths in current directory
	cwd, err := os.Getwd()
	if err == nil && strings.HasPrefix(absPath, cwd) {
		return true
	}

	// Check if path is under home directory
	home, err := os.UserHomeDir()
	if err == nil {
		homeConfig := filepath.Join(home, ".blackhole")
		if strings.HasPrefix(absPath, homeConfig) {
			return true
		}
	}

	// Check if path is in system config directories
	systemDirs := []string{
		"/etc/blackhole",
		"/usr/local/etc/blackhole",
	}
	for _, dir := range systemDirs {
		if strings.HasPrefix(absPath, dir) {
			return true
		}
	}

	return false
}
