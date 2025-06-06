# Development Tooling and Automation

This document describes tools and automation that help maintain code quality and reduce boilerplate.

## Code Generation

### 1. Interface Mocks

```bash
# Install mockgen
go install github.com/golang/mock/mockgen@latest

# Generate mocks for testing
#go:generate mockgen -source=storage.go -destination=mocks/storage_mock.go -package=mocks
type Storage interface {
    GetFile(ctx context.Context, id string) (*File, error)
    StoreFile(ctx context.Context, data []byte) (string, error)
}

# Run generation
go generate ./...
```

### 2. Struct Tags and Validation

```go
// Use struct tags for automatic validation
type CreateFileRequest struct {
    Name string `json:"name" validate:"required,min=1,max=255" example:"document.pdf"`
    Size int64  `json:"size" validate:"required,min=1,max=5368709120" example:"1048576"`
    Type string `json:"type" validate:"required,oneof=document image video" example:"document"`
}

// Generate validation code
//go:generate go run github.com/go-playground/validator/v10/cmd/generate
```

### 3. API Documentation

```go
// Auto-generate OpenAPI spec from code
//go:generate swag init -g cmd/api/main.go -o docs/api

// @title Blackhole Network API
// @version 1.0
// @description Decentralized storage and compute API

// @contact.name API Support
// @contact.email support@blackhole.network

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host api.blackhole.network
// @BasePath /api/v1

// GetFile godoc
// @Summary Get file by ID
// @Description Returns file metadata and download URL
// @Tags files
// @Accept json
// @Produce json
// @Param id path string true "File ID"
// @Success 200 {object} FileResponse
// @Failure 404 {object} ErrorResponse
// @Router /files/{id} [get]
func GetFile(c *fiber.Ctx) error {
    // Implementation
}
```

## Linting and Formatting

### 1. Linter Configuration

```yaml
# .golangci.yml
run:
  timeout: 5m
  tests: true

linters:
  enable:
    - gofmt
    - goimports
    - golint
    - govet
    - ineffassign
    - misspell
    - unconvert
    - gocritic
    - gocognit
    - godox
    - gosec
    - nakedret
    - prealloc
    - scopelint
    - goconst
    - gocyclo

linters-settings:
  gocyclo:
    min-complexity: 15
  goconst:
    min-len: 3
    min-occurrences: 3
  misspell:
    locale: US
  goimports:
    local-prefixes: github.com/blackhole
  gocritic:
    enabled-tags:
      - diagnostic
      - experimental
      - opinionated
      - performance
      - style

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - gocyclo
        - errcheck
        - dupl
        - gosec
```

### 2. Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-merge-conflict
      - id: check-added-large-files
        args: ['--maxkb=1024']

  - repo: https://github.com/dnephin/pre-commit-golang
    rev: v0.5.1
    hooks:
      - id: go-fmt
      - id: go-vet
      - id: go-imports
      - id: go-cyclo
        args: [-over=15]
      - id: go-mod-tidy
      - id: go-unit-tests
      - id: golangci-lint

  - repo: local
    hooks:
      - id: go-generate
        name: Run go generate
        entry: go generate ./...
        language: system
        pass_filenames: false
```

## Development Scripts

### 1. Makefile

```makefile
.PHONY: all build test clean

# Variables
BINARY_NAME=blackhole
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

# Commands
all: test build

build:
	go build ${LDFLAGS} -o ${BINARY_NAME} ./cmd/blackhole

test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

bench:
	go test -bench=. -benchmem ./...

lint:
	golangci-lint run

fmt:
	gofmt -s -w .
	goimports -w .

generate:
	go generate ./...

deps:
	go mod download
	go mod tidy

clean:
	go clean
	rm -f ${BINARY_NAME}
	rm -f coverage.out coverage.html

# Development helpers
dev-setup:
	go install github.com/golang/mock/mockgen@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	pre-commit install

run-local:
	go run ${LDFLAGS} ./cmd/blackhole node start --dev

docker-build:
	docker build -t ${BINARY_NAME}:${VERSION} .

proto:
	protoc --go_out=. --go-grpc_out=. proto/*.proto
```

### 2. Development Environment Setup

```bash
#!/bin/bash
# scripts/dev-setup.sh

echo "Setting up Blackhole Network development environment..."

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.22"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: Go $REQUIRED_VERSION or higher is required"
    exit 1
fi

# Install tools
echo "Installing development tools..."
make dev-setup

# Setup git hooks
echo "Setting up git hooks..."
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
echo "Running pre-push checks..."
make lint
make test
EOF
chmod +x .git/hooks/pre-push

echo "Development environment ready!"
```

## Continuous Integration

### 1. GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.22'
      - name: Run linters
        uses: golangci/golangci-lint-action@v3

  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        go: ['1.22', '1.23']
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: ${{ matrix.go }}
      - name: Run tests
        run: make test
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run gosec
        uses: securego/gosec@master
        with:
          args: ./...
```

## Debugging Tools

### 1. Delve Debugger

```bash
# Install
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug configurations
# .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/cmd/blackhole",
            "args": ["node", "start", "--dev"],
            "env": {
                "LOG_LEVEL": "debug"
            }
        },
        {
            "name": "Debug Test",
            "type": "go",
            "request": "launch",
            "mode": "test",
            "program": "${workspaceFolder}/pkg/storage",
            "args": ["-test.v", "-test.run", "TestStoreFile"]
        }
    ]
}
```

### 2. Performance Profiling

```go
// Enable profiling endpoints
import _ "net/http/pprof"

func EnableProfiling() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}

// Profile CPU
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

// Profile memory
go tool pprof http://localhost:6060/debug/pprof/heap

// Profile goroutines
go tool pprof http://localhost:6060/debug/pprof/goroutine

// Trace execution
wget http://localhost:6060/debug/pprof/trace?seconds=5
go tool trace trace
```

## Custom Tools

### 1. Dependency Checker

```go
// tools/depcheck/main.go
package main

import (
    "fmt"
    "go/build"
    "log"
    "strings"
)

func main() {
    pkg, err := build.ImportDir(".", 0)
    if err != nil {
        log.Fatal(err)
    }

    // Check for forbidden imports
    forbidden := []string{
        "github.com/blackhole/internal",
        "unsafe",
    }

    for _, imp := range pkg.Imports {
        for _, f := range forbidden {
            if strings.Contains(imp, f) {
                fmt.Printf("Forbidden import: %s\n", imp)
                os.Exit(1)
            }
        }
    }
}
```

### 2. Migration Generator

```bash
#!/bin/bash
# scripts/new-migration.sh

NAME=$1
TIMESTAMP=$(date +%Y%m%d%H%M%S)
FILENAME="migrations/${TIMESTAMP}_${NAME}.sql"

cat > $FILENAME << EOF
-- +migrate Up
-- SQL for migration up

-- +migrate Down
-- SQL for migration down
EOF

echo "Created migration: $FILENAME"
```

These tools and automation ensure consistent code quality and reduce manual work.
