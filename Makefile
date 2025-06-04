.PHONY: all build test clean lint fmt generate deps dev-setup run run-log build-run-log proto help

# Variables
BINARY_NAME=blackhole
BUILD_DIR=build
BINARY_PATH=${BUILD_DIR}/${BINARY_NAME}
VERSION?=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.Version=${VERSION}"
GO_FILES=$(shell find . -name '*.go' -type f -not -path "./vendor/*")

# Default target
all: test build

# Build the application
build:
	@echo "Building ${BINARY_NAME} to ${BUILD_DIR}/..."
	@mkdir -p ${BUILD_DIR}
	@go build ${LDFLAGS} -o ${BINARY_PATH} ./cmd/blackhole

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

# Run linters
lint:
	@echo "Running linters..."
	@golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	@gofmt -s -w .
	@goimports -w .

# Generate code
generate:
	@echo "Generating code..."
	@go generate ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@go clean
	@rm -rf ${BUILD_DIR}
	@rm -f coverage.out coverage.html
	@rm -rf logs/

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	@go install github.com/golang/mock/mockgen@latest
	@go install github.com/swaggo/swag/cmd/swag@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@pre-commit install || echo "pre-commit not installed"

# Run locally in development mode
run:
	@echo "Running in development mode..."
	@go run ${LDFLAGS} ./cmd/blackhole node start --dev

# Run with logging
run-log:
	@echo "Running with logging to logs/blackhole.log..."
	@mkdir -p logs
	@${BINARY_PATH} node start 2>&1 | tee logs/blackhole.log

# Build and run with logging
build-run-log:
	@echo "Building and running with logging to logs/blackhole.log..."
	@mkdir -p logs ${BUILD_DIR}
	@echo "=== BUILD PHASE ===" > logs/blackhole.log
	@echo "Building ${BINARY_NAME} to ${BUILD_DIR}/..." | tee -a logs/blackhole.log
	@set -o pipefail; \
	if go build ${LDFLAGS} -o ${BINARY_PATH} ./cmd/blackhole 2>&1 | tee -a logs/blackhole.log; then \
		echo "Build successful!" | tee -a logs/blackhole.log; \
		echo "" | tee -a logs/blackhole.log; \
		echo "=== RUN PHASE ===" | tee -a logs/blackhole.log; \
		${BINARY_PATH} node start 2>&1 | tee -a logs/blackhole.log; \
	else \
		echo "Build failed! Check logs/blackhole.log for details" | tee -a logs/blackhole.log; \
		exit 1; \
	fi

# Build and run with timestamped logging
build-run-log-ts:
	@echo "Cleaning, building and running with timestamped logging to logs/blackhole.log..."
	@mkdir -p logs
	@echo "$$(date '+%Y-%m-%d %H:%M:%S') === CLEAN PHASE ===" > logs/blackhole.log
	@echo "Cleaning build artifacts..." | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log
	@go clean 2>&1 | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log
	@rm -rf ${BUILD_DIR} 2>&1 | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log
	@echo "Clean complete!" | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log
	@echo "" | tee -a logs/blackhole.log
	@mkdir -p ${BUILD_DIR}
	@echo "$$(date '+%Y-%m-%d %H:%M:%S') === BUILD PHASE ===" | tee -a logs/blackhole.log
	@echo "Building ${BINARY_NAME} to ${BUILD_DIR}/..." | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log
	@set -o pipefail; \
	if go build ${LDFLAGS} -o ${BINARY_PATH} ./cmd/blackhole 2>&1 | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log; [ $${PIPESTATUS[0]} -eq 0 ]; then \
		echo "Build successful!" | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log; \
		echo "" | tee -a logs/blackhole.log; \
		echo "$$(date '+%Y-%m-%d %H:%M:%S') === RUN PHASE ===" | tee -a logs/blackhole.log; \
		${BINARY_PATH} node start 2>&1 | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log; \
	else \
		echo "Build failed! Check logs/blackhole.log for details" | while IFS= read -r line; do echo "$$(date '+%Y-%m-%d %H:%M:%S') $$line"; done | tee -a logs/blackhole.log; \
		exit 1; \
	fi

# Build for all platforms
build-all:
	@echo "Building for all platforms..."
	@mkdir -p ${BUILD_DIR}/dist
	@GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/dist/${BINARY_NAME}-darwin-amd64 ./cmd/blackhole
	@GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD_DIR}/dist/${BINARY_NAME}-darwin-arm64 ./cmd/blackhole
	@GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/dist/${BINARY_NAME}-linux-amd64 ./cmd/blackhole
	@GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD_DIR}/dist/${BINARY_NAME}-linux-arm64 ./cmd/blackhole
	@GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/dist/${BINARY_NAME}-windows-amd64.exe ./cmd/blackhole

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@protoc --go_out=. --go-grpc_out=. proto/*.proto || echo "No proto files to generate"

# Help
help:
	@echo "Blackhole Network - Makefile Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all         Run tests and build (default)"
	@echo "  build       Build the binary"
	@echo "  test        Run tests with coverage"
	@echo "  bench       Run benchmarks"
	@echo "  lint        Run linters"
	@echo "  fmt         Format code"
	@echo "  generate    Run go generate"
	@echo "  deps        Download and tidy dependencies"
	@echo "  clean       Clean build artifacts"
	@echo "  dev-setup   Install development tools"
	@echo "  run         Run in development mode"
	@echo "  run-log     Run with logging to logs/blackhole.log"
	@echo "  build-run-log Build and run with logging"
	@echo "  build-run-log-ts Build and run with timestamped logging"
	@echo "  build-all   Build for all platforms"
	@echo "  proto       Generate protobuf files"
	@echo "  help        Show this help message"