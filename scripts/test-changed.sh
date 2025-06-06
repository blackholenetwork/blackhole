#!/bin/bash
# Test only changed Go packages

set -e

# Get list of changed Go files
CHANGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)

if [ -z "$CHANGED_FILES" ]; then
  echo "No Go files changed, skipping tests"
  exit 0
fi

# Extract unique package paths from changed files
PACKAGES=$(echo "$CHANGED_FILES" | xargs -I {} dirname {} | grep -E '^(cmd|pkg|internal)' | sort -u | sed 's|^|./|' | tr '\n' ' ')

if [ -z "$PACKAGES" ]; then
  echo "No testable packages changed"
  exit 0
fi

echo "Testing changed packages: $PACKAGES"

# Run tests only for changed packages
# shellcheck disable=SC2086
go test -v -short $PACKAGES

# Run linter only on changed packages
# shellcheck disable=SC2086
golangci-lint run $PACKAGES
