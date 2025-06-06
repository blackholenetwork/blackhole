# How Pre-commit Hooks Work

## Overview

Pre-commit hooks are scripts that run automatically before each commit to check your code. They catch issues early, ensuring code quality before changes enter the repository.

```
Developer → git commit → Pre-commit Hooks → Success? → Commit Created
                              ↓                ↓
                         (Auto-fix)         (Blocked)
```

## How It Works

### 1. Installation

```bash
# Install pre-commit tool
pip install pre-commit
# or
brew install pre-commit

# Install hooks in your repo
pre-commit install
```

This creates `.git/hooks/pre-commit` that intercepts git commits.

### 2. When You Commit

```bash
git add file.go
git commit -m "Add new feature"
```

Pre-commit automatically:
1. Runs all configured hooks
2. Shows progress for each check
3. Auto-fixes issues when possible
4. Blocks commit if checks fail

### 3. Example Output

```
❯ git commit -m "Add new feature"
trailing-whitespace..................................Passed
end-of-file-fixer....................................Fixed
check-yaml...........................................Passed
go-fmt...............................................Failed
- hook id: go-fmt
- files were modified by this hook

golangci-lint........................................Failed
- hook id: golangci-lint
- exit code: 1

pkg/core/storage.go:15:1: Error return value is not checked (errcheck)
        file.Close()
        ^
```

## Our Configuration

Looking at `.pre-commit-config.yaml`:

### Basic File Checks
```yaml
- repo: https://github.com/pre-commit/pre-commit-hooks
  hooks:
    - id: trailing-whitespace     # Removes trailing spaces
    - id: end-of-file-fixer       # Ensures files end with newline
    - id: check-yaml              # Validates YAML syntax
    - id: check-json              # Validates JSON syntax
    - id: detect-private-key      # Prevents committing secrets
    - id: check-merge-conflict    # Prevents committing merge markers
```

### Go-Specific Checks
```yaml
- repo: https://github.com/dnephin/pre-commit-golang
  hooks:
    - id: go-fmt          # Formats Go code
    - id: go-imports      # Organizes imports
    - id: go-vet          # Reports suspicious constructs
    - id: golangci-lint   # Runs 40+ linters
    - id: go-unit-tests   # Runs tests
    - id: go-build        # Ensures code compiles
```

### Security Checks
```yaml
- repo: https://github.com/gitguardian/ggshield
  hooks:
    - id: ggshield        # Scans for secrets/credentials
```

## Common Scenarios

### Scenario 1: Auto-fix Issues

```bash
❯ git commit -m "Update docs"
trailing-whitespace..................................Fixed
end-of-file-fixer....................................Fixed
```

Pre-commit automatically fixed trailing whitespace and added newlines. Just run `git add` and commit again:

```bash
git add -u
git commit -m "Update docs"
```

### Scenario 2: Manual Fix Required

```bash
❯ git commit -m "Add feature"
go-fmt...............................................Failed
- hook id: go-fmt
- files were modified by this hook
```

The hook formatted your code. Review and add changes:

```bash
git diff              # Review changes
git add -u           # Add formatted files
git commit -m "Add feature"
```

### Scenario 3: Code Issues

```bash
❯ git commit -m "New function"
golangci-lint........................................Failed
- exit code: 1

pkg/core/handler.go:25:1: ineffectual assignment to `err` (ineffassign)
```

Fix the code issue, then commit:

```bash
# Fix the error handling in handler.go
vim pkg/core/handler.go
git add pkg/core/handler.go
git commit -m "New function with proper error handling"
```

## Bypassing Hooks (Emergency Only!)

```bash
# Skip all hooks - USE SPARINGLY!
git commit -m "Emergency fix" --no-verify

# Skip specific hooks
SKIP=golangci-lint,go-unit-tests git commit -m "WIP commit"
```

## Running Hooks Manually

```bash
# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run go-fmt --all-files

# Run on staged files
pre-commit run

# Update hooks to latest versions
pre-commit autoupdate
```

## Benefits

1. **Consistent Code Style**: Formatting is automatic
2. **Early Bug Detection**: Linters catch issues before review
3. **Security**: Prevents committing secrets
4. **Time Saving**: No need to manually run checks
5. **Clean History**: No "fix formatting" commits

## Customization

### Skip Hooks for Specific Files

In `.pre-commit-config.yaml`:
```yaml
- id: golangci-lint
  exclude: ^test/fixtures/
```

### Add Custom Hooks

```yaml
- repo: local
  hooks:
    - id: no-todos
      name: Check for TODOs
      entry: bash -c 'git diff --cached | grep -E "^\+" | grep -i todo && exit 1 || exit 0'
      language: system
```

### Project-Specific Rules

Configure in `.golangci.yml`:
```yaml
linters-settings:
  errcheck:
    check-type-assertions: true
  govet:
    check-shadowing: true
```

## Troubleshooting

### Problem: Hooks Not Running
```bash
# Reinstall hooks
pre-commit install
```

### Problem: Hooks Too Slow
```bash
# Run only on changed files (default)
pre-commit run

# Skip expensive hooks during development
SKIP=go-unit-tests,go-build git commit -m "WIP"
```

### Problem: Different Results in CI
```bash
# Ensure same tool versions
pre-commit run --all-files
```

## Team Workflow

1. **First Time Setup**:
   ```bash
   git clone <repo>
   cd <repo>
   pre-commit install
   ```

2. **Daily Development**:
   - Write code normally
   - Commit as usual
   - Pre-commit handles formatting
   - Fix any reported issues

3. **CI Integration**:
   ```yaml
   # .github/workflows/pre-commit.yml
   - name: Run pre-commit
     uses: pre-commit/action@v3.0.0
   ```

## Summary

Pre-commit hooks act as your personal code quality assistant:
- ✅ Catches issues before they're committed
- ✅ Automatically fixes formatting
- ✅ Ensures consistent code style
- ✅ Prevents common mistakes
- ✅ Saves time in code review

The key is to embrace them as a helpful tool, not a hindrance. They make your code better with minimal effort!
