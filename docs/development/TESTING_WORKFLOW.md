# Testing Workflow Guide

## Quick Reference

### During Development

```bash
# Quick test while developing (no coverage, short tests only)
make test-quick

# Test only the package you're working on
go test ./pkg/core/monitor/...

# Test with specific test name
go test -run TestPluginInit ./pkg/core/monitor/...
```

### Before Committing

```bash
# Option 1: Let pre-commit run tests on changed packages only (default)
git commit -m "your message"

# Option 2: Skip tests entirely (use sparingly!)
git commit --no-verify -m "your message"

# Option 3: Run full test suite manually
make test
git commit -m "your message"
```

### CI/CD Strategy

1. **Pre-commit**: Tests only changed packages (fast)
2. **Pull Request**: Full test suite with coverage
3. **Main branch**: Full test suite + integration tests

## Test Organization

### Short Tests (run with -short flag)
- Unit tests
- Fast integration tests (<1s)
- No external dependencies

### Long Tests (skipped with -short flag)
```go
func TestLongRunning(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping long test in short mode")
    }
    // Long test code here
}
```

## Performance Tips

1. **Use test caching**: Go automatically caches test results
   ```bash
   # Clear test cache if needed
   go clean -testcache
   ```

2. **Parallel tests**: Enable for faster execution
   ```go
   func TestParallel(t *testing.T) {
       t.Parallel()
       // Test code
   }
   ```

3. **Table-driven tests**: Group related tests
   ```go
   func TestCases(t *testing.T) {
       tests := []struct{
           name string
           input int
           want int
       }{
           {"case1", 1, 2},
           {"case2", 2, 4},
       }

       for _, tt := range tests {
           t.Run(tt.name, func(t *testing.T) {
               // Test code
           })
       }
   }
   ```

## Environment Variables

- `SKIP=make-test`: Skip test hook in pre-commit
- `GO_TEST_TIMEOUT=10m`: Increase test timeout
- `GO_TEST_PARALLEL=4`: Limit parallel test execution
