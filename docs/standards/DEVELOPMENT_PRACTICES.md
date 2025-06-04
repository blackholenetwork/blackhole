# Blackhole Network - Development Practices

This document defines development practices, workflows, and conventions beyond coding standards.

## 1. Git Workflow Standards

### Branch Naming
```bash
# Feature branches
feature/add-storage-encryption
feature/implement-p2p-discovery

# Bug fixes
fix/memory-leak-in-chunking
fix/race-condition-storage

# Refactoring
refactor/simplify-network-layer
refactor/extract-common-utils

# Documentation
docs/add-api-examples
docs/update-architecture
```

### Commit Message Format
```bash
# Format: <type>(<scope>): <subject>

# Examples
feat(storage): add erasure coding support
fix(network): resolve NAT traversal timeout
docs(api): add authentication examples
refactor(compute): simplify job scheduling
test(storage): add chunk verification tests
perf(indexer): optimize search queries
chore(deps): update libp2p to v0.33.0

# Breaking changes
feat(api)!: change file upload response format

# Multi-line with details
fix(storage): prevent data corruption on power loss

The storage layer now properly flushes data to disk before
confirming writes. This prevents corruption when power is
lost during write operations.

Fixes #123
```

### Pull Request Standards
```markdown
## Description
Brief description of what this PR does.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass locally
- [ ] Integration tests pass locally
- [ ] Manual testing completed

## Checklist
- [ ] Code follows project coding standards
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
- [ ] No new linter warnings
```

## 2. Code Review Standards

### Review Checklist
- **Correctness**: Does the code do what it's supposed to?
- **Design**: Is the code well-designed and fits with the architecture?
- **Complexity**: Could this be simpler?
- **Tests**: Are there adequate tests?
- **Naming**: Are names clear and consistent?
- **Comments**: Is complex logic explained?
- **Standards**: Does it follow our coding standards?
- **Security**: Are there any security concerns?
- **Performance**: Are there any performance issues?

### Review Comments
```go
// ✅ GOOD: Specific and actionable
// "This could cause a race condition if two goroutines call this simultaneously. 
// Consider adding a mutex or using sync.Once"

// ❌ BAD: Vague or personal preference
// "I don't like this"
// "This is wrong"
```

## 3. Testing Practices

### Test Coverage Requirements
- Minimum 80% coverage for new code
- Critical paths must have 100% coverage
- Integration tests for all public APIs

### Test Organization
```
pkg/storage/
├── storage.go
├── storage_test.go      # Unit tests
├── integration_test.go  # Integration tests
├── testdata/           # Test fixtures
│   ├── valid_file.dat
│   └── corrupt_file.dat
└── benchmark_test.go   # Performance tests
```

### Test Data Management
```go
// ✅ CORRECT - Use testdata directory
func TestProcessFile(t *testing.T) {
    data, err := os.ReadFile("testdata/sample.json")
    require.NoError(t, err)
    // Use data
}

// ✅ CORRECT - Generate test data
func generateTestFile(size int64) []byte {
    data := make([]byte, size)
    rand.Read(data)
    return data
}

// ❌ WRONG - Hardcoded test data in code
func TestSomething(t *testing.T) {
    data := []byte{0x01, 0x02, 0x03, ...} // Don't do this
}
```

### Benchmark Standards
```go
func BenchmarkStorageWrite(b *testing.B) {
    storage := setupTestStorage(b)
    data := generateTestData(1 * MB)
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        _, err := storage.Write(data)
        if err != nil {
            b.Fatal(err)
        }
    }
    
    b.SetBytes(int64(len(data)))
}
```

## 4. Dependency Management

### Adding Dependencies
```bash
# Before adding a dependency, ask:
# 1. Do we really need this?
# 2. Is it actively maintained?
# 3. What's the license?
# 4. How large is it?
# 5. Can we implement it ourselves simply?

# If yes to all, then:
go get github.com/some/package@v1.2.3
go mod tidy
```

### Dependency Guidelines
- Prefer standard library when possible
- Pin to specific versions, not latest
- Review licenses for compatibility
- Avoid dependencies with many sub-dependencies
- Document why each dependency is needed

## 5. Performance Guidelines

### Profiling Standards
```go
// CPU profiling in tests
func TestPerformance(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping performance test")
    }
    
    f, _ := os.Create("cpu.prof")
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()
    
    // Run performance-critical code
}

// Memory profiling
func TestMemoryUsage(t *testing.T) {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    before := m.Alloc
    
    // Run code
    
    runtime.ReadMemStats(&m)
    after := m.Alloc
    
    if after-before > 100*MB {
        t.Errorf("Used too much memory: %d bytes", after-before)
    }
}
```

### Optimization Rules
1. **Measure First**: Never optimize without profiling
2. **Algorithm First**: Better algorithm > micro-optimizations
3. **Memory > CPU**: Optimize allocations before CPU
4. **Document**: Always document why optimization was needed

## 6. Debugging Practices

### Debug Logging
```go
// Use build tags for debug code
// +build debug

package storage

func (s *Storage) debugDump() {
    log.Debug("storage state",
        "chunks", len(s.chunks),
        "size", s.totalSize,
        "state", s.state,
    )
}
```

### Debugging Helpers
```go
// ✅ CORRECT - Conditional compilation
func debugLog(format string, args ...any) {
    if os.Getenv("BLACKHOLE_DEBUG") == "1" {
        log.Printf("[DEBUG] "+format, args...)
    }
}

// ✅ CORRECT - Debug assertions
func assert(condition bool, msg string) {
    if !condition && os.Getenv("BLACKHOLE_DEBUG") == "1" {
        panic("assertion failed: " + msg)
    }
}
```

## 7. Release Process

### Version Numbering
```
v0.1.0 - Initial release
v0.2.0 - New feature
v0.2.1 - Bug fix
v1.0.0 - First stable release

Major.Minor.Patch
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes
```

### Release Checklist
- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in code
- [ ] Release notes written
- [ ] Binaries built for all platforms
- [ ] Docker images built and pushed
- [ ] Git tag created and pushed

### Changelog Format
```markdown
# Changelog

## [0.2.0] - 2025-06-04

### Added
- Erasure coding support for storage redundancy
- P2P network discovery via DHT
- Basic web dashboard

### Changed
- Improved chunk verification performance by 50%
- Updated libp2p to v0.33.0

### Fixed
- Memory leak in chunk processing
- Race condition in peer connection handling

### Security
- Fixed potential DoS in file upload endpoint
```

## 8. Documentation Standards

### Code Documentation Priority
1. **Public APIs**: MUST be documented
2. **Complex Algorithms**: MUST explain the approach
3. **Non-obvious Decisions**: MUST explain why
4. **Workarounds**: MUST explain what and why
5. **Internal Functions**: Document if complex

### README Standards
Each package should have a README with:
- Purpose of the package
- Basic usage examples
- Key types and interfaces
- Dependencies
- Performance characteristics

### Architecture Decision Records (ADR)
```markdown
# ADR-001: Use libp2p for networking

## Status
Accepted

## Context
We need a P2P networking library that handles NAT traversal,
peer discovery, and secure communication.

## Decision
Use libp2p because:
- Proven in production (IPFS, Filecoin)
- Handles NAT traversal
- Built-in DHT
- Active development

## Consequences
- Additional dependency
- Learning curve for team
- Locked into libp2p abstractions
```

## 9. Monitoring and Observability

### Metrics Standards
```go
// Define metrics at package level
var (
    filesUploaded = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackhole_files_uploaded_total",
            Help: "Total number of files uploaded",
        },
        []string{"status", "tier"},
    )
    
    uploadDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackhole_upload_duration_seconds",
            Help: "Upload duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"tier"},
    )
)

// Use in code
start := time.Now()
// ... upload logic ...
uploadDuration.WithLabelValues(tier).Observe(time.Since(start).Seconds())
filesUploaded.WithLabelValues("success", tier).Inc()
```

### Tracing Standards
```go
// Use OpenTelemetry for distributed tracing
func (s *Storage) StoreFile(ctx context.Context, data []byte) error {
    ctx, span := tracer.Start(ctx, "storage.StoreFile",
        trace.WithAttributes(
            attribute.Int64("size", int64(len(data))),
        ),
    )
    defer span.End()
    
    // Implementation
    
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, err.Error())
        return err
    }
    
    return nil
}
```

## 10. Security Practices

### Secure Coding
- Never trust user input
- Always validate and sanitize
- Use prepared statements for queries
- Never log sensitive data
- Use constant-time comparisons for secrets
- Implement rate limiting on all endpoints

### Security Review Checklist
- [ ] Input validation implemented
- [ ] Authentication required where needed
- [ ] Authorization checks in place
- [ ] Rate limiting configured
- [ ] Sensitive data not logged
- [ ] CORS properly configured
- [ ] Security headers set

## 11. Development Environment

### Required Tools
```bash
# Go version
go version  # Must be 1.22+

# Linters
golangci-lint version  # Latest

# Tools
go install github.com/goreleaser/goreleaser@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/mgechev/revive@latest
```

### IDE Configuration
```json
// VS Code settings.json
{
    "go.lintTool": "golangci-lint",
    "go.lintOnSave": "package",
    "go.formatTool": "goimports",
    "go.testOnSave": true,
    "go.coverOnTestPackage": true,
    "go.useLanguageServer": true
}
```

## 12. Continuous Improvement

### Code Metrics to Track
- Test coverage trend
- Cyclomatic complexity
- Technical debt ratio
- Build time
- Test execution time
- Linter warning count

### Regular Reviews
- Weekly: Review new dependencies
- Monthly: Review error rates and performance
- Quarterly: Architecture review
- Yearly: Full security audit

These practices ensure consistent, high-quality development across the team and project lifecycle.