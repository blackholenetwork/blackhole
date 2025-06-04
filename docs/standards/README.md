# Blackhole Network Standards

This directory contains all coding standards, development practices, and conventions for the Blackhole Network project. These standards are **mandatory** and enforced through tooling and code reviews.

## Standards Documents

### 1. [Coding Standards](./CODING_STANDARDS.md)
- Method signature patterns
- Error handling conventions
- Resource management
- Concurrency patterns
- Interface design
- Testing standards
- Performance guidelines
- Security practices

### 2. [Development Practices](./DEVELOPMENT_PRACTICES.md)
- Git workflow and branching
- Code review process
- Testing practices
- Dependency management
- Debugging techniques
- Release process
- Monitoring standards
- Documentation requirements

## Quick Reference

### Most Important Rules

1. **Always use context.Context as first parameter**
   ```go
   func DoSomething(ctx context.Context, ...) error
   ```

2. **Always wrap errors with context**
   ```go
   return fmt.Errorf("failed to process %s: %w", id, err)
   ```

3. **Always cleanup resources**
   ```go
   defer file.Close()
   defer cancel()
   ```

4. **Always validate inputs**
   ```go
   if err := validate(input); err != nil {
       return fmt.Errorf("invalid input: %w", err)
   }
   ```

5. **Always write tests**
   - Minimum 80% coverage
   - Table-driven tests for multiple cases
   - Integration tests for public APIs

## Enforcement

These standards are enforced through:

1. **Pre-commit hooks** - Run automatically before commit
2. **CI/CD pipeline** - Blocks PRs that violate standards
3. **Linter configuration** - `.golangci.yml` enforces rules
4. **Code reviews** - Reviewers check compliance

## Adding New Standards

When proposing new standards:

1. Create a PR with the proposed standard
2. Include rationale and examples
3. Get consensus from team
4. Update tooling to enforce if possible
5. Document in the appropriate file

## Non-Negotiable Principles

1. **Consistency** > Personal preference
2. **Explicit** > Implicit
3. **Simple** > Clever
4. **Testable** > Convenient
5. **Secure** > Fast

Remember: These standards exist to prevent spaghetti code and ensure long-term maintainability. When in doubt, refer to these documents.