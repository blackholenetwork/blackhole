# Development Documentation

This folder contains guides and principles for development practices.

## Documents

### 🎯 [Code Design Principles](./CODE_DESIGN_PRINCIPLES.md)
Fundamental principles for writing maintainable code:
- Composition over inheritance
- Interface segregation
- Dependency inversion
- Single source of truth
- Fail fast
- And 7 more principles with examples

### 🛠️ [Tooling](./TOOLING.md)
Development tools and automation:
- Code generation tools
- Linting and formatting setup
- Development scripts
- Debugging tools
- Custom tooling

## Quick Reference

### Design Principles Cheat Sheet

1. **Composition > Inheritance** - Build with small pieces
2. **Small Interfaces** - Many specific rather than few general
3. **Depend on Abstractions** - Not concrete implementations
4. **Single Source of Truth** - Don't duplicate state
5. **Explicit > Implicit** - Clear is better than clever
6. **Fail Fast** - Catch errors early
7. **Command-Query Separation** - Methods either do or return
8. **Idempotency** - Same input = same result
9. **Open/Closed** - Open for extension, closed for modification
10. **Least Astonishment** - Predictable behavior
11. **Builder Pattern** - For complex objects
12. **Functional Options** - For flexible APIs

### Development Workflow

1. **Setup Environment**
   ```bash
   make dev-setup
   ```

2. **Generate Code**
   ```bash
   go generate ./...
   ```

3. **Run Tests**
   ```bash
   make test
   ```

4. **Check Code Quality**
   ```bash
   make lint
   ```

5. **Build**
   ```bash
   make build
   ```

## Best Practices

### Before Coding
- Read relevant design docs
- Check existing patterns
- Review interfaces
- Plan your approach

### While Coding
- Follow design principles
- Use existing utilities
- Write tests first (TDD)
- Document complex logic

### After Coding
- Run all checks
- Update documentation
- Create examples
- Consider reusability
