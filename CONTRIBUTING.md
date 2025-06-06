# Contributing to Blackhole Network

Thank you for your interest in contributing to Blackhole Network! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Commit Messages](#commit-messages)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful and constructive in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/blackhole.git
   cd blackhole
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/blackholenetwork/blackhole.git
   ```

## Development Setup

### Prerequisites

- Go 1.22 or later
- Make
- Git
- golangci-lint
- pre-commit (optional but recommended)

### Initial Setup

1. **Install Go dependencies**:
   ```bash
   make deps
   ```

2. **Set up development tools**:
   ```bash
   make dev-setup
   ```

3. **Install pre-commit hooks** (recommended):
   ```bash
   pre-commit install
   ```

4. **Verify setup**:
   ```bash
   make test
   make lint
   ```

### Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Run tests locally**:
   ```bash
   make test
   ```

4. **Run linters**:
   ```bash
   make lint
   ```

5. **Build the project**:
   ```bash
   make build
   ```

## How to Contribute

### Reporting Bugs

- Use the GitHub Issues tracker
- Check if the issue already exists
- Include detailed steps to reproduce
- Provide system information (OS, Go version, etc.)
- Include relevant logs or error messages

### Suggesting Features

- Open a GitHub Issue with the "enhancement" label
- Clearly describe the feature and its benefits
- Consider the project scope and roadmap
- Be open to feedback and discussion

### Submitting Code

1. **Check existing issues** or create a new one
2. **Fork and clone** the repository
3. **Create a feature branch** from `main`
4. **Write your code** following our standards
5. **Add tests** for new functionality
6. **Update documentation** as needed
7. **Submit a pull request**

## Coding Standards

### Go Code Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use `gofmt` and `goimports` for formatting
- Keep functions small and focused
- Use meaningful variable and function names
- Add comments for exported functions and types

### Project Structure

```
blackhole/
├── cmd/           # Application entrypoints
├── pkg/           # Public packages
│   ├── core/      # Core functionality
│   ├── plugin/    # Plugin system
│   └── common/    # Shared utilities
├── internal/      # Private application code
├── docs/          # Documentation
├── scripts/       # Build and utility scripts
└── web/           # Web dashboard
```

### Error Handling

- Always check and handle errors
- Use wrapped errors with context:
  ```go
  return fmt.Errorf("failed to process: %w", err)
  ```
- Create custom error types when appropriate
- Log errors at the appropriate level

### Testing

- Write unit tests for all new code
- Aim for >80% code coverage
- Use table-driven tests where appropriate
- Mock external dependencies
- Test both success and failure cases

Example test structure:
```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name    string
        input   interface{}
        want    interface{}
        wantErr bool
    }{
        // test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // test implementation
        })
    }
}
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific package tests
go test ./pkg/core/...

# Run tests with race detection
go test -race ./...
```

### Writing Tests

- Place tests in `*_test.go` files
- Use descriptive test names
- Test edge cases and error conditions
- Use testify/assert for assertions
- Mock external dependencies

## Pull Request Process

1. **Update your fork**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Rebase your feature branch**:
   ```bash
   git checkout feature/your-feature
   git rebase main
   ```

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature
   ```

4. **Create Pull Request**:
   - Use a clear, descriptive title
   - Reference related issues
   - Describe what changes were made and why
   - Include screenshots for UI changes
   - Ensure all checks pass

5. **Code Review**:
   - Respond to feedback promptly
   - Make requested changes
   - Keep the PR updated with main branch

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages follow guidelines
- [ ] PR description is complete
- [ ] Related issues are linked

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes
- `perf`: Performance improvements

### Examples

```
feat(core): add P2P networking module

Implement basic P2P networking using libp2p including:
- Peer discovery via DHT
- NAT traversal
- Connection management

Closes #123
```

```
fix(storage): resolve memory leak in chunk processing

The chunk processor was not releasing buffers after processing,
causing memory usage to grow unbounded.
```

## Documentation

### Code Documentation

- Add godoc comments to all exported types and functions
- Include examples in comments where helpful
- Keep comments up-to-date with code changes

### Project Documentation

- Update README.md for significant changes
- Add design docs for new features in `docs/`
- Update API documentation
- Include migration guides for breaking changes

## Community

### Getting Help

- Check the [documentation](docs/)
- Search existing [issues](https://github.com/blackholenetwork/blackhole/issues)
- Ask in [discussions](https://github.com/blackholenetwork/blackhole/discussions)
- Join our [Discord server](#) (coming soon)

### Stay Updated

- Watch the repository for updates
- Follow our [blog](#) for announcements
- Subscribe to release notifications

## Development Tips

### Useful Make Commands

```bash
make help          # Show all available commands
make build         # Build the binary
make test          # Run tests
make lint          # Run linters
make fmt           # Format code
make run           # Run in development mode
make clean         # Clean build artifacts
```

### Debugging

1. **Enable debug logging**:
   ```bash
   BLACKHOLE_LOG_LEVEL=debug ./blackhole
   ```

2. **Use delve debugger**:
   ```bash
   dlv debug ./cmd/blackhole
   ```

3. **Profile performance**:
   ```bash
   go test -cpuprofile cpu.prof -memprofile mem.prof
   ```

## License

By contributing to Blackhole Network, you agree that your contributions will be licensed under the project's license.

---

Thank you for contributing to Blackhole Network! Your efforts help make decentralized infrastructure accessible to everyone.