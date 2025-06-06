# How the Infrastructure Works

This guide explains how all the Layer 0 infrastructure components work together to provide a complete development, build, and deployment pipeline for Blackhole Network.

## Overview

```
Developer → Code → Pre-commit → Push → CI/CD → Release → Distribution
                      ↓                           ↓
                 Quality Checks              Multi-platform
                                              Packages
```

## 1. Development Workflow

### Local Development Setup

When a developer clones the repository:

```bash
git clone https://github.com/blackholenetwork/blackhole
cd blackhole
make dev-setup  # Installs all development tools
```

This installs:
- Go dependencies
- golangci-lint for code quality
- pre-commit hooks
- Development tools

### Writing Code

1. **IDE Integration**: The `.golangci.yml` provides consistent linting across all IDEs
2. **Code Standards**: `CONTRIBUTING.md` defines coding guidelines
3. **Auto-formatting**: Go fmt/imports run automatically

### Pre-commit Hooks

When you commit code:

```bash
git add .
git commit -m "feat: add new feature"
```

The pre-commit hooks automatically:
1. Format Go code (`go fmt`, `goimports`)
2. Run linters (`golangci-lint` with 40+ checks)
3. Run tests (`go test`)
4. Check for security issues (`gosec`)
5. Validate commit message format
6. Prevent commits to main branch

If any check fails, the commit is blocked until fixed.

## 2. Continuous Integration

### GitHub Actions Workflow

When code is pushed:

```yaml
on: [push, pull_request]
jobs:
  lint:
    - golangci-lint run
  test:
    - go test ./...
  build:
    - go build
```

### Quality Gates

- All tests must pass
- No linting errors
- Code coverage thresholds
- Security scans

## 3. Release Process

### Creating a Release

When you create a git tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GoReleaser automatically:

1. **Builds binaries** for all platforms:
   - macOS (Intel & Apple Silicon)
   - Linux (x64, ARM64, ARMv7)
   - Windows (x64)

2. **Creates packages**:
   - `.tar.gz` archives for Unix
   - `.zip` for Windows
   - `.deb` for Debian/Ubuntu
   - `.rpm` for RedHat/Fedora
   - `.apk` for Alpine
   - Docker images

3. **Generates release artifacts**:
   - Checksums file
   - Release notes from commits
   - Software Bill of Materials (SBOM)
   - Signed artifacts

4. **Publishes to repositories**:
   - GitHub Releases
   - Homebrew tap
   - Docker Hub
   - Package registries

## 4. Installation Methods

### macOS (Homebrew)

```bash
brew install blackholenetwork/tap/blackhole
```

How it works:
1. Homebrew reads the formula from the tap repository
2. Downloads the correct binary for your architecture
3. Installs to `/usr/local/bin` (Intel) or `/opt/homebrew/bin` (Apple Silicon)
4. Sets up shell completions
5. Creates launchd service

### Windows (MSI Installer)

```powershell
# Download and run installer
blackhole-1.0.0-x64.msi
```

The MSI installer:
1. Checks system requirements
2. Installs to `C:\Program Files\Blackhole`
3. Creates Windows service
4. Adds to PATH
5. Creates Start Menu shortcuts
6. Configures Windows Firewall rules
7. Sets up auto-start on boot

### Linux (Package Managers)

```bash
# Debian/Ubuntu
sudo dpkg -i blackhole_1.0.0_amd64.deb

# RedHat/Fedora
sudo rpm -i blackhole-1.0.0.x86_64.rpm
```

Linux packages:
1. Create system user `blackhole`
2. Install binary to `/usr/bin/blackhole`
3. Create systemd service
4. Set up directories:
   - `/etc/blackhole/` - Configuration
   - `/var/lib/blackhole/` - Data
   - `/var/log/blackhole/` - Logs
5. Enable service to start on boot

### Docker

```bash
docker run -d blackholenetwork/blackhole:latest
```

Docker process:
1. Multi-stage build creates minimal image
2. Runs as non-root user
3. Exposes ports 8080, 4001, 4002
4. Mounts volumes for persistence
5. Health checks ensure availability

## 5. Configuration Management

### Default Configuration Flow

```
Package Default → System Config → User Config → Environment Vars → CLI Flags
    (lowest)                                                        (highest)
```

Each installation method provides:
- Default config in package
- System-wide config location
- User override capability
- Environment variable support

## 6. Service Management

### macOS
```bash
brew services start blackhole
brew services stop blackhole
brew services restart blackhole
```

### Windows
```powershell
Start-Service Blackhole
Stop-Service Blackhole
Restart-Service Blackhole
```

### Linux
```bash
sudo systemctl start blackhole
sudo systemctl stop blackhole
sudo systemctl restart blackhole
sudo systemctl status blackhole
```

### Docker
```bash
docker-compose up -d
docker-compose down
docker-compose restart
docker-compose logs -f
```

## 7. Monitoring & Observability

### Metrics Collection

The application exposes Prometheus metrics on port 9090:
- System metrics (CPU, memory, disk)
- P2P network stats
- Storage usage
- API request rates

### Docker Monitoring Stack

```bash
docker-compose --profile monitoring up
```

This starts:
1. **Prometheus**: Scrapes metrics every 15s
2. **Grafana**: Visualizes metrics with pre-built dashboards
3. **AlertManager**: Sends alerts based on rules

## 8. Development Tools Integration

### VSCode

`.vscode/settings.json` configures:
- Go tools
- Linting on save
- Test runner
- Debugging

### GoLand/IntelliJ

Reads `.golangci.yml` for:
- Code inspections
- Format on save
- Import optimization

## 9. Security Pipeline

### Build-time Security

1. **Dependency scanning**: Checks for vulnerable dependencies
2. **Static analysis**: `gosec` finds security issues
3. **Secret scanning**: Prevents API keys in code
4. **License compliance**: Ensures compatible licenses

### Runtime Security

1. **Minimal containers**: Distroless/Alpine base
2. **Non-root execution**: Dedicated user accounts
3. **Capability dropping**: Limited system permissions
4. **Network policies**: Restricted communication

## 10. Update Mechanism

### Auto-update Flow

```
Check Version → Download Update → Verify Signature → Apply Update → Restart
```

Each package manager handles updates:
- **Homebrew**: `brew upgrade blackhole`
- **APT/YUM**: System update commands
- **Windows**: MSI supports in-place upgrades
- **Docker**: Pull new image tag

## Complete Example: Feature Development to Production

1. **Developer creates feature branch**
   ```bash
   git checkout -b feature/new-storage
   ```

2. **Write code with real-time feedback**
   - Linter shows issues in IDE
   - Tests run locally
   - Pre-commit validates on commit

3. **Push triggers CI**
   ```bash
   git push origin feature/new-storage
   ```
   - GitHub Actions run full test suite
   - Build artifacts for testing

4. **Merge to main**
   - PR review process
   - All checks must pass
   - Squash and merge

5. **Release preparation**
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

6. **Automated release**
   - GoReleaser builds all platforms
   - Creates GitHub release
   - Updates Homebrew formula
   - Pushes Docker images
   - Generates changelogs

7. **User updates**
   ```bash
   # macOS
   brew upgrade blackhole
   
   # Linux
   sudo apt update && sudo apt upgrade blackhole
   
   # Docker
   docker pull blackholenetwork/blackhole:latest
   ```

8. **Monitoring confirms health**
   - Grafana shows version rollout
   - No error rate increase
   - Performance metrics stable

This infrastructure ensures consistent, reliable software delivery from development to production across all platforms.