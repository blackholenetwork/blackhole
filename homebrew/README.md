# Blackhole Homebrew Tap

This directory contains the Homebrew formula for installing Blackhole on macOS and Linux.

## Installation

### From Official Tap (Recommended)

Once the tap is published, users will be able to install Blackhole using:

```bash
brew tap blackholenetwork/blackhole
brew install blackhole
```

### Local Development Installation

For local testing of the formula:

```bash
# Install directly from the local formula
brew install --build-from-source ./homebrew/Formula/blackhole.rb

# Or create a local tap
brew tap-new $USER/local-tap
cp ./homebrew/Formula/blackhole.rb $(brew --repository)/Library/Taps/$USER/homebrew-local-tap/Formula/
brew install $USER/local-tap/blackhole
```

## Managing the Service

Blackhole can be managed as a Homebrew service:

```bash
# Start the service
brew services start blackhole

# Stop the service
brew services stop blackhole

# Restart the service
brew services restart blackhole

# Check service status
brew services list
```

## Formula Details

The formula:
- Downloads platform-specific binaries from GitHub releases
- Installs the `blackhole` binary to `$(brew --prefix)/bin`
- Generates and installs shell completions for bash, zsh, and fish
- Configures a Homebrew service for background operation
- Logs output to `$(brew --prefix)/var/log/blackhole.log`

## Updating the Formula

When releasing a new version:

1. Update the `version` in the formula
2. Build release binaries for all platforms:
   - darwin-arm64 (Apple Silicon)
   - darwin-amd64 (Intel Mac)
   - linux-arm64 (ARM Linux)
   - linux-amd64 (x86_64 Linux)
3. Create GitHub release with these binaries
4. Update the SHA256 checksums in the formula:
   ```bash
   shasum -a 256 blackhole-darwin-arm64.tar.gz
   shasum -a 256 blackhole-darwin-amd64.tar.gz
   shasum -a 256 blackhole-linux-arm64.tar.gz
   shasum -a 256 blackhole-linux-amd64.tar.gz
   ```
5. Test the formula locally before pushing

## Publishing to a Tap

To publish this as an official tap:

1. Create a new repository named `homebrew-blackhole`
2. Copy the Formula directory to the new repository
3. Push to GitHub under the blackholenetwork organization
4. Users can then `brew tap blackholenetwork/blackhole`

## Testing the Formula

Run the formula tests:

```bash
brew test blackhole
brew audit --strict blackhole
```

## Troubleshooting

### Logs
Check service logs at:
- Output: `/opt/homebrew/var/log/blackhole.log` (Apple Silicon)
- Output: `/usr/local/var/log/blackhole.log` (Intel Mac)
- Errors: `*.error.log` in the same directory

### Common Issues

1. **Port conflicts**: Default port 8080 may be in use
   - Solution: Edit config file to use different port

2. **Service won't start**: Check error logs
   - Solution: Run `blackhole` directly to see startup errors

3. **Formula installation fails**: Ensure Xcode Command Line Tools installed
   - Solution: `xcode-select --install`
