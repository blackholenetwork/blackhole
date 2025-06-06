class Blackhole < Formula
  desc "Decentralized infrastructure platform that transforms idle computing resources into a global shared network"
  homepage "https://github.com/blackholenetwork/blackhole"
  version "0.1.0"
  
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/blackholenetwork/blackhole/releases/download/v#{version}/blackhole-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_ARM64"
    else
      url "https://github.com/blackholenetwork/blackhole/releases/download/v#{version}/blackhole-darwin-amd64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_DARWIN_AMD64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/blackholenetwork/blackhole/releases/download/v#{version}/blackhole-linux-arm64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    else
      url "https://github.com/blackholenetwork/blackhole/releases/download/v#{version}/blackhole-linux-amd64.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_AMD64"
    end
  end

  def install
    bin.install "blackhole"
    
    # Install shell completions
    generate_completions_from_executable(bin/"blackhole", "completion")
  end

  service do
    run [opt_bin/"blackhole", "start"]
    keep_alive true
    log_path var/"log/blackhole.log"
    error_log_path var/"log/blackhole.error.log"
  end

  test do
    # Test version output
    assert_match "blackhole version #{version}", shell_output("#{bin}/blackhole version")
    
    # Test that the binary runs without errors
    system "#{bin}/blackhole", "--help"
    
    # Test config generation
    config_file = testpath/"config.yaml"
    system "#{bin}/blackhole", "init", "--config", config_file
    assert_predicate config_file, :exist?
    
    # Test that service can start (but immediately stop it)
    port = free_port
    pid = fork do
      exec "#{bin}/blackhole", "start", "--port", port.to_s, "--config", config_file
    end
    sleep 2
    
    # Check if service is responding
    require "net/http"
    response = Net::HTTP.get_response("localhost", "/health", port)
    assert_equal "200", response.code
    
  ensure
    Process.kill("TERM", pid) if pid
    Process.wait(pid) if pid
  end

  private

  def free_port
    server = TCPServer.new(0)
    port = server.addr[1]
    server.close
    port
  end
end