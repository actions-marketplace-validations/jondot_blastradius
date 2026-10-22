# Homebrew formula TEMPLATE for br. Do not publish this file as it is.
# `packaging/homebrew/fill.sh VERSION` replaces the three @...@ placeholders below with the sha256 values
# from the release's .sha256 files and writes the result next to this file as br.filled.rb.
# The filled file goes into a tap repository (for example jondot/homebrew-tap, as Formula/br.rb).
class Br < Formula
  desc "Find where a bad package landed in your org, what it could reach, and who to tell"
  homepage "https://github.com/jondot/blastradius"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/jondot/blastradius/releases/download/v#{version}/br-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/jondot/blastradius/releases/download/v#{version}/br-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/jondot/blastradius/releases/download/v#{version}/br-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_UNKNOWN_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/jondot/blastradius/releases/download/v#{version}/br-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_UNKNOWN_LINUX_MUSL@"
    end
  end

  def install
    bin.install "br"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/br --version")
    # the built-in sample org needs no network and no token
    assert_match "demo org (acme)", shell_output("#{bin}/br demo 2>&1")
  end
end
