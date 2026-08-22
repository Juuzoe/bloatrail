# Homebrew formula for Bloatrail.
#
#   brew install Juuzoe/tap/bloatrail
#
# Homebrew removed installation from a formula URL, so this file has to live in
# a tap repository named homebrew-tap before anyone can install from it.
class Bloatrail < Formula
  desc "Developer-aware disk analyser that explains what is safe to delete"
  homepage "https://github.com/Juuzoe/bloatrail"
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.3.0/bloatrail-v0.3.0-aarch64-apple-darwin.tar.gz"
      sha256 "7c1f8414e6be91e67b936b6f5a09da5d11b3e4d2e087b24a3bd6709680bc2cda"
    end
    on_intel do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.3.0/bloatrail-v0.3.0-x86_64-apple-darwin.tar.gz"
      sha256 "00e5dab59de8a20a0d176cee4c74fcd3c789078fe4c1fb96bac4201f3fcb9f00"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.3.0/bloatrail-v0.3.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "91f720cadf3571d6051136c17cd4ffe779d772561a8980a90a1d84d39f0ef0a4"
    end
    on_intel do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.3.0/bloatrail-v0.3.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "a160bb153fb1b37f8fa28178d990563f6772bd97a175e9ab49c2219da04faada"
    end
  end

  def install
    bin.install "bloatrail"
    # The desktop app ships in the macOS archives only.
    bin.install "bloatrail-gui" if File.exist?("bloatrail-gui")
    generate_completions_from_executable(bin/"bloatrail", "completions", shells: [:bash, :zsh, :fish])
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bloatrail --version")
    system bin/"bloatrail", "scan", testpath, "--no-progress", "--json"
  end
end
