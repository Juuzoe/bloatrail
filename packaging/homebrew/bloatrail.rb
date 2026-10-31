# Homebrew formula for Bloatrail.
#
#   brew install Juuzoe/tap/bloatrail
#
# Homebrew removed installation from a formula URL, so this file has to live in
# a tap repository named homebrew-tap before anyone can install from it.
class Bloatrail < Formula
  desc "Developer-aware disk analyser that explains what is safe to delete"
  homepage "https://github.com/Juuzoe/bloatrail"
  version "0.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.4.0/bloatrail-v0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "90602d79aba533de7f64081878ad24e157cc2a75636f2993551a0e6fa59f3d97"
    end
    on_intel do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.4.0/bloatrail-v0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "ed67a5c53b0723d83ea28cf7f2462cc49b160b43db91c6e9a63cbb05dfa2eba8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.4.0/bloatrail-v0.4.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "f4ad43b46a239ccd68aaa19e6d3b8fc4f5a7a7b0e0a9e73c4dda056817cf20e5"
    end
    on_intel do
      url "https://github.com/Juuzoe/bloatrail/releases/download/v0.4.0/bloatrail-v0.4.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "aeb9e8560d28bb88e71288eeb2baef71085eb094e2b4a15c85ebd38d7bb550d7"
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
