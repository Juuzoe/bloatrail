#!/bin/sh
# Install Bloatrail on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.sh | sh
#
# Downloads the release archive for this machine, checks it against the
# published checksum and copies the binaries into place.
#
#   BLOATRAIL_VERSION       install a specific tag instead of the latest
#   BLOATRAIL_INSTALL_DIR   install somewhere other than the default
#   BLOATRAIL_NO_VERIFY=1   proceed even if the checksum cannot be checked

set -eu

REPO="Juuzoe/bloatrail"
BIN="bloatrail"

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "this script needs $1, which is not installed"
}

# --- what are we running on? -------------------------------------------------

detect_target() {
    os=$(uname -s)
    arch=$(uname -m)

    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        arm64 | aarch64) arch=aarch64 ;;
        *) die "unsupported processor: $arch. Build from source with: cargo install --git https://github.com/$REPO" ;;
    esac

    case "$os" in
        Darwin)
            echo "${arch}-apple-darwin"
            ;;
        Linux)
            # The musl build is static and runs anywhere, so it is the default
            # on x86. No musl build is published for ARM yet, so ARM uses glibc.
            if [ "$arch" = "x86_64" ]; then
                echo "x86_64-unknown-linux-musl"
            else
                echo "aarch64-unknown-linux-gnu"
            fi
            ;;
        *)
            die "unsupported system: $os. Build from source with: cargo install --git https://github.com/$REPO"
            ;;
    esac
}

# --- where does it go? -------------------------------------------------------

detect_install_dir() {
    if [ -n "${BLOATRAIL_INSTALL_DIR:-}" ]; then
        echo "$BLOATRAIL_INSTALL_DIR"
    elif [ -w /usr/local/bin ]; then
        echo /usr/local/bin
    elif [ -n "${HOME:-}" ]; then
        echo "$HOME/.local/bin"
    else
        die "HOME is not set and /usr/local/bin is not writable. Set BLOATRAIL_INSTALL_DIR to choose a location."
    fi
}

# Name the file the user's shell actually reads. Getting this wrong is worse
# than saying nothing: macOS has defaulted to zsh since Catalina, and zsh never
# reads ~/.profile.
shell_profile() {
    case "$(basename "${SHELL:-sh}")" in
        zsh) echo "${ZDOTDIR:-$HOME}/.zshrc" ;;
        bash)
            if [ "$(uname -s)" = "Darwin" ]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.bashrc"
            fi
            ;;
        fish) echo "${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
        *) echo "$HOME/.profile" ;;
    esac
}

# --- fetch -------------------------------------------------------------------

latest_version() {
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' |
        head -n 1
}

checksum_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

# Refuse to install something that could not be checked, unless the caller has
# said otherwise. Skipping quietly would make a tampered download and a normal
# one look identical.
verify() {
    archive_path="$1"
    archive_name="$2"
    sums="$3"

    if [ ! -s "$sums" ]; then
        unverified "the checksum file could not be downloaded"
        return
    fi

    # Tolerate a trailing carriage return in case a line was produced on Windows.
    expected=$(sed 's/\r$//' "$sums" | grep " $archive_name\$" | awk '{print $1}' | head -n 1)
    if [ -z "$expected" ]; then
        unverified "SHA256SUMS lists no entry for $archive_name"
        return
    fi

    actual=$(checksum_of "$archive_path")
    if [ -z "$actual" ]; then
        unverified "neither sha256sum nor shasum is installed"
        return
    fi

    if [ "$actual" != "$expected" ]; then
        die "checksum mismatch for $archive_name
  expected $expected
  got      $actual
The download does not match what the release publishes. Nothing was installed."
    fi
    info "Checksum verified"
}

unverified() {
    if [ "${BLOATRAIL_NO_VERIFY:-0}" = "1" ]; then
        warn "installing without verifying the download: $1"
        return
    fi
    die "cannot verify the download: $1
Re-run with BLOATRAIL_NO_VERIFY=1 to install anyway, or download the archive
and check it by hand: https://github.com/$REPO/releases"
}

main() {
    need curl
    need tar

    target=$(detect_target)

    version=${BLOATRAIL_VERSION:-}
    if [ -z "$version" ]; then
        version=$(latest_version) || true
        [ -n "$version" ] || die "could not determine the latest version; set BLOATRAIL_VERSION to install a specific one"
    fi

    archive="$BIN-$version-$target.tar.gz"
    url="https://github.com/$REPO/releases/download/$version/$archive"

    tmp=$(mktemp -d)
    # Each signal exits explicitly. A handler that only cleans up would return
    # to the interrupted line and carry on against a directory it just deleted,
    # reporting the interruption as a corrupt archive.
    trap 'rm -rf "$tmp"' EXIT
    trap 'rm -rf "$tmp"; exit 130' INT
    trap 'rm -rf "$tmp"; exit 143' TERM

    info "Downloading $BIN $version for $target"
    curl -fsSL "$url" -o "$tmp/$archive" ||
        die "could not download $url
Check https://github.com/$REPO/releases for the available builds."

    curl -fsSL "https://github.com/$REPO/releases/download/$version/SHA256SUMS" \
        -o "$tmp/SHA256SUMS" 2>/dev/null || true
    verify "$tmp/$archive" "$archive" "$tmp/SHA256SUMS"

    tar xzf "$tmp/$archive" -C "$tmp"
    payload="$tmp/$BIN-$version-$target"
    [ -f "$payload/$BIN" ] || die "the archive did not contain $BIN"

    dir=$(detect_install_dir)

    # Create and write through one code path, so a directory that needs root is
    # handled rather than aborting on mkdir before the fallback is reached.
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        elevate=""
    elif mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ]; then
        elevate=""
    elif command -v sudo >/dev/null 2>&1; then
        info "$dir needs elevated permissions"
        elevate="sudo"
        $elevate mkdir -p "$dir"
    else
        die "$dir cannot be written to and sudo is unavailable. Set BLOATRAIL_INSTALL_DIR to somewhere you can write."
    fi

    installed=""
    # The desktop app ships in the macOS archives; on Linux it is built from
    # source, so it is installed only when the archive actually carries it.
    for name in "$BIN" "$BIN-gui"; do
        if [ -f "$payload/$name" ]; then
            $elevate install -m 755 "$payload/$name" "$dir/$name"
            installed="$installed $name"
        fi
    done

    info "Installed$installed to $dir"

    case ":${PATH:-}:" in
        *":$dir:"*) ;;
        *)
            profile=$(shell_profile)
            info ""
            info "$dir is not on your PATH. Add it with:"
            info "  echo 'export PATH=\"$dir:\$PATH\"' >> $profile"
            info "Then open a new terminal, or run it by full path:"
            info "  $dir/$BIN scan"
            info ""
            return
            ;;
    esac

    info ""
    info "Try it:  $BIN scan"
}

main "$@"
