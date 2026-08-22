#!/bin/sh
# Install Bloatrail on macOS or Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.sh | sh
#
# Downloads the release archive for this machine, verifies its checksum and
# copies one binary into place. Set BLOATRAIL_INSTALL_DIR to choose where, and
# BLOATRAIL_VERSION to pin a release instead of taking the latest.

set -eu

REPO="Juuzoe/bloatrail"
BIN="bloatrail"

info() { printf '%s\n' "$*"; }
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
        *) die "unsupported processor: $arch. Build from source with: cargo install $BIN" ;;
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
            die "unsupported system: $os. Build from source with: cargo install $BIN"
            ;;
    esac
}

# --- where does it go? -------------------------------------------------------

detect_install_dir() {
    if [ -n "${BLOATRAIL_INSTALL_DIR:-}" ]; then
        echo "$BLOATRAIL_INSTALL_DIR"
    elif [ -w /usr/local/bin ] 2>/dev/null; then
        echo /usr/local/bin
    else
        echo "$HOME/.local/bin"
    fi
}

# --- fetch -------------------------------------------------------------------

latest_version() {
    curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' |
        head -n 1
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
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT INT TERM

    info "Downloading $BIN $version for $target"
    curl -fsSL "$url" -o "$tmp/$archive" ||
        die "could not download $url
Check https://github.com/$REPO/releases for the available builds."

    # The release publishes one checksum file for every archive. A missing or
    # unreadable file is not fatal, but a mismatch is.
    if curl -fsSL "https://github.com/$REPO/releases/download/$version/SHA256SUMS" -o "$tmp/SHA256SUMS" 2>/dev/null; then
        expected=$(grep " $archive\$" "$tmp/SHA256SUMS" | awk '{print $1}' | head -n 1)
        if [ -n "$expected" ]; then
            if command -v sha256sum >/dev/null 2>&1; then
                actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
            else
                actual=""
            fi
            if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
                die "checksum mismatch for $archive
  expected $expected
  got      $actual"
            fi
            [ -n "$actual" ] && info "Checksum verified"
        fi
    fi

    tar xzf "$tmp/$archive" -C "$tmp"
    extracted="$tmp/$BIN-$version-$target/$BIN"
    [ -f "$extracted" ] || die "the archive did not contain $BIN"

    dir=$(detect_install_dir)
    mkdir -p "$dir"

    if [ -w "$dir" ]; then
        install -m 755 "$extracted" "$dir/$BIN"
    elif command -v sudo >/dev/null 2>&1; then
        info "$dir needs elevated permissions"
        sudo install -m 755 "$extracted" "$dir/$BIN"
    else
        die "$dir is not writable and sudo is unavailable. Set BLOATRAIL_INSTALL_DIR to somewhere you can write."
    fi

    info "Installed $BIN to $dir/$BIN"

    case ":$PATH:" in
        *":$dir:"*) ;;
        *)
            info ""
            info "$dir is not on your PATH. Add it:"
            info "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile"
            ;;
    esac

    info ""
    info "Try it:  $BIN scan"
}

main "$@"
