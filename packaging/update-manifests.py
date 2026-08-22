#!/usr/bin/env python3
"""Regenerate the package manifests from a published release.

The Scoop manifest, the Homebrew formula and the AUR PKGBUILD all need the
checksums of files that only exist once a release is built, so they are
generated rather than hand-edited.

    python packaging/update-manifests.py v0.3.0

Reads SHA256SUMS from the release and rewrites every manifest in place.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

REPO = "Juuzoe/bloatrail"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def checksums(version: str) -> dict[str, str]:
    """Map archive filename to its SHA-256, as published with the release."""
    text = fetch(f"https://github.com/{REPO}/releases/download/{version}/SHA256SUMS")
    sums: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            sums[parts[-1]] = parts[0].lower()
    if not sums:
        raise SystemExit(f"no checksums found for {version}")
    return sums


def archive(version: str, target: str, extension: str) -> str:
    return f"bloatrail-{version}-{target}.{extension}"


def url_for(version: str, name: str) -> str:
    return f"https://github.com/{REPO}/releases/download/{version}/{name}"


def need(sums: dict[str, str], name: str) -> str:
    if name not in sums:
        raise SystemExit(f"{name} is missing from SHA256SUMS")
    return sums[name]


def write_scoop(version: str, sums: dict[str, str]) -> Path:
    number = version.lstrip("v")
    x64 = archive(version, "x86_64-pc-windows-msvc", "zip")
    arm = archive(version, "aarch64-pc-windows-msvc", "zip")

    architecture = {
        "64bit": {
            "url": url_for(version, x64),
            "hash": need(sums, x64),
            "extract_dir": x64[: -len(".zip")],
        }
    }
    if arm in sums:
        architecture["arm64"] = {
            "url": url_for(version, arm),
            "hash": sums[arm],
            "extract_dir": arm[: -len(".zip")],
        }

    manifest = {
        "version": number,
        "description": "Developer-aware disk analyser: finds what is taking up space and what is safe to delete",
        "homepage": f"https://github.com/{REPO}",
        "license": "MIT",
        "architecture": architecture,
        "bin": ["bloatrail.exe"],
        "shortcuts": [["bloatrail-gui.exe", "Bloatrail"]],
        "checkver": {"github": f"https://github.com/{REPO}"},
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": url_for(
                        "v$version", "bloatrail-v$version-x86_64-pc-windows-msvc.zip"
                    ),
                    "extract_dir": "bloatrail-v$version-x86_64-pc-windows-msvc",
                },
                "arm64": {
                    "url": url_for(
                        "v$version", "bloatrail-v$version-aarch64-pc-windows-msvc.zip"
                    ),
                    "extract_dir": "bloatrail-v$version-aarch64-pc-windows-msvc",
                },
            },
            # The release publishes one combined SHA256SUMS rather than a
            # sidecar per archive, so autoupdate reads the hash out of it.
            "hash": {
                "url": url_for("v$version", "SHA256SUMS"),
                "regex": "$sha256\\s+$basename",
            },
        },
    }

    path = HERE / "scoop" / "bloatrail.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=4) + "\n", encoding="utf-8")
    return path


def write_homebrew(version: str, sums: dict[str, str]) -> Path:
    number = version.lstrip("v")
    arm_mac = archive(version, "aarch64-apple-darwin", "tar.gz")
    x64_mac = archive(version, "x86_64-apple-darwin", "tar.gz")
    x64_linux = archive(version, "x86_64-unknown-linux-musl", "tar.gz")
    arm_linux = archive(version, "aarch64-unknown-linux-gnu", "tar.gz")

    formula = f'''# Homebrew formula for Bloatrail.
#
#   brew install {REPO.split("/")[0]}/tap/bloatrail
#
# Homebrew removed installation from a formula URL, so this file has to live in
# a tap repository named homebrew-tap before anyone can install from it.
class Bloatrail < Formula
  desc "Developer-aware disk analyser that explains what is safe to delete"
  homepage "https://github.com/{REPO}"
  version "{number}"
  license "MIT"

  on_macos do
    on_arm do
      url "{url_for(version, arm_mac)}"
      sha256 "{need(sums, arm_mac)}"
    end
    on_intel do
      url "{url_for(version, x64_mac)}"
      sha256 "{need(sums, x64_mac)}"
    end
  end

  on_linux do
    on_arm do
      url "{url_for(version, arm_linux)}"
      sha256 "{need(sums, arm_linux)}"
    end
    on_intel do
      url "{url_for(version, x64_linux)}"
      sha256 "{need(sums, x64_linux)}"
    end
  end

  def install
    bin.install "bloatrail"
    # The desktop app ships in the macOS archives only.
    bin.install "bloatrail-gui" if File.exist?("bloatrail-gui")
    generate_completions_from_executable(bin/"bloatrail", "completions", shells: [:bash, :zsh, :fish])
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/bloatrail --version")
    system bin/"bloatrail", "scan", testpath, "--no-progress", "--json"
  end
end
'''
    path = HERE / "homebrew" / "bloatrail.rb"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(formula, encoding="utf-8")
    return path


def write_pkgbuild(version: str, sums: dict[str, str]) -> Path:
    number = version.lstrip("v")
    x64 = archive(version, "x86_64-unknown-linux-musl", "tar.gz")
    arm = archive(version, "aarch64-unknown-linux-gnu", "tar.gz")

    pkgbuild = f"""# Maintainer: Maksym Gavrylenko <mgavrylenko05@gmail.com>
pkgname=bloatrail-bin
pkgver={number}
pkgrel=1
pkgdesc="Developer-aware disk analyser that explains what is safe to delete"
arch=('x86_64' 'aarch64')
url="https://github.com/{REPO}"
license=('MIT')
provides=('bloatrail')
conflicts=('bloatrail')

source_x86_64=("{url_for(version, x64)}")
sha256sums_x86_64=('{need(sums, x64)}')

source_aarch64=("{url_for(version, arm)}")
sha256sums_aarch64=('{need(sums, arm)}')

package() {{
    # An `&&` one-liner would abort the build on x86_64, because makepkg runs
    # with `set -e` and a false test is a non-zero exit.
    local dir
    if [ "$CARCH" = "aarch64" ]; then
        dir="bloatrail-{version}-aarch64-unknown-linux-gnu"
    else
        dir="bloatrail-{version}-x86_64-unknown-linux-musl"
    fi

    install -Dm755 "$srcdir/$dir/bloatrail" "$pkgdir/usr/bin/bloatrail"
    install -Dm644 "$srcdir/$dir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 "$srcdir/$dir/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"

    "$srcdir/$dir/bloatrail" completions bash |
        install -Dm644 /dev/stdin "$pkgdir/usr/share/bash-completion/completions/bloatrail"
    "$srcdir/$dir/bloatrail" completions zsh |
        install -Dm644 /dev/stdin "$pkgdir/usr/share/zsh/site-functions/_bloatrail"
    "$srcdir/$dir/bloatrail" completions fish |
        install -Dm644 /dev/stdin "$pkgdir/usr/share/fish/vendor_completions.d/bloatrail.fish"
}}
"""
    path = HERE / "aur" / "PKGBUILD"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pkgbuild, encoding="utf-8")
    return path


def write_winget(version: str, sums: dict[str, str]) -> list[Path]:
    """Manifests for microsoft/winget-pkgs, which takes a pull request."""
    number = version.lstrip("v")
    x64 = archive(version, "x86_64-pc-windows-msvc", "zip")
    arm = archive(version, "aarch64-pc-windows-msvc", "zip")

    # Both Windows archives carry the CLI and the desktop app.
    def windows_installer(architecture: str, name: str, digest: str) -> dict:
        folder = name[: -len(".zip")]
        return {
            "Architecture": architecture,
            "InstallerUrl": url_for(version, name),
            "InstallerSha256": digest.upper(),
            "NestedInstallerFiles": [
                {
                    "RelativeFilePath": f"{folder}\\{binary}.exe",
                    "PortableCommandAlias": binary,
                }
                for binary in ("bloatrail", "bloatrail-gui")
            ],
        }

    installers = [windows_installer("x64", x64, need(sums, x64))]
    if arm in sums:
        installers.append(windows_installer("arm64", arm, sums[arm]))

    directory = HERE / "winget"
    directory.mkdir(parents=True, exist_ok=True)
    written = []

    version_manifest = f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.6.0.schema.json
PackageIdentifier: Juuzoe.Bloatrail
PackageVersion: {number}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"""
    installer_manifest = (
        "# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.6.0.schema.json\n"
        "PackageIdentifier: Juuzoe.Bloatrail\n"
        f"PackageVersion: {number}\n"
        "InstallerType: zip\n"
        "NestedInstallerType: portable\n"
        "Installers:\n"
    )
    for installer in installers:
        installer_manifest += f"  - Architecture: {installer['Architecture']}\n"
        installer_manifest += f"    InstallerUrl: {installer['InstallerUrl']}\n"
        installer_manifest += f"    InstallerSha256: {installer['InstallerSha256']}\n"
        installer_manifest += "    NestedInstallerFiles:\n"
        for nested in installer["NestedInstallerFiles"]:
            installer_manifest += f"      - RelativeFilePath: {nested['RelativeFilePath']}\n"
            installer_manifest += (
                f"        PortableCommandAlias: {nested['PortableCommandAlias']}\n"
            )
    installer_manifest += "ManifestType: installer\nManifestVersion: 1.6.0\n"

    locale_manifest = f"""# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.6.0.schema.json
PackageIdentifier: Juuzoe.Bloatrail
PackageVersion: {number}
PackageLocale: en-US
Publisher: Maksym Gavrylenko
PublisherUrl: https://github.com/{REPO.split("/")[0]}
PackageName: Bloatrail
PackageUrl: https://github.com/{REPO}
License: MIT
LicenseUrl: https://github.com/{REPO}/blob/main/LICENSE
ShortDescription: Developer-aware disk analyser that explains what is safe to delete
Description: |-
  Bloatrail reads the project files around a directory before judging it, so a
  target directory beside a Cargo.toml is regenerable build output while the
  same name elsewhere is left alone. It identifies dependencies, build
  artifacts, caches, Git data and container storage, explains why each one is
  on disk, and offers to remove only what your tools can rebuild.
Moniker: bloatrail
Tags:
  - cleanup
  - cli
  - disk-space
  - disk-usage
  - rust
ReleaseNotesUrl: https://github.com/{REPO}/releases/tag/{version}
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"""

    for name, content in [
        ("Juuzoe.Bloatrail.yaml", version_manifest),
        ("Juuzoe.Bloatrail.installer.yaml", installer_manifest),
        ("Juuzoe.Bloatrail.locale.en-US.yaml", locale_manifest),
    ]:
        path = directory / name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <version-tag>   e.g. v0.3.0")
    version = sys.argv[1]
    if not version.startswith("v"):
        raise SystemExit("the version tag must start with 'v'")
    # makepkg rejects a pkgver containing a hyphen, and Scoop and winget both
    # want a plain version, so a prerelease tag would emit manifests that no
    # package manager can read. Refuse rather than write them.
    number = version.lstrip("v")
    if not all(part.isdigit() for part in number.split(".")):
        raise SystemExit(
            f"{version} is not a plain release tag. Prerelease and build "
            "metadata are not supported by every manifest format, so these "
            "files are only generated for tags like v0.3.0."
        )

    sums = checksums(version)
    print(f"{len(sums)} checksums read for {version}")

    written = [
        write_scoop(version, sums),
        write_homebrew(version, sums),
        write_pkgbuild(version, sums),
        *write_winget(version, sums),
    ]
    for path in written:
        print(f"  wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
