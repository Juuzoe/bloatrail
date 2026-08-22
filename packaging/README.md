# Packaging

Manifests for the package managers Bloatrail is distributed through. Every file
here is generated, because each one needs the checksum of an archive that only
exists once a release is built:

```bash
python packaging/update-manifests.py v0.3.0
```

That reads `SHA256SUMS` from the published release and rewrites all of them.
Run it after a release finishes, then commit the result.

## Scoop (Windows)

Scoop installs straight from a URL, so the manifest works without a bucket:

```powershell
scoop install https://raw.githubusercontent.com/Juuzoe/bloatrail/main/packaging/scoop/bloatrail.json
```

To submit it to the community bucket, open a pull request against
[ScoopInstaller/Extras](https://github.com/ScoopInstaller/Extras) with
`bloatrail.json` in `bucket/`.

## Homebrew (macOS and Linux)

Homebrew removed installation from a formula URL, so this one needs a tap
before anybody can use it. Create a repository called `homebrew-tap`, put
`bloatrail.rb` in its `Formula/` directory, and the install command becomes:

```bash
brew install juuzoe/tap/bloatrail
```

homebrew-core has a notability requirement, so it comes after the project has
users, not before.

## AUR (Arch Linux)

`aur/PKGBUILD` builds `bloatrail-bin` from the published archives. Publishing
needs an AUR account and an SSH key registered with it:

```bash
git clone ssh://aur@aur.archlinux.org/bloatrail-bin.git
cp packaging/aur/PKGBUILD bloatrail-bin/
cd bloatrail-bin
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO && git commit -m "Update to 0.3.0" && git push
```

## winget (Windows)

`winget/` holds the three manifests the community repository expects. Submitting
means opening a pull request against
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs), placing them
under `manifests/j/Juuzoe/Bloatrail/<version>/`. Validate first:

```powershell
winget validate --manifest packaging/winget
```

## crates.io

`cargo publish` runs from the release workflow when a `CARGO_REGISTRY_TOKEN`
secret exists. Create the token at <https://crates.io/settings/tokens> and add
it under Settings → Secrets and variables → Actions. Without it the step is
skipped and the GitHub release still completes.
