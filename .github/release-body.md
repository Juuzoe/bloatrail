## Install

**macOS and Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.ps1 | iex
```

**With Cargo**

```sh
cargo install bloatrail
```

Or download an archive below and put `bloatrail` on your `PATH`.

## Which file do I want?

| You are on | File |
| --- | --- |
| Windows, ordinary PC | `x86_64-pc-windows-msvc.zip` |
| Windows on ARM (Snapdragon, Surface Pro X) | `aarch64-pc-windows-msvc.zip` |
| Mac with Apple silicon (M1 and later) | `aarch64-apple-darwin.tar.gz` |
| Mac with an Intel processor | `x86_64-apple-darwin.tar.gz` |
| Linux, ordinary PC | `x86_64-unknown-linux-musl.tar.gz` |
| Linux on ARM (Raspberry Pi 4/5, ARM server) | `aarch64-unknown-linux-gnu.tar.gz` |

The musl build is statically linked and runs on any distribution. The Windows
and macOS archives contain the desktop app alongside the CLI; on Linux, build
it with `cargo install bloatrail --features gui`.

`SHA256SUMS` covers every archive:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Downloads through a browser are quarantined by macOS. Either use the install
script above, which is not affected, or clear the flag:

```sh
xattr -dr com.apple.quarantine bloatrail
```

---
