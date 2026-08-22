## Install

**macOS and Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.ps1 | iex
```

**From source**

```sh
cargo install --git https://github.com/Juuzoe/bloatrail --locked
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

The musl build is statically linked and runs on any distribution;
`x86_64-unknown-linux-gnu` is here too for anyone who prefers the system glibc.
The Windows and macOS archives contain the desktop app alongside the CLI. On
Linux it needs a matching GTK and X11 at runtime, which no single archive can
promise across distributions, so build it with
`cargo install --git https://github.com/Juuzoe/bloatrail --locked --features gui`.

`SHA256SUMS` covers every archive, including the Windows ones:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Downloads through a browser are quarantined by macOS. Either use the install
script above, which is not affected, or clear the flag:

```sh
xattr -dr com.apple.quarantine bloatrail
```

---
