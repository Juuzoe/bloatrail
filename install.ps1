<#
.SYNOPSIS
    Install Bloatrail on Windows.

.DESCRIPTION
    irm https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.ps1 | iex

    Downloads the release archive for this machine, verifies its checksum and
    copies the CLI and desktop app into place. Nothing is installed system-wide
    and no registry keys are written.

.PARAMETER Version
    Release tag to install, for example v0.3.0. Defaults to the latest release.

.PARAMETER InstallDir
    Where to put the binaries. Defaults to %LOCALAPPDATA%\Programs\Bloatrail.
#>
[CmdletBinding()]
param(
    [string] $Version = $env:BLOATRAIL_VERSION,
    [string] $InstallDir = $env:BLOATRAIL_INSTALL_DIR
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'Juuzoe/bloatrail'

function Write-Info { param([string] $Message) Write-Host $Message }

# TLS 1.2 is not the default on Windows PowerShell 5.1, and GitHub requires it.
[Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- what are we running on? -------------------------------------------------

$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }

$target = switch ($arch) {
    'AMD64' { 'x86_64-pc-windows-msvc' }
    'ARM64' { 'aarch64-pc-windows-msvc' }
    default {
        throw "Unsupported processor architecture '$arch'. Build from source with: cargo install bloatrail"
    }
}

# --- which release? ----------------------------------------------------------

if (-not $Version) {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $Version = $release.tag_name
    } catch {
        throw "Could not determine the latest version. Pass -Version, or see https://github.com/$Repo/releases"
    }
}

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Bloatrail'
}

$archive = "bloatrail-$Version-$target.zip"
$url = "https://github.com/$Repo/releases/download/$Version/$archive"
$temp = Join-Path ([IO.Path]::GetTempPath()) ("bloatrail-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    Write-Info "Downloading Bloatrail $Version for $target"
    $zip = Join-Path $temp $archive
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    } catch {
        throw "Could not download $url`nCheck https://github.com/$Repo/releases for the available builds."
    }

    # The release publishes one checksum file for every archive. A missing file
    # is not fatal, but a mismatch is.
    try {
        $sums = Join-Path $temp 'SHA256SUMS'
        Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$Version/SHA256SUMS" -OutFile $sums -UseBasicParsing
        $line = Select-String -Path $sums -Pattern ([regex]::Escape($archive)) | Select-Object -First 1
        if ($line) {
            $expected = ($line.Line -split '\s+')[0]
            $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected.ToLower()) {
                throw "Checksum mismatch for $archive`n  expected $expected`n  got      $actual"
            }
            Write-Info 'Checksum verified'
        }
    } catch [System.Net.WebException] {
        Write-Info 'No checksum file published for this release; skipping verification.'
    }

    Expand-Archive -Path $zip -DestinationPath $temp -Force
    $payload = Join-Path $temp "bloatrail-$Version-$target"
    if (-not (Test-Path $payload)) { throw "The archive did not contain the expected folder." }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Get-ChildItem -Path $payload -Filter '*.exe' | ForEach-Object {
        Copy-Item $_.FullName -Destination $InstallDir -Force
        Write-Info "Installed $($_.Name)"
    }

    # Put it on PATH for future sessions, and this one.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    if (($userPath -split ';') -notcontains $InstallDir) {
        $updated = if ($userPath.TrimEnd(';')) { $userPath.TrimEnd(';') + ';' + $InstallDir } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
        Write-Info "Added $InstallDir to your PATH"
    }
    if (($env:Path -split ';') -notcontains $InstallDir) {
        $env:Path = $env:Path.TrimEnd(';') + ';' + $InstallDir
    }

    Write-Info ''
    Write-Info "Bloatrail $Version is installed in $InstallDir"
    Write-Info 'Try it:  bloatrail scan'
    Write-Info 'Desktop app:  bloatrail-gui'
} finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}
