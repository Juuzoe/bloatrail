<#
.SYNOPSIS
    Install Bloatrail on Windows.

.DESCRIPTION
    irm https://raw.githubusercontent.com/Juuzoe/bloatrail/main/install.ps1 | iex

    Downloads the release archive for this machine, checks it against the
    published checksum and copies the binaries into place. Nothing is installed
    system-wide and no registry keys are written beyond the user's PATH.

    Piping to iex leaves no way to pass parameters, so the options are
    environment variables:

      $env:BLOATRAIL_VERSION      = 'v0.3.0'   # install a specific tag
      $env:BLOATRAIL_INSTALL_DIR  = 'C:\tools' # install somewhere else
      $env:BLOATRAIL_NO_VERIFY    = '1'        # proceed without a checksum
#>

# Everything lives in a function so that `iex` does not leave StrictMode and
# ErrorActionPreference altered in the caller's session: both are scoped here.
function Install-Bloatrail {
    [CmdletBinding()]
    param(
        [string] $Version,
        [string] $InstallDir,
        [switch] $NoVerify
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $repo = 'Juuzoe/bloatrail'

    function Write-Info { param([string] $Message) Write-Host $Message }

    # TLS 1.2 is not the default on Windows PowerShell 5.1, and GitHub requires it.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # --- what are we running on? --------------------------------------------

    # PROCESSOR_ARCHITECTURE describes the *process*, so a 64-bit x64
    # PowerShell emulated on an ARM64 machine reports AMD64. Ask the OS.
    $target = $null
    try {
        switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
            'Arm64' { $target = 'aarch64-pc-windows-msvc' }
            'X64'   { $target = 'x86_64-pc-windows-msvc' }
        }
    } catch {
        # Older hosts without RuntimeInformation fall through to the variables.
    }
    if (-not $target) {
        $arch = $env:PROCESSOR_ARCHITECTURE
        if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
        $target = switch ($arch) {
            'ARM64' { 'aarch64-pc-windows-msvc' }
            'AMD64' { 'x86_64-pc-windows-msvc' }
            default {
                throw "Unsupported processor architecture '$arch'. Build from source with: cargo install --git https://github.com/$repo"
            }
        }
    }

    # --- which release? ------------------------------------------------------

    if (-not $Version) { $Version = $env:BLOATRAIL_VERSION }
    if (-not $Version) {
        try {
            $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
            $Version = $release.tag_name
        } catch {
            throw "Could not determine the latest version. Set `$env:BLOATRAIL_VERSION to a tag, or see https://github.com/$repo/releases"
        }
    }

    if (-not $InstallDir) { $InstallDir = $env:BLOATRAIL_INSTALL_DIR }
    if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Bloatrail' }
    if (-not $NoVerify) { $NoVerify = ($env:BLOATRAIL_NO_VERIFY -eq '1') }

    $archive = "bloatrail-$Version-$target.zip"
    $url = "https://github.com/$repo/releases/download/$Version/$archive"
    $temp = Join-Path ([IO.Path]::GetTempPath()) ("bloatrail-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp -Force | Out-Null

    try {
        Write-Info "Downloading Bloatrail $Version for $target"
        $zip = Join-Path $temp $archive
        try {
            Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        } catch {
            throw "Could not download $url`nCheck https://github.com/$repo/releases for the available builds."
        }

        # Fetching the checksum file is allowed to fail; comparing against it is
        # not. The two are separate so a mismatch can never be mistaken for a
        # network problem and swallowed. Windows PowerShell and PowerShell 7
        # raise different exception types, so the fetch catches everything.
        $sums = Join-Path $temp 'SHA256SUMS'
        $reason = $null
        try {
            Invoke-WebRequest -Uri "https://github.com/$repo/releases/download/$Version/SHA256SUMS" -OutFile $sums -UseBasicParsing
        } catch {
            $reason = 'the checksum file could not be downloaded'
        }

        if (-not $reason) {
            $line = Select-String -Path $sums -Pattern ([regex]::Escape($archive)) | Select-Object -First 1
            if (-not $line) {
                $reason = "SHA256SUMS lists no entry for $archive"
            } else {
                $expected = (($line.Line -split '\s+') | Where-Object { $_ })[0]
                $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
                if ($actual -ne $expected.ToLower()) {
                    throw "Checksum mismatch for $archive`n  expected $expected`n  got      $actual`nThe download does not match what the release publishes. Nothing was installed."
                }
                Write-Info 'Checksum verified'
            }
        }

        # Refuse rather than install something unchecked, unless told otherwise:
        # skipping quietly would make a tampered download look like a normal one.
        if ($reason) {
            if (-not $NoVerify) {
                throw "Cannot verify the download: $reason`nSet `$env:BLOATRAIL_NO_VERIFY = '1' to install anyway, or download the archive and check it by hand: https://github.com/$repo/releases"
            }
            Write-Warning "Installing without verifying the download: $reason"
        }

        Expand-Archive -Path $zip -DestinationPath $temp -Force
        $payload = Join-Path $temp "bloatrail-$Version-$target"
        if (-not (Test-Path $payload)) { throw 'The archive did not contain the expected folder.' }

        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        $installed = @()
        Get-ChildItem -Path $payload -Filter '*.exe' | ForEach-Object {
            Copy-Item $_.FullName -Destination $InstallDir -Force
            $installed += $_.Name
            Write-Info "Installed $($_.Name)"
        }
        if (-not $installed) { throw 'The archive contained no executables.' }

        Add-ToUserPath -Directory $InstallDir

        Write-Info ''
        Write-Info "Bloatrail $Version is installed in $InstallDir"
        Write-Info 'Try it:  bloatrail scan'
        if ($installed -contains 'bloatrail-gui.exe') {
            Write-Info 'Desktop app:  bloatrail-gui'
        }
    } finally {
        Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Add-ToUserPath {
    param([Parameter(Mandatory)] [string] $Directory)

    # [Environment]::GetEnvironmentVariable expands %VAR% references, and
    # writing the expanded result back would replace entries like
    # %JAVA_HOME%\bin with whatever they happen to point at today. Read and
    # write through the registry instead, preserving the value's kind.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $current = $key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        $kind = if ($key.GetValueNames() -contains 'Path') { $key.GetValueKind('Path') } else { 'ExpandString' }

        $entries = @($current -split ';' | Where-Object { $_ })
        if ($entries -notcontains $Directory) {
            $key.SetValue('Path', (($entries + $Directory) -join ';'), $kind)
            Write-Host "Added $Directory to your PATH"
        }
    } finally {
        if ($key) { $key.Dispose() }
    }

    # Make it usable in this session too, so the next line of advice works.
    if (($env:Path -split ';') -notcontains $Directory) {
        $env:Path = $env:Path.TrimEnd(';') + ';' + $Directory
    }
}

Install-Bloatrail
