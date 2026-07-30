# infishark CLI installer for Windows.
#
# Prefers a prebuilt infishark.exe from GitHub Releases; otherwise builds from
# source with the local Rust + MSVC toolchain. Install root: %USERPROFILE%\.infishark\bin
#
# irm https://cdn.infishark.com/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$repo   = 'infishark/infishark'
$dest   = Join-Path $env:USERPROFILE '.infishark\bin'
$bin    = Join-Path $dest 'infishark.exe'
$target = 'x86_64-pc-windows-msvc'

function Say([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn([string]$m) { Write-Host "note: $m" -ForegroundColor Yellow }
function Fail([string]$m) { throw $m }

function Assert-Exe([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        Fail "Expected binary missing: $path"
    }
    if ((Get-Item -LiteralPath $path).Length -le 0) {
        Fail "Expected binary is empty: $path"
    }
}

New-Item -ItemType Directory -Force -Path $dest | Out-Null

$installed = $false
$url = "https://github.com/$repo/releases/latest/download/infishark-$target.zip"

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) (
    'infishark-install-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$zip = Join-Path $tmpDir 'infishark.zip'
try {
    Say "Installing prebuilt infishark ($target)"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    if (-not (Test-Path -LiteralPath $zip) -or (Get-Item -LiteralPath $zip).Length -le 0) {
        Fail "download empty or missing"
    }
    Expand-Archive -Path $zip -DestinationPath $tmpDir -Force
    $found = Get-ChildItem -Path $tmpDir -Filter 'infishark.exe' -Recurse -File |
        Select-Object -First 1
    if (-not $found) {
        Fail "archive has no infishark.exe"
    }
    Copy-Item -LiteralPath $found.FullName -Destination $bin -Force
    Assert-Exe $bin
    $installed = $true
} catch {
    Warn "prebuilt unavailable ($($_.Exception.Message)); trying source build"
} finally {
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $installed) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Fail @"
No prebuilt binary and Rust is not installed.
Install Rust from https://rustup.rs, plus Visual Studio Build Tools 2022 with
the "Desktop development with C++" workload (MSVC + Windows SDK), then re-run.
"@
    }

    $link = Get-Command link.exe -ErrorAction SilentlyContinue
    if ($null -eq $link) {
        Warn "link.exe not on PATH. Open 'x64 Native Tools Command Prompt for VS' (or install VS Build Tools MSVC + Windows SDK) before building from source."
    } elseif ($link.Source -notmatch '[\\/]Microsoft Visual Studio[\\/]') {
        Warn "link.exe is '$($link.Source)' — not MSVC. Put Visual Studio's linker first on PATH, or remove the other link.exe (e.g. Git/Hermes usr\bin)."
    }

    Say "Building infishark from source (needs MSVC; Smart App Control may block unsigned cargo build scripts)"
    $cargoRoot = Split-Path $dest -Parent
    & cargo install --git "https://github.com/$repo" infishark-cli --root $cargoRoot
    if ($LASTEXITCODE -ne 0) {
        Fail @"
cargo install failed (exit $LASTEXITCODE).
Requirements for a Windows source build:
  - Rust (rustup) with the stable MSVC toolchain
  - Visual Studio Build Tools 2022: MSVC + Windows SDK
  - MSVC link.exe on PATH (not a Unix link.exe from Git)
  - Windows Smart App Control may block unsigned cargo build-script EXEs;
    use the prebuilt release binary, or temporarily allow the build under SAC.
"@
    }
    Assert-Exe $bin
}

Say "Installed infishark.exe to $dest"
if (";$env:Path;" -notlike "*;$dest;*") {
    Warn "add it to PATH -> setx PATH `"$dest;$env:Path`""
}
Say "Done. Run: infishark ports"
