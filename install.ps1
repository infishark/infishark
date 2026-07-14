# infishark CLI installer for Windows.
# Installs a prebuilt infishark.exe when one is published; otherwise builds from existing Rust toolchain. Target: %USERPROFILE%\.infishark\bin.
#
#   irm https://cdn.infishark.com/install.ps1 | iex
$ErrorActionPreference = 'Stop'

$repo   = 'infishark/infishark'
$dest   = Join-Path $env:USERPROFILE '.infishark\bin'
$target = 'x86_64-pc-windows-msvc'

function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }

New-Item -ItemType Directory -Force -Path $dest | Out-Null

$installed = $false
$url = "https://github.com/$repo/releases/latest/download/infishark-$target.zip"
try {
    Say "Installing prebuilt infishark ($target)"
    $tmp = New-TemporaryFile
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    Expand-Archive -Path $tmp -DestinationPath $dest -Force
    Remove-Item $tmp
    $installed = $true
} catch {
    Say "No prebuilt binary; building from source"
}

if (-not $installed) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Rust isn't installed. Install it from https://rustup.rs then re-run."
    }
    cargo install --git "https://github.com/$repo" infishark-cli --root (Split-Path $dest -Parent)
}

Say "Installed infishark.exe to $dest"
if (";$env:Path;" -notlike "*;$dest;*") {
    Write-Host "note: add it to PATH -> setx PATH `"$dest;$env:Path`"" -ForegroundColor Yellow
}
Say "Done. Run: infishark ports"
