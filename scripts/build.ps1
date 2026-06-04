<#
.SYNOPSIS
    Full ReaperShield build pipeline: Vite frontend → mirror to cli/dist →
    Rust release build → Unblock MOTW. One command, no manual steps.
.PARAMETER SkipGui
    Skip the React build (use this if you only changed Rust code and the
    frontend is already in cli/dist).
.PARAMETER Debug
    Build the debug variant instead of release.
#>
param(
    [switch]$SkipGui = $false,
    [switch]$Debug = $false
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $stamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$stamp] === ReaperShield full build ===" -ForegroundColor Magenta

    if (-not $SkipGui) {
        if (-not (Test-Path "gui\node_modules")) {
            Write-Host "[$stamp] [1/4] npm install (first run only)..." -ForegroundColor Cyan
            Push-Location gui
            try { npm install --no-audit --no-fund --loglevel=error }
            finally { Pop-Location }
        } else {
            Write-Host "[$stamp] [1/4] npm install (skipped, node_modules present)" -ForegroundColor DarkGray
        }

        Write-Host "[$stamp] [2/4] npm run build (Vite → gui/dist)..." -ForegroundColor Cyan
        Push-Location gui
        try { npm run build 2>&1 | Select-String -Pattern "built in|error" | ForEach-Object { Write-Host "    $_" } }
        finally { Pop-Location }

        Write-Host "[$stamp] [3/4] mirroring gui/dist → cli/dist..." -ForegroundColor Cyan
        New-Item -ItemType Directory -Path "cli\dist" -Force | Out-Null
        Get-ChildItem "cli\dist" -Recurse -File -ErrorAction SilentlyContinue | Remove-Item -Force
        Copy-Item -Path "gui\dist\*" -Destination "cli\dist\" -Recurse -Force
    } else {
        Write-Host "[$stamp] [1-3/4] GUI build skipped (-SkipGui)" -ForegroundColor DarkGray
    }

    Write-Host "[$stamp] [4/4] cargo build..." -ForegroundColor Cyan
    $profile = if ($Debug) { "debug" } else { "release" }
    $flag = if ($Debug) { "" } else { "--release" }
    cargo build $flag -p reapershield-cli
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    $exe = "target\$profile\reapershield.exe"
    if (Test-Path $exe) {
        Write-Host "[$stamp] Unblocking $exe (clears Mark-of-the-Web)..." -ForegroundColor Cyan
        try { Unblock-File -LiteralPath $exe -ErrorAction Stop } catch { }
        $size = (Get-Item $exe).Length
        Write-Host "[$stamp] OK - $exe ($([math]::Round($size/1MB, 2)) MB)" -ForegroundColor Green
        Write-Host "[$stamp] Run with:  .\$exe" -ForegroundColor Green
    } else {
        Write-Host "[$stamp] WARNING: $exe not produced" -ForegroundColor Yellow
    }
} finally {
    Pop-Location
}
