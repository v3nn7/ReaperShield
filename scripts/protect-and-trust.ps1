<#
.SYNOPSIS
    One-shot: protect a binary with auto-signing and add the cert to
    LocalMachine\TrustedPublisher (kills the SmartScreen dialog permanently
    for this machine). Auto-elevates to admin via UAC.
.PARAMETER Input
    Path to the source EXE to protect
.PARAMETER Output
    Path to write the protected + signed EXE
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\protect-and-trust.ps1 `
        -Input test_target\test_target.exe `
        -Output test_target\test_target_protected.exe
#>
param(
    [Parameter(Mandatory=$true)][string]$Input,
    [Parameter(Mandatory=$true)][string]$Output
)

# Auto-elevate to admin so we can write to LocalMachine\TrustedPublisher.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Input `"$Input`" -Output `"$Output`""
    Write-Host "[protect] Requesting admin elevation..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList $arg -Wait
    exit $LASTEXITCODE
}

$root = Split-Path -Parent $PSScriptRoot
$reaper = Join-Path $root "target\release\reapershield.exe"
if (-not (Test-Path $reaper)) {
    Write-Host "[protect] Building release binary..." -ForegroundColor Cyan
    & "$root\scripts\build.ps1" -SkipGui | Out-Null
}

Write-Host "[protect] Running ReaperShield pipeline with --trust..." -ForegroundColor Cyan
& $reaper protect $Input --output $Output --trust
exit $LASTEXITCODE
