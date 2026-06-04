<#
.SYNOPSIS
    Unblocks the ReaperShield release EXE and optionally code-signs it with
    a self-signed cert. The Mark-of-the-Web (MOTW) inherited from the
    workspace path is what causes the Windows "This app can't run on your
    PC" dialog. Unblock-File removes it. If you also want the SmartScreen
    "Unknown publisher" warning gone, run this script as admin so the cert
    can be added to LocalMachine\TrustedPublisher.
.PARAMETER ExePath
    Path to the EXE. Defaults to target\release\reapershield.exe.
.PARAMETER Sign
    Also generate / reuse a self-signed cert and sign the EXE.
#>
param(
    [string]$ExePath = "target\release\reapershield.exe",
    [switch]$Sign = $false
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Host "[sign] EXE not found: $ExePath" -ForegroundColor Red
    Write-Host "[sign] Run 'cargo build --release -p reapershield-cli' first." -ForegroundColor Yellow
    exit 1
}
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path

# 1) Unblock — clears the Zone.Identifier ADS that triggers the dialog
Write-Host "[sign] Unblocking $ExePath..." -ForegroundColor Cyan
try { Unblock-File -LiteralPath $ExePath -ErrorAction Stop } catch { }

# 2) Optional: sign with a self-signed cert
if ($Sign) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ExePath `"$ExePath`" -Sign"
        Start-Process powershell -Verb RunAs -ArgumentList $arg
        exit 0
    }
    $CertSubject = "CN=ReaperShield Dev, O=ReaperShield, L=Internal, C=PL"
    $existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.Subject -eq $CertSubject -and $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Code Signing" }
    } | Select-Object -First 1
    if (-not $existing) {
        Write-Host "[sign] Creating self-signed cert..." -ForegroundColor Cyan
        $existing = New-SelfSignedCertificate -Subject $CertSubject -Type CodeSigningCert `
            -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5) `
            -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256
    }
    $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher", "LocalMachine")
    $rootStore.Open("ReadWrite")
    try { $rootStore.Add($existing) } catch { }
    $rootStore.Close()
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($signtool) {
        & signtool.exe sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
            /sha1 $existing.Thumbprint /s MY $ExePath
    } else {
        Set-AuthenticodeSignature -FilePath $ExePath -Certificate $existing `
            -TimestampServer "http://timestamp.digicert.com"
    }
    $verify = Get-AuthenticodeSignature -FilePath $ExePath
    if ($verify.Status -eq "Valid") {
        Write-Host "[sign] Signed and trusted locally." -ForegroundColor Green
    } else {
        Write-Host "[sign] Signature status: $($verify.Status)" -ForegroundColor Yellow
    }
}

# 3) Final check
Write-Host "[sign] Done. Run the EXE now." -ForegroundColor Green
