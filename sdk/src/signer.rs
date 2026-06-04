//! Optional post-protection code-signing step.
//!
//! Runs after the protected EXE is written. Uses signtool.exe if available
//! (ships with Windows SDK), otherwise falls back to a short PowerShell
//! snippet that uses Set-AuthenticodeSignature. The self-signed dev cert
//! is created in the user's store on demand.

use crate::{PostSignConfig, SignStatus};
use chrono::Utc;
use std::path::Path;
use std::process::Command;

/// Sign `exe_path` according to `config`. On success, the EXE is overwritten
/// in place with the signed version. Safe to call on non-Windows (returns
/// `Ok(SignStatus { signed: false, error: Some("non-windows") })`).
pub fn sign_exe(exe_path: &Path, config: &PostSignConfig) -> SignStatus {
    #[cfg(not(windows))]
    {
        return SignStatus {
            signed: false,
            signer: String::new(),
            timestamp: None,
            cert_thumbprint: None,
            trusted_locally: false,
            error: Some("code signing only supported on Windows".into()),
        };
    }

    #[cfg(windows)]
    {
        sign_exe_windows(exe_path, config)
    }
}

#[cfg(windows)]
fn sign_exe_windows(exe_path: &Path, config: &PostSignConfig) -> SignStatus {
    let exe = exe_path.to_string_lossy().replace('\'', "''");

    // 1) Locate signtool.exe (Windows SDK), or fall back to PowerShell.
    let signtool = config
        .signtool_path
        .clone()
        .or_else(find_signtool)
        .map(|p| p.to_string_lossy().to_string());

    // 2) Find or create the cert, capture its thumbprint.
    let thumbprint = match ensure_cert(config) {
        Ok(t) => t,
        Err(e) => {
            return SignStatus {
                signed: false,
                signer: String::new(),
                timestamp: None,
                cert_thumbprint: None,
                trusted_locally: false,
                error: Some(format!("cert: {}", e)),
            };
        }
    };

    // 3) Optional: trust the cert locally.
    let trusted_locally = if config.trust_locally {
        trust_cert_locally(&config.cert_subject).unwrap_or(false)
    } else {
        false
    };

    // 4) Sign.
    let ts = Utc::now();
    let sign_result = if let Some(tool) = signtool.as_deref() {
        let mut cmd = Command::new(tool);
        cmd.arg("sign")
            .arg("/fd").arg("SHA256")
            .arg("/sha1").arg(&thumbprint);
        if let Some(url) = &config.timestamp_url {
            cmd.arg("/tr").arg(url).arg("/td").arg("SHA256");
        }
        cmd.arg(exe_path);
        cmd.output()
    } else {
        // PowerShell fallback.
        let ts_arg = match &config.timestamp_url {
            Some(u) => format!("-TimestampServer '{}'", u.replace('\'', "''")),
            None => String::new(),
        };
        let script = format!(
            "$p='{}'; $c=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Thumbprint -eq '{}' }} | Select-Object -First 1; \
             if (-not $c) {{ exit 2 }}; \
             Set-AuthenticodeSignature -FilePath $p -Certificate $c {ts} -ErrorAction Stop | Out-Null; \
             if ((Get-AuthenticodeSignature $p).Status -ne 'Valid') {{ exit 3 }}",
            exe, thumbprint, ts = ts_arg
        );
        Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
            .output()
    };

    match sign_result {
        Ok(o) if o.status.success() => SignStatus {
            signed: true,
            signer: config.cert_subject.clone(),
            timestamp: Some(ts),
            cert_thumbprint: Some(thumbprint),
            trusted_locally,
            error: None,
        },
        Ok(o) => SignStatus {
            signed: false,
            signer: String::new(),
            timestamp: None,
            cert_thumbprint: Some(thumbprint),
            trusted_locally,
            error: Some(format!(
                "signer exit={}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            )),
        },
        Err(e) => SignStatus {
            signed: false,
            signer: String::new(),
            timestamp: None,
            cert_thumbprint: Some(thumbprint),
            trusted_locally,
            error: Some(format!("spawn failed: {}", e)),
        },
    }
}

#[cfg(windows)]
fn find_signtool() -> Option<std::path::PathBuf> {
    if let Ok(out) = Command::new("where").arg("signtool.exe").output() {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let p = std::path::PathBuf::from(line.trim());
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    // Typical Windows SDK install locations.
    let pf = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| "C:\\Program Files (x86)".into());
    for kit in ["Windows Kits\\10\\bin", "Windows Kits\\11\\bin"] {
        let base = std::path::Path::new(&pf).join(kit);
        if let Ok(read) = std::fs::read_dir(&base) {
            for entry in read.flatten() {
                let cand = entry.path().join("x64").join("signtool.exe");
                if cand.exists() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn ensure_cert(config: &PostSignConfig) -> Result<String, String> {
    // 1) Look for existing cert with that subject.
    let lookup_script = format!(
        "$c = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -eq '{}' -and ($_.Extensions | Where-Object {{ $_.Oid.FriendlyName -eq 'Code Signing' }}) }} | Select-Object -First 1; if ($c) {{ $c.Thumbprint }} else {{ '' }}",
        config.cert_subject.replace('\'', "''")
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &lookup_script])
        .output()
        .map_err(|e| format!("powershell lookup failed: {}", e))?;
    let existing = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !existing.is_empty() {
        return Ok(existing);
    }
    if !config.self_signed {
        return Err(format!(
            "no cert with subject '{}' found in CurrentUser\\My and self_signed=false",
            config.cert_subject
        ));
    }
    // 2) Create self-signed cert.
    let create_script = format!(
        "$pwd = ConvertTo-SecureString -String 'ReaperShield' -Force -AsPlainText; \
         New-SelfSignedCertificate -Subject '{}' -Type CodeSigningCert \
         -CertStoreLocation 'Cert:\\CurrentUser\\My' \
         -NotAfter (Get-Date).AddYears(5) \
         -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 \
         | Select-Object -ExpandProperty Thumbprint",
        config.cert_subject.replace('\'', "''")
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &create_script])
        .output()
        .map_err(|e| format!("powershell create failed: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "cert creation failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(windows)]
fn trust_cert_locally(subject: &str) -> Result<bool, String> {
    let script = format!(
        "$c = Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -eq '{}' }} | Select-Object -First 1; \
         if (-not $c) {{ exit 1 }}; \
         $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine'); \
         $store.Open('ReadWrite'); \
         $store.Add($c); $store.Close(); 'OK'",
        subject.replace('\'', "''")
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .map_err(|e| format!("powershell trust failed: {}", e))?;
    Ok(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("OK"))
}
