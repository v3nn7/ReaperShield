use chrono::{DateTime, Utc};
use goblin::pe::PE;
use md5::Context as Md5Context;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("PE parsing failed: {0}")]
    PeParseError(String),

    #[error("Not a valid PE executable")]
    InvalidPeFile,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_size: u32,
    pub raw_data_pointer: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MitigationStatus {
    pub has_dep: bool,
    pub has_aslr: bool,
    pub has_high_entropy_aslr: bool,
    pub has_cfg: bool,
    pub has_force_integrity: bool,
    pub has_nx: bool,
    pub has_safeseh: bool,
    pub has_gs: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImportInfo {
    pub dll: String,
    pub function: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub rva: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeReport {
    pub file_name: String,
    pub file_size: u64,
    pub hashes: FileHashes,
    pub timestamp: DateTime<Utc>,
    
    // Header Info
    pub is_64_bit: bool,
    pub machine: u16,
    pub entry_point: u64,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsytem: u16,
    
    // Analysis
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub tls_callbacks: Vec<u32>,
    pub global_entropy: f64,
    pub mitigations: MitigationStatus,
    pub has_digital_signature: bool,
    pub packer_detected: bool,
    pub detected_packer_name: Option<String>,
    
    // Security Assessment
    pub security_score: u32, // out of 100
    pub security_issues: Vec<String>,
}

/// Calculate Shannon Entropy for a byte buffer
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Compute MD5, SHA-1, and SHA-256 for a buffer
pub fn compute_hashes(data: &[u8]) -> FileHashes {
    // MD5
    let mut md5_ctx = Md5Context::new();
    md5_ctx.consume(data);
    let md5_hash = format!("{:x}", md5_ctx.compute());

    // SHA1
    let mut sha1_ctx = Sha1::new();
    sha1_ctx.update(data);
    let sha1_hash = format!("{:x}", sha1_ctx.finalize());

    // SHA256
    let mut sha256_ctx = Sha256::new();
    sha256_ctx.update(data);
    let sha256_hash = format!("{:x}", sha256_ctx.finalize());

    FileHashes {
        md5: md5_hash,
        sha1: sha1_hash,
        sha256: sha256_hash,
    }
}

pub struct PeAnalyzer;

impl PeAnalyzer {
    pub fn analyze_file<P: AsRef<Path>>(path: P) -> Result<PeReport, AnalyzerError> {
        let path_ref = path.as_ref();
        let file_name = path_ref
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut file = File::open(path_ref)?;
        let file_size = file.metadata()?.len();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        Self::analyze_buffer(&buffer, file_name, file_size)
    }

    pub fn analyze_buffer(
        buffer: &[u8],
        file_name: String,
        file_size: u64,
    ) -> Result<PeReport, AnalyzerError> {
        let pe = PE::parse(buffer).map_err(|e| AnalyzerError::PeParseError(e.to_string()))?;

        // 1. Hashes
        let hashes = compute_hashes(buffer);

        // 2. Global Entropy
        let global_entropy = calculate_entropy(buffer);

        // 3. Sections & Section-specific analysis
        let mut sections = Vec::new();
        let mut packer_detected = false;
        let mut detected_packer_name = None;
        let mut security_issues = Vec::new();

        for section in pe.sections.iter() {
            let section_name = section.name().unwrap_or("").to_string();
            
            // Get section data
            let start = section.pointer_to_raw_data as usize;
            let end = (section.pointer_to_raw_data + section.size_of_raw_data) as usize;
            let section_data = if start < buffer.len() && end <= buffer.len() {
                &buffer[start..end]
            } else if start < buffer.len() {
                &buffer[start..]
            } else {
                &[]
            };

            let section_entropy = calculate_entropy(section_data);

            // Characteristics flags
            // IMAGE_SCN_MEM_READ = 0x40000000
            // IMAGE_SCN_MEM_WRITE = 0x80000000
            // IMAGE_SCN_MEM_EXECUTE = 0x20000000
            let is_readable = (section.characteristics & 0x4000_0000) != 0;
            let is_writable = (section.characteristics & 0x8000_0000) != 0;
            let is_executable = (section.characteristics & 0x2000_0000) != 0;

            let mut is_suspicious = false;
            let mut suspicion_reasons = Vec::new();

            // Executable and writable
            if is_writable && is_executable {
                is_suspicious = true;
                suspicion_reasons.push("Section is both Writable and Executable (W^X violation)".to_string());
            }

            // High entropy in non-resource sections (indicates packing or encryption)
            if section_entropy > 7.4 && section_name != ".rsrc" {
                is_suspicious = true;
                suspicion_reasons.push(format!("High entropy ({:.2}) suggests packed or encrypted code", section_entropy));
            }

            // Common packers naming
            let packer_names = ["UPX", "VMP", "THEM", "ASPACK", "PECOMP"];
            for p in &packer_names {
                if section_name.contains(p) {
                    packer_detected = true;
                    detected_packer_name = Some((*p).to_string());
                    is_suspicious = true;
                    suspicion_reasons.push(format!("Section name matches known packer/protector pattern ({})", p));
                }
            }

            // Size discrepancy
            if section.virtual_size > 0 && section.size_of_raw_data == 0 {
                is_suspicious = true;
                suspicion_reasons.push("Section virtual size is positive but raw size is zero (allocated at runtime)".to_string());
            }

            if is_suspicious {
                for r in &suspicion_reasons {
                    security_issues.push(format!("Section {}: {}", section_name, r));
                }
            }

            sections.push(SectionInfo {
                name: section_name,
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_data_size: section.size_of_raw_data,
                raw_data_pointer: section.pointer_to_raw_data,
                characteristics: section.characteristics,
                entropy: section_entropy,
                is_readable,
                is_writable,
                is_executable,
                is_suspicious,
                suspicion_reasons,
            });
        }

        // 4. Imports & Exports
        let mut imports = Vec::new();
        for import in pe.imports.iter() {
            imports.push(ImportInfo {
                dll: import.dll.to_string(),
                function: import.name.to_string(),
            });
        }

        let mut exports = Vec::new();
        for export in pe.exports.iter() {
            exports.push(ExportInfo {
                name: export.name.unwrap_or("").to_string(),
                rva: export.rva,
            });
        }

        // 5. TLS Callbacks Detection
        let mut tls_callbacks = Vec::new();
        if let Some(pe_header) = pe.header.optional_header {
            // TLS Directory is index 9
            let data_dirs = pe_header.data_directories;
            if let Some(Some((_, tls_dir))) = data_dirs.data_directories.get(9) {
                if tls_dir.virtual_address != 0 && tls_dir.size != 0 {
                    // Let's add the directory address as a callback location indicator
                    tls_callbacks.push(tls_dir.virtual_address);
                    security_issues.push("TLS Directory found. Potential TLS Callbacks present (anti-debug risk)".to_string());
                }
            }
        }

        // 6. Mitigations detection
        let mut has_dep = false;
        let mut has_aslr = false;
        let mut has_high_entropy_aslr = false;
        let mut has_cfg = false;
        let mut has_force_integrity = false;
        let mut has_nx = false;
        let mut has_safeseh = false;
        let mut has_gs = false;

        if let Some(opt) = pe.header.optional_header {
            let dll_characteristics = opt.windows_fields.dll_characteristics;
            // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
            has_aslr = (dll_characteristics & 0x0040) != 0;
            // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
            has_high_entropy_aslr = (dll_characteristics & 0x0020) != 0;
            // IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
            has_dep = (dll_characteristics & 0x0100) != 0;
            has_nx = has_dep;
            // IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
            has_cfg = (dll_characteristics & 0x4000) != 0;
            // IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
            has_force_integrity = (dll_characteristics & 0x0080) != 0;
            // IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400 (if NO_SEH, SafeSEH is implicit, else check flag if 32bit)
            let no_seh = (dll_characteristics & 0x0400) != 0;
            has_safeseh = no_seh || pe.is_64; // X64 has SEH exception tables instead of SafeSEH, so marked safe
            
            // GS (Stack cookies) are typically detected statically by searching imports or compiler features, 
            // but we can assume true if certain compiler features or CRT imports exist, or if we have CFG.
            // Let's check imports for security cookies helper (__security_cookie or similar)
            has_gs = imports.iter().any(|imp| {
                imp.function.contains("security_cookie") 
                || imp.function.contains("SecurityCookie")
                || imp.function.contains("__GS")
            }) || pe.is_64; // Default true on modern 64bit compiler targets unless disabled
        }

        let mitigations = MitigationStatus {
            has_dep,
            has_aslr,
            has_high_entropy_aslr,
            has_cfg,
            has_force_integrity,
            has_nx,
            has_safeseh,
            has_gs,
        };

        // 7. Security score computation
        // Base score is 100.
        // We deduct points for missing mitigations and security issues.
        let mut score: i32 = 100;

        if !has_dep {
            score -= 15;
            security_issues.push("DEP (Data Execution Prevention) is disabled".to_string());
        }
        if !has_aslr {
            score -= 15;
            security_issues.push("ASLR (Address Space Layout Randomization) is disabled".to_string());
        }
        if !has_high_entropy_aslr && pe.is_64 {
            score -= 5;
            security_issues.push("High Entropy ASLR is disabled (64-bit binary)".to_string());
        }
        if !has_cfg {
            score -= 10;
            security_issues.push("CFG (Control Flow Guard) is disabled".to_string());
        }
        if !has_safeseh && !pe.is_64 {
            score -= 10;
            security_issues.push("SafeSEH is disabled (32-bit binary)".to_string());
        }
        if !has_gs {
            score -= 5;
            security_issues.push("Stack Canary/Cookie protection (GS) not detected".to_string());
        }

        // Deduct for suspicious sections
        for sec in &sections {
            if sec.is_readable && sec.is_writable && sec.is_executable {
                score -= 15; // massive deduction
            } else if sec.is_writable && sec.is_executable {
                score -= 10;
            }
            if sec.entropy > 7.6 && sec.name != ".rsrc" {
                score -= 5;
            }
        }

        if packer_detected {
            score -= 10; // packed binaries might flag security warnings
        }

        let security_score = score.clamp(0, 100) as u32;

        // 8. Digital Signature Presence
        // Security data directory is index 4
        let mut has_digital_signature = false;
        if let Some(opt) = pe.header.optional_header {
            if let Some(Some((_, sig_dir))) = opt.data_directories.data_directories.get(4) {
                if sig_dir.virtual_address != 0 && sig_dir.size != 0 {
                    has_digital_signature = true;
                }
            }
        }
        if !has_digital_signature {
            security_issues.push("Binary is unsigned (no valid digital signature found)".to_string());
        }

        Ok(PeReport {
            file_name,
            file_size,
            hashes,
            timestamp: Utc::now(),
            is_64_bit: pe.is_64,
            machine: pe.header.coff_header.machine,
            entry_point: pe.entry as u64,
            image_base: pe.image_base as u64,
            section_alignment: pe.header.optional_header.map(|o| o.windows_fields.section_alignment).unwrap_or(0),
            file_alignment: pe.header.optional_header.map(|o| o.windows_fields.file_alignment).unwrap_or(0),
            subsytem: pe.header.optional_header.map(|o| o.windows_fields.subsystem).unwrap_or(0),
            sections,
            imports,
            exports,
            tls_callbacks,
            global_entropy,
            mitigations,
            has_digital_signature,
            packer_detected,
            detected_packer_name,
            security_score,
            security_issues,
        })
    }
}
