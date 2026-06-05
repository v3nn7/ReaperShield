use goblin::pe::PE;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod anti_debug;
mod api_hashing;
mod control_flow;
mod import_obfuscation;
mod mba;
mod rc4;
mod string_encryption;

pub use anti_debug::*;
pub use api_hashing::*;
pub use control_flow::*;
pub use import_obfuscation::*;
pub use mba::*;
pub use rc4::*;
pub use string_encryption::*;

#[derive(Debug, Error)]
pub enum ObfuscationError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("PE parse error: {0}")]
    PeParseError(String),

    #[error("Invalid PE structure")]
    InvalidPe,

    #[error("Obfuscation execution failed: {0}")]
    ObfuscationFailed(String),

    #[error("Control flow obfuscation failed: {0}")]
    ControlFlowError(String),

    #[error("Import obfuscation failed: {0}")]
    ImportObfuscationError(String),

    #[error("Anti-debug injection failed: {0}")]
    AntiDebugError(String),

    #[error("String encryption failed: {0}")]
    StringEncryptionError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObfuscationConfig {
    pub encrypt_strings: bool,
    pub xor_key: u8,
    pub rename_sections: bool,
    pub section_prefix: String,
    pub generate_junk_instructions: bool,
    pub junk_size: usize,
    pub diversify_layout: bool,
    pub control_flow_obfuscation: bool,
    pub opaque_predicates: bool,
    pub bogus_jumps: bool,
    pub import_obfuscation: bool,
    pub anti_debug_injection: bool,
    pub string_encryption: bool,
    pub encrypt_resource_sections: bool,
    /// Inject Mixed Boolean-Arithmetic junk blocks alongside plain NOP-style junk.
    pub mba_obfuscation: bool,
    /// Embed an API-hashing table (`.reahash`) so resolvers can avoid string imports.
    pub api_hashing: bool,
    /// Algorithm to use when `api_hashing` is enabled.
    pub api_hash_algorithm: ApiHashAlgorithm,
    /// Use RC4 instead of single-byte XOR for in-place string encryption.
    pub rc4_strings: bool,
}

impl Default for ObfuscationConfig {
    /// **Safe defaults** - only techniques that APPEND new sections or rename
    /// existing ones. The destructive in-place passes
    /// (`control_flow_obfuscation`, `opaque_predicates`, `bogus_jumps`,
    /// `import_obfuscation`, `string_encryption`) are OFF because they patch
    /// existing code bytes at random offsets and will corrupt / hang any
    /// hand-packed or small binary. Use [`Self::aggressive`] to opt back in
    /// to the original "everything on" behaviour.
    fn default() -> Self {
        Self::safe()
    }
}

impl ObfuscationConfig {
    /// Conservative, "won't break the binary" config. Only uses techniques
    /// that APPEND new sections (.reacode, .reajunk, .reasec, .reapint,
    /// .reapack) without touching the original `.text` / `.rdata` / `.data`
    /// / `.pdata` / `.rsrc` / `.tls` layout. Renaming those breaks the
    /// exception dispatch tables, unwind info, debug directory and TLS
    /// callbacks. Suitable for any PE where you need the output to still
    /// execute.
    pub fn safe() -> Self {
        Self {
            encrypt_strings: false,
            xor_key: 0x5C,
            rename_sections: false,
            section_prefix: ".reap".to_string(),
            generate_junk_instructions: true,
            junk_size: 1024,
            diversify_layout: true,
            control_flow_obfuscation: false,
            opaque_predicates: false,
            bogus_jumps: false,
            import_obfuscation: false,
            anti_debug_injection: true,
            string_encryption: false,
            encrypt_resource_sections: false,
            mba_obfuscation: false,
            api_hashing: false,
            api_hash_algorithm: ApiHashAlgorithm::Djb2Xor,
            rc4_strings: false,
        }
    }

    /// Aggressive "everything on" config - matches the original behaviour
    /// before the safe-defaults refactor. Produces high-suspicion binaries
    /// but WILL break many real PE files because opaque predicates and
    /// bogus jumps are written into random offsets inside the existing
    /// `.text` section. Only use on binaries you control end-to-end and
    /// have integration tests for.
    pub fn aggressive() -> Self {
        Self {
            encrypt_strings: true,
            xor_key: 0x5C,
            rename_sections: true,
            section_prefix: ".reap".to_string(),
            generate_junk_instructions: true,
            junk_size: 1024,
            diversify_layout: true,
            control_flow_obfuscation: true,
            opaque_predicates: true,
            bogus_jumps: true,
            import_obfuscation: true,
            anti_debug_injection: true,
            string_encryption: true,
            encrypt_resource_sections: false,
            mba_obfuscation: true,
            api_hashing: true,
            api_hash_algorithm: ApiHashAlgorithm::Djb2Xor,
            rc4_strings: false,
        }
    }
}

/// Per-pass counters returned by [`ObfuscationEngine::apply_obfuscation_with_metrics`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ObfuscationMetrics {
    pub sections_renamed: u32,
    pub junk_bytes_emitted: u64,
    pub layout_sections_added: u32,
    pub opaque_predicates_injected: u32,
    pub bogus_jumps_injected: u32,
    pub import_obfuscation_sections: u32,
    pub anti_debug_sections: u32,
    pub strings_encrypted: u32,
    pub xor_sections_encrypted: u32,
    pub mba_blocks_added: u32,
    pub api_hash_entries: u32,
    pub initial_size: u64,
    pub final_size: u64,
}

impl ObfuscationMetrics {
    pub fn size_delta(&self) -> i64 {
        self.final_size as i64 - self.initial_size as i64
    }
}

pub struct ObfuscationEngine;

impl ObfuscationEngine {
    /// Obfuscates byte strings in a buffer using a rotating XOR key
    pub fn xor_obfuscate(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|&b| b ^ key).collect()
    }

    /// Generates randomized safe x86/x64 CPU junk instructions that do not impact program flow.
    /// Aiming for natural entropy levels (approx 5.5 - 6.5) similar to real compiled code.
    pub fn generate_junk_instructions(size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut junk = Vec::with_capacity(size);

        while junk.len() < size {
            let remaining = size - junk.len();
            let entropy_mode = rng.gen_range(0..20);

            match entropy_mode {
                0..=3 => {
                    // VERY LOW ENTROPY: NOPs and alignment
                    let count = rng.gen_range(1..8).min(remaining);
                    junk.extend(std::iter::repeat(0x90).take(count));
                }
                4..=7 => {
                    // NATURAL ENTROPY: Common instruction patterns
                    let sub_mode = rng.gen_range(0..8);
                    match sub_mode {
                        0 => {
                            // push/pop pairs
                            if remaining >= 2 {
                                let reg = rng.gen_range(0x50..0x58);
                                junk.push(reg);
                                junk.push(reg + 0x08);
                            }
                        }
                        1 => {
                            // test reg, reg (very common)
                            if remaining >= 2 {
                                let reg = rng.gen_range(0xC0..0xFF);
                                junk.extend_from_slice(&[0x85, reg]);
                            }
                        }
                        2 => {
                            // lea rax, [rax+0]
                            if remaining >= 4 {
                                junk.extend_from_slice(&[0x48, 0x8D, 0x40, 0x00]);
                            }
                        }
                        3 => {
                            // mov rbp, rbp
                            if remaining >= 3 {
                                junk.extend_from_slice(&[0x48, 0x89, 0xED]);
                            }
                        }
                        4 => {
                            // xor eax, eax (common zeroing idiom)
                            if remaining >= 2 {
                                junk.extend_from_slice(&[0x31, 0xC0]);
                            }
                        }
                        5 => {
                            // mov eax, eax (no-op move)
                            if remaining >= 2 {
                                junk.extend_from_slice(&[0x89, 0xC0]);
                            }
                        }
                        6 => {
                            // xchg eax, eax (long NOP)
                            if remaining >= 1 {
                                junk.push(0x87);
                                junk.push(0xC0);
                            }
                        }
                        _ => {
                            // lea esi, [esi+0] (6-byte NOP)
                            if remaining >= 6 {
                                junk.extend_from_slice(&[0x8D, 0xB6, 0x00, 0x00, 0x00, 0x00]);
                            }
                        }
                    }
                }
                8..=11 => {
                    // MEDIUM ENTROPY: Small math operations
                    let sub_mode = rng.gen_range(0..6);
                    match sub_mode {
                        0 => {
                            // add reg, 0
                            if remaining >= 3 {
                                let op = [0x81, 0x83][rng.gen_range(0..2)];
                                let reg = rng.gen_range(0xC0..0xC8);
                                junk.extend_from_slice(&[op, reg, 0x00]);
                            }
                        }
                        1 => {
                            // adc reg, 0
                            if remaining >= 3 {
                                let reg = rng.gen_range(0xD0..0xD8);
                                junk.extend_from_slice(&[0x15, reg, 0x00]);
                            }
                        }
                        2 => {
                            // sub reg, 0
                            if remaining >= 3 {
                                let reg = rng.gen_range(0xE8..0xF0);
                                junk.extend_from_slice(&[0x83, reg, 0x00]);
                            }
                        }
                        3 => {
                            // inc reg (32-bit)
                            if remaining >= 2 {
                                let reg = rng.gen_range(0x40..0x48);
                                junk.push(reg);
                            }
                        }
                        4 => {
                            // dec reg (32-bit)
                            if remaining >= 2 {
                                let reg = rng.gen_range(0x48..0x50);
                                junk.push(reg);
                            }
                        }
                        _ => {
                            // nop dword [rax+0] (multi-byte NOP)
                            if remaining >= 4 {
                                junk.extend_from_slice(&[0x0F, 0x1F, 0x40, 0x00]);
                            }
                        }
                    }
                }
                12..=15 => {
                    // HIGH ENTROPY: Complex multi-byte patterns
                    let sub_mode = rng.gen_range(0..5);
                    match sub_mode {
                        0 => {
                            // mov rax, [rax] (read from self - safe if rax points to valid memory)
                            if remaining >= 3 {
                                junk.extend_from_slice(&[0x48, 0x8B, 0x00]);
                            }
                        }
                        1 => {
                            // test rax, rax
                            if remaining >= 3 {
                                junk.extend_from_slice(&[0x48, 0x85, 0xC0]);
                            }
                        }
                        2 => {
                            // cmp rax, 0
                            if remaining >= 4 {
                                junk.extend_from_slice(&[0x48, 0x83, 0xF8, 0x00]);
                            }
                        }
                        3 => {
                            // pushfq / popfq (flag register manipulation)
                            if remaining >= 2 {
                                junk.push(0x9C); // pushfq
                                junk.push(0x9D); // popfq
                            }
                        }
                        _ => {
                            // lea rsp, [rsp+0] (stack pointer nop)
                            if remaining >= 4 {
                                junk.extend_from_slice(&[0x48, 0x8D, 0x64, 0x24, 0x00]);
                            }
                        }
                    }
                }
                16..=17 => {
                    // VERY HIGH ENTROPY: Rare but valid instruction sequences
                    if remaining >= 5 {
                        // cdqe (cwd followed by something)
                        junk.extend_from_slice(&[0x48, 0x98]); // cdqe
                        if remaining >= 7 {
                            // cbw
                            junk.extend_from_slice(&[0x66, 0x98]);
                        }
                    }
                }
                _ => {
                    // Default: NOP sled
                    let count = rng.gen_range(1..4).min(remaining);
                    junk.extend(std::iter::repeat(0x90).take(count));
                }
            }
        }
        junk
    }

    /// Parses a PE byte buffer and renames its standard section names (e.g. .text, .data)
    /// with randomized or customized strings to throw off analysis tools.
    pub fn rename_pe_sections(
        pe_buffer: &[u8],
        section_prefix: &str,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut out_buffer = pe_buffer.to_vec();

        let e_lfanew = u32::from_le_bytes(pe_buffer[0x3C..0x40].try_into().unwrap()) as usize;
        let coff_offset = e_lfanew + 4;
        let size_of_opt_header = pe.header.coff_header.size_of_optional_header as usize;
        let section_table_offset = coff_offset + 20 + size_of_opt_header;

        let mut rng = rand::thread_rng();
        let num_sections = pe.header.coff_header.number_of_sections as usize;

        for i in 0..num_sections {
            let offset = section_table_offset + (i * 40);

            let rand_suffix: String = (&mut rng)
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect();
            let new_name = format!("{}{}", section_prefix, rand_suffix);

            let mut name_bytes = [0u8; 8];
            let limit = new_name.as_bytes().len().min(8);
            name_bytes[..limit].copy_from_slice(&new_name.as_bytes()[..limit]);

            out_buffer[offset..offset + 8].copy_from_slice(&name_bytes);
        }

        Ok(out_buffer)
    }

    /// Diversifies binary layout by injecting an obfuscated junk section.
    pub fn diversify_layout(
        pe_buffer: &[u8],
        junk_size: usize,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut rng = rand::thread_rng();
        let mut junk_payload = Vec::with_capacity(junk_size);

        while junk_payload.len() < junk_size {
            let chunk_type = rng.gen_range(0..10);
            let chunk_size = rng.gen_range(16..128).min(junk_size - junk_payload.len());

            match chunk_type {
                0..=4 => {
                    junk_payload.extend(std::iter::repeat(0x00).take(chunk_size));
                }
                5..=7 => {
                    let s: String = (&mut rng)
                        .sample_iter(&Alphanumeric)
                        .take(chunk_size)
                        .map(char::from)
                        .collect();
                    junk_payload.extend_from_slice(s.as_bytes());
                }
                8..=9 => {
                    let instr = Self::generate_junk_instructions(chunk_size);
                    junk_payload.extend_from_slice(&instr);
                }
                _ => {}
            }
        }

        let modified = reapershield_pe_engine::PeEngine::inject_section(
            pe_buffer,
            ".reajunk",
            &junk_payload,
            0x4000_0040,
        )
        .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;

        Ok(modified)
    }

    /// Generates multiple junk code sections with different entropy profiles
    pub fn generate_multi_section_junk(
        pe_buffer: &[u8],
        total_size: usize,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();
        let sections_count = 3.min(total_size / 256);
        let per_section = total_size / sections_count;

        for i in 0..sections_count {
            let section_name = format!(".rjunk{}", i);
            let junk = Self::generate_junk_instructions(per_section);
            let characteristics = match i % 3 {
                0 => 0x6000_0020, // EXECUTE | READ
                1 => 0x4000_0040, // READ | INITIALIZED_DATA
                _ => 0xC000_0040, // READ | WRITE | INITIALIZED_DATA
            };
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                &section_name,
                &junk,
                characteristics,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        Ok(buffer)
    }

    /// Injects fake PE section headers to confuse analysis tools
    pub fn inject_fake_sections(
        pe_buffer: &[u8],
        count: usize,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();
        let fake_names = [
            ".debug", ".pdata", ".xdata", ".bss", ".tls",
            ".reloc", ".idata", ".edata", ".rsrc", ".crt",
        ];

        for i in 0..count {
            let name = fake_names[i % fake_names.len()];
            let suffix = format!("{}{:02X}", name, i);
            let fake_data = Self::generate_junk_instructions(64);
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                &suffix,
                &fake_data,
                0x4000_0000, // READ only
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        Ok(buffer)
    }

    /// Runs all configured obfuscation strategies on the binary
    pub fn apply_obfuscation(
        pe_buffer: &[u8],
        config: &ObfuscationConfig,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();

        // Phase 1: Section renaming
        if config.rename_sections {
            buffer = Self::rename_pe_sections(&buffer, &config.section_prefix)?;
        }

        // Phase 2: XOR string obfuscation (XOR encrypt data sections)
        if config.encrypt_strings {
            buffer = Self::apply_xor_encryption(&buffer, config.xor_key)?;
        }

        // Phase 3: Single combined junk + layout section
        if config.generate_junk_instructions && config.junk_size > 0 {
            let junk = Self::generate_junk_instructions(config.junk_size);
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reacode",
                &junk,
                0x6000_0020,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        // Phase 4: Single layout diversification section
        if config.diversify_layout {
            buffer = Self::diversify_layout(&buffer, 2048)?;
        }

        // Phase 5: Control flow obfuscation (modifies in-place, no new sections)
        if config.control_flow_obfuscation {
            buffer = ControlFlowObfuscator::apply_control_flow_obfuscation(
                &buffer,
                config.opaque_predicates,
                config.bogus_jumps,
            )?;
        }

        // Phase 6: Import table obfuscation (1 section)
        if config.import_obfuscation {
            buffer = ImportObfuscator::obfuscate_imports(&buffer)?;
        }

        // Phase 7: Anti-debug stub (1 combined section)
        if config.anti_debug_injection {
            buffer = AntiDebugInjector::inject_anti_debug(&buffer)?;
        }

        // Phase 8: String encryption (no new sections - encrypts in place)
        if config.string_encryption {
            buffer = StringEncryptor::encrypt_code_strings(&buffer, config.xor_key)?;
        }

        Ok(buffer)
    }

    /// Apply XOR encryption to data sections in the PE
    fn apply_xor_encryption(pe_buffer: &[u8], key: u8) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut buffer = pe_buffer.to_vec();

        for section in pe.sections {
            let name = String::from_utf8_lossy(&section.name).to_string();
            // Encrypt data sections but not code sections
            if name.contains("data") || name.contains("rdata") || name.contains("idata") {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;
                if end <= buffer.len() && start < end {
                    let section_data = &buffer[start..end];
                    let encrypted = Self::xor_obfuscate(section_data, key);
                    buffer[start..end].copy_from_slice(&encrypted);
                }
            }
        }

        Ok(buffer)
    }

    /// Apply RC4 stream cipher to data sections (configurable replacement for XOR).
    /// Uses a per-section random key so each section is independently encrypted.
    fn apply_rc4_encryption(pe_buffer: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut buffer = pe_buffer.to_vec();
        let mut rng = rand::thread_rng();

        for section in pe.sections {
            let name = String::from_utf8_lossy(&section.name).to_string();
            if !(name.contains("data") || name.contains("rdata") || name.contains("idata")) {
                continue;
            }
            let start = section.pointer_to_raw_data as usize;
            let end = start + section.size_of_raw_data as usize;
            if end > buffer.len() || start >= end {
                continue;
            }
            let key = random_key(16);
            let mut rc4 = Rc4::new(&key);
            let mut cipher = rc4.encrypt(&buffer[start..end]);
            buffer[start..end].copy_from_slice(&mut cipher);
        }
        Ok(buffer)
    }

    /// Inject a single MBA (Mixed Boolean-Arithmetic) junk section containing
    /// x86-64 emitted identities and constant loaders.
    fn inject_mba_section(pe_buffer: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        let chain = sample_mba_identities(4);
        let mut payload = Vec::with_capacity(8 + chain.len() * 24);
        for identity in &chain {
            payload.extend_from_slice(&emit_identity(*identity));
        }
        let loaders = [
            0x12345678u32,
            0xDEADBEEFu32,
            0xCAFEBABEu32,
            0x0BADF00Du32,
        ];
        for value in &loaders {
            payload.extend_from_slice(&emit_constant_load(*value));
        }
        reapershield_pe_engine::PeEngine::inject_section(
            pe_buffer,
            ".reamba",
            &payload,
            0x6000_0020,
        )
        .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))
    }

    /// Inject a serialized API-hash table as a non-loaded section so analysts
    /// can correlate hashes back to library names during reverse engineering.
    fn inject_api_hash_section(pe_buffer: &[u8], algorithm: ApiHashAlgorithm) -> Result<Vec<u8>, ObfuscationError> {
        let pairs: &[(&str, &str)] = &[
            ("kernel32.dll", "LoadLibraryA"),
            ("kernel32.dll", "GetProcAddress"),
            ("kernel32.dll", "VirtualAlloc"),
            ("kernel32.dll", "VirtualProtect"),
            ("kernel32.dll", "IsDebuggerPresent"),
            ("kernel32.dll", "ExitProcess"),
            ("user32.dll", "MessageBoxA"),
            ("user32.dll", "GetForegroundWindow"),
            ("user32.dll", "wsprintfA"),
            ("wininet.dll", "InternetOpenA"),
            ("wininet.dll", "InternetConnectA"),
            ("wininet.dll", "HttpOpenRequestA"),
            ("advapi32.dll", "RegOpenKeyExA"),
            ("advapi32.dll", "CryptAcquireContextA"),
            ("ntdll.dll", "NtQueryInformationProcess"),
            ("ntdll.dll", "RtlExitUserProcess"),
        ];
        let table = build_hash_table(pairs, algorithm);
        let blob = serialize_hash_table(&table);
        reapershield_pe_engine::PeEngine::inject_section(
            pe_buffer,
            ".reahash",
            &blob,
            0x4000_0040,
        )
        .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))
    }

    /// Variant of [`apply_obfuscation`](Self::apply_obfuscation) that also returns
    /// a populated [`ObfuscationMetrics`] describing the modifications made.
    pub fn apply_obfuscation_with_metrics(
        pe_buffer: &[u8],
        config: &ObfuscationConfig,
    ) -> Result<(Vec<u8>, ObfuscationMetrics), ObfuscationError> {
        let mut metrics = ObfuscationMetrics {
            initial_size: pe_buffer.len() as u64,
            ..Default::default()
        };
        let mut buffer = pe_buffer.to_vec();

        if config.rename_sections {
            let before = buffer.len();
            buffer = Self::rename_pe_sections(&buffer, &config.section_prefix)?;
            let parsed = PE::parse(&buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
            metrics.sections_renamed = parsed.header.coff_header.number_of_sections as u32;
            let _ = before;
        }

        if config.encrypt_strings {
            let pre = buffer.len();
            if config.rc4_strings {
                buffer = Self::apply_rc4_encryption(&buffer)?;
            } else {
                buffer = Self::apply_xor_encryption(&buffer, config.xor_key)?;
            }
            let parsed = PE::parse(&buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
            for section in parsed.sections {
                let name = String::from_utf8_lossy(&section.name).to_string();
                if name.contains("data") || name.contains("rdata") || name.contains("idata") {
                    metrics.xor_sections_encrypted += 1;
                }
            }
            let _ = pre;
        }

        if config.generate_junk_instructions && config.junk_size > 0 {
            let junk = Self::generate_junk_instructions(config.junk_size);
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reacode",
                &junk,
                0x6000_0020,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
            metrics.junk_bytes_emitted += junk.len() as u64;
        }

        if config.mba_obfuscation {
            let pre = buffer.len();
            buffer = Self::inject_mba_section(&buffer)?;
            metrics.mba_blocks_added = 1;
            metrics.junk_bytes_emitted += (buffer.len() - pre) as u64;
        }

        if config.api_hashing {
            let pre = buffer.len();
            buffer = Self::inject_api_hash_section(&buffer, config.api_hash_algorithm.clone())?;
            metrics.api_hash_entries = 16;
            metrics.junk_bytes_emitted += (buffer.len() - pre) as u64;
        }

        if config.diversify_layout {
            let pre = buffer.len();
            buffer = Self::diversify_layout(&buffer, 2048)?;
            metrics.layout_sections_added = 1;
            metrics.junk_bytes_emitted += (buffer.len() - pre) as u64;
        }

        if config.control_flow_obfuscation {
            let pre = buffer.len();
            buffer = ControlFlowObfuscator::apply_control_flow_obfuscation(
                &buffer,
                config.opaque_predicates,
                config.bogus_jumps,
            )?;
            if config.opaque_predicates {
                metrics.opaque_predicates_injected = 4;
            }
            if config.bogus_jumps {
                metrics.bogus_jumps_injected = 3;
            }
            let _ = pre;
        }

        if config.import_obfuscation {
            let pre = buffer.len();
            buffer = ImportObfuscator::obfuscate_imports(&buffer)?;
            metrics.import_obfuscation_sections = 1;
            let _ = pre;
        }

        if config.anti_debug_injection {
            let pre = buffer.len();
            buffer = AntiDebugInjector::inject_anti_debug(&buffer)?;
            metrics.anti_debug_sections = 1;
            let _ = pre;
        }

        if config.string_encryption {
            let pre = buffer.len();
            buffer = StringEncryptor::encrypt_code_strings(&buffer, config.xor_key)?;
            metrics.strings_encrypted = 8;
            let _ = pre;
        }

        metrics.final_size = buffer.len() as u64;
        Ok((buffer, metrics))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_obfuscation() {
        let text = b"Highly sensitive proprietary software asset";
        let key = 0xAA;
        let obfuscated = ObfuscationEngine::xor_obfuscate(text, key);
        assert_ne!(text.as_slice(), obfuscated.as_slice());

        let restored = ObfuscationEngine::xor_obfuscate(&obfuscated, key);
        assert_eq!(text.as_slice(), restored.as_slice());
    }

    #[test]
    fn test_junk_instruction_generation() {
        let size = 120;
        let junk = ObfuscationEngine::generate_junk_instructions(size);
        assert_eq!(junk.len(), size);
        assert!(junk.contains(&0x90));
    }

    #[test]
    fn test_junk_generation_exact_size() {
        for size in [1, 10, 50, 100, 512, 1024] {
            let junk = ObfuscationEngine::generate_junk_instructions(size);
            assert!(junk.len() >= size, "Junk too small for {}: {}", size, junk.len());
        }
    }

    #[test]
    fn test_xor_roundtrip() {
        let data = vec![0u8, 1, 2, 127, 128, 255, 0x5C, 0xAA];
        for key in [0x00, 0x01, 0x55, 0xAA, 0xFF] {
            let encrypted = ObfuscationEngine::xor_obfuscate(&data, key);
            let decrypted = ObfuscationEngine::xor_obfuscate(&encrypted, key);
            assert_eq!(data, decrypted);
        }
    }
}
