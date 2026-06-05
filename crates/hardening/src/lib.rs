use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HardeningError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("PE parsing failed: {0}")]
    PeParseError(String),

    #[error("Invalid PE file structure")]
    InvalidPe,

    #[error("Hardening application failed: {0}")]
    HardeningFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionIntegrity {
    pub name: String,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub sha256_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningIntegrityManifest {
    pub file_hash: String,
    pub section_count: usize,
    pub sections: Vec<SectionIntegrity>,
    pub tamper_protection_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HardeningConfig {
    pub force_dep: bool,
    pub force_aslr: bool,
    pub force_high_entropy_aslr: bool,
    pub force_cfg: bool,
    pub force_integrity_check: bool,
    pub inject_anti_tamper: bool,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            force_dep: true,
            force_aslr: true,
            force_high_entropy_aslr: true,
            force_cfg: true,
            force_integrity_check: true,
            inject_anti_tamper: true,
        }
    }
}

pub struct HardeningSystem;

impl HardeningSystem {
    /// Computes SHA256 hashes for all individual raw data sections of a PE
    pub fn generate_integrity_manifest(pe_buffer: &[u8]) -> Result<HardeningIntegrityManifest, HardeningError> {
        let pe = PE::parse(pe_buffer).map_err(|e| HardeningError::PeParseError(e.to_string()))?;
        
        let mut sections_integrity = Vec::new();
        
        // Calculate file hash
        let mut hasher = Sha256::new();
        hasher.update(pe_buffer);
        let file_hash = format!("{:x}", hasher.finalize());

        for section in pe.sections.iter() {
            let name = section.name().unwrap_or("").to_string();
            
            let start = section.pointer_to_raw_data as usize;
            let end = (section.pointer_to_raw_data + section.size_of_raw_data) as usize;
            let section_data = if start < pe_buffer.len() && end <= pe_buffer.len() {
                &pe_buffer[start..end]
            } else if start < pe_buffer.len() {
                &pe_buffer[start..]
            } else {
                &[]
            };

            let mut sec_hasher = Sha256::new();
            sec_hasher.update(section_data);
            let sha256_hash = format!("{:x}", sec_hasher.finalize());

            sections_integrity.push(SectionIntegrity {
                name,
                virtual_address: section.virtual_address,
                raw_size: section.size_of_raw_data,
                sha256_hash,
            });
        }

        Ok(HardeningIntegrityManifest {
            file_hash,
            section_count: pe.sections.len(),
            sections: sections_integrity,
            tamper_protection_enabled: true,
        })
    }

    /// Rewrites PE header characteristics to strictly enforce security mitigations
    pub fn enforce_pe_mitigations(
        pe_buffer: &[u8],
        config: &HardeningConfig,
    ) -> Result<Vec<u8>, HardeningError> {
        let pe = PE::parse(pe_buffer).map_err(|e| HardeningError::PeParseError(e.to_string()))?;
        let mut out_buffer = pe_buffer.to_vec();

        let e_lfanew = u32::from_le_bytes(pe_buffer[0x3C..0x40].try_into().unwrap()) as usize;
        let coff_offset = e_lfanew + 4;
        
        // Optional Header field offsets (from coff_offset + 24, i.e. past
        // the 4-byte PE\0\0 signature and 20-byte COFF header). DllCharacteristics
        // is at offset 70 of the Optional Header for BOTH PE32 and PE32+.
        // (Previous version used `coff_offset + 20 + 70`, which is 4 bytes
        // too early and clobbered SizeOfStackReserve/Commit, breaking the
        // binary at load time.)
        let dll_characteristics_offset = coff_offset + 24 + 70;

        if out_buffer.len() < dll_characteristics_offset + 2 {
            return Err(HardeningError::InvalidPe);
        }

        let mut dll_characteristics = u16::from_le_bytes(
            out_buffer[dll_characteristics_offset..dll_characteristics_offset + 2]
                .try_into()
                .unwrap(),
        );

        if config.force_aslr {
            dll_characteristics |= 0x0040; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        }
        if config.force_high_entropy_aslr {
            dll_characteristics |= 0x0020; // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        }
        if config.force_dep {
            dll_characteristics |= 0x0100; // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        }
        if config.force_cfg {
            dll_characteristics |= 0x4000; // IMAGE_DLLCHARACTERISTICS_GUARD_CF
        }
        if config.force_integrity_check {
            dll_characteristics |= 0x0080; // IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
        }

        // Write updated mitigations
        out_buffer[dll_characteristics_offset..dll_characteristics_offset + 2]
            .copy_from_slice(&dll_characteristics.to_le_bytes());

        Ok(out_buffer)
    }

    /// Verifies if a given modified PE buffer still matches its initial integrity manifest (Anti-tamper check)
    pub fn verify_integrity(
        pe_buffer: &[u8],
        manifest: &HardeningIntegrityManifest,
    ) -> Result<bool, HardeningError> {
        let current_manifest = Self::generate_integrity_manifest(pe_buffer)?;

        // Index current sections by name for comparisons
        let mut current_sec_map = HashMap::new();
        for sec in &current_manifest.sections {
            current_sec_map.insert(&sec.name, sec);
        }

        for expected in &manifest.sections {
            // Ignore custom integrity or packer sections that we added during protective passes
            if expected.name == ".reapint" || expected.name == ".reapack" || expected.name == ".reapver" {
                continue;
            }

            if let Some(current) = current_sec_map.get(&expected.name) {
                if current.sha256_hash != expected.sha256_hash {
                    // Tampering detected!
                    return Ok(false);
                }
            } else {
                // Critical code or resource section was deleted!
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Injects an anti-tamper checker manifest into the binary as a custom protected section
    pub fn apply_hardening(
        pe_buffer: &[u8],
        config: &HardeningConfig,
    ) -> Result<Vec<u8>, HardeningError> {
        let mut buffer = Self::enforce_pe_mitigations(pe_buffer, config)?;

        if config.inject_anti_tamper {
            let manifest = Self::generate_integrity_manifest(&buffer)?;
            let manifest_bytes = serde_json::to_vec(&manifest)
                .map_err(|e| HardeningError::HardeningFailed(e.to_string()))?;

            // Inject integrity manifest as a section named ".reapint"
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reapint",
                &manifest_bytes,
                0x4000_0040, // READ initialized data
            ).map_err(|e| HardeningError::HardeningFailed(e.to_string()))?;
        }

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_manifest_generation() {
        // Simple mock PE header format (DLL characteristics)
        let mut pe_mock = vec![0u8; 512];
        pe_mock[0..2].copy_from_slice(b"MZ"); // DOS signature
        pe_mock[0x3C..0x40].copy_from_slice(&128u32.to_le_bytes()); // e_lfanew
        pe_mock[128..132].copy_from_slice(b"PE\0\0"); // PE signature
        // COFF header (20 bytes): Machine (2), Sections Count (2)
        pe_mock[132..134].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        pe_mock[134..136].copy_from_slice(&0u16.to_le_bytes()); // 0 sections

        let manifest_res = HardeningSystem::generate_integrity_manifest(&pe_mock);
        assert!(manifest_res.is_ok());
        let manifest = manifest_res.unwrap();
        assert_eq!(manifest.section_count, 0);
    }
}
