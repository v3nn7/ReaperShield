use goblin::pe::PE;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    pub encrypt_strings: bool,
    pub xor_key: u8,
    pub rename_sections: bool,
    pub section_prefix: String,
    pub generate_junk_instructions: bool,
    pub junk_size: usize,
    pub diversify_layout: bool,
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
            // Randomly decide the "density" for this chunk to create variable entropy
            let entropy_mode = rng.gen_range(0..10);
            
            match entropy_mode {
                0..=3 => {
                    // VERY LOW ENTROPY: NOPs and alignment (very common in real compilers)
                    let count = rng.gen_range(1..8).min(size - junk.len());
                    junk.extend(std::iter::repeat(0x90).take(count));
                }
                4..=7 => {
                    // NATURAL ENTROPY: Common instruction patterns
                    let sub_mode = rng.gen_range(0..5);
                    match sub_mode {
                        0 => { // push/pop pairs
                            if junk.len() + 2 <= size {
                                let reg = rng.gen_range(0x50..0x58);
                                junk.push(reg);
                                junk.push(reg + 0x08);
                            }
                        }
                        1 => { // test reg, reg (very common)
                            if junk.len() + 2 <= size {
                                let reg = rng.gen_range(0xC0..0xFF);
                                junk.extend_from_slice(&[0x85, reg]);
                            }
                        }
                        2 => { // lea rax, [rax+0]
                            if junk.len() + 4 <= size {
                                junk.extend_from_slice(&[0x48, 0x8D, 0x40, 0x00]);
                            }
                        }
                        3 => { // mov rbp, rbp
                            if junk.len() + 3 <= size {
                                junk.extend_from_slice(&[0x48, 0x89, 0xED]);
                            }
                        }
                        _ => junk.push(0x90),
                    }
                }
                8..=9 => {
                    // MEDIUM ENTROPY: Small math operations
                    if junk.len() + 3 <= size {
                        let op = [0x81, 0x83][rng.gen_range(0..2)];
                        let reg = rng.gen_range(0xC0..0xC8);
                        junk.extend_from_slice(&[op, reg, 0x00]);
                    }
                _ => {
                    junk.push(0x90);
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

        // PE structures
        let e_lfanew = u32::from_le_bytes(pe_buffer[0x3C..0x40].try_into().unwrap()) as usize;
        let coff_offset = e_lfanew + 4;
        let size_of_opt_header = pe.header.coff_header.size_of_optional_header as usize;
        let section_table_offset = coff_offset + 20 + size_of_opt_header;

        let mut rng = rand::thread_rng();
        let num_sections = pe.header.coff_header.number_of_sections as usize;

        for i in 0..num_sections {
            // Find current section offset in section headers table
            let offset = section_table_offset + (i * 40);
            
            // Generate unique randomized name
            let rand_suffix: String = (&mut rng)
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect();
            let new_name = format!("{}{}", section_prefix, rand_suffix);
            
            // Format to 8-byte array
            let mut name_bytes = [0u8; 8];
            let limit = new_name.as_bytes().len().min(8);
            name_bytes[..limit].copy_from_slice(&new_name.as_bytes()[..limit]);

            // Replace section name in output buffer (Section Name is first 8 bytes of section header)
            out_buffer[offset..offset + 8].copy_from_slice(&name_bytes);
        }

        Ok(out_buffer)
    }

    /// Diversifies binary layout by injecting an obfuscated junk section.
    /// Focused on mimicking real data sections (mix of strings, pointers, and padding).
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
                    // Low entropy: Zero padding / Nulls (extremely common in .data/.rdata)
                    junk_payload.extend(std::iter::repeat(0x00).take(chunk_size));
                }
                5..=7 => {
                    // Medium entropy: Fake ASCII strings / metadata
                    let s: String = (&mut rng)
                        .sample_iter(&Alphanumeric)
                        .take(chunk_size)
                        .map(char::from)
                        .collect();
                    junk_payload.extend_from_slice(s.as_bytes());
                }
                8..=9 => {
                    // Realistic "Code/Data" mix
                    let instr = Self::generate_junk_instructions(chunk_size);
                    junk_payload.extend_from_slice(&instr);
                }
                _ => {}
            }
        }

        // Inject the randomized junk as an initialized read-only data section `.reajunk`
        let modified = reapershield_pe_engine::PeEngine::inject_section(
            pe_buffer,
            ".reajunk",
            &junk_payload,
            0x4000_0040, // READ initialized data
        ).map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;

        Ok(modified)
    }

    /// Runs all configured obfuscation strategies on the binary
    pub fn apply_obfuscation(
        pe_buffer: &[u8],
        config: &ObfuscationConfig,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();

        if config.rename_sections {
            buffer = Self::rename_pe_sections(&buffer, &config.section_prefix)?;
        }

        if config.generate_junk_instructions && config.junk_size > 0 {
            let junk = Self::generate_junk_instructions(config.junk_size);
            // Append junk instructions as an executable section `.reajunk`
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reacode",
                &junk,
                0x6000_0020, // EXECUTE | READ code section
            ).map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        if config.diversify_layout {
            buffer = Self::diversify_layout(&buffer, 1024)?;
        }

        Ok(buffer)
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
        // Ensure NOP is included
        assert!(junk.contains(&0x90));
    }
}
