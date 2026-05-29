use goblin::pe::PE;
use rand::Rng;
use serde::{Deserialize, Serialize};
use super::ObfuscationError;

/// String encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEncryptionConfig {
    pub encrypt_ascii: bool,
    pub encrypt_unicode: bool,
    pub min_string_length: usize,
    pub runtime_decrypt: bool,
    pub xor_key_rotation: bool,
}

impl Default for StringEncryptionConfig {
    fn default() -> Self {
        Self {
            encrypt_ascii: true,
            encrypt_unicode: true,
            min_string_length: 4,
            runtime_decrypt: true,
            xor_key_rotation: true,
        }
    }
}

pub struct StringEncryptor;

impl StringEncryptor {
    /// Encrypts a string with XOR and generates the decryption key
    fn encrypt_string(data: &[u8], key: u8) -> (Vec<u8>, u8) {
        let encrypted: Vec<u8> = data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key.wrapping_add(i as u8))
            .collect();
        (encrypted, key)
    }

    /// Generates a runtime decrypt routine for a specific string
    fn generate_decrypt_routine(
        encrypted_data: &[u8],
        key: u8,
        rva_offset: u32,
    ) -> Vec<u8> {
        let mut code = Vec::new();

        // Save registers
        code.extend_from_slice(&[0x50]); // push rax
        code.extend_from_slice(&[0x51]); // push rcx
        code.extend_from_slice(&[0x52]); // push rdx

        // Load pointer to encrypted string
        // lea rdi, [rip+offset] (points to encrypted data)
        code.extend_from_slice(&[0x48, 0x8D, 0x3D]);
        code.extend_from_slice(&rva_offset.to_le_bytes());

        // mov ecx, length
        code.extend_from_slice(&[0xB9]);
        code.extend_from_slice(&(encrypted_data.len() as u32).to_le_bytes());

        // mov al, key
        code.extend_from_slice(&[0xB0, key]);

        // decrypt_loop:
        // xor byte [rdi], al
        code.extend_from_slice(&[0x30, 0x07]);
        // inc al (key rotation)
        code.extend_from_slice(&[0xFE, 0xC0]);
        // inc rdi
        code.extend_from_slice(&[0x48, 0xFF, 0xC7]);
        // dec ecx
        code.extend_from_slice(&[0xFF, 0xC9]);
        // jnz decrypt_loop
        code.extend_from_slice(&[0x75, 0xF8]); // jump back 8 bytes

        // Restore registers
        code.extend_from_slice(&[0x5A]); // pop rdx
        code.extend_from_slice(&[0x59]); // pop rcx
        code.extend_from_slice(&[0x58]); // pop rax

        code
    }

    /// Generates a more complex decrypt routine with multiple layers
    fn generate_advanced_decrypt_routine(
        encrypted_data: &[u8],
        base_key: u8,
    ) -> Vec<u8> {
        let mut code = Vec::new();
        let mut rng = rand::thread_rng();

        // Anti-disassembly: insert junk before real code
        code.extend_from_slice(&[0x90, 0x90, 0x90]); // nops

        // Save more registers for complex decryption
        code.extend_from_slice(&[0x50, 0x51, 0x52, 0x53, 0x56, 0x57]); // push rax- rdi

        // xor ecx, ecx (counter)
        code.extend_from_slice(&[0x31, 0xC9]);

        // mov rsi, <address of encrypted data> (will be patched)
        code.extend_from_slice(&[0x48, 0xBE]);
        let fake_addr = rng.gen::<u64>();
        code.extend_from_slice(&fake_addr.to_le_bytes());

        // mov edx, length
        code.extend_from_slice(&[0xBA]);
        code.extend_from_slice(&(encrypted_data.len() as u32).to_le_bytes());

        // mov al, base_key
        code.extend_from_slice(&[0xB0, base_key]);

        // decrypt_loop:
        // mov bl, [rsi + rcx]
        code.extend_from_slice(&[0x8A, 0x1C, 0x0E]);
        // xor bl, al
        code.extend_from_slice(&[0x30, 0xC3]);
        // mov [rsi + rcx], bl
        code.extend_from_slice(&[0x88, 0x1C, 0x0E]);
        // add al, cl (key rotation with counter)
        code.extend_from_slice(&[0x00, 0xC8]);
        // inc rcx
        code.extend_from_slice(&[0x48, 0xFF, 0xC1]);
        // cmp rcx, rdx
        code.extend_from_slice(&[0x48, 0x39, 0xD1]);
        // jl decrypt_loop
        code.extend_from_slice(&[0x7C, 0xF4]); // jump back 12 bytes

        // Restore
        code.extend_from_slice(&[0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58]); // pop rdi- rax

        code
    }

    /// Scans code sections for ASCII/Unicode strings and XOR-encrypts them in place.
    /// No new sections injected - purely in-place transformation.
    pub fn encrypt_code_strings(
        pe_buffer: &[u8],
        base_key: u8,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut buffer = pe_buffer.to_vec();
        let mut rng = rand::thread_rng();
        let mut encrypted_count = 0;

        for section in pe.sections {
            let name = String::from_utf8_lossy(&section.name).to_string();

            // Only process code and read-only data sections
            if !name.contains("text") && !name.contains("code") && !name.contains("rdata") {
                continue;
            }

            let section_start = section.pointer_to_raw_data as usize;
            let section_size = section.size_of_raw_data as usize;
            let section_end = section_start + section_size;

            if section_end > buffer.len() {
                continue;
            }

            let section_data = &buffer[section_start..section_end];

            // Find ASCII strings
            let strings = Self::find_strings(section_data, 6);

            for (offset, string_data) in strings {
                if string_data.len() < 6 || encrypted_count >= 32 {
                    continue;
                }

                let key = base_key.wrapping_add(rng.gen_range(1..255));
                let (encrypted, _) = Self::encrypt_string(&string_data, key);

                // XOR encrypt in place
                if section_start + offset + encrypted.len() <= buffer.len() {
                    buffer[section_start + offset..section_start + offset + encrypted.len()]
                        .copy_from_slice(&encrypted);
                    encrypted_count += 1;
                }
            }
        }

        Ok(buffer)
    }

    /// Finds printable ASCII strings in data
    fn find_strings(data: &[u8], min_length: usize) -> Vec<(usize, Vec<u8>)> {
        let mut strings = Vec::new();
        let mut current_start = None;
        let mut current_string = Vec::new();

        for (i, &byte) in data.iter().enumerate() {
            if byte >= 0x20 && byte < 0x7F {
                if current_start.is_none() {
                    current_start = Some(i);
                }
                current_string.push(byte);
            } else {
                if let Some(_start) = current_start {
                    if current_string.len() >= min_length {
                        strings.push((_start, current_string.clone()));
                    }
                }
                current_start = None;
                current_string.clear();
            }
        }

        // Handle string at end of data
        if let Some(_start) = current_start {
            if current_string.len() >= min_length {
                strings.push((_start, current_string));
            }
        }

        strings
    }

    /// Generates a string decryption table with all encrypted strings
    pub fn generate_string_table(
        strings: &[(Vec<u8>, u8)], // (encrypted_data, key)
    ) -> Vec<u8> {
        let mut table = Vec::new();

        // Table header: number of strings
        table.extend_from_slice(&(strings.len() as u32).to_le_bytes());

        for (encrypted, key) in strings {
            // Length of encrypted data
            table.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
            // Key
            table.push(*key);
            // Encrypted data
            table.extend_from_slice(encrypted);
        }

        table
    }

    /// Generates bulk string encryption for multiple strings
    pub fn encrypt_bulk_strings(
        strings: &[&[u8]],
        base_key: u8,
    ) -> (Vec<(Vec<u8>, u8)>, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut encrypted_strings = Vec::new();
        let mut decrypt_routines = Vec::new();

        for string in strings {
            let key = base_key.wrapping_add(rng.gen_range(0..255));
            let (encrypted, _) = Self::encrypt_string(string, key);
            encrypted_strings.push((encrypted.clone(), key));

            let routine = Self::generate_advanced_decrypt_routine(&encrypted, key);
            decrypt_routines.extend_from_slice(&routine);
        }

        (encrypted_strings, decrypt_routines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_encryption_roundtrip() {
        let test_string = b"Hello, World!";
        let key = 0x42;
        let (encrypted, _) = StringEncryptor::encrypt_string(test_string, key);

        // Verify encrypted is different from original
        assert_ne!(test_string.as_slice(), encrypted.as_slice());

        // Decrypt manually
        let decrypted: Vec<u8> = encrypted
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key.wrapping_add(i as u8))
            .collect();

        assert_eq!(test_string.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_find_strings() {
        let data = b"\x00\x00Hello\x00\x00World\x00\x00";
        let strings = StringEncryptor::find_strings(data, 3);
        assert!(strings.len() >= 2);
    }

    #[test]
    fn test_decrypt_routine() {
        let encrypted = vec![0x12, 0x34, 0x56, 0x78];
        let routine = StringEncryptor::generate_decrypt_routine(&encrypted, 0xAA, 0x1000);
        assert!(!routine.is_empty());
        // Should contain xor instruction
        assert!(routine.windows(2).any(|w| w == [0x30, 0x07]));
    }

    #[test]
    fn test_string_table() {
        let strings = vec![
            (vec![0x12, 0x34], 0xAA),
            (vec![0x56, 0x78, 0x9A], 0xBB),
        ];
        let table = StringEncryptor::generate_string_table(&strings);
        assert!(!table.is_empty());
        // Should start with count
        assert_eq!(&table[0..4], &2u32.to_le_bytes());
    }
}
