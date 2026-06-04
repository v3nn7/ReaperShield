//! API hashing utilities for import obfuscation.
//!
//! Instead of leaving raw `LoadLibraryA` / `GetProcAddress` style strings in
//! the binary, ReaperShield can replace them with compile-time hashes that
//! the runtime resolves by walking the export table of each loaded module.
//! Multiple hash algorithms are supported so different campaigns can use
//! distinct fingerprints.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApiHashAlgorithm {
    /// Daniel J. Bernstein's `times-33` hash (`hash = hash * 33 + c`).
    Djb2,
    /// XOR variant of djb2 (`hash = hash * 33 ^ c`).
    Djb2Xor,
    /// FNV-1a 32-bit.
    Fnv1a32,
    /// 32-bit CRC32 (poly 0xEDB88320, IEEE / zlib).
    Crc32,
    /// 32-bit ROR-13 (NTAPI-style; popular shellcode hash).
    Ror13,
}

impl ApiHashAlgorithm {
    pub fn hash(&self, data: &[u8]) -> u32 {
        match self {
            ApiHashAlgorithm::Djb2 => {
                let mut h: u32 = 5381;
                for &c in data {
                    h = h.wrapping_mul(33).wrapping_add(c as u32);
                }
                h
            }
            ApiHashAlgorithm::Djb2Xor => {
                let mut h: u32 = 5381;
                for &c in data {
                    h = h.wrapping_mul(33) ^ (c as u32);
                }
                h
            }
            ApiHashAlgorithm::Fnv1a32 => {
                let mut h: u32 = 0x811C_9DC5;
                for &c in data {
                    h ^= c as u32;
                    h = h.wrapping_mul(0x0100_0193);
                }
                h
            }
            ApiHashAlgorithm::Crc32 => crc32_ieee(data),
            ApiHashAlgorithm::Ror13 => {
                let mut h: u32 = 0;
                for &c in data {
                    h = h.rotate_right(13).wrapping_add(c as u32);
                }
                h
            }
        }
    }
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        let mut x = (crc ^ b as u32) & 0xFF;
        for _ in 0..8 {
            x = if x & 1 != 0 {
                (x >> 1) ^ 0xEDB8_8320
            } else {
                x >> 1
            };
        }
        crc = (crc >> 8) ^ x;
    }
    !crc
}

/// One pre-computed entry in the API hash table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashedApi {
    pub dll: String,
    pub function: String,
    pub dll_hash: u32,
    pub function_hash: u32,
}

/// Build a lookup table of hashed `(dll, function)` pairs.
pub fn build_hash_table(
    pairs: &[(&str, &str)],
    algo: ApiHashAlgorithm,
) -> Vec<HashedApi> {
    pairs
        .iter()
        .map(|(dll, func)| HashedApi {
            dll: (*dll).to_string(),
            function: (*func).to_string(),
            dll_hash: algo.hash(dll.to_uppercase().as_bytes()),
            function_hash: algo.hash(func.as_bytes()),
        })
        .collect()
}

/// Serialize a hash table to a compact little-endian binary layout suitable
/// for embedding into a `.reahash` section.
///
/// Layout: `u32 entry_count` then for each entry: `u32 dll_hash | u32 fn_hash`.
pub fn serialize_hash_table(table: &[HashedApi]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + table.len() * 8);
    out.extend_from_slice(&(table.len() as u32).to_le_bytes());
    for e in table {
        out.extend_from_slice(&e.dll_hash.to_le_bytes());
        out.extend_from_slice(&e.function_hash.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn djb2_consistent_and_distinguishing() {
        let a = ApiHashAlgorithm::Djb2.hash(b"hello");
        let b = ApiHashAlgorithm::Djb2.hash(b"hello");
        let c = ApiHashAlgorithm::Djb2.hash(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Empty string must equal the offset basis (5381).
        assert_eq!(ApiHashAlgorithm::Djb2.hash(b""), 5381);
    }

    #[test]
    fn fnv1a_known_vector() {
        // fnv1a-32("") = 0x811C9DC5 (offset basis)
        assert_eq!(ApiHashAlgorithm::Fnv1a32.hash(b""), 0x811C_9DC5);
    }

    #[test]
    fn crc32_known_vector() {
        // CRC32("123456789") = 0xCBF43926
        assert_eq!(ApiHashAlgorithm::Crc32.hash(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn ror13_known_vector() {
        // Verify ror13 hash isn't trivially zero / equal across inputs.
        let a = ApiHashAlgorithm::Ror13.hash(b"LoadLibraryA");
        let b = ApiHashAlgorithm::Ror13.hash(b"GetProcAddress");
        assert_ne!(a, b);
        assert_ne!(a, 0);
    }

    #[test]
    fn hash_table_serializes() {
        let table = build_hash_table(
            &[("kernel32.dll", "LoadLibraryA"), ("ntdll.dll", "NtClose")],
            ApiHashAlgorithm::Djb2Xor,
        );
        let bytes = serialize_hash_table(&table);
        // 4 byte count + 2 entries * 8 bytes = 20
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[..4], &2u32.to_le_bytes());
    }

    #[test]
    fn different_algorithms_produce_different_hashes() {
        let input = b"GetProcAddress";
        let a = ApiHashAlgorithm::Djb2.hash(input);
        let b = ApiHashAlgorithm::Djb2Xor.hash(input);
        let c = ApiHashAlgorithm::Fnv1a32.hash(input);
        let d = ApiHashAlgorithm::Crc32.hash(input);
        let e = ApiHashAlgorithm::Ror13.hash(input);
        let set: std::collections::HashSet<u32> = [a, b, c, d, e].iter().copied().collect();
        assert_eq!(set.len(), 5);
    }
}
