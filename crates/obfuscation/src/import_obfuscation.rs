use goblin::pe::PE;
use rand::Rng;
use serde::{Deserialize, Serialize};
use super::ObfuscationError;

/// Import obfuscation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportObfuscationConfig {
    pub redirect_thunks: bool,
    pub add_fake_imports: bool,
    pub shuffle_import_order: bool,
    pub obfuscate_dll_names: bool,
}

impl Default for ImportObfuscationConfig {
    fn default() -> Self {
        Self {
            redirect_thunks: true,
            add_fake_imports: true,
            shuffle_import_order: true,
            obfuscate_dll_names: true,
        }
    }
}

/// Fake DLL names that look legitimate but are controlled by us
const FAKE_DLLS: &[&str] = &[
    "api-ms-win-core-heap-l1-1-0.dll",
    "api-ms-win-core-registry-l1-1-0.dll",
    "api-ms-win-core-processthreads-l1-1-0.dll",
    "api-ms-win-core-synch-l1-2-0.dll",
    "api-ms-win-core-file-l1-2-0.dll",
    "api-ms-win-core-memory-l1-1-0.dll",
];

/// Fake function names that appear in import table
const FAKE_FUNCTIONS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "RtlInitUnicodeString",
    "RtlAllocateHeap",
    "RtlFreeHeap",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
];

pub struct ImportObfuscator;

impl ImportObfuscator {
    /// Generates fake import descriptor entries
    fn generate_fake_imports(count: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut fake_imports = Vec::new();

        for _ in 0..count {
            let _dll_name = FAKE_DLLS[rng.gen_range(0..FAKE_DLLS.len())];
            let func_name = FAKE_FUNCTIONS[rng.gen_range(0..FAKE_FUNCTIONS.len())];

            // Create a fake IMAGE_IMPORT_DESCRIPTOR (20 bytes)
            let mut descriptor = [0u8; 20];

            // OriginalFirstThunk (RVA to INT) - random fake RVA
            let fake_rva: u32 = rng.gen_range(0x1000..0x10000);
            descriptor[0..4].copy_from_slice(&fake_rva.to_le_bytes());

            // TimeDateStamp
            descriptor[4..8].copy_from_slice(&rng.gen::<[u8; 4]>());

            // ForwarderChain
            descriptor[8..12].copy_from_slice(&rng.gen::<[u8; 4]>());

            // Name (RVA to DLL name string)
            let name_rva: u32 = rng.gen_range(0x1000..0x10000);
            descriptor[12..16].copy_from_slice(&name_rva.to_le_bytes());

            // FirstThunk (RVA to IAT)
            let iat_rva: u32 = rng.gen_range(0x1000..0x10000);
            descriptor[16..20].copy_from_slice(&iat_rva.to_le_bytes());

            fake_imports.extend_from_slice(&descriptor);

            // Add a fake Hint/Name entry (2 byte hint + name)
            let hint = rng.gen::<u16>().to_le_bytes();
            fake_imports.extend_from_slice(&hint);
            fake_imports.extend_from_slice(func_name.as_bytes());
            fake_imports.push(0); // null terminator
        }

        // Add null terminator descriptor
        fake_imports.extend_from_slice(&[0u8; 20]);

        fake_imports
    }

    /// Generates IAT (Import Address Table) entries with opaque pointers
    fn generate_fake_iat_entries(count: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut iat = Vec::new();

        for _ in 0..count {
            // Each IAT entry is 8 bytes (64-bit) or 4 bytes (32-bit)
            // Using 64-bit entries with fake RVAs
            let entry: u64 = rng.gen_range(0x1000..0x100000);
            iat.extend_from_slice(&entry.to_le_bytes());
        }

        // Null terminator
        iat.extend_from_slice(&[0u8; 8]);

        iat
    }

    /// Creates a thunk redirect stub that jumps through IAT
    fn generate_thunk_redirect(original_rva: u32) -> Vec<u8> {
        let mut code = Vec::new();

        // Save registers
        code.extend_from_slice(&[0x50]); // push rax

        // Load IAT entry address
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        code.extend_from_slice(&original_rva.to_le_bytes());
        code.extend_from_slice(&[0x00, 0x00, 0x00]); // pad to 8 bytes

        // Dereference and jump
        code.extend_from_slice(&[0xFF, 0x20]); // jmp [rax]

        // Restore (dead code)
        code.extend_from_slice(&[0x58]); // pop rax

        code
    }

    /// Injects fake import table data into PE
    pub fn obfuscate_imports(pe_buffer: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut buffer = pe_buffer.to_vec();
        let mut rng = rand::thread_rng();

        // Count real imports
        let real_import_count = pe.imports.len();

        // Generate fake imports to dilute the real ones
        let fake_count = (real_import_count * 2).max(4).min(12);
        let fake_imports = Self::generate_fake_imports(fake_count);

        // Combine fake imports + IAT + thunk stubs into ONE section
        let mut combined = fake_imports;
        let fake_iat = Self::generate_fake_iat_entries(fake_count * 2);
        combined.extend_from_slice(&fake_iat);

        let mut thunk_stubs = Vec::new();
        for _ in 0..4 {
            let fake_rva: u32 = rng.gen_range(0x1000..0x10000);
            thunk_stubs.extend_from_slice(&Self::generate_thunk_redirect(fake_rva));
        }
        combined.extend_from_slice(&thunk_stubs);

        buffer = reapershield_pe_engine::PeEngine::inject_section(
            &buffer,
            ".reaimp",
            &combined,
            0x6000_0040, // EXECUTE | READ | INITIALIZED_DATA
        )
        .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;

        Ok(buffer)
    }

    /// Generates a complete fake import directory
    pub fn generate_fake_import_directory() -> Vec<u8> {
        let mut dir = Vec::new();

        // IMAGE_DIRECTORY_ENTRY_IMPORT (index 1)
        // We create a minimal valid directory entry
        dir.extend_from_slice(&[0u8; 8]); // Import table RVA and size

        // IMAGE_DIRECTORY_ENTRY_IAT (index 12)
        dir.extend_from_slice(&[0u8; 8]); // IAT RVA and size

        dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_imports() {
        let imports = ImportObfuscator::generate_fake_imports(5);
        assert!(!imports.is_empty());
        // Should have 5 descriptors (20 bytes each) + null terminator + hints/names
        assert!(imports.len() >= 5 * 20 + 20);
    }

    #[test]
    fn test_fake_iat() {
        let iat = ImportObfuscator::generate_fake_iat_entries(10);
        assert!(!iat.is_empty());
        // 10 entries * 8 bytes + null terminator
        assert!(iat.len() >= 10 * 8 + 8);
    }

    #[test]
    fn test_thunk_redirect() {
        let stub = ImportObfuscator::generate_thunk_redirect(0x1234);
        assert!(!stub.is_empty());
        // Should contain jmp instruction
        assert!(stub.windows(2).any(|w| w == [0xFF, 0x20]));
    }
}
