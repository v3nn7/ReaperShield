use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use super::ObfuscationError;

/// Anti-debug technique configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugConfig {
    pub peb_checks: bool,
    pub hardware_breakpoint_detection: bool,
    pub timing_checks: bool,
    pub exception_handling: bool,
    pub parent_process_check: bool,
    pub environment_checks: bool,
}

impl Default for AntiDebugConfig {
    fn default() -> Self {
        Self {
            peb_checks: true,
            hardware_breakpoint_detection: true,
            timing_checks: true,
            exception_handling: true,
            parent_process_check: true,
            environment_checks: true,
        }
    }
}

pub struct AntiDebugInjector;

impl AntiDebugInjector {
    /// Generates PEB (Process Environment Block) debugger detection code
    /// Checks the BeingDebugged flag and NtGlobalFlag
    fn generate_peb_check() -> Vec<u8> {
        let mut code = Vec::new();

        // Check BeingDebugged flag in PEB
        // mov rax, gs:[0x60] (PEB pointer in x64)
        code.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        // movzx eax, byte [rax+2] (BeingDebugged flag)
        code.extend_from_slice(&[0x0F, 0xB6, 0x40, 0x02]);
        // test eax, eax
        code.extend_from_slice(&[0x85, 0xC0]);
        // jnz debugger_found
        code.extend_from_slice(&[0x75, 0x14]);

        // Check NtGlobalFlag
        // mov rax, gs:[0x60]
        code.extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        // mov ecx, [rax+0xBC] (NtGlobalFlag for x64)
        code.extend_from_slice(&[0x8B, 0x88, 0xBC, 0x00, 0x00, 0x00]);
        // test ecx, 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
        code.extend_from_slice(&[0xF7, 0xC1, 0x70, 0x00, 0x00, 0x00]);
        // jnz debugger_found
        code.extend_from_slice(&[0x75, 0x02]);

        // Normal execution continues
        code.extend_from_slice(&[0x90, 0x90]); // nop nop

        // debugger_found: (termination or evasion)
        // int 3 (crash to deter debugging)
        code.extend_from_slice(&[0xCC]);

        code
    }

    /// Generates hardware breakpoint detection code
    /// Checks DR0-DR7 debug registers
    fn generate_hardware_breakpoint_check() -> Vec<u8> {
        let mut code = Vec::new();

        // mov rax, dr0 (check debug register 0)
        code.extend_from_slice(&[0x48, 0x0F, 0x21, 0xC0]);
        // test rax, rax
        code.extend_from_slice(&[0x48, 0x85, 0xC0]);
        // jnz hw_breakpoint_found
        code.extend_from_slice(&[0x75, 0x18]);

        // mov rax, dr1
        code.extend_from_slice(&[0x48, 0x0F, 0x21, 0xC8]);
        // test rax, rax
        code.extend_from_slice(&[0x48, 0x85, 0xC0]);
        // jnz hw_breakpoint_found
        code.extend_from_slice(&[0x75, 0x10]);

        // mov rax, dr3
        code.extend_from_slice(&[0x48, 0x0F, 0x21, 0xD8]);
        // test rax, rax
        code.extend_from_slice(&[0x48, 0x85, 0xC0]);
        // jnz hw_breakpoint_found
        code.extend_from_slice(&[0x75, 0x04]);

        // Normal execution
        code.extend_from_slice(&[0x90, 0x90]);

        // hw_breakpoint_found:
        code.extend_from_slice(&[0xCC]); // int 3

        code
    }

    /// Generates timing-based detection using RDTSC
    fn generate_timing_check() -> Vec<u8> {
        let mut code = Vec::new();

        // rdtsc (read time stamp counter)
        code.extend_from_slice(&[0x0F, 0x31]);
        // Store in ecx:edx
        code.extend_from_slice(&[0x89, 0xD1]); // mov ecx, edx

        // Do some work
        // xor eax, eax
        code.extend_from_slice(&[0x31, 0xC0]);
        // inc eax
        code.extend_from_slice(&[0xFF, 0xC0]);

        // rdtsc again
        code.extend_from_slice(&[0x0F, 0x31]);
        // sub edx, ecx (calculate time difference)
        code.extend_from_slice(&[0x29, 0xCA]);

        // cmp edx, 0xFFFF (if difference is too large, likely being debugged)
        code.extend_from_slice(&[0x81, 0xFA, 0xFF, 0xFF, 0x00, 0x00]);
        // jg timing_anomaly
        code.extend_from_slice(&[0x7F, 0x04]);

        // Normal
        code.extend_from_slice(&[0x90, 0x90]);

        // timing_anomaly:
        code.extend_from_slice(&[0xCC]);

        code
    }

    /// Generates exception-based anti-debug code
    fn generate_exception_check() -> Vec<u8> {
        let mut code = Vec::new();

        // Push exception handler frame
        // This is a simplified version - real implementation would use SEH

        // xor eax, eax
        code.extend_from_slice(&[0x31, 0xC0]);
        // push eax (handler = NULL)
        code.extend_from_slice(&[0x50]);
        // push fs:[0] (previous handler)
        code.extend_from_slice(&[0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00]);
        // mov fs:[0], esp (set new handler)
        code.extend_from_slice(&[0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00]);

        // int 3 (trigger exception)
        code.extend_from_slice(&[0xCC]);

        // If debugger is present, exception will be handled
        // If not, we need to clean up

        // Restore original handler
        code.extend_from_slice(&[0x64, 0x8F, 0x05, 0x00, 0x00, 0x00, 0x00]); // pop fs:[0]
        code.extend_from_slice(&[0x83, 0xC4, 0x04]); // add esp, 4

        code
    }

    /// Generates parent process name check (checks for common debugger processes)
    fn generate_parent_process_check() -> Vec<u8> {
        let mut code = Vec::new();

        // This is a stub that would call NtQueryInformationProcess
        // to get parent process name and check against known debuggers

        // mov eax, 0 ( STATUS_SUCCESS )
        code.extend_from_slice(&[0x31, 0xC0]);
        // For now, just a nop sled that would be filled with actual API calls
        for _ in 0..16 {
            code.push(0x90);
        }

        code
    }

    /// Generates environment detection code (VM, sandbox checks)
    fn generate_environment_check() -> Vec<u8> {
        let mut code = Vec::new();

        // Check for VM-specific registry keys
        // This is simplified - real version would call RegOpenKeyExA

        // xor eax, eax
        code.extend_from_slice(&[0x31, 0xC0]);
        // cmp eax, 1 (fake comparison)
        code.extend_from_slice(&[0x83, 0xF8, 0x01]);
        // je vm_detected
        code.extend_from_slice(&[0x74, 0x04]);
        // Normal
        code.extend_from_slice(&[0x90, 0x90]);
        // vm_detected:
        code.extend_from_slice(&[0xCC]);

        code
    }

    /// Generates a comprehensive anti-debug stub with multiple techniques
    fn generate_anti_debug_stub() -> Vec<u8> {
        let mut stub = Vec::new();

        // Add all anti-debug techniques
        stub.extend_from_slice(&Self::generate_peb_check());
        stub.extend_from_slice(&Self::generate_hardware_breakpoint_check());
        stub.extend_from_slice(&Self::generate_timing_check());
        stub.extend_from_slice(&Self::generate_exception_check());
        stub.extend_from_slice(&Self::generate_parent_process_check());
        stub.extend_from_slice(&Self::generate_environment_check());

        // If all checks pass, continue execution
        // xor eax, eax
        stub.extend_from_slice(&[0x31, 0xC0]);
        // ret
        stub.extend_from_slice(&[0xC3]);

        stub
    }

    /// Injects anti-debug stubs into the PE binary (single combined section)
    pub fn inject_anti_debug(pe_buffer: &[u8]) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();

        // Combine all anti-debug techniques into ONE section
        let full_stub = Self::generate_anti_debug_stub();
        buffer = reapershield_pe_engine::PeEngine::inject_section(
            &buffer,
            ".reasec",
            &full_stub,
            0x6000_0020, // EXECUTE | READ
        )
        .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;

        Ok(buffer)
    }

    /// Generates anti-debug code for specific techniques only
    pub fn inject_specific_antidebug(
        pe_buffer: &[u8],
        config: &AntiDebugConfig,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();

        if config.peb_checks {
            let code = Self::generate_peb_check();
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reapeb",
                &code,
                0x6000_0020,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        if config.hardware_breakpoint_detection {
            let code = Self::generate_hardware_breakpoint_check();
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reahw",
                &code,
                0x6000_0020,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        if config.timing_checks {
            let code = Self::generate_timing_check();
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reartc",
                &code,
                0x6000_0020,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        if config.exception_handling {
            let code = Self::generate_exception_check();
            buffer = reapershield_pe_engine::PeEngine::inject_section(
                &buffer,
                ".reaxcp",
                &code,
                0x6000_0020,
            )
            .map_err(|e| ObfuscationError::ObfuscationFailed(e.to_string()))?;
        }

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peb_check() {
        let code = AntiDebugInjector::generate_peb_check();
        assert!(!code.is_empty());
        // Should contain int 3
        assert!(code.contains(&0xCC));
        // Should contain PEB access (gs segment)
        assert!(code.contains(&0x65));
    }

    #[test]
    fn test_hardware_breakpoint_check() {
        let code = AntiDebugInjector::generate_hardware_breakpoint_check();
        assert!(!code.is_empty());
        // Should contain debug register access
        assert!(code.windows(3).any(|w| w[0] == 0x0F && w[1] == 0x21));
    }

    #[test]
    fn test_timing_check() {
        let code = AntiDebugInjector::generate_timing_check();
        assert!(!code.is_empty());
        // Should contain rdtsc instruction
        assert!(code.windows(2).any(|w| w == [0x0F, 0x31]));
    }

    #[test]
    fn test_exception_check() {
        let code = AntiDebugInjector::generate_exception_check();
        assert!(!code.is_empty());
        // Should contain int 3
        assert!(code.contains(&0xCC));
    }

    #[test]
    fn test_full_stub() {
        let stub = AntiDebugInjector::generate_anti_debug_stub();
        assert!(!stub.is_empty());
        // Should be substantial
        assert!(stub.len() > 50);
        // Should end with ret
        assert_eq!(*stub.last().unwrap(), 0xC3);
    }
}
