use goblin::pe::PE;
use rand::Rng;
use serde::{Deserialize, Serialize};
use super::ObfuscationError;

/// Control flow obfuscation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowConfig {
    pub opaque_predicates: bool,
    pub bogus_jumps: bool,
    pub flatten_control_flow: bool,
    pub junk_blocks: usize,
}

impl Default for ControlFlowConfig {
    fn default() -> Self {
        Self {
            opaque_predicates: true,
            bogus_jumps: true,
            flatten_control_flow: false,
            junk_blocks: 16,
        }
    }
}

/// Opaque predicate types - always evaluate to a known value but hard to analyze statically
#[derive(Debug, Clone)]
enum OpaquePredicate {
    /// x * (x - 1) % 2 == 0 (always true for any integer)
    AlwaysTrue,
    /// x * x >= 0 (always true for signed integers)
    AlwaysTrueSquared,
    /// (x | 1) != 0 (always true)
    AlwaysTrueOr,
    /// (x & 0) == 0 (always true)
    AlwaysTrueAnd,
}

pub struct ControlFlowObfuscator;

impl ControlFlowObfuscator {
    /// Generates x86/x64 opaque predicate code that always evaluates to a known result
    /// but is computationally expensive for deobfuscators to resolve statically.
    fn generate_opaque_predicate(predicate: &OpaquePredicate) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut code = Vec::new();

        match predicate {
            OpaquePredicate::AlwaysTrue => {
                // mov eax, [esp] ; or any register with known value
                // test eax, eax
                // jnz +1
                // nop
                let reg_offset = rng.gen_range(0..8);
                code.extend_from_slice(&[0x48, 0x89, 0xE0 + reg_offset]); // mov rax, rsp (always non-zero)
                code.extend_from_slice(&[0x48, 0x85, 0xC0]); // test rax, rax
                code.extend_from_slice(&[0x0F, 0x85, 0x02, 0x00, 0x00, 0x00]); // jnz +2
                code.extend_from_slice(&[0x90, 0x90]); // nop nop (never reached)
            }
            OpaquePredicate::AlwaysTrueSquared => {
                // xor eax, eax
                // inc eax
                // test eax, eax
                // jz +2
                // nop nop
                code.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
                code.extend_from_slice(&[0xFF, 0xC0]); // inc eax
                code.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
                code.extend_from_slice(&[0x74, 0x02]); // jz +2
                code.extend_from_slice(&[0x90, 0x90]); // nop nop (dead code)
            }
            OpaquePredicate::AlwaysTrueOr => {
                // mov al, 0xFF
                // test al, 1
                // jz +2
                // nop nop
                code.extend_from_slice(&[0xB0, 0xFF]); // mov al, 0xFF
                code.extend_from_slice(&[0xA8, 0x01]); // test al, 1
                code.extend_from_slice(&[0x74, 0x02]); // jz +2
                code.extend_from_slice(&[0x90, 0x90]); // nop nop
            }
            OpaquePredicate::AlwaysTrueAnd => {
                // xor ecx, ecx
                // test ecx, 0
                // jnz +2
                // nop nop
                code.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx
                code.extend_from_slice(&[0xF7, 0xC1, 0x00, 0x00, 0x00, 0x00]); // test ecx, 0
                code.extend_from_slice(&[0x75, 0x02]); // jnz +2
                code.extend_from_slice(&[0x90, 0x90]); // nop nop
            }
        }

        code
    }

    /// Generates bogus conditional jump blocks that branch to dead code
    fn generate_bogus_jump_block() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut code = Vec::new();

        // Generate random comparison
        let cmp_type = rng.gen_range(0..4);
        match cmp_type {
            0 => {
                // cmp eax, 0x12345678
                code.extend_from_slice(&[0x3D]);
                code.extend_from_slice(&rng.gen::<[u8; 4]>());
            }
            1 => {
                // cmp rcx, rdx
                code.extend_from_slice(&[0x48, 0x39, 0xD1]);
            }
            2 => {
                // test eax, eax
                code.extend_from_slice(&[0x85, 0xC0]);
            }
            _ => {
                // or eax, eax
                code.extend_from_slice(&[0x09, 0xC0]);
            }
        }

        // Conditional jump over dead code (jumps are inverted - this path is never taken)
        let dead_code_size = rng.gen_range(4..16);
        let jump_offset = dead_code_size as i8;

        let cond_jump = match rng.gen_range(0..6) {
            0 => [0x74, jump_offset as u8], // je
            1 => [0x75, jump_offset as u8], // jne
            2 => [0x7C, jump_offset as u8], // jl
            3 => [0x7E, jump_offset as u8], // jle
            4 => [0x7F, jump_offset as u8], // jg
            _ => [0x7D, jump_offset as u8], // jge
        };

        code.extend_from_slice(&cond_jump);

        // Dead code block (unreachable or rarely reached)
        let dead_junk = super::ObfuscationEngine::generate_junk_instructions(dead_code_size);
        code.extend_from_slice(&dead_junk);

        // Landing pad
        code.extend_from_slice(&[0x90]); // nop

        code
    }

    /// Generates a fake indirect jump through computed address
    fn generate_fake_indirect_jump() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut code = Vec::new();

        // lea rax, [rip+0] (gets current address)
        code.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);

        // add rax, some_offset (points to next instruction)
        let offset = rng.gen_range(5..20);
        code.extend_from_slice(&[0x48, 0x83, 0xC0, offset as u8]);

        // push rax (fake return address)
        code.extend_from_slice(&[0x50]);

        // ret (jump to fake return address - actually falls through)
        code.extend_from_slice(&[0xC3]);

        // Padding nops
        for _ in 0..5 {
            code.push(0x90);
        }

        code
    }

    /// Injects opaque predicates at random positions within code sections
    fn inject_opaque_predicates(
        pe_buffer: &[u8],
        count: usize,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut buffer = pe_buffer.to_vec();
        let mut rng = rand::thread_rng();

        for section in pe.sections {
            let name = String::from_utf8_lossy(&section.name).to_string();
            if !name.contains("text") && !name.contains("code") {
                continue;
            }

            let section_start = section.pointer_to_raw_data as usize;
            let section_size = section.size_of_raw_data as usize;
            let section_end = section_start + section_size;

            if section_end > buffer.len() {
                continue;
            }

            let mut injections = Vec::new();
            for _ in 0..count {
                let predicate = match rng.gen_range(0..4) {
                    0 => OpaquePredicate::AlwaysTrue,
                    1 => OpaquePredicate::AlwaysTrueSquared,
                    2 => OpaquePredicate::AlwaysTrueOr,
                    _ => OpaquePredicate::AlwaysTrueAnd,
                };

                let code = Self::generate_opaque_predicate(&predicate);
                let offset = rng.gen_range(section_start..section_end.saturating_sub(code.len()));
                injections.push((offset, code));
            }

            // Sort by offset in reverse to avoid shifting
            injections.sort_by(|a, b| b.0.cmp(&a.0));

            for (offset, code) in injections {
                // Insert code at offset, pushing existing bytes forward
                let remaining = buffer.len() - offset;
                buffer.reserve(code.len());
                buffer.extend_from_slice(&vec![0x90; code.len()]); // Make space
                buffer.copy_within(offset..offset + remaining, offset + code.len());
                buffer[offset..offset + code.len()].copy_from_slice(&code);
            }
        }

        Ok(buffer)
    }

    /// Injects bogus jump blocks into code sections
    fn inject_bogus_jumps(
        pe_buffer: &[u8],
        count: usize,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let pe = PE::parse(pe_buffer).map_err(|e| ObfuscationError::PeParseError(e.to_string()))?;
        let mut buffer = pe_buffer.to_vec();
        let mut rng = rand::thread_rng();

        for section in pe.sections {
            let name = String::from_utf8_lossy(&section.name).to_string();
            if !name.contains("text") && !name.contains("code") {
                continue;
            }

            let section_start = section.pointer_to_raw_data as usize;
            let section_size = section.size_of_raw_data as usize;
            let section_end = section_start + section_size;

            if section_end > buffer.len() {
                continue;
            }

            let mut injections = Vec::new();
            for _ in 0..count {
                let code = if rng.gen_bool(0.3) {
                    Self::generate_fake_indirect_jump()
                } else {
                    Self::generate_bogus_jump_block()
                };

                let offset = rng.gen_range(section_start..section_end.saturating_sub(code.len()));
                injections.push((offset, code));
            }

            injections.sort_by(|a, b| b.0.cmp(&a.0));

            for (offset, code) in injections {
                let remaining = buffer.len() - offset;
                buffer.reserve(code.len());
                buffer.extend_from_slice(&vec![0x90; code.len()]);
                buffer.copy_within(offset..offset + remaining, offset + code.len());
                buffer[offset..offset + code.len()].copy_from_slice(&code);
            }
        }

        Ok(buffer)
    }

    /// Applies comprehensive control flow obfuscation
    pub fn apply_control_flow_obfuscation(
        pe_buffer: &[u8],
        opaque_predicates: bool,
        bogus_jumps: bool,
    ) -> Result<Vec<u8>, ObfuscationError> {
        let mut buffer = pe_buffer.to_vec();

        if opaque_predicates {
            buffer = Self::inject_opaque_predicates(&buffer, 8)?;
        }

        if bogus_jumps {
            buffer = Self::inject_bogus_jumps(&buffer, 6)?;
        }

        Ok(buffer)
    }

    /// Generates a full control flow flattening stub (conceptual - would need full disassembly)
    pub fn generate_flattening_stub() -> Vec<u8> {
        let mut code = Vec::new();

        // State variable in a register
        // mov ecx, 0 (initial state)
        code.extend_from_slice(&[0xB9, 0x00, 0x00, 0x00, 0x00]);

        // Dispatcher loop:
        // cmp ecx, 0
        code.extend_from_slice(&[0x83, 0xF9, 0x00]);
        // je state_0
        code.extend_from_slice(&[0x74, 0x0A]);
        // cmp ecx, 1
        code.extend_from_slice(&[0x83, 0xF9, 0x01]);
        // je state_1
        code.extend_from_slice(&[0x74, 0x14]);
        // jmp dispatcher
        code.extend_from_slice(&[0xE9, 0xF0, 0xFF, 0xFF, 0xFF]);

        // state_0: actual block 0 code
        // (real instructions would go here)
        code.extend_from_slice(&[0x90, 0x90]);
        // mov ecx, 1 (next state)
        code.extend_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
        // jmp dispatcher
        code.extend_from_slice(&[0xE9, 0xE0, 0xFF, 0xFF, 0xFF]);

        // state_1: actual block 1 code
        code.extend_from_slice(&[0x90, 0x90]);
        // mov ecx, 0 (loop back)
        code.extend_from_slice(&[0xB9, 0x00, 0x00, 0x00, 0x00]);
        // jmp dispatcher
        code.extend_from_slice(&[0xE9, 0xD0, 0xFF, 0xFF, 0xFF]);

        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_predicate_generation() {
        for predicate in [
            OpaquePredicate::AlwaysTrue,
            OpaquePredicate::AlwaysTrueSquared,
            OpaquePredicate::AlwaysTrueOr,
            OpaquePredicate::AlwaysTrueAnd,
        ] {
            let code = ControlFlowObfuscator::generate_opaque_predicate(&predicate);
            assert!(!code.is_empty());
            assert!(code.len() >= 6);
        }
    }

    #[test]
    fn test_bogus_jump_block() {
        let code = ControlFlowObfuscator::generate_bogus_jump_block();
        assert!(!code.is_empty());
        assert!(code.len() >= 4);
    }

    #[test]
    fn test_fake_indirect_jump() {
        let code = ControlFlowObfuscator::generate_fake_indirect_jump();
        assert!(!code.is_empty());
        // Should contain ret instruction
        assert!(code.contains(&0xC3));
    }

    #[test]
    fn test_flattening_stub() {
        let code = ControlFlowObfuscator::generate_flattening_stub();
        assert!(!code.is_empty());
        // Should contain comparison instructions (0x83 = cmp reg, imm8)
        assert!(code.contains(&0x83));
        // Should contain conditional jumps (0x74 = je, 0x75 = jne)
        assert!(code.windows(1).any(|w| w[0] == 0x74 || w[0] == 0x75));
    }
}
