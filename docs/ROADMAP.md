# ReaperShield - Product & Engineering Roadmap

This document outlines the development phases, technical objectives, and research milestones scheduled for the ReaperShield Executable Protection Platform.

---

## Phase 1: Core Platform Architecture (Completed)
- [x] Create modular Rust workspace with distinct crates for Analyzer, Obfuscation, Packers, Hardening, and Crypto.
- [x] Implement AES-256-GCM and ChaCha20-Poly1305 crypting routines.
- [x] Create section-injection mechanisms for PE modification.
- [x] Implement initial Shannon Entropy block scanning and analysis.
- [x] Configure Clap-based CLI.
- [x] Design React + TypeScript + Tailwind modern dark UI.

---

## Phase 2: Runtime Anti-Debugging & Anti-Virtualization (Q3 2026)
To elevate reverse engineering difficulty, native protection stubs will include hardware-level checks:
- **Heuristic Debug Detection**:
  - Scanning PEB (Process Environment Block) fields: `BeingDebugged`, `NtGlobalFlag`.
  - Checking hardware breakpoints (`DR0`-`DR3` registers).
  - Monitoring timing checks (`RDTSC` loop checks to spot single-stepping delays).
- **Anti-VM Audits**:
  - Searching for virtualization hardware strings (QEMU, VirtualBox, VMware).
  - Checking descriptor tables (`SIDT`, `SGDT`, `SLDT`).
  - Scanning specialized registry subkeys inside target hosts.

---

## Phase 3: Compile-Time Obfuscation (LLVM Pass) (Q4 2026)
Extend structural obfuscation from post-compile PE editing to build-time passes:
- **LLVM Optimizer Passes**:
  - Implement Control Flow Flattening (CFF) to segment block paths into switch-dispatchers.
  - Integrate instruction substitution passes (replacing standard math with cryptographically equivalent loops).
  - Automate string encrypt-on-use LLVM passes to shield credentials.

---

## Phase 4: WASM Plugin Ecosystem & Web Interop (Q1 2027)
- Integrate a WASM runtime loader (e.g. via `wasmer` or `wasmtime`) into `reapershield-plugins`.
- Permit developers to write custom heuristic scanners or payload packers in Rust/Go, compile them to WebAssembly, and load them dynamically in the CLI and GUI.
- Support cloud-hosted dashboards to pool threat-alert telemetry streams.
