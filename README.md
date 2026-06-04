# ReaperShield

Enterprise-grade PE protection toolkit written in Rust. Analyzes, hardens,
obfuscates, encrypts and packs Windows executables — with a Tauri GUI and
CLI on top.

## Crates

| Crate           | Purpose                                                        |
| --------------- | -------------------------------------------------------------- |
| `analyzer`      | PE parsing, hashes, entropy, mitigation + suspicion scoring    |
| `pe-engine`     | Section injection, overlay, checksum, DLL chars, relocations   |
| `crypto`        | AES-GCM / ChaCha20 / XChaCha20 + Argon2id KDF + HKDF + zeroize |
| `obfuscation`   | XOR/RC4, MBA, API hashing, anti-debug, CF flattening, junk     |
| `hardening`     | Force DEP / ASLR / CFG / integrity, anti-tamper stubs          |
| `packer`        | Zstd / LZMA bundling with encrypted assets                     |
| `visualization` | Entropy heatmaps, section blocks, import graphs                |
| `telemetry`     | Runtime instrumentation logs                                   |
| `reports`       | HTML / JSON audit reports                                      |
| `evasion`       | (Windows-only) injection, hollowing, reflective loaders        |
| `cli`           | Unified `reapershield` binary (CLI + Tauri shell)              |
| `sdk`           | High-level pipeline orchestration                              |

## Build order (do this exactly, top to bottom)

The CLI binary is a Tauri app. It **embeds the React GUI at compile time**, so
the Vite build **must** run *before* the Rust release build, or the EXE will
show a blank page. The build order is fixed by Tauri's `generate_context!()`
proc macro — but `scripts\build.ps1` + `cli\build.rs` automate the whole thing.

### 1. One-time toolchain check

```powershell
# Windows + MSVC + WebView2 + Node 18+
node --version
cargo --version
rustc --version
```

### 2. Single-command build (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

That command does, in order:
1. `npm install` in `gui/` (skipped if `node_modules/` already present)
2. `npm run build` → `gui/dist/`
3. Mirrors `gui/dist/` → `cli/dist/` (where `tauri::generate_context!()` reads from)
4. `cargo build --release -p reapershield-cli`
5. `Unblock-File` on the resulting EXE (kills the Mark-of-the-Web dialog)

Output: `target\release\reapershield.exe` (~12 MB).

Flags:
- `-SkipGui` — skip the npm steps (when you only changed Rust code)
- `-Debug` — produce `target\debug\reapershield.exe` instead of release

### 3. Manual build (if you want to see each step)

```powershell
cd gui
npm install        # ~180 packages, downloads once
npm run build      # Vite produces gui/dist/{index.html, assets/*}
cd ..
Copy-Item -Path gui\dist\* -Destination cli\dist\ -Recurse -Force
cargo build --release -p reapershield-cli
Unblock-File target\release\reapershield.exe
```

### 4. Launch

```powershell
.\target\release\reapershield.exe
```

No arguments → GUI mode (loads the embedded React app).
With subcommands → CLI mode:

```powershell
.\target\release\reapershield.exe --help
.\target\release\reapershield.exe analyze --file path\to\target.exe
.\target\release\reapershield.exe protect --file target.exe --output out.exe
.\target\release\reapershield.exe gui
```

### Rebuild loop (after editing React code)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

### Rebuild loop (after editing Rust code)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipGui
```

The `cli\build.rs` also auto-detects when `gui/dist` is newer than
`cli/dist` and re-stages it during a plain `cargo build`, so even the
manual loop stays sane.

### Sign the output (built into the pipeline)

The signer lives in `sdk\src\signer.rs` and is wired into the protection
pipeline as the very last step (step 5b, right after the file is written
and before the post-protection analysis report is generated).

```powershell
# Standalone - sign any EXE
.\reapershield.exe sign path\to\binary.exe

# As the last step of the protection pipeline
.\reapershield.exe protect target.exe --output out.exe --sign

# Auto-elevate, add cert to LocalMachine\TrustedPublisher, then run the
# full pipeline in one command (kills the SmartScreen dialog permanently
# for this machine)
powershell -ExecutionPolicy Bypass -File scripts\protect-and-trust.ps1 `
    -Input target.exe `
    -Output target_protected.exe
```

What the auto-signer does:
1. Finds (or generates, on first run) a self-signed SHA-256 code-signing
   cert in `CurrentUser\My` (5-year validity, RSA-2048).
2. Locates `signtool.exe` from the Windows SDK, or falls back to
   `Set-AuthenticodeSignature` via PowerShell.
3. Stamps an RFC 3161 timestamp (`timestamp.digicert.com` by default).
4. If `--trust` is passed, copies the cert to `LocalMachine\TrustedPublisher`
   (requires admin via the auto-elevating wrapper script).

The signer result (thumbprint, signer subject, timestamp, trust status) is
returned to the GUI in `ProtectionSummary.sign_status` and shown in the
"After" panel.

For public distribution replace the self-signed cert with a real EV
code-signing cert from DigiCert, Sectigo, etc.

### Tests

```powershell
cargo test -p reapershield-crypto
cargo test -p reapershield-pe-engine
cargo test -p reapershield-obfuscation
```

## Dev mode (hot reload, recommended for GUI work)

```powershell
# Terminal 1 — Vite dev server on http://localhost:1420
cd gui
npm run dev

# Terminal 2 — Rust binary in dev mode (reads from Vite, hot reload)
cargo run -p reapershield-cli
```

Tauri picks up the `devPath: "http://localhost:1420"` URL on dev builds, so
edits to `gui/src/**` hot-reload without rebuilding Rust.

## Troubleshooting

| Symptom                                              | Fix                                                                                  |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| EXE opens to a blank page                            | You skipped step 2 or 3 — re-run `npm run build` and `Copy-Item` into `cli/dist/`   |
| `proc macro panicked: distDir not found`             | `cli/dist/index.html` is missing — copy from `gui/dist/`                              |
| WebView2 loader error on first run                   | Install [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) |
| "This app can't run on your PC" / SmartScreen dialog  | The Mark-of-the-Web inherited from the cargo workspace path. Quick fix: `Unblock-File "target\release\reapershield.exe"`. Or run `powershell -ExecutionPolicy Bypass -File scripts\sign.ps1` (add `-Sign` for a self-signed cert + auto-elevation). For public distribution a real EV cert is still required. |
| `error[E0063]: missing fields api_hash_algorithm`    | Stale Rust code — `cargo clean -p reapershield-cli && cargo build --release`         |
| GUI shows "ReaperShield CLI" placeholder             | You're running the wrong binary, or `cli/dist/` was not refreshed                     |

## Project layout

```
ReaperShield/
├── crates/                 # library crates (workspace members)
│   ├── analyzer/
│   ├── crypto/
│   ├── evasion/
│   ├── hardening/
│   ├── obfuscation/
│   ├── packer/
│   ├── pe-engine/
│   ├── reports/
│   ├── telemetry/
│   └── visualization/
├── sdk/                    # high-level pipeline
├── cli/                    # reapershield.exe (Tauri shell + clap subcommands)
│   └── dist/               # embedded React build (mirror of gui/dist/)
├── gui/                    # Vite + React + Tailwind frontend
│   ├── src/App.tsx
│   └── src-tauri/          # (legacy alt Tauri shell — keep for reference)
├── Cargo.toml              # workspace root
└── README.md
```

## Security note

ReaperShield is intended for **legitimate software protection** of binaries
you own or are authorized to harden. The evasion primitives are gated to
Windows targets and intended for red-team and EDR-research scenarios under
explicit authorization.
