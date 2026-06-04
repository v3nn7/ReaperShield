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
proc macro.

### 1. One-time toolchain check

```powershell
# Windows + MSVC + WebView2 + Node 18+
node --version
cargo --version
rustc --version
```

### 2. Build the React frontend

```powershell
cd gui
npm install        # ~180 packages, downloads once
npm run build      # Vite produces gui/dist/{index.html, assets/*}
cd ..
```

Expected output:

```
dist/index.html                   0.63 kB │ gzip:   0.40 kB
dist/assets/index--JTpZ91v.css   16.14 kB │ gzip:   3.74 kB
dist/assets/index-qdD59KSM.js    31.76 kB │ gzip:   6.98 kB
dist/assets/index-Yv7eXR5T.js   568.19 kB │ gzip: 160.91 kB
```

### 3. Stage the frontend where Tauri's macro can find it

The CLI binary's `cli/tauri.conf.json` sets `distDir: "./dist"`, so the
Vite output must be mirrored into `cli/dist/`:

```powershell
Copy-Item -Path gui\dist\* -Destination cli\dist\ -Recurse -Force
```

(Or just `xcopy /E /Y gui\dist cli\dist` if you prefer.)

### 4. Build the Rust release binary

```powershell
cargo build --release -p reapershield-cli
```

Output: `target\release\reapershield.exe` (~12 MB).

### 5. Launch

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
cd gui; npm run build; cd ..
Copy-Item -Path gui\dist\* -Destination cli\dist\ -Recurse -Force
cargo build --release -p reapershield-cli
```

### Rebuild loop (after editing Rust code)

```powershell
cargo build --release -p reapershield-cli
```

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
