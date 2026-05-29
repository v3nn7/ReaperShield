# ReaperShield - Build & Deployment Instructions

This guide walks you through compiling the Rust workspace, building the command line utility, and launching the native desktop application.

---

## 1. Prerequisites

Ensure you have the following installed on your machine:

- **Rust (Stable)**: Ensure you have `rustc` and `cargo` installed (v1.70+ recommended). Check with:
  ```bash
  rustc --version
  ```
- **Node.js & npm**: Required to build the React frontend and hot-reload. Check with:
  ```bash
  node --version
  ```
- **Platform Development Kits**:
  - **Windows**: Build Tools for Visual Studio 2022 (C++ desktop development workload).
  - **Linux**: Standard libraries (`libsoup-3`, `webkit2gtk-4.1` or equivalent depending on your distro).

---

## 2. Compiling the Rust Workspace

ReaperShield uses a modular cargo workspace. To compile all libraries, the SDK, and the CLI binary in release mode:

```bash
cargo build --release
```

This generates:
- The `reapershield` CLI tool in `./target/release/reapershield.exe` (or `reapershield` on Linux).

---

## 3. Running the CLI Tool

Verify the CLI is fully operational by requesting an analysis of itself:

```bash
# Analyze a target executable
./target/release/reapershield analyze ./target/release/reapershield.exe

# Apply automated pipeline protection
./target/release/reapershield protect ./target/release/reapershield.exe --output ./target/release/reapershield_secured.exe

# Scramble PE sections and inject x86 CPU junk code
./target/release/reapershield obfuscate ./target/release/reapershield.exe --prefix .shld --junk-size 1024
```

---

## 4. Running the Desktop Application

The GUI is powered by Tauri (Rust Backend + React Frontend). Follow these steps to start development:

### Step 4.1: Install Frontend Dependencies
Navigate to the `gui/` folder and install NPM packages:
```bash
# Navigate to GUI folder
cd gui

# Install packages
npm install
```

### Step 4.2: Run in Development Mode
Launch the live hot-reloading development shell:
```bash
npm run tauri dev
```

### Step 4.3: Compile the Desktop Installer
To package the final, production-ready installer (standalone EXE and MSI):
```bash
npm run tauri build
```
This outputs compiled installers to `./gui/src-tauri/target/release/bundle/msi/`.

---

## 5. Security Integration Rules

The generated HTML interactive audits and JSON metadata reports are written directly to the target output directory. This is useful for build auditing, DevOps logging, and verifying mitigation metrics inside CI pipelines.
