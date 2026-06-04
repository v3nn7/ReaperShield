use std::path::Path;
use std::time::SystemTime;

fn main() {
    // Auto-stage the Vite build into ./dist so `cargo build` works without a
    // manual `npm run build` + `Copy-Item` step. Skips silently if Node/npm
    // or the gui/ directory is missing (developer might be working on a
    // checkout without the frontend, e.g. backend-only change).
    println!("cargo:rerun-if-changed=../gui/src");
    println!("cargo:rerun-if-changed=../gui/index.html");
    println!("cargo:rerun-if-changed=../gui/package.json");
    println!("cargo:rerun-if-changed=../dist");

    let gui_dist = Path::new("../gui/dist");
    let cli_dist = Path::new("dist");
    let index_html = cli_dist.join("index.html");

    let needs_stage = match (gui_dist.exists(), index_html.exists()) {
        (true, true) => {
            // Both present — stage only if gui/dist is newer than cli/dist.
            let gui_mtime = std::fs::metadata(gui_dist.join("index.html"))
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            let cli_mtime = std::fs::metadata(&index_html)
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            gui_mtime > cli_mtime
        }
        (true, false) => true,  // gui built, cli not yet mirrored
        (false, _) => false,    // no frontend at all — skip
    };

    if needs_stage {
        // Try to find npm. If absent, do nothing (caller will see a clearer
        // error from generate_context!() than if we hard-failed here).
        if let Ok(_) = std::process::Command::new("npm").arg("--version").output() {
            eprintln!("build.rs: staging gui/dist → cli/dist (vite build if needed)");
            // Run npm run build only if gui/dist is missing
            if !gui_dist.exists() {
                let _ = std::process::Command::new("npm")
                    .args(["run", "build"])
                    .current_dir("../gui")
                    .status();
            }
            // Mirror
            let _ = std::fs::remove_dir_all(cli_dist);
            std::fs::create_dir_all(cli_dist).ok();
            copy_dir_recursive(gui_dist, cli_dist);
        } else {
            eprintln!("build.rs: npm not found, skipping GUI staging");
        }
    }

    tauri_build::build()
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if from.is_dir() {
                std::fs::create_dir_all(&to).ok();
                copy_dir_recursive(&from, &to);
            } else {
                let _ = std::fs::copy(&from, &to);
            }
        }
    }
}
