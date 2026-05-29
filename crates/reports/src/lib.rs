use chrono::{DateTime, Utc};
use reapershield_analyzer::PeReport;
use reapershield_telemetry::TelemetryRecord;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization failed: {0}")]
    SerializationError(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditReport {
    pub report_id: String,
    pub created_at: DateTime<Utc>,
    pub binary_report: PeReport,
    pub telemetry_events: Vec<TelemetryRecord>,
    pub protection_applied: bool,
    pub compression_ratio: Option<f32>,
}

pub struct ReportGenerator;

impl ReportGenerator {
    /// Generates a complete serialized JSON audit file
    pub fn generate_json_report<P: AsRef<Path>>(
        report: &AuditReport,
        output_path: P,
    ) -> Result<(), ReportError> {
        let serialized = serde_json::to_string_pretty(report)
            .map_err(|e| ReportError::SerializationError(e.to_string()))?;
        let mut file = File::create(output_path)?;
        file.write_all(serialized.as_bytes())?;
        Ok(())
    }

    /// Generates a professional, responsive, enterprise-grade HTML report
    pub fn generate_html_report<P: AsRef<Path>>(
        report: &AuditReport,
        output_path: P,
    ) -> Result<(), ReportError> {
        let binary = &report.binary_report;
        let mitigations = &binary.mitigations;

        // Determine score color
        let score_color = if binary.security_score >= 80 {
            "#10b981" // green
        } else if binary.security_score >= 50 {
            "#f59e0b" // amber
        } else {
            "#ef4444" // red
        };

        // Create issues list
        let mut issues_html = String::new();
        if binary.security_issues.is_empty() {
            issues_html.push_str("<div class='item success'>✓ No critical security vulnerabilities or missing mitigations detected.</div>");
        } else {
            for issue in &binary.security_issues {
                issues_html.push_str(&format!(
                    "<div class='item danger'>⚠ {}</div>",
                    html_escape::encode_text(issue)
                ));
            }
        }

        // Create sections list
        let mut sections_html = String::new();
        for sec in &binary.sections {
            let status_badge = if sec.is_suspicious {
                "<span class='badge danger'>SUSPICIOUS</span>"
            } else {
                "<span class='badge success'>NORMAL</span>"
            };

            let permissions = format!(
                "{}{}{}",
                if sec.is_readable { "R" } else { "-" },
                if sec.is_writable { "W" } else { "-" },
                if sec.is_executable { "X" } else { "-" }
            );

            sections_html.push_str(&format!(
                "<tr>
                    <td><code>{}</code></td>
                    <td>0x{:08X}</td>
                    <td>{} bytes</td>
                    <td>{:.4}</td>
                    <td><code>{}</code></td>
                    <td>{}</td>
                </tr>",
                html_escape::encode_text(&sec.name),
                sec.virtual_address,
                sec.raw_data_size,
                sec.entropy,
                permissions,
                status_badge
            ));
        }

        // Create mitigations table
        let mitigations_html = format!(
            "<div class='mitigations-grid'>
                <div class='mit-card {}'>
                    <div class='mit-title'>DEP / NX Compatibility</div>
                    <div class='mit-val'>{}</div>
                </div>
                <div class='mit-card {}'>
                    <div class='mit-title'>ASLR Enabled</div>
                    <div class='mit-val'>{}</div>
                </div>
                <div class='mit-card {}'>
                    <div class='mit-title'>High Entropy ASLR</div>
                    <div class='mit-val'>{}</div>
                </div>
                <div class='mit-card {}'>
                    <div class='mit-title'>Control Flow Guard (CFG)</div>
                    <div class='mit-val'>{}</div>
                </div>
                <div class='mit-card {}'>
                    <div class='mit-title'>SafeSEH (Structured Exception Handling)</div>
                    <div class='mit-val'>{}</div>
                </div>
                <div class='mit-card {}'>
                    <div class='mit-title'>Stack Buffer Canary (GS)</div>
                    <div class='mit-val'>{}</div>
                </div>
            </div>",
            if mitigations.has_dep { "green" } else { "red" },
            if mitigations.has_dep { "PASS" } else { "FAIL" },
            if mitigations.has_aslr { "green" } else { "red" },
            if mitigations.has_aslr { "PASS" } else { "FAIL" },
            if mitigations.has_high_entropy_aslr { "green" } else { "red" },
            if mitigations.has_high_entropy_aslr { "PASS" } else { "FAIL" },
            if mitigations.has_cfg { "green" } else { "red" },
            if mitigations.has_cfg { "PASS" } else { "FAIL" },
            if mitigations.has_safeseh { "green" } else { "red" },
            if mitigations.has_safeseh { "PASS" } else { "FAIL" },
            if mitigations.has_gs { "green" } else { "red" },
            if mitigations.has_gs { "PASS" } else { "FAIL" }
        );

        // Create telemetry events list
        let mut telemetry_html = String::new();
        if report.telemetry_events.is_empty() {
            telemetry_html.push_str("<p class='text-muted'>No telemetry traces stored in audit session.</p>");
        } else {
            telemetry_html.push_str("<table class='table'><thead><tr><th>Time</th><th>Severity</th><th>Event Data</th></tr></thead><tbody>");
            for log in &report.telemetry_events {
                let lvl_class = match log.level {
                    reapershield_telemetry::TelemetryLevel::Info => "badge success",
                    reapershield_telemetry::TelemetryLevel::Warning => "badge warning",
                    reapershield_telemetry::TelemetryLevel::Error => "badge danger",
                    reapershield_telemetry::TelemetryLevel::Critical => "badge danger",
                    reapershield_telemetry::TelemetryLevel::Security => "badge danger",
                };
                let lvl_text = format!("{:?}", log.level);
                let event_text = format!("{:?}", log.event);

                telemetry_html.push_str(&format!(
                    "<tr>
                        <td style='white-space:nowrap;'>{}</td>
                        <td><span class='{}'>{}</span></td>
                        <td><code>{}</code></td>
                    </tr>",
                    log.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    lvl_class,
                    lvl_text,
                    html_escape::encode_text(&event_text)
                ));
            }
            telemetry_html.push_str("</tbody></table>");
        }

        let packer_status_text = if binary.packer_detected {
            format!("COMPRESSION DETECTED ({})", binary.detected_packer_name.as_ref().unwrap_or(&"Unknown".to_string()))
        } else {
            "NONE".to_string()
        };

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReaperShield Security Audit Report - {file_name}</title>
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --bg-card: #151b2c;
            --border: #232d45;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
        }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 40px;
        }}
        .brand h1 {{
            margin: 0;
            font-size: 28px;
            letter-spacing: -0.5px;
            color: var(--text-primary);
        }}
        .brand span {{
            color: var(--accent-blue);
        }}
        .brand p {{
            margin: 4px 0 0 0;
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
        }}
        .card h2 {{
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 18px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }}
        .score-box {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            text-align: center;
        }}
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 8px solid {score_color};
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            font-weight: bold;
            color: {score_color};
            margin-bottom: 15px;
        }}
        .info-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .info-table td {{
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
        }}
        .info-table td:first-child {{
            color: var(--text-secondary);
            font-weight: 500;
        }}
        .info-table td:last-child {{
            text-align: right;
            font-family: monospace;
        }}
        .mitigations-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .mit-card {{
            padding: 16px;
            border-radius: 6px;
            border-left: 4px solid #fff;
            background-color: rgba(255,255,255,0.02);
        }}
        .mit-card.green {{
            border-left-color: var(--accent-green);
            background-color: rgba(16,185,129,0.05);
        }}
        .mit-card.red {{
            border-left-color: var(--accent-red);
            background-color: rgba(239,68,68,0.05);
        }}
        .mit-title {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        .mit-val {{
            font-size: 16px;
            font-weight: bold;
        }}
        .table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        .table th, .table td {{
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }}
        .table th {{
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 13px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge.success {{
            background-color: rgba(16,185,129,0.2);
            color: var(--accent-green);
        }}
        .badge.danger {{
            background-color: rgba(239,68,68,0.2);
            color: var(--accent-red);
        }}
        .badge.warning {{
            background-color: rgba(245,158,11,0.2);
            color: var(--accent-amber);
        }}
        .issues-list .item {{
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-size: 14px;
        }}
        .issues-list .item.danger {{
            background-color: rgba(239,68,68,0.1);
            color: #f87171;
            border: 1px solid rgba(239,68,68,0.2);
        }}
        .issues-list .item.success {{
            background-color: rgba(16,185,129,0.1);
            color: #34d399;
            border: 1px solid rgba(16,185,129,0.2);
        }}
        code {{
            font-family: Consolas, Monaco, monospace;
            background-color: rgba(255,255,255,0.05);
            padding: 2px 6px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>Reaper<span>Shield</span></h1>
                <p>Enterprise Executable Protection Platform • Security Audit</p>
            </div>
            <div class="date" style="text-align: right;">
                <div style="font-weight:600;">Report: #{report_id}</div>
                <div style="color:var(--text-secondary); font-size:13px; margin-top:4px;">Generated: {report_date}</div>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <h2>Target Specifications</h2>
                <table class="info-table">
                    <tr>
                        <td>Binary File Name</td>
                        <td>{file_name}</td>
                    </tr>
                    <tr>
                        <td>File Size</td>
                        <td>{file_size} bytes</td>
                    </tr>
                    <tr>
                        <td>Architecture</td>
                        <td>{arch}</td>
                    </tr>
                    <tr>
                        <td>Image Base Address</td>
                        <td>0x{image_base:016X}</td>
                    </tr>
                    <tr>
                        <td>Entry Point Address (RVA)</td>
                        <td>0x{entry_point:08X}</td>
                    </tr>
                    <tr>
                        <td>MD5 Hash</td>
                        <td>{md5_hash}</td>
                    </tr>
                    <tr>
                        <td>SHA-256 Hash</td>
                        <td>{sha256_hash}</td>
                    </tr>
                    <tr>
                        <td>Average Entropy</td>
                        <td>{global_entropy:.4}</td>
                    </tr>
                    <tr>
                        <td>Packer Detection</td>
                        <td>{packer_status}</td>
                    </tr>
                    <tr>
                        <td>Signed Status</td>
                        <td>{signed_status}</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <div class="score-box">
                    <div class="score-circle">{security_score}</div>
                    <div style="font-weight:bold; font-size:18px; margin-bottom:5px;">Security Audit Score</div>
                    <div style="color:var(--text-secondary); font-size:13px;">Platform rating of executable defenses and mitigations</div>
                </div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 40px;">
            <h2>Security Mitigations Compliance</h2>
            {mitigations}
        </div>

        <div class="card" style="margin-bottom: 40px;">
            <h2>Identified Security Issues & Recommendations</h2>
            <div class="issues-list">
                {issues}
            </div>
        </div>

        <div class="card" style="margin-bottom: 40px;">
            <h2>Section Layout & Analysis</h2>
            <div style="overflow-x:auto;">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Section</th>
                            <th>Virtual Addr (RVA)</th>
                            <th>Raw Size</th>
                            <th>Entropy</th>
                            <th>Permissions</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sections}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <h2>Audit Telemetry Log Traces</h2>
            <div style="overflow-x:auto; max-height: 400px; overflow-y: auto;">
                {telemetry}
            </div>
        </div>
    </div>
</body>
</html>"#,
            file_name = html_escape::encode_text(&binary.file_name),
            report_id = report.report_id,
            report_date = report.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
            file_size = binary.file_size,
            arch = if binary.is_64_bit { "x86_64 (64-bit)" } else { "x86 (32-bit)" },
            image_base = binary.image_base,
            entry_point = binary.entry_point,
            md5_hash = binary.hashes.md5,
            sha256_hash = binary.hashes.sha256,
            global_entropy = binary.global_entropy,
            packer_status = packer_status_text,
            signed_status = if binary.has_digital_signature { "SIGNED (VALID)" } else { "UNSIGNED" },
            security_score = binary.security_score,
            mitigations = mitigations_html,
            issues = issues_html,
            sections = sections_html,
            telemetry = telemetry_html
        );

        let mut file = File::create(output_path)?;
        file.write_all(html.as_bytes())?;
        Ok(())
    }
}

// Simple internal module to handle minimal HTML escaping safely
mod html_escape {
    pub fn encode_text(input: &str) -> String {
        let mut s = String::new();
        for c in input.chars() {
            match c {
                '<' => s.push_str("&lt;"),
                '>' => s.push_str("&gt;"),
                '&' => s.push_str("&amp;"),
                '"' => s.push_str("&quot;"),
                '\'' => s.push_str("&#x27;"),
                _ => s.push(c),
            }
        }
        s
    }
}
