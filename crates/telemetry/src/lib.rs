use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TelemetryLevel {
    Info,
    Warning,
    Error,
    Critical,
    Security,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TelemetryEvent {
    IntegrityAlert {
        section_name: String,
        expected_hash: String,
        found_hash: String,
    },
    CrashReport {
        exception_code: u32,
        instruction_pointer: u64,
        backtrace: Vec<String>,
    },
    ExecutionTrace {
        module_name: String,
        elapsed_ms: u64,
    },
    PerformanceStat {
        cpu_usage_pct: f32,
        memory_bytes: u64,
    },
    GenericMessage {
        subsystem: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRecord {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub level: TelemetryLevel,
    pub event: TelemetryEvent,
}

pub struct TelemetryManager {
    log_path: Option<PathBuf>,
}

impl TelemetryManager {
    pub fn new<P: AsRef<Path>>(log_path: Option<P>) -> Self {
        Self {
            log_path: log_path.map(|p| p.as_ref().to_path_buf()),
        }
    }

    /// Logs an event, outputs it via standard Rust logging facade, and writes to log_path if present
    pub fn log_event(&self, level: TelemetryLevel, event: TelemetryEvent) -> TelemetryRecord {
        let record = TelemetryRecord {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level,
            event,
        };

        // Output to standard logging framework (facilitating console viewing)
        match level {
            TelemetryLevel::Info => log::info!("{:?}", record.event),
            TelemetryLevel::Warning => log::warn!("{:?}", record.event),
            TelemetryLevel::Error => log::error!("{:?}", record.event),
            TelemetryLevel::Critical => log::error!("CRITICAL: {:?}", record.event),
            TelemetryLevel::Security => log::warn!("SECURITY ALERT: {:?}", record.event),
        }

        // Save to file if configured
        if let Some(ref path) = self.log_path {
            if let Ok(serialized) = serde_json::to_string(&record) {
                if let Ok(mut file) = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .append(true)
                    .open(path)
                {
                    let _ = writeln!(file, "{}", serialized);
                }
            }
        }

        record
    }

    /// Reads logs from the telemetry file and deserializes them into a collection
    pub fn read_logs(&self) -> Result<Vec<TelemetryRecord>, std::io::Error> {
        let path = match &self.log_path {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };

        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(path)?;
        let mut records = Vec::new();

        for line in content.lines() {
            if !line.trim().is_empty() {
                if let Ok(record) = serde_json::from_str::<TelemetryRecord>(line) {
                    records.push(record);
                }
            }
        }

        Ok(records)
    }

    /// Helper to generate standard mock alert records to populate telemetry reports when empty
    pub fn generate_mock_telemetry() -> Vec<TelemetryRecord> {
        vec![
            TelemetryRecord {
                id: Uuid::new_v4(),
                timestamp: Utc::now() - chrono::Duration::hours(2),
                level: TelemetryLevel::Info,
                event: TelemetryEvent::GenericMessage {
                    subsystem: "Loader".to_string(),
                    message: "ReaperShield startup routine completed successfully.".to_string(),
                },
            },
            TelemetryRecord {
                id: Uuid::new_v4(),
                timestamp: Utc::now() - chrono::Duration::minutes(90),
                level: TelemetryLevel::Security,
                event: TelemetryEvent::IntegrityAlert {
                    section_name: ".text".to_string(),
                    expected_hash: "a4f89d3c5017e8b901a18274d75891ac3de29841".to_string(),
                    found_hash: "a4f89d3c5017e8b901a18274d75891ac3de29841".to_string(), // match = safe
                },
            },
            TelemetryRecord {
                id: Uuid::new_v4(),
                timestamp: Utc::now() - chrono::Duration::minutes(45),
                level: TelemetryLevel::Info,
                event: TelemetryEvent::ExecutionTrace {
                    module_name: "reapershield-crypto".to_string(),
                    elapsed_ms: 12,
                },
            },
            TelemetryRecord {
                id: Uuid::new_v4(),
                timestamp: Utc::now() - chrono::Duration::minutes(10),
                level: TelemetryLevel::Warning,
                event: TelemetryEvent::PerformanceStat {
                    cpu_usage_pct: 1.2,
                    memory_bytes: 4 * 1024 * 1024,
                },
            },
        ]
    }
}
