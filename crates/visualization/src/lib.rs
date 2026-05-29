use reapershield_analyzer::{calculate_entropy, PeReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionBlock {
    pub name: String,
    pub start_address: u32,
    pub size: u32,
    pub entropy: f64,
    pub size_percentage: f32,
    pub is_suspicious: bool,
    pub permission_level: String, // e.g. "RX", "RW", "RWX"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "DLL" or "Function"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGraphEdge {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGraph {
    pub nodes: Vec<ImportGraphNode>,
    pub edges: Vec<ImportGraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDistribution {
    pub readable_bytes: u64,
    pub writable_bytes: u64,
    pub executable_bytes: u64,
    pub writable_executable_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryVisuals {
    pub entropy_heatmap: Vec<f64>, // List of entropy values calculated per buffer blocks
    pub layout_blocks: Vec<SectionBlock>,
    pub import_graph: ImportGraph,
    pub permissions: PermissionDistribution,
}

pub struct VisualizationEngine;

impl ObfuscationVisuals {
    // Helper to calculate blocks
}

impl VisualizationEngine {
    /// Generates a dense entropy array by slicing binary buffer into N equal slices
    pub fn generate_entropy_heatmap(buffer: &[u8], block_count: usize) -> Vec<f64> {
        if buffer.is_empty() || block_count == 0 {
            return vec![0.0; block_count];
        }

        let chunk_size = (buffer.len() / block_count).max(1);
        let mut heatmap = Vec::with_capacity(block_count);

        for i in 0..block_count {
            let start = i * chunk_size;
            let end = ((i + 1) * chunk_size).min(buffer.len());

            if start >= buffer.len() {
                heatmap.push(0.0);
            } else {
                let slice = &buffer[start..end];
                let slice_entropy = calculate_entropy(slice);
                heatmap.push(slice_entropy);
            }
        }

        heatmap
    }

    /// Compiles structural PE metadata into highly specific chart data formats
    pub fn generate_visuals(
        buffer: &[u8],
        report: &PeReport,
    ) -> BinaryVisuals {
        // 1. Heatmap (standard 256 cells for visual charts)
        let entropy_heatmap = Self::generate_entropy_heatmap(buffer, 256);

        // 2. Section blocks
        let total_raw_size: u32 = report.sections.iter().map(|s| s.raw_data_size).sum();
        let mut layout_blocks = Vec::new();
        
        let mut rx_bytes = 0u64;
        let mut rw_bytes = 0u64;
        let mut r_bytes = 0u64;
        let mut rwx_bytes = 0u64;

        for sec in &report.sections {
            let size_percentage = if total_raw_size > 0 {
                (sec.raw_data_size as f32 / total_raw_size as f32) * 100.0
            } else {
                0.0
            };

            let permission_level = format!(
                "{}{}{}",
                if sec.is_readable { "R" } else { "" },
                if sec.is_writable { "W" } else { "" },
                if sec.is_executable { "X" } else { "" }
            );

            // Tally bytes
            let bytes = sec.raw_data_size as u64;
            if sec.is_writable && sec.is_executable {
                rwx_bytes += bytes;
            } else if sec.is_writable {
                rw_bytes += bytes;
            } else if sec.is_executable {
                rx_bytes += bytes;
            } else if sec.is_readable {
                r_bytes += bytes;
            }

            layout_blocks.push(SectionBlock {
                name: sec.name.clone(),
                start_address: sec.virtual_address,
                size: sec.raw_data_size,
                entropy: sec.entropy,
                size_percentage,
                is_suspicious: sec.is_suspicious,
                permission_level,
            });
        }

        // 3. Import graph structure
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Node for main app
        nodes.push(ImportGraphNode {
            id: "binary".to_string(),
            label: report.file_name.clone(),
            node_type: "Root".to_string(),
        });

        // Group imports by DLL to present an organized graph hierarchy
        let mut dll_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for imp in &report.imports {
            dll_map.entry(imp.dll.clone()).or_default().push(imp.function.clone());
        }

        // Add max 10 DLLs and 3 functions per DLL to keep visualization charts clutter-free and fast
        for (dll_index, (dll, funcs)) in dll_map.iter().enumerate().take(10) {
            let dll_node_id = format!("dll_{}", dll_index);
            nodes.push(ImportGraphNode {
                id: dll_node_id.clone(),
                label: dll.clone(),
                node_type: "DLL".to_string(),
            });

            edges.push(ImportGraphEdge {
                source: "binary".to_string(),
                target: dll_node_id.clone(),
            });

            for (f_idx, func) in funcs.iter().enumerate().take(3) {
                let func_node_id = format!("func_{}_{}", dll_index, f_idx);
                nodes.push(ImportGraphNode {
                    id: func_node_id.clone(),
                    label: func.clone(),
                    node_type: "Function".to_string(),
                });

                edges.push(ImportGraphEdge {
                    source: dll_node_id.clone(),
                    target: func_node_id,
                });
            }
        }

        BinaryVisuals {
            entropy_heatmap,
            layout_blocks,
            import_graph: ImportGraph { nodes, edges },
            permissions: PermissionDistribution {
                readable_bytes: r_bytes,
                writable_bytes: rw_bytes,
                executable_bytes: rx_bytes,
                writable_executable_bytes: rwx_bytes,
            },
        }
    }
}

// Dummy helper struct to fulfill any compilation traits
#[derive(Debug, Serialize, Deserialize)]
pub struct ObfuscationVisuals {
    pub symbol_coverage: f32,
    pub complexity_index: f32,
}
