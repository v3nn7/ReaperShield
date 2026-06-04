use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum PeEngineError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("PE parse error: {0}")]
    PeParseError(String),

    #[error("Insufficient space in PE headers to inject new section")]
    NoHeaderSpace,

    #[error("Invalid PE structure: {0}")]
    InvalidPe(String),

    #[error("Resource editing failed: {0}")]
    ResourceEditError(String),

    #[error("Section name too long (max 8 bytes): {0}")]
    SectionNameTooLong(String),

    #[error("Section not found: {0}")]
    SectionNotFound(String),

    #[error("Out of bounds access in PE buffer (offset {offset} > len {len})")]
    OutOfBounds { offset: usize, len: usize },
}

// ============================================================================
// Standard PE characteristic flags
// ============================================================================

pub mod characteristics {
    pub const SCN_CNT_CODE: u32 = 0x0000_0020;
    pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
    pub const SCN_MEM_SHARED: u32 = 0x1000_0000;
    pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    pub const SCN_MEM_READ: u32 = 0x4000_0000;
    pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

    pub const READ_ONLY_DATA: u32 = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ;
    pub const READ_WRITE_DATA: u32 = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE;
    pub const CODE_RX: u32 = SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
    pub const CODE_RWX: u32 = SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_MEM_WRITE;
}

pub mod dll_characteristics {
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const NO_ISOLATION: u16 = 0x0200;
    pub const NO_SEH: u16 = 0x0400;
    pub const NO_BIND: u16 = 0x0800;
    pub const APPCONTAINER: u16 = 0x1000;
    pub const WDM_DRIVER: u16 = 0x2000;
    pub const GUARD_CF: u16 = 0x4000;
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

// ============================================================================
// Public data
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub company_name: String,
    pub product_name: String,
    pub file_description: String,
    pub file_version: String,
    pub product_version: String,
    pub legal_copyright: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeMetadataPatch {
    pub version_info: Option<VersionInfo>,
    pub manifest: Option<String>,
    pub icon_path: Option<String>,
}

/// Summary of a PE file's basic layout (cheap to compute, no full parsing exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeLayout {
    pub is_64_bit: bool,
    pub section_count: u16,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub image_base: u64,
    pub entry_point: u32,
    pub overlay_offset: Option<usize>,
    pub overlay_size: usize,
    pub checksum: u32,
}

// ============================================================================
// Engine
// ============================================================================

pub struct PeEngine;

impl PeEngine {
    /// Align a value up to the given alignment boundary.
    pub fn align_up(value: u32, alignment: u32) -> u32 {
        if alignment == 0 {
            return value;
        }
        let remainder = value % alignment;
        if remainder == 0 {
            value
        } else {
            value + (alignment - remainder)
        }
    }

    /// Read the PE header offset (`e_lfanew`) from the DOS header.
    fn read_e_lfanew(buffer: &[u8]) -> Result<usize, PeEngineError> {
        if buffer.len() < 0x40 {
            return Err(PeEngineError::InvalidPe("buffer too small for DOS header".into()));
        }
        let v = u32::from_le_bytes(buffer[0x3C..0x40].try_into().unwrap()) as usize;
        if v + 24 > buffer.len() {
            return Err(PeEngineError::InvalidPe("e_lfanew points outside buffer".into()));
        }
        Ok(v)
    }

    /// Find a section by its (NUL-trimmed) name; returns `(index, header_offset_in_file)`.
    pub fn find_section_by_name(
        pe_buffer: &[u8],
        name: &str,
    ) -> Result<(usize, usize), PeEngineError> {
        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let coff_offset = e_lfanew + 4;
        let size_of_opt_header = pe.header.coff_header.size_of_optional_header as usize;
        let section_table_offset = coff_offset + 20 + size_of_opt_header;

        for (i, sec) in pe.sections.iter().enumerate() {
            let sec_name = sec.name().unwrap_or("");
            if sec_name == name {
                return Ok((i, section_table_offset + i * 40));
            }
        }
        Err(PeEngineError::SectionNotFound(name.into()))
    }

    /// Extract a section's raw bytes from the PE buffer.
    pub fn extract_section<'a>(
        pe_buffer: &'a [u8],
        name: &str,
    ) -> Result<&'a [u8], PeEngineError> {
        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
        for sec in &pe.sections {
            let sec_name = sec.name().unwrap_or("");
            if sec_name == name {
                let start = sec.pointer_to_raw_data as usize;
                let end = start + sec.size_of_raw_data as usize;
                if end > pe_buffer.len() {
                    return Err(PeEngineError::OutOfBounds {
                        offset: end,
                        len: pe_buffer.len(),
                    });
                }
                return Ok(&pe_buffer[start..end]);
            }
        }
        Err(PeEngineError::SectionNotFound(name.into()))
    }

    /// Compute key layout metadata + overlay info for a PE buffer.
    pub fn analyze_layout(pe_buffer: &[u8]) -> Result<PeLayout, PeEngineError> {
        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
        let opt = pe
            .header
            .optional_header
            .ok_or_else(|| PeEngineError::InvalidPe("missing optional header".into()))?;

        // Overlay = bytes after the last section's raw-data range.
        let mut overlay_offset_candidate: usize = 0;
        for sec in &pe.sections {
            let end = sec.pointer_to_raw_data as usize + sec.size_of_raw_data as usize;
            if end > overlay_offset_candidate {
                overlay_offset_candidate = end;
            }
        }
        let (overlay_offset, overlay_size) = if overlay_offset_candidate < pe_buffer.len() {
            (
                Some(overlay_offset_candidate),
                pe_buffer.len() - overlay_offset_candidate,
            )
        } else {
            (None, 0)
        };

        Ok(PeLayout {
            is_64_bit: pe.is_64,
            section_count: pe.header.coff_header.number_of_sections,
            size_of_headers: opt.windows_fields.size_of_headers,
            size_of_image: opt.windows_fields.size_of_image,
            section_alignment: opt.windows_fields.section_alignment,
            file_alignment: opt.windows_fields.file_alignment,
            image_base: opt.windows_fields.image_base,
            entry_point: opt.standard_fields.address_of_entry_point as u32,
            overlay_offset,
            overlay_size,
            checksum: opt.windows_fields.check_sum,
        })
    }

    /// Locate the offset of the `CheckSum` field inside the Optional Header.
    fn checksum_offset(pe_buffer: &[u8]) -> Result<usize, PeEngineError> {
        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let coff_offset = e_lfanew + 4;
        // PE32 and PE32+ both have CheckSum at OptionalHeader offset 64.
        Ok(coff_offset + 20 + 64)
    }

    /// Locate the offset of the `DllCharacteristics` field inside the Optional Header.
    pub fn dll_characteristics_offset(pe_buffer: &[u8]) -> Result<usize, PeEngineError> {
        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let coff_offset = e_lfanew + 4;
        // PE32+: offset 70; PE32: offset 70 as well (both use the same offset relative to OH).
        let oh_offset = coff_offset + 20;
        let _ = pe; // suppress unused
        Ok(oh_offset + 70)
    }

    /// Locate the offset of the `AddressOfEntryPoint` field inside the Optional Header.
    pub fn entry_point_offset(pe_buffer: &[u8]) -> Result<usize, PeEngineError> {
        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let coff_offset = e_lfanew + 4;
        Ok(coff_offset + 20 + 16)
    }

    /// Locate the offset of the `Subsystem` field inside the Optional Header.
    pub fn subsystem_offset(pe_buffer: &[u8]) -> Result<usize, PeEngineError> {
        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let coff_offset = e_lfanew + 4;
        Ok(coff_offset + 20 + 68)
    }

    /// Update entry point RVA.
    pub fn set_entry_point(pe_buffer: &mut [u8], new_rva: u32) -> Result<(), PeEngineError> {
        let off = Self::entry_point_offset(pe_buffer)?;
        pe_buffer[off..off + 4].copy_from_slice(&new_rva.to_le_bytes());
        Ok(())
    }

    /// Set / OR-mask the `DllCharacteristics` flags.
    pub fn or_dll_characteristics(pe_buffer: &mut [u8], mask: u16) -> Result<(), PeEngineError> {
        let off = Self::dll_characteristics_offset(pe_buffer)?;
        let cur = u16::from_le_bytes(pe_buffer[off..off + 2].try_into().unwrap());
        let new = cur | mask;
        pe_buffer[off..off + 2].copy_from_slice(&new.to_le_bytes());
        Ok(())
    }

    /// Compute the Microsoft PE checksum for a file image (per `IMAGE_NT_HEADERS.CheckSum`).
    pub fn compute_pe_checksum(pe_buffer: &[u8]) -> Result<u32, PeEngineError> {
        let cs_off = Self::checksum_offset(pe_buffer)?;
        let mut sum: u64 = 0;

        // Process buffer in 16-bit words. The 4 checksum bytes themselves are excluded.
        let mut i: usize = 0;
        let len = pe_buffer.len();
        while i + 1 < len {
            let in_cs = i >= cs_off && i < cs_off + 4;
            let w = if in_cs {
                0u16
            } else {
                u16::from_le_bytes([pe_buffer[i], pe_buffer[i + 1]])
            };
            sum = sum.wrapping_add(w as u64);
            // Fold high bits down (16-bit one's complement)
            sum = (sum & 0xFFFF).wrapping_add(sum >> 16);
            i += 2;
        }
        if i < len {
            sum = sum.wrapping_add(pe_buffer[i] as u64);
            sum = (sum & 0xFFFF).wrapping_add(sum >> 16);
        }
        // Final fold + add file size (per Microsoft spec)
        let folded = (sum & 0xFFFF) as u32;
        Ok(folded.wrapping_add(len as u32))
    }

    /// Recalculate and write the PE checksum field in place.
    pub fn update_checksum(pe_buffer: &mut [u8]) -> Result<u32, PeEngineError> {
        let cs_off = Self::checksum_offset(pe_buffer)?;
        // Zero the current checksum bytes first so the algorithm is deterministic.
        pe_buffer[cs_off..cs_off + 4].copy_from_slice(&[0u8; 4]);
        let new = Self::compute_pe_checksum(pe_buffer)?;
        pe_buffer[cs_off..cs_off + 4].copy_from_slice(&new.to_le_bytes());
        Ok(new)
    }

    /// Add a new section to an existing PE buffer.
    ///
    /// Updates the COFF header (`NumberOfSections`), the Optional Header (`SizeOfImage`),
    /// preserves any trailing overlay, and appends the aligned payload.
    pub fn inject_section(
        pe_buffer: &[u8],
        section_name: &str,
        payload_data: &[u8],
        characteristics: u32,
    ) -> Result<Vec<u8>, PeEngineError> {
        if section_name.as_bytes().len() > 8 {
            return Err(PeEngineError::SectionNameTooLong(section_name.into()));
        }

        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;

        if pe.header.coff_header.number_of_sections >= 96 {
            return Err(PeEngineError::ResourceEditError(
                "Max PE section count exceeded".into(),
            ));
        }

        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let coff_offset = e_lfanew + 4;
        let num_sections = pe.header.coff_header.number_of_sections;
        let size_of_opt_header = pe.header.coff_header.size_of_optional_header as usize;
        let section_table_offset = coff_offset + 20 + size_of_opt_header;
        let end_of_section_table = section_table_offset + (num_sections as usize * 40);

        let opt = pe
            .header
            .optional_header
            .ok_or_else(|| PeEngineError::InvalidPe("missing optional header".into()))?;
        let section_alignment = opt.windows_fields.section_alignment;
        let file_alignment = opt.windows_fields.file_alignment;

        // Detect overlay so we can preserve it across section appends.
        let layout = Self::analyze_layout(pe_buffer)?;
        let overlay: Vec<u8> = match layout.overlay_offset {
            Some(off) if layout.overlay_size > 0 => pe_buffer[off..off + layout.overlay_size].to_vec(),
            _ => Vec::new(),
        };
        let last_raw_end = layout.overlay_offset.unwrap_or(pe_buffer.len());

        // Find first section's raw data pointer
        let mut first_section_raw_ptr = u32::MAX;
        for sec in pe.sections.iter() {
            if sec.pointer_to_raw_data > 0 && sec.pointer_to_raw_data < first_section_raw_ptr {
                first_section_raw_ptr = sec.pointer_to_raw_data;
            }
        }

        let mut out_buffer = pe_buffer.to_vec();

        // If section table can't fit a new entry, shift all raw section data forward.
        if (end_of_section_table + 40) > first_section_raw_ptr as usize {
            let needed = (end_of_section_table + 40) - first_section_raw_ptr as usize;
            let shift = Self::align_up(needed as u32, file_alignment) as usize;

            let old_len = out_buffer.len();
            out_buffer.resize(old_len + shift, 0);

            // Snapshot original section headers (idx, src_start, src_size).
            let mut snap: Vec<(usize, usize, usize)> = pe
                .sections
                .iter()
                .enumerate()
                .map(|(i, s)| (i, s.pointer_to_raw_data as usize, s.size_of_raw_data as usize))
                .collect();
            // Reverse order so we don't overwrite data we still need to move.
            snap.sort_by(|a, b| b.1.cmp(&a.1));

            for (idx, src_start, src_size) in snap {
                if src_start == 0 || src_size == 0 {
                    continue;
                }
                let src_end = src_start + src_size;
                if src_end > old_len {
                    continue;
                }
                let dst_start = src_start + shift;
                // Safe non-overlapping copy using copy_within
                out_buffer.copy_within(src_start..src_end, dst_start);
                // Zero out region between old and new locations to avoid leakage.
                let zero_end = dst_start.min(src_end);
                for b in &mut out_buffer[src_start..zero_end] {
                    *b = 0;
                }
                // Update header's pointer_to_raw_data
                let hdr_off = section_table_offset + (idx * 40);
                let new_ptr = (src_start as u32) + shift as u32;
                out_buffer[hdr_off + 20..hdr_off + 24].copy_from_slice(&new_ptr.to_le_bytes());
            }

            // Bump SizeOfImage to match the shift (in section_alignment units).
            let size_of_image_offset = coff_offset + 20 + 56;
            let old_soi = u32::from_le_bytes(
                out_buffer[size_of_image_offset..size_of_image_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            let new_soi = Self::align_up(old_soi + shift as u32, section_alignment);
            out_buffer[size_of_image_offset..size_of_image_offset + 4]
                .copy_from_slice(&new_soi.to_le_bytes());
        }

        // Re-parse to read up-to-date section info after any shifts.
        // (Cheap because we only need basic fields.)
        let pe2 = PE::parse(&out_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;

        let last_va = pe2
            .sections
            .last()
            .map(|s| s.virtual_address + s.virtual_size.max(s.size_of_raw_data))
            .unwrap_or(0);
        let last_raw = pe2
            .sections
            .last()
            .map(|s| s.pointer_to_raw_data + s.size_of_raw_data)
            .unwrap_or(0);

        let new_virtual_address = Self::align_up(last_va, section_alignment);
        let new_raw_pointer = Self::align_up(last_raw.max(last_raw_end as u32), file_alignment);
        let payload_aligned_size = Self::align_up(payload_data.len() as u32, file_alignment);

        // Build a 40-byte section header.
        let mut new_header = [0u8; 40];
        let name_bytes = section_name.as_bytes();
        let limit = name_bytes.len().min(8);
        new_header[..limit].copy_from_slice(&name_bytes[..limit]);
        // VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
        new_header[8..12].copy_from_slice(&(payload_data.len() as u32).to_le_bytes());
        new_header[12..16].copy_from_slice(&new_virtual_address.to_le_bytes());
        new_header[16..20].copy_from_slice(&payload_aligned_size.to_le_bytes());
        new_header[20..24].copy_from_slice(&new_raw_pointer.to_le_bytes());
        new_header[36..40].copy_from_slice(&characteristics.to_le_bytes());

        // Insert section header.
        let end_of_section_table_after_shift = section_table_offset + (num_sections as usize * 40);
        if end_of_section_table_after_shift + 40 > out_buffer.len() {
            return Err(PeEngineError::NoHeaderSpace);
        }
        out_buffer[end_of_section_table_after_shift..end_of_section_table_after_shift + 40]
            .copy_from_slice(&new_header);

        // Bump section count.
        let new_num_sections = num_sections + 1;
        out_buffer[coff_offset + 2..coff_offset + 4]
            .copy_from_slice(&new_num_sections.to_le_bytes());

        // Update SizeOfImage to span the new section.
        let size_of_image_offset = coff_offset + 20 + 56;
        let new_size_of_image =
            Self::align_up(new_virtual_address + payload_data.len() as u32, section_alignment);
        out_buffer[size_of_image_offset..size_of_image_offset + 4]
            .copy_from_slice(&new_size_of_image.to_le_bytes());

        // Pad up to the new raw pointer, then write the payload, then restore overlay.
        if out_buffer.len() < new_raw_pointer as usize {
            out_buffer.resize(new_raw_pointer as usize, 0);
        } else {
            out_buffer.truncate(new_raw_pointer as usize);
        }
        let mut aligned_payload = payload_data.to_vec();
        aligned_payload.resize(payload_aligned_size as usize, 0);
        out_buffer.extend_from_slice(&aligned_payload);

        // Re-attach the overlay so trailing data (signatures, installers, etc.) isn't lost.
        if !overlay.is_empty() {
            out_buffer.extend_from_slice(&overlay);
        }

        Ok(out_buffer)
    }

    /// Inject multiple sections in one pass (more efficient than chained calls).
    pub fn inject_sections(
        pe_buffer: &[u8],
        sections: &[(&str, &[u8], u32)],
    ) -> Result<Vec<u8>, PeEngineError> {
        let mut out = pe_buffer.to_vec();
        for (name, data, ch) in sections {
            out = Self::inject_section(&out, name, data, *ch)?;
        }
        Ok(out)
    }

    /// Modify or replace PE resources (version strings, icons, manifests).
    ///
    /// Note: this implementation stores metadata in dedicated `.reapver`, `.reapman`,
    /// `.reapico` sections that the ReaperShield SDK + telemetry can read directly.
    /// Editing the OS-level `.rsrc` directory requires a full IMAGE_RESOURCE_DIRECTORY
    /// rewrite, which is deferred to a future release.
    pub fn patch_metadata(
        pe_buffer: &[u8],
        patch: &PeMetadataPatch,
    ) -> Result<Vec<u8>, PeEngineError> {
        let mut buffer = pe_buffer.to_vec();

        if let Some(info) = &patch.version_info {
            let info_bytes = serde_json::to_vec(info)
                .map_err(|e| PeEngineError::ResourceEditError(e.to_string()))?;
            buffer = Self::inject_section(&buffer, ".reapver", &info_bytes, characteristics::READ_ONLY_DATA)?;
        }

        if let Some(manifest) = &patch.manifest {
            buffer = Self::inject_section(
                &buffer,
                ".reapman",
                manifest.as_bytes(),
                characteristics::READ_ONLY_DATA,
            )?;
        }

        if let Some(icon_path) = &patch.icon_path {
            if let Ok(mut icon_file) = File::open(icon_path) {
                let mut icon_bytes = Vec::new();
                if icon_file.read_to_end(&mut icon_bytes).is_ok() {
                    buffer = Self::inject_section(
                        &buffer,
                        ".reapico",
                        &icon_bytes,
                        characteristics::READ_ONLY_DATA,
                    )?;
                }
            }
        }

        Ok(buffer)
    }

    /// Save modified executable buffer to disk.
    pub fn save_pe<P: AsRef<Path>>(buffer: &[u8], path: P) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(buffer)?;
        Ok(())
    }

    // ========================================================================
    // Relocation helpers
    // ========================================================================

    /// Locate the file offset + size of the `.reloc` data, if present.
    /// Prefers the official IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5) data
    /// directory, falling back to a `.reloc`-named section if the directory
    /// is empty (rare but possible for stripped relocations).
    pub fn locate_reloc_section(pe_buffer: &[u8]) -> Result<Option<(usize, usize)>, PeEngineError> {
        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
        let sections: Vec<(u32, u32, u32)> = pe
            .sections
            .iter()
            .map(|s| (s.virtual_address, s.virtual_size, s.pointer_to_raw_data))
            .collect();

        // Preferred: data directory #5 = IMAGE_DIRECTORY_ENTRY_BASERELOC.
        if let Some(opt) = pe.header.optional_header.as_ref() {
            if let Some(dir) = opt.data_directories.get_base_relocation_table() {
                if dir.size > 0 {
                    if let Some(off) = Self::rva_to_file_offset_static(&sections, dir.virtual_address) {
                        let end = off.saturating_add(dir.size as usize);
                        if end <= pe_buffer.len() {
                            return Ok(Some((off, dir.size as usize)));
                        }
                    }
                }
            }
        }
        // Fallback: find a section literally named .reloc.
        for sec in pe.sections {
            let name = String::from_utf8_lossy(&sec.name).trim_end_matches('\0').to_string();
            if name.eq_ignore_ascii_case(".reloc") && sec.size_of_raw_data > 0 {
                let start = sec.pointer_to_raw_data as usize;
                let end = start.saturating_add(sec.size_of_raw_data as usize);
                if end <= pe_buffer.len() {
                    return Ok(Some((start, end - start)));
                }
            }
        }
        Ok(None)
    }

    /// Parse the base relocation table from `.reloc`. Returns an empty table
    /// if the section is absent (the PE will not be rebasable, but is valid).
    pub fn parse_relocations(pe_buffer: &[u8]) -> Result<RelocationTable, PeEngineError> {
        let mut table = RelocationTable::default();
        let (start, size) = match Self::locate_reloc_section(pe_buffer)? {
            Some(v) => v,
            None => return Ok(table),
        };

        let mut cursor = start;
        let end = start + size;
        while cursor + 8 <= end {
            let page_rva = u32::from_le_bytes(
                pe_buffer[cursor..cursor + 4].try_into().unwrap(),
            );
            let block_size = u32::from_le_bytes(
                pe_buffer[cursor + 4..cursor + 8].try_into().unwrap(),
            ) as usize;

            if block_size == 0 || block_size < 8 {
                break;
            }
            if cursor + block_size > end {
                break;
            }

            let entry_count = (block_size - 8) / 2;
            let mut entries = Vec::with_capacity(entry_count);
            for i in 0..entry_count {
                let off = cursor + 8 + i * 2;
                let raw = u16::from_le_bytes(pe_buffer[off..off + 2].try_into().unwrap());
                let reloc_type = (raw >> 12) & 0x0F;
                let offset = raw & 0x0FFF;
                if reloc_type == 0 {
                    continue; // padding entry
                }
                entries.push(RelocationEntry {
                    rva: page_rva.wrapping_add(offset as u32),
                    reloc_type,
                });
            }
            if !entries.is_empty() {
                table.total_entries += entries.len() as u32;
                table.blocks.push(RelocationBlock { page_rva, entries });
            }
            cursor += block_size;
        }
        Ok(table)
    }

    /// Rewrite the IMAGE_OPTIONAL_HEADER `ImageBase` field. PE32+ uses 8 bytes,
    /// PE32 uses 4 bytes — this picks the right one based on the magic.
    pub fn set_image_base(pe_buffer: &mut [u8], new_base: u64) -> Result<(), PeEngineError> {
        let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
        let opt = pe
            .header
            .optional_header
            .ok_or_else(|| PeEngineError::InvalidPe("missing optional header".into()))?;
        let e_lfanew = Self::read_e_lfanew(pe_buffer)?;
        let image_base_offset = e_lfanew + 4 + 20 + 24; // after standard fields
        if opt.standard_fields.magic == 0x20b {
            // PE32+
            if pe_buffer.len() < image_base_offset + 8 {
                return Err(PeEngineError::OutOfBounds {
                    offset: image_base_offset + 8,
                    len: pe_buffer.len(),
                });
            }
            pe_buffer[image_base_offset..image_base_offset + 8]
                .copy_from_slice(&new_base.to_le_bytes());
        } else if opt.standard_fields.magic == 0x10b {
            // PE32
            if pe_buffer.len() < image_base_offset + 4 {
                return Err(PeEngineError::OutOfBounds {
                    offset: image_base_offset + 4,
                    len: pe_buffer.len(),
                });
            }
            pe_buffer[image_base_offset..image_base_offset + 4]
                .copy_from_slice(&(new_base as u32).to_le_bytes());
        } else {
            return Err(PeEngineError::InvalidPe(format!(
                "unknown optional header magic 0x{:x}",
                opt.standard_fields.magic
            )));
        }
        Ok(())
    }

    /// Rebase the image in-place to `new_image_base`, walking the `.reloc`
    /// table and applying HIGHLOW (4-byte) / DIR64 (8-byte) / LOW/HIGH (2-byte)
    /// fixups. Returns the number of fixups actually applied.
    ///
    /// This is the correct way to:
    /// * lift a binary out of its compile-time `ImageBase` collision,
    /// * support reflective loaders that ignore `ImageBase`,
    /// * produce deterministic addresses in reproducible builds.
    pub fn apply_relocations(
        pe_buffer: &mut [u8],
        new_image_base: u64,
    ) -> Result<u32, PeEngineError> {
        // Snapshot everything we need from the parsed PE before taking &mut.
        let (old_base, sections, has_reloc) = {
            let pe = PE::parse(pe_buffer).map_err(|e| PeEngineError::PeParseError(e.to_string()))?;
            let opt = pe
                .header
                .optional_header
                .ok_or_else(|| PeEngineError::InvalidPe("missing optional header".into()))?;
            let old_base = if opt.standard_fields.magic == 0x20b {
                opt.windows_fields.image_base
            } else {
                opt.windows_fields.image_base as u64
            };
            let sections: Vec<(u32, u32, u32)> = pe
                .sections
                .iter()
                .map(|s| (s.virtual_address, s.virtual_size, s.pointer_to_raw_data))
                .collect();
            (old_base, sections, Self::locate_reloc_section(pe_buffer)?.is_some())
        };

        if old_base == new_image_base || !has_reloc {
            return Ok(0);
        }
        let delta = (new_image_base as i128) - (old_base as i128);

        let (start, size) = Self::locate_reloc_section(pe_buffer)?.unwrap();
        let end = start + size;
        let mut cursor = start;
        let mut applied: u32 = 0;

        while cursor + 8 <= end {
            let block_size = u32::from_le_bytes(
                pe_buffer[cursor + 4..cursor + 8].try_into().unwrap(),
            ) as usize;
            if block_size == 0 || block_size < 8 || cursor + block_size > end {
                break;
            }
            let entry_count = (block_size - 8) / 2;
            for i in 0..entry_count {
                let off = cursor + 8 + i * 2;
                let raw = u16::from_le_bytes(pe_buffer[off..off + 2].try_into().unwrap());
                let reloc_type = (raw >> 12) & 0x0F;
                let rva_offset = (raw & 0x0FFF) as u32;
                let page_rva = u32::from_le_bytes(
                    pe_buffer[cursor..cursor + 4].try_into().unwrap(),
                );
                let target_rva = page_rva.wrapping_add(rva_offset);
                let file_off = match Self::rva_to_file_offset_static(&sections, target_rva) {
                    Some(o) => o,
                    None => continue,
                };

                match reloc_type {
                    0x03 => {
                        if file_off + 4 > pe_buffer.len() {
                            continue;
                        }
                        let old_val = u32::from_le_bytes(
                            pe_buffer[file_off..file_off + 4].try_into().unwrap(),
                        );
                        let new_val = (old_val as i128 + delta) as u32;
                        pe_buffer[file_off..file_off + 4]
                            .copy_from_slice(&new_val.to_le_bytes());
                        applied += 1;
                    }
                    0x0A => {
                        if file_off + 8 > pe_buffer.len() {
                            continue;
                        }
                        let old_val = u64::from_le_bytes(
                            pe_buffer[file_off..file_off + 8].try_into().unwrap(),
                        );
                        let new_val = (old_val as i128 + delta) as u64;
                        pe_buffer[file_off..file_off + 8]
                            .copy_from_slice(&new_val.to_le_bytes());
                        applied += 1;
                    }
                    0x02 => {
                        if file_off + 2 > pe_buffer.len() {
                            continue;
                        }
                        let old_val = u16::from_le_bytes(
                            pe_buffer[file_off..file_off + 2].try_into().unwrap(),
                        );
                        let new_val = (old_val as i128 + (delta >> 16)) as u16;
                        pe_buffer[file_off..file_off + 2]
                            .copy_from_slice(&new_val.to_le_bytes());
                        applied += 1;
                    }
                    0x01 => {
                        if file_off + 2 > pe_buffer.len() {
                            continue;
                        }
                        let old_val = u16::from_le_bytes(
                            pe_buffer[file_off..file_off + 2].try_into().unwrap(),
                        );
                        let new_val = (old_val as i128 + (delta & 0xFFFF)) as u16;
                        pe_buffer[file_off..file_off + 2]
                            .copy_from_slice(&new_val.to_le_bytes());
                        applied += 1;
                    }
                    0x04 | 0x05 => {
                        // HIGHLOW/3 / HIGHADJ — word-pair fixups across a 32-bit
                        // slot. We skip these conservatively; modern PE32+
                        // binaries use only DIR64 + HIGHLOW.
                    }
                    _ => {}
                }
            }
            cursor += block_size;
        }

        Self::set_image_base(pe_buffer, new_image_base)?;
        Ok(applied)
    }

    /// Convert an RVA to a file offset using a pre-snapshotted section list
    /// (`virtual_address`, `virtual_size`, `pointer_to_raw_data`).
    fn rva_to_file_offset_static(sections: &[(u32, u32, u32)], rva: u32) -> Option<usize> {
        for &(va, vsize, raw_ptr) in sections {
            let end = va.saturating_add(vsize);
            if rva >= va && rva < end {
                let delta = rva - va;
                return Some(raw_ptr as usize + delta as usize);
            }
        }
        None
    }
}

// ============================================================================
// Relocation table types
// ============================================================================

/// One base-relocation entry: the `RVA` that holds a pointer-sized absolute
/// address, and the relocation `type` (HIGHLOW=3, DIR64=0xA, HIGH=2, LOW=1...).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RelocationEntry {
    pub rva: u32,
    pub reloc_type: u16,
}

/// One base-relocation **block** — 4 KiB page of fixups sharing a base RVA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationBlock {
    pub page_rva: u32,
    pub entries: Vec<RelocationEntry>,
}

/// Full relocation table parsed from `.reloc`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelocationTable {
    pub blocks: Vec<RelocationBlock>,
    pub total_entries: u32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_up_basic() {
        assert_eq!(PeEngine::align_up(0, 0x200), 0);
        assert_eq!(PeEngine::align_up(1, 0x200), 0x200);
        assert_eq!(PeEngine::align_up(0x200, 0x200), 0x200);
        assert_eq!(PeEngine::align_up(0x201, 0x200), 0x400);
        assert_eq!(PeEngine::align_up(5, 0), 5);
    }

    #[test]
    fn checksum_of_empty_buffer_invalid() {
        // Too small to host a DOS header — must fail cleanly.
        let buf = vec![0u8; 4];
        assert!(PeEngine::compute_pe_checksum(&buf).is_err());
    }

    #[test]
    fn characteristics_consts_sanity() {
        use characteristics::*;
        assert_eq!(READ_ONLY_DATA & SCN_MEM_WRITE, 0);
    }

    /// Build a tiny PE32+ image with a `.text` and a `.reloc` section. The
    /// `.reloc` data holds one DIR64 entry pointing at a known VA inside
    /// `.text`. The BASE_RELOC data directory (index 5) is also populated.
    fn build_minimal_pe_with_reloc(text_va: u32, image_base: u64, reloc_rva: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 2048];
        // DOS header
        buf[0..2].copy_from_slice(b"MZ");
        let e_lfanew: u32 = 0x80;
        buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE signature at e_lfanew
        buf[e_lfanew as usize..e_lfanew as usize + 4]
            .copy_from_slice(b"PE\0\0");
        let coff = e_lfanew as usize + 4;
        // COFF header: machine=AMD64, num_sections=2, opt_size=240
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        let opt_size: u16 = 240;
        buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        buf[coff + 18..coff + 20].copy_from_slice(&0u16.to_le_bytes());
        // Optional header (PE32+) — magic 0x20B at +0
        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        // SectionAlignment=0x1000, FileAlignment=0x200 at +32 / +36
        buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes());
        // SizeOfImage at +56
        buf[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        // SizeOfHeaders at +60
        buf[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        // NumberOfRvaAndSizes at +108 = 16
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        // ImageBase at +24 (8 bytes for PE32+)
        buf[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        // Data directory #5 (BASE_RELOC) at opt + 112 + 5*8 = opt + 152:
        //   RVA (4) + size (4)
        buf[opt + 152..opt + 156].copy_from_slice(&reloc_rva.to_le_bytes());
        buf[opt + 156..opt + 160].copy_from_slice(&16u32.to_le_bytes());

        // Section table at opt + opt_size
        let sec = opt + opt_size as usize;
        // Section 0: ".text" at file 0x200, VA text_va, size 0x200
        buf[sec..sec + 5].copy_from_slice(b".text");
        buf[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&text_va.to_le_bytes());
        buf[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // Section 1: ".reloc" at file 0x400, VA reloc_rva (already page-aligned),
        // size 0x200.
        let sec2 = sec + 40;
        buf[sec2..sec2 + 6].copy_from_slice(b".reloc");
        buf[sec2 + 8..sec2 + 12].copy_from_slice(&0x100u32.to_le_bytes());
        buf[sec2 + 12..sec2 + 16].copy_from_slice(&reloc_rva.to_le_bytes());
        buf[sec2 + 16..sec2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sec2 + 20..sec2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        buf[sec2 + 36..sec2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        // Plant a DIR64 pointer at text_va in the file (raw offset 0x200).
        let target_abs = image_base.wrapping_add(text_va as u64);
        let raw_text_offset = 0x200usize;
        buf[raw_text_offset..raw_text_offset + 8]
            .copy_from_slice(&target_abs.to_le_bytes());

        // Plant a `.reloc` block at file offset 0x400 with one DIR64 entry
        // pointing at the same text_va RVA.
        let reloc_file_offset = 0x400usize;
        let block_size: u32 = 8 + 2;
        buf[reloc_file_offset + 4..reloc_file_offset + 8]
            .copy_from_slice(&block_size.to_le_bytes());
        // We want the reloc to point at text_va (not reloc_rva), so use
        // page = text_va & ~0xFFF, offset = text_va & 0xFFF.
        let text_page = text_va & !0xFFF;
        let text_offset = (text_va & 0xFFF) as u16;
        buf[reloc_file_offset..reloc_file_offset + 4]
            .copy_from_slice(&text_page.to_le_bytes());
        let entry: u16 = (0x0A << 12) | text_offset;
        buf[reloc_file_offset + 8..reloc_file_offset + 10]
            .copy_from_slice(&entry.to_le_bytes());
        buf
    }

    #[test]
    fn relocation_parse_finds_dir64_entry() {
        let pe = build_minimal_pe_with_reloc(0x1000, 0x0000_0000_0040_0000, 0x1000);
        let located = PeEngine::locate_reloc_section(&pe).unwrap();
        eprintln!("locate_reloc_section = {:?}", located);
        let table = PeEngine::parse_relocations(&pe).unwrap();
        eprintln!("table = {:#?}", table);
        assert_eq!(table.total_entries, 1);
        assert_eq!(table.blocks.len(), 1);
        assert_eq!(table.blocks[0].page_rva, 0x1000);
        assert_eq!(table.blocks[0].entries[0].rva, 0x1000);
        assert_eq!(table.blocks[0].entries[0].reloc_type, 0x0A);
    }

    #[test]
    fn relocation_rebase_updates_dir64_pointer() {
        let image_base = 0x0000_0000_0040_0000u64;
        let new_base = 0x0000_0000_0080_0000u64;
        let mut pe = build_minimal_pe_with_reloc(0x1000, image_base, 0x1000);
        let applied = PeEngine::apply_relocations(&mut pe, new_base).unwrap();
        assert_eq!(applied, 1);
        // ImageBase header should be updated.
        let pe_parsed = goblin::pe::PE::parse(&pe).unwrap();
        let opt = pe_parsed.header.optional_header.unwrap();
        assert_eq!(opt.windows_fields.image_base, new_base);
        // DIR64 value at 0x200 should now point to new_base + 0x1000.
        let stored = u64::from_le_bytes(pe[0x200..0x208].try_into().unwrap());
        assert_eq!(stored, new_base + 0x1000);
    }

    #[test]
    fn relocation_rebase_noop_when_base_unchanged() {
        let mut pe = build_minimal_pe_with_reloc(0x1000, 0x0040_0000, 0x1000);
        let applied = PeEngine::apply_relocations(&mut pe, 0x0040_0000).unwrap();
        assert_eq!(applied, 0);
    }

    #[test]
    fn relocation_set_image_base_updates_header() {
        let mut pe = build_minimal_pe_with_reloc(0x1000, 0x0040_0000, 0x1000);
        PeEngine::set_image_base(&mut pe, 0x00C0_0000).unwrap();
        let parsed = goblin::pe::PE::parse(&pe).unwrap();
        let opt = parsed.header.optional_header.unwrap();
        assert_eq!(opt.windows_fields.image_base, 0x00C0_0000);
    }
}
