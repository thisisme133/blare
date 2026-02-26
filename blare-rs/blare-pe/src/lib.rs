use std::cmp::{max, min};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;

pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;

const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
const IMAGE_SUBSYSTEM_EFI_ROM: u16 = 13;

const RELOC_TYPE_ABSOLUTE: u16 = 0;
const RELOC_TYPE_DIR64: u16 = 10;

const UNW_FLAG_EHANDLER: u8 = 0x1;
const UNW_FLAG_UHANDLER: u8 = 0x2;
const UNW_FLAG_CHAININFO: u8 = 0x4;

#[derive(Debug, Error)]
pub enum PeError {
    #[error("invalid pe: {0}")]
    Invalid(String),
    #[error("unsupported pe: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
    pub characteristics: u32,
}

impl SectionInfo {
    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = max(self.virtual_size, self.size_of_raw_data);
        rva >= self.virtual_address && rva < self.virtual_address.saturating_add(size)
    }

    pub fn executable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocEntry {
    pub rva: u32,
    pub typ: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RuntimeFunctionEntry {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFn {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<ImportedFn>,
}

#[derive(Debug, Clone, Copy)]
pub struct AddedSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

#[derive(Debug, Clone)]
pub struct RebuildSectionSpec {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct UnwindInfoSummary {
    pub flags: u8,
    pub size: u32,
    pub supports_safe_clone: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DataDirectoryInfo {
    pub index: usize,
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LoadConfigSummary {
    pub size: u32,
    pub guard_cf_function_table: Option<u64>,
    pub guard_cf_function_count: Option<u64>,
    pub guard_flags: Option<u32>,
    pub guard_eh_continuation_table: Option<u64>,
    pub guard_eh_continuation_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardCfFunctionTable {
    pub table_rva: u32,
    pub entry_count: u64,
    pub entry_size: u32,
    pub guard_flags: u32,
    pub entries: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEhContinuationTable {
    pub table_rva: u32,
    pub entry_count: u64,
    pub entry_size: u32,
    pub guard_flags: u32,
    pub entries: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindRecord {
    pub unwind_rva: u32,
    pub flags: u8,
    pub prolog_size: u8,
    pub count_of_codes: u8,
    pub aligned_codes_size: u32,
    pub full_size: u32,
    pub chained_entry: Option<RuntimeFunctionEntry>,
    pub exception_handler_rva: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeBinaryKind {
    UserMode,
    KernelDriver,
    Uefi,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PeFile {
    bytes: Vec<u8>,
    file_header_offset: usize,
    optional_header_offset: usize,
    data_directory_offset: usize,
    number_of_rva_and_sizes: usize,
    section_table_offset: usize,
    number_of_sections: usize,
    file_alignment: u32,
    section_alignment: u32,
    size_of_headers: u32,
    image_base: u64,
    characteristics: u16,
    subsystem: u16,
    sections: Vec<SectionInfo>,
}

#[derive(Debug, Clone, Copy)]
struct LoadConfigLayout {
    size_in_directory: u32,
    size_in_header: u32,
    guard_cf_function_table: u64,
    guard_cf_function_count: u64,
    guard_flags: u32,
    guard_eh_continuation_table: u64,
    guard_eh_continuation_count: u64,
}

fn read_u16(bytes: &[u8], off: usize) -> Result<u16, PeError> {
    let end = off
        .checked_add(2)
        .ok_or_else(|| PeError::Invalid("u16 offset overflow".to_string()))?;
    let data = bytes
        .get(off..end)
        .ok_or_else(|| PeError::Invalid(format!("u16 out of range at offset 0x{off:x}")))?;
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32, PeError> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| PeError::Invalid("u32 offset overflow".to_string()))?;
    let data = bytes
        .get(off..end)
        .ok_or_else(|| PeError::Invalid(format!("u32 out of range at offset 0x{off:x}")))?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn read_u64(bytes: &[u8], off: usize) -> Result<u64, PeError> {
    let end = off
        .checked_add(8)
        .ok_or_else(|| PeError::Invalid("u64 offset overflow".to_string()))?;
    let data = bytes
        .get(off..end)
        .ok_or_else(|| PeError::Invalid(format!("u64 out of range at offset 0x{off:x}")))?;
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

fn write_u16(bytes: &mut [u8], off: usize, value: u16) -> Result<(), PeError> {
    let end = off
        .checked_add(2)
        .ok_or_else(|| PeError::Invalid("u16 offset overflow".to_string()))?;
    let data = bytes
        .get_mut(off..end)
        .ok_or_else(|| PeError::Invalid(format!("u16 out of range at offset 0x{off:x}")))?;
    data.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], off: usize, value: u32) -> Result<(), PeError> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| PeError::Invalid("u32 offset overflow".to_string()))?;
    let data = bytes
        .get_mut(off..end)
        .ok_or_else(|| PeError::Invalid(format!("u32 out of range at offset 0x{off:x}")))?;
    data.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

fn section_name(bytes: &[u8; 8]) -> String {
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

fn guard_cf_entry_size_from_flags(flags: u32) -> Result<u32, PeError> {
    // IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK/SHIFT (winnt.h):
    // the nibble encodes an additional byte count per entry.
    // Entry stride = 4-byte RVA + encoded additional bytes.
    let additional = (flags >> 28) & 0xF;
    Ok(4 + additional)
}

fn classify_binary_kind(subsystem: u16) -> PeBinaryKind {
    match subsystem {
        IMAGE_SUBSYSTEM_WINDOWS_GUI
        | IMAGE_SUBSYSTEM_WINDOWS_CUI
        | IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => PeBinaryKind::UserMode,
        IMAGE_SUBSYSTEM_NATIVE => PeBinaryKind::KernelDriver,
        IMAGE_SUBSYSTEM_EFI_APPLICATION
        | IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
        | IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
        | IMAGE_SUBSYSTEM_EFI_ROM => PeBinaryKind::Uefi,
        _ => PeBinaryKind::Unknown,
    }
}

impl PeFile {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, PeError> {
        if bytes.len() < 0x40 {
            return Err(PeError::Invalid(
                "file too small for DOS header".to_string(),
            ));
        }

        if &bytes[0..2] != b"MZ" {
            return Err(PeError::Invalid("missing MZ signature".to_string()));
        }

        let pe_offset = read_u32(&bytes, 0x3c)? as usize;
        let pe_sig_end = pe_offset
            .checked_add(4)
            .ok_or_else(|| PeError::Invalid("PE signature offset overflow".to_string()))?;
        if bytes.get(pe_offset..pe_sig_end) != Some(b"PE\0\0") {
            return Err(PeError::Invalid("missing PE signature".to_string()));
        }

        let file_header_offset = pe_offset + 4;
        let number_of_sections = read_u16(&bytes, file_header_offset + 2)? as usize;
        let size_of_optional_header = read_u16(&bytes, file_header_offset + 16)? as usize;
        let characteristics = read_u16(&bytes, file_header_offset + 18)?;

        let optional_header_offset = file_header_offset + 20;
        let magic = read_u16(&bytes, optional_header_offset)?;
        if magic != 0x20b {
            return Err(PeError::Unsupported(format!(
                "only PE32+ (0x20b) is supported, got 0x{magic:x}"
            )));
        }

        if size_of_optional_header < 112 {
            return Err(PeError::Invalid(
                "optional header too small for PE32+ directories".to_string(),
            ));
        }

        let image_base = read_u64(&bytes, optional_header_offset + 24)?;
        let section_alignment = read_u32(&bytes, optional_header_offset + 32)?;
        let file_alignment = read_u32(&bytes, optional_header_offset + 36)?;
        let size_of_headers = read_u32(&bytes, optional_header_offset + 60)?;
        let subsystem = read_u16(&bytes, optional_header_offset + 68)?;

        let number_of_rva_and_sizes = read_u32(&bytes, optional_header_offset + 108)? as usize;
        if number_of_rva_and_sizes < 6 {
            return Err(PeError::Invalid(format!(
                "expected at least 6 data directories, got {number_of_rva_and_sizes}"
            )));
        }

        let data_directory_offset = optional_header_offset + 112;
        let section_table_offset = optional_header_offset + size_of_optional_header;

        let section_table_size = number_of_sections
            .checked_mul(40)
            .ok_or_else(|| PeError::Invalid("section table size overflow".to_string()))?;
        let section_table_end = section_table_offset
            .checked_add(section_table_size)
            .ok_or_else(|| PeError::Invalid("section table end overflow".to_string()))?;
        if section_table_end > bytes.len() {
            return Err(PeError::Invalid(
                "section table exceeds file size".to_string(),
            ));
        }

        let mut sections = Vec::with_capacity(number_of_sections);
        for i in 0..number_of_sections {
            let off = section_table_offset + (i * 40);
            let name_bytes: [u8; 8] = bytes[off..off + 8]
                .try_into()
                .map_err(|_| PeError::Invalid("invalid section name bytes".to_string()))?;
            let section = SectionInfo {
                name: section_name(&name_bytes),
                virtual_size: read_u32(&bytes, off + 8)?,
                virtual_address: read_u32(&bytes, off + 12)?,
                size_of_raw_data: read_u32(&bytes, off + 16)?,
                pointer_to_raw_data: read_u32(&bytes, off + 20)?,
                characteristics: read_u32(&bytes, off + 36)?,
            };
            sections.push(section);
        }

        Ok(Self {
            bytes,
            file_header_offset,
            optional_header_offset,
            data_directory_offset,
            number_of_rva_and_sizes,
            section_table_offset,
            number_of_sections,
            file_alignment,
            section_alignment,
            size_of_headers,
            image_base,
            characteristics,
            subsystem,
            sections,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn characteristics(&self) -> u16 {
        self.characteristics
    }

    pub fn subsystem(&self) -> u16 {
        self.subsystem
    }

    pub fn binary_kind(&self) -> PeBinaryKind {
        classify_binary_kind(self.subsystem)
    }

    pub fn entrypoint_rva(&self) -> Result<u32, PeError> {
        read_u32(&self.bytes, self.optional_header_offset + 16)
    }

    pub fn size_of_image(&self) -> Result<u32, PeError> {
        read_u32(&self.bytes, self.optional_header_offset + 56)
    }

    pub fn sections(&self) -> &[SectionInfo] {
        &self.sections
    }

    pub fn file_alignment(&self) -> u32 {
        self.file_alignment
    }

    pub fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    pub fn next_section_virtual_address(&self) -> Result<u32, PeError> {
        let last = self
            .sections
            .last()
            .ok_or_else(|| PeError::Invalid("pe has no section".to_string()))?;
        Ok(align_up(
            last.virtual_address
                .saturating_add(max(last.virtual_size, last.size_of_raw_data)),
            self.section_alignment,
        ))
    }

    pub fn number_of_data_directories(&self) -> usize {
        self.number_of_rva_and_sizes
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }

        for sec in &self.sections {
            let size = max(sec.virtual_size, sec.size_of_raw_data);
            if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(size) {
                let delta = rva - sec.virtual_address;
                let off = sec.pointer_to_raw_data.saturating_add(delta);
                if off < sec.pointer_to_raw_data.saturating_add(sec.size_of_raw_data) {
                    return Some(off as usize);
                }
            }
        }

        None
    }

    pub fn read_rva_slice(&self, rva: u32, size: usize) -> Result<&[u8], PeError> {
        let file_off = self
            .rva_to_file_offset(rva)
            .ok_or_else(|| PeError::Invalid(format!("cannot map rva 0x{rva:x} to file offset")))?;
        let end = file_off
            .checked_add(size)
            .ok_or_else(|| PeError::Invalid("slice end overflow".to_string()))?;
        self.bytes
            .get(file_off..end)
            .ok_or_else(|| PeError::Invalid(format!("slice out of bounds at rva 0x{rva:x}")))
    }

    fn read_c_string_at_file_offset(&self, file_off: usize) -> Result<String, PeError> {
        if file_off >= self.bytes.len() {
            return Err(PeError::Invalid(format!(
                "cstring offset 0x{file_off:x} out of bounds"
            )));
        }
        let mut end = file_off;
        while end < self.bytes.len() && self.bytes[end] != 0 {
            end += 1;
        }
        if end == self.bytes.len() {
            return Err(PeError::Invalid(format!(
                "unterminated cstring at file offset 0x{file_off:x}"
            )));
        }
        Ok(String::from_utf8_lossy(&self.bytes[file_off..end]).to_string())
    }

    fn read_rva_c_string(&self, rva: u32) -> Result<String, PeError> {
        let file_off = self
            .rva_to_file_offset(rva)
            .ok_or_else(|| PeError::Invalid(format!("cstring rva 0x{rva:x} is invalid")))?;
        self.read_c_string_at_file_offset(file_off)
    }

    fn parse_import_name(&self, import_by_name_rva: u32) -> Result<String, PeError> {
        let off = self.rva_to_file_offset(import_by_name_rva).ok_or_else(|| {
            PeError::Invalid(format!(
                "import-by-name rva 0x{import_by_name_rva:x} is invalid"
            ))
        })?;
        let name_off = off
            .checked_add(2)
            .ok_or_else(|| PeError::Invalid("import-by-name offset overflow".to_string()))?;
        self.read_c_string_at_file_offset(name_off)
    }

    pub fn executable_section_for_rva(&self, rva: u32) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|s| s.executable() && s.contains_rva(rva))
    }

    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    pub fn section_by_name(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn section_payload(&self, name: &str) -> Result<Vec<u8>, PeError> {
        let section = self
            .section_by_name(name)
            .ok_or_else(|| PeError::Invalid(format!("section '{name}' not found")))?;
        self.section_payload_for(section)
    }

    fn section_payload_for(&self, section: &SectionInfo) -> Result<Vec<u8>, PeError> {
        if section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0 {
            return Ok(Vec::new());
        }
        let start = section.pointer_to_raw_data as usize;
        let end = start
            .checked_add(section.size_of_raw_data as usize)
            .ok_or_else(|| PeError::Invalid("section payload bounds overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(PeError::Invalid(format!(
                "section '{}' payload exceeds file bounds",
                section.name
            )));
        }
        Ok(self.bytes[start..end].to_vec())
    }

    pub fn rebuild_with_sections(
        &mut self,
        mut specs: Vec<RebuildSectionSpec>,
    ) -> Result<(), PeError> {
        if specs.is_empty() {
            return Err(PeError::Invalid(
                "cannot rebuild pe with zero sections".to_string(),
            ));
        }
        if specs.len() > u16::MAX as usize {
            return Err(PeError::Unsupported(format!(
                "too many sections for pe/coff header: {}",
                specs.len()
            )));
        }

        for spec in &specs {
            if spec.name.is_empty() || spec.name.len() > 8 {
                return Err(PeError::Invalid(format!(
                    "section name '{}' must be 1..=8 bytes",
                    spec.name
                )));
            }
        }

        specs.sort_by_key(|s| s.virtual_address);
        for i in 1..specs.len() {
            let prev = &specs[i - 1];
            let cur = &specs[i];
            if prev.virtual_address == cur.virtual_address {
                return Err(PeError::Invalid(format!(
                    "sections '{}' and '{}' share virtual_address 0x{:x}",
                    prev.name, cur.name, prev.virtual_address
                )));
            }
            let prev_raw_size = if prev.payload.is_empty() {
                0
            } else {
                align_up(prev.payload.len() as u32, self.file_alignment)
            };
            let prev_end = prev
                .virtual_address
                .saturating_add(max(prev.virtual_size, prev_raw_size));
            if prev_end > cur.virtual_address {
                return Err(PeError::Invalid(format!(
                    "section '{}' overlaps '{}': 0x{:x}..0x{:x} vs start 0x{:x}",
                    prev.name, cur.name, prev.virtual_address, prev_end, cur.virtual_address
                )));
            }
        }

        let table_end = self
            .section_table_offset
            .checked_add(specs.len() * 40)
            .ok_or_else(|| PeError::Invalid("section table size overflow".to_string()))?;
        let new_size_of_headers = align_up(
            u32::try_from(table_end)
                .map_err(|_| PeError::Invalid("section table exceeds u32".to_string()))?,
            self.file_alignment,
        );
        let mut new_bytes = vec![0u8; new_size_of_headers as usize];
        let copy_len = self.bytes.len().min(new_bytes.len());
        new_bytes[..copy_len].copy_from_slice(&self.bytes[..copy_len]);

        if self.section_table_offset < new_bytes.len() {
            new_bytes[self.section_table_offset..].fill(0);
        }

        write_u16(
            &mut new_bytes,
            self.file_header_offset + 2,
            specs.len() as u16,
        )?;
        // Drop stale COFF symbol table pointers after full rebuild.
        write_u32(&mut new_bytes, self.file_header_offset + 8, 0)?;
        write_u32(&mut new_bytes, self.file_header_offset + 12, 0)?;
        write_u32(
            &mut new_bytes,
            self.optional_header_offset + 60,
            new_size_of_headers,
        )?;
        // Authenticode certificate directory uses file offsets and is invalid after rebuild.
        if self.number_of_rva_and_sizes > 4 {
            let cert_off = self
                .data_directory_offset
                .checked_add(4 * 8)
                .ok_or_else(|| {
                    PeError::Invalid("certificate directory offset overflow".to_string())
                })?;
            write_u32(&mut new_bytes, cert_off, 0)?;
            write_u32(&mut new_bytes, cert_off + 4, 0)?;
        }

        let mut cursor = new_size_of_headers;
        let mut sections = Vec::with_capacity(specs.len());
        let mut size_of_code = 0u32;
        let mut size_of_init = 0u32;
        let mut size_of_uninit = 0u32;
        let mut max_end = new_size_of_headers;

        for (index, spec) in specs.iter().enumerate() {
            let raw_size = if spec.payload.is_empty() {
                0
            } else {
                align_up(spec.payload.len() as u32, self.file_alignment)
            };
            let ptr_raw = if raw_size == 0 {
                0
            } else {
                cursor = align_up(cursor, self.file_alignment);
                cursor
            };

            if raw_size != 0 {
                let start = ptr_raw as usize;
                let end = start.checked_add(raw_size as usize).ok_or_else(|| {
                    PeError::Invalid("rebuilt section raw bounds overflow".to_string())
                })?;
                if new_bytes.len() < end {
                    new_bytes.resize(end, 0);
                }
                let used_end = start.checked_add(spec.payload.len()).ok_or_else(|| {
                    PeError::Invalid("rebuilt section payload bounds overflow".to_string())
                })?;
                new_bytes[start..used_end].copy_from_slice(&spec.payload);
                if used_end < end {
                    new_bytes[used_end..end].fill(0);
                }
                cursor = ptr_raw.saturating_add(raw_size);
            }

            let hdr = self
                .section_table_offset
                .checked_add(index * 40)
                .ok_or_else(|| PeError::Invalid("section header offset overflow".to_string()))?;
            let hdr_end = hdr
                .checked_add(40)
                .ok_or_else(|| PeError::Invalid("section header bounds overflow".to_string()))?;
            if hdr_end > new_bytes.len() {
                return Err(PeError::Invalid(
                    "section header exceeds rebuilt headers".to_string(),
                ));
            }

            let mut name_bytes = [0u8; 8];
            name_bytes[..spec.name.len()].copy_from_slice(spec.name.as_bytes());
            new_bytes[hdr..hdr + 8].copy_from_slice(&name_bytes);
            write_u32(&mut new_bytes, hdr + 8, spec.virtual_size)?;
            write_u32(&mut new_bytes, hdr + 12, spec.virtual_address)?;
            write_u32(&mut new_bytes, hdr + 16, raw_size)?;
            write_u32(&mut new_bytes, hdr + 20, ptr_raw)?;
            write_u32(&mut new_bytes, hdr + 24, 0)?;
            write_u32(&mut new_bytes, hdr + 28, 0)?;
            write_u16(&mut new_bytes, hdr + 32, 0)?;
            write_u16(&mut new_bytes, hdr + 34, 0)?;
            write_u32(&mut new_bytes, hdr + 36, spec.characteristics)?;

            sections.push(SectionInfo {
                name: spec.name.clone(),
                virtual_address: spec.virtual_address,
                virtual_size: spec.virtual_size,
                pointer_to_raw_data: ptr_raw,
                size_of_raw_data: raw_size,
                characteristics: spec.characteristics,
            });

            if (spec.characteristics & IMAGE_SCN_CNT_CODE) != 0 {
                size_of_code = size_of_code.saturating_add(raw_size);
            }
            if (spec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
                size_of_init = size_of_init.saturating_add(raw_size);
            }
            if (spec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
                size_of_uninit = size_of_uninit.saturating_add(spec.virtual_size);
            }

            let mapped = max(spec.virtual_size, raw_size);
            max_end = max(max_end, spec.virtual_address.saturating_add(mapped));
        }

        write_u32(
            &mut new_bytes,
            self.optional_header_offset + 4,
            size_of_code,
        )?;
        write_u32(
            &mut new_bytes,
            self.optional_header_offset + 8,
            size_of_init,
        )?;
        write_u32(
            &mut new_bytes,
            self.optional_header_offset + 12,
            size_of_uninit,
        )?;
        write_u32(
            &mut new_bytes,
            self.optional_header_offset + 56,
            align_up(max_end, self.section_alignment),
        )?;

        self.bytes = new_bytes;
        self.number_of_sections = sections.len();
        self.size_of_headers = new_size_of_headers;
        self.sections = sections;
        Ok(())
    }

    pub fn overwrite_section_payload(
        &mut self,
        name: &str,
        payload: &[u8],
    ) -> Result<AddedSection, PeError> {
        let Some(index) = self.sections.iter().position(|s| s.name == name) else {
            return Err(PeError::Invalid(format!("section '{name}' not found")));
        };
        let section_ptr = self.sections[index].pointer_to_raw_data;
        if section_ptr == 0 {
            return Err(PeError::Invalid(format!(
                "section '{name}' has no raw data pointer"
            )));
        }

        let section_va = self.sections[index].virtual_address;
        let next_section_va = self
            .sections
            .iter()
            .filter(|s| s.virtual_address > section_va)
            .map(|s| s.virtual_address)
            .min();
        let virtual_span = next_section_va
            .map(|next| next.saturating_sub(section_va))
            .unwrap_or(u32::MAX);
        let payload_len_u32 = u32::try_from(payload.len()).map_err(|_| {
            PeError::Invalid(format!("section '{name}' payload length exceeds u32"))
        })?;
        if payload_len_u32 > virtual_span {
            return Err(PeError::Unsupported(format!(
                "payload for section '{name}' exceeds available virtual span: {} > {}",
                payload_len_u32, virtual_span
            )));
        }

        let raw_off = section_ptr as usize;
        let old_raw_size = self.sections[index].size_of_raw_data as usize;
        let old_raw_end = raw_off
            .checked_add(old_raw_size)
            .ok_or_else(|| PeError::Invalid("section raw bounds overflow".to_string()))?;
        if old_raw_end > self.bytes.len() {
            return Err(PeError::Invalid(format!(
                "section '{name}' raw data exceeds file bounds"
            )));
        }

        let new_raw_size_u32 = align_up(payload_len_u32, self.file_alignment);
        if new_raw_size_u32 > virtual_span {
            return Err(PeError::Unsupported(format!(
                "raw payload for section '{name}' exceeds available virtual span after alignment: {} > {}",
                new_raw_size_u32, virtual_span
            )));
        }
        let new_raw_size = new_raw_size_u32 as usize;
        if new_raw_size > old_raw_size {
            let delta = new_raw_size - old_raw_size;
            let delta_u32 = u32::try_from(delta).map_err(|_| {
                PeError::Invalid("section growth delta does not fit into u32".to_string())
            })?;
            let old_len = self.bytes.len();
            self.bytes.resize(old_len.saturating_add(delta), 0);
            self.bytes
                .copy_within(old_raw_end..old_len, old_raw_end.saturating_add(delta));
            self.bytes[old_raw_end..old_raw_end.saturating_add(delta)].fill(0);

            for i in (index + 1)..self.sections.len() {
                if self.sections[i].pointer_to_raw_data >= old_raw_end as u32
                    && self.sections[i].pointer_to_raw_data != 0
                {
                    let new_ptr = self.sections[i]
                        .pointer_to_raw_data
                        .checked_add(delta_u32)
                        .ok_or_else(|| {
                            PeError::Invalid(
                                "section pointer_to_raw_data overflow on payload growth"
                                    .to_string(),
                            )
                        })?;
                    let hdr = self
                        .section_table_offset
                        .checked_add(i * 40)
                        .ok_or_else(|| {
                            PeError::Invalid("section header offset overflow".to_string())
                        })?;
                    write_u32(&mut self.bytes, hdr + 20, new_ptr)?;
                    self.sections[i].pointer_to_raw_data = new_ptr;
                }
            }

            let symbol_table_ptr = read_u32(&self.bytes, self.file_header_offset + 8)?;
            if symbol_table_ptr >= old_raw_end as u32 && symbol_table_ptr != 0 {
                let new_symbol_ptr = symbol_table_ptr.checked_add(delta_u32).ok_or_else(|| {
                    PeError::Invalid("symbol table pointer overflow on payload growth".to_string())
                })?;
                write_u32(&mut self.bytes, self.file_header_offset + 8, new_symbol_ptr)?;
            }

            if self.number_of_rva_and_sizes > 4 {
                let security_directory_offset = self
                    .data_directory_offset
                    .checked_add(4 * 8)
                    .ok_or_else(|| {
                        PeError::Invalid("security directory offset overflow".to_string())
                    })?;
                let security_file_off = read_u32(&self.bytes, security_directory_offset)?;
                if security_file_off >= old_raw_end as u32 && security_file_off != 0 {
                    let new_security_file_off =
                        security_file_off.checked_add(delta_u32).ok_or_else(|| {
                            PeError::Invalid(
                                "security directory file offset overflow on payload growth"
                                    .to_string(),
                            )
                        })?;
                    write_u32(
                        &mut self.bytes,
                        security_directory_offset,
                        new_security_file_off,
                    )?;
                }
            }

            let hdr = self
                .section_table_offset
                .checked_add(index * 40)
                .ok_or_else(|| PeError::Invalid("section header offset overflow".to_string()))?;
            write_u32(&mut self.bytes, hdr + 16, new_raw_size_u32)?;
            self.sections[index].size_of_raw_data = new_raw_size_u32;
        }

        let effective_raw_size = self.sections[index].size_of_raw_data as usize;
        let raw_end = raw_off
            .checked_add(effective_raw_size)
            .ok_or_else(|| PeError::Invalid("section raw bounds overflow".to_string()))?;
        if raw_end > self.bytes.len() {
            return Err(PeError::Invalid(format!(
                "section '{name}' raw data exceeds file bounds after growth"
            )));
        }

        let used_end = raw_off
            .checked_add(payload.len())
            .ok_or_else(|| PeError::Invalid("payload bounds overflow".to_string()))?;
        self.bytes[raw_off..used_end].copy_from_slice(payload);
        if used_end < raw_end {
            self.bytes[used_end..raw_end].fill(0);
        }

        let old_virtual_size = self.sections[index].virtual_size;
        let new_virtual_size = max(old_virtual_size, payload.len() as u32);
        if new_virtual_size != old_virtual_size {
            let hdr = self
                .section_table_offset
                .checked_add(index * 40)
                .ok_or_else(|| PeError::Invalid("section header offset overflow".to_string()))?;
            write_u32(&mut self.bytes, hdr + 8, new_virtual_size)?;
            self.sections[index].virtual_size = new_virtual_size;
        }

        let max_end = self.sections.iter().fold(0u32, |acc, sec| {
            let end = sec
                .virtual_address
                .saturating_add(max(sec.virtual_size, sec.size_of_raw_data));
            acc.max(end)
        });
        let new_size_of_image = align_up(max_end, self.section_alignment);
        write_u32(
            &mut self.bytes,
            self.optional_header_offset + 56,
            new_size_of_image,
        )?;

        Ok(AddedSection {
            virtual_address: self.sections[index].virtual_address,
            virtual_size: self.sections[index].virtual_size,
            pointer_to_raw_data: self.sections[index].pointer_to_raw_data,
            size_of_raw_data: self.sections[index].size_of_raw_data,
        })
    }

    pub fn fill_rva_range(&mut self, start_rva: u32, size: u32, value: u8) -> Result<(), PeError> {
        if size == 0 {
            return Ok(());
        }

        let end_rva = start_rva
            .checked_add(size)
            .ok_or_else(|| PeError::Invalid("rva fill range overflow".to_string()))?;
        let mut mapped = 0u32;

        for section in &self.sections {
            if section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0 {
                continue;
            }

            let section_start = section.virtual_address;
            let section_end =
                section_start.saturating_add(max(section.virtual_size, section.size_of_raw_data));
            let overlap_start = max(start_rva, section_start);
            let overlap_end = min(end_rva, section_end);
            if overlap_start >= overlap_end {
                continue;
            }

            let section_delta = overlap_start.saturating_sub(section_start);
            if section_delta >= section.size_of_raw_data {
                continue;
            }

            let overlap_len = overlap_end.saturating_sub(overlap_start);
            let writable_len = min(overlap_len, section.size_of_raw_data - section_delta);
            if writable_len == 0 {
                continue;
            }

            let file_start = section
                .pointer_to_raw_data
                .checked_add(section_delta)
                .ok_or_else(|| PeError::Invalid("rva fill file offset overflow".to_string()))?
                as usize;
            let file_end = file_start
                .checked_add(writable_len as usize)
                .ok_or_else(|| PeError::Invalid("rva fill file end overflow".to_string()))?;
            if file_end > self.bytes.len() {
                return Err(PeError::Invalid(format!(
                    "rva fill out of bounds for section '{}' (rva 0x{:x})",
                    section.name, overlap_start
                )));
            }

            self.bytes[file_start..file_end].fill(value);
            mapped = mapped.saturating_add(writable_len);
        }

        if mapped != size {
            return Err(PeError::Invalid(format!(
                "rva fill could not map full range [0x{start_rva:x}, 0x{end_rva:x}) mapped={mapped} expected={size}"
            )));
        }

        Ok(())
    }

    pub fn set_entrypoint_rva(&mut self, rva: u32) -> Result<(), PeError> {
        write_u32(&mut self.bytes, self.optional_header_offset + 16, rva)
    }

    pub fn set_directory(&mut self, index: usize, rva: u32, size: u32) -> Result<(), PeError> {
        let entry_off = self
            .data_directory_offset
            .checked_add(index * 8)
            .ok_or_else(|| PeError::Invalid("directory offset overflow".to_string()))?;
        write_u32(&mut self.bytes, entry_off, rva)?;
        write_u32(&mut self.bytes, entry_off + 4, size)?;
        Ok(())
    }

    pub fn get_directory(&self, index: usize) -> Result<(u32, u32), PeError> {
        if index >= self.number_of_rva_and_sizes {
            return Ok((0, 0));
        }
        let entry_off = self
            .data_directory_offset
            .checked_add(index * 8)
            .ok_or_else(|| PeError::Invalid("directory offset overflow".to_string()))?;
        Ok((
            read_u32(&self.bytes, entry_off)?,
            read_u32(&self.bytes, entry_off + 4)?,
        ))
    }

    pub fn directories(&self) -> Result<Vec<DataDirectoryInfo>, PeError> {
        let mut out = Vec::with_capacity(self.number_of_rva_and_sizes);
        for index in 0..self.number_of_rva_and_sizes {
            let (virtual_address, size) = self.get_directory(index)?;
            out.push(DataDirectoryInfo {
                index,
                virtual_address,
                size,
            });
        }
        Ok(out)
    }

    fn load_config_layout(&self) -> Result<Option<LoadConfigLayout>, PeError> {
        let (rva, size) = self.get_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)?;
        if rva == 0 || size == 0 {
            return Ok(None);
        }

        let file_offset = self
            .rva_to_file_offset(rva)
            .ok_or_else(|| PeError::Invalid("load config rva invalid".to_string()))?;
        if file_offset + 4 > self.bytes.len() {
            return Err(PeError::Invalid("load config out of bounds".to_string()));
        }

        let size_in_header = read_u32(&self.bytes, file_offset)?;

        // IMAGE_LOAD_CONFIG_DIRECTORY64 (PE32+) offsets.
        // GuardCFFunctionTable: 0x80, GuardCFFunctionCount: 0x88, GuardFlags: 0x90.
        let guard_cf_function_table = if size_in_header >= 0x88 {
            read_u64(&self.bytes, file_offset + 0x80)?
        } else {
            0
        };
        let guard_cf_function_count = if size_in_header >= 0x90 {
            read_u64(&self.bytes, file_offset + 0x88)?
        } else {
            0
        };
        let guard_flags = if size_in_header >= 0x94 {
            read_u32(&self.bytes, file_offset + 0x90)?
        } else {
            0
        };
        // GuardEHContinuationTable: 0x108, GuardEHContinuationCount: 0x110.
        let guard_eh_continuation_table = if size_in_header >= 0x110 {
            read_u64(&self.bytes, file_offset + 0x108)?
        } else {
            0
        };
        let guard_eh_continuation_count = if size_in_header >= 0x118 {
            read_u64(&self.bytes, file_offset + 0x110)?
        } else {
            0
        };

        Ok(Some(LoadConfigLayout {
            size_in_directory: size,
            size_in_header,
            guard_cf_function_table,
            guard_cf_function_count,
            guard_flags,
            guard_eh_continuation_table,
            guard_eh_continuation_count,
        }))
    }

    pub fn load_config_summary(&self) -> Result<Option<LoadConfigSummary>, PeError> {
        let Some(layout) = self.load_config_layout()? else {
            return Ok(None);
        };

        Ok(Some(LoadConfigSummary {
            size: layout.size_in_directory.min(layout.size_in_header),
            guard_cf_function_table: if layout.guard_cf_function_table == 0 {
                None
            } else {
                Some(layout.guard_cf_function_table)
            },
            guard_cf_function_count: if layout.guard_cf_function_count == 0 {
                None
            } else {
                Some(layout.guard_cf_function_count)
            },
            guard_flags: if layout.guard_flags == 0 {
                None
            } else {
                Some(layout.guard_flags)
            },
            guard_eh_continuation_table: if layout.guard_eh_continuation_table == 0 {
                None
            } else {
                Some(layout.guard_eh_continuation_table)
            },
            guard_eh_continuation_count: if layout.guard_eh_continuation_count == 0 {
                None
            } else {
                Some(layout.guard_eh_continuation_count)
            },
        }))
    }

    pub fn parse_guard_cf_function_table(&self) -> Result<Option<GuardCfFunctionTable>, PeError> {
        let Some(layout) = self.load_config_layout()? else {
            return Ok(None);
        };

        if layout.guard_cf_function_table == 0 || layout.guard_cf_function_count == 0 {
            return Ok(None);
        }

        if layout.guard_cf_function_table < self.image_base {
            return Err(PeError::Invalid(format!(
                "guard cf table va 0x{:x} below image base 0x{:x}",
                layout.guard_cf_function_table, self.image_base
            )));
        }

        let table_rva_u64 = layout.guard_cf_function_table - self.image_base;
        let table_rva = u32::try_from(table_rva_u64).map_err(|_| {
            PeError::Invalid(format!(
                "guard cf table va 0x{:x} does not fit 32-bit rva",
                layout.guard_cf_function_table
            ))
        })?;

        let entry_size = guard_cf_entry_size_from_flags(layout.guard_flags)?;
        let count = usize::try_from(layout.guard_cf_function_count).map_err(|_| {
            PeError::Invalid(format!(
                "guard cf function count {} does not fit usize",
                layout.guard_cf_function_count
            ))
        })?;

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry_rva = table_rva
                .checked_add((i as u32).saturating_mul(entry_size))
                .ok_or_else(|| PeError::Invalid("guard cf table entry rva overflow".to_string()))?;
            let data = self.read_rva_slice(entry_rva, 4)?;
            entries.push(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
        }

        Ok(Some(GuardCfFunctionTable {
            table_rva,
            entry_count: layout.guard_cf_function_count,
            entry_size,
            guard_flags: layout.guard_flags,
            entries,
        }))
    }

    pub fn remap_guard_cf_function_table<F>(&mut self, mut remap: F) -> Result<usize, PeError>
    where
        F: FnMut(u32) -> u32,
    {
        let Some(table) = self.parse_guard_cf_function_table()? else {
            return Ok(0);
        };

        let entry_size = table.entry_size as usize;
        if entry_size < 4 {
            return Err(PeError::Invalid(format!(
                "invalid guard cf entry size {}",
                table.entry_size
            )));
        }

        #[derive(Debug, Clone)]
        struct GuardCfRecord {
            rva: u32,
            raw: Vec<u8>,
        }

        let mut records = Vec::<GuardCfRecord>::with_capacity(table.entries.len());
        let mut changed = 0usize;
        for idx in 0..table.entries.len() {
            let entry_rva = table
                .table_rva
                .checked_add((idx as u32).saturating_mul(table.entry_size))
                .ok_or_else(|| PeError::Invalid("guard cf patch entry rva overflow".to_string()))?;
            let mut raw = self.read_rva_slice(entry_rva, entry_size)?.to_vec();
            let old = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let next = remap(old);
            if next != old {
                changed += 1;
            }
            raw[0..4].copy_from_slice(&next.to_le_bytes());
            records.push(GuardCfRecord { rva: next, raw });
        }

        // Keep CFG target table sorted for loader expectations.
        records.sort_unstable_by_key(|r| r.rva);

        for (idx, record) in records.iter().enumerate() {
            let dst_entry_rva = table
                .table_rva
                .checked_add((idx as u32).saturating_mul(table.entry_size))
                .ok_or_else(|| PeError::Invalid("guard cf patch entry rva overflow".to_string()))?;
            let file_off = self.rva_to_file_offset(dst_entry_rva).ok_or_else(|| {
                PeError::Invalid(format!(
                    "guard cf table entry rva 0x{dst_entry_rva:x} is not mappable"
                ))
            })?;
            let end = file_off
                .checked_add(entry_size)
                .ok_or_else(|| PeError::Invalid("guard cf patch bounds overflow".to_string()))?;
            if end > self.bytes.len() {
                return Err(PeError::Invalid(
                    "guard cf patch entry exceeds file bounds".to_string(),
                ));
            }
            self.bytes[file_off..end].copy_from_slice(&record.raw);
        }

        Ok(changed)
    }

    pub fn parse_guard_eh_continuation_table(
        &self,
    ) -> Result<Option<GuardEhContinuationTable>, PeError> {
        let Some(layout) = self.load_config_layout()? else {
            return Ok(None);
        };

        if layout.guard_eh_continuation_table == 0 || layout.guard_eh_continuation_count == 0 {
            return Ok(None);
        }

        if layout.guard_eh_continuation_table < self.image_base {
            return Err(PeError::Invalid(format!(
                "guard eh continuation table va 0x{:x} below image base 0x{:x}",
                layout.guard_eh_continuation_table, self.image_base
            )));
        }

        let table_rva_u64 = layout.guard_eh_continuation_table - self.image_base;
        let table_rva = u32::try_from(table_rva_u64).map_err(|_| {
            PeError::Invalid(format!(
                "guard eh continuation table va 0x{:x} does not fit 32-bit rva",
                layout.guard_eh_continuation_table
            ))
        })?;

        let count = usize::try_from(layout.guard_eh_continuation_count).map_err(|_| {
            PeError::Invalid(format!(
                "guard eh continuation count {} does not fit usize",
                layout.guard_eh_continuation_count
            ))
        })?;
        let entry_size = guard_cf_entry_size_from_flags(layout.guard_flags)?;
        if entry_size < 4 {
            return Err(PeError::Invalid(format!(
                "invalid guard eh continuation entry size {}",
                entry_size
            )));
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry_rva = table_rva
                .checked_add((i as u32).saturating_mul(entry_size))
                .ok_or_else(|| {
                    PeError::Invalid("guard eh continuation entry rva overflow".to_string())
                })?;
            let data = self.read_rva_slice(entry_rva, 4)?;
            entries.push(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
        }

        Ok(Some(GuardEhContinuationTable {
            table_rva,
            entry_count: layout.guard_eh_continuation_count,
            entry_size,
            guard_flags: layout.guard_flags,
            entries,
        }))
    }

    pub fn remap_guard_eh_continuation_table<F>(&mut self, mut remap: F) -> Result<usize, PeError>
    where
        F: FnMut(u32) -> u32,
    {
        let Some(table) = self.parse_guard_eh_continuation_table()? else {
            return Ok(0);
        };

        let entry_size = table.entry_size as usize;
        if entry_size < 4 {
            return Err(PeError::Invalid(format!(
                "invalid guard eh continuation entry size {}",
                table.entry_size
            )));
        }

        #[derive(Debug, Clone)]
        struct GuardEhRecord {
            rva: u32,
            raw: Vec<u8>,
        }

        let mut records = Vec::<GuardEhRecord>::with_capacity(table.entries.len());
        let mut changed = 0usize;
        for idx in 0..table.entries.len() {
            let entry_rva = table
                .table_rva
                .checked_add((idx as u32).saturating_mul(table.entry_size))
                .ok_or_else(|| {
                    PeError::Invalid("guard eh continuation entry rva overflow".to_string())
                })?;
            let mut raw = self.read_rva_slice(entry_rva, entry_size)?.to_vec();
            let old = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let next = remap(old);
            if next != old {
                changed += 1;
            }
            raw[0..4].copy_from_slice(&next.to_le_bytes());
            records.push(GuardEhRecord { rva: next, raw });
        }

        // Keep loader lookup table sorted.
        records.sort_unstable_by_key(|r| r.rva);

        for (idx, record) in records.iter().enumerate() {
            let entry_rva = table
                .table_rva
                .checked_add((idx as u32).saturating_mul(table.entry_size))
                .ok_or_else(|| {
                    PeError::Invalid("guard eh continuation patch entry rva overflow".to_string())
                })?;
            let file_off = self.rva_to_file_offset(entry_rva).ok_or_else(|| {
                PeError::Invalid(format!(
                    "guard eh continuation entry rva 0x{entry_rva:x} is not mappable"
                ))
            })?;
            let end = file_off.checked_add(entry_size).ok_or_else(|| {
                PeError::Invalid("guard eh continuation patch bounds overflow".to_string())
            })?;
            if end > self.bytes.len() {
                return Err(PeError::Invalid(
                    "guard eh continuation patch entry exceeds file bounds".to_string(),
                ));
            }
            self.bytes[file_off..end].copy_from_slice(&record.raw);
        }

        Ok(changed)
    }

    fn ensure_section_header_capacity(
        &mut self,
        required_header_end: usize,
    ) -> Result<(), PeError> {
        let required_header_end = u32::try_from(required_header_end)
            .map_err(|_| PeError::Invalid("required header size exceeds u32".to_string()))?;
        let first_raw = self
            .sections
            .iter()
            .filter(|s| s.pointer_to_raw_data != 0)
            .map(|s| s.pointer_to_raw_data)
            .min()
            .unwrap_or(self.size_of_headers);

        if required_header_end <= first_raw {
            return Ok(());
        }

        let new_size_of_headers = align_up(required_header_end, self.file_alignment);
        if new_size_of_headers <= first_raw {
            self.size_of_headers = new_size_of_headers;
            write_u32(
                &mut self.bytes,
                self.optional_header_offset + 60,
                self.size_of_headers,
            )?;
            return Ok(());
        }

        let delta = new_size_of_headers.saturating_sub(first_raw);
        let first_raw_off = first_raw as usize;
        let delta_off = delta as usize;
        let old_len = self.bytes.len();
        self.bytes.resize(old_len.saturating_add(delta_off), 0);
        self.bytes
            .copy_within(first_raw_off..old_len, first_raw_off + delta_off);
        self.bytes[first_raw_off..first_raw_off + delta_off].fill(0);

        for index in 0..self.sections.len() {
            let hdr = self
                .section_table_offset
                .checked_add(index * 40)
                .ok_or_else(|| PeError::Invalid("section header offset overflow".to_string()))?;

            if self.sections[index].pointer_to_raw_data >= first_raw
                && self.sections[index].pointer_to_raw_data != 0
            {
                let next = self.sections[index]
                    .pointer_to_raw_data
                    .saturating_add(delta);
                self.sections[index].pointer_to_raw_data = next;
                write_u32(&mut self.bytes, hdr + 20, next)?;
            }

            let ptr_reloc = read_u32(&self.bytes, hdr + 24)?;
            if ptr_reloc >= first_raw && ptr_reloc != 0 {
                write_u32(&mut self.bytes, hdr + 24, ptr_reloc.saturating_add(delta))?;
            }

            let ptr_lines = read_u32(&self.bytes, hdr + 28)?;
            if ptr_lines >= first_raw && ptr_lines != 0 {
                write_u32(&mut self.bytes, hdr + 28, ptr_lines.saturating_add(delta))?;
            }
        }

        let symbol_table_ptr = read_u32(&self.bytes, self.file_header_offset + 8)?;
        if symbol_table_ptr >= first_raw && symbol_table_ptr != 0 {
            write_u32(
                &mut self.bytes,
                self.file_header_offset + 8,
                symbol_table_ptr.saturating_add(delta),
            )?;
        }

        if self.number_of_rva_and_sizes > 4 {
            let security_directory_offset = self
                .data_directory_offset
                .checked_add(4 * 8)
                .ok_or_else(|| {
                    PeError::Invalid("security directory offset overflow".to_string())
                })?;
            let security_file_off = read_u32(&self.bytes, security_directory_offset)?;
            if security_file_off >= first_raw && security_file_off != 0 {
                write_u32(
                    &mut self.bytes,
                    security_directory_offset,
                    security_file_off.saturating_add(delta),
                )?;
            }
        }

        self.size_of_headers = new_size_of_headers;
        write_u32(
            &mut self.bytes,
            self.optional_header_offset + 60,
            self.size_of_headers,
        )?;
        Ok(())
    }

    pub fn add_section(
        &mut self,
        name: &str,
        characteristics: u32,
        payload: &[u8],
    ) -> Result<AddedSection, PeError> {
        if name.is_empty() || name.len() > 8 {
            return Err(PeError::Invalid(format!(
                "section name '{}' must be 1..=8 bytes",
                name
            )));
        }

        let new_header_offset = self
            .section_table_offset
            .checked_add(self.number_of_sections * 40)
            .ok_or_else(|| PeError::Invalid("new section header offset overflow".to_string()))?;
        let needed_headers = new_header_offset + 40;
        self.ensure_section_header_capacity(needed_headers)?;

        let last = self
            .sections
            .last()
            .ok_or_else(|| PeError::Invalid("pe has no section".to_string()))?;

        let last_virtual_end = align_up(
            last.virtual_address
                .saturating_add(max(last.virtual_size, last.size_of_raw_data)),
            self.section_alignment,
        );
        let virtual_address = last_virtual_end;
        let virtual_size = payload.len() as u32;

        let current_file_size = self.bytes.len() as u32;
        let pointer_to_raw_data = align_up(current_file_size, self.file_alignment);
        let size_of_raw_data = align_up(virtual_size, self.file_alignment);

        if self.bytes.len() < pointer_to_raw_data as usize {
            self.bytes.resize(pointer_to_raw_data as usize, 0);
        }
        self.bytes.extend_from_slice(payload);
        if self.bytes.len() < pointer_to_raw_data.saturating_add(size_of_raw_data) as usize {
            self.bytes.resize(
                pointer_to_raw_data.saturating_add(size_of_raw_data) as usize,
                0,
            );
        }

        let mut name_bytes = [0u8; 8];
        name_bytes[..name.len()].copy_from_slice(name.as_bytes());

        let hdr = new_header_offset;
        self.bytes[hdr..hdr + 8].copy_from_slice(&name_bytes);
        write_u32(&mut self.bytes, hdr + 8, virtual_size)?;
        write_u32(&mut self.bytes, hdr + 12, virtual_address)?;
        write_u32(&mut self.bytes, hdr + 16, size_of_raw_data)?;
        write_u32(&mut self.bytes, hdr + 20, pointer_to_raw_data)?;
        write_u32(&mut self.bytes, hdr + 24, 0)?;
        write_u32(&mut self.bytes, hdr + 28, 0)?;
        write_u16(&mut self.bytes, hdr + 32, 0)?;
        write_u16(&mut self.bytes, hdr + 34, 0)?;
        write_u32(&mut self.bytes, hdr + 36, characteristics)?;

        self.number_of_sections += 1;
        write_u16(
            &mut self.bytes,
            self.file_header_offset + 2,
            self.number_of_sections as u16,
        )?;

        let new_size_of_image = align_up(
            virtual_address.saturating_add(max(virtual_size, size_of_raw_data)),
            self.section_alignment,
        );
        write_u32(
            &mut self.bytes,
            self.optional_header_offset + 56,
            new_size_of_image,
        )?;

        let section = SectionInfo {
            name: name.to_string(),
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
            characteristics,
        };
        self.sections.push(section);

        Ok(AddedSection {
            virtual_address,
            virtual_size,
            pointer_to_raw_data,
            size_of_raw_data,
        })
    }

    pub fn parse_import_directory(&self) -> Result<Vec<ImportEntry>, PeError> {
        let (import_rva, import_size) = self.get_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)?;
        if import_rva == 0 || import_size == 0 {
            return Ok(Vec::new());
        }

        let start = self
            .rva_to_file_offset(import_rva)
            .ok_or_else(|| PeError::Invalid("import directory rva is invalid".to_string()))?;
        let max_end = start
            .checked_add(import_size as usize)
            .ok_or_else(|| PeError::Invalid("import directory size overflow".to_string()))?;
        let end = max_end.min(self.bytes.len());
        if start >= end {
            return Ok(Vec::new());
        }

        let mut out = Vec::<ImportEntry>::new();
        let mut desc_off = start;
        while desc_off + 20 <= end {
            let original_first_thunk = read_u32(&self.bytes, desc_off)?;
            let _time_date_stamp = read_u32(&self.bytes, desc_off + 4)?;
            let _forwarder_chain = read_u32(&self.bytes, desc_off + 8)?;
            let name_rva = read_u32(&self.bytes, desc_off + 12)?;
            let first_thunk = read_u32(&self.bytes, desc_off + 16)?;

            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            if first_thunk == 0 {
                return Err(PeError::Invalid(format!(
                    "invalid import descriptor at offset 0x{desc_off:x}: first_thunk is zero"
                )));
            }

            let dll_name = self.read_rva_c_string(name_rva)?;
            let lookup_table_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            let mut functions = Vec::<ImportedFn>::new();
            let mut thunk_index = 0u32;
            loop {
                let lookup_rva = lookup_table_rva.saturating_add(thunk_index.saturating_mul(8));
                let lookup_off = self.rva_to_file_offset(lookup_rva).ok_or_else(|| {
                    PeError::Invalid(format!(
                        "import thunk lookup rva 0x{lookup_rva:x} is invalid"
                    ))
                })?;
                let lookup_value = read_u64(&self.bytes, lookup_off)?;
                if lookup_value == 0 {
                    break;
                }

                let iat_rva = first_thunk.saturating_add(thunk_index.saturating_mul(8));
                let is_ordinal = (lookup_value & 0x8000_0000_0000_0000) != 0;
                if is_ordinal {
                    let ordinal = (lookup_value & 0xFFFF) as u16;
                    functions.push(ImportedFn {
                        name: None,
                        ordinal: Some(ordinal),
                        iat_rva,
                    });
                } else {
                    let import_by_name_rva = u32::try_from(lookup_value).map_err(|_| {
                        PeError::Invalid(format!(
                            "import-by-name rva out of range: 0x{lookup_value:x}"
                        ))
                    })?;
                    let name = self.parse_import_name(import_by_name_rva)?;
                    functions.push(ImportedFn {
                        name: Some(name),
                        ordinal: None,
                        iat_rva,
                    });
                }

                thunk_index = thunk_index.saturating_add(1);
            }

            out.push(ImportEntry {
                dll_name,
                functions,
            });
            desc_off += 20;
        }

        Ok(out)
    }

    pub fn zero_iat_entries(&mut self, iat_rvas: &[u32]) -> Result<(), PeError> {
        for rva in iat_rvas {
            let off = self
                .rva_to_file_offset(*rva)
                .ok_or_else(|| PeError::Invalid(format!("iat rva 0x{rva:x} is invalid")))?;
            let end = off
                .checked_add(8)
                .ok_or_else(|| PeError::Invalid("iat zeroing offset overflow".to_string()))?;
            if end > self.bytes.len() {
                return Err(PeError::Invalid(format!(
                    "iat zeroing out of bounds for rva 0x{rva:x}"
                )));
            }
            self.bytes[off..end].fill(0);
        }
        Ok(())
    }

    pub fn parse_relocations(&self) -> Result<Vec<RelocEntry>, PeError> {
        let (reloc_rva, reloc_size) = self.get_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)?;
        if reloc_rva == 0 || reloc_size == 0 {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let start_off = self
            .rva_to_file_offset(reloc_rva)
            .ok_or_else(|| PeError::Invalid("reloc directory rva is invalid".to_string()))?;
        let end_off = start_off
            .checked_add(reloc_size as usize)
            .ok_or_else(|| PeError::Invalid("reloc directory size overflow".to_string()))?;
        if end_off > self.bytes.len() {
            return Err(PeError::Invalid(
                "reloc directory out of bounds".to_string(),
            ));
        }

        let mut off = start_off;
        while off + 8 <= end_off {
            let page_rva = read_u32(&self.bytes, off)?;
            let block_size = read_u32(&self.bytes, off + 4)? as usize;
            if block_size < 8 {
                break;
            }
            if off + block_size > end_off {
                return Err(PeError::Invalid(
                    "reloc block exceeds directory size".to_string(),
                ));
            }

            let count = (block_size - 8) / 2;
            for i in 0..count {
                let eoff = off + 8 + (i * 2);
                let raw = read_u16(&self.bytes, eoff)?;
                let typ = raw >> 12;
                let delta = (raw & 0x0fff) as u32;
                if typ == RELOC_TYPE_ABSOLUTE {
                    continue;
                }
                entries.push(RelocEntry {
                    rva: page_rva.saturating_add(delta),
                    typ,
                });
            }

            off += block_size;
        }

        Ok(entries)
    }

    pub fn emit_relocations(entries: &[RelocEntry]) -> Vec<u8> {
        let mut by_page: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
        for e in entries {
            let page = e.rva & !0xfff;
            let offset = e.rva & 0xfff;
            let word = ((e.typ & 0x000f) << 12) | (offset as u16 & 0x0fff);
            by_page.entry(page).or_default().push(word);
        }

        let mut out = Vec::new();
        for (page, mut words) in by_page {
            words.sort_unstable();
            if words.len() % 2 != 0 {
                words.push((RELOC_TYPE_ABSOLUTE << 12) | 0);
            }

            let block_size = 8u32 + (words.len() as u32 * 2);
            out.extend_from_slice(&page.to_le_bytes());
            out.extend_from_slice(&block_size.to_le_bytes());
            for w in words {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }

        out
    }

    pub fn parse_runtime_functions(&self) -> Result<Vec<RuntimeFunctionEntry>, PeError> {
        let (rva, size) = self.get_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;
        if rva == 0 || size == 0 {
            return Ok(Vec::new());
        }

        if size % 12 != 0 {
            return Err(PeError::Invalid(format!(
                "exception directory size {size} is not multiple of 12"
            )));
        }

        let start = self
            .rva_to_file_offset(rva)
            .ok_or_else(|| PeError::Invalid("exception directory rva invalid".to_string()))?;
        let end = start
            .checked_add(size as usize)
            .ok_or_else(|| PeError::Invalid("exception directory size overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(PeError::Invalid(
                "exception directory out of bounds".to_string(),
            ));
        }

        let mut out = Vec::with_capacity((size / 12) as usize);
        let mut off = start;
        while off + 12 <= end {
            out.push(RuntimeFunctionEntry {
                begin_address: read_u32(&self.bytes, off)?,
                end_address: read_u32(&self.bytes, off + 4)?,
                unwind_info_address: read_u32(&self.bytes, off + 8)?,
            });
            off += 12;
        }

        Ok(out)
    }

    pub fn parse_unwind_info_summary(
        &self,
        unwind_info_rva: u32,
    ) -> Result<UnwindInfoSummary, PeError> {
        let header = self.read_rva_slice(unwind_info_rva, 4)?;
        let flags = header[0] >> 3;
        let count_of_codes = header[2] as u32;

        let mut size = 4u32 + count_of_codes * 2;
        size = align_up(size, 4);

        if (flags & UNW_FLAG_CHAININFO) != 0 {
            size = size.saturating_add(12);
        }

        let supports_safe_clone =
            (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO)) == 0;

        Ok(UnwindInfoSummary {
            flags,
            size,
            supports_safe_clone,
        })
    }

    pub fn parse_unwind_record(
        &self,
        unwind_info_rva: u32,
        next_unwind_rva: Option<u32>,
    ) -> Result<UnwindRecord, PeError> {
        let header = self.read_rva_slice(unwind_info_rva, 4)?;
        let flags = header[0] >> 3;
        let prolog_size = header[1];
        let count_of_codes = header[2];
        let mut aligned_codes_size = 4u32 + (count_of_codes as u32) * 2;
        aligned_codes_size = align_up(aligned_codes_size, 4);

        let has_chain = (flags & UNW_FLAG_CHAININFO) != 0;
        let has_handler = (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 && !has_chain;

        let mut full_size = aligned_codes_size;
        let mut chained_entry = None;
        let mut exception_handler_rva = None;

        if has_chain {
            let chain_off_rva = unwind_info_rva.saturating_add(aligned_codes_size);
            let chain = self.read_rva_slice(chain_off_rva, 12)?;
            chained_entry = Some(RuntimeFunctionEntry {
                begin_address: u32::from_le_bytes(chain[0..4].try_into().unwrap_or([0u8; 4])),
                end_address: u32::from_le_bytes(chain[4..8].try_into().unwrap_or([0u8; 4])),
                unwind_info_address: u32::from_le_bytes(
                    chain[8..12].try_into().unwrap_or([0u8; 4]),
                ),
            });
            full_size = full_size.saturating_add(12);
        } else if has_handler {
            let handler_off_rva = unwind_info_rva.saturating_add(aligned_codes_size);
            let handler = self.read_rva_slice(handler_off_rva, 4)?;
            exception_handler_rva = Some(u32::from_le_bytes(
                handler[0..4].try_into().unwrap_or([0u8; 4]),
            ));
            full_size = full_size.saturating_add(4);

            // Language specific data length is variable. Use the next known xdata record
            // boundary when available, otherwise keep minimal handler payload.
            if let Some(next) = next_unwind_rva {
                if next > unwind_info_rva.saturating_add(full_size) {
                    full_size = next.saturating_sub(unwind_info_rva);
                }
            }
        }

        if let Some(sec) = self.section_for_rva(unwind_info_rva) {
            let sec_end = sec
                .virtual_address
                .saturating_add(max(sec.virtual_size, sec.size_of_raw_data));
            let max_size = sec_end.saturating_sub(unwind_info_rva);
            full_size = full_size.min(max_size);
        }

        Ok(UnwindRecord {
            unwind_rva: unwind_info_rva,
            flags,
            prolog_size,
            count_of_codes,
            aligned_codes_size,
            full_size,
            chained_entry,
            exception_handler_rva,
        })
    }

    pub fn parse_unwind_records_from_runtime(
        &self,
        runtime_entries: &[RuntimeFunctionEntry],
    ) -> Result<Vec<UnwindRecord>, PeError> {
        let mut unwind_rvas = runtime_entries
            .iter()
            .map(|e| e.unwind_info_address)
            .collect::<Vec<_>>();
        unwind_rvas.sort_unstable();
        unwind_rvas.dedup();

        let mut out = Vec::with_capacity(unwind_rvas.len());
        for (idx, rva) in unwind_rvas.iter().copied().enumerate() {
            let next = unwind_rvas.get(idx + 1).copied();
            out.push(self.parse_unwind_record(rva, next)?);
        }
        Ok(out)
    }

    pub fn read_unwind_record_bytes(&self, record: &UnwindRecord) -> Result<Vec<u8>, PeError> {
        let data = self.read_rva_slice(record.unwind_rva, record.full_size as usize)?;
        Ok(data.to_vec())
    }

    pub fn clone_unwind_info_if_safe(
        &self,
        unwind_info_rva: u32,
    ) -> Result<Option<Vec<u8>>, PeError> {
        let summary = self.parse_unwind_info_summary(unwind_info_rva)?;
        if !summary.supports_safe_clone {
            return Ok(None);
        }

        let data = self.read_rva_slice(unwind_info_rva, summary.size as usize)?;
        Ok(Some(data.to_vec()))
    }

    pub fn write_directory_blob(
        &mut self,
        dir_index: usize,
        default_name: &str,
        section_characteristics: u32,
        blob: &[u8],
    ) -> Result<AddedSection, PeError> {
        let section = self.add_section(default_name, section_characteristics, blob)?;
        self.set_directory(dir_index, section.virtual_address, blob.len() as u32)?;
        Ok(section)
    }

    pub fn is_supported_reloc_type(typ: u16) -> bool {
        typ == RELOC_TYPE_DIR64 || typ == RELOC_TYPE_ABSOLUTE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_pe(mut bytes: Vec<u8>) -> PeFile {
        if bytes.len() < 0x1000 {
            bytes.resize(0x1000, 0);
        }

        PeFile {
            bytes,
            file_header_offset: 0,
            optional_header_offset: 0,
            data_directory_offset: 0,
            number_of_rva_and_sizes: 16,
            section_table_offset: 0,
            number_of_sections: 0,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            size_of_headers: 0x1000,
            image_base: 0x140000000,
            characteristics: 0,
            subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI,
            sections: Vec::new(),
        }
    }

    #[test]
    fn classify_binary_kind_variants() {
        assert_eq!(
            classify_binary_kind(IMAGE_SUBSYSTEM_WINDOWS_GUI),
            PeBinaryKind::UserMode
        );
        assert_eq!(
            classify_binary_kind(IMAGE_SUBSYSTEM_WINDOWS_CUI),
            PeBinaryKind::UserMode
        );
        assert_eq!(
            classify_binary_kind(IMAGE_SUBSYSTEM_NATIVE),
            PeBinaryKind::KernelDriver
        );
        assert_eq!(
            classify_binary_kind(IMAGE_SUBSYSTEM_EFI_APPLICATION),
            PeBinaryKind::Uefi
        );
        assert_eq!(
            classify_binary_kind(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER),
            PeBinaryKind::Uefi
        );
        assert_eq!(
            classify_binary_kind(IMAGE_SUBSYSTEM_EFI_ROM),
            PeBinaryKind::Uefi
        );
        assert_eq!(classify_binary_kind(0), PeBinaryKind::Unknown);
    }

    #[test]
    fn overwrite_section_payload_can_grow_and_shift_following_offsets() {
        let mut pe = make_test_pe(vec![0u8; 0x2000]);
        pe.file_header_offset = 0x80;
        pe.optional_header_offset = 0x100;
        pe.data_directory_offset = 0x180;
        pe.section_table_offset = 0x200;
        pe.number_of_sections = 2;
        pe.file_alignment = 0x200;
        pe.section_alignment = 0x1000;
        pe.sections = vec![
            SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x180,
                pointer_to_raw_data: 0x400,
                size_of_raw_data: 0x200,
                characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            },
            SectionInfo {
                name: ".rdata".to_string(),
                virtual_address: 0x2000,
                virtual_size: 0x180,
                pointer_to_raw_data: 0x600,
                size_of_raw_data: 0x200,
                characteristics: IMAGE_SCN_MEM_READ,
            },
        ];

        let text_hdr = pe.section_table_offset;
        write_u32(&mut pe.bytes, text_hdr + 8, 0x180).expect("write text virtual_size");
        write_u32(&mut pe.bytes, text_hdr + 12, 0x1000).expect("write text virtual_address");
        write_u32(&mut pe.bytes, text_hdr + 16, 0x200).expect("write text size_of_raw_data");
        write_u32(&mut pe.bytes, text_hdr + 20, 0x400).expect("write text pointer_to_raw_data");

        let rdata_hdr = pe.section_table_offset + 40;
        write_u32(&mut pe.bytes, rdata_hdr + 8, 0x180).expect("write rdata virtual_size");
        write_u32(&mut pe.bytes, rdata_hdr + 12, 0x2000).expect("write rdata virtual_address");
        write_u32(&mut pe.bytes, rdata_hdr + 16, 0x200).expect("write rdata size_of_raw_data");
        write_u32(&mut pe.bytes, rdata_hdr + 20, 0x600).expect("write rdata pointer_to_raw_data");

        // OptionalHeader.SizeOfImage
        write_u32(&mut pe.bytes, pe.optional_header_offset + 56, 0x3000)
            .expect("write initial size_of_image");

        // COFF symbol table pointer (file offset).
        write_u32(&mut pe.bytes, pe.file_header_offset + 8, 0x880)
            .expect("write initial symbol table pointer");
        // Security directory entry (index 4) uses file offsets.
        write_u32(&mut pe.bytes, pe.data_directory_offset + 4 * 8, 0x900)
            .expect("write security directory file offset");
        write_u32(&mut pe.bytes, pe.data_directory_offset + 4 * 8 + 4, 0x40)
            .expect("write security directory size");

        pe.bytes[0x400..0x600].fill(0x11);
        pe.bytes[0x600..0x800].fill(0x22);

        let payload = vec![0xAB; 0x500]; // aligned raw growth: 0x200 -> 0x600
        let added = pe
            .overwrite_section_payload(".text", &payload)
            .expect("overwrite payload");

        assert_eq!(added.size_of_raw_data, 0x600);
        assert_eq!(pe.sections[0].size_of_raw_data, 0x600);
        assert_eq!(pe.sections[0].virtual_size, 0x500);
        assert_eq!(pe.sections[1].pointer_to_raw_data, 0xA00);
        assert_eq!(
            read_u32(&pe.bytes, rdata_hdr + 20).expect("read shifted rdata pointer"),
            0xA00
        );
        assert_eq!(
            read_u32(&pe.bytes, pe.file_header_offset + 8).expect("read shifted symbol pointer"),
            0xC80
        );
        assert_eq!(
            read_u32(&pe.bytes, pe.data_directory_offset + 4 * 8)
                .expect("read shifted security file offset"),
            0xD00
        );
        assert_eq!(pe.bytes[0x400], 0xAB);
        assert_eq!(pe.bytes[0x400 + 0x4ff], 0xAB);
        assert_eq!(pe.bytes[0x400 + 0x500], 0x00);
        assert_eq!(pe.bytes[0xA00], 0x22);
        assert_eq!(pe.size_of_image().expect("read size_of_image"), 0x3000);
    }

    #[test]
    fn overwrite_section_payload_rejects_virtual_span_overflow() {
        let mut pe = make_test_pe(vec![0u8; 0x3000]);
        pe.section_table_offset = 0x200;
        pe.number_of_sections = 2;
        pe.file_alignment = 0x200;
        pe.section_alignment = 0x1000;
        pe.sections = vec![
            SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x180,
                pointer_to_raw_data: 0x400,
                size_of_raw_data: 0x200,
                characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            },
            SectionInfo {
                name: ".rdata".to_string(),
                virtual_address: 0x2000,
                virtual_size: 0x180,
                pointer_to_raw_data: 0x600,
                size_of_raw_data: 0x200,
                characteristics: IMAGE_SCN_MEM_READ,
            },
        ];

        // Gap between 0x1000 and 0x2000 is 0x1000 bytes. This payload exceeds it.
        let payload = vec![0xCC; 0x1001];
        let err = pe
            .overwrite_section_payload(".text", &payload)
            .expect_err("must reject payload that would overlap the next section VA");
        assert!(matches!(err, PeError::Unsupported(_)));
    }

    #[test]
    fn rebuild_with_sections_rewrites_section_table_and_payloads() {
        let mut pe = make_test_pe(vec![0u8; 0x3000]);
        pe.file_header_offset = 0x80;
        pe.optional_header_offset = 0x100;
        pe.data_directory_offset = 0x180;
        pe.section_table_offset = 0x200;
        pe.number_of_sections = 2;
        pe.file_alignment = 0x200;
        pe.section_alignment = 0x1000;
        pe.sections = vec![
            SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x180,
                pointer_to_raw_data: 0x400,
                size_of_raw_data: 0x200,
                characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            },
            SectionInfo {
                name: ".rdata".to_string(),
                virtual_address: 0x2000,
                virtual_size: 0x180,
                pointer_to_raw_data: 0x600,
                size_of_raw_data: 0x200,
                characteristics: IMAGE_SCN_MEM_READ,
            },
        ];
        write_u32(&mut pe.bytes, pe.file_header_offset + 8, 0x900).expect("write symbol table ptr");
        write_u32(&mut pe.bytes, pe.file_header_offset + 12, 12).expect("write symbol count");
        write_u32(&mut pe.bytes, pe.data_directory_offset + 4 * 8, 0x1200)
            .expect("write cert table file off");
        write_u32(&mut pe.bytes, pe.data_directory_offset + 4 * 8 + 4, 0x80)
            .expect("write cert table size");

        let specs = vec![
            RebuildSectionSpec {
                name: ".text".to_string(),
                virtual_address: 0x4000,
                virtual_size: 0x350,
                characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
                payload: vec![0x90; 0x350],
            },
            RebuildSectionSpec {
                name: ".rdata".to_string(),
                virtual_address: 0x5000,
                virtual_size: 0x40,
                characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                payload: vec![0x41; 0x40],
            },
        ];

        pe.rebuild_with_sections(specs).expect("rebuild sections");

        assert_eq!(pe.sections.len(), 2);
        assert_eq!(pe.sections[0].name, ".text");
        assert_eq!(pe.sections[0].virtual_address, 0x4000);
        assert_eq!(pe.sections[1].name, ".rdata");
        assert_eq!(pe.sections[1].virtual_address, 0x5000);
        assert_eq!(
            read_u16(&pe.bytes, pe.file_header_offset + 2).expect("read section count"),
            2
        );
        assert_eq!(
            read_u32(&pe.bytes, pe.file_header_offset + 8).expect("read sym ptr"),
            0
        );
        assert_eq!(
            read_u32(&pe.bytes, pe.file_header_offset + 12).expect("read sym cnt"),
            0
        );
        assert_eq!(
            read_u32(&pe.bytes, pe.data_directory_offset + 4 * 8).expect("read cert file off"),
            0
        );
        assert_eq!(
            read_u32(&pe.bytes, pe.data_directory_offset + 4 * 8 + 4).expect("read cert size"),
            0
        );

        let text_payload = pe.section_payload(".text").expect("read text payload");
        assert_eq!(text_payload[0], 0x90);
        assert_eq!(text_payload[0x34F], 0x90);
    }

    #[test]
    fn reloc_emit_has_block_header() {
        let entries = vec![
            RelocEntry {
                rva: 0x2000,
                typ: 10,
            },
            RelocEntry {
                rva: 0x2008,
                typ: 10,
            },
        ];
        let blob = PeFile::emit_relocations(&entries);
        assert!(blob.len() >= 12);
        assert_eq!(u32::from_le_bytes(blob[0..4].try_into().unwrap()), 0x2000);
    }

    #[test]
    fn parse_unwind_chaininfo_record() {
        let mut bytes = vec![0u8; 0x1000];
        let rva = 0x200usize;

        // version=1, flags=CHAININFO(0x4) => byte0 = version | (flags<<3)
        bytes[rva] = 1 | (UNW_FLAG_CHAININFO << 3);
        bytes[rva + 1] = 4; // prolog
        bytes[rva + 2] = 2; // count of unwind codes
        bytes[rva + 3] = 0;
        // 2 unwind codes (4 bytes), aligned already.
        bytes[rva + 4] = 0x11;
        bytes[rva + 5] = 0x22;
        bytes[rva + 6] = 0x33;
        bytes[rva + 7] = 0x44;
        // chained runtime function entry
        bytes[rva + 8..rva + 12].copy_from_slice(&0x1234u32.to_le_bytes());
        bytes[rva + 12..rva + 16].copy_from_slice(&0x1278u32.to_le_bytes());
        bytes[rva + 16..rva + 20].copy_from_slice(&0x2200u32.to_le_bytes());

        let pe = make_test_pe(bytes);
        let rec = pe.parse_unwind_record(0x200, None).expect("parse unwind");
        assert_eq!(rec.flags, UNW_FLAG_CHAININFO);
        assert_eq!(rec.full_size, 20);
        assert!(rec.chained_entry.is_some());
    }

    #[test]
    fn parse_unwind_handler_record_uses_next_boundary() {
        let mut bytes = vec![0u8; 0x1000];
        let rva = 0x240usize;

        // version=1, flags=EHANDLER(0x1)
        bytes[rva] = 1 | (UNW_FLAG_EHANDLER << 3);
        bytes[rva + 1] = 3;
        bytes[rva + 2] = 0; // no unwind codes
        bytes[rva + 3] = 0;
        bytes[rva + 4..rva + 8].copy_from_slice(&0x8888u32.to_le_bytes()); // handler rva
        // emulate LSDA until next unwind record at 0x260
        bytes[rva + 8..0x260].fill(0xAA);

        let pe = make_test_pe(bytes);
        let rec = pe
            .parse_unwind_record(0x240, Some(0x260))
            .expect("parse unwind");
        assert_eq!(rec.flags, UNW_FLAG_EHANDLER);
        assert_eq!(rec.full_size, 0x20);
        assert_eq!(rec.exception_handler_rva, Some(0x8888));
    }

    #[test]
    fn parse_guard_cf_table_entries() {
        let mut bytes = vec![0u8; 0x1000];
        let load_config_rva = 0x300usize;
        let table_rva = 0x3c0usize;

        // DataDirectory[LOAD_CONFIG] at index 10, entry offset = 10 * 8.
        bytes[80..84].copy_from_slice(&(load_config_rva as u32).to_le_bytes());
        bytes[84..88].copy_from_slice(&0xA0u32.to_le_bytes());

        bytes[load_config_rva..load_config_rva + 4].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[load_config_rva + 0x80..load_config_rva + 0x88]
            .copy_from_slice(&(0x140000000u64 + table_rva as u64).to_le_bytes());
        bytes[load_config_rva + 0x88..load_config_rva + 0x90].copy_from_slice(&3u64.to_le_bytes());
        bytes[load_config_rva + 0x90..load_config_rva + 0x94].copy_from_slice(&0u32.to_le_bytes());

        bytes[table_rva..table_rva + 4].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[table_rva + 4..table_rva + 8].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[table_rva + 8..table_rva + 12].copy_from_slice(&0x1300u32.to_le_bytes());

        let pe = make_test_pe(bytes);
        let table = pe
            .parse_guard_cf_function_table()
            .expect("parse guard cf table")
            .expect("table present");
        assert_eq!(table.table_rva, table_rva as u32);
        assert_eq!(table.entry_count, 3);
        assert_eq!(table.entry_size, 4);
        assert_eq!(table.entries, vec![0x1100, 0x1200, 0x1300]);
    }

    #[test]
    fn remap_guard_cf_table_entries_sorted() {
        let mut bytes = vec![0u8; 0x1000];
        let load_config_rva = 0x300usize;
        let table_rva = 0x3c0usize;

        bytes[80..84].copy_from_slice(&(load_config_rva as u32).to_le_bytes());
        bytes[84..88].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[load_config_rva..load_config_rva + 4].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[load_config_rva + 0x80..load_config_rva + 0x88]
            .copy_from_slice(&(0x140000000u64 + table_rva as u64).to_le_bytes());
        bytes[load_config_rva + 0x88..load_config_rva + 0x90].copy_from_slice(&3u64.to_le_bytes());
        bytes[load_config_rva + 0x90..load_config_rva + 0x94].copy_from_slice(&0u32.to_le_bytes());

        bytes[table_rva..table_rva + 4].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[table_rva + 4..table_rva + 8].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[table_rva + 8..table_rva + 12].copy_from_slice(&0x1200u32.to_le_bytes());

        let mut pe = make_test_pe(bytes);
        let changed = pe
            .remap_guard_cf_function_table(|rva| if rva == 0x1200 { 0x1400 } else { rva })
            .expect("remap guard cf table");
        assert_eq!(changed, 1);

        let table = pe
            .parse_guard_cf_function_table()
            .expect("parse guard cf table")
            .expect("table present");
        assert_eq!(table.entries, vec![0x1100, 0x1300, 0x1400]);
    }

    #[test]
    fn remap_guard_cf_extended_entries_preserve_payload() {
        let mut bytes = vec![0u8; 0x1000];
        let load_config_rva = 0x300usize;
        let table_rva = 0x3c0usize;

        bytes[80..84].copy_from_slice(&(load_config_rva as u32).to_le_bytes());
        bytes[84..88].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[load_config_rva..load_config_rva + 4].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[load_config_rva + 0x80..load_config_rva + 0x88]
            .copy_from_slice(&(0x140000000u64 + table_rva as u64).to_le_bytes());
        bytes[load_config_rva + 0x88..load_config_rva + 0x90].copy_from_slice(&3u64.to_le_bytes());
        // high nibble = 2 => entry size = 4 + 2 = 6 bytes
        bytes[load_config_rva + 0x90..load_config_rva + 0x94]
            .copy_from_slice(&0x2000_0000u32.to_le_bytes());

        // entry 0: rva=0x1300, payload=0xA1 0x01
        bytes[table_rva..table_rva + 4].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[table_rva + 4] = 0xA1;
        bytes[table_rva + 5] = 0x01;
        // entry 1: rva=0x1100, payload=0xB2 0x02
        bytes[table_rva + 6..table_rva + 10].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[table_rva + 10] = 0xB2;
        bytes[table_rva + 11] = 0x02;
        // entry 2: rva=0x1200, payload=0xC3 0x03
        bytes[table_rva + 12..table_rva + 16].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[table_rva + 16] = 0xC3;
        bytes[table_rva + 17] = 0x03;

        let mut pe = make_test_pe(bytes);
        let parsed = pe
            .parse_guard_cf_function_table()
            .expect("parse guard cf table")
            .expect("table present");
        assert_eq!(parsed.entry_size, 6);
        assert_eq!(parsed.entries, vec![0x1300, 0x1100, 0x1200]);

        let changed = pe
            .remap_guard_cf_function_table(|rva| if rva == 0x1200 { 0x1400 } else { rva })
            .expect("remap guard cf table");
        assert_eq!(changed, 1);

        let table = pe
            .parse_guard_cf_function_table()
            .expect("parse guard cf table")
            .expect("table present");
        assert_eq!(table.entry_size, 6);
        assert_eq!(table.entries, vec![0x1100, 0x1300, 0x1400]);

        let raw = pe
            .read_rva_slice(table_rva as u32, 18)
            .expect("read remapped guard cf table");
        assert_eq!(raw[4], 0xB2);
        assert_eq!(raw[5], 0x02);
        assert_eq!(raw[10], 0xA1);
        assert_eq!(raw[11], 0x01);
        assert_eq!(raw[16], 0xC3);
        assert_eq!(raw[17], 0x03);
    }

    #[test]
    fn parse_guard_eh_continuation_table_entries() {
        let mut bytes = vec![0u8; 0x1000];
        let load_config_rva = 0x300usize;
        let table_rva = 0x480usize;

        bytes[80..84].copy_from_slice(&(load_config_rva as u32).to_le_bytes());
        bytes[84..88].copy_from_slice(&0x140u32.to_le_bytes());
        bytes[load_config_rva..load_config_rva + 4].copy_from_slice(&0x140u32.to_le_bytes());
        bytes[load_config_rva + 0x108..load_config_rva + 0x110]
            .copy_from_slice(&(0x140000000u64 + table_rva as u64).to_le_bytes());
        bytes[load_config_rva + 0x110..load_config_rva + 0x118]
            .copy_from_slice(&3u64.to_le_bytes());

        bytes[table_rva..table_rva + 4].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[table_rva + 4..table_rva + 8].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[table_rva + 8..table_rva + 12].copy_from_slice(&0x1200u32.to_le_bytes());

        let pe = make_test_pe(bytes);
        let table = pe
            .parse_guard_eh_continuation_table()
            .expect("parse guard eh continuation table")
            .expect("table present");
        assert_eq!(table.table_rva, table_rva as u32);
        assert_eq!(table.entry_count, 3);
        assert_eq!(table.entries, vec![0x1300, 0x1100, 0x1200]);
    }

    #[test]
    fn remap_guard_eh_continuation_table_entries_sorted() {
        let mut bytes = vec![0u8; 0x1000];
        let load_config_rva = 0x300usize;
        let table_rva = 0x480usize;

        bytes[80..84].copy_from_slice(&(load_config_rva as u32).to_le_bytes());
        bytes[84..88].copy_from_slice(&0x140u32.to_le_bytes());
        bytes[load_config_rva..load_config_rva + 4].copy_from_slice(&0x140u32.to_le_bytes());
        bytes[load_config_rva + 0x108..load_config_rva + 0x110]
            .copy_from_slice(&(0x140000000u64 + table_rva as u64).to_le_bytes());
        bytes[load_config_rva + 0x110..load_config_rva + 0x118]
            .copy_from_slice(&3u64.to_le_bytes());

        bytes[table_rva..table_rva + 4].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[table_rva + 4..table_rva + 8].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[table_rva + 8..table_rva + 12].copy_from_slice(&0x1200u32.to_le_bytes());

        let mut pe = make_test_pe(bytes);
        let changed = pe
            .remap_guard_eh_continuation_table(|rva| if rva == 0x1200 { 0x1400 } else { rva })
            .expect("remap guard eh continuation table");
        assert_eq!(changed, 1);

        let table = pe
            .parse_guard_eh_continuation_table()
            .expect("parse guard eh continuation table")
            .expect("table present");
        assert_eq!(table.entries, vec![0x1100, 0x1300, 0x1400]);
    }

    #[test]
    fn remap_guard_eh_continuation_extended_entries_preserve_payload() {
        let mut bytes = vec![0u8; 0x1000];
        let load_config_rva = 0x300usize;
        let table_rva = 0x4a0usize;

        bytes[80..84].copy_from_slice(&(load_config_rva as u32).to_le_bytes());
        bytes[84..88].copy_from_slice(&0x140u32.to_le_bytes());
        bytes[load_config_rva..load_config_rva + 4].copy_from_slice(&0x140u32.to_le_bytes());
        bytes[load_config_rva + 0x90..load_config_rva + 0x94]
            .copy_from_slice(&0x1000_0000u32.to_le_bytes());
        bytes[load_config_rva + 0x108..load_config_rva + 0x110]
            .copy_from_slice(&(0x140000000u64 + table_rva as u64).to_le_bytes());
        bytes[load_config_rva + 0x110..load_config_rva + 0x118]
            .copy_from_slice(&3u64.to_le_bytes());

        bytes[table_rva..table_rva + 4].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[table_rva + 4] = 0xA1;
        bytes[table_rva + 5..table_rva + 9].copy_from_slice(&0x1100u32.to_le_bytes());
        bytes[table_rva + 9] = 0xB2;
        bytes[table_rva + 10..table_rva + 14].copy_from_slice(&0x1200u32.to_le_bytes());
        bytes[table_rva + 14] = 0xC3;

        let mut pe = make_test_pe(bytes);
        let parsed = pe
            .parse_guard_eh_continuation_table()
            .expect("parse guard eh continuation table")
            .expect("table present");
        assert_eq!(parsed.entry_size, 5);
        assert_eq!(parsed.entries, vec![0x1300, 0x1100, 0x1200]);

        let changed = pe
            .remap_guard_eh_continuation_table(|rva| if rva == 0x1200 { 0x1400 } else { rva })
            .expect("remap guard eh continuation table");
        assert_eq!(changed, 1);

        let table = pe
            .parse_guard_eh_continuation_table()
            .expect("parse guard eh continuation table")
            .expect("table present");
        assert_eq!(table.entry_size, 5);
        assert_eq!(table.entries, vec![0x1100, 0x1300, 0x1400]);

        let raw = pe
            .read_rva_slice(table_rva as u32, 15)
            .expect("read remapped guard eh continuation table");
        assert_eq!(raw[4], 0xB2);
        assert_eq!(raw[9], 0xA1);
        assert_eq!(raw[14], 0xC3);
    }
}
