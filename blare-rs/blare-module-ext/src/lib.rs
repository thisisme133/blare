use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSection {
    pub name: String,
    pub size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionSymbol {
    pub name: String,
    pub section_number: i16,
    pub value: u32,
    pub storage_class: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionModule {
    pub source_path: String,
    pub machine: u16,
    pub sections: Vec<ExtensionSection>,
    pub symbols: Vec<ExtensionSymbol>,
}

fn read_u16_le(data: &[u8], off: usize) -> Result<u16> {
    let slice = data
        .get(off..off + 2)
        .with_context(|| format!("u16 out of bounds at 0x{off:x}"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_i16_le(data: &[u8], off: usize) -> Result<i16> {
    Ok(read_u16_le(data, off)? as i16)
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    let slice = data
        .get(off..off + 4)
        .with_context(|| format!("u32 out of bounds at 0x{off:x}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn parse_name(field: &[u8], string_table: &[u8]) -> String {
    if field.len() != 8 {
        return String::new();
    }

    // Long COFF symbol name: first 4 bytes zero, next 4 bytes offset in string table.
    if field[0..4] == [0, 0, 0, 0] {
        let off = u32::from_le_bytes([field[4], field[5], field[6], field[7]]) as usize;
        if off >= 4 && off < string_table.len() {
            let s = &string_table[off..];
            let len = s.iter().position(|b| *b == 0).unwrap_or(s.len());
            return String::from_utf8_lossy(&s[..len]).to_string();
        }
        return String::new();
    }

    let len = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..len]).to_string()
}

pub fn parse_extension_object(path: impl AsRef<Path>) -> Result<ExtensionModule> {
    let path_ref = path.as_ref();
    let bytes = fs::read(path_ref)
        .with_context(|| format!("failed to read object {}", path_ref.display()))?;

    if bytes.len() < 20 {
        anyhow::bail!("file too small for COFF header");
    }

    let machine = read_u16_le(&bytes, 0)?;
    let section_count = read_u16_le(&bytes, 2)? as usize;
    let ptr_to_symbol_table = read_u32_le(&bytes, 8)? as usize;
    let symbol_count = read_u32_le(&bytes, 12)? as usize;
    let size_of_optional_header = read_u16_le(&bytes, 16)? as usize;

    let section_table_off = 20 + size_of_optional_header;
    let section_table_size = section_count
        .checked_mul(40)
        .context("section table overflow")?;
    if section_table_off + section_table_size > bytes.len() {
        anyhow::bail!("section table out of bounds");
    }

    let mut sections = Vec::with_capacity(section_count);
    for idx in 0..section_count {
        let off = section_table_off + idx * 40;
        let name = parse_name(&bytes[off..off + 8], &[]);
        let size = read_u32_le(&bytes, off + 16)?;
        let raw_ptr = read_u32_le(&bytes, off + 20)?;
        let characteristics = read_u32_le(&bytes, off + 36)?;
        sections.push(ExtensionSection {
            name,
            size,
            raw_ptr,
            characteristics,
        });
    }

    let sym_table_size = symbol_count
        .checked_mul(18)
        .context("symbol table overflow")?;
    let string_table_off = ptr_to_symbol_table
        .checked_add(sym_table_size)
        .context("string table offset overflow")?;

    if string_table_off + 4 > bytes.len() {
        anyhow::bail!("COFF string table out of bounds");
    }

    let string_table_len = read_u32_le(&bytes, string_table_off)? as usize;
    let string_table_end = string_table_off
        .checked_add(string_table_len)
        .context("string table end overflow")?;
    if string_table_end > bytes.len() {
        anyhow::bail!("COFF string table exceeds file size");
    }
    let string_table = &bytes[string_table_off..string_table_end];

    let mut symbols = Vec::new();
    let mut i = 0usize;
    while i < symbol_count {
        let off = ptr_to_symbol_table + i * 18;
        if off + 18 > bytes.len() {
            anyhow::bail!("COFF symbol out of bounds at index {i}");
        }

        let name = parse_name(&bytes[off..off + 8], string_table);
        let value = read_u32_le(&bytes, off + 8)?;
        let section_number = read_i16_le(&bytes, off + 12)?;
        let storage_class = bytes[off + 16];
        let aux_count = bytes[off + 17] as usize;

        symbols.push(ExtensionSymbol {
            name,
            section_number,
            value,
            storage_class,
        });

        i = i.saturating_add(1 + aux_count);
    }

    Ok(ExtensionModule {
        source_path: path_ref.display().to_string(),
        machine,
        sections,
        symbols,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_short() {
        let field = *b".text\0\0\0";
        assert_eq!(parse_name(&field, &[]), ".text");
    }
}
