use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CfgError {
    #[error("failed to parse cfg json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("failed to read cfg file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid address '{value}'")]
    InvalidAddress { value: String },
    #[error("invalid cfg: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EdgeType {
    Call,
    Branch,
    Fallthrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectSiteKind {
    Call,
    Jump,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectSiteCfg {
    pub address: u64,
    pub kind: IndirectSiteKind,
    pub possible_targets: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpTableCfg {
    pub site: u64,
    pub base: Option<u64>,
    pub entry_size: Option<u8>,
    pub min_index: Option<i64>,
    pub max_index: Option<i64>,
    pub targets: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CfgCoverageReport {
    pub executable_bytes: u64,
    pub covered_bytes: u64,
    pub coverage_ratio: f64,
    pub function_count: usize,
    pub functions_in_executable_ranges: usize,
}

impl fmt::Display for EdgeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeType::Call => write!(f, "call"),
            EdgeType::Branch => write!(f, "branch"),
            EdgeType::Fallthrough => write!(f, "fallthrough"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgramCfg {
    pub program_name: String,
    pub image_base: u64,
    pub functions: Vec<FunctionCfg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionCfg {
    pub name: String,
    pub address: u64,
    pub blocks: Vec<BlockCfg>,
    pub edges: Vec<EdgeCfg>,
    pub indirect_call_sites: Vec<u64>,
    pub indirect_sites: Vec<IndirectSiteCfg>,
    pub jump_tables: Vec<JumpTableCfg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockCfg {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EdgeCfg {
    pub from: u64,
    pub to: u64,
    pub edge_type: EdgeType,
    pub indirect: bool,
}

impl BlockCfg {
    pub fn contains(&self, va: u64) -> bool {
        va >= self.start && va < self.end
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawProgramCfg {
    program_name: String,
    image_base: String,
    functions: Vec<RawFunctionCfg>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawFunctionCfg {
    name: String,
    address: String,
    blocks: Vec<RawBlockCfg>,
    edges: Vec<RawEdgeCfg>,
    #[serde(default)]
    indirect_call_sites: Vec<String>,
    #[serde(default)]
    indirect_sites: Vec<RawIndirectSiteCfg>,
    #[serde(default)]
    jump_tables: Vec<RawJumpTableCfg>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawBlockCfg {
    start: String,
    end: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawEdgeCfg {
    from: String,
    to: String,
    #[serde(rename = "type")]
    edge_type: EdgeType,
    #[serde(default)]
    indirect: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RawIndirectSiteCfg {
    address: String,
    #[serde(default = "default_indirect_site_kind")]
    kind: IndirectSiteKind,
    #[serde(default)]
    possible_targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawJumpTableCfg {
    site: String,
    #[serde(default)]
    base: Option<String>,
    #[serde(default)]
    entry_size: Option<u8>,
    #[serde(default)]
    min_index: Option<i64>,
    #[serde(default)]
    max_index: Option<i64>,
    #[serde(default)]
    targets: Vec<String>,
}

fn default_indirect_site_kind() -> IndirectSiteKind {
    IndirectSiteKind::Call
}

fn parse_hex_u64(value: &str) -> Result<u64, CfgError> {
    let trimmed = value.trim();
    let no_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    u64::from_str_radix(no_prefix, 16).map_err(|_| CfgError::InvalidAddress {
        value: value.to_string(),
    })
}

impl TryFrom<RawProgramCfg> for ProgramCfg {
    type Error = CfgError;

    fn try_from(value: RawProgramCfg) -> Result<Self, Self::Error> {
        let mut functions = Vec::with_capacity(value.functions.len());

        for rf in value.functions {
            let mut blocks = Vec::with_capacity(rf.blocks.len());
            for rb in rf.blocks {
                let start = parse_hex_u64(&rb.start)?;
                let end = parse_hex_u64(&rb.end)?;
                if end <= start {
                    return Err(CfgError::Invalid(format!(
                        "function '{}' has invalid block range [0x{start:x}, 0x{end:x})",
                        rf.name
                    )));
                }
                blocks.push(BlockCfg { start, end });
            }

            // Some Ghidra exports can contain synthetic function records with no decoded blocks.
            // They are not rewritable and should be ignored at ingestion time.
            if blocks.is_empty() {
                continue;
            }

            let starts: HashSet<u64> = blocks.iter().map(|b| b.start).collect();
            let mut edges = Vec::with_capacity(rf.edges.len());
            for re in rf.edges {
                let mut from = parse_hex_u64(&re.from)?;
                let mut to = parse_hex_u64(&re.to)?;
                if !starts.contains(&from) {
                    // Canonicalize edge source to owning block start when Ghidra reports an
                    // interior address.
                    if let Some(block_start) =
                        blocks.iter().find(|b| b.contains(from)).map(|b| b.start)
                    {
                        from = block_start;
                    } else {
                        return Err(CfgError::Invalid(format!(
                            "function '{}' edge.from 0x{from:x} does not match a block start",
                            rf.name
                        )));
                    }
                }
                if !starts.contains(&to) {
                    // Ghidra may report edge targets inside a discovered block. Canonicalize
                    // these targets to the owning block start for compatibility with ExportCFG.java.
                    if let Some(block_start) =
                        blocks.iter().find(|b| b.contains(to)).map(|b| b.start)
                    {
                        to = block_start;
                    }
                }

                edges.push(EdgeCfg {
                    from,
                    to,
                    edge_type: re.edge_type,
                    indirect: re.indirect,
                });
            }

            let mut indirect_call_sites = Vec::with_capacity(rf.indirect_call_sites.len());
            for site in rf.indirect_call_sites {
                let va = parse_hex_u64(&site)?;
                indirect_call_sites.push(va);
            }

            let mut indirect_sites = Vec::with_capacity(rf.indirect_sites.len());
            for site in rf.indirect_sites {
                let address = parse_hex_u64(&site.address)?;
                let mut possible_targets = Vec::with_capacity(site.possible_targets.len());
                let mut seen_targets = HashSet::new();
                for t in site.possible_targets {
                    let mut target = parse_hex_u64(&t)?;
                    if !starts.contains(&target) {
                        if let Some(block_start) =
                            blocks.iter().find(|b| b.contains(target)).map(|b| b.start)
                        {
                            target = block_start;
                        }
                    }
                    if seen_targets.insert(target) {
                        possible_targets.push(target);
                    }
                }
                indirect_sites.push(IndirectSiteCfg {
                    address,
                    kind: site.kind,
                    possible_targets,
                });
            }

            let mut jump_tables = Vec::with_capacity(rf.jump_tables.len());
            for jt in rf.jump_tables {
                let site = parse_hex_u64(&jt.site)?;
                let base = match jt.base {
                    Some(v) => Some(parse_hex_u64(&v)?),
                    None => None,
                };
                let mut targets = Vec::with_capacity(jt.targets.len());
                let mut seen_targets = HashSet::new();
                for t in jt.targets {
                    let mut target = parse_hex_u64(&t)?;
                    if !starts.contains(&target) {
                        if let Some(block_start) =
                            blocks.iter().find(|b| b.contains(target)).map(|b| b.start)
                        {
                            target = block_start;
                        }
                    }
                    if seen_targets.insert(target) {
                        targets.push(target);
                    }
                }

                jump_tables.push(JumpTableCfg {
                    site,
                    base,
                    entry_size: jt.entry_size,
                    min_index: jt.min_index,
                    max_index: jt.max_index,
                    targets,
                });
            }

            let mut seen_indirect_legacy: HashSet<(u64, IndirectSiteKind)> =
                indirect_sites.iter().map(|s| (s.address, s.kind)).collect();
            for site in &indirect_call_sites {
                if seen_indirect_legacy.insert((*site, IndirectSiteKind::Call)) {
                    indirect_sites.push(IndirectSiteCfg {
                        address: *site,
                        kind: IndirectSiteKind::Call,
                        possible_targets: Vec::new(),
                    });
                }
            }

            let mut address = parse_hex_u64(&rf.address)?;
            if !starts.contains(&address) {
                if let Some(block_start) =
                    blocks.iter().find(|b| b.contains(address)).map(|b| b.start)
                {
                    address = block_start;
                } else {
                    return Err(CfgError::Invalid(format!(
                        "function '{}' entry 0x{address:x} is not in block starts",
                        rf.name
                    )));
                }
            }

            functions.push(FunctionCfg {
                name: rf.name,
                address,
                blocks,
                edges,
                indirect_call_sites,
                indirect_sites,
                jump_tables,
            });
        }

        let image_base = parse_hex_u64(&value.image_base)?;
        Ok(Self {
            program_name: value.program_name,
            image_base,
            functions,
        })
    }
}

impl ProgramCfg {
    pub fn from_json_str(json: &str) -> Result<Self, CfgError> {
        let raw: RawProgramCfg = serde_json::from_str(json)?;
        let cfg = ProgramCfg::try_from(raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_json_path(path: impl AsRef<Path>) -> Result<Self, CfgError> {
        let path_ref = path.as_ref();
        let json = fs::read_to_string(path_ref).map_err(|source| CfgError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::from_json_str(&json)
    }

    pub fn validate(&self) -> Result<(), CfgError> {
        if self.functions.is_empty() {
            return Err(CfgError::Invalid("cfg has no functions".to_string()));
        }

        let mut seen_functions = HashSet::new();
        for f in &self.functions {
            if !seen_functions.insert(f.address) {
                return Err(CfgError::Invalid(format!(
                    "duplicate function entry address 0x{:x}",
                    f.address
                )));
            }

            if f.blocks.is_empty() {
                return Err(CfgError::Invalid(format!(
                    "function '{}' has no blocks",
                    f.name
                )));
            }

            let mut seen_blocks = HashSet::new();
            for block in &f.blocks {
                if !seen_blocks.insert(block.start) {
                    return Err(CfgError::Invalid(format!(
                        "function '{}' duplicate block start 0x{:x}",
                        f.name, block.start
                    )));
                }
                if block.end <= block.start {
                    return Err(CfgError::Invalid(format!(
                        "function '{}' invalid block [0x{:x}, 0x{:x})",
                        f.name, block.start, block.end
                    )));
                }
            }

            for edge in &f.edges {
                if !seen_blocks.contains(&edge.from) {
                    return Err(CfgError::Invalid(format!(
                        "function '{}' edge.from 0x{:x} does not match a block start",
                        f.name, edge.from
                    )));
                }
            }

            let mut seen_indirect_sites = HashSet::new();
            for site in &f.indirect_sites {
                if !seen_indirect_sites.insert((site.address, site.kind)) {
                    return Err(CfgError::Invalid(format!(
                        "function '{}' has duplicate indirect site at 0x{:x} ({:?})",
                        f.name, site.address, site.kind
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn to_rva(&self, va: u64) -> Result<u32, CfgError> {
        if va < self.image_base {
            return Err(CfgError::Invalid(format!(
                "virtual address 0x{va:x} is below image base 0x{:x}",
                self.image_base
            )));
        }

        let rva = va - self.image_base;
        u32::try_from(rva).map_err(|_| {
            CfgError::Invalid(format!(
                "virtual address 0x{va:x} does not fit into 32-bit rva"
            ))
        })
    }

    pub fn coverage_report(&self, executable_ranges: &[(u64, u64)]) -> CfgCoverageReport {
        fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
            ranges.sort_unstable_by_key(|r| r.0);
            let mut out: Vec<(u64, u64)> = Vec::new();
            for (start, end) in ranges {
                if start >= end {
                    continue;
                }
                if let Some(last) = out.last_mut() {
                    if start <= last.1 {
                        last.1 = last.1.max(end);
                        continue;
                    }
                }
                out.push((start, end));
            }
            out
        }

        fn intersect_len(a: (u64, u64), b: (u64, u64)) -> u64 {
            let s = a.0.max(b.0);
            let e = a.1.min(b.1);
            e.saturating_sub(s)
        }

        let exec = merge(executable_ranges.to_vec());
        let cfg_blocks = merge(
            self.functions
                .iter()
                .flat_map(|f| f.blocks.iter().map(|b| (b.start, b.end)))
                .collect(),
        );

        let executable_bytes = exec.iter().map(|(s, e)| e.saturating_sub(*s)).sum::<u64>();
        let mut covered_bytes = 0u64;
        for c in &cfg_blocks {
            for e in &exec {
                covered_bytes = covered_bytes.saturating_add(intersect_len(*c, *e));
            }
        }

        let functions_in_executable_ranges = self
            .functions
            .iter()
            .filter(|f| exec.iter().any(|(s, e)| f.address >= *s && f.address < *e))
            .count();

        let coverage_ratio = if executable_bytes == 0 {
            0.0
        } else {
            covered_bytes as f64 / executable_bytes as f64
        };

        CfgCoverageReport {
            executable_bytes,
            covered_bytes,
            coverage_ratio,
            function_count: self.functions.len(),
            functions_in_executable_ranges,
        }
    }

    pub fn to_ghidra_json_pretty(&self) -> Result<String, CfgError> {
        fn is_false(v: &bool) -> bool {
            !*v
        }

        #[derive(Serialize)]
        struct OutProgram<'a> {
            program_name: &'a str,
            image_base: String,
            functions: Vec<OutFunction<'a>>,
        }

        #[derive(Serialize)]
        struct OutFunction<'a> {
            name: &'a str,
            address: String,
            blocks: Vec<OutBlock>,
            edges: Vec<OutEdge>,
            indirect_call_sites: Vec<String>,
            indirect_sites: Vec<OutIndirectSite>,
            jump_tables: Vec<OutJumpTable>,
        }

        #[derive(Serialize)]
        struct OutBlock {
            start: String,
            end: String,
        }

        #[derive(Serialize)]
        struct OutEdge {
            from: String,
            to: String,
            #[serde(rename = "type")]
            edge_type: EdgeType,
            #[serde(skip_serializing_if = "is_false")]
            indirect: bool,
        }

        #[derive(Serialize)]
        struct OutIndirectSite {
            address: String,
            kind: IndirectSiteKind,
            possible_targets: Vec<String>,
        }

        #[derive(Serialize)]
        struct OutJumpTable {
            site: String,
            base: Option<String>,
            entry_size: Option<u8>,
            min_index: Option<i64>,
            max_index: Option<i64>,
            targets: Vec<String>,
        }

        let mut out_functions = Vec::with_capacity(self.functions.len());
        for f in &self.functions {
            out_functions.push(OutFunction {
                name: &f.name,
                address: format!("0x{:x}", f.address),
                blocks: f
                    .blocks
                    .iter()
                    .map(|b| OutBlock {
                        start: format!("0x{:x}", b.start),
                        end: format!("0x{:x}", b.end),
                    })
                    .collect(),
                edges: f
                    .edges
                    .iter()
                    .map(|e| OutEdge {
                        from: format!("0x{:x}", e.from),
                        to: format!("0x{:x}", e.to),
                        edge_type: e.edge_type,
                        indirect: e.indirect,
                    })
                    .collect(),
                indirect_call_sites: f
                    .indirect_call_sites
                    .iter()
                    .map(|va| format!("0x{:x}", va))
                    .collect(),
                indirect_sites: f
                    .indirect_sites
                    .iter()
                    .map(|s| OutIndirectSite {
                        address: format!("0x{:x}", s.address),
                        kind: s.kind,
                        possible_targets: s
                            .possible_targets
                            .iter()
                            .map(|t| format!("0x{:x}", t))
                            .collect(),
                    })
                    .collect(),
                jump_tables: f
                    .jump_tables
                    .iter()
                    .map(|jt| OutJumpTable {
                        site: format!("0x{:x}", jt.site),
                        base: jt.base.map(|b| format!("0x{:x}", b)),
                        entry_size: jt.entry_size,
                        min_index: jt.min_index,
                        max_index: jt.max_index,
                        targets: jt.targets.iter().map(|t| format!("0x{:x}", t)).collect(),
                    })
                    .collect(),
            });
        }

        let out = OutProgram {
            program_name: &self.program_name,
            image_base: format!("0x{:x}", self.image_base),
            functions: out_functions,
        };

        serde_json::to_string_pretty(&out).map_err(CfgError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_cfg() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "main",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions.len(), 1);
        assert_eq!(cfg.to_rva(0x140001000).unwrap(), 0x1000);
    }

    #[test]
    fn reject_invalid_edge() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "main",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [
                { "from": "0x140001100", "to": "0x140001000", "type": "branch" }
              ],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let err = ProgramCfg::from_json_str(json).expect_err("must fail");
        assert!(err.to_string().contains("does not match a block start"));
    }

    #[test]
    fn normalize_non_call_edge_target_inside_block() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" },
                { "start": "0x140001010", "end": "0x140001020" }
              ],
              "edges": [
                { "from": "0x140001000", "to": "0x140001018", "type": "branch" }
              ],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].edges[0].to, 0x140001010);
    }

    #[test]
    fn normalize_call_edge_target_inside_block() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" },
                { "start": "0x140001010", "end": "0x140001020" }
              ],
              "edges": [
                { "from": "0x140001000", "to": "0x140001018", "type": "call" }
              ],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].edges[0].to, 0x140001010);
    }

    #[test]
    fn parse_with_unknown_fields_is_allowed() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "source_tool": "ghidra",
          "functions": [
            {
              "name": "main",
              "address": "0x140001000",
              "unknown_func_field": 1,
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010", "unknown_block_field": true }
              ],
              "edges": [],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions.len(), 1);
    }

    #[test]
    fn normalize_function_entry_inside_block() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001005",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].address, 0x140001000);
    }

    #[test]
    fn normalize_edge_from_inside_block() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [
                { "from": "0x140001004", "to": "0x140001000", "type": "branch" }
              ],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].edges[0].from, 0x140001000);
    }

    #[test]
    fn allow_non_call_tail_edge_to_function_entry() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [
                { "from": "0x140001000", "to": "0x140001100", "type": "branch" }
              ],
              "indirect_call_sites": []
            },
            {
              "name": "g",
              "address": "0x140001100",
              "blocks": [
                { "start": "0x140001100", "end": "0x140001110" }
              ],
              "edges": [],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].edges[0].to, 0x140001100);
    }

    #[test]
    fn dedupe_legacy_and_extended_indirect_call_sites() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [],
              "indirect_call_sites": ["0x140001005"],
              "indirect_sites": [
                {
                  "address": "0x140001005",
                  "kind": "call",
                  "possible_targets": []
                }
              ]
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].indirect_sites.len(), 1);
    }

    #[test]
    fn parse_extended_indirect_and_jump_tables() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001030" },
                { "start": "0x140001030", "end": "0x140001040" }
              ],
              "edges": [
                { "from": "0x140001000", "to": "0x140001030", "type": "branch", "indirect": true }
              ],
              "indirect_call_sites": ["0x140001010"],
              "indirect_sites": [
                {
                  "address": "0x140001020",
                  "kind": "jump",
                  "possible_targets": ["0x140001030"]
                }
              ],
              "jump_tables": [
                {
                  "site": "0x140001020",
                  "entry_size": 4,
                  "min_index": 0,
                  "max_index": 1,
                  "targets": ["0x140001030"]
                }
              ]
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(cfg.functions[0].indirect_sites.len(), 2); // includes legacy indirect_call_sites projection
        assert_eq!(cfg.functions[0].jump_tables.len(), 1);
    }

    #[test]
    fn normalize_indirect_and_jump_table_targets_inside_block() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "f",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" },
                { "start": "0x140001010", "end": "0x140001020" }
              ],
              "edges": [],
              "indirect_call_sites": [],
              "indirect_sites": [
                {
                  "address": "0x140001005",
                  "kind": "jump",
                  "possible_targets": ["0x140001018", "0x140001010"]
                }
              ],
              "jump_tables": [
                {
                  "site": "0x140001005",
                  "targets": ["0x140001018", "0x140001010"]
                }
              ]
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        assert_eq!(
            cfg.functions[0].indirect_sites[0].possible_targets,
            vec![0x140001010]
        );
        assert_eq!(cfg.functions[0].jump_tables[0].targets, vec![0x140001010]);
    }

    #[test]
    fn coverage_report_computes_ratio() {
        let json = r#"
        {
          "program_name": "fixture.exe",
          "image_base": "0x140000000",
          "functions": [
            {
              "name": "main",
              "address": "0x140001000",
              "blocks": [
                { "start": "0x140001000", "end": "0x140001010" }
              ],
              "edges": [],
              "indirect_call_sites": []
            }
          ]
        }
        "#;

        let cfg = ProgramCfg::from_json_str(json).expect("cfg parse should work");
        let coverage = cfg.coverage_report(&[(0x140001000, 0x140001020)]);
        assert_eq!(coverage.executable_bytes, 0x20);
        assert_eq!(coverage.covered_bytes, 0x10);
        assert!((coverage.coverage_ratio - 0.5).abs() < 0.0001);
    }
}
