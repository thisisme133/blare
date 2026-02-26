use std::collections::{BTreeMap, HashMap, HashSet, hash_map::RandomState};
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use blare_cfg::{BlockCfg, EdgeType, FunctionCfg, IndirectSiteKind, ProgramCfg};
use blare_lift::{lift_program, validate_cfg_against_pe};
use blare_passes::{
    ProfilePassOptions, available_profile_names, build_profile_pass_with_options, profile_from_name,
};
use blare_pe::{PeBinaryKind, PeFile};
use blare_rewrite::{RewriteOptions, RewritePolicy, SectionLayout, rewrite_binary};
use clap::{Parser, Subcommand, ValueEnum};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction,
    NasmFormatter, OpKind,
};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "blare")]
#[command(about = "BLARE-inspired PE64 AOT rewriter")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ValidateCfg {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        cfg: PathBuf,
    },
    IngestGhidra {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        cfg: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value_t = 0.90)]
        min_coverage: f64,
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    Rewrite {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        cfg: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        map: PathBuf,
        #[arg(long, default_value = "balanced")]
        profile: String,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, default_value_t = false)]
        strict_unwind: bool,
        #[arg(long, default_value_t = false)]
        clear_unwind_info: bool,
        #[arg(long, value_enum, default_value_t = CliRewritePolicy::PerFunction)]
        rewrite_policy: CliRewritePolicy,
        #[arg(long, value_enum, default_value_t = CliSectionLayout::Keep)]
        section_layout: CliSectionLayout,
        #[arg(long, default_value_t = false)]
        allow_unsafe_compact: bool,
        #[arg(long, default_value_t = 0.35)]
        indirect_cf_probability: f64,
        #[arg(long, default_value_t = false)]
        import_protection: bool,
        #[arg(long, default_value_t = false)]
        anti_debug: bool,
        #[arg(long, default_value_t = false)]
        obscure_entry_point: bool,
        #[arg(long, default_value_t = false)]
        strip_legacy_code: bool,
        #[arg(long, default_value_t = false)]
        strip_legacy_code_aggressive: bool,
    },
    VerifySeh {
        #[arg(long)]
        input: PathBuf,
    },
    VerifyUnwind {
        #[arg(long)]
        input: PathBuf,
    },
    Inspect {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    SeedCfg {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    ExportCytoscape {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        cfg: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        function: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliRewritePolicy {
    PerFunction,
    Module,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSectionLayout {
    Keep,
    Compact,
    Rebuild,
}

impl From<CliRewritePolicy> for RewritePolicy {
    fn from(value: CliRewritePolicy) -> Self {
        match value {
            CliRewritePolicy::PerFunction => RewritePolicy::PerFunction,
            CliRewritePolicy::Module => RewritePolicy::Module,
        }
    }
}

impl From<CliSectionLayout> for SectionLayout {
    fn from(value: CliSectionLayout) -> Self {
        match value {
            CliSectionLayout::Keep => SectionLayout::Keep,
            CliSectionLayout::Compact => SectionLayout::Compact,
            CliSectionLayout::Rebuild => SectionLayout::Rebuild,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::ValidateCfg { input, cfg } => cmd_validate_cfg(input, cfg),
        Command::IngestGhidra {
            input,
            cfg,
            output,
            min_coverage,
            strict,
        } => cmd_ingest_ghidra(input, cfg, output, min_coverage, strict),
        Command::Rewrite {
            input,
            cfg,
            output,
            map,
            profile,
            seed,
            strict_unwind,
            clear_unwind_info,
            rewrite_policy,
            section_layout,
            allow_unsafe_compact,
            indirect_cf_probability,
            import_protection,
            anti_debug,
            obscure_entry_point,
            strip_legacy_code,
            strip_legacy_code_aggressive,
        } => cmd_rewrite(
            input,
            cfg,
            output,
            map,
            profile,
            seed,
            strict_unwind,
            clear_unwind_info,
            rewrite_policy,
            section_layout,
            allow_unsafe_compact,
            indirect_cf_probability,
            import_protection,
            anti_debug,
            obscure_entry_point,
            strip_legacy_code,
            strip_legacy_code_aggressive,
        ),
        Command::VerifySeh { input } => cmd_verify_unwind(input),
        Command::VerifyUnwind { input } => cmd_verify_unwind(input),
        Command::Inspect { input, json } => cmd_inspect(input, json),
        Command::SeedCfg { input, output } => cmd_seed_cfg(input, output),
        Command::ExportCytoscape {
            input,
            cfg,
            output,
            function,
        } => cmd_export_cytoscape(input, cfg, output, function),
    }
}

fn cmd_validate_cfg(input: PathBuf, cfg_path: PathBuf) -> Result<()> {
    let cfg = ProgramCfg::from_json_path(&cfg_path)
        .with_context(|| format!("failed to load cfg file {}", cfg_path.display()))?;

    let bytes = fs::read(&input)
        .with_context(|| format!("failed to read input binary {}", input.display()))?;
    let pe = PeFile::parse(bytes)?;

    validate_cfg_against_pe(&cfg, &pe)?;

    println!(
        "CFG valid: program='{}' image_base=0x{:x} kind={:?} functions={} sections={}",
        cfg.program_name,
        cfg.image_base,
        pe.binary_kind(),
        cfg.functions.len(),
        pe.sections().len()
    );

    Ok(())
}

fn executable_ranges_from_pe(pe: &PeFile) -> Vec<(u64, u64)> {
    pe.sections()
        .iter()
        .filter(|s| s.executable())
        .map(|s| {
            let start = pe.image_base() + s.virtual_address as u64;
            let end = start + std::cmp::max(s.virtual_size, s.size_of_raw_data) as u64;
            (start, end)
        })
        .collect()
}

fn cmd_ingest_ghidra(
    input: PathBuf,
    cfg_path: PathBuf,
    output: Option<PathBuf>,
    min_coverage: f64,
    strict: bool,
) -> Result<()> {
    let cfg = ProgramCfg::from_json_path(&cfg_path)
        .with_context(|| format!("failed to load cfg file {}", cfg_path.display()))?;
    let bytes = fs::read(&input)
        .with_context(|| format!("failed to read input binary {}", input.display()))?;
    let pe = PeFile::parse(bytes)?;

    validate_cfg_against_pe(&cfg, &pe)?;
    let coverage = cfg.coverage_report(&executable_ranges_from_pe(&pe));

    if coverage.coverage_ratio < min_coverage {
        anyhow::bail!(
            "CFG coverage {:.4} is lower than required {:.4}",
            coverage.coverage_ratio,
            min_coverage
        );
    }

    let (_, diagnostics) = lift_program(&cfg, &pe)?;
    if strict && !diagnostics.fallback_functions.is_empty() {
        anyhow::bail!(
            "strict ingest rejected cfg: {} fallback function(s) detected during lift",
            diagnostics.fallback_functions.len()
        );
    }

    if let Some(path) = output {
        let json = cfg.to_ghidra_json_pretty()?;
        fs::write(&path, json)
            .with_context(|| format!("failed to write normalized cfg {}", path.display()))?;
        println!(
            "ingest-ghidra ok: output='{}' coverage={:.4} functions={}/{} fallback_functions={}",
            path.display(),
            coverage.coverage_ratio,
            coverage.functions_in_executable_ranges,
            coverage.function_count,
            diagnostics.fallback_functions.len()
        );
    } else {
        println!(
            "ingest-ghidra ok: coverage={:.4} covered_bytes={} executable_bytes={} functions={}/{} fallback_functions={}",
            coverage.coverage_ratio,
            coverage.covered_bytes,
            coverage.executable_bytes,
            coverage.functions_in_executable_ranges,
            coverage.function_count,
            diagnostics.fallback_functions.len()
        );
    }

    if !strict && !diagnostics.fallback_functions.is_empty() {
        println!(
            "ingest-ghidra warning: {} fallback function(s) detected; rerun with --strict to reject this CFG",
            diagnostics.fallback_functions.len()
        );
    }
    Ok(())
}

fn cmd_rewrite(
    input: PathBuf,
    cfg_path: PathBuf,
    output: PathBuf,
    map: PathBuf,
    profile: String,
    seed: Option<u64>,
    strict_unwind: bool,
    clear_unwind_info: bool,
    rewrite_policy: CliRewritePolicy,
    section_layout: CliSectionLayout,
    allow_unsafe_compact: bool,
    indirect_cf_probability: f64,
    import_protection: bool,
    anti_debug: bool,
    obscure_entry_point: bool,
    strip_legacy_code: bool,
    strip_legacy_code_aggressive: bool,
) -> Result<()> {
    let cfg = ProgramCfg::from_json_path(&cfg_path)
        .with_context(|| format!("failed to load cfg file {}", cfg_path.display()))?;

    let input_bytes = fs::read(&input)
        .with_context(|| format!("failed to read input binary {}", input.display()))?;

    let profile = profile_from_name(&profile).with_context(|| {
        format!(
            "invalid profile '{}' (available: {})",
            profile,
            available_profile_names().join(", ")
        )
    })?;
    if !indirect_cf_probability.is_finite() || !(0.0..=1.0).contains(&indirect_cf_probability) {
        anyhow::bail!(
            "--indirect-cf-probability must be within [0.0, 1.0], got {}",
            indirect_cf_probability
        );
    }

    let seed = seed.unwrap_or_else(default_obfuscation_seed);
    let pass = build_profile_pass_with_options(
        profile,
        seed,
        ProfilePassOptions {
            indirect_cf_probability,
        },
    );

    let options = RewriteOptions {
        strict_unwind,
        clear_unwind_info,
        policy: rewrite_policy.into(),
        section_layout: section_layout.into(),
        allow_unsafe_compact,
        indirect_cf_probability,
        import_protection,
        anti_debug,
        obscure_entry_point,
        strip_legacy_code,
        strip_legacy_code_aggressive,
    };
    let artifact = rewrite_binary(&cfg, &input_bytes, pass.as_ref(), options)?;

    fs::write(&output, &artifact.output)
        .with_context(|| format!("failed to write output binary {}", output.display()))?;

    let map_json = serde_json::to_string_pretty(&artifact.map)?;
    fs::write(&map, map_json)
        .with_context(|| format!("failed to write rewrite map {}", map.display()))?;

    println!(
        "rewrite completed: output='{}' map='{}' profile={} seed={} rewritten_bytes={} remapped_relocations={} fallback_functions={}",
        output.display(),
        map.display(),
        profile.as_str(),
        seed,
        artifact.map.rewritten_bytes,
        artifact.map.remapped_relocations,
        artifact.map.functions.iter().filter(|f| f.fallback).count()
    );

    if !artifact.diagnostics.fallback_functions.is_empty() {
        println!("fallback diagnostics:");
        for (name, reason) in artifact.diagnostics.fallback_functions {
            println!("- {}: {}", name, reason);
        }
    }

    Ok(())
}

fn default_obfuscation_seed() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    hasher.write_u128(nanos);
    hasher.write_u32(std::process::id());
    hasher.finish()
}

fn cmd_verify_unwind(input: PathBuf) -> Result<()> {
    let bytes = fs::read(&input)
        .with_context(|| format!("failed to read input binary {}", input.display()))?;
    let pe = PeFile::parse(bytes)?;

    let runtime = pe.parse_runtime_functions()?;
    if runtime.is_empty() {
        if pe.binary_kind() == PeBinaryKind::Uefi {
            println!(
                "unwind verification ok: runtime_functions=0 image_base=0x{:x} kind=uefi (no exception directory)",
                pe.image_base()
            );
            return Ok(());
        }
        anyhow::bail!("exception directory is empty");
    }

    let mut prev_begin = 0u32;
    for (idx, entry) in runtime.iter().enumerate() {
        if idx != 0 && entry.begin_address < prev_begin {
            anyhow::bail!(
                "runtime function table is not sorted: 0x{:x} after 0x{:x}",
                entry.begin_address,
                prev_begin
            );
        }
        prev_begin = entry.begin_address;

        let summary = pe
            .parse_unwind_info_summary(entry.unwind_info_address)
            .with_context(|| {
                format!(
                    "invalid unwind info for runtime function [0x{:x}, 0x{:x}) at 0x{:x}",
                    entry.begin_address, entry.end_address, entry.unwind_info_address
                )
            })?;

        if summary.size == 0 {
            anyhow::bail!(
                "unwind info at 0x{:x} has zero size",
                entry.unwind_info_address
            );
        }
    }

    println!(
        "unwind verification ok: runtime_functions={} image_base=0x{:x}",
        runtime.len(),
        pe.image_base()
    );

    Ok(())
}

#[derive(Debug, Serialize)]
struct InspectSummary {
    image_base: u64,
    binary_kind: PeBinaryKind,
    subsystem: u16,
    characteristics: u16,
    entrypoint_rva: u32,
    sections: usize,
    executable_sections: usize,
    data_directories: usize,
    exception_directory: (u32, u32),
    reloc_directory: (u32, u32),
    runtime_functions: usize,
    relocations: usize,
    load_config: Option<blare_pe::LoadConfigSummary>,
}

fn cmd_inspect(input: PathBuf, as_json: bool) -> Result<()> {
    let bytes = fs::read(&input)
        .with_context(|| format!("failed to read input binary {}", input.display()))?;
    let pe = PeFile::parse(bytes)?;
    let runtime = pe.parse_runtime_functions()?;
    let relocs = pe.parse_relocations()?;
    let exception_dir = pe.get_directory(blare_pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;
    let reloc_dir = pe.get_directory(blare_pe::IMAGE_DIRECTORY_ENTRY_BASERELOC)?;
    let load_config = pe.load_config_summary()?;

    let summary = InspectSummary {
        image_base: pe.image_base(),
        binary_kind: pe.binary_kind(),
        subsystem: pe.subsystem(),
        characteristics: pe.characteristics(),
        entrypoint_rva: pe.entrypoint_rva()?,
        sections: pe.sections().len(),
        executable_sections: pe.sections().iter().filter(|s| s.executable()).count(),
        data_directories: pe.number_of_data_directories(),
        exception_directory: exception_dir,
        reloc_directory: reloc_dir,
        runtime_functions: runtime.len(),
        relocations: relocs.len(),
        load_config,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "inspect: image_base=0x{:x} kind={:?} subsystem=0x{:x} entrypoint_rva=0x{:x} sections={} exec_sections={} runtime_functions={} relocations={}",
            summary.image_base,
            summary.binary_kind,
            summary.subsystem,
            summary.entrypoint_rva,
            summary.sections,
            summary.executable_sections,
            summary.runtime_functions,
            summary.relocations
        );
    }

    Ok(())
}

fn cmd_seed_cfg(input: PathBuf, output: PathBuf) -> Result<()> {
    let bytes = fs::read(&input)
        .with_context(|| format!("failed to read input binary {}", input.display()))?;
    let pe = PeFile::parse(bytes)?;
    let runtime = pe.parse_runtime_functions()?;
    if runtime.is_empty() {
        if pe.binary_kind() == PeBinaryKind::Uefi {
            anyhow::bail!(
                "cannot seed cfg for uefi binary without exception directory; use ingest-ghidra with ExportCFG output"
            );
        }
        anyhow::bail!("cannot seed cfg: exception directory is empty");
    }

    let image_base = pe.image_base();
    let entrypoint_rva = pe.entrypoint_rva()? as u64;
    let selected = runtime
        .iter()
        .find(|entry| {
            let start = entry.begin_address as u64;
            let end = entry.end_address as u64;
            entrypoint_rva >= start && entrypoint_rva < end
        })
        .copied()
        .unwrap_or(runtime[0]);

    let mut functions = Vec::new();
    for (idx, entry) in [selected].iter().enumerate() {
        let start = image_base + entry.begin_address as u64;
        let end = image_base + entry.end_address as u64;
        if end <= start {
            continue;
        }
        functions.push(FunctionCfg {
            name: format!("fn_{idx:04x}_{:x}", entry.begin_address),
            address: start,
            blocks: vec![BlockCfg { start, end }],
            edges: Vec::new(),
            indirect_call_sites: Vec::new(),
            indirect_sites: Vec::new(),
            jump_tables: Vec::new(),
        });
    }

    let cfg = ProgramCfg {
        program_name: input
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown.exe".to_string()),
        image_base,
        functions,
    };

    let json = cfg.to_ghidra_json_pretty()?;
    fs::write(&output, json)
        .with_context(|| format!("failed to write cfg json {}", output.display()))?;
    println!(
        "seed cfg generated: output='{}' functions={}",
        output.display(),
        cfg.functions.len()
    );
    Ok(())
}

fn parse_hex_u64_cli(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    let no_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(no_prefix, 16).with_context(|| format!("invalid hex address '{}'", value))
}

fn select_function_index(cfg: &ProgramCfg, selector: Option<&str>) -> Result<usize> {
    if cfg.functions.is_empty() {
        anyhow::bail!("cfg has no functions");
    }

    let Some(selector) = selector else {
        return Ok(0);
    };

    if selector.starts_with("0x") || selector.starts_with("0X") {
        let va = parse_hex_u64_cli(selector)?;
        return cfg
            .functions
            .iter()
            .position(|f| f.address == va)
            .ok_or_else(|| anyhow::anyhow!("function address '{}' not found in cfg", selector));
    }

    if let Some(index) = cfg.functions.iter().position(|f| f.name == selector) {
        return Ok(index);
    }
    let lower = selector.to_ascii_lowercase();
    if let Some(index) = cfg
        .functions
        .iter()
        .position(|f| f.name.to_ascii_lowercase() == lower)
    {
        return Ok(index);
    }

    anyhow::bail!("function '{}' not found in cfg", selector);
}

fn va_to_rva32(image_base: u64, va: u64) -> Option<u32> {
    if va < image_base {
        return None;
    }
    let rva = va - image_base;
    u32::try_from(rva).ok()
}

const MAX_NODE_PREVIEW_INSTRUCTIONS: usize = 8;

#[derive(Default)]
struct FormatterTokenCollector {
    parts: Vec<(String, FormatterTextKind)>,
}

impl FormatterOutput for FormatterTokenCollector {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        self.parts.push((text.to_string(), kind));
    }
}

struct PlainFormatterOutput<'a> {
    text: &'a mut String,
}

impl FormatterOutput for PlainFormatterOutput<'_> {
    fn write(&mut self, text: &str, _kind: FormatterTextKind) {
        self.text.push_str(text);
    }
}

#[derive(Default)]
struct DecodedBlockView {
    instruction_count: usize,
    preview: Vec<CytoscapeInstructionLine>,
    xref_tokens: Vec<String>,
}

fn formatter_kind_to_css(kind: FormatterTextKind) -> &'static str {
    match kind {
        FormatterTextKind::Mnemonic => "mnemonic",
        FormatterTextKind::Register => "register",
        FormatterTextKind::Number => "immediate",
        FormatterTextKind::FunctionAddress | FormatterTextKind::LabelAddress => "address",
        FormatterTextKind::Prefix => "prefix",
        FormatterTextKind::Keyword | FormatterTextKind::Directive => "keyword",
        FormatterTextKind::Operator | FormatterTextKind::Punctuation => "punct",
        _ => "text",
    }
}

fn normalize_xref_value(text: &str) -> String {
    let trimmed = text.trim().to_ascii_lowercase();
    let cleaned: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == 'x' || *c == '+' || *c == '-')
        .collect();
    if cleaned.is_empty() { trimmed } else { cleaned }
}

fn parse_formatted_number_to_u64(text: &str) -> Option<u64> {
    let mut s = text.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    if s.starts_with('+') {
        s = s.trim_start_matches('+').to_string();
    }
    if s.starts_with('-') {
        return None;
    }
    s = s
        .chars()
        .filter(|c| *c != '_' && *c != '\'' && *c != '`')
        .collect::<String>();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_suffix('h') {
        let hex = hex.trim_start_matches('0');
        if hex.is_empty() {
            return Some(0);
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = s.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    let parse_hex = |raw: &str| -> Option<u64> {
        let hex = raw.trim_start_matches('0');
        if hex.is_empty() {
            Some(0)
        } else {
            u64::from_str_radix(hex, 16).ok()
        }
    };
    if s.chars().all(|c| c.is_ascii_hexdigit()) {
        let has_hex_alpha = s.bytes().any(|b| matches!(b, b'a'..=b'f'));
        let looks_padded_address = s.starts_with('0') && s.len() >= 8;
        let looks_large_digit_address = s.chars().all(|c| c.is_ascii_digit()) && s.len() >= 9;
        if has_hex_alpha || looks_padded_address || looks_large_digit_address {
            if let Some(v) = parse_hex(&s) {
                return Some(v);
            }
        }
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<u64>().ok();
    }
    None
}

fn memory_operand_key(formatter: &mut NasmFormatter, inst: &Instruction, op_index: u32) -> String {
    let mut operand_text = String::new();
    let mut output = PlainFormatterOutput {
        text: &mut operand_text,
    };
    let _ = formatter.format_operand(inst, &mut output, op_index);
    format!("mem:{}", normalize_xref_value(&operand_text))
}

fn immediate_op_value(inst: &Instruction, kind: OpKind) -> Option<u64> {
    match kind {
        OpKind::Immediate8 => Some(inst.immediate8to64() as u64),
        OpKind::Immediate16 => Some(inst.immediate16() as u64),
        OpKind::Immediate32 => Some(inst.immediate32() as u64),
        OpKind::Immediate64 => Some(inst.immediate64()),
        OpKind::Immediate8to16 => Some(inst.immediate8to16() as u64),
        OpKind::Immediate8to32 => Some(inst.immediate8to32() as u64),
        OpKind::Immediate8to64 => Some(inst.immediate8to64() as u64),
        OpKind::Immediate32to64 => Some(inst.immediate32to64() as u64),
        OpKind::NearBranch16 => Some(inst.near_branch16() as u64),
        OpKind::NearBranch32 => Some(inst.near_branch32() as u64),
        OpKind::NearBranch64 => Some(inst.near_branch64()),
        OpKind::FarBranch16 => Some(inst.far_branch16() as u64),
        OpKind::FarBranch32 => Some(inst.far_branch32() as u64),
        _ => None,
    }
}

fn is_memory_op_kind(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

fn decode_block_view(pe: &PeFile, image_base: u64, block: &BlockCfg) -> DecodedBlockView {
    let mut out = DecodedBlockView::default();
    if block.end <= block.start {
        return out;
    }
    let Some(start_rva) = va_to_rva32(image_base, block.start) else {
        return out;
    };
    let size = block.end.saturating_sub(block.start);
    let Ok(size_usize) = usize::try_from(size) else {
        return out;
    };
    let Ok(bytes) = pe.read_rva_slice(start_rva, size_usize) else {
        return out;
    };

    let mut decoder = Decoder::with_ip(64, bytes, block.start, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut xref_tokens = HashSet::<String>::new();
    while decoder.can_decode() {
        let inst = decoder.decode();
        if inst.is_invalid() {
            break;
        }
        if inst.ip() < block.start || inst.ip() >= block.end {
            break;
        }
        out.instruction_count = out.instruction_count.saturating_add(1);

        for op_index in 0..inst.op_count() {
            let op_kind = inst.op_kind(op_index);
            if op_kind == OpKind::Register {
                let reg = inst.op_register(op_index);
                let reg_name = format!("{:?}", reg).to_ascii_lowercase();
                xref_tokens.insert(format!("reg:{reg_name}"));
                continue;
            }
            if is_memory_op_kind(op_kind) {
                xref_tokens.insert(memory_operand_key(&mut formatter, &inst, op_index));
            }
            if let Some(imm) = immediate_op_value(&inst, op_kind) {
                xref_tokens.insert(format!("imm:0x{imm:x}"));
            }
        }

        if out.preview.len() < MAX_NODE_PREVIEW_INSTRUCTIONS {
            let mut collector = FormatterTokenCollector::default();
            formatter.format(&inst, &mut collector);
            let mut tokens = Vec::with_capacity(collector.parts.len());
            for (text, kind) in collector.parts {
                let css_kind = formatter_kind_to_css(kind).to_string();
                let xref = match kind {
                    FormatterTextKind::Register => {
                        Some(format!("reg:{}", normalize_xref_value(&text)))
                    }
                    FormatterTextKind::Number
                    | FormatterTextKind::FunctionAddress
                    | FormatterTextKind::LabelAddress => {
                        if let Some(v) = parse_formatted_number_to_u64(&text) {
                            Some(format!("imm:0x{v:x}"))
                        } else {
                            Some(format!("imm:{}", normalize_xref_value(&text)))
                        }
                    }
                    _ => None,
                };
                if let Some(x) = xref.clone() {
                    xref_tokens.insert(x);
                }
                tokens.push(CytoscapeInstructionToken {
                    text,
                    kind: css_kind,
                    xref,
                });
            }

            out.preview.push(CytoscapeInstructionLine {
                address: String::new(),
                tokens,
            });
        }

        if inst.next_ip() <= inst.ip() || inst.next_ip() > block.end {
            break;
        }
    }
    let mut xrefs = xref_tokens.into_iter().collect::<Vec<_>>();
    xrefs.sort_unstable();
    out.xref_tokens = xrefs;
    out
}

fn resolve_target_function_index(
    target: u64,
    function_by_address: &HashMap<u64, usize>,
    block_owner_by_start: &HashMap<u64, usize>,
    block_ranges: &[(u64, u64, usize)],
) -> Option<usize> {
    if let Some(index) = function_by_address.get(&target).copied() {
        return Some(index);
    }
    if let Some(index) = block_owner_by_start.get(&target).copied() {
        return Some(index);
    }
    block_ranges
        .iter()
        .find(|(start, end, _)| target >= *start && target < *end)
        .map(|(_, _, idx)| *idx)
}

fn is_plausible_synthetic_call_target(target: u64, image_base: u64, pe: Option<&PeFile>) -> bool {
    if target < image_base {
        return false;
    }
    let Some(rva) = va_to_rva32(image_base, target) else {
        return false;
    };
    match pe {
        Some(pe) => pe.section_for_rva(rva).is_some(),
        None => true,
    }
}

fn compute_function_reference_counts(cfg: &ProgramCfg) -> (Vec<usize>, Vec<usize>) {
    let mut function_by_address = HashMap::<u64, usize>::with_capacity(cfg.functions.len());
    let mut block_owner_by_start = HashMap::<u64, usize>::new();
    let mut block_ranges = Vec::<(u64, u64, usize)>::new();
    for (func_idx, func) in cfg.functions.iter().enumerate() {
        function_by_address.insert(func.address, func_idx);
        for block in &func.blocks {
            block_owner_by_start.insert(block.start, func_idx);
            block_ranges.push((block.start, block.end, func_idx));
        }
    }

    let mut refs_to = vec![0usize; cfg.functions.len()];
    let mut refs_from = vec![0usize; cfg.functions.len()];

    for (src_idx, func) in cfg.functions.iter().enumerate() {
        let mut out_refs = 0usize;
        for edge in &func.edges {
            if !matches!(edge.edge_type, EdgeType::Call) {
                continue;
            }
            if let Some(dst_idx) = resolve_target_function_index(
                edge.to,
                &function_by_address,
                &block_owner_by_start,
                &block_ranges,
            ) {
                refs_to[dst_idx] = refs_to[dst_idx].saturating_add(1);
                out_refs = out_refs.saturating_add(1);
            }
        }

        for site in &func.indirect_sites {
            if !matches!(site.kind, IndirectSiteKind::Call) {
                continue;
            }
            let mut seen = HashSet::<usize>::new();
            for target in &site.possible_targets {
                if let Some(dst_idx) = resolve_target_function_index(
                    *target,
                    &function_by_address,
                    &block_owner_by_start,
                    &block_ranges,
                ) {
                    if seen.insert(dst_idx) {
                        refs_to[dst_idx] = refs_to[dst_idx].saturating_add(1);
                        out_refs = out_refs.saturating_add(1);
                    }
                }
            }
        }

        refs_from[src_idx] = out_refs;
    }

    (refs_to, refs_from)
}

#[derive(Debug, Serialize)]
struct CytoscapeExport {
    meta: CytoscapeMeta,
    functions: Vec<CytoscapeFunction>,
}

#[derive(Debug, Serialize)]
struct CytoscapeMeta {
    program_name: String,
    image_base: String,
    total_functions: usize,
    total_blocks: usize,
    total_edges: usize,
    selected_function_id: String,
    instruction_source: String,
}

#[derive(Debug, Serialize)]
struct CytoscapeFunction {
    id: String,
    name: String,
    address: String,
    rva: String,
    block_count: usize,
    edge_count: usize,
    instruction_count: usize,
    refs_to_function: usize,
    refs_from_function: usize,
    indirect_sites_count: usize,
    elements: CytoscapeElements,
}

#[derive(Debug, Serialize)]
struct CytoscapeElements {
    nodes: Vec<CytoscapeNode>,
    edges: Vec<CytoscapeEdge>,
}

#[derive(Debug, Serialize)]
struct CytoscapeNode {
    data: CytoscapeNodeData,
    classes: String,
}

#[derive(Debug, Serialize)]
struct CytoscapeNodeData {
    id: String,
    label: String,
    title: String,
    rva: String,
    start: String,
    end: String,
    size_bytes: u64,
    instruction_count: usize,
    preview_truncated: usize,
    instructions: Vec<CytoscapeInstructionLine>,
    xref_tokens: Vec<String>,
    node_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_function_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CytoscapeEdge {
    data: CytoscapeEdgeData,
    classes: String,
}

#[derive(Debug, Serialize)]
struct CytoscapeEdgeData {
    id: String,
    source: String,
    target: String,
    label: String,
    edge_type: String,
    indirect: bool,
    backward: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_function_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CytoscapeInstructionLine {
    address: String,
    tokens: Vec<CytoscapeInstructionToken>,
}

#[derive(Debug, Serialize)]
struct CytoscapeInstructionToken {
    text: String,
    kind: String,
    xref: Option<String>,
}

fn cmd_export_cytoscape(
    input: Option<PathBuf>,
    cfg_path: PathBuf,
    output: PathBuf,
    function: Option<String>,
) -> Result<()> {
    let cfg = ProgramCfg::from_json_path(&cfg_path)
        .with_context(|| format!("failed to load cfg file {}", cfg_path.display()))?;
    let selected_index = select_function_index(&cfg, function.as_deref())?;

    let pe = if let Some(input_path) = input.as_ref() {
        let bytes = fs::read(input_path)
            .with_context(|| format!("failed to read input binary {}", input_path.display()))?;
        let pe = PeFile::parse(bytes)?;
        if pe.image_base() != cfg.image_base {
            println!(
                "warning: cfg image base 0x{:x} differs from input image base 0x{:x}; counts may be approximate",
                cfg.image_base,
                pe.image_base()
            );
        }
        Some(pe)
    } else {
        None
    };

    let mut function_by_address = HashMap::<u64, usize>::with_capacity(cfg.functions.len());
    let mut block_owner_by_start = HashMap::<u64, usize>::new();
    let mut block_ranges = Vec::<(u64, u64, usize)>::new();
    for (func_idx, func) in cfg.functions.iter().enumerate() {
        function_by_address.insert(func.address, func_idx);
        for block in &func.blocks {
            block_owner_by_start.insert(block.start, func_idx);
            block_ranges.push((block.start, block.end, func_idx));
        }
    }

    let (refs_to, refs_from) = compute_function_reference_counts(&cfg);

    let display_function_name = |index: usize| -> String {
        let raw = cfg.functions[index].name.trim();
        if raw.is_empty() {
            format!("sub_{:x}", cfg.functions[index].address)
        } else {
            raw.to_string()
        }
    };

    let mut functions_out = Vec::with_capacity(cfg.functions.len());
    let mut synthetic_target_refs = HashMap::<u64, usize>::new();
    for (func_idx, func) in cfg.functions.iter().enumerate() {
        let block_starts: HashSet<u64> = func.blocks.iter().map(|b| b.start).collect();

        let mut outgoing_branch_like = HashMap::<u64, usize>::new();
        let mut branch_count_by_from = HashMap::<u64, usize>::new();
        let mut fallthrough_count_by_from = HashMap::<u64, usize>::new();
        for edge in &func.edges {
            if matches!(edge.edge_type, EdgeType::Branch | EdgeType::Fallthrough)
                && block_starts.contains(&edge.from)
            {
                *outgoing_branch_like.entry(edge.from).or_insert(0) += 1;
            }
            if block_starts.contains(&edge.from) {
                match edge.edge_type {
                    EdgeType::Branch => {
                        *branch_count_by_from.entry(edge.from).or_insert(0) += 1;
                    }
                    EdgeType::Fallthrough => {
                        *fallthrough_count_by_from.entry(edge.from).or_insert(0) += 1;
                    }
                    EdgeType::Call => {}
                }
            }
        }

        let mut function_instruction_count = 0usize;
        let mut nodes = Vec::with_capacity(func.blocks.len());
        for block in &func.blocks {
            let decode_view = pe
                .as_ref()
                .map(|p| decode_block_view(p, cfg.image_base, block))
                .unwrap_or_default();
            let inst_count = decode_view.instruction_count;
            function_instruction_count = function_instruction_count.saturating_add(inst_count);

            let rva = block.start.saturating_sub(cfg.image_base);
            let mut classes = Vec::new();
            if block.start == func.address {
                classes.push("entry");
            }
            if outgoing_branch_like.get(&block.start).copied().unwrap_or(0) == 0 {
                classes.push("exit");
            }
            if func
                .indirect_sites
                .iter()
                .any(|s| s.address >= block.start && s.address < block.end)
            {
                classes.push("has-indirect");
            }

            nodes.push(CytoscapeNode {
                data: CytoscapeNodeData {
                    id: format!("b_{:x}", block.start),
                    label: format!("loc_{rva:x}"),
                    title: format!("0x{:x}", block.start),
                    rva: format!("0x{rva:x}"),
                    start: format!("0x{:x}", block.start),
                    end: format!("0x{:x}", block.end),
                    size_bytes: block.end.saturating_sub(block.start),
                    instruction_count: inst_count,
                    preview_truncated: inst_count.saturating_sub(decode_view.preview.len()),
                    instructions: decode_view.preview,
                    xref_tokens: decode_view.xref_tokens,
                    node_kind: "block".to_string(),
                    target_function_id: None,
                },
                classes: classes.join(" "),
            });
        }

        let mut edges = Vec::<CytoscapeEdge>::new();
        let mut external_nodes = HashSet::<u64>::new();
        for (edge_idx, edge) in func.edges.iter().enumerate() {
            if !block_starts.contains(&edge.from) {
                continue;
            }
            let source = format!("b_{:x}", edge.from);
            let mut target_function_id: Option<String> = None;
            let target = if block_starts.contains(&edge.to) {
                format!("b_{:x}", edge.to)
            } else if matches!(edge.edge_type, EdgeType::Call) {
                let target_id = format!("x_{:x}", edge.to);
                if external_nodes.insert(edge.to) {
                    let (title, classes, linked_function_id) = if let Some(target_idx) =
                        resolve_target_function_index(
                            edge.to,
                            &function_by_address,
                            &block_owner_by_start,
                            &block_ranges,
                        ) {
                        let fid = format!("fn_{:x}", cfg.functions[target_idx].address);
                        (
                            format!(
                                "{}\\n0x{:x}",
                                display_function_name(target_idx),
                                cfg.functions[target_idx].address
                            ),
                            "external known-function".to_string(),
                            Some(fid),
                        )
                    } else if is_plausible_synthetic_call_target(
                        edge.to,
                        cfg.image_base,
                        pe.as_ref(),
                    ) {
                        let fid = format!("fn_{:x}", edge.to);
                        (
                            format!("sub_{:x}\\n0x{:x}", edge.to, edge.to),
                            "external synthetic-target".to_string(),
                            Some(fid),
                        )
                    } else {
                        (format!("sub_{:x}", edge.to), "external".to_string(), None)
                    };
                    nodes.push(CytoscapeNode {
                        data: CytoscapeNodeData {
                            id: target_id.clone(),
                            label: title.clone(),
                            title,
                            rva: if edge.to >= cfg.image_base {
                                format!("0x{:x}", edge.to - cfg.image_base)
                            } else {
                                "0x0".to_string()
                            },
                            start: format!("0x{:x}", edge.to),
                            end: format!("0x{:x}", edge.to),
                            size_bytes: 0,
                            instruction_count: 0,
                            preview_truncated: 0,
                            instructions: Vec::new(),
                            xref_tokens: Vec::new(),
                            node_kind: "external".to_string(),
                            target_function_id: linked_function_id.clone(),
                        },
                        classes,
                    });
                    target_function_id = linked_function_id;
                } else if let Some(target_idx) = resolve_target_function_index(
                    edge.to,
                    &function_by_address,
                    &block_owner_by_start,
                    &block_ranges,
                ) {
                    target_function_id =
                        Some(format!("fn_{:x}", cfg.functions[target_idx].address));
                } else if is_plausible_synthetic_call_target(edge.to, cfg.image_base, pe.as_ref()) {
                    target_function_id = Some(format!("fn_{:x}", edge.to));
                }
                target_id
            } else {
                continue;
            };

            if target_function_id.is_some() && !function_by_address.contains_key(&edge.to) {
                *synthetic_target_refs.entry(edge.to).or_insert(0) += 1;
            }

            let edge_type = match edge.edge_type {
                EdgeType::Call => "call",
                EdgeType::Branch => {
                    let branch_count = branch_count_by_from.get(&edge.from).copied().unwrap_or(0);
                    let fallthrough_count = fallthrough_count_by_from
                        .get(&edge.from)
                        .copied()
                        .unwrap_or(0);
                    if branch_count == 1 && fallthrough_count == 0 && !edge.indirect {
                        "unconditional"
                    } else {
                        "branch-true"
                    }
                }
                EdgeType::Fallthrough => "branch-false",
            };
            let mut classes = vec![edge_type];
            if edge.indirect {
                classes.push("indirect");
            }
            let backward = block_starts.contains(&edge.to) && edge.to < edge.from;
            if backward {
                classes.push("loop-back");
            }
            edges.push(CytoscapeEdge {
                data: CytoscapeEdgeData {
                    id: format!("e_{func_idx:05x}_{edge_idx:05x}"),
                    source,
                    target,
                    label: edge_type.to_string(),
                    edge_type: edge_type.to_string(),
                    indirect: edge.indirect,
                    backward,
                    target_function_id,
                },
                classes: classes.join(" "),
            });
        }

        let function_rva = func.address.saturating_sub(cfg.image_base);
        functions_out.push(CytoscapeFunction {
            id: format!("fn_{:x}", func.address),
            name: display_function_name(func_idx),
            address: format!("0x{:x}", func.address),
            rva: format!("0x{function_rva:x}"),
            block_count: func.blocks.len(),
            edge_count: edges.len(),
            instruction_count: function_instruction_count,
            refs_to_function: refs_to.get(func_idx).copied().unwrap_or(0),
            refs_from_function: refs_from.get(func_idx).copied().unwrap_or(0),
            indirect_sites_count: func.indirect_sites.len(),
            elements: CytoscapeElements { nodes, edges },
        });
    }

    let mut synthetic_sorted = BTreeMap::<u64, usize>::new();
    for (target, refs) in synthetic_target_refs {
        synthetic_sorted.insert(target, refs);
    }
    let mut existing_ids = functions_out
        .iter()
        .map(|f| f.id.clone())
        .collect::<HashSet<_>>();
    for (target, refs_to_function) in synthetic_sorted {
        let id = format!("fn_{target:x}");
        if existing_ids.contains(&id) {
            continue;
        }
        existing_ids.insert(id.clone());
        let name = format!("sub_{target:x}");
        let rva = if target >= cfg.image_base {
            format!("0x{:x}", target - cfg.image_base)
        } else {
            "0x0".to_string()
        };
        functions_out.push(CytoscapeFunction {
            id,
            name: name.clone(),
            address: format!("0x{target:x}"),
            rva: rva.clone(),
            block_count: 1,
            edge_count: 0,
            instruction_count: 0,
            refs_to_function,
            refs_from_function: 0,
            indirect_sites_count: 0,
            elements: CytoscapeElements {
                nodes: vec![CytoscapeNode {
                    data: CytoscapeNodeData {
                        id: format!("sx_{target:x}"),
                        label: name.clone(),
                        title: format!("{name}\\n0x{target:x}"),
                        rva,
                        start: format!("0x{target:x}"),
                        end: format!("0x{target:x}"),
                        size_bytes: 0,
                        instruction_count: 0,
                        preview_truncated: 0,
                        instructions: Vec::new(),
                        xref_tokens: Vec::new(),
                        node_kind: "external".to_string(),
                        target_function_id: None,
                    },
                    classes: "external synthetic-root".to_string(),
                }],
                edges: Vec::new(),
            },
        });
    }

    let selected_function_id = functions_out
        .get(selected_index)
        .map(|f| f.id.clone())
        .ok_or_else(|| anyhow::anyhow!("internal error: selected function not present"))?;

    let out = CytoscapeExport {
        meta: CytoscapeMeta {
            program_name: cfg.program_name,
            image_base: format!("0x{:x}", cfg.image_base),
            total_functions: functions_out.len(),
            total_blocks: functions_out.iter().map(|f| f.block_count).sum(),
            total_edges: functions_out.iter().map(|f| f.edge_count).sum(),
            selected_function_id,
            instruction_source: if pe.is_some() {
                "decoded".to_string()
            } else {
                "unavailable".to_string()
            },
        },
        functions: functions_out,
    };

    let json = serde_json::to_string_pretty(&out)?;
    fs::write(&output, json)
        .with_context(|| format!("failed to write cytoscape json {}", output.display()))?;

    println!(
        "export-cytoscape ok: output='{}' functions={} selected='{}' instruction_source={}",
        output.display(),
        out.meta.total_functions,
        out.meta.selected_function_id,
        out.meta.instruction_source
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_cfg() -> ProgramCfg {
        ProgramCfg {
            program_name: "demo.exe".to_string(),
            image_base: 0x140000000,
            functions: vec![
                FunctionCfg {
                    name: "main".to_string(),
                    address: 0x140001000,
                    blocks: vec![BlockCfg {
                        start: 0x140001000,
                        end: 0x140001010,
                    }],
                    edges: Vec::new(),
                    indirect_call_sites: Vec::new(),
                    indirect_sites: Vec::new(),
                    jump_tables: Vec::new(),
                },
                FunctionCfg {
                    name: "Helper".to_string(),
                    address: 0x140002000,
                    blocks: vec![BlockCfg {
                        start: 0x140002000,
                        end: 0x140002010,
                    }],
                    edges: Vec::new(),
                    indirect_call_sites: Vec::new(),
                    indirect_sites: Vec::new(),
                    jump_tables: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn parse_hex_u64_cli_supports_prefix() {
        assert_eq!(parse_hex_u64_cli("0x140001000").unwrap(), 0x140001000);
        assert_eq!(parse_hex_u64_cli("140001000").unwrap(), 0x140001000);
        assert!(parse_hex_u64_cli("xyz").is_err());
    }

    #[test]
    fn select_function_by_name_or_address() {
        let cfg = demo_cfg();
        let main_idx = select_function_index(&cfg, Some("main")).unwrap();
        let helper_idx = select_function_index(&cfg, Some("helper")).unwrap();
        let addr_idx = select_function_index(&cfg, Some("0x140002000")).unwrap();
        assert_eq!(cfg.functions[main_idx].address, 0x140001000);
        assert_eq!(cfg.functions[helper_idx].address, 0x140002000);
        assert_eq!(cfg.functions[addr_idx].name, "Helper");
        assert!(select_function_index(&cfg, Some("missing")).is_err());
    }

    #[test]
    fn compute_reference_counts_handles_direct_and_indirect_calls() {
        let mut cfg = demo_cfg();
        cfg.functions[0].edges.push(blare_cfg::EdgeCfg {
            from: 0x140001000,
            to: 0x140002000,
            edge_type: EdgeType::Call,
            indirect: false,
        });
        cfg.functions[0]
            .indirect_sites
            .push(blare_cfg::IndirectSiteCfg {
                address: 0x140001004,
                kind: IndirectSiteKind::Call,
                possible_targets: vec![0x140002000],
            });
        let (refs_to, refs_from) = compute_function_reference_counts(&cfg);
        assert_eq!(refs_to[1], 2);
        assert_eq!(refs_from[0], 2);
    }
}
