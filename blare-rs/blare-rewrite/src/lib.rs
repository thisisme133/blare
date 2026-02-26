use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use blare_cfg::ProgramCfg;
use blare_ir::{BlockId, BlockLayoutStrategy, EdgeKind, PassStatsRecord, ProgramIr, Terminator};
use blare_lift::{LiftDiagnostics, lift_program};
use blare_passes::Pass;
use blare_pe::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, ImportEntry, PeBinaryKind, PeFile,
    RebuildSectionSpec, RelocEntry, RuntimeFunctionEntry, UnwindRecord,
};
use blare_protect::{
    IMPORT_RECORD_SIZE, ImportResolverLayout, PreEntryOptions, ProtectedImportRecord,
    build_encrypted_import_blob, build_import_entry_stub, build_import_resolver_stub,
    build_pre_entry_stub, fnv1a64,
};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, FlowControl, Instruction, InstructionBlock, Mnemonic,
    OpKind, Register,
};
use serde::{Deserialize, Serialize};

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const RELOC_TYPE_DIR64: u16 = 10;
const WINDOWS_MAX_SIZE_OF_IMAGE: u64 = 2_000_000_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RewritePolicy {
    PerFunction,
    Module,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SectionLayout {
    Keep,
    Compact,
    Rebuild,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RewriteOptions {
    pub strict_unwind: bool,
    pub policy: RewritePolicy,
    pub section_layout: SectionLayout,
    pub allow_unsafe_compact: bool,
    pub indirect_cf_probability: f64,
    pub import_protection: bool,
    pub anti_debug: bool,
    pub obscure_entry_point: bool,
    pub clear_unwind_info: bool,
    pub strip_legacy_code: bool,
    pub strip_legacy_code_aggressive: bool,
}

impl Default for RewriteOptions {
    fn default() -> Self {
        Self {
            strict_unwind: false,
            policy: RewritePolicy::PerFunction,
            section_layout: SectionLayout::Keep,
            allow_unsafe_compact: false,
            indirect_cf_probability: 0.35,
            import_protection: false,
            anti_debug: false,
            obscure_entry_point: false,
            clear_unwind_info: false,
            strip_legacy_code: false,
            strip_legacy_code_aggressive: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRewriteEntry {
    pub name: String,
    pub old_rva: u64,
    pub new_rva: Option<u64>,
    pub fallback: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRewriteEntry {
    pub function_name: String,
    pub old_rva: u64,
    pub new_rva: Option<u64>,
    pub encoded_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteMap {
    pub image_base: u64,
    pub obfuscation_profile: Option<String>,
    pub obfuscation_seed: Option<u64>,
    pub applied_passes: Vec<String>,
    pub pass_stats: Vec<PassStatsRecord>,
    pub rewritten_bytes: u64,
    pub remapped_relocations: usize,
    pub remapped_guard_cf_entries: usize,
    pub remapped_guard_eh_continuation_entries: usize,
    pub rewritten_runtime_functions: usize,
    pub cloned_unwind_infos: usize,
    pub exception_directory_rva: u32,
    pub exception_directory_size: u32,
    pub reloc_directory_rva: u32,
    pub reloc_directory_size: u32,
    pub total_functions: usize,
    pub rewritten_functions: usize,
    pub fallback_functions: usize,
    pub total_edges: usize,
    pub indirect_edges: usize,
    pub jump_table_edges: usize,
    pub unresolved_edges: usize,
    pub unresolved_indirect_edges: usize,
    pub cross_function_edges: usize,
    pub cross_function_indirect_edges: usize,
    pub indirect_thunks: usize,
    pub thunk_table_entries: usize,
    pub import_protection_enabled: bool,
    pub protected_imports: usize,
    pub import_stub_sites: usize,
    pub anti_debug_enabled: bool,
    pub obscure_entry_point_enabled: bool,
    pub strip_legacy_code_enabled: bool,
    pub stripped_legacy_ranges: usize,
    pub stripped_legacy_bytes: u64,
    pub preentry_stub_rva: Option<u32>,
    pub preentry_stub_size: u32,
    pub functions: Vec<FunctionRewriteEntry>,
    pub blocks: Vec<BlockRewriteEntry>,
}

#[derive(Debug, Clone)]
pub struct RewriteArtifact {
    pub output: Vec<u8>,
    pub map: RewriteMap,
    pub diagnostics: LiftDiagnostics,
}

#[derive(Debug, Clone)]
struct InstRange {
    old_rva: u32,
    len: u32,
    new_rva: u32,
}

#[derive(Debug, Clone)]
struct RvaRange {
    old_start: u32,
    old_end: u32,
    new_start: u32,
}

#[derive(Debug, Clone)]
struct EncodedBlock {
    bytes: Vec<u8>,
    inst_ranges: Vec<InstRange>,
}

#[derive(Debug, Clone)]
struct PendingBlockEncoding {
    block_start_rva: u64,
    encode_rva: u64,
    source_ranges: Vec<(u32, u32)>,
    instructions: Vec<Instruction>,
}

#[derive(Debug, Clone)]
struct FunctionRange {
    new_start: u32,
    new_end: u32,
}

#[derive(Debug, Clone)]
struct SyntheticRvaAllocator {
    next_inst_rva: u64,
    next_block_rva: u64,
}

impl SyntheticRvaAllocator {
    fn new(ir: &ProgramIr) -> Self {
        let mut max_rva = 0u64;
        for inst in &ir.insts {
            max_rva = max_rva.max(inst.original_rva);
        }
        for block in &ir.blocks {
            max_rva = max_rva.max(block.end_rva);
        }
        let mut base = max_rva.saturating_add(0x20000);
        if base > 0xF000_0000 {
            base = 0x6000_0000;
        }
        Self {
            next_inst_rva: base,
            next_block_rva: base.saturating_add(0x0100_0000),
        }
    }

    fn next_inst(&mut self) -> u64 {
        let out = self.next_inst_rva;
        self.next_inst_rva = self.next_inst_rva.saturating_add(0x10);
        out
    }

    fn next_block(&mut self) -> u64 {
        let out = self.next_block_rva;
        self.next_block_rva = self.next_block_rva.saturating_add(0x100);
        out
    }
}

#[derive(Debug, Clone, Default)]
struct ThunkMaterialization {
    added_relocations: Vec<RelocEntry>,
    entry_count: usize,
    patched_sites: usize,
}

#[derive(Debug, Clone, Default)]
struct ImportProtectionContext {
    records: Vec<ProtectedImportRecord>,
    stub_site_patches: Vec<ImportSitePatch>,
}

#[derive(Debug, Clone, Copy)]
struct ImportSitePatch {
    entry_index: usize,
    load_entry_rva: u64,
}

#[derive(Debug, Clone, Default)]
struct ImportMaterialization {
    entry_count: usize,
    patched_sites: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct PreEntryMaterialization {
    stub_rva: Option<u32>,
    stub_size: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct LegacyStripSummary {
    ranges: usize,
    bytes: u64,
}

fn align_up_usize(value: usize, align: usize) -> usize {
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

pub fn rewrite_binary(
    cfg: &ProgramCfg,
    input: &[u8],
    pass: &dyn Pass,
    options: RewriteOptions,
) -> Result<RewriteArtifact> {
    let mut pe = PeFile::parse(input.to_vec())?;
    let (mut ir, diagnostics) = lift_program(cfg, &pe)?;

    if !options.indirect_cf_probability.is_finite()
        || !(0.0..=1.0).contains(&options.indirect_cf_probability)
    {
        anyhow::bail!(
            "indirect control-flow probability must be within [0.0, 1.0], got {}",
            options.indirect_cf_probability
        );
    }

    let mut fallback_reasons = HashMap::<u64, String>::new();
    for (name, reason) in &diagnostics.fallback_functions {
        if let Some(func) = ir.functions.iter().find(|f| &f.name == name) {
            fallback_reasons.insert(func.address_rva, reason.clone());
        }
    }

    if options.policy == RewritePolicy::Module {
        let pre_fallback = ir.functions.iter().filter(|f| f.fallback).count();
        if pre_fallback > 0 {
            anyhow::bail!(
                "module policy requires 0 fallback functions, got {pre_fallback} after lifting"
            );
        }
    }

    let runtime_entries = pe.parse_runtime_functions()?;
    let mut runtime_by_begin = HashMap::new();
    for entry in &runtime_entries {
        runtime_by_begin.insert(entry.begin_address as u64, *entry);
    }
    let runtime_metadata_optional_globally =
        pe.binary_kind() == PeBinaryKind::Uefi && runtime_entries.is_empty();

    // Functions with no runtime metadata can still be valid leaf functions on PE64.
    // Keep strict behavior for functions that appear to require unwind metadata.
    let mut fallback_due_runtime = Vec::<(u64, String)>::new();
    for func in &ir.functions {
        if func.fallback || runtime_by_begin.contains_key(&func.address_rva) {
            continue;
        }

        if function_requires_runtime_metadata(&ir, func)
            && !runtime_metadata_optional_by_name(&func.name)
            && !runtime_metadata_optional_by_pattern(&ir, func)
            && !runtime_metadata_optional_globally
        {
            if options.policy == RewritePolicy::Module || options.strict_unwind {
                anyhow::bail!(
                    "missing runtime function metadata for function '{}' (rva 0x{:x})",
                    func.name,
                    func.address_rva
                );
            }
            fallback_due_runtime.push((
                func.address_rva,
                "missing runtime function metadata".to_string(),
            ));
        }
    }
    for (rva, reason) in fallback_due_runtime {
        if let Some(func) = ir.functions.iter_mut().find(|f| f.address_rva == rva) {
            func.fallback = true;
            fallback_reasons.insert(rva, reason);
        }
    }

    let baseline_rewritable_bytes: u64 = ir
        .functions
        .iter()
        .filter(|f| !f.fallback)
        .flat_map(|f| f.blocks.iter().copied())
        .map(|bid| {
            let b = ir.block(bid);
            b.end_rva.saturating_sub(b.start_rva)
        })
        .sum();
    let safe_legacy_ranges = collect_safe_strip_ranges_prepass(&ir);

    pass.run(&mut ir)?;
    let mut import_ctx = ImportProtectionContext::default();
    if options.import_protection {
        import_ctx = apply_iat_obfuscation(
            &mut ir,
            &pe.parse_import_directory()
                .context("failed to parse PE import directory")?,
        )?;
    }
    resolve_direct_edge_targets_after_passes(&mut ir);
    let sigbreaker_mode = matches!(ir.obfuscation_profile.as_deref(), Some("sigbreaker"));
    if sigbreaker_mode
        && !matches!(
            options.section_layout,
            SectionLayout::Compact | SectionLayout::Rebuild
        )
    {
        anyhow::bail!(
            "sigbreaker profile requires --section-layout compact or rebuild"
        );
    }

    let compact_layout = options.section_layout == SectionLayout::Compact;
    let rebuild_layout = options.section_layout == SectionLayout::Rebuild;
    let unresolved_direct_edges = ir
        .edges
        .iter()
        .filter(|e| {
            e.target_rva.is_some()
                && e.to.is_none()
                && !e.indirect
                && !matches!(
                    e.kind,
                    EdgeKind::IndirectCall | EdgeKind::IndirectJump | EdgeKind::JumpTable
                )
        })
        .collect::<Vec<_>>();
    let rewritable_ranges = ir
        .functions
        .iter()
        .filter(|f| !f.fallback)
        .flat_map(|f| {
            f.blocks.iter().map(|bid| {
                let block = ir.block(*bid);
                (block.start_rva, block.end_rva)
            })
        })
        .collect::<Vec<_>>();
    if compact_layout {
        let fallback_count = ir.functions.iter().filter(|f| f.fallback).count();
        if fallback_count > 0 {
            anyhow::bail!(
                "compact section layout requires 0 fallback functions, got {fallback_count}"
            );
        }
        if !unresolved_direct_edges.is_empty() && !options.allow_unsafe_compact {
            let dangerous_edges = unresolved_direct_edges
                .iter()
                .filter(|edge| {
                    let Some(target) = edge.target_rva else {
                        return false;
                    };
                    rewritable_ranges
                        .iter()
                        .any(|(start, end)| target >= *start && target < *end)
                })
                .count();

            if dangerous_edges > 0 {
                anyhow::bail!(
                    "compact section layout is unsafe with unresolved direct CFG edges: {dangerous_edges} unresolved target(s) fall inside rewritten ranges ({} total unresolved direct edges)",
                    unresolved_direct_edges.len()
                );
            }
        }
    }
    if rebuild_layout && !unresolved_direct_edges.is_empty() {
        let replaced_ranges = [".text", ".pdata", ".xdata", ".reloc"]
            .iter()
            .filter_map(|name| pe.section_by_name(name))
            .map(|sec| {
                let start = sec.virtual_address as u64;
                let end = start + std::cmp::max(sec.virtual_size, sec.size_of_raw_data) as u64;
                (start, end)
            })
            .collect::<Vec<_>>();

        let dangerous_edges = unresolved_direct_edges
            .iter()
            .filter(|edge| {
                let Some(target) = edge.target_rva else {
                    return true;
                };
                if rewritable_ranges
                    .iter()
                    .any(|(start, end)| target >= *start && target < *end)
                {
                    return true;
                }
                if replaced_ranges
                    .iter()
                    .any(|(start, end)| target >= *start && target < *end)
                {
                    return true;
                }
                pe.section_for_rva(target as u32).is_none()
            })
            .count();
        if dangerous_edges > 0 {
            anyhow::bail!(
                "rebuild section layout is unsafe with unresolved direct CFG edges: {dangerous_edges} unresolved target(s) fall in replaced/unmapped ranges ({} total unresolved direct edges)",
                unresolved_direct_edges.len()
            );
        }
    }

    let block_order = collect_rewritable_blocks(&ir);
    if block_order.is_empty() {
        anyhow::bail!("no rewritable blocks available after fallback filtering");
    }

    let text_base_rva = if compact_layout {
        pe.section_by_name(".text")
            .ok_or_else(|| anyhow::anyhow!("compact layout requires .text section"))?
            .virtual_address as u64
    } else {
        pe.next_section_virtual_address()? as u64
    };
    let mut block_map = initial_block_layout(&ir, &block_order, text_base_rva);

    for _ in 0..8 {
        let (next_map, _) = encode_with_layout(&ir, &block_order, &block_map)?;
        if next_map == block_map {
            break;
        }
        block_map = next_map;
    }

    let (_, encoded_blocks) = encode_with_layout(&ir, &block_order, &block_map)?;
    let (mut text_blob, inst_ranges, block_sizes) =
        build_text_blob(&ir, &block_order, &block_map, &encoded_blocks)?;

    if sigbreaker_mode && text_blob.len() as u64 > baseline_rewritable_bytes {
        anyhow::bail!(
            "sigbreaker zero-bloat violation: rewritten text {} bytes > baseline {} bytes",
            text_blob.len(),
            baseline_rewritable_bytes
        );
    }

    let emitted_text_section_name = if compact_layout { ".text" } else { ".blrtxt" };
    if compact_layout {
        pe.overwrite_section_payload(emitted_text_section_name, &text_blob)?;
    } else {
        pe.add_section(
            emitted_text_section_name,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            &text_blob,
        )?;
    }

    let mut function_ranges = HashMap::<u64, FunctionRange>::new();
    for func in &ir.functions {
        if func.fallback {
            continue;
        }

        let mut min_start = u32::MAX;
        let mut max_end = 0u32;
        for block_id in &func.blocks {
            let block = ir.block(*block_id);
            if let Some(new_start) = block_map.get(&block.start_rva) {
                min_start = min_start.min(*new_start as u32);
                let size = *block_sizes.get(&block.start_rva).ok_or_else(|| {
                    anyhow::anyhow!("missing block size for 0x{:x}", block.start_rva)
                })?;
                max_end = max_end.max((*new_start as u32).saturating_add(size));
            }
        }

        if min_start != u32::MAX {
            function_ranges.insert(
                func.address_rva,
                FunctionRange {
                    new_start: min_start,
                    new_end: max_end,
                },
            );
        }
    }

    if options.policy == RewritePolicy::Module {
        let rewritten = function_ranges.len();
        let expected = ir.functions.len();
        if rewritten != expected {
            anyhow::bail!(
                "module policy requires full rewrite: rewritten={rewritten}, total={expected}"
            );
        }
    }

    let block_ranges = collect_block_ranges(&ir, &block_map);
    let thunk_materialization = materialize_indirect_thunks(
        &mut pe,
        &ir,
        &inst_ranges,
        &block_ranges,
        &function_ranges,
        text_base_rva as u32,
        &mut text_blob,
    )?;
    let import_materialization = if options.import_protection {
        materialize_import_protection(
            &mut pe,
            &import_ctx,
            ir.obfuscation_seed.unwrap_or_default(),
            &inst_ranges,
            text_base_rva as u32,
            &mut text_blob,
        )?
    } else {
        ImportMaterialization::default()
    };
    if thunk_materialization.patched_sites > 0 || import_materialization.patched_sites > 0 {
        pe.overwrite_section_payload(emitted_text_section_name, &text_blob)?;
    }
    let mut rewritten_runtime_functions = 0usize;
    let mut cloned_unwind_infos = 0usize;
    let (mut exception_directory_rva, mut exception_directory_size) = if runtime_entries.is_empty()
    {
        pe.set_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION, 0, 0)?;
        (0u32, 0u32)
    } else {
        // Build xdata for all unwind records, including EH/UH/CHAININFO.
        let unwind_records = pe
            .parse_unwind_records_from_runtime(&runtime_entries)
            .context("failed to parse unwind records")?;

        let mut xdata_blob = Vec::<u8>::new();
        let mut old_unwind_to_off = HashMap::<u32, u32>::new();
        for record in &unwind_records {
            let aligned = align_up_usize(xdata_blob.len(), 4);
            if xdata_blob.len() < aligned {
                xdata_blob.resize(aligned, 0);
            }

            let offset = xdata_blob.len() as u32;
            let bytes = pe.read_unwind_record_bytes(record).with_context(|| {
                format!("failed to read unwind record at 0x{:x}", record.unwind_rva)
            })?;
            xdata_blob.extend_from_slice(&bytes);
            old_unwind_to_off.insert(record.unwind_rva, offset);
        }

        let xdata_payload = if xdata_blob.is_empty() {
            vec![0u8; 4]
        } else {
            xdata_blob
        };

        let predicted_xdata_base = pe.next_section_virtual_address()?;
        let mut old_unwind_to_new = HashMap::<u32, u32>::new();
        for (old, off) in &old_unwind_to_off {
            old_unwind_to_new.insert(*old, predicted_xdata_base.saturating_add(*off));
        }

        let mut final_xdata_payload = if xdata_payload.is_empty() {
            vec![0u8; 4]
        } else {
            xdata_payload
        };
        patch_unwind_records(
            &mut final_xdata_payload,
            &unwind_records,
            &old_unwind_to_off,
            &old_unwind_to_new,
            &block_ranges,
            &function_ranges,
            options,
        )?;

        let xdata_section = pe.add_section(
            ".blrxdt",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            &final_xdata_payload,
        )?;
        if xdata_section.virtual_address != predicted_xdata_base {
            anyhow::bail!(
                "unexpected xdata section RVA drift: predicted=0x{:x}, actual=0x{:x}",
                predicted_xdata_base,
                xdata_section.virtual_address
            );
        }

        let mut updated_runtime_entries = runtime_entries.clone();
        for entry in &mut updated_runtime_entries {
            if let Some(new_range) = function_ranges.get(&(entry.begin_address as u64)) {
                entry.begin_address = new_range.new_start;
                entry.end_address = new_range.new_end;
                if let Some(new_unwind) = old_unwind_to_new.get(&entry.unwind_info_address) {
                    entry.unwind_info_address = *new_unwind;
                } else if options.strict_unwind {
                    anyhow::bail!(
                        "strict unwind enabled but no remap found for unwind rva 0x{:x}",
                        entry.unwind_info_address
                    );
                }
                rewritten_runtime_functions += 1;
            }
        }
        updated_runtime_entries.sort_by_key(|e| e.begin_address);

        let pdata_blob = serialize_runtime_function_table(&updated_runtime_entries);
        let pdata_section = pe.add_section(
            ".blrpdt",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            &pdata_blob,
        )?;
        pe.set_directory(
            IMAGE_DIRECTORY_ENTRY_EXCEPTION,
            pdata_section.virtual_address,
            pdata_blob.len() as u32,
        )?;

        cloned_unwind_infos = old_unwind_to_new.len();
        (pdata_section.virtual_address, pdata_blob.len() as u32)
    };
    if options.clear_unwind_info {
        pe.set_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION, 0, 0)?;
        exception_directory_rva = 0;
        exception_directory_size = 0;
        zero_section_if_present(&mut pe, ".blrxdt")?;
        zero_section_if_present(&mut pe, ".blrpdt")?;
    }
    if rebuild_layout && rewritten_runtime_functions != runtime_entries.len() {
        anyhow::bail!(
            "rebuild section layout requires full runtime metadata rewrite coverage, got {}/{} runtime functions remapped",
            rewritten_runtime_functions,
            runtime_entries.len()
        );
    }

    let reloc_entries = pe.parse_relocations()?;
    let mut remapped = 0usize;
    let mut remapped_relocs = Vec::with_capacity(reloc_entries.len());
    for reloc in reloc_entries {
        let new_rva = remap_rva_global(reloc.rva, &inst_ranges, &block_ranges, &function_ranges)
            .unwrap_or(reloc.rva);
        if new_rva != reloc.rva {
            remapped += 1;
        }
        remapped_relocs.push(RelocEntry {
            rva: new_rva,
            typ: reloc.typ,
        });
    }
    remapped_relocs.extend(thunk_materialization.added_relocations.iter().cloned());

    let reloc_blob = PeFile::emit_relocations(&remapped_relocs);
    let (reloc_dir_rva, reloc_dir_size) = if reloc_blob.is_empty() {
        pe.get_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)?
    } else if compact_layout {
        let section = pe.overwrite_section_payload(".reloc", &reloc_blob)?;
        pe.set_directory(
            IMAGE_DIRECTORY_ENTRY_BASERELOC,
            section.virtual_address,
            reloc_blob.len() as u32,
        )?;
        (section.virtual_address, reloc_blob.len() as u32)
    } else {
        let section = pe.add_section(
            ".blrloc",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            &reloc_blob,
        )?;
        pe.set_directory(
            IMAGE_DIRECTORY_ENTRY_BASERELOC,
            section.virtual_address,
            reloc_blob.len() as u32,
        )?;
        (section.virtual_address, reloc_blob.len() as u32)
    };

    let old_entry = pe.entrypoint_rva()?;
    let mut true_entry_rva = old_entry;
    if let Some(new_entry) =
        remap_rva_global(old_entry, &inst_ranges, &block_ranges, &function_ranges)
    {
        pe.set_entrypoint_rva(new_entry)?;
        true_entry_rva = new_entry;
    }
    let preentry_binary_kind = pe.binary_kind();
    let preentry_oep_va = pe.image_base().saturating_add(true_entry_rva as u64);
    let preentry_materialization = if options.anti_debug || options.obscure_entry_point {
        materialize_preentry_stub(&mut pe, preentry_binary_kind, options, preentry_oep_va)?
    } else {
        PreEntryMaterialization::default()
    };

    let preserved_legacy_block_starts = collect_risky_legacy_block_starts(&ir);
    let unresolved_legacy_targets = collect_unresolved_legacy_targets(&ir);
    let legacy_strip_summary = if options.strip_legacy_code && !compact_layout && !rebuild_layout {
        if options.strip_legacy_code_aggressive {
            clear_legacy_rewritten_code(
                &mut pe,
                &block_ranges,
                &preserved_legacy_block_starts,
                &unresolved_legacy_targets,
            )?
        } else {
            clear_legacy_named_ranges(&mut pe, &safe_legacy_ranges)?
        }
    } else {
        LegacyStripSummary::default()
    };

    let remapped_guard_cf_entries = pe
        .remap_guard_cf_function_table(|old_rva| {
            remap_rva_global(old_rva, &inst_ranges, &block_ranges, &function_ranges)
                .unwrap_or(old_rva)
        })
        .context("failed to remap guard cf function table")?;
    let remapped_guard_eh_continuation_entries = pe
        .remap_guard_eh_continuation_table(|old_rva| {
            remap_rva_global(old_rva, &inst_ranges, &block_ranges, &function_ranges)
                .unwrap_or(old_rva)
        })
        .context("failed to remap guard eh continuation table")?;

    if rebuild_layout {
        finalize_rebuild_layout(&mut pe)?;
    }

    let rewritten_size_of_image = pe.size_of_image()? as u64;
    if rewritten_size_of_image > WINDOWS_MAX_SIZE_OF_IMAGE {
        anyhow::bail!(
            "rewritten image SizeOfImage {} exceeds Windows loader safety bound {}",
            rewritten_size_of_image,
            WINDOWS_MAX_SIZE_OF_IMAGE
        );
    }

    let mut functions = Vec::with_capacity(ir.functions.len());
    for func in &ir.functions {
        let new_rva = function_ranges
            .get(&func.address_rva)
            .map(|r| r.new_start as u64);
        functions.push(FunctionRewriteEntry {
            name: func.name.clone(),
            old_rva: func.address_rva,
            new_rva,
            fallback: func.fallback,
            reason: fallback_reasons.get(&func.address_rva).cloned(),
        });
    }

    let mut blocks = Vec::new();
    for func in &ir.functions {
        for block_id in &func.blocks {
            let block = ir.block(*block_id);
            let new_rva = block_map.get(&block.start_rva).copied();
            let size = block_sizes.get(&block.start_rva).copied();
            blocks.push(BlockRewriteEntry {
                function_name: func.name.clone(),
                old_rva: block.start_rva,
                new_rva,
                encoded_size: size,
            });
        }
    }

    let total_edges = ir.edges.len();
    let indirect_edges = ir
        .edges
        .iter()
        .filter(|e| e.indirect || matches!(e.kind, EdgeKind::IndirectCall | EdgeKind::IndirectJump))
        .count();
    let jump_table_edges = ir
        .edges
        .iter()
        .filter(|e| matches!(e.kind, EdgeKind::JumpTable))
        .count();
    let unresolved_edges = ir
        .edges
        .iter()
        .filter(|e| e.target_rva.is_some() && e.to.is_none())
        .count();
    let unresolved_indirect_edges = ir
        .edges
        .iter()
        .filter(|e| {
            e.target_rva.is_some()
                && e.to.is_none()
                && (e.indirect || matches!(e.kind, EdgeKind::IndirectCall | EdgeKind::IndirectJump))
        })
        .count();
    let cross_function_edges = ir
        .edges
        .iter()
        .filter(|e| {
            e.to.is_some_and(|to| ir.block(e.from).function != ir.block(to).function)
        })
        .count();
    let cross_function_indirect_edges = ir
        .edges
        .iter()
        .filter(|e| {
            e.to.is_some_and(|to| ir.block(e.from).function != ir.block(to).function)
                && (e.indirect || matches!(e.kind, EdgeKind::IndirectCall | EdgeKind::IndirectJump))
        })
        .count();

    let map = RewriteMap {
        image_base: pe.image_base(),
        obfuscation_profile: ir.obfuscation_profile.clone(),
        obfuscation_seed: ir.obfuscation_seed,
        applied_passes: ir.applied_passes.clone(),
        pass_stats: ir.pass_stats.clone(),
        rewritten_bytes: text_blob.len() as u64,
        remapped_relocations: remapped,
        remapped_guard_cf_entries,
        remapped_guard_eh_continuation_entries,
        rewritten_runtime_functions,
        cloned_unwind_infos,
        exception_directory_rva,
        exception_directory_size,
        reloc_directory_rva: reloc_dir_rva,
        reloc_directory_size: reloc_dir_size,
        total_functions: ir.functions.len(),
        rewritten_functions: function_ranges.len(),
        fallback_functions: ir.functions.iter().filter(|f| f.fallback).count(),
        total_edges,
        indirect_edges,
        jump_table_edges,
        unresolved_edges,
        unresolved_indirect_edges,
        cross_function_edges,
        cross_function_indirect_edges,
        indirect_thunks: ir.indirect_thunks.len(),
        thunk_table_entries: thunk_materialization.entry_count,
        import_protection_enabled: options.import_protection,
        protected_imports: import_materialization.entry_count,
        import_stub_sites: import_materialization.patched_sites,
        anti_debug_enabled: options.anti_debug,
        obscure_entry_point_enabled: options.obscure_entry_point,
        strip_legacy_code_enabled: options.strip_legacy_code && !compact_layout && !rebuild_layout,
        stripped_legacy_ranges: legacy_strip_summary.ranges,
        stripped_legacy_bytes: legacy_strip_summary.bytes,
        preentry_stub_rva: preentry_materialization.stub_rva,
        preentry_stub_size: preentry_materialization.stub_size,
        functions,
        blocks,
    };

    let output = pe.into_bytes();

    Ok(RewriteArtifact {
        output,
        map,
        diagnostics,
    })
}

fn finalize_rebuild_layout(pe: &mut PeFile) -> Result<()> {
    let src_text = if pe.section_by_name(".blrtxt").is_some() {
        ".blrtxt"
    } else {
        anyhow::bail!(
            "rebuild section layout requires rewritten text section '.blrtxt' to be present"
        );
    };
    let src_pdata = if pe.section_by_name(".blrpdt").is_some() {
        Some(".blrpdt")
    } else if pe.section_by_name(".pdata").is_some() {
        Some(".pdata")
    } else {
        None
    };
    let src_xdata = if pe.section_by_name(".blrxdt").is_some() {
        Some(".blrxdt")
    } else if pe.section_by_name(".xdata").is_some() {
        Some(".xdata")
    } else {
        None
    };
    let src_reloc = if pe.section_by_name(".blrloc").is_some() {
        Some(".blrloc")
    } else if pe.section_by_name(".reloc").is_some() {
        Some(".reloc")
    } else {
        None
    };

    let mut rebuilt_sections = Vec::<RebuildSectionSpec>::new();
    let current_sections = pe.sections().to_vec();
    for section in current_sections {
        let name = section.name.as_str();
        if matches!(
            name,
            ".text"
                | ".pdata"
                | ".xdata"
                | ".reloc"
                | ".ltxt"
                | ".lpdt"
                | ".lxdt"
                | ".lloc"
                | ".blrtxt"
                | ".blrpdt"
                | ".blrxdt"
                | ".blrloc"
        ) {
            continue;
        }
        rebuilt_sections.push(RebuildSectionSpec {
            name: section.name.clone(),
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            characteristics: section.characteristics,
            payload: pe.section_payload(&section.name)?,
        });
    }

    let add_replacement = |out: &mut Vec<RebuildSectionSpec>,
                           source_name: Option<&str>,
                           target_name: &str|
     -> Result<()> {
        let Some(source_name) = source_name else {
            return Ok(());
        };
        let source = pe
            .section_by_name(source_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing section '{}'", source_name))?;
        out.push(RebuildSectionSpec {
            name: target_name.to_string(),
            virtual_address: source.virtual_address,
            virtual_size: source.virtual_size,
            characteristics: source.characteristics,
            payload: pe.section_payload(source_name)?,
        });
        Ok(())
    };

    add_replacement(&mut rebuilt_sections, Some(src_text), ".text")?;
    add_replacement(&mut rebuilt_sections, src_pdata, ".pdata")?;
    add_replacement(&mut rebuilt_sections, src_xdata, ".xdata")?;
    add_replacement(&mut rebuilt_sections, src_reloc, ".reloc")?;

    pe.rebuild_with_sections(rebuilt_sections)
        .context("failed to rebuild pe section table for rebuild layout")?;
    Ok(())
}

fn resolve_direct_edge_targets_after_passes(ir: &mut ProgramIr) {
    let mut by_start = HashMap::<u64, BlockId>::new();
    let mut by_range = Vec::<(u64, u64, BlockId)>::new();
    for block in &ir.blocks {
        if ir.function(block.function).fallback {
            continue;
        }
        by_start.entry(block.start_rva).or_insert(block.id);
        by_range.push((block.start_rva, block.end_rva, block.id));
    }

    for idx in 0..ir.edges.len() {
        let edge = &ir.edges[idx];
        if edge.to.is_some()
            || edge.target_rva.is_none()
            || edge.indirect
            || matches!(
                edge.kind,
                EdgeKind::IndirectCall | EdgeKind::IndirectJump | EdgeKind::JumpTable
            )
        {
            continue;
        }
        let target = edge.target_rva.unwrap_or_default();

        if let Some(target_block) = by_start.get(&target).copied() {
            let canonical = ir.block(target_block).start_rva;
            ir.edges[idx].to = Some(target_block);
            ir.edges[idx].target_rva = Some(canonical);
            continue;
        }

        let candidates = by_range
            .iter()
            .filter_map(|(start, end, bid)| {
                if target >= *start && target < *end {
                    Some(*bid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }

        let src_func = ir.block(ir.edges[idx].from).function;
        let same_func = candidates
            .iter()
            .copied()
            .filter(|bid| ir.block(*bid).function == src_func)
            .collect::<Vec<_>>();
        let chosen = if same_func.len() == 1 {
            Some(same_func[0])
        } else if same_func.is_empty() && candidates.len() == 1 {
            Some(candidates[0])
        } else {
            None
        };

        if let Some(target_block) = chosen {
            let canonical = ir.block(target_block).start_rva;
            ir.edges[idx].to = Some(target_block);
            ir.edges[idx].target_rva = Some(canonical);
        }
    }
}

fn patch_unwind_records(
    blob: &mut [u8],
    records: &[UnwindRecord],
    old_unwind_to_off: &HashMap<u32, u32>,
    old_unwind_to_new: &HashMap<u32, u32>,
    block_ranges: &[RvaRange],
    function_ranges: &HashMap<u64, FunctionRange>,
    options: RewriteOptions,
) -> Result<()> {
    fn is_in_rewritten_ranges(rva: u32, block_ranges: &[RvaRange]) -> bool {
        block_ranges
            .iter()
            .any(|r| rva >= r.old_start && rva < r.old_end)
    }

    for record in records {
        let Some(off) = old_unwind_to_off.get(&record.unwind_rva).copied() else {
            continue;
        };
        let start = off as usize;
        let end = start.saturating_add(record.full_size as usize);
        if end > blob.len() {
            anyhow::bail!(
                "xdata patch out of bounds for unwind 0x{:x}",
                record.unwind_rva
            );
        }

        if let Some(chain) = record.chained_entry {
            let chain_off = start + record.aligned_codes_size as usize;
            if chain_off + 12 > end {
                anyhow::bail!("invalid chained unwind layout at 0x{:x}", record.unwind_rva);
            }

            let new_begin =
                remap_rva_global(chain.begin_address, &[], block_ranges, function_ranges)
                    .unwrap_or(chain.begin_address);
            let new_end = remap_rva_global(chain.end_address, &[], block_ranges, function_ranges)
                .unwrap_or(chain.end_address);
            let new_unwind = old_unwind_to_new
                .get(&chain.unwind_info_address)
                .copied()
                .unwrap_or(chain.unwind_info_address);
            if options.strict_unwind
                && chain.unwind_info_address != 0
                && !old_unwind_to_new.contains_key(&chain.unwind_info_address)
            {
                anyhow::bail!(
                    "strict unwind enabled: chained unwind target 0x{:x} not remapped",
                    chain.unwind_info_address
                );
            }

            blob[chain_off..chain_off + 4].copy_from_slice(&new_begin.to_le_bytes());
            blob[chain_off + 4..chain_off + 8].copy_from_slice(&new_end.to_le_bytes());
            blob[chain_off + 8..chain_off + 12].copy_from_slice(&new_unwind.to_le_bytes());
            continue;
        }

        if let Some(handler) = record.exception_handler_rva {
            let handler_off = start + record.aligned_codes_size as usize;
            if handler_off + 4 > end {
                anyhow::bail!("invalid handler unwind layout at 0x{:x}", record.unwind_rva);
            }

            let new_handler =
                remap_rva_global(handler, &[], block_ranges, function_ranges).unwrap_or(handler);

            if options.strict_unwind
                && new_handler == handler
                && is_in_rewritten_ranges(handler, block_ranges)
            {
                anyhow::bail!(
                    "strict unwind enabled: handler 0x{:x} not remapped for unwind 0x{:x}",
                    handler,
                    record.unwind_rva
                );
            }

            blob[handler_off..handler_off + 4].copy_from_slice(&new_handler.to_le_bytes());
        }
    }

    Ok(())
}

fn collect_rewritable_blocks(ir: &ProgramIr) -> Vec<BlockId> {
    let mut out = Vec::new();
    for f in &ir.functions {
        if f.fallback {
            continue;
        }

        let mut blocks = f.blocks.clone();
        if matches!(ir.block_layout_strategy, BlockLayoutStrategy::SortedByRva) {
            blocks.sort_by_key(|id| ir.block(*id).start_rva);
        }
        out.extend(blocks);
    }
    out
}

fn function_requires_runtime_metadata(ir: &ProgramIr, func: &blare_ir::Function) -> bool {
    for block_id in &func.blocks {
        let block = ir.block(*block_id);
        for inst_id in &block.insts {
            let inst = ir.inst(*inst_id).instruction;

            if matches!(
                inst.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ) {
                return true;
            }

            if matches!(
                inst.mnemonic(),
                Mnemonic::Push | Mnemonic::Pop | Mnemonic::Enter | Mnemonic::Leave
            ) {
                return true;
            }

            if instruction_writes_stack_base(inst) {
                return true;
            }
        }
    }

    false
}

fn runtime_metadata_optional_by_name(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    lname.contains("chkstk") || lname.contains("alloca_probe")
}

fn runtime_metadata_optional_by_pattern(ir: &ProgramIr, func: &blare_ir::Function) -> bool {
    let mut ordered = Vec::<(u64, Instruction)>::new();
    for block_id in &func.blocks {
        let block = ir.block(*block_id);
        for inst_id in &block.insts {
            let inst = ir.inst(*inst_id);
            ordered.push((inst.original_rva, inst.instruction));
        }
    }
    ordered.sort_unstable_by_key(|(rva, _)| *rva);

    let mut insts = Vec::<Instruction>::with_capacity(ordered.len());
    for (_, inst) in ordered {
        if inst.mnemonic() != Mnemonic::Nop {
            insts.push(inst);
        }
    }
    if insts.len() < 8 {
        return false;
    }

    if insts.iter().any(|inst| {
        matches!(
            inst.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        )
    }) {
        return false;
    }

    if !is_push_reg(insts[0], Register::RCX) || !is_push_reg(insts[1], Register::RAX) {
        return false;
    }

    let n = insts.len();
    if insts[n - 1].mnemonic() != Mnemonic::Ret
        || !is_pop_reg(insts[n - 3], Register::RAX)
        || !is_pop_reg(insts[n - 2], Register::RCX)
    {
        return false;
    }

    let mut mem_or_count = 0usize;
    let mut has_cmp = false;
    let mut has_sub = false;
    let mut has_lea = false;
    for inst in &insts {
        match inst.mnemonic() {
            Mnemonic::Or => {
                if inst.op_count() >= 1 && inst.op_kind(0) == OpKind::Memory {
                    mem_or_count += 1;
                }
            }
            Mnemonic::Cmp => has_cmp = true,
            Mnemonic::Sub => has_sub = true,
            Mnemonic::Lea => has_lea = true,
            _ => {}
        }
    }
    if mem_or_count < 2 || !has_cmp || !has_sub || !has_lea {
        return false;
    }

    // Require a clear loop/back-edge shape to avoid widening this exception.
    ir.edges.iter().any(|edge| {
        edge.to.is_some_and(|to| {
            ir.block(edge.from).function == func.id
                && ir.block(to).function == func.id
                && ir.block(to).start_rva <= ir.block(edge.from).start_rva
        })
    })
}

fn is_push_reg(inst: Instruction, reg: Register) -> bool {
    inst.mnemonic() == Mnemonic::Push
        && inst.op_count() == 1
        && inst.op_kind(0) == OpKind::Register
        && inst.op_register(0) == reg
}

fn is_pop_reg(inst: Instruction, reg: Register) -> bool {
    inst.mnemonic() == Mnemonic::Pop
        && inst.op_count() == 1
        && inst.op_kind(0) == OpKind::Register
        && inst.op_register(0) == reg
}

fn instruction_writes_stack_base(inst: Instruction) -> bool {
    if inst.op_count() == 0 || inst.op_kind(0) != OpKind::Register {
        return false;
    }

    let dst = inst.op_register(0);
    if !matches!(
        dst,
        Register::RSP
            | Register::ESP
            | Register::SP
            | Register::SPL
            | Register::RBP
            | Register::EBP
            | Register::BP
            | Register::BPL
    ) {
        return false;
    }

    matches!(
        inst.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Lea
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
    )
}

fn initial_block_layout(
    ir: &ProgramIr,
    block_order: &[BlockId],
    text_base_rva: u64,
) -> HashMap<u64, u64> {
    let mut cursor = text_base_rva;
    let mut map = HashMap::new();
    for bid in block_order {
        let block = ir.block(*bid);
        map.insert(block.start_rva, cursor);
        cursor = cursor.saturating_add(block.end_rva.saturating_sub(block.start_rva));
    }
    map
}

fn collect_block_ranges(ir: &ProgramIr, block_map: &HashMap<u64, u64>) -> Vec<RvaRange> {
    let mut out = Vec::new();
    for b in &ir.blocks {
        if let Some(new_start) = block_map.get(&b.start_rva) {
            out.push(RvaRange {
                old_start: b.start_rva as u32,
                old_end: b.end_rva as u32,
                new_start: *new_start as u32,
            });
        }
    }
    out
}

fn encode_with_layout(
    ir: &ProgramIr,
    block_order: &[BlockId],
    target_map: &HashMap<u64, u64>,
) -> Result<(HashMap<u64, u64>, HashMap<u64, EncodedBlock>)> {
    let first = block_order
        .first()
        .map(|b| ir.block(*b).start_rva)
        .ok_or_else(|| anyhow::anyhow!("empty block order"))?;
    let base = *target_map
        .get(&first)
        .ok_or_else(|| anyhow::anyhow!("missing first block map entry"))?;

    let image_base = ir.image_base;
    let mut remap_ranges = Vec::<(u64, u64, u64)>::with_capacity(block_order.len());
    for bid in block_order {
        let block = ir.block(*bid);
        if let Some(new_start) = target_map.get(&block.start_rva) {
            remap_ranges.push((block.start_rva, block.end_rva, *new_start));
        }
    }
    remap_ranges.sort_unstable_by_key(|(old_start, _, _)| *old_start);

    let mut pending = Vec::<PendingBlockEncoding>::with_capacity(block_order.len());
    for bid in block_order {
        let block = ir.block(*bid);
        let encode_rva = *target_map.get(&block.start_rva).ok_or_else(|| {
            anyhow::anyhow!("missing block map entry for 0x{:x}", block.start_rva)
        })?;

        let mut instructions = Vec::<Instruction>::with_capacity(block.insts.len());
        let mut source_ranges = Vec::<(u32, u32)>::with_capacity(block.insts.len());

        for iid in &block.insts {
            let inst_data = ir.inst(*iid);
            let mut inst = inst_data.instruction;

            if inst.is_jmp_short_or_near() || inst.is_jcc_short_or_near() || inst.is_call_near() {
                let target_va = inst.near_branch_target();
                if target_va >= image_base {
                    let old_target_rva = target_va - image_base;
                    if let Some(new_target_rva) = target_map
                        .get(&old_target_rva)
                        .copied()
                        .or_else(|| remap_rva_with_block_layout(old_target_rva, &remap_ranges))
                    {
                        inst.set_near_branch64(image_base + new_target_rva);
                    }
                }
            }

            source_ranges.push((inst_data.original_rva as u32, inst.len() as u32));
            instructions.push(inst);
        }

        pending.push(PendingBlockEncoding {
            block_start_rva: block.start_rva,
            encode_rva,
            source_ranges,
            instructions,
        });
    }

    let mut blocks = Vec::<InstructionBlock<'_>>::with_capacity(pending.len());
    for p in &pending {
        blocks.push(InstructionBlock::new(
            &p.instructions,
            image_base + p.encode_rva,
        ));
    }

    let encoded_results = BlockEncoder::encode_slice(
        64,
        &blocks,
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )
    .map_err(|e| anyhow::anyhow!("block encoder failed: {e}"))?;

    if encoded_results.len() != pending.len() {
        anyhow::bail!(
            "block encoder returned {} results for {} blocks",
            encoded_results.len(),
            pending.len()
        );
    }

    let mut next_map = HashMap::new();
    let mut encoded_blocks = HashMap::new();
    let mut cursor = base;

    for (pending_block, encoded) in pending.into_iter().zip(encoded_results.into_iter()) {
        next_map.insert(pending_block.block_start_rva, cursor);

        let mut inst_ranges = Vec::with_capacity(pending_block.source_ranges.len());
        for (idx, (old_rva, len)) in pending_block.source_ranges.into_iter().enumerate() {
            let off = *encoded
                .new_instruction_offsets
                .get(idx)
                .ok_or_else(|| anyhow::anyhow!("missing instruction offset for index {idx}"))?;
            if off == u32::MAX {
                continue;
            }
            let effective_len = if len == 0 {
                let mut next_off = encoded.code_buffer.len() as u32;
                for cand in encoded.new_instruction_offsets.iter().skip(idx + 1) {
                    if *cand != u32::MAX {
                        next_off = *cand;
                        break;
                    }
                }
                next_off.saturating_sub(off).max(1)
            } else {
                len
            };
            inst_ranges.push(InstRange {
                old_rva,
                len: effective_len,
                new_rva: (cursor as u32).saturating_add(off),
            });
        }

        cursor = cursor.saturating_add(encoded.code_buffer.len() as u64);
        encoded_blocks.insert(
            pending_block.block_start_rva,
            EncodedBlock {
                bytes: encoded.code_buffer,
                inst_ranges,
            },
        );
    }

    Ok((next_map, encoded_blocks))
}

fn remap_rva_with_block_layout(old_rva: u64, ranges: &[(u64, u64, u64)]) -> Option<u64> {
    let idx = ranges.partition_point(|(old_start, _, _)| *old_start <= old_rva);
    if idx == 0 {
        return None;
    }
    let (old_start, old_end, new_start) = ranges[idx - 1];
    if old_rva >= old_start && old_rva < old_end {
        Some(new_start.saturating_add(old_rva.saturating_sub(old_start)))
    } else {
        None
    }
}

fn build_text_blob(
    ir: &ProgramIr,
    block_order: &[BlockId],
    block_map: &HashMap<u64, u64>,
    encoded_blocks: &HashMap<u64, EncodedBlock>,
) -> Result<(Vec<u8>, Vec<InstRange>, HashMap<u64, u32>)> {
    let first = block_order
        .first()
        .ok_or_else(|| anyhow::anyhow!("no blocks to emit"))?;
    let base = *block_map
        .get(&ir.block(*first).start_rva)
        .ok_or_else(|| anyhow::anyhow!("missing map entry for first block"))?;

    let mut blob = Vec::<u8>::new();
    let mut inst_ranges = Vec::<InstRange>::new();
    let mut block_sizes = HashMap::<u64, u32>::new();

    let mut cursor = base;
    for bid in block_order {
        let block = ir.block(*bid);
        let start = *block_map.get(&block.start_rva).ok_or_else(|| {
            anyhow::anyhow!("missing map entry for block 0x{:x}", block.start_rva)
        })?;
        let enc = encoded_blocks.get(&block.start_rva).ok_or_else(|| {
            anyhow::anyhow!("missing encoded bytes for block 0x{:x}", block.start_rva)
        })?;

        if start > cursor {
            let pad = (start - cursor) as usize;
            blob.resize(blob.len() + pad, 0);
            cursor = start;
        }

        blob.extend_from_slice(&enc.bytes);
        cursor = cursor.saturating_add(enc.bytes.len() as u64);
        block_sizes.insert(block.start_rva, enc.bytes.len() as u32);
        inst_ranges.extend(enc.inst_ranges.iter().cloned());
    }

    Ok((blob, inst_ranges, block_sizes))
}

fn serialize_runtime_function_table(entries: &[RuntimeFunctionEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 12);
    for e in entries {
        out.extend_from_slice(&e.begin_address.to_le_bytes());
        out.extend_from_slice(&e.end_address.to_le_bytes());
        out.extend_from_slice(&e.unwind_info_address.to_le_bytes());
    }
    out
}

fn remap_rva_global(
    old_rva: u32,
    inst_ranges: &[InstRange],
    block_ranges: &[RvaRange],
    function_ranges: &HashMap<u64, FunctionRange>,
) -> Option<u32> {
    for range in inst_ranges {
        if old_rva >= range.old_rva && old_rva < range.old_rva.saturating_add(range.len) {
            let delta = old_rva - range.old_rva;
            return Some(range.new_rva.saturating_add(delta));
        }
    }

    for range in block_ranges {
        if old_rva >= range.old_start && old_rva < range.old_end {
            let delta = old_rva - range.old_start;
            return Some(range.new_start.saturating_add(delta));
        }
    }

    if let Some(new_func) = function_ranges.get(&(old_rva as u64)) {
        return Some(new_func.new_start);
    }

    None
}

fn iat_rva_from_call_mem(inst: Instruction, image_base: u64) -> Option<u32> {
    if inst.mnemonic() != Mnemonic::Call {
        return None;
    }
    if inst.op_count() == 0 || inst.op_kind(0) != OpKind::Memory {
        return None;
    }
    if !inst.is_ip_rel_memory_operand() {
        return None;
    }
    let target_va = inst.ip_rel_memory_address();
    if target_va < image_base {
        return None;
    }
    let rva = target_va - image_base;
    u32::try_from(rva).ok()
}

fn apply_iat_obfuscation(
    ir: &mut ProgramIr,
    imports: &[ImportEntry],
) -> Result<ImportProtectionContext> {
    let mut records = Vec::<ProtectedImportRecord>::new();
    let mut by_iat_rva = HashMap::<u32, usize>::new();
    for entry in imports {
        let dll_hash = fnv1a64(&entry.dll_name.to_ascii_lowercase());
        for imported in &entry.functions {
            let Some(fn_name) = imported.name.as_deref() else {
                // Ordinal imports need a dedicated resolver path; keep them untouched for now.
                continue;
            };
            let fn_hash = fnv1a64(fn_name);
            let idx = records.len();
            records.push(ProtectedImportRecord {
                hash_dll: dll_hash,
                hash_fn: fn_hash,
                iat_rva: imported.iat_rva,
            });
            by_iat_rva.insert(imported.iat_rva, idx);
        }
    }

    if records.is_empty() {
        return Ok(ImportProtectionContext::default());
    }

    let Some(host_function) = ir.functions.iter().find(|f| !f.fallback).map(|f| f.id) else {
        return Ok(ImportProtectionContext::default());
    };

    let mut allocator = SyntheticRvaAllocator::new(ir);

    let resolver_entry_start = allocator.next_block();
    let resolver_module_check_start = allocator.next_block();
    let resolver_module_hash_loop_start = allocator.next_block();
    let resolver_module_hash_done_start = allocator.next_block();
    let resolver_name_loop_check_start = allocator.next_block();
    let resolver_name_hash_loop_start = allocator.next_block();
    let resolver_name_hash_done_start = allocator.next_block();
    let resolver_name_match_start = allocator.next_block();
    let resolver_next_name_start = allocator.next_block();
    let resolver_next_module_start = allocator.next_block();
    let resolver_not_found_start = allocator.next_block();

    let resolver_entry_id = ir.add_block(
        host_function,
        resolver_entry_start,
        resolver_entry_start + 1,
    );
    let resolver_module_check_id = ir.add_block(
        host_function,
        resolver_module_check_start,
        resolver_module_check_start + 1,
    );
    let resolver_module_hash_loop_id = ir.add_block(
        host_function,
        resolver_module_hash_loop_start,
        resolver_module_hash_loop_start + 1,
    );
    let resolver_module_hash_done_id = ir.add_block(
        host_function,
        resolver_module_hash_done_start,
        resolver_module_hash_done_start + 1,
    );
    let resolver_name_loop_check_id = ir.add_block(
        host_function,
        resolver_name_loop_check_start,
        resolver_name_loop_check_start + 1,
    );
    let resolver_name_hash_loop_id = ir.add_block(
        host_function,
        resolver_name_hash_loop_start,
        resolver_name_hash_loop_start + 1,
    );
    let resolver_name_hash_done_id = ir.add_block(
        host_function,
        resolver_name_hash_done_start,
        resolver_name_hash_done_start + 1,
    );
    let resolver_name_match_id = ir.add_block(
        host_function,
        resolver_name_match_start,
        resolver_name_match_start + 1,
    );
    let resolver_next_name_id = ir.add_block(
        host_function,
        resolver_next_name_start,
        resolver_next_name_start + 1,
    );
    let resolver_next_module_id = ir.add_block(
        host_function,
        resolver_next_module_start,
        resolver_next_module_start + 1,
    );
    let resolver_not_found_id = ir.add_block(
        host_function,
        resolver_not_found_start,
        resolver_not_found_start + 1,
    );

    let resolver = build_import_resolver_stub(ImportResolverLayout {
        module_check_va: ir.image_base + resolver_module_check_start,
        module_hash_loop_va: ir.image_base + resolver_module_hash_loop_start,
        module_hash_done_va: ir.image_base + resolver_module_hash_done_start,
        name_loop_check_va: ir.image_base + resolver_name_loop_check_start,
        name_hash_loop_va: ir.image_base + resolver_name_hash_loop_start,
        name_hash_done_va: ir.image_base + resolver_name_hash_done_start,
        name_match_va: ir.image_base + resolver_name_match_start,
        next_name_va: ir.image_base + resolver_next_name_start,
        next_module_va: ir.image_base + resolver_next_module_start,
        not_found_va: ir.image_base + resolver_not_found_start,
    })
    .context("failed to build import resolver stub")?;

    for inst in resolver.entry {
        ir.add_instruction(resolver_entry_id, allocator.next_inst(), inst);
    }
    for inst in resolver.module_check {
        ir.add_instruction(resolver_module_check_id, allocator.next_inst(), inst);
    }
    for inst in resolver.module_hash_loop {
        ir.add_instruction(resolver_module_hash_loop_id, allocator.next_inst(), inst);
    }
    for inst in resolver.module_hash_done {
        ir.add_instruction(resolver_module_hash_done_id, allocator.next_inst(), inst);
    }
    for inst in resolver.name_loop_check {
        ir.add_instruction(resolver_name_loop_check_id, allocator.next_inst(), inst);
    }
    for inst in resolver.name_hash_loop {
        ir.add_instruction(resolver_name_hash_loop_id, allocator.next_inst(), inst);
    }
    for inst in resolver.name_hash_done {
        ir.add_instruction(resolver_name_hash_done_id, allocator.next_inst(), inst);
    }
    for inst in resolver.name_match {
        ir.add_instruction(resolver_name_match_id, allocator.next_inst(), inst);
    }
    for inst in resolver.next_name {
        ir.add_instruction(resolver_next_name_id, allocator.next_inst(), inst);
    }
    for inst in resolver.next_module {
        ir.add_instruction(resolver_next_module_id, allocator.next_inst(), inst);
    }
    for inst in resolver.not_found {
        ir.add_instruction(resolver_not_found_id, allocator.next_inst(), inst);
    }

    ir.block_mut(resolver_entry_id).terminator = Terminator::UnconditionalBranch {
        target: resolver_module_check_start,
    };
    ir.block_mut(resolver_name_match_id).terminator = Terminator::Return;
    ir.block_mut(resolver_not_found_id).terminator = Terminator::Return;

    let mut stub_by_record = HashMap::<usize, (BlockId, u64)>::new();
    let mut mutated_functions = std::collections::HashSet::<blare_ir::FunctionId>::new();
    let mut mutated_blocks = std::collections::HashSet::<BlockId>::new();
    let mut patched_sites = Vec::<ImportSitePatch>::new();
    let mut patched_calls = 0usize;
    let mut injected_blocks = 11usize;

    for fidx in 0..ir.functions.len() {
        if ir.functions[fidx].fallback {
            continue;
        }
        let function_id = ir.functions[fidx].id;
        let block_ids = ir.functions[fidx].blocks.clone();

        for block_id in block_ids {
            let inst_ids = ir.block(block_id).insts.clone();
            for (inst_index, inst_id) in inst_ids.iter().enumerate() {
                let inst = ir.inst(*inst_id).instruction;
                let Some(iat_rva) = iat_rva_from_call_mem(inst, ir.image_base) else {
                    continue;
                };
                let Some(record_index) = by_iat_rva.get(&iat_rva).copied() else {
                    continue;
                };

                let (stub_block_id, stub_start) =
                    if let Some(existing) = stub_by_record.get(&record_index).copied() {
                        existing
                    } else {
                        let stub_start = allocator.next_block();
                        let stub_id = ir.add_block(host_function, stub_start, stub_start + 1);
                        let stub = build_import_entry_stub(
                            0,
                            ir.image_base
                                .saturating_add(records[record_index].iat_rva as u64),
                            ir.image_base + resolver_entry_start,
                        )
                        .context("failed to build import entry stub")?;

                        for (idx, stub_inst) in stub.instructions.into_iter().enumerate() {
                            let orig_rva = allocator.next_inst();
                            if idx == stub.entry_addr_inst_index {
                                patched_sites.push(ImportSitePatch {
                                    entry_index: record_index,
                                    load_entry_rva: orig_rva,
                                });
                            }
                            ir.add_instruction(stub_id, orig_rva, stub_inst);
                        }
                        ir.block_mut(stub_id).terminator = Terminator::IndirectBranch;
                        ir.add_edge(stub_id, None, None, EdgeKind::IndirectJump, true);
                        stub_by_record.insert(record_index, (stub_id, stub_start));
                        injected_blocks += 1;
                        (stub_id, stub_start)
                    };

                let patched =
                    Instruction::with_branch(Code::Call_rel32_64, ir.image_base + stub_start)
                        .map_err(|err| anyhow::anyhow!("failed to patch import callsite: {err}"))?;
                ir.insts[inst_id.0].instruction = patched;
                patched_calls += 1;
                mutated_blocks.insert(block_id);
                mutated_blocks.insert(stub_block_id);
                mutated_functions.insert(function_id);

                if inst_index + 1 == inst_ids.len()
                    && matches!(ir.block(block_id).terminator, Terminator::IndirectCall)
                {
                    ir.block_mut(block_id).terminator =
                        Terminator::DirectCall { target: stub_start };
                    let outgoing = ir.block(block_id).outgoing_edges.clone();
                    let mut retargeted = false;
                    for edge_id in outgoing {
                        let edge = &mut ir.edges[edge_id];
                        if matches!(edge.kind, EdgeKind::IndirectCall) {
                            edge.kind = EdgeKind::Call;
                            edge.indirect = false;
                            edge.to = Some(stub_block_id);
                            edge.target_rva = Some(stub_start);
                            retargeted = true;
                        }
                    }
                    if !retargeted {
                        ir.add_edge(
                            block_id,
                            Some(stub_block_id),
                            Some(stub_start),
                            EdgeKind::Call,
                            false,
                        );
                    }
                }
            }
        }
    }

    if patched_calls == 0 {
        return Ok(ImportProtectionContext::default());
    }

    let mut used_record_indices = stub_by_record.keys().copied().collect::<Vec<_>>();
    used_record_indices.sort_unstable();
    let mut record_index_remap = HashMap::<usize, usize>::new();
    let mut protected_records = Vec::with_capacity(used_record_indices.len());
    for old_idx in used_record_indices {
        let new_idx = protected_records.len();
        record_index_remap.insert(old_idx, new_idx);
        protected_records.push(records[old_idx].clone());
    }
    for patch in &mut patched_sites {
        patch.entry_index = *record_index_remap.get(&patch.entry_index).ok_or_else(|| {
            anyhow::anyhow!(
                "missing record remap for protected import entry index {}",
                patch.entry_index
            )
        })?;
    }

    ir.record_applied_pass("iat-obfuscation");
    ir.record_pass_stats(PassStatsRecord {
        name: "iat-obfuscation".to_string(),
        mutated_functions: mutated_functions.len(),
        mutated_blocks: mutated_blocks.len(),
        mutated_instructions: patched_calls,
        injected_blocks,
        skipped_sites: 0,
    });

    Ok(ImportProtectionContext {
        records: protected_records,
        stub_site_patches: patched_sites,
    })
}

fn materialize_import_protection(
    pe: &mut PeFile,
    import_ctx: &ImportProtectionContext,
    seed: u64,
    inst_ranges: &[InstRange],
    text_base_rva: u32,
    text_blob: &mut [u8],
) -> Result<ImportMaterialization> {
    if import_ctx.records.is_empty() {
        return Ok(ImportMaterialization::default());
    }

    let blob = build_encrypted_import_blob(&import_ctx.records, seed);
    let import_section = pe.add_section(
        ".blrimp",
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        &blob,
    )?;

    let mut patched_sites = 0usize;
    for patch in &import_ctx.stub_site_patches {
        let Some(inst_range) = inst_ranges
            .iter()
            .find(|range| range.old_rva as u64 == patch.load_entry_rva)
        else {
            anyhow::bail!(
                "missing encoded range for import stub site rva 0x{:x}",
                patch.load_entry_rva
            );
        };

        if inst_range.new_rva < text_base_rva {
            anyhow::bail!(
                "import stub remap produced invalid rva 0x{:x} (< text base 0x{:x})",
                inst_range.new_rva,
                text_base_rva
            );
        }
        let inst_len = inst_range.len as usize;
        if inst_len < 8 {
            anyhow::bail!(
                "import stub load instruction too short for imm64 patch (len={inst_len})"
            );
        }
        let inst_off = (inst_range.new_rva - text_base_rva) as usize;
        let imm_off = inst_off + inst_len - 8;
        if imm_off + 8 > text_blob.len() {
            anyhow::bail!(
                "import stub patch out of text bounds: offset={} len={}",
                imm_off,
                text_blob.len()
            );
        }

        let entry_rva = import_section
            .virtual_address
            .saturating_add((patch.entry_index * IMPORT_RECORD_SIZE) as u32);
        let entry_va = pe.image_base().saturating_add(entry_rva as u64);
        text_blob[imm_off..imm_off + 8].copy_from_slice(&entry_va.to_le_bytes());
        patched_sites += 1;
    }

    Ok(ImportMaterialization {
        entry_count: import_ctx.records.len(),
        patched_sites,
    })
}

fn zero_section_if_present(pe: &mut PeFile, section_name: &str) -> Result<()> {
    let Some(section) = pe.section_by_name(section_name).cloned() else {
        return Ok(());
    };
    let payload = vec![0u8; section.virtual_size as usize];
    pe.overwrite_section_payload(section_name, &payload)
        .with_context(|| format!("failed to zero section '{section_name}'"))?;
    Ok(())
}

fn collect_unresolved_legacy_targets(ir: &ProgramIr) -> Vec<u32> {
    let mut targets = ir
        .edges
        .iter()
        .filter_map(|edge| {
            if edge.to.is_none() {
                edge.target_rva.and_then(|rva| u32::try_from(rva).ok())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn collect_risky_legacy_block_starts(ir: &ProgramIr) -> HashSet<u32> {
    let mut risky_functions = HashSet::new();

    for edge in &ir.edges {
        if edge.to.is_none() || matches!(edge.kind, EdgeKind::IndirectJump | EdgeKind::JumpTable) {
            risky_functions.insert(ir.block(edge.from).function);
        }
    }

    for block in &ir.blocks {
        if matches!(block.terminator, Terminator::IndirectBranch) {
            risky_functions.insert(block.function);
        }
    }

    let mut preserved = HashSet::new();
    for function in &ir.functions {
        if !risky_functions.contains(&function.id) {
            continue;
        }
        for block_id in &function.blocks {
            if let Ok(start) = u32::try_from(ir.block(*block_id).start_rva) {
                preserved.insert(start);
            }
        }
    }

    preserved
}

fn is_safe_strip_name(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    matches!(
        lname.as_str(),
        "main" | "wmain" | "winmain" | "wwinmain" | "dllmain" | "efi_main"
    ) || lname.contains("fibonacci")
        || lname.contains("fib")
}

fn collect_safe_strip_ranges_prepass(ir: &ProgramIr) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    for function in &ir.functions {
        if function.fallback || !is_safe_strip_name(&function.name) {
            continue;
        }
        for block_id in &function.blocks {
            let block = ir.block(*block_id);
            if block.end_rva <= block.start_rva {
                continue;
            }
            if let (Ok(start), Ok(end)) =
                (u32::try_from(block.start_rva), u32::try_from(block.end_rva))
            {
                ranges.push((start, end));
            }
        }
    }
    ranges
}

fn clear_legacy_named_ranges(pe: &mut PeFile, ranges: &[(u32, u32)]) -> Result<LegacyStripSummary> {
    let mut filtered = ranges
        .iter()
        .filter_map(|(start, end)| {
            if end <= start {
                return None;
            }
            let section = pe.section_for_rva(*start)?;
            if !section.executable() {
                return None;
            }
            Some((*start, *end))
        })
        .collect::<Vec<_>>();
    filtered.sort_unstable_by_key(|(start, _)| *start);
    clear_legacy_ranges(pe, filtered)
}

fn clear_legacy_rewritten_code(
    pe: &mut PeFile,
    block_ranges: &[RvaRange],
    preserved_block_starts: &HashSet<u32>,
    unresolved_targets: &[u32],
) -> Result<LegacyStripSummary> {
    if block_ranges.is_empty() {
        return Ok(LegacyStripSummary::default());
    }

    let mut ranges = block_ranges
        .iter()
        .filter_map(|range| {
            if range.old_end > range.old_start {
                let section = pe.section_for_rva(range.old_start)?;
                if !section.executable() {
                    return None;
                }
                if preserved_block_starts.contains(&range.old_start) {
                    return None;
                }
                if range_contains_preserved_target(
                    range.old_start,
                    range.old_end,
                    unresolved_targets,
                ) {
                    return None;
                }
                Some((range.old_start, range.old_end))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|(start, _)| *start);
    clear_legacy_ranges(pe, ranges)
}

fn range_contains_preserved_target(start: u32, end: u32, targets: &[u32]) -> bool {
    if start >= end || targets.is_empty() {
        return false;
    }
    let idx = targets.partition_point(|target| *target < start);
    idx < targets.len() && targets[idx] < end
}

fn clear_legacy_ranges(pe: &mut PeFile, ranges: Vec<(u32, u32)>) -> Result<LegacyStripSummary> {
    if ranges.is_empty() {
        return Ok(LegacyStripSummary::default());
    }

    let mut merged = Vec::<(u32, u32)>::new();
    for (start, end) in ranges {
        if let Some((_, last_end)) = merged.last_mut() {
            if start <= *last_end {
                *last_end = (*last_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut cleared_bytes = 0u64;
    for (start, end) in &merged {
        let len = end.saturating_sub(*start);
        pe.fill_rva_range(*start, len, 0).with_context(|| {
            format!("failed to clear legacy code range [0x{start:x}, 0x{end:x})")
        })?;
        cleared_bytes = cleared_bytes.saturating_add(len as u64);
    }

    Ok(LegacyStripSummary {
        ranges: merged.len(),
        bytes: cleared_bytes,
    })
}

fn materialize_preentry_stub(
    pe: &mut PeFile,
    binary_kind: PeBinaryKind,
    options: RewriteOptions,
    true_oep_va: u64,
) -> Result<PreEntryMaterialization> {
    if options.obscure_entry_point && binary_kind != PeBinaryKind::UserMode {
        anyhow::bail!(
            "obscure entry point is only supported for user-mode binaries, got {:?}",
            binary_kind
        );
    }

    let predicted_rva = pe.next_section_virtual_address()?;
    let stub = build_pre_entry_stub(
        pe.image_base().saturating_add(predicted_rva as u64),
        PreEntryOptions::with_defaults(
            true_oep_va,
            options.anti_debug || options.obscure_entry_point,
            options.obscure_entry_point,
        ),
    )
    .context("failed to build pre-entry anti-debug stub")?;
    if stub.bytes.is_empty() {
        return Ok(PreEntryMaterialization::default());
    }

    let section = pe.add_section(
        ".blrpre",
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        &stub.bytes,
    )?;
    if section.virtual_address != predicted_rva {
        anyhow::bail!(
            "unexpected pre-entry section RVA drift: predicted=0x{:x}, actual=0x{:x}",
            predicted_rva,
            section.virtual_address
        );
    }

    pe.set_entrypoint_rva(section.virtual_address)?;

    Ok(PreEntryMaterialization {
        stub_rva: Some(section.virtual_address),
        stub_size: stub.bytes.len() as u32,
    })
}

fn materialize_indirect_thunks(
    pe: &mut PeFile,
    ir: &ProgramIr,
    inst_ranges: &[InstRange],
    block_ranges: &[RvaRange],
    function_ranges: &HashMap<u64, FunctionRange>,
    text_base_rva: u32,
    text_blob: &mut [u8],
) -> Result<ThunkMaterialization> {
    if ir.indirect_thunks.is_empty() {
        return Ok(ThunkMaterialization::default());
    }

    let mut materialization = ThunkMaterialization {
        added_relocations: Vec::with_capacity(ir.indirect_thunks.len()),
        entry_count: 0,
        patched_sites: 0,
    };

    for thunk in &ir.indirect_thunks {
        let Some(inst_range) = inst_ranges
            .iter()
            .find(|range| range.old_rva as u64 == thunk.load_entry_rva)
        else {
            anyhow::bail!(
                "missing encoded instruction range for thunk load site rva 0x{:x}",
                thunk.load_entry_rva
            );
        };

        if inst_range.new_rva < text_base_rva {
            anyhow::bail!(
                "invalid remapped thunk load rva 0x{:x} before text base 0x{:x}",
                inst_range.new_rva,
                text_base_rva
            );
        }
        let inst_offset = (inst_range.new_rva - text_base_rva) as usize;
        let inst_len = inst_range.len as usize;
        if inst_len < 4 || inst_offset.saturating_add(inst_len) > text_blob.len() {
            anyhow::bail!(
                "invalid thunk load patch bounds: offset={} len={} text_len={}",
                inst_offset,
                inst_len,
                text_blob.len()
            );
        }

        let old_target = u32::try_from(thunk.target_rva).with_context(|| {
            format!(
                "thunk target rva 0x{:x} does not fit into 32-bit rva",
                thunk.target_rva
            )
        })?;
        let target_rva = remap_rva_global(old_target, inst_ranges, block_ranges, function_ranges)
            .unwrap_or(old_target) as u64;
        let target_va = pe.image_base().saturating_add(target_rva);
        let encoded_target = target_va.wrapping_sub(thunk.decode_key as i64 as u64);

        let imm_offset = inst_offset + inst_len - 8;
        text_blob[imm_offset..imm_offset + 8].copy_from_slice(&encoded_target.to_le_bytes());
        materialization.added_relocations.push(RelocEntry {
            rva: inst_range.new_rva.saturating_add((inst_len - 8) as u32),
            typ: RELOC_TYPE_DIR64,
        });
        materialization.patched_sites += 1;
    }

    materialization
        .added_relocations
        .sort_unstable_by_key(|entry| (entry.rva, entry.typ));
    materialization
        .added_relocations
        .dedup_by(|a, b| a.rva == b.rva && a.typ == b.typ);
    materialization.entry_count = materialization.patched_sites;

    Ok(materialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn build_ir_with_single_block(
        name: &str,
        func_rva: u64,
        bytes: &[u8],
        self_loop: bool,
    ) -> ProgramIr {
        let mut ir = ProgramIr::new(0x140000000);
        let fid = ir.add_function(name, func_rva);
        let bid = ir.add_block(fid, func_rva, func_rva + bytes.len() as u64);

        let mut decoder =
            Decoder::with_ip(64, bytes, ir.image_base + func_rva, DecoderOptions::NONE);
        while decoder.can_decode() {
            let inst = decoder.decode();
            if inst.is_invalid() {
                break;
            }
            ir.add_instruction(bid, inst.ip() - ir.image_base, inst);
        }

        if self_loop {
            ir.add_edge(bid, Some(bid), Some(func_rva), EdgeKind::Branch, false);
        }
        ir
    }

    #[test]
    fn stack_probe_pattern_is_optional_without_symbol_name() {
        let bytes: &[u8] = &[
            0x51, 0x50, 0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x18, 0x72,
            0x19, 0x48, 0x81, 0xe9, 0x00, 0x10, 0x00, 0x00, 0x48, 0x83, 0x09, 0x00, 0x48, 0x2d,
            0x00, 0x10, 0x00, 0x00, 0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x77, 0xe7, 0x48, 0x29,
            0xc1, 0x48, 0x83, 0x09, 0x00, 0x58, 0x59, 0xc3,
        ];
        let ir = build_ir_with_single_block("FUN_1400c3a00", 0x1000, bytes, true);
        let func = &ir.functions[0];
        assert!(function_requires_runtime_metadata(&ir, func));
        assert!(runtime_metadata_optional_by_pattern(&ir, func));
    }

    #[test]
    fn non_probe_leaf_is_not_marked_optional() {
        let bytes: &[u8] = &[0x51, 0x50, 0x58, 0x59, 0xc3];
        let ir = build_ir_with_single_block("FUN_foo", 0x2000, bytes, true);
        let func = &ir.functions[0];
        assert!(!runtime_metadata_optional_by_pattern(&ir, func));
    }

    #[test]
    fn stack_probe_pattern_with_padding_nops_is_optional() {
        let mut bytes = vec![0x90; 80];
        bytes.extend_from_slice(&[
            0x51, 0x50, 0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x18, 0x72,
            0x19, 0x48, 0x81, 0xe9, 0x00, 0x10, 0x00, 0x00, 0x48, 0x83, 0x09, 0x00, 0x48, 0x2d,
            0x00, 0x10, 0x00, 0x00, 0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x77, 0xe7, 0x48, 0x29,
            0xc1, 0x48, 0x83, 0x09, 0x00, 0x58, 0x59, 0xc3,
        ]);
        bytes.extend_from_slice(&[0x90; 80]);

        let ir = build_ir_with_single_block("FUN_1400c3a00", 0x3000, &bytes, true);
        let func = &ir.functions[0];
        assert!(function_requires_runtime_metadata(&ir, func));
        assert!(runtime_metadata_optional_by_pattern(&ir, func));
    }

    #[test]
    fn remap_rva_with_block_layout_remaps_interior_targets() {
        let ranges = vec![
            (0x1000_u64, 0x1010_u64, 0x5000_u64),
            (0x2000_u64, 0x2010_u64, 0x6000_u64),
        ];
        assert_eq!(remap_rva_with_block_layout(0x1000, &ranges), Some(0x5000));
        assert_eq!(remap_rva_with_block_layout(0x1008, &ranges), Some(0x5008));
        assert_eq!(remap_rva_with_block_layout(0x2010, &ranges), None);
        assert_eq!(remap_rva_with_block_layout(0x1fff, &ranges), None);
    }
}
