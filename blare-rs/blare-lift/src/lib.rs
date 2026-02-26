use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use blare_cfg::{BlockCfg, FunctionCfg, ProgramCfg};
use blare_ir::{BlockId, EdgeKind, ProgramIr, Terminator};
use blare_pe::PeFile;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};

#[derive(Debug, Clone)]
pub struct LiftDiagnostics {
    pub fallback_functions: Vec<(String, String)>,
    pub noreturn_function_rvas: HashSet<u64>,
}

impl LiftDiagnostics {
    fn new() -> Self {
        Self {
            fallback_functions: Vec::new(),
            noreturn_function_rvas: HashSet::new(),
        }
    }
}

pub fn validate_cfg_against_pe(cfg: &ProgramCfg, pe: &PeFile) -> Result<()> {
    if cfg.image_base != pe.image_base() {
        anyhow::bail!(
            "cfg image_base 0x{:x} does not match pe image_base 0x{:x}",
            cfg.image_base,
            pe.image_base()
        );
    }

    for func in &cfg.functions {
        for block in &func.blocks {
            let start_rva = cfg.to_rva(block.start)? as u32;
            let end_rva = cfg.to_rva(block.end)? as u32;
            if end_rva <= start_rva {
                anyhow::bail!(
                    "function '{}' has invalid block [0x{:x},0x{:x})",
                    func.name,
                    block.start,
                    block.end
                );
            }

            let start_sec = pe.executable_section_for_rva(start_rva).with_context(|| {
                format!("block start rva 0x{start_rva:x} is not in executable section")
            })?;
            let end_minus_one = end_rva - 1;
            let end_sec = pe
                .executable_section_for_rva(end_minus_one)
                .with_context(|| {
                    format!("block end rva 0x{end_rva:x} (exclusive) leaves executable section")
                })?;

            if start_sec.name != end_sec.name {
                anyhow::bail!(
                    "block 0x{start_rva:x}..0x{end_rva:x} spans multiple sections ('{}' -> '{}')",
                    start_sec.name,
                    end_sec.name
                );
            }
        }
    }

    Ok(())
}

pub fn lift_program(cfg: &ProgramCfg, pe: &PeFile) -> Result<(ProgramIr, LiftDiagnostics)> {
    validate_cfg_against_pe(cfg, pe)?;

    let mut ir = ProgramIr::new(cfg.image_base);
    let mut diagnostics = LiftDiagnostics::new();
    let mut name_by_rva = HashMap::new();

    for f in &cfg.functions {
        let function_rva = cfg.to_rva(f.address)? as u64;
        name_by_rva.insert(function_rva, f.name.clone());

        let fid = ir.add_function(f.name.clone(), function_rva);

        let lifted = lift_function(cfg, pe, &mut ir, fid, f);
        if let Err(err) = lifted {
            ir.function_mut(fid).fallback = true;
            diagnostics
                .fallback_functions
                .push((f.name.clone(), format!("{err:#}")));
        }
    }

    resolve_deferred_edge_targets(&mut ir);
    diagnostics.noreturn_function_rvas = analyze_noreturn(&ir, &name_by_rva);

    Ok((ir, diagnostics))
}

fn lift_function(
    cfg: &ProgramCfg,
    pe: &PeFile,
    ir: &mut ProgramIr,
    fid: blare_ir::FunctionId,
    func: &FunctionCfg,
) -> Result<()> {
    for block in &func.blocks {
        lift_block(cfg, pe, ir, fid, block).with_context(|| {
            format!(
                "failed to lift function '{}' block 0x{:x}",
                func.name, block.start
            )
        })?;
    }

    wire_function_edges(cfg, ir, fid, func)?;

    Ok(())
}

fn wire_function_edges(
    cfg: &ProgramCfg,
    ir: &mut ProgramIr,
    fid: blare_ir::FunctionId,
    func: &FunctionCfg,
) -> Result<()> {
    let (by_start, by_range) = collect_block_target_index(ir);

    for edge in &func.edges {
        let from_rva = cfg.to_rva(edge.from)? as u64;
        let mut to_rva = va_to_rva_if_in_image(cfg, edge.to);
        let Some(from_id) = by_start.get(&from_rva).copied() else {
            continue;
        };
        let to_id = to_rva.and_then(|rva| resolve_target_block(ir, fid, rva, &by_start, &by_range));
        if let Some(target_block) = to_id {
            to_rva = Some(ir.block(target_block).start_rva);
        }
        let kind = match edge.edge_type {
            blare_cfg::EdgeType::Call if edge.indirect => EdgeKind::IndirectCall,
            blare_cfg::EdgeType::Call => EdgeKind::Call,
            blare_cfg::EdgeType::Branch if edge.indirect => EdgeKind::IndirectJump,
            blare_cfg::EdgeType::Branch => EdgeKind::Branch,
            blare_cfg::EdgeType::Fallthrough => EdgeKind::Fallthrough,
        };

        ir.add_edge(from_id, to_id, to_rva, kind, edge.indirect);
    }

    for site in &func.indirect_sites {
        let Some(site_rva) = va_to_rva_if_in_image(cfg, site.address) else {
            continue;
        };
        let from_id = find_block_containing_rva(ir, fid, site_rva);
        let Some(from_id) = from_id else {
            continue;
        };

        if site.possible_targets.is_empty() {
            let kind = match site.kind {
                blare_cfg::IndirectSiteKind::Call => EdgeKind::IndirectCall,
                blare_cfg::IndirectSiteKind::Jump => EdgeKind::IndirectJump,
            };
            ir.add_edge(from_id, None, None, kind, true);
        } else {
            for target in &site.possible_targets {
                let mut target_rva = va_to_rva_if_in_image(cfg, *target);
                let to_id = target_rva
                    .and_then(|rva| resolve_target_block(ir, fid, rva, &by_start, &by_range));
                if let Some(target_block) = to_id {
                    target_rva = Some(ir.block(target_block).start_rva);
                }
                let kind = match site.kind {
                    blare_cfg::IndirectSiteKind::Call => EdgeKind::IndirectCall,
                    blare_cfg::IndirectSiteKind::Jump => EdgeKind::IndirectJump,
                };
                ir.add_edge(from_id, to_id, target_rva, kind, true);
            }
        }
    }

    for jt in &func.jump_tables {
        let Some(site_rva) = va_to_rva_if_in_image(cfg, jt.site) else {
            continue;
        };
        let from_id = find_block_containing_rva(ir, fid, site_rva);
        let Some(from_id) = from_id else {
            continue;
        };

        for target in &jt.targets {
            let mut target_rva = va_to_rva_if_in_image(cfg, *target);
            let to_id =
                target_rva.and_then(|rva| resolve_target_block(ir, fid, rva, &by_start, &by_range));
            if let Some(target_block) = to_id {
                target_rva = Some(ir.block(target_block).start_rva);
            }
            ir.add_edge(from_id, to_id, target_rva, EdgeKind::JumpTable, true);
        }
    }

    Ok(())
}

fn collect_block_target_index(ir: &ProgramIr) -> (HashMap<u64, BlockId>, Vec<(u64, u64, BlockId)>) {
    let mut by_start = HashMap::<u64, BlockId>::new();
    let mut by_range = Vec::<(u64, u64, BlockId)>::new();
    for block in &ir.blocks {
        if ir.function(block.function).fallback {
            continue;
        }
        by_start.entry(block.start_rva).or_insert(block.id);
        by_range.push((block.start_rva, block.end_rva, block.id));
    }
    (by_start, by_range)
}

fn find_block_containing_rva_global(by_range: &[(u64, u64, BlockId)], rva: u64) -> Option<BlockId> {
    by_range
        .iter()
        .find(|(start, end, _)| rva >= *start && rva < *end)
        .map(|(_, _, id)| *id)
}

fn resolve_target_block(
    ir: &ProgramIr,
    fid: blare_ir::FunctionId,
    target_rva: u64,
    by_start: &HashMap<u64, BlockId>,
    by_range: &[(u64, u64, BlockId)],
) -> Option<BlockId> {
    if let Some(id) = by_start.get(&target_rva).copied() {
        return Some(id);
    }

    if let Some(id) = find_block_containing_rva(ir, fid, target_rva) {
        if !ir.function(ir.block(id).function).fallback {
            return Some(id);
        }
    }

    find_block_containing_rva_global(by_range, target_rva)
}

fn resolve_deferred_edge_targets(ir: &mut ProgramIr) {
    for idx in 0..ir.edges.len() {
        if ir.edges[idx].to.is_some() {
            continue;
        }
        let Some(target_rva) = ir.edges[idx].target_rva else {
            continue;
        };
        let source_func = ir.block(ir.edges[idx].from).function;
        if ir.function(source_func).fallback {
            continue;
        }

        let mut resolved = resolve_target_in_function(ir, source_func, target_rva);
        if resolved.is_none() {
            let global_candidates = find_block_candidates_global(ir, target_rva);
            if global_candidates.len() == 1 {
                resolved = Some(global_candidates[0]);
            }
        }

        if let Some(target_block) = resolved {
            let canonical_rva = ir.block(target_block).start_rva;
            ir.edges[idx].to = Some(target_block);
            ir.edges[idx].target_rva = Some(canonical_rva);
        }
    }
}

fn resolve_target_in_function(
    ir: &ProgramIr,
    fid: blare_ir::FunctionId,
    target_rva: u64,
) -> Option<BlockId> {
    for bid in &ir.function(fid).blocks {
        let block = ir.block(*bid);
        if block.start_rva == target_rva {
            return Some(*bid);
        }
    }
    find_block_containing_rva(ir, fid, target_rva)
}

fn find_block_candidates_global(ir: &ProgramIr, target_rva: u64) -> Vec<BlockId> {
    let mut out = Vec::new();
    for block in &ir.blocks {
        if ir.function(block.function).fallback {
            continue;
        }
        if target_rva >= block.start_rva && target_rva < block.end_rva {
            out.push(block.id);
        }
    }
    out
}

fn va_to_rva_if_in_image(cfg: &ProgramCfg, va: u64) -> Option<u64> {
    if va < cfg.image_base {
        return None;
    }
    let rva = va - cfg.image_base;
    if rva > u32::MAX as u64 {
        return None;
    }
    Some(rva)
}

fn find_block_containing_rva(
    ir: &ProgramIr,
    fid: blare_ir::FunctionId,
    rva: u64,
) -> Option<BlockId> {
    for bid in &ir.function(fid).blocks {
        let b = ir.block(*bid);
        if rva >= b.start_rva && rva < b.end_rva {
            return Some(*bid);
        }
    }
    None
}

fn lift_block(
    cfg: &ProgramCfg,
    pe: &PeFile,
    ir: &mut ProgramIr,
    fid: blare_ir::FunctionId,
    block: &BlockCfg,
) -> Result<()> {
    let start_rva = cfg.to_rva(block.start)? as u64;
    let end_rva = cfg.to_rva(block.end)? as u64;

    let block_id = ir.add_block(fid, start_rva, end_rva);

    let size = (end_rva - start_rva) as usize;
    let bytes = pe.read_rva_slice(start_rva as u32, size)?;
    let ip = cfg.image_base + start_rva;
    let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);

    while decoder.can_decode() {
        if decoder.ip() >= cfg.image_base + end_rva {
            break;
        }

        let inst = decoder.decode();
        if inst.is_invalid() {
            anyhow::bail!(
                "invalid instruction at va 0x{:x} (rva 0x{:x})",
                decoder.ip(),
                decoder.ip().saturating_sub(cfg.image_base)
            );
        }

        let original_rva = inst.ip().saturating_sub(cfg.image_base);
        ir.add_instruction(block_id, original_rva, inst);
    }

    let block_ref = ir.block(block_id).clone();
    if block_ref.insts.is_empty() {
        anyhow::bail!(
            "empty decoded block for range rva 0x{:x}..0x{:x}",
            start_rva,
            end_rva
        );
    }

    let last = ir.inst(*block_ref.insts.last().expect("inst exists"));
    let terminator = classify_terminator(last.instruction, cfg.image_base);
    ir.block_mut(block_id).terminator = terminator;

    Ok(())
}

fn classify_terminator(inst: Instruction, image_base: u64) -> Terminator {
    match inst.flow_control() {
        FlowControl::Return => Terminator::Return,
        FlowControl::UnconditionalBranch => {
            if inst.is_jmp_short_or_near() {
                Terminator::UnconditionalBranch {
                    target: inst.near_branch_target().saturating_sub(image_base),
                }
            } else {
                Terminator::IndirectBranch
            }
        }
        FlowControl::ConditionalBranch => {
            let target = inst.near_branch_target().saturating_sub(image_base);
            let fallthrough = (inst.next_ip().saturating_sub(image_base)) as u64;
            Terminator::ConditionalBranch {
                target,
                fallthrough,
            }
        }
        FlowControl::IndirectBranch => Terminator::IndirectBranch,
        FlowControl::Call => {
            if inst.is_call_near() {
                Terminator::DirectCall {
                    target: inst.near_branch_target().saturating_sub(image_base),
                }
            } else {
                Terminator::IndirectCall
            }
        }
        FlowControl::IndirectCall => Terminator::IndirectCall,
        FlowControl::Exception | FlowControl::XbeginXabortXend => Terminator::Trap,
        FlowControl::Next => {
            if matches!(inst.mnemonic(), Mnemonic::Ud2 | Mnemonic::Int3) {
                Terminator::Trap
            } else {
                Terminator::Fallthrough
            }
        }
        _ => Terminator::Unknown,
    }
}

fn analyze_noreturn(ir: &ProgramIr, name_by_rva: &HashMap<u64, String>) -> HashSet<u64> {
    let mut noreturn = HashSet::new();

    for f in &ir.functions {
        if name_by_rva
            .get(&f.address_rva)
            .is_some_and(|name| is_seed_noreturn_name(name))
        {
            noreturn.insert(f.address_rva);
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for f in &ir.functions {
            if noreturn.contains(&f.address_rva) {
                continue;
            }

            let mut all_terminate = true;
            for b in &f.blocks {
                let block = ir.block(*b);
                match &block.terminator {
                    Terminator::Trap => {}
                    Terminator::DirectCall { target } if noreturn.contains(target) => {}
                    _ => {
                        let has_only_unresolved_indirect = block.outgoing_edges.iter().all(|eid| {
                            matches!(
                                ir.edges[*eid].kind,
                                EdgeKind::IndirectCall | EdgeKind::IndirectJump
                            )
                        });
                        if !has_only_unresolved_indirect {
                            all_terminate = false;
                            break;
                        }
                    }
                }
            }

            if all_terminate {
                noreturn.insert(f.address_rva);
                changed = true;
            }
        }
    }

    noreturn
}

fn is_seed_noreturn_name(name: &str) -> bool {
    const WHITELIST: [&str; 8] = [
        "_exit",
        "exit",
        "abort",
        "terminate",
        "exitprocess",
        "panic",
        "panic_impl",
        "rust_begin_unwind",
    ];

    let mut variants = Vec::<String>::new();
    let mut normalized = name.trim().to_ascii_lowercase();
    if let Some(idx) = normalized.rfind("::") {
        normalized = normalized[idx + 2..].to_string();
    }
    if let Some(idx) = normalized.rfind('!') {
        normalized = normalized[idx + 1..].to_string();
    }
    if let Some(idx) = normalized.find('@') {
        normalized = normalized[..idx].to_string();
    }
    variants.push(normalized.clone());
    variants.push(normalized.trim_start_matches('_').to_string());
    for prefix in ["__imp_", "imp_", "j_"] {
        if normalized.starts_with(prefix) {
            variants.push(normalized[prefix.len()..].to_string());
        }
    }

    variants
        .into_iter()
        .any(|candidate| WHITELIST.contains(&candidate.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blare_cfg::{EdgeCfg, EdgeType, IndirectSiteCfg, IndirectSiteKind, JumpTableCfg};

    #[test]
    fn noreturn_from_name_seed_exact_match() {
        let mut ir = ProgramIr::new(0x140000000);
        let id = ir.add_function("ExitProcess", 0x2000);
        let b = ir.add_block(id, 0x2000, 0x2002);
        ir.block_mut(b).terminator = Terminator::Trap;

        let mut names = HashMap::new();
        names.insert(0x2000, "ExitProcess".to_string());

        let n = analyze_noreturn(&ir, &names);
        assert!(n.contains(&0x2000));
    }

    #[test]
    fn noreturn_name_substring_false_positive_is_avoided() {
        let mut ir = ProgramIr::new(0x140000000);
        let id = ir.add_function("next_exit_code", 0x2100);
        let b = ir.add_block(id, 0x2100, 0x2102);
        ir.block_mut(b).terminator = Terminator::UnconditionalBranch { target: 0x2100 };
        ir.add_edge(b, Some(b), Some(0x2100), EdgeKind::Branch, false);

        let mut names = HashMap::new();
        names.insert(0x2100, "next_exit_code".to_string());

        let n = analyze_noreturn(&ir, &names);
        assert!(!n.contains(&0x2100));
    }

    #[test]
    fn wire_resolves_cross_function_targets_and_canonicalizes_rva() {
        let image_base = 0x140000000;
        let cfg = ProgramCfg {
            program_name: "fixture.exe".to_string(),
            image_base,
            functions: vec![
                FunctionCfg {
                    name: "f".to_string(),
                    address: image_base + 0x1000,
                    blocks: vec![BlockCfg {
                        start: image_base + 0x1000,
                        end: image_base + 0x1010,
                    }],
                    edges: vec![EdgeCfg {
                        from: image_base + 0x1000,
                        to: image_base + 0x2008,
                        edge_type: EdgeType::Branch,
                        indirect: true,
                    }],
                    indirect_call_sites: Vec::new(),
                    indirect_sites: vec![IndirectSiteCfg {
                        address: image_base + 0x1004,
                        kind: IndirectSiteKind::Jump,
                        possible_targets: vec![image_base + 0x200c],
                    }],
                    jump_tables: vec![JumpTableCfg {
                        site: image_base + 0x1006,
                        base: None,
                        entry_size: None,
                        min_index: None,
                        max_index: None,
                        targets: vec![image_base + 0x200e],
                    }],
                },
                FunctionCfg {
                    name: "g".to_string(),
                    address: image_base + 0x2000,
                    blocks: vec![BlockCfg {
                        start: image_base + 0x2000,
                        end: image_base + 0x2010,
                    }],
                    edges: Vec::new(),
                    indirect_call_sites: Vec::new(),
                    indirect_sites: Vec::new(),
                    jump_tables: Vec::new(),
                },
            ],
        };

        let mut ir = ProgramIr::new(image_base);
        let fid_f = ir.add_function("f", 0x1000);
        let fid_g = ir.add_function("g", 0x2000);
        let _b_f = ir.add_block(fid_f, 0x1000, 0x1010);
        let b_g = ir.add_block(fid_g, 0x2000, 0x2010);

        wire_function_edges(&cfg, &mut ir, fid_f, &cfg.functions[0]).expect("wire succeeds");
        assert_eq!(ir.edges.len(), 3);

        for e in &ir.edges {
            assert_eq!(e.to, Some(b_g));
            assert_eq!(e.target_rva, Some(0x2000));
        }
    }

    #[test]
    fn resolve_deferred_targets_fixes_unresolved_interior_rva() {
        let mut ir = ProgramIr::new(0x140000000);
        let fid_a = ir.add_function("a", 0x1000);
        let fid_b = ir.add_function("b", 0x2000);
        let b_a = ir.add_block(fid_a, 0x1000, 0x1010);
        let b_b = ir.add_block(fid_b, 0x2000, 0x2010);
        ir.add_edge(b_a, None, Some(0x2008), EdgeKind::IndirectJump, true);

        resolve_deferred_edge_targets(&mut ir);
        assert_eq!(ir.edges[0].to, Some(b_b));
        assert_eq!(ir.edges[0].target_rva, Some(0x2000));
    }

    #[test]
    fn resolve_deferred_targets_skips_ambiguous_overlaps() {
        let mut ir = ProgramIr::new(0x140000000);
        let fid_a = ir.add_function("a", 0x1000);
        let fid_b = ir.add_function("b", 0x2000);
        let fid_c = ir.add_function("c", 0x2008);
        let b_a = ir.add_block(fid_a, 0x1000, 0x1010);
        let _b_b = ir.add_block(fid_b, 0x2000, 0x2010);
        let _b_c = ir.add_block(fid_c, 0x2008, 0x2018);
        ir.add_edge(b_a, None, Some(0x2009), EdgeKind::IndirectJump, true);

        resolve_deferred_edge_targets(&mut ir);
        assert_eq!(ir.edges[0].to, None);
        assert_eq!(ir.edges[0].target_rva, Some(0x2009));
    }
}
