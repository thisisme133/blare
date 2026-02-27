use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::{Context, Result, bail};
use blare_ir::{
    BlockId, EdgeKind, FunctionId, IndirectThunkKind, PassStatsRecord, ProgramIr, Terminator,
};
use iced_x86::{
    Code, FlowControl, IcedError, Instruction, InstructionInfoFactory, MemoryOperand, Mnemonic,
    OpAccess, OpKind, Register,
};

pub trait Pass {
    fn name(&self) -> &'static str;
    fn run(&self, ir: &mut ProgramIr) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfuscationProfile {
    Balanced,
    Aggressive,
    Sigbreaker,
    Custom,
}

impl ObfuscationProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
            Self::Sigbreaker => "sigbreaker",
            Self::Custom => "custom",
        }
    }

    fn is_aggressive(self) -> bool {
        matches!(self, Self::Aggressive)
    }
}

const PROFILE_NAMES: [&str; 4] = ["balanced", "aggressive", "sigbreaker", "custom"];

#[derive(Debug, Clone, Copy)]
pub struct ProfilePassOptions {
    pub indirect_cf_probability: f64,
}

impl Default for ProfilePassOptions {
    fn default() -> Self {
        Self {
            indirect_cf_probability: 0.35,
        }
    }
}

pub fn available_profile_names() -> &'static [&'static str] {
    &PROFILE_NAMES
}

pub fn profile_from_name(name: &str) -> Option<ObfuscationProfile> {
    match name.trim().to_ascii_lowercase().as_str() {
        "balanced" => Some(ObfuscationProfile::Balanced),
        "aggressive" => Some(ObfuscationProfile::Aggressive),
        "sigbreaker" => Some(ObfuscationProfile::Sigbreaker),
        "custom" => Some(ObfuscationProfile::Custom),
        _ => None,
    }
}

pub fn build_profile_pass(profile: ObfuscationProfile, seed: u64) -> Box<dyn Pass + Send + Sync> {
    build_profile_pass_with_options(profile, seed, ProfilePassOptions::default())
}

pub fn build_profile_pass_with_options(
    profile: ObfuscationProfile,
    seed: u64,
    options: ProfilePassOptions,
) -> Box<dyn Pass + Send + Sync> {
    let mut passes: Vec<Box<dyn Pass + Send + Sync>> = Vec::new();

    match profile {
        ObfuscationProfile::Balanced | ObfuscationProfile::Aggressive => {
            let aggressive = profile.is_aggressive();
            // Constant synthesis early: hide magic numbers before other passes
            passes.push(Box::new(OpaqueConstantSynthesisPass {
                seed: seed ^ 0xb3c7_1e4d_92a5_6f08,
                aggressive,
            }));
            passes.push(Box::new(MbaNonLinearPass {
                seed: seed ^ 0x09f4_729e_f4a7_2f13,
                aggressive,
            }));
            passes.push(Box::new(OpaqueOneWayPredicatePass {
                seed: seed ^ 0x5d58_8b65_657f_b2d5,
                aggressive,
            }));
            passes.push(Box::new(OpaquePathExplosionPass {
                seed: seed ^ 0x86a7_6174_5d3b_4c1f,
                aggressive,
            }));
            if aggressive {
                // Dead stores: pollute pseudocode with phantom variables
                passes.push(Box::new(DeadStoreInjectionPass {
                    seed: seed ^ 0xe1f2_3b5c_7d89_a0b4,
                    aggressive,
                }));
                passes.push(Box::new(LoopEncodedSemanticsPass {
                    seed: seed ^ 0xd4aa_8f3b_73b2_0c5d,
                    min_amount: 2,
                    max_iterations: 256,
                }));
                passes.push(Box::new(ObscureReferencesPass {
                    seed: seed ^ 0x4b7a_11df_8a6e_99c3,
                    aggressive,
                }));
                passes.push(Box::new(IndirectControlFlowPass {
                    seed: seed ^ 0x73d9_42a6_c51b_0ef7,
                    probability: options.indirect_cf_probability.clamp(0.0, 1.0),
                }));
                passes.push(Box::new(IdaDecompilerCrasherPass {
                    seed: seed ^ 0x9ca8_37db_2f8e_4ad1,
                    aggressive,
                }));
                // Control flow flattening: destroy structured control flow
                passes.push(Box::new(ControlFlowFlatteningPass {
                    seed: seed ^ 0xa4d8_6c3f_1b5e_97a2,
                }));
                // Push-ret: fragment functions by replacing jmp with push+ret
                passes.push(Box::new(PushRetBranchPass {
                    seed: seed ^ 0x7b2e_d4a1_93f5_c806,
                    probability: 0.3,
                }));
                // String reference obfuscation: break xrefs to strings
                passes.push(Box::new(StringReferenceObfuscationPass {
                    seed: seed ^ 0xf9c1_5d7e_a2b3_0846,
                    aggressive,
                }));
            }
            passes.push(Box::new(SigInstructionReorderPass {
                seed: seed ^ 0x67e7_9f53_36a5_a6af,
                require_mutation: false,
            }));
            passes.push(Box::new(SigBlockShufflePass {
                seed: seed ^ 0x22e4_a1c8_84b9_5ca7,
                require_mutation: false,
            }));
            passes.push(Box::new(SigSegmentSelectorPass {
                seed: seed ^ 0x15e7_d8c4_6af0_5c3d,
                require_mutation: false,
                allow_size_growth: true,
            }));
        }
        ObfuscationProfile::Sigbreaker => {
            passes.push(Box::new(SigInstructionReorderPass {
                seed: seed ^ 0x67e7_9f53_36a5_a6af,
                require_mutation: false,
            }));
            passes.push(Box::new(SigBlockShufflePass {
                seed: seed ^ 0x22e4_a1c8_84b9_5ca7,
                require_mutation: false,
            }));
            passes.push(Box::new(SigSegmentSelectorPass {
                seed: seed ^ 0x15e7_d8c4_6af0_5c3d,
                require_mutation: false,
                allow_size_growth: false,
            }));
        }
        ObfuscationProfile::Custom => {
            passes.push(Box::new(OpaqueConstantSynthesisPass {
                seed: seed ^ 0xb3c7_1e4d_92a5_6f08,
                aggressive: true,
            }));
            passes.push(Box::new(MbaNonLinearPass {
                seed: seed ^ 0x09f4_729e_f4a7_2f13,
                aggressive: true,
            }));
            passes.push(Box::new(OpaqueOneWayPredicatePass {
                seed: seed ^ 0x5d58_8b65_657f_b2d5,
                aggressive: true,
            }));
            passes.push(Box::new(OpaquePathExplosionPass {
                seed: seed ^ 0x86a7_6174_5d3b_4c1f,
                aggressive: true,
            }));
            passes.push(Box::new(ObscureReferencesPass {
                seed: seed ^ 0x4b7a_11df_8a6e_99c3,
                aggressive: true,
            }));
            passes.push(Box::new(StringReferenceObfuscationPass {
                seed: seed ^ 0xf9c1_5d7e_a2b3_0846,
                aggressive: true,
            }));
        }
    }

    Box::new(PassPipeline {
        profile,
        seed,
        passes,
    })
}

struct PassPipeline {
    profile: ObfuscationProfile,
    seed: u64,
    passes: Vec<Box<dyn Pass + Send + Sync>>,
}

impl Pass for PassPipeline {
    fn name(&self) -> &'static str {
        "profile-pipeline"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        ir.set_obfuscation_context(self.profile.as_str(), self.seed);
        for pass in &self.passes {
            pass.run(ir)
                .with_context(|| format!("pass '{}' failed", pass.name()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct MbaNonLinearPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for MbaNonLinearPass {
    fn name(&self) -> &'static str {
        "mba-nonlinear"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }

            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();
            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let original_ids = ir.block(block_id).insts.clone();
                if original_ids.len() < 2 {
                    continue;
                }

                let mut rebuilt = Vec::with_capacity(original_ids.len());
                for (inst_index, inst_id) in original_ids.iter().enumerate() {
                    let inst = ir.inst(*inst_id).instruction;
                    let mut injected_here = false;

                    if inst_index + 1 < original_ids.len()
                        && is_mba_candidate(inst)
                        && should_inject(
                            self.seed,
                            block_start,
                            inst_index as u64,
                            self.aggressive,
                            2,
                        )
                    {
                        if let Some((x, y)) = mba_input_from_inst(inst) {
                            let mut forbidden = vec![x];
                            if let MbaInput::Reg(y_reg) = y {
                                forbidden.push(y_reg);
                            }
                            if let Some((tmp1, tmp2)) =
                                choose_two_scratch_regs(inst, &mut info_factory, &forbidden)
                            {
                                let seq = build_mba_nonlinear_sequence(
                                    x,
                                    y,
                                    tmp1,
                                    tmp2,
                                    mix_seed(self.seed, block_start ^ inst_index as u64),
                                )?;
                                for syn in seq {
                                    let syn_id =
                                        ir.add_instruction(block_id, allocator.next_inst(), syn);
                                    rebuilt.push(syn_id);
                                    mutated_instructions += 1;
                                }
                                injected_here = true;
                            } else {
                                skipped_sites += 1;
                            }
                        } else {
                            skipped_sites += 1;
                        }
                    }

                    rebuilt.push(*inst_id);
                    if injected_here {
                        mutated_blocks.insert(block_id);
                        mutated_functions.insert(function_id);
                    }
                }

                if rebuilt != original_ids {
                    ir.block_mut(block_id).insts = rebuilt;
                }
            }
        }

        if mutated_instructions == 0 {
            bail!("mba-nonlinear produced 0 safe mutations (strict fail-closed policy)");
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct OpaqueOneWayPredicatePass {
    seed: u64,
    aggressive: bool,
}

impl Pass for OpaqueOneWayPredicatePass {
    fn name(&self) -> &'static str {
        "opaque-one-way"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;

            let block_ids = ir.functions[fidx].blocks.clone();
            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let original_ids = ir.block(block_id).insts.clone();
                if original_ids.len() < 2 {
                    continue;
                }

                let mut rebuilt = Vec::with_capacity(original_ids.len());
                let mut idx = 0usize;
                let mut block_changed = false;

                while idx < original_ids.len() {
                    if idx + 1 < original_ids.len() {
                        let cmp = ir.inst(original_ids[idx]).instruction;
                        let jcc = ir.inst(original_ids[idx + 1]).instruction;
                        if (is_eq_cmp_followed_by_eq_jcc(cmp, jcc)
                            || is_test_zero_followed_by_eq_jcc(cmp, jcc))
                            && should_inject(self.seed, block_start, idx as u64, self.aggressive, 2)
                        {
                            let cmp_inputs = if is_eq_cmp_followed_by_eq_jcc(cmp, jcc) {
                                cmp_operand_reg64(cmp).zip(cmp_operand_imm64(cmp))
                            } else {
                                test_operand_reg64(cmp).map(|reg| (reg, 0u64))
                            };

                            if let Some((reg, imm)) = cmp_inputs {
                                if let Some((tmp1, tmp2)) =
                                    choose_two_scratch_regs(cmp, &mut info_factory, &[reg])
                                {
                                    let sequence = build_one_way_cmp_sequence(
                                        reg,
                                        imm,
                                        tmp1,
                                        tmp2,
                                        mix_seed(self.seed, block_start ^ idx as u64),
                                    )?;

                                    for syn in sequence {
                                        let syn_id = ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            syn,
                                        );
                                        rebuilt.push(syn_id);
                                        mutated_instructions += 1;
                                    }

                                    // keep original branch, drop original cmp
                                    rebuilt.push(original_ids[idx + 1]);
                                    idx += 2;
                                    block_changed = true;
                                    mutated_blocks.insert(block_id);
                                    mutated_functions.insert(function_id);
                                    continue;
                                }
                            }
                            skipped_sites += 1;
                        }
                    }

                    rebuilt.push(original_ids[idx]);
                    idx += 1;
                }

                if block_changed {
                    ir.block_mut(block_id).insts = rebuilt;
                } else {
                    let block = ir.block(block_id).clone();
                    if block.insts.is_empty() {
                        continue;
                    }
                    let detour_target = match block.terminator {
                        Terminator::UnconditionalBranch { target } => Some(target),
                        Terminator::Return => None,
                        _ => {
                            skipped_sites += 1;
                            continue;
                        }
                    };

                    let source_reg =
                        select_source_reg_for_path_predicate(ir, block_id, &mut info_factory)
                            .unwrap_or(Register::RAX);
                    let Some((tmp1, tmp2)) = choose_two_scratch_regs(
                        ir.inst(*block.insts.last().expect("non-empty")).instruction,
                        &mut info_factory,
                        &[source_reg],
                    ) else {
                        skipped_sites += 1;
                        continue;
                    };

                    let mut rebuilt = Vec::with_capacity(block.insts.len() + 20);
                    for id in &block.insts[..block.insts.len() - 1] {
                        rebuilt.push(*id);
                    }

                    let sequence = build_one_way_cmp_sequence(
                        source_reg,
                        mix_seed(self.seed, block.start_rva),
                        tmp1,
                        tmp2,
                        mix_seed(self.seed, block.start_rva ^ 0xA5A5_A5A5_A5A5_A5A5),
                    )?;
                    for syn in sequence {
                        let syn_id = ir.add_instruction(block_id, allocator.next_inst(), syn);
                        rebuilt.push(syn_id);
                        mutated_instructions += 1;
                    }

                    match detour_target {
                        Some(target) => {
                            let jcc = Instruction::with_branch(
                                Code::Jne_rel32_64,
                                ir.image_base + target,
                            )
                            .map_err(anyhow_from_iced)?;
                            let jcc_id = ir.add_instruction(block_id, allocator.next_inst(), jcc);
                            rebuilt.push(jcc_id);
                            mutated_instructions += 1;
                        }
                        None => {
                            let detour_start = allocator.next_block();
                            let detour_id =
                                ir.add_block(function_id, detour_start, detour_start + 1);
                            let ret = Instruction::with(Code::Retnq);
                            ir.add_instruction(detour_id, allocator.next_inst(), ret);
                            ir.block_mut(detour_id).terminator = Terminator::Return;
                            ir.add_edge(
                                block_id,
                                Some(detour_id),
                                Some(detour_start),
                                blare_ir::EdgeKind::Branch,
                                false,
                            );
                            let jcc = Instruction::with_branch(
                                Code::Jne_rel32_64,
                                ir.image_base + detour_start,
                            )
                            .map_err(anyhow_from_iced)?;
                            let jcc_id = ir.add_instruction(block_id, allocator.next_inst(), jcc);
                            rebuilt.push(jcc_id);
                            mutated_instructions += 1;
                            injected_blocks += 1;
                            mutated_blocks.insert(detour_id);
                        }
                    }

                    rebuilt.push(*block.insts.last().expect("non-empty"));
                    ir.block_mut(block_id).insts = rebuilt;
                    mutated_blocks.insert(block_id);
                    mutated_functions.insert(function_id);
                }
            }
        }

        if mutated_instructions == 0 {
            bail!("opaque-one-way produced 0 safe mutations (strict fail-closed policy)");
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct OpaquePathExplosionPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for OpaquePathExplosionPass {
    fn name(&self) -> &'static str {
        "opaque-path-explosion"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }

            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();
            for (block_index, block_id) in block_ids.iter().enumerate() {
                let block_id = *block_id;
                let block = ir.block(block_id).clone();
                if block.insts.is_empty() {
                    continue;
                }

                if !matches!(
                    block.terminator,
                    Terminator::UnconditionalBranch { .. } | Terminator::Return
                ) {
                    continue;
                }

                if !should_inject(
                    self.seed,
                    block.start_rva,
                    block_index as u64,
                    self.aggressive,
                    2,
                ) {
                    continue;
                }

                let source_reg =
                    select_source_reg_for_path_predicate(ir, block_id, &mut info_factory)
                        .unwrap_or(Register::RAX);
                let Some(tmp) = choose_one_scratch_reg(
                    &ir.inst(*block.insts.last().expect("non-empty")).instruction,
                    &mut info_factory,
                    &[source_reg],
                ) else {
                    skipped_sites += 1;
                    continue;
                };

                let detour_start = allocator.next_block();
                let detour_id = ir.add_block(function_id, detour_start, detour_start + 1);
                let detour_target = match block.terminator {
                    Terminator::UnconditionalBranch { target } => Some(target),
                    Terminator::Return => None,
                    _ => None,
                };

                match detour_target {
                    Some(target) => {
                        let jmp =
                            Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + target)
                                .map_err(anyhow_from_iced)?;
                        ir.add_instruction(detour_id, allocator.next_inst(), jmp);
                        ir.block_mut(detour_id).terminator =
                            Terminator::UnconditionalBranch { target };
                        ir.add_edge(
                            detour_id,
                            None,
                            Some(target),
                            blare_ir::EdgeKind::Branch,
                            false,
                        );
                    }
                    None => {
                        let ret = Instruction::with(Code::Retnq);
                        ir.add_instruction(detour_id, allocator.next_inst(), ret);
                        ir.block_mut(detour_id).terminator = Terminator::Return;
                    }
                }

                let mut rebuilt = Vec::with_capacity(block.insts.len() + 10);
                for id in &block.insts[..block.insts.len() - 1] {
                    rebuilt.push(*id);
                }

                let guard = build_path_explosion_guard(
                    source_reg,
                    tmp,
                    detour_start,
                    mix_seed(self.seed, block.start_rva),
                    ir.image_base,
                )?;
                for syn in guard {
                    let syn_id = ir.add_instruction(block_id, allocator.next_inst(), syn);
                    rebuilt.push(syn_id);
                    mutated_instructions += 1;
                }

                rebuilt.push(*block.insts.last().expect("non-empty"));
                ir.block_mut(block_id).insts = rebuilt;
                ir.add_edge(
                    block_id,
                    Some(detour_id),
                    Some(detour_start),
                    blare_ir::EdgeKind::Branch,
                    false,
                );

                injected_blocks += 1;
                mutated_blocks.insert(block_id);
                mutated_blocks.insert(detour_id);
                mutated_functions.insert(function_id);
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ThunkFlowKind {
    Call,
    Branch,
}

#[derive(Debug, Clone, Copy)]
struct ThunkBuildResult {
    block_id: BlockId,
    start_rva: u64,
}

#[derive(Debug, Clone, Copy)]
struct LoopEncodedSemanticsPass {
    seed: u64,
    min_amount: u32,
    max_iterations: u32,
}

impl Pass for LoopEncodedSemanticsPass {
    fn name(&self) -> &'static str {
        "loop-encoded-semantics"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for (block_index, block_id) in block_ids.iter().enumerate() {
                let block_id = *block_id;
                let block = ir.block(block_id).clone();
                if block.insts.len() != 1 {
                    continue;
                }
                if !matches!(
                    block.terminator,
                    Terminator::UnconditionalBranch { .. } | Terminator::Return
                ) {
                    continue;
                }
                if !should_inject(self.seed, block.start_rva, block_index as u64, true, 1) {
                    continue;
                }

                let inst_id = block.insts[0];
                let inst = ir.inst(inst_id).instruction;
                let Some((dst, amount, add_direction)) =
                    normalize_add_sub_imm_candidate(inst, self.min_amount, self.max_iterations)
                else {
                    skipped_sites += 1;
                    continue;
                };

                let Some(counter) = choose_one_scratch_reg(&inst, &mut info_factory, &[dst]) else {
                    skipped_sites += 1;
                    continue;
                };

                let opaque_mask = derive_loop_counter_mask(self.seed, block.start_rva, amount);
                let encoded_count = (amount as u64) ^ (opaque_mask as u64);

                let loop_start = allocator.next_block();
                let loop_id = ir.add_block(function_id, loop_start, loop_start + 1);
                let exit_start = allocator.next_block();
                let exit_id = ir.add_block(function_id, exit_start, exit_start + 1);

                let mut rebuilt_entry = Vec::with_capacity(4);
                let push_counter =
                    Instruction::with1(Code::Push_r64, counter).map_err(anyhow_from_iced)?;
                let push_counter_id =
                    ir.add_instruction(block_id, allocator.next_inst(), push_counter);
                rebuilt_entry.push(push_counter_id);
                mutated_instructions += 1;

                let mov_counter = Instruction::with2(Code::Mov_r64_imm64, counter, encoded_count)
                    .map_err(anyhow_from_iced)?;
                let mov_counter_id =
                    ir.add_instruction(block_id, allocator.next_inst(), mov_counter);
                rebuilt_entry.push(mov_counter_id);
                mutated_instructions += 1;

                let xor_counter =
                    Instruction::with2(Code::Xor_rm64_imm32, counter, opaque_mask as i32)
                        .map_err(anyhow_from_iced)?;
                let xor_counter_id =
                    ir.add_instruction(block_id, allocator.next_inst(), xor_counter);
                rebuilt_entry.push(xor_counter_id);
                mutated_instructions += 1;

                let jmp_loop =
                    Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + loop_start)
                        .map_err(anyhow_from_iced)?;
                let jmp_loop_id = ir.add_instruction(block_id, allocator.next_inst(), jmp_loop);
                rebuilt_entry.push(jmp_loop_id);
                mutated_instructions += 1;

                ir.block_mut(block_id).insts = rebuilt_entry;
                ir.block_mut(block_id).terminator =
                    Terminator::UnconditionalBranch { target: loop_start };
                ir.block_mut(block_id).outgoing_edges.clear();
                ir.add_edge(
                    block_id,
                    Some(loop_id),
                    Some(loop_start),
                    EdgeKind::Branch,
                    false,
                );

                let cmp_counter = Instruction::with2(Code::Cmp_rm64_imm32, counter, 0)
                    .map_err(anyhow_from_iced)?;
                ir.add_instruction(loop_id, allocator.next_inst(), cmp_counter);
                mutated_instructions += 1;
                let je_exit =
                    Instruction::with_branch(Code::Je_rel32_64, ir.image_base + exit_start)
                        .map_err(anyhow_from_iced)?;
                ir.add_instruction(loop_id, allocator.next_inst(), je_exit);
                mutated_instructions += 1;

                let step = if add_direction {
                    Instruction::with2(Code::Add_rm64_imm32, dst, 1).map_err(anyhow_from_iced)?
                } else {
                    Instruction::with2(Code::Sub_rm64_imm32, dst, 1).map_err(anyhow_from_iced)?
                };
                ir.add_instruction(loop_id, allocator.next_inst(), step);
                mutated_instructions += 1;

                let dec_counter = Instruction::with2(Code::Sub_rm64_imm32, counter, 1)
                    .map_err(anyhow_from_iced)?;
                ir.add_instruction(loop_id, allocator.next_inst(), dec_counter);
                mutated_instructions += 1;

                let jmp_back =
                    Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + loop_start)
                        .map_err(anyhow_from_iced)?;
                ir.add_instruction(loop_id, allocator.next_inst(), jmp_back);
                mutated_instructions += 1;

                ir.block_mut(loop_id).terminator = Terminator::ConditionalBranch {
                    target: exit_start,
                    fallthrough: loop_start,
                };
                ir.block_mut(loop_id).outgoing_edges.clear();
                ir.add_edge(
                    loop_id,
                    Some(exit_id),
                    Some(exit_start),
                    EdgeKind::Branch,
                    false,
                );
                ir.add_edge(
                    loop_id,
                    Some(loop_id),
                    Some(loop_start),
                    EdgeKind::Branch,
                    false,
                );

                if add_direction {
                    let rewind = Instruction::with2(Code::Sub_rm64_imm32, dst, amount as i32)
                        .map_err(anyhow_from_iced)?;
                    ir.add_instruction(exit_id, allocator.next_inst(), rewind);
                    mutated_instructions += 1;
                    let replay = Instruction::with2(Code::Add_rm64_imm32, dst, amount as i32)
                        .map_err(anyhow_from_iced)?;
                    ir.add_instruction(exit_id, allocator.next_inst(), replay);
                    mutated_instructions += 1;
                } else {
                    let rewind = Instruction::with2(Code::Add_rm64_imm32, dst, amount as i32)
                        .map_err(anyhow_from_iced)?;
                    ir.add_instruction(exit_id, allocator.next_inst(), rewind);
                    mutated_instructions += 1;
                    let replay = Instruction::with2(Code::Sub_rm64_imm32, dst, amount as i32)
                        .map_err(anyhow_from_iced)?;
                    ir.add_instruction(exit_id, allocator.next_inst(), replay);
                    mutated_instructions += 1;
                }

                let pop_counter =
                    Instruction::with1(Code::Pop_r64, counter).map_err(anyhow_from_iced)?;
                ir.add_instruction(exit_id, allocator.next_inst(), pop_counter);
                mutated_instructions += 1;

                ir.block_mut(exit_id).outgoing_edges.clear();
                match block.terminator {
                    Terminator::UnconditionalBranch { target } => {
                        let jmp_target =
                            Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + target)
                                .map_err(anyhow_from_iced)?;
                        ir.add_instruction(exit_id, allocator.next_inst(), jmp_target);
                        mutated_instructions += 1;
                        ir.block_mut(exit_id).terminator =
                            Terminator::UnconditionalBranch { target };
                        let to = find_block_by_start_rva(ir, target);
                        ir.add_edge(exit_id, to, Some(target), EdgeKind::Branch, false);
                    }
                    Terminator::Return => {
                        let ret = Instruction::with(Code::Retnq);
                        ir.add_instruction(exit_id, allocator.next_inst(), ret);
                        mutated_instructions += 1;
                        ir.block_mut(exit_id).terminator = Terminator::Return;
                    }
                    _ => {
                        ir.block_mut(exit_id).terminator = Terminator::Unknown;
                        skipped_sites += 1;
                    }
                }

                mutated_blocks.insert(block_id);
                mutated_blocks.insert(loop_id);
                mutated_blocks.insert(exit_id);
                mutated_functions.insert(function_id);
                injected_blocks += 2;
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ObscureReferencesPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for ObscureReferencesPass {
    fn name(&self) -> &'static str {
        "obscure-references"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut thunk_cache = HashMap::<(FunctionId, u64, ThunkFlowKind), ThunkBuildResult>::new();
        let known_targets = collect_known_reference_rvas(ir);

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let inst_ids = ir.block(block_id).insts.clone();
                for (inst_idx, inst_id) in inst_ids.iter().enumerate() {
                    let inst = ir.inst(*inst_id).instruction;

                    if instruction_points_to_known_memory_target(
                        inst,
                        ir.image_base,
                        &known_targets,
                    ) {
                        skipped_sites += 1;
                    }

                    let thunk_kind = if inst.is_call_near() {
                        Some(ThunkFlowKind::Call)
                    } else if inst.is_jmp_short_or_near() {
                        Some(ThunkFlowKind::Branch)
                    } else {
                        None
                    };
                    let Some(thunk_kind) = thunk_kind else {
                        continue;
                    };

                    if !should_inject(self.seed, block_start, inst_idx as u64, self.aggressive, 2) {
                        continue;
                    }

                    let target_va = inst.near_branch_target();
                    if target_va < ir.image_base {
                        skipped_sites += 1;
                        continue;
                    }
                    let target_rva = target_va - ir.image_base;
                    if !known_targets.contains(&target_rva) {
                        skipped_sites += 1;
                        continue;
                    }

                    let thunk = ensure_indirect_thunk(
                        ir,
                        &mut allocator,
                        function_id,
                        target_rva,
                        thunk_kind,
                        self.seed,
                        &mut thunk_cache,
                    )?;
                    if !mutated_blocks.contains(&thunk.block_id) {
                        injected_blocks += 1;
                    }
                    mutated_blocks.insert(thunk.block_id);

                    let rewritten =
                        Instruction::with_branch(inst.code(), ir.image_base + thunk.start_rva)
                            .map_err(anyhow_from_iced)?;
                    ir.insts[inst_id.0].instruction = rewritten;
                    mutated_instructions += 1;
                    mutated_blocks.insert(block_id);
                    mutated_functions.insert(function_id);

                    if inst_idx + 1 == inst_ids.len() {
                        let term = ir.block(block_id).terminator.clone();
                        match term {
                            Terminator::DirectCall { target } if target == target_rva => {
                                ir.block_mut(block_id).terminator = Terminator::DirectCall {
                                    target: thunk.start_rva,
                                };
                                retarget_block_edges_to_thunk(
                                    ir,
                                    block_id,
                                    target,
                                    thunk,
                                    EdgeKind::Call,
                                );
                            }
                            Terminator::UnconditionalBranch { target } if target == target_rva => {
                                ir.block_mut(block_id).terminator =
                                    Terminator::UnconditionalBranch {
                                        target: thunk.start_rva,
                                    };
                                retarget_block_edges_to_thunk(
                                    ir,
                                    block_id,
                                    target,
                                    thunk,
                                    EdgeKind::Branch,
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct IndirectControlFlowPass {
    seed: u64,
    probability: f64,
}

impl Pass for IndirectControlFlowPass {
    fn name(&self) -> &'static str {
        "indirect-control-flow"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        if self.probability <= 0.0 || !self.probability.is_finite() {
            record_pass_outcome(ir, self.name(), 0, 0, 0, 0, 0);
            return Ok(());
        }

        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut thunk_cache = HashMap::<(FunctionId, u64, ThunkFlowKind), ThunkBuildResult>::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();
            for (block_index, block_id) in block_ids.iter().enumerate() {
                let block_id = *block_id;
                let block = ir.block(block_id).clone();
                let (old_target, conditional) = match block.terminator {
                    Terminator::UnconditionalBranch { target } => (target, false),
                    Terminator::ConditionalBranch { target, .. } => (target, true),
                    _ => continue,
                };
                if block.insts.is_empty() {
                    continue;
                }
                if !should_inject_with_probability(
                    self.seed,
                    block.start_rva,
                    block_index as u64,
                    self.probability,
                ) {
                    continue;
                }

                let last_id = *block.insts.last().expect("non-empty");
                let last_inst = ir.inst(last_id).instruction;
                if conditional && !last_inst.is_jcc_short_or_near() {
                    skipped_sites += 1;
                    continue;
                }
                if !conditional && !last_inst.is_jmp_short_or_near() {
                    skipped_sites += 1;
                    continue;
                }

                let thunk = ensure_indirect_thunk(
                    ir,
                    &mut allocator,
                    function_id,
                    old_target,
                    ThunkFlowKind::Branch,
                    self.seed,
                    &mut thunk_cache,
                )?;
                if !mutated_blocks.contains(&thunk.block_id) {
                    injected_blocks += 1;
                }
                mutated_blocks.insert(thunk.block_id);

                let rewritten =
                    Instruction::with_branch(last_inst.code(), ir.image_base + thunk.start_rva)
                        .map_err(anyhow_from_iced)?;
                ir.insts[last_id.0].instruction = rewritten;
                mutated_instructions += 1;
                mutated_blocks.insert(block_id);
                mutated_functions.insert(function_id);

                match ir.block(block_id).terminator.clone() {
                    Terminator::UnconditionalBranch { .. } => {
                        ir.block_mut(block_id).terminator = Terminator::UnconditionalBranch {
                            target: thunk.start_rva,
                        };
                        retarget_block_edges_to_thunk(
                            ir,
                            block_id,
                            old_target,
                            thunk,
                            EdgeKind::Branch,
                        );
                    }
                    Terminator::ConditionalBranch { fallthrough, .. } => {
                        ir.block_mut(block_id).terminator = Terminator::ConditionalBranch {
                            target: thunk.start_rva,
                            fallthrough,
                        };
                        retarget_block_edges_to_thunk(
                            ir,
                            block_id,
                            old_target,
                            thunk,
                            EdgeKind::Branch,
                        );
                    }
                    _ => {}
                }
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct IdaDecompilerCrasherPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for IdaDecompilerCrasherPass {
    fn name(&self) -> &'static str {
        "ida-decompiler-crasher"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for (block_index, block_id) in block_ids.iter().enumerate() {
                let block_id = *block_id;
                let block = ir.block(block_id).clone();
                if block.insts.is_empty() {
                    continue;
                }
                if !matches!(
                    block.terminator,
                    Terminator::UnconditionalBranch { .. } | Terminator::Return
                ) {
                    continue;
                }
                if !should_inject(
                    self.seed,
                    block.start_rva,
                    block_index as u64,
                    self.aggressive,
                    3,
                ) {
                    continue;
                }

                let last_inst = ir.inst(*block.insts.last().expect("non-empty")).instruction;
                let Some(tmp) = choose_one_scratch_reg(&last_inst, &mut info_factory, &[]) else {
                    skipped_sites += 1;
                    continue;
                };

                let detour_start = allocator.next_block();
                let detour_id = ir.add_block(function_id, detour_start, detour_start + 1);
                injected_blocks += 1;
                mutated_blocks.insert(detour_id);

                let push_tmp = Instruction::with1(Code::Push_r64, tmp).map_err(anyhow_from_iced)?;
                ir.add_instruction(detour_id, allocator.next_inst(), push_tmp);
                mutated_instructions += 1;
                let pop_tmp = Instruction::with1(Code::Pop_r64, tmp).map_err(anyhow_from_iced)?;
                ir.add_instruction(detour_id, allocator.next_inst(), pop_tmp);
                mutated_instructions += 1;

                match block.terminator {
                    Terminator::UnconditionalBranch { target } => {
                        let jmp =
                            Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + target)
                                .map_err(anyhow_from_iced)?;
                        ir.add_instruction(detour_id, allocator.next_inst(), jmp);
                        mutated_instructions += 1;
                        ir.block_mut(detour_id).terminator =
                            Terminator::UnconditionalBranch { target };
                        let to = find_block_by_start_rva(ir, target);
                        ir.add_edge(detour_id, to, Some(target), EdgeKind::Branch, false);
                    }
                    Terminator::Return => {
                        let ret = Instruction::with(Code::Retnq);
                        ir.add_instruction(detour_id, allocator.next_inst(), ret);
                        mutated_instructions += 1;
                        ir.block_mut(detour_id).terminator = Terminator::Return;
                    }
                    _ => {
                        ir.block_mut(detour_id).terminator = Terminator::Unknown;
                    }
                }

                let mut rebuilt = Vec::with_capacity(block.insts.len() + 16);
                for id in &block.insts[..block.insts.len() - 1] {
                    rebuilt.push(*id);
                }

                let push_rcx =
                    Instruction::with1(Code::Push_r64, Register::RCX).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), push_rcx));
                mutated_instructions += 1;
                let push_rdi =
                    Instruction::with1(Code::Push_r64, Register::RDI).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), push_rdi));
                mutated_instructions += 1;
                let push_rax =
                    Instruction::with1(Code::Push_r64, Register::RAX).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), push_rax));
                mutated_instructions += 1;

                let xor_eax = Instruction::with2(Code::Xor_rm64_r64, Register::RAX, Register::RAX)
                    .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), xor_eax));
                mutated_instructions += 1;

                let mov_rcx = Instruction::with2(Code::Mov_r64_imm64, Register::RCX, 0u64)
                    .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), mov_rcx));
                mutated_instructions += 1;

                let lea_rdi_rsp = Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RDI,
                    MemoryOperand::with_base(Register::RSP),
                )
                .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), lea_rdi_rsp));
                mutated_instructions += 1;

                let repne_scasb = Instruction::with_repne_scasb(64).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), repne_scasb));
                mutated_instructions += 1;

                let pop_rax =
                    Instruction::with1(Code::Pop_r64, Register::RAX).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), pop_rax));
                mutated_instructions += 1;
                let pop_rdi =
                    Instruction::with1(Code::Pop_r64, Register::RDI).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), pop_rdi));
                mutated_instructions += 1;
                let pop_rcx =
                    Instruction::with1(Code::Pop_r64, Register::RCX).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), pop_rcx));
                mutated_instructions += 1;

                let cmp_tmp =
                    Instruction::with2(Code::Cmp_rm64_r64, tmp, tmp).map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), cmp_tmp));
                mutated_instructions += 1;

                let jne_detour =
                    Instruction::with_branch(Code::Jne_rel32_64, ir.image_base + detour_start)
                        .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), jne_detour));
                mutated_instructions += 1;

                rebuilt.push(*block.insts.last().expect("non-empty"));
                ir.block_mut(block_id).insts = rebuilt;
                ir.add_edge(
                    block_id,
                    Some(detour_id),
                    Some(detour_start),
                    EdgeKind::Branch,
                    false,
                );

                mutated_blocks.insert(block_id);
                mutated_functions.insert(function_id);
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pass: OpaqueConstantSynthesisPass
// Replaces immediate constants with runtime-computed equivalents to hide
// semantic meaning of magic numbers (loop counts, ASCII bases, etc.)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct OpaqueConstantSynthesisPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for OpaqueConstantSynthesisPass {
    fn name(&self) -> &'static str {
        "opaque-constant-synthesis"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let original_ids = ir.block(block_id).insts.clone();
                if original_ids.len() < 2 {
                    continue;
                }

                let mut rebuilt = Vec::with_capacity(original_ids.len() * 2);
                for (inst_index, inst_id) in original_ids.iter().enumerate() {
                    let inst = ir.inst(*inst_id).instruction;

                    if inst_index + 1 < original_ids.len()
                        && should_inject(
                            self.seed,
                            block_start,
                            inst_index as u64,
                            self.aggressive,
                            2,
                        )
                    {
                        if let Some((dst_reg, imm_val, mnemonic)) =
                            extract_constant_synthesis_target(inst)
                        {
                            let xor_key =
                                derive_xor_key_i32(self.seed, block_start, inst_index as u64);
                            let sext_key = xor_key as i64 as u64;

                            match mnemonic {
                                Mnemonic::Mov => {
                                    // mov reg, imm -> mov reg, (imm^sext_key); xor reg, key
                                    let encoded = (imm_val as u64) ^ sext_key;
                                    if self.aggressive {
                                        let rot =
                                            ((mix_seed(self.seed, block_start ^ inst_index as u64)
                                                >> 5)
                                                & 0xF) as u32
                                                | 1;
                                        let pre_rot = encoded.rotate_left(rot);
                                        let mov_enc = Instruction::with2(
                                            Code::Mov_r64_imm64,
                                            dst_reg,
                                            pre_rot,
                                        )
                                        .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            mov_enc,
                                        ));
                                        let ror_inst = Instruction::with2(
                                            Code::Ror_rm64_imm8,
                                            dst_reg,
                                            rot,
                                        )
                                        .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            ror_inst,
                                        ));
                                        mutated_instructions += 1;
                                    } else {
                                        let mov_enc = Instruction::with2(
                                            Code::Mov_r64_imm64,
                                            dst_reg,
                                            encoded,
                                        )
                                        .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            mov_enc,
                                        ));
                                    }
                                    let xor_dec = Instruction::with2(
                                        Code::Xor_rm64_imm32,
                                        dst_reg,
                                        xor_key,
                                    )
                                    .map_err(anyhow_from_iced)?;
                                    rebuilt.push(ir.add_instruction(
                                        block_id,
                                        allocator.next_inst(),
                                        xor_dec,
                                    ));
                                    mutated_instructions += 2;
                                    mutated_blocks.insert(block_id);
                                    mutated_functions.insert(function_id);
                                    continue; // skip adding original inst
                                }
                                Mnemonic::Cmp | Mnemonic::Add | Mnemonic::Sub => {
                                    // Need scratch register for non-mov ops
                                    if let Some(tmp) = choose_one_scratch_reg(
                                        &inst,
                                        &mut info_factory,
                                        &[dst_reg],
                                    ) {
                                        let encoded = (imm_val as u64) ^ sext_key;
                                        let push_tmp = Instruction::with1(Code::Push_r64, tmp)
                                            .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            push_tmp,
                                        ));
                                        let mov_enc = Instruction::with2(
                                            Code::Mov_r64_imm64,
                                            tmp,
                                            encoded,
                                        )
                                        .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            mov_enc,
                                        ));
                                        let xor_dec = Instruction::with2(
                                            Code::Xor_rm64_imm32,
                                            tmp,
                                            xor_key,
                                        )
                                        .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            xor_dec,
                                        ));
                                        // Emit the original operation but with register operand
                                        let code = match mnemonic {
                                            Mnemonic::Cmp => Code::Cmp_rm64_r64,
                                            Mnemonic::Add => Code::Add_rm64_r64,
                                            Mnemonic::Sub => Code::Sub_rm64_r64,
                                            _ => unreachable!(),
                                        };
                                        let op_inst =
                                            Instruction::with2(code, dst_reg, tmp)
                                                .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            op_inst,
                                        ));
                                        // pop does NOT modify flags -> safe after cmp/add/sub
                                        let pop_tmp = Instruction::with1(Code::Pop_r64, tmp)
                                            .map_err(anyhow_from_iced)?;
                                        rebuilt.push(ir.add_instruction(
                                            block_id,
                                            allocator.next_inst(),
                                            pop_tmp,
                                        ));
                                        mutated_instructions += 5;
                                        mutated_blocks.insert(block_id);
                                        mutated_functions.insert(function_id);
                                        continue; // skip adding original inst
                                    } else {
                                        skipped_sites += 1;
                                    }
                                }
                                _ => {
                                    skipped_sites += 1;
                                }
                            }
                        }
                    }

                    rebuilt.push(*inst_id);
                }

                if rebuilt != original_ids {
                    ir.block_mut(block_id).insts = rebuilt;
                }
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pass: DeadStoreInjectionPass
// Injects meaningless computations to create phantom variables in decompiler
// output, polluting the pseudocode with irrelevant expressions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct DeadStoreInjectionPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for DeadStoreInjectionPass {
    fn name(&self) -> &'static str {
        "dead-store-injection"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let original_ids = ir.block(block_id).insts.clone();
                if original_ids.len() < 2 {
                    continue;
                }

                let mut rebuilt = Vec::with_capacity(original_ids.len() * 2);
                for (inst_index, inst_id) in original_ids.iter().enumerate() {
                    rebuilt.push(*inst_id);

                    // Inject dead stores AFTER certain instructions (not the last one)
                    if inst_index + 1 >= original_ids.len() {
                        continue;
                    }
                    if !should_inject(
                        self.seed,
                        block_start,
                        inst_index as u64,
                        self.aggressive,
                        3,
                    ) {
                        continue;
                    }

                    let inst = ir.inst(*inst_id).instruction;
                    let Some((tmp1, tmp2)) =
                        choose_two_scratch_regs(inst, &mut info_factory, &[])
                    else {
                        skipped_sites += 1;
                        continue;
                    };

                    let site_seed = mix_seed(self.seed, block_start ^ inst_index as u64);
                    let template = (site_seed >> 3) % 3;
                    let c1 = ((site_seed >> 7) as u32 | 1) as i32;
                    let c2 = ((site_seed >> 19) as u32 | 1) as i32;
                    let c3 = ((site_seed >> 31) as u32 | 1) as i32;

                    // Save registers and flags
                    let push_t1 = Instruction::with1(Code::Push_r64, tmp1)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(
                        block_id,
                        allocator.next_inst(),
                        push_t1,
                    ));
                    let push_t2 = Instruction::with1(Code::Push_r64, tmp2)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(
                        block_id,
                        allocator.next_inst(),
                        push_t2,
                    ));
                    let pushfq = Instruction::with(Code::Pushfq);
                    rebuilt.push(ir.add_instruction(
                        block_id,
                        allocator.next_inst(),
                        pushfq,
                    ));

                    // Dead computation (varies by template)
                    match template {
                        0 => {
                            // Template 0: imul + xor + ror
                            let mov_c = Instruction::with2(Code::Mov_r64_imm64, tmp1, c1 as i64 as u64)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), mov_c));
                            let imul_inst = Instruction::with3(Code::Imul_r64_rm64_imm32, tmp1, tmp1, c2)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), imul_inst));
                            let xor_inst = Instruction::with2(Code::Xor_rm64_imm32, tmp1, c3)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), xor_inst));
                            let mov_t2 = Instruction::with2(Code::Mov_rm64_r64, tmp2, tmp1)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), mov_t2));
                            let ror_inst = Instruction::with2(Code::Ror_rm64_imm8, tmp2, 7u32)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), ror_inst));
                            let add_inst = Instruction::with2(Code::Add_rm64_r64, tmp1, tmp2)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), add_inst));
                            mutated_instructions += 6;
                        }
                        1 => {
                            // Template 1: mov + and + or + not pattern
                            let mov_c = Instruction::with2(Code::Mov_r64_imm64, tmp1, c1 as i64 as u64)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), mov_c));
                            let mov_c2 = Instruction::with2(Code::Mov_r64_imm64, tmp2, c2 as i64 as u64)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), mov_c2));
                            let and_inst = Instruction::with2(Code::And_rm64_r64, tmp1, tmp2)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), and_inst));
                            let or_inst = Instruction::with2(Code::Or_rm64_r64, tmp2, tmp1)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), or_inst));
                            let sub_inst = Instruction::with2(Code::Sub_rm64_r64, tmp1, tmp2)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), sub_inst));
                            mutated_instructions += 5;
                        }
                        _ => {
                            // Template 2: shift + xor chain
                            let mov_c = Instruction::with2(Code::Mov_r64_imm64, tmp1, c1 as i64 as u64)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), mov_c));
                            let shl_inst = Instruction::with2(Code::Shl_rm64_imm8, tmp1, 13u32)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), shl_inst));
                            let xor_inst = Instruction::with2(Code::Xor_rm64_imm32, tmp1, c2)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), xor_inst));
                            let shr_inst = Instruction::with2(Code::Shr_rm64_imm8, tmp1, 7u32)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), shr_inst));
                            let xor2 = Instruction::with2(Code::Xor_rm64_imm32, tmp1, c3)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), xor2));
                            mutated_instructions += 5;
                        }
                    }

                    // Restore flags with TF cleared
                    let pop_flags = Instruction::with1(Code::Pop_r64, tmp2)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), pop_flags));
                    let and_tf = Instruction::with2(Code::And_rm64_imm32, tmp2, !0x100i32)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), and_tf));
                    let push_flags = Instruction::with1(Code::Push_r64, tmp2)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), push_flags));
                    let popfq = Instruction::with(Code::Popfq);
                    rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), popfq));
                    let pop_t2 = Instruction::with1(Code::Pop_r64, tmp2)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), pop_t2));
                    let pop_t1 = Instruction::with1(Code::Pop_r64, tmp1)
                        .map_err(anyhow_from_iced)?;
                    rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), pop_t1));
                    mutated_instructions += 6;

                    mutated_blocks.insert(block_id);
                    mutated_functions.insert(function_id);
                }

                if rebuilt != original_ids {
                    ir.block_mut(block_id).insts = rebuilt;
                }
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pass: PushRetBranchPass
// Replaces jmp target with push+mov+lea+xchg+ret to confuse IDA's call
// graph analysis and function boundary detection.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct PushRetBranchPass {
    seed: u64,
    probability: f64,
}

impl Pass for PushRetBranchPass {
    fn name(&self) -> &'static str {
        "push-ret-branch"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for (block_index, block_id) in block_ids.iter().enumerate() {
                let block_id = *block_id;
                let block = ir.block(block_id).clone();
                if block.insts.is_empty() {
                    continue;
                }

                let target_rva = match block.terminator {
                    Terminator::UnconditionalBranch { target } => target,
                    _ => continue,
                };

                let last_id = *block.insts.last().expect("non-empty");
                let last_inst = ir.inst(last_id).instruction;
                if !last_inst.is_jmp_short_or_near() {
                    skipped_sites += 1;
                    continue;
                }

                if !should_inject_with_probability(
                    self.seed,
                    block.start_rva,
                    block_index as u64,
                    self.probability,
                ) {
                    continue;
                }

                let decode_key =
                    derive_thunk_decode_key(self.seed, target_rva, ThunkFlowKind::Branch);

                // Build inline push-ret sequence replacing the jmp
                let mut rebuilt = Vec::with_capacity(block.insts.len() + 5);
                for id in &block.insts[..block.insts.len() - 1] {
                    rebuilt.push(*id);
                }

                // push rax
                let push_rax = Instruction::with1(Code::Push_r64, Register::RAX)
                    .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), push_rax));

                // mov rax, 0  (placeholder, patched by rewriter to target_va - decode_key)
                let load_entry_rva = allocator.next_inst();
                let mov_placeholder =
                    Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 0u64)
                        .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, load_entry_rva, mov_placeholder));

                // lea rax, [rax + decode_key]
                let lea_decode = Instruction::with2(
                    Code::Lea_r64_m,
                    Register::RAX,
                    MemoryOperand::with_base_displ(Register::RAX, decode_key as i64),
                )
                .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), lea_decode));

                // xchg [rsp], rax
                let xchg = Instruction::with2(
                    Code::Xchg_rm64_r64,
                    MemoryOperand::with_base(Register::RSP),
                    Register::RAX,
                )
                .map_err(anyhow_from_iced)?;
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), xchg));

                // ret
                let ret = Instruction::with(Code::Retnq);
                rebuilt.push(ir.add_instruction(block_id, allocator.next_inst(), ret));

                ir.block_mut(block_id).insts = rebuilt;

                // Record thunk for rewriter to patch the mov placeholder
                ir.add_indirect_thunk_record(
                    function_id,
                    block_id,
                    IndirectThunkKind::Branch,
                    target_rva,
                    load_entry_rva,
                    decode_key,
                );

                mutated_instructions += 5;
                mutated_blocks.insert(block_id);
                mutated_functions.insert(function_id);
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pass: StringReferenceObfuscationPass
// Breaks IDA cross-references to strings by replacing RIP-relative LEA
// instructions (pointing to data) with mov+lea decode sequences.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct StringReferenceObfuscationPass {
    seed: u64,
    aggressive: bool,
}

impl Pass for StringReferenceObfuscationPass {
    fn name(&self) -> &'static str {
        "string-reference-obfuscation"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);

        // Collect code addresses so we only obfuscate data references
        let code_rvas = collect_code_rvas(ir);

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let original_ids = ir.block(block_id).insts.clone();
                if original_ids.is_empty() {
                    continue;
                }

                let mut rebuilt = Vec::with_capacity(original_ids.len() * 2);
                let mut block_changed = false;

                for (inst_index, inst_id) in original_ids.iter().enumerate() {
                    let inst = ir.inst(*inst_id).instruction;

                    // Check: is this a LEA with RIP-relative memory operand?
                    if inst.mnemonic() == Mnemonic::Lea
                        && inst.is_ip_rel_memory_operand()
                        && inst.op_count() >= 2
                        && inst.op_kind(0) == OpKind::Register
                        && is_gpr64(inst.op_register(0))
                        && should_inject(
                            self.seed,
                            block_start,
                            inst_index as u64,
                            self.aggressive,
                            2,
                        )
                    {
                        let target_va = inst.ip_rel_memory_address();
                        if target_va < ir.image_base {
                            rebuilt.push(*inst_id);
                            skipped_sites += 1;
                            continue;
                        }
                        let target_rva = target_va - ir.image_base;

                        // Only obfuscate data references, skip code references
                        if code_rvas.contains(&target_rva) {
                            rebuilt.push(*inst_id);
                            skipped_sites += 1;
                            continue;
                        }

                        let dst_reg = inst.op_register(0);
                        let decode_key = derive_thunk_decode_key(
                            self.seed,
                            target_rva,
                            ThunkFlowKind::Branch,
                        );

                        // mov dst_reg, 0  (placeholder, patched to target_va - decode_key)
                        let load_entry_rva = allocator.next_inst();
                        let mov_placeholder = Instruction::with2(
                            Code::Mov_r64_imm64,
                            dst_reg,
                            0u64,
                        )
                        .map_err(anyhow_from_iced)?;
                        rebuilt.push(ir.add_instruction(
                            block_id,
                            load_entry_rva,
                            mov_placeholder,
                        ));

                        // lea dst_reg, [dst_reg + decode_key]
                        let lea_decode = Instruction::with2(
                            Code::Lea_r64_m,
                            dst_reg,
                            MemoryOperand::with_base_displ(dst_reg, decode_key as i64),
                        )
                        .map_err(anyhow_from_iced)?;
                        rebuilt.push(ir.add_instruction(
                            block_id,
                            allocator.next_inst(),
                            lea_decode,
                        ));

                        // Record for rewriter patching + relocation
                        ir.add_indirect_thunk_record(
                            function_id,
                            block_id,
                            IndirectThunkKind::Branch,
                            target_rva,
                            load_entry_rva,
                            decode_key,
                        );

                        mutated_instructions += 2;
                        block_changed = true;
                        continue; // skip original instruction
                    }

                    rebuilt.push(*inst_id);
                }

                if block_changed {
                    ir.block_mut(block_id).insts = rebuilt;
                    mutated_blocks.insert(block_id);
                    mutated_functions.insert(function_id);
                }
            }
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pass: ControlFlowFlatteningPass
// Transforms structured control flow (loops, if/else) into a dispatcher-based
// state machine. This is the most effective anti-decompilation technique.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct ControlFlowFlatteningPass {
    seed: u64,
}

impl Pass for ControlFlowFlatteningPass {
    fn name(&self) -> &'static str {
        "control-flow-flattening"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut allocator = SyntheticRvaAllocator::new(ir);
        let mut info_factory = InstructionInfoFactory::new();

        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut injected_blocks = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();

            if block_ids.len() < 3 {
                skipped_sites += 1;
                continue;
            }

            // Find unused callee-saved register for state variable
            let Some(state_reg) =
                find_cff_state_register(ir, &block_ids, &mut info_factory)
            else {
                skipped_sites += 1;
                continue;
            };

            // Assign state IDs to each block
            let mut block_state_map = HashMap::<BlockId, u32>::new();
            let mut rva_state_map = HashMap::<u64, u32>::new();
            for &bid in &block_ids {
                let start_rva = ir.block(bid).start_rva;
                let state = (mix_seed(self.seed, start_rva) as u32) | 0x100;
                block_state_map.insert(bid, state);
                rva_state_map.insert(start_rva, state);
            }

            let entry_block = block_ids[0];
            let entry_state = block_state_map[&entry_block];

            // Create dispatcher block
            let dispatcher_start = allocator.next_block();
            let dispatcher_id = ir.add_block(function_id, dispatcher_start, dispatcher_start + 1);
            injected_blocks += 1;

            // Build dispatcher: cmp/je chain for each block
            let mut state_targets = Vec::with_capacity(block_ids.len());
            for &bid in &block_ids {
                let state = block_state_map[&bid];
                let target_rva = ir.block(bid).start_rva;

                let cmp_state = Instruction::with2(Code::Cmp_rm64_imm32, state_reg, state as i32)
                    .map_err(anyhow_from_iced)?;
                ir.add_instruction(dispatcher_id, allocator.next_inst(), cmp_state);
                mutated_instructions += 1;

                let je_block =
                    Instruction::with_branch(Code::Je_rel32_64, ir.image_base + target_rva)
                        .map_err(anyhow_from_iced)?;
                ir.add_instruction(dispatcher_id, allocator.next_inst(), je_block);
                mutated_instructions += 1;

                ir.add_edge(
                    dispatcher_id,
                    Some(bid),
                    Some(target_rva),
                    EdgeKind::Branch,
                    false,
                );

                state_targets.push((state, target_rva));
            }

            // Default: jump to entry block (safety)
            let jmp_default =
                Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + ir.block(entry_block).start_rva)
                    .map_err(anyhow_from_iced)?;
            ir.add_instruction(dispatcher_id, allocator.next_inst(), jmp_default);
            mutated_instructions += 1;

            ir.block_mut(dispatcher_id).terminator = Terminator::Dispatcher {
                state_targets,
                default_target: ir.block(entry_block).start_rva,
            };
            mutated_blocks.insert(dispatcher_id);

            // Create entry wrapper: push state_reg, mov state_reg, init_state, jmp dispatcher
            let wrapper_start = allocator.next_block();
            let wrapper_id = ir.add_block(function_id, wrapper_start, wrapper_start + 1);
            injected_blocks += 1;

            let push_state = Instruction::with1(Code::Push_r64, state_reg)
                .map_err(anyhow_from_iced)?;
            ir.add_instruction(wrapper_id, allocator.next_inst(), push_state);
            mutated_instructions += 1;

            let mov_init = Instruction::with2(
                Code::Mov_r64_imm64,
                state_reg,
                entry_state as u64,
            )
            .map_err(anyhow_from_iced)?;
            ir.add_instruction(wrapper_id, allocator.next_inst(), mov_init);
            mutated_instructions += 1;

            let jmp_disp =
                Instruction::with_branch(Code::Jmp_rel32_64, ir.image_base + dispatcher_start)
                    .map_err(anyhow_from_iced)?;
            ir.add_instruction(wrapper_id, allocator.next_inst(), jmp_disp);
            mutated_instructions += 1;

            ir.block_mut(wrapper_id).terminator =
                Terminator::UnconditionalBranch { target: dispatcher_start };
            ir.add_edge(
                wrapper_id,
                Some(dispatcher_id),
                Some(dispatcher_start),
                EdgeKind::Branch,
                false,
            );
            mutated_blocks.insert(wrapper_id);

            // Set the wrapper as the function's entry point
            // Move wrapper to front of blocks list
            let func_blocks = &mut ir.functions[fidx].blocks;
            // Only if wrapper is in the list (it was added by add_block)
            if let Some(pos) = func_blocks.iter().position(|&b| b == wrapper_id) {
                func_blocks.remove(pos);
                func_blocks.insert(0, wrapper_id);
            }
            // Also ensure dispatcher is second
            if let Some(pos) = func_blocks.iter().position(|&b| b == dispatcher_id) {
                func_blocks.remove(pos);
                func_blocks.insert(1, dispatcher_id);
            }

            // Rewrite each original block's terminator to use state machine
            for &bid in &block_ids {
                let block = ir.block(bid).clone();
                let term = block.terminator.clone();

                match term {
                    Terminator::UnconditionalBranch { target } => {
                        if let Some(&next_state) = rva_state_map.get(&target) {
                            // Replace last jmp with: mov state_reg, next_state; jmp dispatcher
                            let mut rebuilt = Vec::with_capacity(block.insts.len() + 2);
                            // Keep all insts except the last jmp
                            if !block.insts.is_empty() {
                                let last_inst = ir.inst(*block.insts.last().unwrap()).instruction;
                                if last_inst.is_jmp_short_or_near() {
                                    for id in &block.insts[..block.insts.len() - 1] {
                                        rebuilt.push(*id);
                                    }
                                } else {
                                    for id in &block.insts {
                                        rebuilt.push(*id);
                                    }
                                }
                            }

                            let mov_state = Instruction::with2(
                                Code::Mov_r64_imm64,
                                state_reg,
                                next_state as u64,
                            )
                            .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), mov_state));
                            mutated_instructions += 1;

                            let jmp = Instruction::with_branch(
                                Code::Jmp_rel32_64,
                                ir.image_base + dispatcher_start,
                            )
                            .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), jmp));
                            mutated_instructions += 1;

                            ir.block_mut(bid).insts = rebuilt;
                            ir.block_mut(bid).terminator =
                                Terminator::UnconditionalBranch { target: dispatcher_start };
                            mutated_blocks.insert(bid);
                        } else {
                            skipped_sites += 1;
                        }
                    }
                    Terminator::ConditionalBranch { target, fallthrough } => {
                        let taken_state = rva_state_map.get(&target).copied();
                        let fall_state = rva_state_map.get(&fallthrough).copied();

                        if let (Some(taken_state), Some(fall_state)) = (taken_state, fall_state) {
                            // Create trampoline block for taken path
                            let tramp_start = allocator.next_block();
                            let tramp_id =
                                ir.add_block(function_id, tramp_start, tramp_start + 1);
                            injected_blocks += 1;

                            let mov_taken = Instruction::with2(
                                Code::Mov_r64_imm64,
                                state_reg,
                                taken_state as u64,
                            )
                            .map_err(anyhow_from_iced)?;
                            ir.add_instruction(tramp_id, allocator.next_inst(), mov_taken);
                            mutated_instructions += 1;

                            let jmp_disp2 = Instruction::with_branch(
                                Code::Jmp_rel32_64,
                                ir.image_base + dispatcher_start,
                            )
                            .map_err(anyhow_from_iced)?;
                            ir.add_instruction(tramp_id, allocator.next_inst(), jmp_disp2);
                            mutated_instructions += 1;

                            ir.block_mut(tramp_id).terminator =
                                Terminator::UnconditionalBranch { target: dispatcher_start };
                            ir.add_edge(
                                tramp_id,
                                Some(dispatcher_id),
                                Some(dispatcher_start),
                                EdgeKind::Branch,
                                false,
                            );
                            mutated_blocks.insert(tramp_id);

                            // Rewrite block: keep all insts except last jcc, then:
                            // mov state_reg, fall_state (mov doesn't clobber flags)
                            // jcc trampoline
                            // jmp dispatcher
                            let mut rebuilt = Vec::with_capacity(block.insts.len() + 4);
                            let mut jcc_code = Code::INVALID;
                            if !block.insts.is_empty() {
                                let last_inst = ir.inst(*block.insts.last().unwrap()).instruction;
                                if last_inst.is_jcc_short_or_near() {
                                    jcc_code = promote_jcc_to_rel32(last_inst.code());
                                    for id in &block.insts[..block.insts.len() - 1] {
                                        rebuilt.push(*id);
                                    }
                                } else {
                                    for id in &block.insts {
                                        rebuilt.push(*id);
                                    }
                                }
                            }

                            // mov state_reg, fallthrough_state (mov doesn't affect flags!)
                            let mov_fall = Instruction::with2(
                                Code::Mov_r64_imm64,
                                state_reg,
                                fall_state as u64,
                            )
                            .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), mov_fall));
                            mutated_instructions += 1;

                            if jcc_code != Code::INVALID {
                                // jcc to trampoline (taken path)
                                let jcc = Instruction::with_branch(
                                    jcc_code,
                                    ir.image_base + tramp_start,
                                )
                                .map_err(anyhow_from_iced)?;
                                rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), jcc));
                                mutated_instructions += 1;
                            }

                            // jmp dispatcher (fallthrough path)
                            let jmp_fall = Instruction::with_branch(
                                Code::Jmp_rel32_64,
                                ir.image_base + dispatcher_start,
                            )
                            .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), jmp_fall));
                            mutated_instructions += 1;

                            ir.block_mut(bid).insts = rebuilt;
                            ir.block_mut(bid).terminator = Terminator::ConditionalBranch {
                                target: tramp_start,
                                fallthrough: dispatcher_start,
                            };
                            ir.block_mut(bid).outgoing_edges.clear();
                            ir.add_edge(
                                bid,
                                Some(tramp_id),
                                Some(tramp_start),
                                EdgeKind::Branch,
                                false,
                            );
                            ir.add_edge(
                                bid,
                                Some(dispatcher_id),
                                Some(dispatcher_start),
                                EdgeKind::Branch,
                                false,
                            );
                            mutated_blocks.insert(bid);
                        } else {
                            skipped_sites += 1;
                        }
                    }
                    Terminator::Return => {
                        // Insert pop state_reg before ret
                        if !block.insts.is_empty() {
                            let mut rebuilt = Vec::with_capacity(block.insts.len() + 1);
                            for id in &block.insts[..block.insts.len() - 1] {
                                rebuilt.push(*id);
                            }
                            let pop_state = Instruction::with1(Code::Pop_r64, state_reg)
                                .map_err(anyhow_from_iced)?;
                            rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), pop_state));
                            mutated_instructions += 1;
                            rebuilt.push(*block.insts.last().unwrap());
                            ir.block_mut(bid).insts = rebuilt;
                            mutated_blocks.insert(bid);
                        }
                    }
                    Terminator::DirectCall { .. } => {
                        // For DirectCall: keep the call, append state transition
                        // Find the fallthrough target from edges
                        let fallthrough_rva = block.outgoing_edges.iter().find_map(|&eid| {
                            let edge = &ir.edges[eid];
                            if matches!(edge.kind, EdgeKind::Fallthrough | EdgeKind::Branch) {
                                edge.target_rva
                            } else {
                                None
                            }
                        });

                        if let Some(ft_rva) = fallthrough_rva {
                            if let Some(&ft_state) = rva_state_map.get(&ft_rva) {
                                let mut rebuilt = block.insts.clone();
                                let mov_state = Instruction::with2(
                                    Code::Mov_r64_imm64,
                                    state_reg,
                                    ft_state as u64,
                                )
                                .map_err(anyhow_from_iced)?;
                                rebuilt.push(ir.add_instruction(
                                    bid,
                                    allocator.next_inst(),
                                    mov_state,
                                ));
                                mutated_instructions += 1;

                                let jmp = Instruction::with_branch(
                                    Code::Jmp_rel32_64,
                                    ir.image_base + dispatcher_start,
                                )
                                .map_err(anyhow_from_iced)?;
                                rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), jmp));
                                mutated_instructions += 1;

                                ir.block_mut(bid).insts = rebuilt;
                                mutated_blocks.insert(bid);
                            }
                        }
                    }
                    Terminator::Fallthrough => {
                        // Find fallthrough target from edges or next block
                        let ft_rva = block.outgoing_edges.iter().find_map(|&eid| {
                            let edge = &ir.edges[eid];
                            if edge.kind == EdgeKind::Fallthrough {
                                edge.target_rva
                            } else {
                                None
                            }
                        });

                        if let Some(ft_rva) = ft_rva {
                            if let Some(&ft_state) = rva_state_map.get(&ft_rva) {
                                let mut rebuilt = block.insts.clone();
                                let mov_state = Instruction::with2(
                                    Code::Mov_r64_imm64,
                                    state_reg,
                                    ft_state as u64,
                                )
                                .map_err(anyhow_from_iced)?;
                                rebuilt.push(ir.add_instruction(
                                    bid,
                                    allocator.next_inst(),
                                    mov_state,
                                ));
                                mutated_instructions += 1;

                                let jmp = Instruction::with_branch(
                                    Code::Jmp_rel32_64,
                                    ir.image_base + dispatcher_start,
                                )
                                .map_err(anyhow_from_iced)?;
                                rebuilt.push(ir.add_instruction(bid, allocator.next_inst(), jmp));
                                mutated_instructions += 1;

                                ir.block_mut(bid).insts = rebuilt;
                                ir.block_mut(bid).terminator =
                                    Terminator::UnconditionalBranch { target: dispatcher_start };
                                mutated_blocks.insert(bid);
                            }
                        }
                    }
                    _ => {
                        skipped_sites += 1;
                    }
                }
            }

            mutated_functions.insert(function_id);
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            injected_blocks,
            skipped_sites,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers for new passes
// ---------------------------------------------------------------------------

/// Extracts (dst_register, immediate_value, mnemonic) from instructions
/// suitable for constant synthesis obfuscation.
fn extract_constant_synthesis_target(inst: Instruction) -> Option<(Register, i64, Mnemonic)> {
    if inst.op_count() < 2 {
        return None;
    }
    if inst.op_kind(0) != OpKind::Register {
        return None;
    }
    let dst = inst.op_register(0);
    if !is_gpr64(dst) || is_stack_or_base_pointer(dst) {
        return None;
    }
    let mnemonic = inst.mnemonic();
    if !matches!(mnemonic, Mnemonic::Mov | Mnemonic::Cmp | Mnemonic::Add | Mnemonic::Sub) {
        return None;
    }
    let imm = immediate_operand_to_i64(inst, 1)?;
    // Don't obfuscate zero (too many false positives) or very small adjustments
    if imm == 0 {
        return None;
    }
    Some((dst, imm, mnemonic))
}

/// Derives a non-zero i32 XOR key from seed and position.
fn derive_xor_key_i32(seed: u64, scope: u64, idx: u64) -> i32 {
    let mixed = mix_seed(seed ^ 0x7C3E_A1D9_52B8_4F06, scope ^ idx);
    let mut key = (mixed as u32 & 0x7FFF_FFFF) as i32 | 1;
    if key == 1 {
        key = 0x5A3B_4C1F;
    }
    key
}

/// Finds an unused callee-saved register (R15, R14, R13, R12) across all
/// blocks in the given block list. Returns None if all are in use.
fn find_cff_state_register(
    ir: &ProgramIr,
    block_ids: &[BlockId],
    info_factory: &mut InstructionInfoFactory,
) -> Option<Register> {
    let candidates = [Register::R15, Register::R14, Register::R13, Register::R12];
    for &candidate in &candidates {
        let mut in_use = false;
        'outer: for &block_id in block_ids {
            for &inst_id in &ir.block(block_id).insts {
                let inst = ir.inst(inst_id).instruction;
                let regs = used_regs(inst, info_factory, &[]);
                if regs.contains(&candidate) {
                    in_use = true;
                    break 'outer;
                }
            }
        }
        if !in_use {
            return Some(candidate);
        }
    }
    None
}

/// Collects all RVAs that correspond to code (function entries and block starts).
fn collect_code_rvas(ir: &ProgramIr) -> HashSet<u64> {
    let mut rvas = HashSet::new();
    for func in &ir.functions {
        rvas.insert(func.address_rva);
        for &block_id in &func.blocks {
            rvas.insert(ir.block(block_id).start_rva);
        }
    }
    rvas
}

/// Promotes a short/near Jcc code to rel32 form for consistent encoding.
fn promote_jcc_to_rel32(code: Code) -> Code {
    match code {
        Code::Jo_rel8_16 | Code::Jo_rel8_32 | Code::Jo_rel8_64 | Code::Jo_rel32_64 => {
            Code::Jo_rel32_64
        }
        Code::Jno_rel8_16 | Code::Jno_rel8_32 | Code::Jno_rel8_64 | Code::Jno_rel32_64 => {
            Code::Jno_rel32_64
        }
        Code::Jb_rel8_16 | Code::Jb_rel8_32 | Code::Jb_rel8_64 | Code::Jb_rel32_64 => {
            Code::Jb_rel32_64
        }
        Code::Jae_rel8_16 | Code::Jae_rel8_32 | Code::Jae_rel8_64 | Code::Jae_rel32_64 => {
            Code::Jae_rel32_64
        }
        Code::Je_rel8_16 | Code::Je_rel8_32 | Code::Je_rel8_64 | Code::Je_rel32_64 => {
            Code::Je_rel32_64
        }
        Code::Jne_rel8_16 | Code::Jne_rel8_32 | Code::Jne_rel8_64 | Code::Jne_rel32_64 => {
            Code::Jne_rel32_64
        }
        Code::Jbe_rel8_16 | Code::Jbe_rel8_32 | Code::Jbe_rel8_64 | Code::Jbe_rel32_64 => {
            Code::Jbe_rel32_64
        }
        Code::Ja_rel8_16 | Code::Ja_rel8_32 | Code::Ja_rel8_64 | Code::Ja_rel32_64 => {
            Code::Ja_rel32_64
        }
        Code::Js_rel8_16 | Code::Js_rel8_32 | Code::Js_rel8_64 | Code::Js_rel32_64 => {
            Code::Js_rel32_64
        }
        Code::Jns_rel8_16 | Code::Jns_rel8_32 | Code::Jns_rel8_64 | Code::Jns_rel32_64 => {
            Code::Jns_rel32_64
        }
        Code::Jp_rel8_16 | Code::Jp_rel8_32 | Code::Jp_rel8_64 | Code::Jp_rel32_64 => {
            Code::Jp_rel32_64
        }
        Code::Jnp_rel8_16 | Code::Jnp_rel8_32 | Code::Jnp_rel8_64 | Code::Jnp_rel32_64 => {
            Code::Jnp_rel32_64
        }
        Code::Jl_rel8_16 | Code::Jl_rel8_32 | Code::Jl_rel8_64 | Code::Jl_rel32_64 => {
            Code::Jl_rel32_64
        }
        Code::Jge_rel8_16 | Code::Jge_rel8_32 | Code::Jge_rel8_64 | Code::Jge_rel32_64 => {
            Code::Jge_rel32_64
        }
        Code::Jle_rel8_16 | Code::Jle_rel8_32 | Code::Jle_rel8_64 | Code::Jle_rel32_64 => {
            Code::Jle_rel32_64
        }
        Code::Jg_rel8_16 | Code::Jg_rel8_32 | Code::Jg_rel8_64 | Code::Jg_rel32_64 => {
            Code::Jg_rel32_64
        }
        // Fallback: return the original code
        _ => code,
    }
}

fn immediate_operand_to_i64(inst: Instruction, op_index: u32) -> Option<i64> {
    match inst.op_kind(op_index) {
        OpKind::Immediate8 => Some(inst.immediate8() as i8 as i64),
        OpKind::Immediate8to16 => Some(inst.immediate8to16() as i64),
        OpKind::Immediate8to32 => Some(inst.immediate8to32() as i64),
        OpKind::Immediate8to64 => Some(inst.immediate8to64()),
        OpKind::Immediate16 => Some(inst.immediate16() as i16 as i64),
        OpKind::Immediate32 => Some(inst.immediate32() as i32 as i64),
        OpKind::Immediate32to64 => Some(inst.immediate32to64()),
        OpKind::Immediate64 => Some(inst.immediate64() as i64),
        _ => None,
    }
}

fn normalize_add_sub_imm_candidate(
    inst: Instruction,
    min_amount: u32,
    max_iterations: u32,
) -> Option<(Register, u32, bool)> {
    if inst.op_count() < 2 {
        return None;
    }
    if inst.op_kind(0) != OpKind::Register {
        return None;
    }
    let dst = inst.op_register(0);
    if !is_gpr64(dst) {
        return None;
    }
    let imm = immediate_operand_to_i64(inst, 1)?;
    if imm == 0 {
        return None;
    }
    let (amount, add_direction) = match inst.mnemonic() {
        Mnemonic::Add if imm > 0 => (imm as u64, true),
        Mnemonic::Add => ((-imm) as u64, false),
        Mnemonic::Sub if imm > 0 => (imm as u64, false),
        Mnemonic::Sub => ((-imm) as u64, true),
        _ => return None,
    };
    if amount == 0 || amount < min_amount as u64 || amount > max_iterations as u64 {
        return None;
    }
    Some((dst, amount as u32, add_direction))
}

fn derive_loop_counter_mask(seed: u64, block_rva: u64, amount: u32) -> u32 {
    let mut mask = (mix_seed(seed ^ 0x32b7_a4c9_d91e_58f2, block_rva ^ amount as u64) as u32) | 1;
    if mask == amount {
        mask ^= 0x5A5A_5A5A;
    }
    mask
}

fn should_inject_with_probability(seed: u64, scope: u64, idx: u64, probability: f64) -> bool {
    if probability >= 1.0 {
        return true;
    }
    if probability <= 0.0 || !probability.is_finite() {
        return false;
    }
    let mixed = mix_seed(seed, scope ^ idx.wrapping_mul(0x94D0_49BB_1331_11EB));
    let unit = (mixed as f64) / (u64::MAX as f64);
    unit < probability
}

fn collect_known_reference_rvas(ir: &ProgramIr) -> HashSet<u64> {
    let mut known = HashSet::<u64>::new();
    for func in &ir.functions {
        known.insert(func.address_rva);
        for block_id in &func.blocks {
            known.insert(ir.block(*block_id).start_rva);
        }
    }
    for sym in &ir.symbols {
        known.insert(sym.rva);
    }
    for obj in &ir.data_objects {
        known.insert(obj.rva);
    }
    for edge in &ir.edges {
        if let Some(target) = edge.target_rva {
            known.insert(target);
        }
    }
    known
}

fn instruction_points_to_known_memory_target(
    inst: Instruction,
    image_base: u64,
    known_targets: &HashSet<u64>,
) -> bool {
    if !inst.is_ip_rel_memory_operand() {
        return false;
    }
    let target_va = inst.ip_rel_memory_address();
    if target_va < image_base {
        return false;
    }
    known_targets.contains(&(target_va - image_base))
}

fn find_block_by_start_rva(ir: &ProgramIr, target_rva: u64) -> Option<BlockId> {
    ir.blocks
        .iter()
        .find(|b| b.start_rva == target_rva)
        .map(|b| b.id)
}

fn retarget_block_edges_to_thunk(
    ir: &mut ProgramIr,
    from: BlockId,
    old_target_rva: u64,
    thunk: ThunkBuildResult,
    kind: EdgeKind,
) {
    let mut retargeted = false;
    let outgoing = ir.block(from).outgoing_edges.clone();
    for edge_id in outgoing {
        let edge = &mut ir.edges[edge_id];
        if edge.target_rva == Some(old_target_rva) {
            edge.target_rva = Some(thunk.start_rva);
            edge.to = Some(thunk.block_id);
            edge.kind = kind;
            edge.indirect = false;
            retargeted = true;
        }
    }
    if !retargeted {
        ir.add_edge(
            from,
            Some(thunk.block_id),
            Some(thunk.start_rva),
            kind,
            false,
        );
    }
}

fn derive_thunk_decode_key(seed: u64, target_rva: u64, kind: ThunkFlowKind) -> i32 {
    let tag = match kind {
        ThunkFlowKind::Call => 0x5148_0A2D_A21D_C983,
        ThunkFlowKind::Branch => 0x79CE_16B7_3F3A_D2E1,
    };
    let mut key = (mix_seed(seed ^ 0x95d4_7a2b_4e38_1f07, target_rva ^ tag) as u32) as i32;
    if key == 0 {
        key = 0x1357_9BDF;
    }
    key
}

fn ensure_indirect_thunk(
    ir: &mut ProgramIr,
    allocator: &mut SyntheticRvaAllocator,
    function_id: FunctionId,
    target_rva: u64,
    kind: ThunkFlowKind,
    seed: u64,
    cache: &mut HashMap<(FunctionId, u64, ThunkFlowKind), ThunkBuildResult>,
) -> Result<ThunkBuildResult> {
    if let Some(existing) = cache.get(&(function_id, target_rva, kind)).copied() {
        return Ok(existing);
    }

    let thunk_start = allocator.next_block();
    let thunk_id = ir.add_block(function_id, thunk_start, thunk_start + 1);

    let push_rax = Instruction::with1(Code::Push_r64, Register::RAX).map_err(anyhow_from_iced)?;
    ir.add_instruction(thunk_id, allocator.next_inst(), push_rax);

    let load_entry_rva = allocator.next_inst();
    let load_entry =
        Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 0u64).map_err(anyhow_from_iced)?;
    ir.add_instruction(thunk_id, load_entry_rva, load_entry);

    let decode_key = derive_thunk_decode_key(seed, target_rva, kind);
    let decode_target = Instruction::with2(
        Code::Lea_r64_m,
        Register::RAX,
        MemoryOperand::with_base_displ(Register::RAX, decode_key as i64),
    )
    .map_err(anyhow_from_iced)?;
    ir.add_instruction(thunk_id, allocator.next_inst(), decode_target);

    let xchg_stack = Instruction::with2(
        Code::Xchg_rm64_r64,
        MemoryOperand::with_base(Register::RSP),
        Register::RAX,
    )
    .map_err(anyhow_from_iced)?;
    ir.add_instruction(thunk_id, allocator.next_inst(), xchg_stack);

    let ret = Instruction::with(Code::Retnq);
    ir.add_instruction(thunk_id, allocator.next_inst(), ret);

    ir.block_mut(thunk_id).terminator = match kind {
        ThunkFlowKind::Call => Terminator::IndirectCall,
        ThunkFlowKind::Branch => Terminator::IndirectBranch,
    };

    let edge_kind = match kind {
        ThunkFlowKind::Call => EdgeKind::IndirectCall,
        ThunkFlowKind::Branch => EdgeKind::IndirectJump,
    };
    let target_block = find_block_by_start_rva(ir, target_rva);
    ir.add_edge(thunk_id, target_block, Some(target_rva), edge_kind, true);
    ir.add_indirect_thunk_record(
        function_id,
        thunk_id,
        match kind {
            ThunkFlowKind::Call => IndirectThunkKind::Call,
            ThunkFlowKind::Branch => IndirectThunkKind::Branch,
        },
        target_rva,
        load_entry_rva,
        decode_key,
    );

    let result = ThunkBuildResult {
        block_id: thunk_id,
        start_rva: thunk_start,
    };
    cache.insert((function_id, target_rva, kind), result);
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
struct SigSegmentSelectorPass {
    seed: u64,
    require_mutation: bool,
    allow_size_growth: bool,
}

impl Pass for SigSegmentSelectorPass {
    fn name(&self) -> &'static str {
        "sig-segment-selector"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut info_factory = InstructionInfoFactory::new();
        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }
            let function_id = ir.functions[fidx].id;

            let block_ids = ir.functions[fidx].blocks.clone();
            for block_id in block_ids {
                let block_start = ir.block(block_id).start_rva;
                let inst_ids = ir.block(block_id).insts.clone();
                for (inst_index, inst_id) in inst_ids.iter().enumerate() {
                    let mut inst = ir.inst(*inst_id).instruction;
                    if !is_segment_selector_candidate(&inst) {
                        skipped_sites += 1;
                        continue;
                    }

                    if !should_inject(self.seed, block_start, inst_index as u64, true, 1) {
                        continue;
                    }

                    let existing_prefix = inst.segment_prefix();
                    let stack_relative = is_stack_or_base_pointer(inst.memory_base());
                    let prefix = if existing_prefix == Register::None {
                        if !self.allow_size_growth {
                            skipped_sites += 1;
                            continue;
                        }
                        if stack_relative {
                            Register::SS
                        } else {
                            Register::DS
                        }
                    } else {
                        match existing_prefix {
                            Register::DS => {
                                if stack_relative {
                                    Register::SS
                                } else {
                                    Register::DS
                                }
                            }
                            Register::SS => {
                                if stack_relative {
                                    Register::DS
                                } else {
                                    skipped_sites += 1;
                                    continue;
                                }
                            }
                            Register::ES | Register::CS => {
                                skipped_sites += 1;
                                continue;
                            }
                            Register::FS | Register::GS => {
                                skipped_sites += 1;
                                continue;
                            }
                            _ => {
                                if stack_relative {
                                    Register::SS
                                } else {
                                    Register::DS
                                }
                            }
                        }
                    };
                    if prefix == Register::SS && !stack_relative {
                        skipped_sites += 1;
                        continue;
                    }
                    if prefix == existing_prefix {
                        skipped_sites += 1;
                        continue;
                    }

                    // Reject instructions that touch FS/GS to avoid semantic drift.
                    let uses_fs_gs = info_factory
                        .info(&inst)
                        .used_memory()
                        .iter()
                        .any(|m| matches!(m.segment(), Register::FS | Register::GS));
                    if uses_fs_gs {
                        skipped_sites += 1;
                        continue;
                    }

                    inst.set_segment_prefix(prefix);
                    ir.insts[inst_id.0].instruction = inst;

                    mutated_instructions += 1;
                    mutated_blocks.insert(block_id);
                    mutated_functions.insert(function_id);
                }
            }
        }

        if self.require_mutation && mutated_instructions == 0 {
            bail!("sig-segment-selector produced 0 safe mutations (strict fail-closed policy)");
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct SigInstructionReorderPass {
    seed: u64,
    require_mutation: bool,
}

impl Pass for SigInstructionReorderPass {
    fn name(&self) -> &'static str {
        "sig-instruction-reorder"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut info_factory = InstructionInfoFactory::new();
        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }

            let function_id = ir.functions[fidx].id;
            let block_ids = ir.functions[fidx].blocks.clone();
            for block_id in block_ids {
                let original = ir.blocks[block_id.0].insts.clone();
                if original.len() < 3 {
                    continue;
                }

                let reorder_upto = original.len().saturating_sub(1);
                if reorder_upto < 2 {
                    continue;
                }

                let mut profiles = Vec::with_capacity(reorder_upto);
                for inst_id in &original[..reorder_upto] {
                    let inst = ir.insts[inst_id.0].instruction;
                    profiles.push(build_inst_profile(inst, &mut info_factory));
                }

                let mut rebuilt = Vec::with_capacity(original.len());
                let mut segment_index = 0usize;
                let mut cursor = 0usize;
                while cursor < reorder_upto {
                    if profiles[cursor].barrier {
                        rebuilt.push(original[cursor]);
                        cursor += 1;
                        continue;
                    }

                    let start = cursor;
                    while cursor < reorder_upto && !profiles[cursor].barrier {
                        cursor += 1;
                    }
                    let end = cursor;

                    if end - start < 2 {
                        rebuilt.extend_from_slice(&original[start..end]);
                        skipped_sites += 1;
                        continue;
                    }

                    let shuffled = reorder_window(
                        &original[start..end],
                        &profiles[start..end],
                        mix_seed(
                            self.seed,
                            ir.blocks[block_id.0].start_rva ^ (segment_index as u64),
                        ),
                    );
                    if shuffled != original[start..end] {
                        mutated_instructions += end - start;
                    }
                    rebuilt.extend(shuffled);
                    segment_index += 1;
                }

                rebuilt.push(*original.last().expect("non-empty"));
                if rebuilt != original {
                    ir.blocks[block_id.0].insts = rebuilt;
                    mutated_blocks.insert(block_id);
                    mutated_functions.insert(function_id);
                }
            }
        }

        if self.require_mutation && mutated_blocks.is_empty() {
            bail!(
                "sig-instruction-reorder produced 0 reordered blocks (strict fail-closed policy)"
            );
        }

        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct SigBlockShufflePass {
    seed: u64,
    require_mutation: bool,
}

impl Pass for SigBlockShufflePass {
    fn name(&self) -> &'static str {
        "sig-block-shuffle"
    }

    fn run(&self, ir: &mut ProgramIr) -> Result<()> {
        let mut mutated_functions = HashSet::<FunctionId>::new();
        let mut mutated_blocks = HashSet::<BlockId>::new();
        let mut mutated_instructions = 0usize;
        let mut skipped_sites = 0usize;

        for fidx in 0..ir.functions.len() {
            if ir.functions[fidx].fallback {
                continue;
            }

            let original = ir.functions[fidx].blocks.clone();
            if original.len() < 3 {
                skipped_sites += 1;
                continue;
            }

            let mut safe_for_shuffle = true;
            for bid in &original {
                let term = &ir.blocks[bid.0].terminator;
                if !matches!(
                    term,
                    Terminator::Return
                        | Terminator::UnconditionalBranch { .. }
                        | Terminator::IndirectBranch
                        | Terminator::Trap
                ) {
                    safe_for_shuffle = false;
                    break;
                }
            }

            if !safe_for_shuffle {
                skipped_sites += 1;
                continue;
            }

            let entry_idx = original
                .iter()
                .position(|bid| ir.blocks[bid.0].start_rva == ir.functions[fidx].address_rva)
                .unwrap_or(0);
            let entry_block = original[entry_idx];

            let mut rest = Vec::with_capacity(original.len() - 1);
            for (idx, bid) in original.iter().enumerate() {
                if idx != entry_idx {
                    rest.push(*bid);
                }
            }
            if rest.len() < 2 {
                skipped_sites += 1;
                continue;
            }

            shuffle_in_place(
                &mut rest,
                mix_seed(
                    self.seed,
                    ir.functions[fidx].address_rva ^ original.len() as u64,
                ),
            );

            let mut reordered = Vec::with_capacity(original.len());
            reordered.push(entry_block);
            reordered.extend(rest);

            if reordered != original {
                ir.functions[fidx].blocks = reordered.clone();
                mutated_functions.insert(ir.functions[fidx].id);
                for b in reordered {
                    mutated_blocks.insert(b);
                    mutated_instructions += ir.block(b).insts.len();
                }
            }
        }

        if self.require_mutation && mutated_functions.is_empty() {
            bail!("sig-block-shuffle produced 0 shuffled functions (strict fail-closed policy)");
        }

        ir.request_preserve_function_block_order();
        record_pass_outcome(
            ir,
            self.name(),
            mutated_functions.len(),
            mutated_blocks.len(),
            mutated_instructions,
            0,
            skipped_sites,
        );
        Ok(())
    }
}

#[derive(Default)]
struct InstProfile {
    reads: BTreeSet<Register>,
    writes: BTreeSet<Register>,
    reads_flags: bool,
    writes_flags: bool,
    touches_memory: bool,
    writes_memory: bool,
    barrier: bool,
}

#[derive(Clone, Copy)]
struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn index(&mut self, upper_exclusive: usize) -> usize {
        debug_assert!(upper_exclusive > 0);
        (self.next_u64() as usize) % upper_exclusive
    }
}

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

        let mut base = max_rva.saturating_add(0x10000);
        if base > 0xF000_0000 {
            base = 0x7000_0000;
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

fn mix_seed(lhs: u64, rhs: u64) -> u64 {
    lhs.rotate_left(17) ^ rhs.rotate_right(11) ^ 0x9e37_79b9_7f4a_7c15
}

fn should_inject(seed: u64, scope: u64, idx: u64, aggressive: bool, stride: u64) -> bool {
    if aggressive {
        return true;
    }
    let mixed = mix_seed(seed, scope ^ idx.wrapping_mul(0xA24B_AED4_9C77_5C7B));
    (mixed % stride.max(1)) == 0
}

fn record_pass_outcome(
    ir: &mut ProgramIr,
    pass_name: &'static str,
    mutated_functions: usize,
    mutated_blocks: usize,
    mutated_instructions: usize,
    injected_blocks: usize,
    skipped_sites: usize,
) {
    ir.record_applied_pass(pass_name);
    ir.record_pass_stats(PassStatsRecord {
        name: pass_name.to_string(),
        mutated_functions,
        mutated_blocks,
        mutated_instructions,
        injected_blocks,
        skipped_sites,
    });
}

#[derive(Clone, Copy)]
enum MbaInput {
    Reg(Register),
    Imm32(i32),
}

fn is_mba_candidate(inst: Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Mov
    ) && matches!(inst.op_kind(0), OpKind::Register)
        && is_gpr64(inst.op_register(0))
        && mba_input_from_inst(inst).is_some()
}

fn mba_input_from_inst(inst: Instruction) -> Option<(Register, MbaInput)> {
    if inst.op_count() < 2 {
        return None;
    }
    if inst.op_kind(0) != OpKind::Register {
        return None;
    }
    let x = inst.op_register(0);
    if !is_gpr64(x) {
        return None;
    }
    let input = match inst.op_kind(1) {
        OpKind::Register => {
            let y = inst.op_register(1);
            if !is_gpr64(y) {
                return None;
            }
            MbaInput::Reg(y)
        }
        OpKind::Immediate8 => MbaInput::Imm32(inst.immediate8() as i8 as i32),
        OpKind::Immediate8to16 => MbaInput::Imm32(inst.immediate8to16() as i32),
        OpKind::Immediate8to32 => MbaInput::Imm32(inst.immediate8to32()),
        OpKind::Immediate8to64 => MbaInput::Imm32(inst.immediate8to64() as i32),
        OpKind::Immediate16 => MbaInput::Imm32(inst.immediate16() as i16 as i32),
        OpKind::Immediate32 => MbaInput::Imm32(inst.immediate32() as i32),
        OpKind::Immediate32to64 => MbaInput::Imm32(inst.immediate32to64() as i32),
        _ => return None,
    };
    Some((x, input))
}

fn build_mba_nonlinear_sequence(
    x: Register,
    y: MbaInput,
    t1: Register,
    t2: Register,
    seed: u64,
) -> Result<Vec<Instruction>> {
    let c1 = (((seed >> 1) as u32) & 0x7FFF_FFFF) as i32 | 1;
    let c2 = (((seed >> 17) as u32) & 0x7FFF_FFFF) as i32 | 1;
    let c3 = (((seed >> 29) as u32) & 0x7FFF_FFFF) as i32 | 1;

    let mut out = Vec::with_capacity(30);
    // Save caller flags and temporaries.
    // Order matters: we later sanitize the saved flags to force TF=0 before POPFQ.
    out.push(Instruction::with1(Code::Push_r64, t1).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Push_r64, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with(Code::Pushfq));

    // Z = (x + y)^2 - x^2 - y^2 - 2xy  == 0 (mod 2^n)
    out.push(Instruction::with2(Code::Mov_rm64_r64, t1, x).map_err(anyhow_from_iced)?);
    emit_add_input_to_reg(&mut out, t1, y)?;
    out.push(Instruction::with2(Code::Imul_r64_rm64, t1, t1).map_err(anyhow_from_iced)?);

    out.push(Instruction::with2(Code::Mov_rm64_r64, t2, x).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Imul_r64_rm64, t2, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Sub_rm64_r64, t1, t2).map_err(anyhow_from_iced)?);

    emit_load_input_to_reg(&mut out, t2, y)?;
    out.push(Instruction::with2(Code::Imul_r64_rm64, t2, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Sub_rm64_r64, t1, t2).map_err(anyhow_from_iced)?);

    out.push(Instruction::with2(Code::Mov_rm64_r64, t2, x).map_err(anyhow_from_iced)?);
    match y {
        MbaInput::Reg(reg) => {
            out.push(Instruction::with2(Code::Imul_r64_rm64, t2, reg).map_err(anyhow_from_iced)?);
        }
        MbaInput::Imm32(imm) => {
            out.push(
                Instruction::with3(Code::Imul_r64_rm64_imm32, t2, t2, imm)
                    .map_err(anyhow_from_iced)?,
            );
        }
    }
    out.push(Instruction::with2(Code::Add_rm64_r64, t2, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Sub_rm64_r64, t1, t2).map_err(anyhow_from_iced)?);

    // Permutation polynomial P(x)=x+2*(x^2+c)
    out.push(Instruction::with2(Code::Mov_rm64_r64, t2, x).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Imul_r64_rm64, t2, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Add_rm64_imm32, t2, c1).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Add_rm64_r64, t2, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Add_rm64_r64, t2, x).map_err(anyhow_from_iced)?);

    // Non-linear coupling & entropy
    out.push(Instruction::with2(Code::Xor_rm64_r64, t1, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with3(Code::Imul_r64_rm64_imm32, t1, t1, c2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Add_rm64_imm32, t1, c3).map_err(anyhow_from_iced)?);

    // Restore flags with TF cleared to avoid accidental single-step traps (0x80000004).
    out.push(Instruction::with1(Code::Pop_r64, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::And_rm64_imm32, t2, !0x100i32).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Push_r64, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with(Code::Popfq));
    out.push(Instruction::with1(Code::Pop_r64, t2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Pop_r64, t1).map_err(anyhow_from_iced)?);
    Ok(out)
}

fn emit_load_input_to_reg(out: &mut Vec<Instruction>, dst: Register, y: MbaInput) -> Result<()> {
    match y {
        MbaInput::Reg(reg) => {
            out.push(Instruction::with2(Code::Mov_rm64_r64, dst, reg).map_err(anyhow_from_iced)?);
        }
        MbaInput::Imm32(imm) => {
            out.push(
                Instruction::with2(Code::Mov_r64_imm64, dst, imm as i64 as u64)
                    .map_err(anyhow_from_iced)?,
            );
        }
    }
    Ok(())
}

fn emit_add_input_to_reg(out: &mut Vec<Instruction>, dst: Register, y: MbaInput) -> Result<()> {
    match y {
        MbaInput::Reg(reg) => {
            out.push(Instruction::with2(Code::Add_rm64_r64, dst, reg).map_err(anyhow_from_iced)?);
        }
        MbaInput::Imm32(imm) => {
            out.push(Instruction::with2(Code::Add_rm64_imm32, dst, imm).map_err(anyhow_from_iced)?);
        }
    }
    Ok(())
}

fn is_eq_cmp_followed_by_eq_jcc(cmp: Instruction, jcc: Instruction) -> bool {
    if cmp.mnemonic() != Mnemonic::Cmp {
        return false;
    }
    if cmp.op_count() < 2 {
        return false;
    }
    if cmp.op_kind(0) != OpKind::Register || !is_gpr64(cmp.op_register(0)) {
        return false;
    }
    if cmp_operand_imm64(cmp).is_none() {
        return false;
    }

    matches!(jcc.mnemonic(), Mnemonic::Je | Mnemonic::Jne)
        && matches!(jcc.flow_control(), FlowControl::ConditionalBranch)
}

fn is_test_zero_followed_by_eq_jcc(test: Instruction, jcc: Instruction) -> bool {
    if test.mnemonic() != Mnemonic::Test {
        return false;
    }
    if test.op_count() < 2 {
        return false;
    }
    if test.op_kind(0) != OpKind::Register || test.op_kind(1) != OpKind::Register {
        return false;
    }

    let r0 = test.op_register(0);
    let r1 = test.op_register(1);
    if r0 != r1 || !is_gpr64(r0) {
        return false;
    }

    matches!(jcc.mnemonic(), Mnemonic::Je | Mnemonic::Jne)
        && matches!(jcc.flow_control(), FlowControl::ConditionalBranch)
}

fn cmp_operand_reg64(cmp: Instruction) -> Option<Register> {
    if cmp.op_kind(0) != OpKind::Register {
        return None;
    }
    let reg = cmp.op_register(0);
    if !is_gpr64(reg) {
        return None;
    }
    Some(reg)
}

fn test_operand_reg64(test: Instruction) -> Option<Register> {
    if test.op_count() < 2 {
        return None;
    }
    if test.op_kind(0) != OpKind::Register || test.op_kind(1) != OpKind::Register {
        return None;
    }
    let reg = test.op_register(0);
    if reg != test.op_register(1) || !is_gpr64(reg) {
        return None;
    }
    Some(reg)
}

fn cmp_operand_imm64(cmp: Instruction) -> Option<u64> {
    if cmp.op_count() < 2 {
        return None;
    }
    match cmp.op_kind(1) {
        OpKind::Immediate8 => Some(cmp.immediate8() as u64),
        OpKind::Immediate16 => Some(cmp.immediate16() as u64),
        OpKind::Immediate32 => Some(cmp.immediate32() as u64),
        OpKind::Immediate64 => Some(cmp.immediate64()),
        OpKind::Immediate8to16 => Some(cmp.immediate8to16() as i64 as u64),
        OpKind::Immediate8to32 => Some(cmp.immediate8to32() as i64 as u64),
        OpKind::Immediate8to64 => Some(cmp.immediate8to64() as u64),
        OpKind::Immediate32to64 => Some(cmp.immediate32to64() as u64),
        _ => None,
    }
}

fn build_one_way_cmp_sequence(
    source_reg: Register,
    imm: u64,
    tmp1: Register,
    tmp2: Register,
    seed: u64,
) -> Result<Vec<Instruction>> {
    let key1 = (((seed >> 3) as u32) & 0x7FFF_FFFF) as i32 | 1;
    let key2 = (((seed >> 23) as u32) & 0x7FFF_FFFF) as i32 | 1;
    let mul1: i32 = 0x045D_9F3B;
    let mul2: i32 = 0x119D_E1F3;

    let mixed_imm = one_way_mix_64(imm, key1 as u64, key2 as u64, mul1 as u64, mul2 as u64);

    let mut out = Vec::with_capacity(16);
    out.push(Instruction::with1(Code::Push_r64, tmp1).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Push_r64, tmp2).map_err(anyhow_from_iced)?);

    out.push(Instruction::with2(Code::Mov_rm64_r64, tmp1, source_reg).map_err(anyhow_from_iced)?);
    emit_one_way_mix_instructions(&mut out, tmp1, key1, key2, mul1, mul2)?;

    out.push(Instruction::with2(Code::Mov_r64_imm64, tmp2, imm).map_err(anyhow_from_iced)?);
    emit_one_way_mix_instructions(&mut out, tmp2, key1, key2, mul1, mul2)?;

    out.push(Instruction::with2(Code::Cmp_rm64_r64, tmp1, tmp2).map_err(anyhow_from_iced)?);

    // Keep a concrete one-way constant in the stream for static pressure.
    // Use MOV (flag-preserving) so the following JE/JNE still consumes CMP flags.
    out.push(Instruction::with2(Code::Mov_r64_imm64, tmp2, mixed_imm).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Pop_r64, tmp2).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Pop_r64, tmp1).map_err(anyhow_from_iced)?);
    Ok(out)
}

fn emit_one_way_mix_instructions(
    out: &mut Vec<Instruction>,
    reg: Register,
    key1: i32,
    key2: i32,
    mul1: i32,
    mul2: i32,
) -> Result<()> {
    out.push(Instruction::with2(Code::Xor_rm64_imm32, reg, key1).map_err(anyhow_from_iced)?);
    out.push(
        Instruction::with3(Code::Imul_r64_rm64_imm32, reg, reg, mul1).map_err(anyhow_from_iced)?,
    );
    out.push(Instruction::with2(Code::Ror_rm64_imm8, reg, 13).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Xor_rm64_imm32, reg, key2).map_err(anyhow_from_iced)?);
    out.push(
        Instruction::with3(Code::Imul_r64_rm64_imm32, reg, reg, mul2).map_err(anyhow_from_iced)?,
    );
    Ok(())
}

fn one_way_mix_64(mut x: u64, key1: u64, key2: u64, mul1: u64, mul2: u64) -> u64 {
    x ^= key1;
    x = x.wrapping_mul(mul1);
    x = x.rotate_right(13);
    x ^= key2;
    x = x.wrapping_mul(mul2);
    x
}

fn build_path_explosion_guard(
    source_reg: Register,
    tmp: Register,
    detour_start_rva: u64,
    seed: u64,
    image_base: u64,
) -> Result<Vec<Instruction>> {
    let mul = (((seed >> 7) as u32) & 0x7FFF_FFFF) as i32 | 1;
    let key = (((seed >> 21) as u32) & 0x7FFF_FFFF) as i32 | 1;

    let mut out = Vec::with_capacity(12);
    out.push(Instruction::with1(Code::Push_r64, tmp).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Mov_rm64_r64, tmp, source_reg).map_err(anyhow_from_iced)?);
    out.push(
        Instruction::with3(Code::Imul_r64_rm64_imm32, tmp, tmp, mul).map_err(anyhow_from_iced)?,
    );
    out.push(Instruction::with2(Code::Xor_rm64_imm32, tmp, key).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::And_rm64_imm32, tmp, 3).map_err(anyhow_from_iced)?);
    out.push(Instruction::with2(Code::Cmp_rm64_imm32, tmp, 1).map_err(anyhow_from_iced)?);
    out.push(Instruction::with1(Code::Pop_r64, tmp).map_err(anyhow_from_iced)?);
    out.push(
        Instruction::with_branch(Code::Jne_rel32_64, image_base + detour_start_rva)
            .map_err(anyhow_from_iced)?,
    );
    Ok(out)
}

fn select_source_reg_for_path_predicate(
    ir: &ProgramIr,
    block_id: BlockId,
    info_factory: &mut InstructionInfoFactory,
) -> Option<Register> {
    let block = ir.block(block_id);
    for iid in &block.insts {
        let inst = ir.inst(*iid).instruction;

        if inst.op_count() > 0 && inst.op_kind(0) == OpKind::Register {
            let reg = inst.op_register(0);
            if is_gpr64(reg) && !is_stack_or_base_pointer(reg) {
                return Some(reg);
            }
        }

        for reg_use in info_factory.info(&inst).used_registers() {
            let reg = reg_use.register();
            if is_gpr64(reg) && !is_stack_or_base_pointer(reg) {
                return Some(reg);
            }
        }
    }
    None
}

fn is_segment_selector_candidate(inst: &Instruction) -> bool {
    if (0..inst.op_count()).all(|idx| inst.op_kind(idx) != OpKind::Memory) {
        return false;
    }

    // Segment overrides on RIP-relative encodings can force absolute addressing forms.
    if inst.is_ip_rel_memory_operand() {
        return false;
    }

    if matches!(
        inst.memory_segment(),
        Register::FS | Register::GS | Register::None
    ) {
        return false;
    }

    true
}

fn build_inst_profile(inst: Instruction, info_factory: &mut InstructionInfoFactory) -> InstProfile {
    let mut profile = InstProfile::default();
    let info = info_factory.info(&inst);

    for reg_use in info.used_registers() {
        let reg = canonical_register(reg_use.register());
        match reg_use.access() {
            OpAccess::Read | OpAccess::CondRead => {
                profile.reads.insert(reg);
            }
            OpAccess::Write | OpAccess::CondWrite => {
                profile.writes.insert(reg);
            }
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                profile.reads.insert(reg);
                profile.writes.insert(reg);
            }
            _ => {}
        }
    }

    for mem_use in info.used_memory() {
        profile.touches_memory = true;
        match mem_use.access() {
            OpAccess::Write
            | OpAccess::CondWrite
            | OpAccess::ReadWrite
            | OpAccess::ReadCondWrite => {
                profile.writes_memory = true;
            }
            _ => {}
        }
    }

    profile.reads_flags = inst.rflags_read() != 0;
    profile.writes_flags = inst.rflags_modified() != 0;

    if matches!(
        inst.flow_control(),
        FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::Return
            | FlowControl::Exception
            | FlowControl::XbeginXabortXend
    ) {
        profile.barrier = true;
    }

    if inst.has_lock_prefix()
        || inst.has_rep_prefix()
        || inst.has_repe_prefix()
        || inst.has_repne_prefix()
    {
        profile.barrier = true;
    }

    if profile
        .writes
        .iter()
        .any(|reg| is_stack_or_base_pointer(*reg))
    {
        profile.barrier = true;
    }

    if matches!(
        inst.memory_base(),
        Register::RSP
            | Register::ESP
            | Register::SP
            | Register::SPL
            | Register::RBP
            | Register::EBP
            | Register::BP
            | Register::BPL
    ) {
        profile.barrier = true;
    }

    profile
}

fn choose_two_scratch_regs(
    inst: Instruction,
    info_factory: &mut InstructionInfoFactory,
    extra_forbidden: &[Register],
) -> Option<(Register, Register)> {
    let used = used_regs(inst, info_factory, extra_forbidden);
    let mut picks = Vec::new();
    for reg in scratch_register_pool().iter().copied() {
        if used.contains(&reg) {
            continue;
        }
        picks.push(reg);
        if picks.len() == 2 {
            return Some((picks[0], picks[1]));
        }
    }
    None
}

fn choose_one_scratch_reg(
    inst: &Instruction,
    info_factory: &mut InstructionInfoFactory,
    extra_forbidden: &[Register],
) -> Option<Register> {
    let used = used_regs(*inst, info_factory, extra_forbidden);
    for reg in scratch_register_pool().iter().copied() {
        if !used.contains(&reg) {
            return Some(reg);
        }
    }
    None
}

fn used_regs(
    inst: Instruction,
    info_factory: &mut InstructionInfoFactory,
    extra_forbidden: &[Register],
) -> HashSet<Register> {
    let mut used = HashSet::new();

    for reg_use in info_factory.info(&inst).used_registers() {
        used.insert(canonical_register(reg_use.register()));
    }
    for idx in 0..inst.op_count() {
        if inst.op_kind(idx) == OpKind::Register {
            used.insert(canonical_register(inst.op_register(idx)));
        }
    }
    for reg in extra_forbidden {
        used.insert(canonical_register(*reg));
    }

    used.insert(Register::RSP);
    used.insert(Register::RBP);
    used
}

fn canonical_register(reg: Register) -> Register {
    if reg == Register::None {
        return reg;
    }
    reg.full_register()
}

fn scratch_register_pool() -> &'static [Register] {
    &[
        Register::R11,
        Register::R10,
        Register::R9,
        Register::R8,
        Register::RDX,
        Register::RCX,
        Register::RAX,
        Register::RDI,
        Register::RSI,
        Register::RBX,
        Register::R15,
        Register::R14,
        Register::R13,
        Register::R12,
    ]
}

fn is_gpr64(reg: Register) -> bool {
    matches!(
        reg,
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::RBX
            | Register::RSP
            | Register::RBP
            | Register::RSI
            | Register::RDI
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    )
}

fn is_stack_or_base_pointer(reg: Register) -> bool {
    matches!(
        reg,
        Register::RSP
            | Register::ESP
            | Register::SP
            | Register::SPL
            | Register::RBP
            | Register::EBP
            | Register::BP
            | Register::BPL
    )
}

fn reorder_window(
    window: &[blare_ir::InstId],
    profiles: &[InstProfile],
    seed: u64,
) -> Vec<blare_ir::InstId> {
    let len = window.len();
    let mut indegree = vec![0usize; len];
    let mut succ = vec![Vec::<usize>::new(); len];

    for i in 0..len {
        for j in (i + 1)..len {
            if has_dependency(&profiles[i], &profiles[j]) {
                succ[i].push(j);
                indegree[j] += 1;
            }
        }
    }

    let mut ready = Vec::<usize>::new();
    for (idx, deg) in indegree.iter().enumerate() {
        if *deg == 0 {
            ready.push(idx);
        }
    }

    let mut rng = DeterministicRng::new(seed);
    let mut out = Vec::<blare_ir::InstId>::with_capacity(len);
    while !ready.is_empty() {
        let pick = rng.index(ready.len());
        let node = ready.swap_remove(pick);
        out.push(window[node]);
        for &next in &succ[node] {
            indegree[next] -= 1;
            if indegree[next] == 0 {
                ready.push(next);
            }
        }
    }

    if out.len() != len {
        return window.to_vec();
    }
    out
}

fn has_dependency(a: &InstProfile, b: &InstProfile) -> bool {
    if a.barrier || b.barrier {
        return true;
    }

    if (a.writes_flags && (b.reads_flags || b.writes_flags)) || (a.reads_flags && b.writes_flags) {
        return true;
    }

    if !a.writes.is_disjoint(&b.reads) {
        return true;
    }
    if !a.writes.is_disjoint(&b.writes) {
        return true;
    }
    if !a.reads.is_disjoint(&b.writes) {
        return true;
    }

    if a.touches_memory && b.touches_memory && (a.writes_memory || b.writes_memory) {
        return true;
    }

    false
}

fn shuffle_in_place<T>(values: &mut [T], seed: u64) {
    if values.len() < 2 {
        return;
    }
    let mut rng = DeterministicRng::new(seed);
    let mut i = values.len() - 1;
    while i > 0 {
        let j = rng.index(i + 1);
        values.swap(i, j);
        i -= 1;
    }
}

fn anyhow_from_iced(err: IcedError) -> anyhow::Error {
    anyhow::anyhow!("{err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode_single(bytes: &[u8]) -> Instruction {
        let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
        let mut inst = Instruction::default();
        decoder.decode_out(&mut inst);
        assert!(
            !inst.is_invalid(),
            "invalid instruction bytes: {bytes:02x?}"
        );
        inst
    }

    #[test]
    fn parse_profile_names() {
        assert_eq!(
            profile_from_name("balanced"),
            Some(ObfuscationProfile::Balanced)
        );
        assert_eq!(
            profile_from_name("aggressive"),
            Some(ObfuscationProfile::Aggressive)
        );
        assert_eq!(
            profile_from_name("sigbreaker"),
            Some(ObfuscationProfile::Sigbreaker)
        );
    }

    #[test]
    fn build_profile_pipeline() {
        let pass = build_profile_pass(ObfuscationProfile::Balanced, 123);
        assert_eq!(pass.name(), "profile-pipeline");
    }

    #[test]
    fn dependency_detects_partial_register_alias_hazard() {
        let mut info_factory = InstructionInfoFactory::new();
        let mov_eax_ecx = decode_single(&[0x89, 0xC8]); // mov eax, ecx
        let sub_ecx_1 = decode_single(&[0x83, 0xE9, 0x01]); // sub ecx, 1
        let a = build_inst_profile(mov_eax_ecx, &mut info_factory);
        let b = build_inst_profile(sub_ecx_1, &mut info_factory);
        assert!(
            has_dependency(&a, &b),
            "WAR hazard ecx read->write must prevent reordering"
        );
    }

    #[test]
    fn used_regs_tracks_full_register_aliases() {
        let mut info_factory = InstructionInfoFactory::new();
        let mov_eax_ecx = decode_single(&[0x89, 0xC8]); // mov eax, ecx
        let used = used_regs(mov_eax_ecx, &mut info_factory, &[]);
        assert!(used.contains(&Register::RAX));
        assert!(used.contains(&Register::RCX));
    }

    #[test]
    fn dependency_detects_flag_hazard_between_xor_and_cmp() {
        let mut info_factory = InstructionInfoFactory::new();
        let xor_edx_r8d = decode_single(&[0x44, 0x31, 0xC2]); // xor edx, r8d
        let cmp_rcx_r9 = decode_single(&[0x4C, 0x39, 0xC9]); // cmp rcx, r9
        let a = build_inst_profile(xor_edx_r8d, &mut info_factory);
        let b = build_inst_profile(cmp_rcx_r9, &mut info_factory);
        assert!(
            has_dependency(&a, &b),
            "flag producer/producer order must be preserved"
        );
    }

    #[test]
    fn loop_encoded_candidate_rejects_amount_one_when_min_is_two() {
        let add_rax_1 = decode_single(&[0x48, 0x83, 0xC0, 0x01]); // add rax, 1
        let add_rax_2 = decode_single(&[0x48, 0x83, 0xC0, 0x02]); // add rax, 2
        assert!(normalize_add_sub_imm_candidate(add_rax_1, 2, 256).is_none());
        assert!(normalize_add_sub_imm_candidate(add_rax_2, 2, 256).is_some());
    }
}
