use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, IcedError, Instruction, InstructionBlock,
    MemoryOperand, Register,
};

pub const IMPORT_RECORD_SIZE: usize = 16;
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x100_0000_01b3;
const RESOLVER_STACK_SIZE: i32 = 0x40;
const SLOT_TARGET_DLL_HASH: i64 = 0x00;
const SLOT_TARGET_FN_HASH: i64 = 0x08;
const SLOT_NAMES_BASE: i64 = 0x10;
const SLOT_ORDINALS_BASE: i64 = 0x18;
const SLOT_FUNCTIONS_BASE: i64 = 0x20;
const SLOT_NAMES_COUNT: i64 = 0x28;
const SLOT_NAME_INDEX: i64 = 0x30;
const SLOT_IAT_ABS_VA: i64 = 0x38;
const PREENTRY_BLOCK_STRIDE: u64 = 0x400;
const EXCEPTION_CONTINUE_EXECUTION: u32 = 0xFFFF_FFFF;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const DEFAULT_RDTSC_THRESHOLD: u32 = 0x0002_0000;
const DEFAULT_BREAKPOINT_SCAN_BYTES: u32 = 32;

#[derive(Debug, Clone)]
pub struct ProtectedImportRecord {
    pub hash_dll: u64,
    pub hash_fn: u64,
    pub iat_rva: u32,
}

#[derive(Debug, Clone)]
pub struct ImportEntryStub {
    pub instructions: Vec<Instruction>,
    pub entry_addr_inst_index: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ImportResolverLayout {
    pub module_check_va: u64,
    pub module_hash_loop_va: u64,
    pub module_hash_done_va: u64,
    pub name_loop_check_va: u64,
    pub name_hash_loop_va: u64,
    pub name_hash_done_va: u64,
    pub name_match_va: u64,
    pub next_name_va: u64,
    pub next_module_va: u64,
    pub not_found_va: u64,
}

#[derive(Debug, Clone)]
pub struct ImportResolverBlocks {
    pub entry: Vec<Instruction>,
    pub module_check: Vec<Instruction>,
    pub module_hash_loop: Vec<Instruction>,
    pub module_hash_done: Vec<Instruction>,
    pub name_loop_check: Vec<Instruction>,
    pub name_hash_loop: Vec<Instruction>,
    pub name_hash_done: Vec<Instruction>,
    pub name_match: Vec<Instruction>,
    pub next_name: Vec<Instruction>,
    pub next_module: Vec<Instruction>,
    pub not_found: Vec<Instruction>,
}

#[derive(Debug, Clone, Copy)]
pub struct PreEntryOptions {
    pub true_oep_va: u64,
    pub anti_debug: bool,
    pub obscure_entry_point: bool,
    pub rdtsc_threshold: u32,
    pub breakpoint_scan_bytes: u32,
}

impl PreEntryOptions {
    pub fn with_defaults(true_oep_va: u64, anti_debug: bool, obscure_entry_point: bool) -> Self {
        Self {
            true_oep_va,
            anti_debug,
            obscure_entry_point,
            rdtsc_threshold: DEFAULT_RDTSC_THRESHOLD,
            breakpoint_scan_bytes: DEFAULT_BREAKPOINT_SCAN_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreEntryStub {
    pub bytes: Vec<u8>,
}

fn stack_slot(offset: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ_size(
        Register::RSP,
        offset,
        if (-128..=127).contains(&offset) { 1 } else { 4 },
    )
}

pub fn fnv1a64(input: &str) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in input.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

pub fn build_encrypted_import_blob(records: &[ProtectedImportRecord], seed: u64) -> Vec<u8> {
    let mut blob = Vec::with_capacity(records.len() * IMPORT_RECORD_SIZE);
    for record in records {
        let enc_hash_dll = record.hash_dll ^ seed;
        let enc_hash_fn = record.hash_fn ^ seed.rotate_left(13);
        blob.extend_from_slice(&enc_hash_dll.to_le_bytes());
        blob.extend_from_slice(&enc_hash_fn.to_le_bytes());
    }
    blob
}

pub fn encode_iat_rva(iat_rva: u32, decode_key: u32) -> u32 {
    iat_rva ^ decode_key
}

pub fn derive_iat_decode_key(seed: u64) -> u32 {
    let lo = seed as u32;
    let hi = (seed >> 32) as u32;
    let mut key = lo ^ hi.rotate_left(7) ^ 0xA7C4_39D1;
    if key == 0 {
        key = 0x1F35_79BD;
    }
    key
}

pub fn build_import_entry_stub(
    entry_va: u64,
    iat_va: u64,
    resolver_target_va: u64,
) -> Result<ImportEntryStub, IcedError> {
    let mut out = Vec::with_capacity(15);

    out.push(Instruction::with1(Code::Push_r64, Register::RCX)?);
    out.push(Instruction::with1(Code::Push_r64, Register::RDX)?);
    out.push(Instruction::with1(Code::Push_r64, Register::R8)?);
    out.push(Instruction::with1(Code::Push_r64, Register::R9)?);

    let mov_entry = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, entry_va)?;
    out.push(mov_entry);
    let entry_addr_inst_index = 4;

    out.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RCX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    out.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RDX,
        MemoryOperand::with_base_displ(Register::RAX, 8),
    )?);
    out.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::R8,
        iat_va,
    )?);
    out.push(Instruction::with_branch(
        Code::Call_rel32_64,
        resolver_target_va,
    )?);
    out.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R11,
        Register::RAX,
    )?);
    out.push(Instruction::with1(Code::Pop_r64, Register::R9)?);
    out.push(Instruction::with1(Code::Pop_r64, Register::R8)?);
    out.push(Instruction::with1(Code::Pop_r64, Register::RDX)?);
    out.push(Instruction::with1(Code::Pop_r64, Register::RCX)?);
    out.push(Instruction::with1(Code::Jmp_rm64, Register::R11)?);

    Ok(ImportEntryStub {
        instructions: out,
        entry_addr_inst_index,
    })
}

pub fn build_import_resolver_stub(
    layout: ImportResolverLayout,
) -> Result<ImportResolverBlocks, IcedError> {
    let mut entry = Vec::with_capacity(11);
    entry.push(Instruction::with2(
        Code::Sub_rm64_imm32,
        Register::RSP,
        RESOLVER_STACK_SIZE,
    )?);
    entry.push(Instruction::with2(
        Code::Mov_rm64_r64,
        stack_slot(SLOT_TARGET_DLL_HASH),
        Register::RCX,
    )?);
    entry.push(Instruction::with2(
        Code::Mov_rm64_r64,
        stack_slot(SLOT_TARGET_FN_HASH),
        Register::RDX,
    )?);
    entry.push(Instruction::with2(
        Code::Mov_rm64_r64,
        stack_slot(SLOT_IAT_ABS_VA),
        Register::R8,
    )?);
    entry.push(Instruction::with2(
        Code::Mov_rm32_imm32,
        Register::ECX,
        0x60,
    )?);
    let mut load_peb = Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        MemoryOperand::with_base(Register::RCX),
    )?;
    load_peb.set_segment_prefix(Register::GS);
    entry.push(load_peb);
    entry.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        MemoryOperand::with_base_displ(Register::RAX, 0x18),
    )?);
    entry.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::R9,
        MemoryOperand::with_base_displ(Register::RAX, 0x20),
    )?);
    entry.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R10,
        MemoryOperand::with_base(Register::R9),
    )?);
    entry.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.module_check_va,
    )?);

    let mut module_check = Vec::with_capacity(24);
    module_check.push(Instruction::with2(
        Code::Cmp_rm64_r64,
        Register::R10,
        Register::R9,
    )?);
    module_check.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.not_found_va,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R11,
        MemoryOperand::with_base_displ(Register::R10, 0x20),
    )?);
    module_check.push(Instruction::with2(
        Code::Test_rm64_r64,
        Register::R11,
        Register::R11,
    )?);
    module_check.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.next_module_va,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EAX,
        MemoryOperand::with_base_displ(Register::R11, 0x3C),
    )?);
    module_check.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::R11,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x88),
    )?);
    module_check.push(Instruction::with2(
        Code::Test_rm32_r32,
        Register::ECX,
        Register::ECX,
    )?);
    module_check.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.next_module_va,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        Register::R11,
    )?);
    module_check.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RCX,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x0C),
    )?);
    module_check.push(Instruction::with2(
        Code::Test_rm32_r32,
        Register::ECX,
        Register::ECX,
    )?);
    module_check.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.next_module_va,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        Register::R11,
    )?);
    module_check.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RCX,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::R8,
        FNV_OFFSET_BASIS,
    )?);
    module_check.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::RDX,
        FNV_PRIME,
    )?);
    module_check.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.module_hash_loop_va,
    )?);

    let mut module_hash_loop = Vec::with_capacity(8);
    module_hash_loop.push(Instruction::with2(
        Code::Movzx_r32_rm16,
        Register::ECX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    module_hash_loop.push(Instruction::with2(
        Code::Test_rm16_r16,
        Register::CX,
        Register::CX,
    )?);
    module_hash_loop.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.module_hash_done_va,
    )?);
    module_hash_loop.push(Instruction::with2(Code::Or_rm8_imm8, Register::CL, 0x20)?);
    module_hash_loop.push(Instruction::with2(
        Code::Xor_rm64_r64,
        Register::R8,
        Register::RCX,
    )?);
    module_hash_loop.push(Instruction::with2(
        Code::Imul_r64_rm64,
        Register::R8,
        Register::RDX,
    )?);
    module_hash_loop.push(Instruction::with2(Code::Add_rm64_imm32, Register::RAX, 2)?);
    module_hash_loop.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.module_hash_loop_va,
    )?);

    let mut module_hash_done = Vec::with_capacity(26);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        stack_slot(SLOT_TARGET_DLL_HASH),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Cmp_rm64_r64,
        Register::R8,
        Register::RAX,
    )?);
    module_hash_done.push(Instruction::with_branch(
        Code::Jne_rel32_64,
        layout.next_module_va,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EAX,
        MemoryOperand::with_base_displ(Register::R11, 0x3C),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::R11,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x88),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        Register::R11,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RCX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x18),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Test_rm32_r32,
        Register::ECX,
        Register::ECX,
    )?);
    module_hash_done.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.next_module_va,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_rm32_r32,
        stack_slot(SLOT_NAMES_COUNT),
        Register::ECX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Xor_rm32_r32,
        Register::ECX,
        Register::ECX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_rm32_r32,
        stack_slot(SLOT_NAME_INDEX),
        Register::ECX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x20),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RDX,
        Register::R11,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RDX,
        Register::RCX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_rm64_r64,
        stack_slot(SLOT_NAMES_BASE),
        Register::RDX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x24),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RDX,
        Register::R11,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RDX,
        Register::RCX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_rm64_r64,
        stack_slot(SLOT_ORDINALS_BASE),
        Register::RDX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0x1C),
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RDX,
        Register::R11,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RDX,
        Register::RCX,
    )?);
    module_hash_done.push(Instruction::with2(
        Code::Mov_rm64_r64,
        stack_slot(SLOT_FUNCTIONS_BASE),
        Register::RDX,
    )?);
    module_hash_done.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.name_loop_check_va,
    )?);

    let mut name_loop_check = Vec::with_capacity(16);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        stack_slot(SLOT_NAME_INDEX),
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EAX,
        stack_slot(SLOT_NAMES_COUNT),
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Cmp_rm32_r32,
        Register::ECX,
        Register::EAX,
    )?);
    name_loop_check.push(Instruction::with_branch(
        Code::Jae_rel32_64,
        layout.next_module_va,
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        stack_slot(SLOT_NAMES_BASE),
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EDX,
        Register::ECX,
    )?);
    name_loop_check.push(Instruction::with2(Code::Shl_rm32_imm8, Register::EDX, 2)?);
    name_loop_check.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EDX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        Register::R11,
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::R8,
        FNV_OFFSET_BASIS,
    )?);
    name_loop_check.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::RDX,
        FNV_PRIME,
    )?);
    name_loop_check.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.name_hash_loop_va,
    )?);

    let mut name_hash_loop = Vec::with_capacity(8);
    name_hash_loop.push(Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::ECX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    name_hash_loop.push(Instruction::with2(Code::Cmp_rm8_imm8, Register::CL, 0)?);
    name_hash_loop.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.name_hash_done_va,
    )?);
    name_hash_loop.push(Instruction::with2(
        Code::Xor_rm64_r64,
        Register::R8,
        Register::RCX,
    )?);
    name_hash_loop.push(Instruction::with2(
        Code::Imul_r64_rm64,
        Register::R8,
        Register::RDX,
    )?);
    name_hash_loop.push(Instruction::with1(Code::Inc_rm64, Register::RAX)?);
    name_hash_loop.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.name_hash_loop_va,
    )?);

    let mut name_hash_done = Vec::with_capacity(4);
    name_hash_done.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        stack_slot(SLOT_TARGET_FN_HASH),
    )?);
    name_hash_done.push(Instruction::with2(
        Code::Cmp_rm64_r64,
        Register::R8,
        Register::RAX,
    )?);
    name_hash_done.push(Instruction::with_branch(
        Code::Je_rel32_64,
        layout.name_match_va,
    )?);
    name_hash_done.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.next_name_va,
    )?);

    let mut next_name = Vec::with_capacity(5);
    next_name.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        stack_slot(SLOT_NAME_INDEX),
    )?);
    next_name.push(Instruction::with1(Code::Inc_rm32, Register::ECX)?);
    next_name.push(Instruction::with2(
        Code::Mov_rm32_r32,
        stack_slot(SLOT_NAME_INDEX),
        Register::ECX,
    )?);
    next_name.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.name_loop_check_va,
    )?);

    let mut next_module = Vec::with_capacity(3);
    next_module.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R10,
        MemoryOperand::with_base(Register::R10),
    )?);
    next_module.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        layout.module_check_va,
    )?);

    let mut not_found = Vec::with_capacity(4);
    not_found.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        stack_slot(SLOT_IAT_ABS_VA),
    )?);
    not_found.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    not_found.push(Instruction::with2(
        Code::Add_rm64_imm32,
        Register::RSP,
        RESOLVER_STACK_SIZE,
    )?);
    not_found.push(Instruction::with(Code::Retnq));

    let mut name_match = Vec::with_capacity(14);
    name_match.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        stack_slot(SLOT_NAME_INDEX),
    )?);
    name_match.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        stack_slot(SLOT_ORDINALS_BASE),
    )?);
    name_match.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EDX,
        Register::ECX,
    )?);
    name_match.push(Instruction::with2(Code::Shl_rm32_imm8, Register::EDX, 1)?);
    name_match.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    name_match.push(Instruction::with2(
        Code::Movzx_r32_rm16,
        Register::ECX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    name_match.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        stack_slot(SLOT_FUNCTIONS_BASE),
    )?);
    name_match.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EDX,
        Register::ECX,
    )?);
    name_match.push(Instruction::with2(Code::Shl_rm32_imm8, Register::EDX, 2)?);
    name_match.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    name_match.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::EDX,
        MemoryOperand::with_base(Register::RAX),
    )?);
    name_match.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        Register::R11,
    )?);
    name_match.push(Instruction::with2(
        Code::Add_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    name_match.push(Instruction::with2(
        Code::Add_rm64_imm32,
        Register::RSP,
        RESOLVER_STACK_SIZE,
    )?);
    name_match.push(Instruction::with(Code::Retnq));

    Ok(ImportResolverBlocks {
        entry,
        module_check,
        module_hash_loop,
        module_hash_done,
        name_loop_check,
        name_hash_loop,
        name_hash_done,
        name_match,
        next_name,
        next_module,
        not_found,
    })
}

pub fn build_pre_entry_stub(
    base_va: u64,
    options: PreEntryOptions,
) -> Result<PreEntryStub, IcedError> {
    if !options.anti_debug && !options.obscure_entry_point {
        return Ok(PreEntryStub { bytes: Vec::new() });
    }

    const IDX_ENTRY: usize = 0;
    const IDX_SCAN_CHECK: usize = 1;
    const IDX_SCAN_BODY: usize = 2;
    const IDX_CLEAN_JUMP: usize = 3;
    const IDX_FAIL_TRAP: usize = 4;

    let use_obscure = options.obscure_entry_point;
    let idx_obscure_setup = if use_obscure { Some(5usize) } else { None };
    let idx_veh_handler = if use_obscure { Some(6usize) } else { None };
    let idx_veh_handler_search = if use_obscure { Some(7usize) } else { None };
    let resolver_base = if use_obscure { Some(8usize) } else { None };
    let block_count = if use_obscure { 19usize } else { 5usize };

    let va = |idx: usize| -> u64 { base_va + (idx as u64) * PREENTRY_BLOCK_STRIDE };

    let mut blocks = vec![Vec::<Instruction>::new(); block_count];
    let post_scan_target = idx_obscure_setup
        .map(va)
        .unwrap_or_else(|| va(IDX_CLEAN_JUMP));

    let mut entry = Vec::with_capacity(40);
    entry.push(Instruction::with(Code::Pushfq));
    entry.push(Instruction::with1(Code::Push_r64, Register::RAX)?);
    entry.push(Instruction::with1(Code::Push_r64, Register::RCX)?);
    entry.push(Instruction::with1(Code::Push_r64, Register::RDX)?);
    entry.push(Instruction::with1(Code::Push_r64, Register::R8)?);
    entry.push(Instruction::with1(Code::Push_r64, Register::R9)?);
    entry.push(Instruction::with1(Code::Push_r64, Register::R10)?);
    entry.push(Instruction::with1(Code::Push_r64, Register::R11)?);
    entry.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::RAX,
        MemoryOperand::with_base_displ_size_bcst_seg(Register::None, 0x60, 4, false, Register::GS),
    )?);
    entry.push(Instruction::with2(
        Code::Cmp_rm8_imm8,
        MemoryOperand::with_base_displ(Register::RAX, 0x02),
        0,
    )?);
    entry.push(Instruction::with_branch(
        Code::Jne_rel32_64,
        va(IDX_FAIL_TRAP),
    )?);
    entry.push(Instruction::with2(
        Code::Mov_r32_rm32,
        Register::ECX,
        MemoryOperand::with_base_displ(Register::RAX, 0xBC),
    )?);
    entry.push(Instruction::with2(
        Code::Test_rm32_imm32,
        Register::ECX,
        0x70,
    )?);
    entry.push(Instruction::with_branch(
        Code::Jne_rel32_64,
        va(IDX_FAIL_TRAP),
    )?);
    entry.push(Instruction::with(Code::Rdtsc));
    entry.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 32)?);
    entry.push(Instruction::with2(
        Code::Or_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    entry.push(Instruction::with2(
        Code::Mov_r64_rm64,
        Register::R10,
        Register::RAX,
    )?);
    entry.push(Instruction::with(Code::Rdtsc));
    entry.push(Instruction::with2(Code::Shl_rm64_imm8, Register::RDX, 32)?);
    entry.push(Instruction::with2(
        Code::Or_rm64_r64,
        Register::RAX,
        Register::RDX,
    )?);
    entry.push(Instruction::with2(
        Code::Sub_rm64_r64,
        Register::RAX,
        Register::R10,
    )?);
    entry.push(Instruction::with2(
        Code::Cmp_rm64_imm32,
        Register::RAX,
        options.rdtsc_threshold as i32,
    )?);
    entry.push(Instruction::with_branch(
        Code::Ja_rel32_64,
        va(IDX_FAIL_TRAP),
    )?);
    entry.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::R9,
        options.true_oep_va,
    )?);
    entry.push(Instruction::with2(
        Code::Xor_rm32_r32,
        Register::ECX,
        Register::ECX,
    )?);
    entry.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        va(IDX_SCAN_CHECK),
    )?);
    blocks[IDX_ENTRY] = entry;

    let mut scan_check = Vec::with_capacity(4);
    scan_check.push(Instruction::with2(
        Code::Cmp_rm32_imm32,
        Register::ECX,
        options.breakpoint_scan_bytes as i32,
    )?);
    scan_check.push(Instruction::with_branch(
        Code::Jae_rel32_64,
        post_scan_target,
    )?);
    scan_check.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        va(IDX_SCAN_BODY),
    )?);
    blocks[IDX_SCAN_CHECK] = scan_check;

    let mut scan_body = Vec::with_capacity(8);
    scan_body.push(Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::EAX,
        MemoryOperand::with_base_index_scale(Register::R9, Register::RCX, 1),
    )?);
    scan_body.push(Instruction::with2(Code::Cmp_rm8_imm8, Register::AL, 0xCC)?);
    scan_body.push(Instruction::with_branch(
        Code::Je_rel32_64,
        va(IDX_FAIL_TRAP),
    )?);
    scan_body.push(Instruction::with1(Code::Inc_rm32, Register::ECX)?);
    scan_body.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        va(IDX_SCAN_CHECK),
    )?);
    blocks[IDX_SCAN_BODY] = scan_body;

    let mut clean_jump = Vec::with_capacity(16);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::R11)?);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::R10)?);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::R9)?);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::R8)?);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::RDX)?);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::RCX)?);
    clean_jump.push(Instruction::with1(Code::Pop_r64, Register::RAX)?);
    clean_jump.push(Instruction::with(Code::Popfq));
    clean_jump.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        options.true_oep_va,
    )?);
    blocks[IDX_CLEAN_JUMP] = clean_jump;

    let mut fail_trap = Vec::with_capacity(2);
    fail_trap.push(Instruction::with(Code::Int3));
    fail_trap.push(Instruction::with_branch(
        Code::Jmp_rel32_64,
        va(IDX_FAIL_TRAP),
    )?);
    blocks[IDX_FAIL_TRAP] = fail_trap;

    if use_obscure {
        let idx_obf = idx_obscure_setup.unwrap();
        let idx_handler = idx_veh_handler.unwrap();
        let idx_handler_search = idx_veh_handler_search.unwrap();
        let res_base = resolver_base.unwrap();

        let resolver_layout = ImportResolverLayout {
            module_check_va: va(res_base + 1),
            module_hash_loop_va: va(res_base + 2),
            module_hash_done_va: va(res_base + 3),
            name_loop_check_va: va(res_base + 4),
            name_hash_loop_va: va(res_base + 5),
            name_hash_done_va: va(res_base + 6),
            name_match_va: va(res_base + 7),
            next_name_va: va(res_base + 8),
            next_module_va: va(res_base + 9),
            not_found_va: va(res_base + 10),
        };
        let resolver = build_import_resolver_stub(resolver_layout)?;

        let mut obscure_setup = Vec::with_capacity(16);
        obscure_setup.push(Instruction::with2(
            Code::Mov_r64_imm64,
            Register::RCX,
            fnv1a64("ntdll.dll"),
        )?);
        obscure_setup.push(Instruction::with2(
            Code::Mov_r64_imm64,
            Register::RDX,
            fnv1a64("RtlAddVectoredExceptionHandler"),
        )?);
        obscure_setup.push(Instruction::with_branch(Code::Call_rel32_64, va(res_base))?);
        obscure_setup.push(Instruction::with2(
            Code::Test_rm64_r64,
            Register::RAX,
            Register::RAX,
        )?);
        obscure_setup.push(Instruction::with_branch(
            Code::Je_rel32_64,
            va(IDX_CLEAN_JUMP),
        )?);
        obscure_setup.push(Instruction::with2(Code::Mov_r64_imm64, Register::RCX, 1)?);
        obscure_setup.push(Instruction::with2(
            Code::Mov_r64_imm64,
            Register::RDX,
            va(idx_handler),
        )?);
        obscure_setup.push(Instruction::with2(
            Code::Sub_rm64_imm32,
            Register::RSP,
            0x20,
        )?);
        obscure_setup.push(Instruction::with1(Code::Call_rm64, Register::RAX)?);
        obscure_setup.push(Instruction::with2(
            Code::Add_rm64_imm32,
            Register::RSP,
            0x20,
        )?);
        obscure_setup.push(Instruction::with(Code::Int3));
        obscure_setup.push(Instruction::with_branch(
            Code::Jmp_rel32_64,
            va(IDX_CLEAN_JUMP),
        )?);
        blocks[idx_obf] = obscure_setup;

        let mut handler = Vec::with_capacity(12);
        handler.push(Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base(Register::RCX),
        )?);
        handler.push(Instruction::with2(
            Code::Cmp_rm32_imm32,
            MemoryOperand::with_base(Register::RAX),
            EXCEPTION_BREAKPOINT as i32,
        )?);
        handler.push(Instruction::with_branch(
            Code::Jne_rel32_64,
            va(idx_handler_search),
        )?);
        handler.push(Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base_displ(Register::RCX, 8),
        )?);
        handler.push(Instruction::with2(
            Code::Mov_r64_imm64,
            Register::RDX,
            options.true_oep_va,
        )?);
        handler.push(Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base_displ(Register::RAX, 0xF8),
            Register::RDX,
        )?);
        handler.push(Instruction::with2(
            Code::Mov_rm32_imm32,
            Register::EAX,
            EXCEPTION_CONTINUE_EXECUTION as i32,
        )?);
        handler.push(Instruction::with(Code::Retnq));
        blocks[idx_handler] = handler;

        let mut handler_search = Vec::with_capacity(3);
        handler_search.push(Instruction::with2(
            Code::Xor_rm32_r32,
            Register::EAX,
            Register::EAX,
        )?);
        handler_search.push(Instruction::with(Code::Retnq));
        blocks[idx_handler_search] = handler_search;

        blocks[res_base] = resolver.entry;
        blocks[res_base + 1] = resolver.module_check;
        blocks[res_base + 2] = resolver.module_hash_loop;
        blocks[res_base + 3] = resolver.module_hash_done;
        blocks[res_base + 4] = resolver.name_loop_check;
        blocks[res_base + 5] = resolver.name_hash_loop;
        blocks[res_base + 6] = resolver.name_hash_done;
        blocks[res_base + 7] = resolver.name_match;
        blocks[res_base + 8] = resolver.next_name;
        blocks[res_base + 9] = resolver.next_module;
        blocks[res_base + 10] = resolver.not_found;
    }

    let mut encoded_inputs = Vec::<InstructionBlock<'_>>::with_capacity(block_count);
    for (idx, insts) in blocks.iter().enumerate() {
        encoded_inputs.push(InstructionBlock::new(insts, va(idx)));
    }
    let encoded = BlockEncoder::encode_slice(64, &encoded_inputs, BlockEncoderOptions::NONE)?;

    let mut payload = vec![0u8; (block_count as u64 * PREENTRY_BLOCK_STRIDE) as usize];
    for (idx, enc_block) in encoded.into_iter().enumerate() {
        let offset = (idx as u64 * PREENTRY_BLOCK_STRIDE) as usize;
        let end = offset + enc_block.code_buffer.len();
        payload[offset..end].copy_from_slice(&enc_block.code_buffer);
    }
    while payload.last().is_some_and(|b| *b == 0) {
        payload.pop();
    }
    if payload.is_empty() {
        payload.push(0x90);
    }

    Ok(PreEntryStub { bytes: payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_preentry_antidebug_stub() {
        let stub = build_pre_entry_stub(
            0x14050_0000,
            PreEntryOptions::with_defaults(0x14010_1000, true, false),
        )
        .expect("preentry anti-debug stub should build");
        assert!(!stub.bytes.is_empty());
        assert!(stub.bytes.iter().any(|b| *b == 0xCC));
    }

    #[test]
    fn build_preentry_obscure_entry_stub() {
        let anti_only = build_pre_entry_stub(
            0x14060_0000,
            PreEntryOptions::with_defaults(0x14020_2000, true, false),
        )
        .expect("preentry anti-debug stub should build");
        let obscure = build_pre_entry_stub(
            0x14060_0000,
            PreEntryOptions::with_defaults(0x14020_2000, true, true),
        )
        .expect("preentry obscure-entry stub should build");
        assert!(obscure.bytes.len() > anti_only.bytes.len());
    }
}
