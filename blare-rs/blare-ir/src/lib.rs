use iced_x86::Instruction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Terminator {
    Return,
    UnconditionalBranch { target: u64 },
    ConditionalBranch { target: u64, fallthrough: u64 },
    DirectCall { target: u64 },
    IndirectCall,
    IndirectBranch,
    Trap,
    Fallthrough,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Call,
    Branch,
    Fallthrough,
    IndirectCall,
    IndirectJump,
    JumpTable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: BlockId,
    pub to: Option<BlockId>,
    pub target_rva: Option<u64>,
    pub kind: EdgeKind,
    pub indirect: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndirectThunkKind {
    Call,
    Branch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub name: String,
    pub rva: u64,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataObject {
    pub name: String,
    pub rva: u64,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectThunkRecord {
    pub function: FunctionId,
    pub block: BlockId,
    pub kind: IndirectThunkKind,
    pub target_rva: u64,
    pub load_entry_rva: u64,
    pub decode_key: i32,
}

#[derive(Debug, Clone)]
pub struct InstData {
    pub id: InstId,
    pub original_rva: u64,
    pub instruction: Instruction,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    pub function: FunctionId,
    pub start_rva: u64,
    pub end_rva: u64,
    pub insts: Vec<InstId>,
    pub terminator: Terminator,
    pub outgoing_edges: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub id: FunctionId,
    pub name: String,
    pub address_rva: u64,
    pub blocks: Vec<BlockId>,
    pub fallback: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PassStatsRecord {
    pub name: String,
    pub mutated_functions: usize,
    pub mutated_blocks: usize,
    pub mutated_instructions: usize,
    pub injected_blocks: usize,
    pub skipped_sites: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockLayoutStrategy {
    #[default]
    SortedByRva,
    PreserveFunctionOrder,
}

#[derive(Debug, Clone, Default)]
pub struct ProgramIr {
    pub image_base: u64,
    pub functions: Vec<Function>,
    pub blocks: Vec<Block>,
    pub insts: Vec<InstData>,
    pub edges: Vec<Edge>,
    pub symbols: Vec<SymbolRecord>,
    pub data_objects: Vec<DataObject>,
    pub indirect_thunks: Vec<IndirectThunkRecord>,
    pub applied_passes: Vec<String>,
    pub obfuscation_profile: Option<String>,
    pub obfuscation_seed: Option<u64>,
    pub pass_stats: Vec<PassStatsRecord>,
    pub block_layout_strategy: BlockLayoutStrategy,
}

impl ProgramIr {
    pub fn new(image_base: u64) -> Self {
        Self {
            image_base,
            ..Self::default()
        }
    }

    pub fn add_function(&mut self, name: impl Into<String>, address_rva: u64) -> FunctionId {
        let id = FunctionId(self.functions.len());
        self.functions.push(Function {
            id,
            name: name.into(),
            address_rva,
            blocks: Vec::new(),
            fallback: false,
        });
        id
    }

    pub fn add_block(&mut self, function: FunctionId, start_rva: u64, end_rva: u64) -> BlockId {
        let id = BlockId(self.blocks.len());
        self.blocks.push(Block {
            id,
            function,
            start_rva,
            end_rva,
            insts: Vec::new(),
            terminator: Terminator::Unknown,
            outgoing_edges: Vec::new(),
        });
        self.functions[function.0].blocks.push(id);
        id
    }

    pub fn add_instruction(
        &mut self,
        block: BlockId,
        original_rva: u64,
        instruction: Instruction,
    ) -> InstId {
        let id = InstId(self.insts.len());
        self.insts.push(InstData {
            id,
            original_rva,
            instruction,
        });
        self.blocks[block.0].insts.push(id);
        id
    }

    pub fn function(&self, id: FunctionId) -> &Function {
        &self.functions[id.0]
    }

    pub fn function_mut(&mut self, id: FunctionId) -> &mut Function {
        &mut self.functions[id.0]
    }

    pub fn block(&self, id: BlockId) -> &Block {
        &self.blocks[id.0]
    }

    pub fn block_mut(&mut self, id: BlockId) -> &mut Block {
        &mut self.blocks[id.0]
    }

    pub fn inst(&self, id: InstId) -> &InstData {
        &self.insts[id.0]
    }

    pub fn add_edge(
        &mut self,
        from: BlockId,
        to: Option<BlockId>,
        target_rva: Option<u64>,
        kind: EdgeKind,
        indirect: bool,
    ) -> usize {
        let edge_id = self.edges.len();
        self.edges.push(Edge {
            from,
            to,
            target_rva,
            kind,
            indirect,
        });
        self.blocks[from.0].outgoing_edges.push(edge_id);
        edge_id
    }

    pub fn add_symbol(&mut self, name: impl Into<String>, rva: u64, kind: SymbolKind) {
        self.symbols.push(SymbolRecord {
            name: name.into(),
            rva,
            kind,
        });
    }

    pub fn add_data_object(&mut self, name: impl Into<String>, rva: u64, size: u32) {
        self.data_objects.push(DataObject {
            name: name.into(),
            rva,
            size,
        });
    }

    pub fn add_indirect_thunk_record(
        &mut self,
        function: FunctionId,
        block: BlockId,
        kind: IndirectThunkKind,
        target_rva: u64,
        load_entry_rva: u64,
        decode_key: i32,
    ) {
        self.indirect_thunks.push(IndirectThunkRecord {
            function,
            block,
            kind,
            target_rva,
            load_entry_rva,
            decode_key,
        });
    }

    pub fn record_applied_pass(&mut self, pass_name: &'static str) {
        if !self.applied_passes.iter().any(|name| name == pass_name) {
            self.applied_passes.push(pass_name.to_string());
        }
    }

    pub fn set_obfuscation_context(&mut self, profile: &str, seed: u64) {
        self.obfuscation_profile = Some(profile.to_string());
        self.obfuscation_seed = Some(seed);
    }

    pub fn record_pass_stats(&mut self, stats: PassStatsRecord) {
        self.pass_stats.push(stats);
    }

    pub fn request_preserve_function_block_order(&mut self) {
        self.block_layout_strategy = BlockLayoutStrategy::PreserveFunctionOrder;
    }
}
