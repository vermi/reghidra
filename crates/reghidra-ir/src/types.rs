use crate::op::IrOp;
use serde::{Deserialize, Serialize};

/// A single IR instruction, mapped back to a source address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInstruction {
    /// The original machine instruction address this was lifted from.
    pub address: u64,
    /// Sub-index within the same address (one machine insn can produce multiple IR ops).
    pub sub_index: u16,
    /// The IR operation.
    pub op: IrOp,
}

/// A basic block in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrBlock {
    /// Block entry address.
    pub address: u64,
    /// IR instructions in this block.
    pub instructions: Vec<IrInstruction>,
}

impl IrBlock {
    pub fn new(address: u64) -> Self {
        Self {
            address,
            instructions: Vec::new(),
        }
    }

    pub fn push(&mut self, address: u64, sub_index: u16, op: IrOp) {
        self.instructions.push(IrInstruction {
            address,
            sub_index,
            op,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }
}

/// A lifted function in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrFunction {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_address: u64,
    /// IR basic blocks, ordered by address.
    pub blocks: Vec<IrBlock>,
}

impl IrFunction {
    pub fn new(name: String, entry_address: u64) -> Self {
        Self {
            name,
            entry_address,
            blocks: Vec::new(),
        }
    }

    /// Total number of IR instructions across all blocks.
    pub fn instruction_count(&self) -> usize {
        self.blocks.iter().map(|b| b.len()).sum()
    }
}
