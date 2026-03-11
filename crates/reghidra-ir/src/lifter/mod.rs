pub mod arm64;
pub mod x86_64;

use crate::op::{IrOp, VarNode};
use crate::types::IrBlock;

/// Context for the lifter to emit IR instructions.
pub struct LiftContext {
    temp_counter: u64,
    current_block: IrBlock,
    blocks: Vec<IrBlock>,
    current_address: u64,
    sub_index: u16,
}

impl LiftContext {
    pub fn new(entry_address: u64) -> Self {
        Self {
            temp_counter: 0,
            current_block: IrBlock::new(entry_address),
            blocks: Vec::new(),
            current_address: entry_address,
            sub_index: 0,
        }
    }

    /// Allocate a fresh temporary varnode.
    pub fn new_temp(&mut self, size: u8) -> VarNode {
        let id = self.temp_counter;
        self.temp_counter += 1;
        VarNode::temp(id, size)
    }

    /// Set the current source address for subsequent emissions.
    pub fn set_address(&mut self, addr: u64) {
        self.current_address = addr;
        self.sub_index = 0;
    }

    /// Emit an IR operation at the current address.
    pub fn emit(&mut self, op: IrOp) {
        self.current_block.push(self.current_address, self.sub_index, op);
        self.sub_index += 1;
    }

    /// Start a new basic block at the given address.
    pub fn start_block(&mut self, addr: u64) {
        if !self.current_block.is_empty() {
            let finished = std::mem::replace(&mut self.current_block, IrBlock::new(addr));
            self.blocks.push(finished);
        } else {
            self.current_block = IrBlock::new(addr);
        }
    }

    /// Finalize and return all blocks.
    pub fn finish(mut self) -> Vec<IrBlock> {
        if !self.current_block.is_empty() {
            self.blocks.push(self.current_block);
        }
        self.blocks
    }
}

/// Input: a disassembled instruction to lift.
pub struct DisasmInput {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
}
