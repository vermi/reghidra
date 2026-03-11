use crate::analysis::functions::Function;
use crate::disasm::DisassembledInstruction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// A basic block: a straight-line sequence of instructions with
/// one entry point and one exit point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Address of the first instruction.
    pub start_address: u64,
    /// Address past the last instruction (exclusive end).
    pub end_address: u64,
    /// Instructions in this block.
    pub instructions: Vec<DisassembledInstruction>,
}

/// An edge in the control flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u64,
    pub to: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Unconditional flow (fallthrough or unconditional jump).
    Unconditional,
    /// True branch of a conditional.
    ConditionalTrue,
    /// False/fallthrough branch of a conditional.
    ConditionalFalse,
}

/// Control flow graph for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    /// Entry block address.
    pub entry: u64,
    /// Basic blocks keyed by start address.
    pub blocks: BTreeMap<u64, BasicBlock>,
    /// Edges between blocks.
    pub edges: Vec<CfgEdge>,
    /// Successors of each block.
    pub successors: HashMap<u64, Vec<u64>>,
    /// Predecessors of each block.
    pub predecessors: HashMap<u64, Vec<u64>>,
}

impl ControlFlowGraph {
    /// Get a block by its start address.
    pub fn block(&self, addr: u64) -> Option<&BasicBlock> {
        self.blocks.get(&addr)
    }

    /// Get successor block addresses for a block.
    pub fn succs(&self, block_addr: u64) -> &[u64] {
        self.successors
            .get(&block_addr)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get predecessor block addresses for a block.
    pub fn preds(&self, block_addr: u64) -> &[u64] {
        self.predecessors
            .get(&block_addr)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Number of basic blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// Build a control flow graph for a function.
pub fn build_cfg(
    function: &Function,
    all_instructions: &[DisassembledInstruction],
) -> ControlFlowGraph {
    let func_start = function.entry_address;
    let func_end = function.entry_address + function.size;

    // Extract instructions belonging to this function
    let func_insns: Vec<&DisassembledInstruction> = all_instructions
        .iter()
        .filter(|i| i.address >= func_start && i.address < func_end)
        .collect();

    if func_insns.is_empty() {
        return ControlFlowGraph {
            entry: func_start,
            blocks: BTreeMap::new(),
            edges: Vec::new(),
            successors: HashMap::new(),
            predecessors: HashMap::new(),
        };
    }

    // Step 1: Identify block leaders (first instruction of each basic block)
    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(func_start); // Function entry is always a leader

    for (i, insn) in func_insns.iter().enumerate() {
        if is_branch(&insn.mnemonic) {
            // Target of a branch is a leader
            if let Some(target) = super::functions::parse_branch_target(&insn.operands) {
                if target >= func_start && target < func_end {
                    leaders.insert(target);
                }
            }

            // Instruction after a branch is a leader (fallthrough)
            if i + 1 < func_insns.len() {
                leaders.insert(func_insns[i + 1].address);
            }
        }

        if is_return(&insn.mnemonic) {
            // Instruction after a return is a leader
            if i + 1 < func_insns.len() {
                leaders.insert(func_insns[i + 1].address);
            }
        }
    }

    // Step 2: Build basic blocks
    let mut sorted_leaders: Vec<u64> = leaders.into_iter().collect();
    sorted_leaders.sort();

    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();

    for (li, &leader) in sorted_leaders.iter().enumerate() {
        let next_leader = sorted_leaders.get(li + 1).copied().unwrap_or(func_end);

        let block_insns: Vec<DisassembledInstruction> = func_insns
            .iter()
            .filter(|i| i.address >= leader && i.address < next_leader)
            .map(|i| (*i).clone())
            .collect();

        if block_insns.is_empty() {
            continue;
        }

        let last = block_insns.last().unwrap();
        let end_address = last.address + last.bytes.len() as u64;

        blocks.insert(
            leader,
            BasicBlock {
                start_address: leader,
                end_address,
                instructions: block_insns,
            },
        );
    }

    // Step 3: Build edges
    let mut edges = Vec::new();
    let mut successors: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut predecessors: HashMap<u64, Vec<u64>> = HashMap::new();

    let block_addrs: Vec<u64> = blocks.keys().copied().collect();

    for &block_addr in &block_addrs {
        let block = &blocks[&block_addr];
        let last_insn = match block.instructions.last() {
            Some(i) => i,
            None => continue,
        };

        if is_return(&last_insn.mnemonic) {
            // No successors for return
            continue;
        }

        if is_unconditional_jump(&last_insn.mnemonic) {
            if let Some(target) = super::functions::parse_branch_target(&last_insn.operands) {
                if blocks.contains_key(&target) {
                    edges.push(CfgEdge {
                        from: block_addr,
                        to: target,
                        kind: EdgeKind::Unconditional,
                    });
                    successors.entry(block_addr).or_default().push(target);
                    predecessors.entry(target).or_default().push(block_addr);
                }
            }
            continue;
        }

        if is_conditional_branch(&last_insn.mnemonic) {
            // True branch (taken)
            if let Some(target) = super::functions::parse_branch_target(&last_insn.operands) {
                if blocks.contains_key(&target) {
                    edges.push(CfgEdge {
                        from: block_addr,
                        to: target,
                        kind: EdgeKind::ConditionalTrue,
                    });
                    successors.entry(block_addr).or_default().push(target);
                    predecessors.entry(target).or_default().push(block_addr);
                }
            }

            // False branch (fallthrough)
            let fallthrough = block.end_address;
            if blocks.contains_key(&fallthrough) {
                edges.push(CfgEdge {
                    from: block_addr,
                    to: fallthrough,
                    kind: EdgeKind::ConditionalFalse,
                });
                successors.entry(block_addr).or_default().push(fallthrough);
                predecessors
                    .entry(fallthrough)
                    .or_default()
                    .push(block_addr);
            }
            continue;
        }

        // Default: fallthrough to next block
        let fallthrough = block.end_address;
        if blocks.contains_key(&fallthrough) {
            edges.push(CfgEdge {
                from: block_addr,
                to: fallthrough,
                kind: EdgeKind::Unconditional,
            });
            successors.entry(block_addr).or_default().push(fallthrough);
            predecessors
                .entry(fallthrough)
                .or_default()
                .push(block_addr);
        }
    }

    ControlFlowGraph {
        entry: func_start,
        blocks,
        edges,
        successors,
        predecessors,
    }
}

fn is_branch(mnemonic: &str) -> bool {
    is_unconditional_jump(mnemonic) || is_conditional_branch(mnemonic) || is_call(mnemonic)
}

fn is_unconditional_jump(mnemonic: &str) -> bool {
    matches!(mnemonic, "jmp" | "b" | "j" | "ba")
}

fn is_conditional_branch(mnemonic: &str) -> bool {
    let m = mnemonic;
    // x86 conditional jumps
    if m.starts_with('j') && m != "jmp" && m != "jal" && m != "jalr" {
        return true;
    }
    // ARM conditional branches
    if m.starts_with("b.") || m.starts_with("cb") || m.starts_with("tb") {
        return true;
    }
    matches!(m, "beq" | "bne" | "blt" | "bgt" | "ble" | "bge"
        | "blo" | "bhi" | "bls" | "bhs" | "bmi" | "bpl"
        | "bvs" | "bvc" | "bcc" | "bcs")
}

fn is_return(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ret" | "retq" | "retn" | "retf" | "iret" | "iretd" | "iretq"
    )
}

fn is_call(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "call" | "bl" | "blr" | "blx" | "jal" | "jalr" | "bctrl"
    )
}
