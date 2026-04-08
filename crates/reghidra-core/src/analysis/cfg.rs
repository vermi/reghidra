use crate::disasm::DisassembledInstruction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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

    /// Compute the function's address extent and instruction count from its
    /// reachable basic blocks.
    ///
    /// Returns `(size, instruction_count)` where `size` is
    /// `max_block_end - entry` and `instruction_count` is the total number
    /// of instructions across all blocks.
    pub fn extent(&self) -> (u64, usize) {
        let mut max_end = self.entry;
        let mut count = 0usize;
        for block in self.blocks.values() {
            if block.end_address > max_end {
                max_end = block.end_address;
            }
            count += block.instructions.len();
        }
        (max_end.saturating_sub(self.entry), count)
    }
}

/// Build a control flow graph for a function via reachability from its entry.
///
/// Starting at `entry`, this follows control flow (fallthrough, direct
/// branches, conditional branches) and stops at:
///   - `ret` instructions
///   - indirect branches (successor unknown)
///   - any branch target that happens to be another `known_entries` entry
///     (treated as a tail call to a separate function)
///
/// `calls` do not transfer control *within* the function — they fall through
/// to the instruction after the call.
pub fn build_cfg_from_entry(
    entry: u64,
    all_instructions: &[DisassembledInstruction],
    known_entries: &BTreeSet<u64>,
    addr_to_idx: &HashMap<u64, usize>,
) -> ControlFlowGraph {
    // ------------------------------------------------------------------
    // Step 1: reachability walk — collect every instruction address
    // that belongs to this function.
    // ------------------------------------------------------------------
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    let mut stack: Vec<u64> = vec![entry];

    while let Some(addr) = stack.pop() {
        if reachable.contains(&addr) {
            continue;
        }
        let Some(&idx) = addr_to_idx.get(&addr) else {
            continue;
        };
        reachable.insert(addr);
        let insn = &all_instructions[idx];

        if super::functions::is_return_instruction(&insn.mnemonic) {
            continue;
        }

        let fallthrough = insn.address + insn.bytes.len() as u64;

        if super::functions::is_unconditional_jump_mnemonic(&insn.mnemonic) {
            if let Some(target) = super::functions::parse_branch_target(&insn.operands) {
                if target == entry || !known_entries.contains(&target) {
                    stack.push(target);
                }
            }
            // Indirect jump (no imm target) is a sink.
            // No fallthrough after an unconditional jump.
            continue;
        }

        if is_conditional_branch(&insn.mnemonic) {
            if let Some(target) = super::functions::parse_branch_target(&insn.operands) {
                if target == entry || !known_entries.contains(&target) {
                    stack.push(target);
                }
            }
            if fallthrough == entry || !known_entries.contains(&fallthrough) {
                stack.push(fallthrough);
            }
            continue;
        }

        // Default (including call): fall through.
        if fallthrough == entry || !known_entries.contains(&fallthrough) {
            stack.push(fallthrough);
        }
    }

    if reachable.is_empty() {
        return ControlFlowGraph {
            entry,
            blocks: BTreeMap::new(),
            edges: Vec::new(),
            successors: HashMap::new(),
            predecessors: HashMap::new(),
        };
    }

    // ------------------------------------------------------------------
    // Step 2: identify block leaders within the reachable set.
    // ------------------------------------------------------------------
    let reachable_vec: Vec<u64> = reachable.iter().copied().collect();
    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(entry);

    for &addr in &reachable_vec {
        let idx = addr_to_idx[&addr];
        let insn = &all_instructions[idx];
        let fallthrough = insn.address + insn.bytes.len() as u64;

        if is_branch(&insn.mnemonic) {
            if let Some(target) = super::functions::parse_branch_target(&insn.operands) {
                if reachable.contains(&target) {
                    leaders.insert(target);
                }
            }
            if reachable.contains(&fallthrough) {
                leaders.insert(fallthrough);
            }
        } else if super::functions::is_return_instruction(&insn.mnemonic) {
            if reachable.contains(&fallthrough) {
                leaders.insert(fallthrough);
            }
        }
    }

    // ------------------------------------------------------------------
    // Step 3: build blocks. Each block extends from its leader through
    // contiguous reachable instructions, stopping at the next leader or
    // at a terminator.
    // ------------------------------------------------------------------
    let mut sorted_leaders: Vec<u64> = leaders.into_iter().collect();
    sorted_leaders.sort();

    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    for (li, &leader) in sorted_leaders.iter().enumerate() {
        let next_leader = sorted_leaders.get(li + 1).copied();

        let mut block_insns: Vec<DisassembledInstruction> = Vec::new();
        let Some(&start_idx) = addr_to_idx.get(&leader) else {
            continue;
        };
        let mut cur_idx = start_idx;

        loop {
            if cur_idx >= all_instructions.len() {
                break;
            }
            let insn = &all_instructions[cur_idx];
            if !reachable.contains(&insn.address) {
                break;
            }
            if let Some(nl) = next_leader {
                if insn.address >= nl {
                    break;
                }
            }
            let is_terminator = is_branch(&insn.mnemonic)
                || super::functions::is_return_instruction(&insn.mnemonic);
            block_insns.push(insn.clone());
            if is_terminator {
                break;
            }
            cur_idx += 1;
        }

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

    // ------------------------------------------------------------------
    // Step 4: build edges between blocks.
    // ------------------------------------------------------------------
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

        if super::functions::is_return_instruction(&last_insn.mnemonic) {
            continue;
        }

        if super::functions::is_unconditional_jump_mnemonic(&last_insn.mnemonic) {
            if let Some(target) = super::functions::parse_branch_target(&last_insn.operands) {
                if blocks.contains_key(&target) {
                    add_edge(
                        &mut edges,
                        &mut successors,
                        &mut predecessors,
                        block_addr,
                        target,
                        EdgeKind::Unconditional,
                    );
                }
            }
            continue;
        }

        if is_conditional_branch(&last_insn.mnemonic) {
            if let Some(target) = super::functions::parse_branch_target(&last_insn.operands) {
                if blocks.contains_key(&target) {
                    add_edge(
                        &mut edges,
                        &mut successors,
                        &mut predecessors,
                        block_addr,
                        target,
                        EdgeKind::ConditionalTrue,
                    );
                }
            }
            let fallthrough = block.end_address;
            if blocks.contains_key(&fallthrough) {
                add_edge(
                    &mut edges,
                    &mut successors,
                    &mut predecessors,
                    block_addr,
                    fallthrough,
                    EdgeKind::ConditionalFalse,
                );
            }
            continue;
        }

        // Default: fallthrough to next block (covers call and ordinary insn).
        let fallthrough = block.end_address;
        if blocks.contains_key(&fallthrough) {
            add_edge(
                &mut edges,
                &mut successors,
                &mut predecessors,
                block_addr,
                fallthrough,
                EdgeKind::Unconditional,
            );
        }
    }

    ControlFlowGraph {
        entry,
        blocks,
        edges,
        successors,
        predecessors,
    }
}

fn add_edge(
    edges: &mut Vec<CfgEdge>,
    successors: &mut HashMap<u64, Vec<u64>>,
    predecessors: &mut HashMap<u64, Vec<u64>>,
    from: u64,
    to: u64,
    kind: EdgeKind,
) {
    edges.push(CfgEdge { from, to, kind });
    successors.entry(from).or_default().push(to);
    predecessors.entry(to).or_default().push(from);
}

fn is_branch(mnemonic: &str) -> bool {
    super::functions::is_unconditional_jump_mnemonic(mnemonic)
        || is_conditional_branch(mnemonic)
        || is_call(mnemonic)
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
    matches!(
        m,
        "beq" | "bne"
            | "blt" | "bgt"
            | "ble" | "bge"
            | "blo" | "bhi"
            | "bls" | "bhs"
            | "bmi" | "bpl"
            | "bvs" | "bvc"
            | "bcc" | "bcs"
    )
}

fn is_call(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "call" | "bl" | "blr" | "blx" | "jal" | "jalr" | "bctrl"
    )
}
