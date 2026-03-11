use crate::op::{IrOp, VarNode};
use crate::types::IrFunction;
use std::collections::{HashMap, HashSet};

/// Run all optimization passes on a function.
pub fn optimize(func: &mut IrFunction) {
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 10 {
        changed = false;
        changed |= constant_fold(func);
        changed |= copy_propagation(func);
        changed |= dead_code_elimination(func);
        changed |= remove_nops(func);
        iterations += 1;
    }
}

/// Constant folding: evaluate operations on constants at compile time.
fn constant_fold(func: &mut IrFunction) -> bool {
    let mut changed = false;

    for block in &mut func.blocks {
        for insn in &mut block.instructions {
            let folded = match &insn.op {
                IrOp::IntAdd { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset.wrapping_add(b.offset);
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntSub { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset.wrapping_sub(b.offset);
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntMul { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset.wrapping_mul(b.offset);
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntAnd { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset & b.offset;
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntOr { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset | b.offset;
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntXor { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset ^ b.offset;
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntShl { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset.wrapping_shl(b.offset as u32);
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntShr { dst, a, b } if a.is_const() && b.is_const() => {
                    let val = a.offset.wrapping_shr(b.offset as u32);
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntNeg { dst, src } if src.is_const() => {
                    let val = (src.offset as i64).wrapping_neg() as u64;
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                IrOp::IntNot { dst, src } if src.is_const() => {
                    let val = !src.offset;
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(val, dst.size) })
                }
                // Identity operations
                IrOp::IntAdd { dst, a, b } if b.is_const() && b.offset == 0 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: a.clone() })
                }
                IrOp::IntSub { dst, a, b } if b.is_const() && b.offset == 0 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: a.clone() })
                }
                IrOp::IntMul { dst, a, b } if b.is_const() && b.offset == 1 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: a.clone() })
                }
                IrOp::IntMul { dst, a: _, b } if b.is_const() && b.offset == 0 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(0, dst.size) })
                }
                IrOp::IntAnd { dst, a: _, b } if b.is_const() && b.offset == 0 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: VarNode::constant(0, dst.size) })
                }
                IrOp::IntOr { dst, a, b } if b.is_const() && b.offset == 0 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: a.clone() })
                }
                IrOp::IntXor { dst, a, b } if b.is_const() && b.offset == 0 => {
                    Some(IrOp::Copy { dst: dst.clone(), src: a.clone() })
                }
                // Copy of self is a nop
                IrOp::Copy { dst, src } if dst == src => {
                    Some(IrOp::Nop)
                }
                _ => None,
            };

            if let Some(new_op) = folded {
                insn.op = new_op;
                changed = true;
            }
        }
    }

    changed
}

/// Copy propagation: replace uses of `t = COPY x` with `x` directly.
fn copy_propagation(func: &mut IrFunction) -> bool {
    let mut changed = false;

    // Build a map of simple copies: temp -> source
    let mut copies: HashMap<VarNode, VarNode> = HashMap::new();

    for block in &func.blocks {
        for insn in &block.instructions {
            if let IrOp::Copy { dst, src } = &insn.op {
                if dst.is_temp() && !src.is_temp() {
                    copies.insert(dst.clone(), src.clone());
                } else if dst.is_temp() && src.is_const() {
                    copies.insert(dst.clone(), src.clone());
                }
            }
        }
    }

    if copies.is_empty() {
        return false;
    }

    // Resolve chains: if t0 = COPY t1, t1 = COPY x => t0 -> x
    let mut resolved: HashMap<VarNode, VarNode> = HashMap::new();
    for (dst, src) in &copies {
        let mut current = src.clone();
        let mut depth = 0;
        while let Some(next) = copies.get(&current) {
            current = next.clone();
            depth += 1;
            if depth > 10 { break; }
        }
        resolved.insert(dst.clone(), current);
    }

    // Replace uses
    for block in &mut func.blocks {
        for insn in &mut block.instructions {
            let sources = insn.op.sources().into_iter().cloned().collect::<Vec<_>>();
            for src in &sources {
                if let Some(replacement) = resolved.get(src) {
                    if replace_source(&mut insn.op, src, replacement) {
                        changed = true;
                    }
                }
            }
        }
    }

    changed
}

/// Dead code elimination: remove instructions whose results are never used.
fn dead_code_elimination(func: &mut IrFunction) -> bool {
    // Collect all used varnodes
    let mut used: HashSet<VarNode> = HashSet::new();

    // First pass: collect all sources (reads)
    for block in &func.blocks {
        for insn in &block.instructions {
            // Terminators and stores always have side effects
            if insn.op.is_terminator() || matches!(insn.op, IrOp::Store { .. } | IrOp::Call { .. } | IrOp::CallInd { .. }) {
                for src in insn.op.sources() {
                    used.insert(src.clone());
                }
            } else {
                for src in insn.op.sources() {
                    used.insert(src.clone());
                }
            }
        }
    }

    // Second pass: remove instructions that write to unused temps
    let mut changed = false;
    for block in &mut func.blocks {
        for insn in &mut block.instructions {
            if let Some(dst) = insn.op.dst() {
                if dst.is_temp() && !used.contains(dst) {
                    insn.op = IrOp::Nop;
                    changed = true;
                }
            }
        }
    }

    changed
}

/// Remove NOP instructions.
fn remove_nops(func: &mut IrFunction) -> bool {
    let mut changed = false;
    for block in &mut func.blocks {
        let before = block.instructions.len();
        block.instructions.retain(|insn| !matches!(insn.op, IrOp::Nop));
        if block.instructions.len() < before {
            changed = true;
        }
    }
    changed
}

/// Replace a source varnode within an IrOp. Returns true if a replacement was made.
fn replace_source(op: &mut IrOp, from: &VarNode, to: &VarNode) -> bool {
    let mut did_replace = false;

    macro_rules! try_replace {
        ($field:expr) => {
            if *$field == *from {
                *$field = to.clone();
                did_replace = true;
            }
        };
    }

    match op {
        IrOp::Copy { src, .. } => { try_replace!(src); }
        IrOp::Load { addr, .. } => { try_replace!(addr); }
        IrOp::Store { addr, src } => { try_replace!(addr); try_replace!(src); }
        IrOp::IntAdd { a, b, .. } | IrOp::IntSub { a, b, .. }
        | IrOp::IntMul { a, b, .. } | IrOp::IntDiv { a, b, .. }
        | IrOp::IntRem { a, b, .. } | IrOp::IntSMul { a, b, .. }
        | IrOp::IntSDiv { a, b, .. } | IrOp::IntSRem { a, b, .. }
        | IrOp::IntAnd { a, b, .. } | IrOp::IntOr { a, b, .. }
        | IrOp::IntXor { a, b, .. } | IrOp::IntShl { a, b, .. }
        | IrOp::IntShr { a, b, .. } | IrOp::IntSar { a, b, .. }
        | IrOp::IntEqual { a, b, .. } | IrOp::IntNotEqual { a, b, .. }
        | IrOp::IntLess { a, b, .. } | IrOp::IntLessEqual { a, b, .. }
        | IrOp::IntSLess { a, b, .. } | IrOp::IntSLessEqual { a, b, .. } => {
            try_replace!(a); try_replace!(b);
        }
        IrOp::IntNeg { src, .. } | IrOp::IntNot { src, .. }
        | IrOp::IntZext { src, .. } | IrOp::IntSext { src, .. }
        | IrOp::Subpiece { src, .. } => {
            try_replace!(src);
        }
        IrOp::CBranch { cond, .. } => { try_replace!(cond); }
        IrOp::CallInd { target } | IrOp::BranchInd { target } => { try_replace!(target); }
        IrOp::Return { value } => {
            if let crate::op::Operand::Var(v) = value {
                try_replace!(v);
            }
        }
        IrOp::Phi { inputs, .. } => {
            for input in inputs {
                try_replace!(input);
            }
        }
        _ => {}
    }

    did_replace
}
