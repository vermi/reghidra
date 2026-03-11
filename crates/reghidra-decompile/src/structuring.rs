use crate::ast::{Expr, Stmt};
use crate::expr_builder::varnode_to_expr;
use crate::DecompileContext;
use reghidra_ir::op::IrOp;
use reghidra_ir::IrFunction;
use std::collections::{HashMap, HashSet};

/// Structure the control flow of an IR function into nested statements.
///
/// This uses a simplified structural analysis:
/// 1. Process blocks in order
/// 2. Convert conditional branches into if/else
/// 3. Detect back-edges for while loops
/// 4. Fall through to goto for complex/irreducible flow
pub fn structure(
    ir: &IrFunction,
    block_stmts: &HashMap<u64, Vec<Stmt>>,
    ctx: &DecompileContext,
) -> Vec<Stmt> {
    if ir.blocks.is_empty() {
        return Vec::new();
    }

    let block_addrs: Vec<u64> = ir.blocks.iter().map(|b| b.address).collect();
    let _block_set: HashSet<u64> = block_addrs.iter().copied().collect();

    // Detect back-edges (loops): an edge where target <= source in block ordering
    let block_order: HashMap<u64, usize> = block_addrs
        .iter()
        .enumerate()
        .map(|(i, &a)| (a, i))
        .collect();

    let mut loop_headers: HashSet<u64> = HashSet::new();
    for block in &ir.blocks {
        let last_op = block.instructions.last().map(|i| &i.op);
        match last_op {
            Some(IrOp::Branch { target }) => {
                if let (Some(&src_ord), Some(&tgt_ord)) =
                    (block_order.get(&block.address), block_order.get(target))
                {
                    if tgt_ord <= src_ord {
                        loop_headers.insert(*target);
                    }
                }
            }
            Some(IrOp::CBranch { target, .. }) => {
                if let (Some(&src_ord), Some(&tgt_ord)) =
                    (block_order.get(&block.address), block_order.get(target))
                {
                    if tgt_ord <= src_ord {
                        loop_headers.insert(*target);
                    }
                }
            }
            _ => {}
        }
    }

    // Build structured output by walking blocks in order
    let mut output = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();

    structure_region(
        &block_addrs,
        0,
        block_addrs.len(),
        ir,
        block_stmts,
        ctx,
        &block_order,
        &loop_headers,
        &mut visited,
        &mut output,
    );

    output
}

fn structure_region(
    block_addrs: &[u64],
    start: usize,
    end: usize,
    ir: &IrFunction,
    block_stmts: &HashMap<u64, Vec<Stmt>>,
    ctx: &DecompileContext,
    block_order: &HashMap<u64, usize>,
    loop_headers: &HashSet<u64>,
    visited: &mut HashSet<u64>,
    output: &mut Vec<Stmt>,
) {
    let mut i = start;
    while i < end {
        let addr = block_addrs[i];
        if visited.contains(&addr) {
            i += 1;
            continue;
        }
        visited.insert(addr);

        let block = match ir.blocks.iter().find(|b| b.address == addr) {
            Some(b) => b,
            None => { i += 1; continue; }
        };

        // Check if this is a loop header
        if loop_headers.contains(&addr) {
            let loop_body = structure_loop(
                addr, block_addrs, i, end, ir, block_stmts, ctx,
                block_order, loop_headers, visited,
            );
            output.push(Stmt::While {
                cond: Expr::IntLit(1, crate::ast::CType::Int32), // while(true) for now
                body: loop_body,
            });
            // Skip past blocks that were consumed by the loop
            while i < end && visited.contains(&block_addrs[i]) {
                i += 1;
            }
            continue;
        }

        // Emit the block's statements with source address marker
        if let Some(stmts) = block_stmts.get(&addr) {
            output.push(Stmt::SourceAddr(addr));
            output.extend(stmts.iter().cloned());
        }

        // Handle the block terminator
        let last_op = block.instructions.last().map(|insn| &insn.op);

        match last_op {
            Some(IrOp::CBranch { cond, target }) => {
                let cond_expr = varnode_to_expr(cond);

                let target_order = block_order.get(target).copied();
                let _fallthrough = block_addrs.get(i + 1).copied();

                // Check if target is a back-edge (loop continue/break)
                if let Some(tgt_ord) = target_order {
                    if tgt_ord <= i {
                        // Back-edge: this is a loop continue or conditional break
                        if loop_headers.contains(target) {
                            output.push(Stmt::If {
                                cond: cond_expr,
                                then_body: vec![Stmt::Continue],
                                else_body: vec![],
                            });
                        } else {
                            output.push(Stmt::If {
                                cond: cond_expr,
                                then_body: vec![Stmt::Goto(*target)],
                                else_body: vec![],
                            });
                        }
                        i += 1;
                        continue;
                    }
                }

                // Forward conditional: build if/else
                let then_body = if let Some(tgt_ord) = target_order {
                    if tgt_ord < end && !visited.contains(target) {
                        // The target block becomes the "then" branch
                        let mut then_stmts = Vec::new();
                        // Simple case: just emit the target block
                        if let Some(stmts) = block_stmts.get(target) {
                            then_stmts.push(Stmt::SourceAddr(*target));
                            then_stmts.extend(stmts.iter().cloned());
                        }
                        visited.insert(*target);
                        then_stmts
                    } else {
                        vec![Stmt::Goto(*target)]
                    }
                } else {
                    vec![Stmt::Goto(*target)]
                };

                if !then_body.is_empty() {
                    output.push(Stmt::If {
                        cond: cond_expr,
                        then_body,
                        else_body: vec![],
                    });
                }
            }
            Some(IrOp::Branch { target }) => {
                // Check for back-edge
                if let Some(&tgt_ord) = block_order.get(target) {
                    if tgt_ord <= i {
                        if loop_headers.contains(target) {
                            // Loop back-edge: handled by the loop structure
                        } else {
                            output.push(Stmt::Goto(*target));
                        }
                    } else {
                        // Forward jump: if it's not to the next block, emit goto
                        let next = block_addrs.get(i + 1).copied();
                        if next != Some(*target) {
                            output.push(Stmt::Goto(*target));
                        }
                    }
                }
            }
            _ => {
                // Fallthrough or return (already handled in statements)
            }
        }

        i += 1;
    }
}

fn structure_loop(
    header: u64,
    block_addrs: &[u64],
    start: usize,
    end: usize,
    ir: &IrFunction,
    block_stmts: &HashMap<u64, Vec<Stmt>>,
    ctx: &DecompileContext,
    block_order: &HashMap<u64, usize>,
    loop_headers: &HashSet<u64>,
    visited: &mut HashSet<u64>,
) -> Vec<Stmt> {
    // Find the extent of the loop: all blocks from header to the last back-edge source
    let mut loop_end = start + 1;
    for (bi, &addr) in block_addrs.iter().enumerate() {
        if bi <= start { continue; }
        if bi >= end { break; }
        let block = match ir.blocks.iter().find(|b| b.address == addr) {
            Some(b) => b,
            None => continue,
        };
        let last_op = block.instructions.last().map(|i| &i.op);
        match last_op {
            Some(IrOp::Branch { target }) if *target == header => {
                loop_end = bi + 1;
            }
            Some(IrOp::CBranch { target, .. }) if *target == header => {
                loop_end = bi + 1;
            }
            _ => {}
        }
    }

    let mut body = Vec::new();
    structure_region(
        block_addrs, start, loop_end, ir, block_stmts, ctx,
        block_order, loop_headers, visited, &mut body,
    );

    // Add a break at the end to prevent infinite loop representation
    // (The actual loop condition should ideally come from the CBranch)
    if !body.iter().any(|s| matches!(s, Stmt::Return(_) | Stmt::Break)) {
        body.push(Stmt::Break);
    }

    body
}
