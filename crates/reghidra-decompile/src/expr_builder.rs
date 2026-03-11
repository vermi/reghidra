use crate::ast::{BinOp, CType, Expr, Stmt, UnaryOp};
use crate::DecompileContext;
use reghidra_ir::op::{IrOp, VarNode, VarSpace};
use reghidra_ir::IrFunction;
use std::collections::HashMap;

/// Convert IR blocks into statement lists keyed by block address.
pub fn build_statements(
    ir: &IrFunction,
    ctx: &DecompileContext,
) -> HashMap<u64, Vec<Stmt>> {
    let mut result = HashMap::new();

    for block in &ir.blocks {
        let mut stmts = Vec::new();

        for insn in &block.instructions {
            match &insn.op {
                IrOp::Copy { dst, src } => {
                    let lhs = varnode_to_expr(dst);
                    let rhs = varnode_to_expr(src);
                    stmts.push(Stmt::Assign(lhs, rhs));
                }
                IrOp::Load { dst, addr } => {
                    let lhs = varnode_to_expr(dst);
                    let rhs = Expr::Deref(
                        Box::new(varnode_to_expr(addr)),
                        CType::from_size(dst.size, false),
                    );
                    stmts.push(Stmt::Assign(lhs, rhs));
                }
                IrOp::Store { addr, src } => {
                    let lhs = Expr::Deref(
                        Box::new(varnode_to_expr(addr)),
                        CType::from_size(src.size, false),
                    );
                    let rhs = varnode_to_expr(src);
                    stmts.push(Stmt::Assign(lhs, rhs));
                }
                IrOp::IntAdd { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::Add),
                IrOp::IntSub { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::Sub),
                IrOp::IntMul { dst, a, b } | IrOp::IntSMul { dst, a, b } => {
                    emit_binop(&mut stmts, dst, a, b, BinOp::Mul);
                }
                IrOp::IntDiv { dst, a, b } | IrOp::IntSDiv { dst, a, b } => {
                    emit_binop(&mut stmts, dst, a, b, BinOp::Div);
                }
                IrOp::IntRem { dst, a, b } | IrOp::IntSRem { dst, a, b } => {
                    emit_binop(&mut stmts, dst, a, b, BinOp::Mod);
                }
                IrOp::IntAnd { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::BitAnd),
                IrOp::IntOr { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::BitOr),
                IrOp::IntXor { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::BitXor),
                IrOp::IntShl { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::Shl),
                IrOp::IntShr { dst, a, b } | IrOp::IntSar { dst, a, b } => {
                    emit_binop(&mut stmts, dst, a, b, BinOp::Shr);
                }
                IrOp::IntNeg { dst, src } => {
                    stmts.push(Stmt::Assign(
                        varnode_to_expr(dst),
                        Expr::Unary(UnaryOp::Neg, Box::new(varnode_to_expr(src))),
                    ));
                }
                IrOp::IntNot { dst, src } => {
                    stmts.push(Stmt::Assign(
                        varnode_to_expr(dst),
                        Expr::Unary(UnaryOp::BitNot, Box::new(varnode_to_expr(src))),
                    ));
                }
                IrOp::IntEqual { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::Eq),
                IrOp::IntNotEqual { dst, a, b } => emit_binop(&mut stmts, dst, a, b, BinOp::Ne),
                IrOp::IntLess { dst, a, b } | IrOp::IntSLess { dst, a, b } => {
                    emit_binop(&mut stmts, dst, a, b, BinOp::Lt);
                }
                IrOp::IntLessEqual { dst, a, b } | IrOp::IntSLessEqual { dst, a, b } => {
                    emit_binop(&mut stmts, dst, a, b, BinOp::Le);
                }
                IrOp::IntZext { dst, src } | IrOp::IntSext { dst, src } => {
                    let target_type = CType::from_size(dst.size, matches!(insn.op, IrOp::IntSext { .. }));
                    stmts.push(Stmt::Assign(
                        varnode_to_expr(dst),
                        Expr::Cast(target_type, Box::new(varnode_to_expr(src))),
                    ));
                }
                IrOp::Subpiece { dst, src, offset: _ } => {
                    let target_type = CType::from_size(dst.size, false);
                    stmts.push(Stmt::Assign(
                        varnode_to_expr(dst),
                        Expr::Cast(target_type, Box::new(varnode_to_expr(src))),
                    ));
                }
                IrOp::Call { target } => {
                    let func_name = ctx
                        .function_names
                        .get(target)
                        .cloned()
                        .unwrap_or_else(|| format!("sub_{target:x}"));
                    stmts.push(Stmt::ExprStmt(Expr::Call(
                        Box::new(Expr::Var(func_name)),
                        Vec::new(),
                    )));
                }
                IrOp::CallInd { target } => {
                    stmts.push(Stmt::ExprStmt(Expr::Call(
                        Box::new(varnode_to_expr(target)),
                        Vec::new(),
                    )));
                }
                IrOp::Return { value } => {
                    let ret_val = value.var().map(|v| varnode_to_expr(v));
                    stmts.push(Stmt::Return(ret_val));
                }
                IrOp::Branch { target } => {
                    // Handled by structuring pass
                    stmts.push(Stmt::Goto(*target));
                }
                IrOp::CBranch { cond: _, target: _ } => {
                    // Handled by structuring pass
                }
                IrOp::BranchInd { target } => {
                    stmts.push(Stmt::Comment(format!(
                        "indirect branch to {}",
                        varnode_display(target)
                    )));
                }
                IrOp::Nop => {}
                IrOp::Unimplemented { mnemonic, operands } => {
                    stmts.push(Stmt::Comment(format!("unimpl: {mnemonic} {operands}")));
                }
                IrOp::Phi { dst, inputs } => {
                    // Phi nodes are SSA artifacts; just use the first input
                    if let Some(first) = inputs.first() {
                        stmts.push(Stmt::Assign(
                            varnode_to_expr(dst),
                            varnode_to_expr(first),
                        ));
                    }
                }
            }
        }

        result.insert(block.address, stmts);
    }

    result
}

fn emit_binop(stmts: &mut Vec<Stmt>, dst: &VarNode, a: &VarNode, b: &VarNode, op: BinOp) {
    stmts.push(Stmt::Assign(
        varnode_to_expr(dst),
        Expr::Binary(
            op,
            Box::new(varnode_to_expr(a)),
            Box::new(varnode_to_expr(b)),
        ),
    ));
}

/// Convert a varnode to an expression.
pub fn varnode_to_expr(vn: &VarNode) -> Expr {
    match vn.space {
        VarSpace::Constant => {
            // Check if this looks like a string address or a small number
            Expr::IntLit(vn.offset, CType::from_size(vn.size, false))
        }
        VarSpace::Register => Expr::Var(register_name(vn.offset, vn.size)),
        VarSpace::Temp => Expr::Var(format!("t{}", vn.offset)),
        VarSpace::Memory => Expr::Deref(
            Box::new(Expr::IntLit(vn.offset, CType::UInt64)),
            CType::from_size(vn.size, false),
        ),
        VarSpace::Stack => Expr::Var(format!("stack_{:x}", vn.offset)),
    }
}

fn varnode_display(vn: &VarNode) -> String {
    match vn.space {
        VarSpace::Constant => format!("0x{:x}", vn.offset),
        VarSpace::Register => register_name(vn.offset, vn.size),
        VarSpace::Temp => format!("t{}", vn.offset),
        VarSpace::Memory => format!("*0x{:x}", vn.offset),
        VarSpace::Stack => format!("stack_{:x}", vn.offset),
    }
}

/// Map register offset+size to a human-readable name.
fn register_name(offset: u64, size: u8) -> String {
    // x86_64 names
    match (offset, size) {
        (0, 8) => "rax".into(),
        (0, 4) => "eax".into(),
        (0, 2) => "ax".into(),
        (0, 1) => "al".into(),
        (1, 8) => "rcx".into(),
        (1, 4) => "ecx".into(),
        (2, 8) => "rdx".into(),
        (2, 4) => "edx".into(),
        (3, 8) => "rbx".into(),
        (3, 4) => "ebx".into(),
        (4, 8) => "rsp".into(),
        (4, 4) => "esp".into(),
        (5, 8) => "rbp".into(),
        (5, 4) => "ebp".into(),
        (6, 8) => "rsi".into(),
        (6, 4) => "esi".into(),
        (7, 8) => "rdi".into(),
        (7, 4) => "edi".into(),
        (8..=15, 8) => format!("r{offset}"),
        (8..=15, 4) => format!("r{offset}d"),
        (16, 8) => "rip".into(),
        (17, _) => "flags".into(),
        // ARM64 names (same offset space)
        (29, 8) => "fp".into(),
        (30, 8) => "lr".into(),
        (31, 8) => "sp".into(),
        (32, _) => "xzr".into(),
        (33, 8) => "pc".into(),
        (34, _) => "nzcv".into(),
        (n, 8) if n <= 28 => format!("x{n}"),
        (n, 4) if n <= 28 => format!("w{n}"),
        _ => format!("r{}_{}", offset, size),
    }
}
