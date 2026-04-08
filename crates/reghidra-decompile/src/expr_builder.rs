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
        // Deferred stack writes that look like x86-32 stdcall/cdecl argument
        // setup (`push x; push y; call f`). We hold onto them until we see a
        // Call (where they become arguments) or any other instruction (where
        // we flush them as plain `*(rsp) = x` statements — i.e. they weren't
        // call args after all).
        let mut pending_stack_writes: Vec<(VarNode, VarNode)> = Vec::new();

        for insn in &block.instructions {
            // Intercept stores to the stack pointer before the main match
            // so a run of pushes can be collapsed into a call's argument list.
            if let IrOp::Store { addr, src } = &insn.op {
                if is_stack_pointer(addr) {
                    pending_stack_writes.push((addr.clone(), src.clone()));
                    continue;
                }
            }

            // For any non-Call instruction, the pushes we saw weren't call
            // arguments — emit them as plain stack writes and continue.
            let is_call = matches!(insn.op, IrOp::Call { .. } | IrOp::CallInd { .. });
            if !is_call {
                flush_stack_writes(&mut stmts, &mut pending_stack_writes);
            }

            match &insn.op {
                IrOp::Copy { dst, src } => {
                    let lhs = varnode_to_expr(dst);
                    let rhs = varnode_to_expr(src);
                    stmts.push(Stmt::Assign(lhs, rhs));
                }
                IrOp::Load { dst, addr } => {
                    let lhs = varnode_to_expr(dst);
                    let rhs = memory_access_expr(addr, dst.size, ctx);
                    stmts.push(Stmt::Assign(lhs, rhs));
                }
                IrOp::Store { addr, src } => {
                    let lhs = memory_access_expr(addr, src.size, ctx);
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
                    // Arity cap: if the callee has a known prototype in
                    // the bundled type archives, take only the last N
                    // pending stack writes as args (where N is the
                    // prototype's fixed arity). Variadic functions opt
                    // out — we can't safely cap them.
                    let prototype = ctx.lookup_prototype(&func_name);
                    let max_args = prototype
                        .filter(|p| !p.is_variadic)
                        .map(|p| p.args.len());
                    let raw_args = drain_pending_for_call(
                        &mut stmts,
                        &mut pending_stack_writes,
                        max_args,
                    );
                    // Type the args from the prototype's parameter list
                    // when one is available. Each arg gets wrapped in a
                    // Cast(declared_type, expr) so the rendered output
                    // shows the user the declared type of the slot
                    // (e.g. `(HANDLE)result`, `(DWORD)0xc0000409`).
                    let args = annotate_call_args(raw_args, prototype);
                    stmts.push(Stmt::ExprStmt(Expr::Call(
                        Box::new(Expr::Var(func_name)),
                        args,
                    )));
                }
                IrOp::CallInd { target } => {
                    // Indirect calls can't be looked up in the archive —
                    // we don't know the target statically. Fall through
                    // to the uncapped drain.
                    let args = drain_pending_for_call(
                        &mut stmts,
                        &mut pending_stack_writes,
                        None,
                    );
                    stmts.push(Stmt::ExprStmt(Expr::Call(
                        Box::new(varnode_to_expr(target)),
                        args,
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

        // Flush any stack writes still pending at the end of the block
        // (e.g. a trailing push with no following call in this block).
        flush_stack_writes(&mut stmts, &mut pending_stack_writes);
        result.insert(block.address, stmts);
    }

    result
}

/// Is this varnode the architectural stack pointer (x86 rsp/esp, ARM64 sp)?
/// Matches the register-offset convention used by the IR lifters.
fn is_stack_pointer(vn: &VarNode) -> bool {
    if vn.space != VarSpace::Register {
        return false;
    }
    // x86_64 RSP = 4, ARM64 SP = 31 (see reghidra-ir lifters).
    vn.offset == 4 || vn.offset == 31
}

/// Emit any deferred stack writes as plain `*(rsp) = value` assignments.
/// Called when we decide the pushes weren't actually call-argument setup.
/// These always have a register address (the stack pointer), so they
/// never hit the global-data rewrite path in `memory_access_expr`.
fn flush_stack_writes(stmts: &mut Vec<Stmt>, pending: &mut Vec<(VarNode, VarNode)>) {
    for (addr, src) in pending.drain(..) {
        let lhs = Expr::Deref(
            Box::new(varnode_to_expr(&addr)),
            CType::from_size(src.size, false),
        );
        let rhs = varnode_to_expr(&src);
        stmts.push(Stmt::Assign(lhs, rhs));
    }
}

/// Minimum address we'll accept as a plausible global-data pointer. Anything
/// below this (NULL, small struct-offset constants, IRQ vector numbers, etc.)
/// stays as a raw `*(0xN)` deref so we don't misname legitimate small
/// integer dereferences as globals.
const GLOBAL_DATA_MIN_ADDR: u64 = 0x1000;

/// Build the expression for a memory access (Load rhs / Store lhs) at
/// `addr` for a value of `size` bytes.
///
/// - For a constant address that looks like a global (>= `GLOBAL_DATA_MIN_ADDR`)
///   and isn't already known as a function pointer or string literal, the
///   access is rewritten as a bare `g_dat_ADDR` variable reference instead
///   of `*(0xADDR)`. This is what users expect to see for `mov [0x40dfd8], eax`
///   and friends, and makes the hex address clickable (the GUI tokenizer
///   recognizes the `g_dat_` prefix).
/// - For a constant address that resolves to a known function (typically a
///   PE IAT slot from `import_addr_map`), emit a bare variable reference by
///   that name — e.g. reading a function pointer from an IAT slot.
/// - Everything else (register/temp addresses, small constants, etc.) falls
///   back to a plain `*(expr)` deref.
fn memory_access_expr(addr: &VarNode, size: u8, ctx: &DecompileContext) -> Expr {
    if addr.space == VarSpace::Constant {
        // Function pointer read from a known slot (e.g. PE IAT entry that
        // some code path reads as data rather than calling directly).
        if let Some(name) = ctx.function_names.get(&addr.offset) {
            return Expr::Var(name.clone());
        }
        // Plausible global — rewrite as a named symbol. Strings are
        // intentionally not rewritten here because string loads are rare
        // and their textual form is preserved elsewhere (string literal
        // references come through as arguments, not Load ops).
        if addr.offset >= GLOBAL_DATA_MIN_ADDR {
            return Expr::Var(format!("g_dat_{:x}", addr.offset));
        }
    }
    Expr::Deref(
        Box::new(varnode_to_expr(addr)),
        CType::from_size(size, false),
    )
}

/// Convert the pending stack-write queue into an argument list for a
/// Call, honoring an optional arity cap.
///
/// Pending writes are in chronological order: the oldest push is at
/// index 0, the most recent push is at the end. On x86 cdecl /
/// stdcall, arguments are pushed right-to-left, so the LAST push
/// chronologically is arg1 and the FIRST push is argN. Reversing
/// gives source order [arg1, arg2, ..., argN].
///
/// When `max_args = Some(n)` and the queue has more than `n` entries,
/// only the *last* `n` entries are consumed as args. Earlier entries
/// stay in the queue — they're not over-attribution to discard,
/// they're typically pre-positioned arguments for a *later* call (or
/// they will be flushed by an intervening non-stack op via the
/// pre-existing `flush_stack_writes` path). This is the key fix from
/// the initial PR 4 implementation, which discarded the overflow as
/// plain stores and lost the legitimate `TerminateProcess` exit-code
/// arg in the canonical pattern:
///
/// ```text
/// push exit_code         ; arg2 of TerminateProcess
/// call GetCurrentProcess ; 0-arg, must NOT consume exit_code
/// push eax               ; arg1 of TerminateProcess
/// call TerminateProcess
/// ```
///
/// With the cap-as-limit semantics, the 0-arg `GetCurrentProcess`
/// leaves `exit_code` in the queue, the `push eax` adds to it, and
/// the 2-arg `TerminateProcess` consumes the trailing two entries.
///
/// `max_args = None` disables the cap entirely — used for indirect
/// calls (unknown target) and for direct calls whose target isn't
/// in the bundled archives. Pre-PR 4 behavior: drain the entire
/// queue.
fn drain_pending_for_call(
    _stmts: &mut Vec<Stmt>,
    pending: &mut Vec<(VarNode, VarNode)>,
    max_args: Option<usize>,
) -> Vec<Expr> {
    let take_n = match max_args {
        Some(cap) => cap.min(pending.len()),
        None => pending.len(),
    };
    if take_n == 0 {
        // 0-arg cap: leave everything in the queue. Don't drain at
        // all. The pre-existing flush logic handles unrelated leftovers
        // when the next non-stack op runs.
        return Vec::new();
    }
    // Split off the last `take_n` entries as the args; the front of
    // the queue stays in `pending` for a later call (or eventual
    // flush). `Vec::split_off(idx)` returns the items from `idx`
    // onwards, leaving the prefix in place.
    let split_at = pending.len() - take_n;
    let consumed: Vec<(VarNode, VarNode)> = pending.split_off(split_at);
    consumed
        .into_iter()
        .rev()
        .map(|(_, src)| varnode_to_expr(&src))
        .collect()
}

/// Annotate a call's argument list with declared types from a known
/// prototype. Each arg expression gets wrapped in
/// `Expr::Cast(declared_type, arg)` so the rendered decompile output
/// surfaces the parameter types (e.g. `TerminateProcess((HANDLE)result,
/// (DWORD)0xc0000409)`). This is the only place in PR 4c that types
/// from the bundled archives become *visible* in the output for the
/// common case where the function being decompiled is a user
/// `sub_XXXX` (which has no archive entry of its own and therefore
/// gets no typed VarDecls).
///
/// When `prototype` is `None`, args pass through unchanged. When the
/// arg list is shorter than the prototype's parameter list, only the
/// supplied args get typed (the missing ones are missing from the
/// output anyway). When the arg list is longer (e.g. variadic), the
/// excess args pass through untyped because the variadic tail has no
/// declared type.
fn annotate_call_args(
    args: Vec<Expr>,
    prototype: Option<&crate::type_archive::FunctionType>,
) -> Vec<Expr> {
    let Some(proto) = prototype else {
        return args;
    };
    args.into_iter()
        .enumerate()
        .map(|(i, arg)| {
            if let Some(proto_arg) = proto.args.get(i) {
                let ctype = crate::type_archive::type_ref_to_ctype(&proto_arg.ty);
                // Skip the cast for `void` arg types (shouldn't
                // happen in practice — void params are illegal in C
                // declarations — but be defensive). Also skip when
                // the arg is already a Cast to the same type, to
                // avoid `((HANDLE)(HANDLE)x)` double-wrapping if
                // some upstream pass already typed the expression.
                if matches!(ctype, CType::Void) {
                    return arg;
                }
                if let Expr::Cast(existing, _) = &arg {
                    if existing == &ctype {
                        return arg;
                    }
                }
                Expr::Cast(ctype, Box::new(arg))
            } else {
                arg
            }
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use reghidra_ir::op::{Operand, VarNode};
    use reghidra_ir::types::{IrBlock, IrFunction, IrInstruction};

    fn mk_ir(ops: Vec<IrOp>) -> IrFunction {
        let mut block = IrBlock::new(0x1000);
        for (i, op) in ops.into_iter().enumerate() {
            block.instructions.push(IrInstruction {
                address: 0x1000,
                sub_index: i as u16,
                op,
            });
        }
        IrFunction {
            name: "f".into(),
            entry_address: 0x1000,
            blocks: vec![block],
        }
    }

    fn empty_ctx() -> DecompileContext {
        DecompileContext {
            function_names: Default::default(),
            string_literals: Default::default(),
            successors: Default::default(),
            predecessors: Default::default(),
            label_names: Default::default(),
            variable_names: Default::default(),
            current_function_display_name: None,
            type_archives: Vec::new(),
        }
    }

    fn rsp4() -> VarNode {
        // x86-32 esp: offset=4, size=4 (matches the lifter's RSP constant)
        VarNode::reg(4, 4)
    }

    #[test]
    fn three_pushes_before_call_become_three_args() {
        // push 1; push 2; push 3; call 0x2000  ->  sub_2000(3, 2, 1)
        let ir = mk_ir(vec![
            IrOp::Store { addr: rsp4(), src: VarNode::constant(1, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(2, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(3, 4) },
            IrOp::Call { target: 0x2000 },
        ]);
        let ctx = empty_ctx();
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        assert_eq!(stmts.len(), 1, "pushes should collapse into the call, got {stmts:?}");
        match &stmts[0] {
            Stmt::ExprStmt(Expr::Call(callee, args)) => {
                assert!(matches!(**callee, Expr::Var(ref name) if name == "sub_2000"));
                // Args appear in source order: first-pushed is last arg
                assert_eq!(args.len(), 3);
                match &args[0] {
                    Expr::IntLit(3, _) => {}
                    other => panic!("arg 0 should be 3, got {other:?}"),
                }
                match &args[2] {
                    Expr::IntLit(1, _) => {}
                    other => panic!("arg 2 should be 1, got {other:?}"),
                }
            }
            other => panic!("expected Call stmt, got {other:?}"),
        }
    }

    #[test]
    fn push_without_call_flushes_as_stack_write() {
        // push 1; nop  ->  *(esp) = 1; (no call)
        let ir = mk_ir(vec![
            IrOp::Store { addr: rsp4(), src: VarNode::constant(1, 4) },
            IrOp::Return { value: Operand::None },
        ]);
        let ctx = empty_ctx();
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        // Expect a flushed Assign then a Return.
        assert!(matches!(&stmts[0], Stmt::Assign(..)));
        assert!(matches!(stmts.last(), Some(Stmt::Return(None))));
    }

    #[test]
    fn intervening_non_call_flushes_earlier_push() {
        // push 1; mov eax, 5; push 2; call 0x2000  ->
        //   *(esp) = 1; eax = 5; sub_2000(2)
        let eax = VarNode::reg(0, 4);
        let ir = mk_ir(vec![
            IrOp::Store { addr: rsp4(), src: VarNode::constant(1, 4) },
            IrOp::Copy { dst: eax, src: VarNode::constant(5, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(2, 4) },
            IrOp::Call { target: 0x2000 },
        ]);
        let ctx = empty_ctx();
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        assert_eq!(stmts.len(), 3);
        assert!(matches!(stmts[0], Stmt::Assign(..)), "earlier push should be flushed");
        assert!(matches!(stmts[1], Stmt::Assign(..)), "the mov should be emitted");
        match &stmts[2] {
            Stmt::ExprStmt(Expr::Call(_, args)) => {
                assert_eq!(args.len(), 1, "only the second push should be an arg");
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn load_from_plausible_global_uses_g_dat_name() {
        // mov eax, [0x40dfd8]  ->  eax = g_dat_40dfd8 (not *(0x40dfd8))
        let eax = VarNode::reg(0, 4);
        let global = VarNode::constant(0x40dfd8, 4);
        let ir = mk_ir(vec![IrOp::Load { dst: eax, addr: global }]);
        let ctx = empty_ctx();
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        match &stmts[0] {
            Stmt::Assign(_, Expr::Var(name)) => {
                assert_eq!(name, "g_dat_40dfd8");
            }
            other => panic!("expected Assign with Var rhs, got {other:?}"),
        }
    }

    #[test]
    fn store_to_plausible_global_uses_g_dat_name() {
        // mov [0x40dfd8], eax  ->  g_dat_40dfd8 = eax
        let eax = VarNode::reg(0, 4);
        let global = VarNode::constant(0x40dfd8, 4);
        let ir = mk_ir(vec![IrOp::Store { addr: global, src: eax }]);
        let ctx = empty_ctx();
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        match &stmts[0] {
            Stmt::Assign(Expr::Var(name), _) => {
                assert_eq!(name, "g_dat_40dfd8");
            }
            other => panic!("expected Assign with Var lhs, got {other:?}"),
        }
    }

    #[test]
    fn load_from_small_constant_stays_deref() {
        // Small constants (< 0x1000) should stay as raw derefs — they're
        // almost certainly struct offsets or null-adjacent values, not
        // globals worth naming.
        let eax = VarNode::reg(0, 4);
        let tiny = VarNode::constant(0x10, 4);
        let ir = mk_ir(vec![IrOp::Load { dst: eax, addr: tiny }]);
        let ctx = empty_ctx();
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        match &stmts[0] {
            Stmt::Assign(_, Expr::Deref(..)) => {}
            other => panic!("expected Deref rhs for small constant, got {other:?}"),
        }
    }

    #[test]
    fn load_from_known_function_pointer_uses_name() {
        // If the address is in function_names (e.g. a PE IAT slot), emit
        // a bare variable reference with that name rather than g_dat_XXXX.
        let eax = VarNode::reg(0, 4);
        let iat = VarNode::constant(0x40a028, 4);
        let ir = mk_ir(vec![IrOp::Load { dst: eax, addr: iat }]);
        let mut ctx = empty_ctx();
        ctx.function_names.insert(0x40a028, "GetLastError".to_string());
        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        match &stmts[0] {
            Stmt::Assign(_, Expr::Var(name)) => {
                assert_eq!(name, "GetLastError");
            }
            other => panic!("expected function-name Var rhs, got {other:?}"),
        }
    }

    /// Regression test for the canonical Win32 idiom where the
    /// `uExitCode` arg of `TerminateProcess` is pre-positioned on the
    /// stack BEFORE the `GetCurrentProcess` call that produces the
    /// `hProcess` arg:
    ///
    /// ```text
    /// push exit_code        ; arg2 (uExitCode), pre-positioned
    /// call GetCurrentProcess ; 0-arg, returns hProcess in eax
    /// push eax              ; arg1 (hProcess)
    /// call TerminateProcess  ; 2-arg
    /// ```
    ///
    /// The arity cap on `GetCurrentProcess` (0 args) must NOT consume
    /// the `exit_code` push, and must NOT discard it as a flushed
    /// store either. It should leave the entry in the pending queue
    /// so the subsequent `TerminateProcess` call can pair it with
    /// the `eax` push and consume both as args.
    ///
    /// This is the case the initial PR 4 arity cap got wrong by
    /// flushing overflow at the call site; PR 4c switched to
    /// "take last N, leave the rest" semantics so legitimate
    /// pre-positioned args survive earlier calls.
    #[test]
    fn arity_cap_preserves_args_across_zero_arg_call() {
        use crate::type_archive::{
            ArgType as ArchiveArg, CallingConvention, FunctionType as ArchiveFn,
            Primitive, TypeArchive, TypeRef,
        };
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut functions: HashMap<String, ArchiveFn> = HashMap::new();
        functions.insert(
            "GetCurrentProcess".to_string(),
            ArchiveFn {
                name: "GetCurrentProcess".to_string(),
                args: vec![],
                return_type: TypeRef::Primitive(Primitive::UInt64),
                calling_convention: CallingConvention::Win64,
                is_variadic: false,
            },
        );
        functions.insert(
            "TerminateProcess".to_string(),
            ArchiveFn {
                name: "TerminateProcess".to_string(),
                args: vec![
                    ArchiveArg {
                        name: "hProcess".to_string(),
                        ty: TypeRef::Primitive(Primitive::UInt64),
                    },
                    ArchiveArg {
                        name: "uExitCode".to_string(),
                        ty: TypeRef::Primitive(Primitive::UInt32),
                    },
                ],
                return_type: TypeRef::Primitive(Primitive::Bool),
                calling_convention: CallingConvention::Win64,
                is_variadic: false,
            },
        );
        let archive = Arc::new(TypeArchive {
            name: "test".to_string(),
            version: crate::type_archive::ARCHIVE_VERSION,
            functions,
            types: HashMap::new(),
        });

        let ir = mk_ir(vec![
            // push 0xc0000409 — uExitCode pre-positioned
            IrOp::Store {
                addr: rsp4(),
                src: VarNode::constant(0xc0000409, 4),
            },
            // call GetCurrentProcess
            IrOp::Call { target: 0x2000 },
            // push 0xfeedface — stand-in for "push eax" (hProcess)
            IrOp::Store {
                addr: rsp4(),
                src: VarNode::constant(0xfeedface, 4),
            },
            // call TerminateProcess
            IrOp::Call { target: 0x3000 },
        ]);

        let mut ctx = empty_ctx();
        ctx.function_names.insert(0x2000, "GetCurrentProcess".to_string());
        ctx.function_names.insert(0x3000, "TerminateProcess".to_string());
        ctx.type_archives = vec![archive];

        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];

        // Expected: only two statements (the calls). No leftover
        // overflow stores. The 0xc0000409 push survives the
        // GetCurrentProcess call and gets consumed as TerminateProcess's
        // second argument.
        assert_eq!(
            stmts.len(),
            2,
            "expected [GetCurrentProcess(), TerminateProcess(...)] only, got {stmts:#?}"
        );
        match &stmts[0] {
            Stmt::ExprStmt(Expr::Call(callee, args)) => {
                assert!(
                    matches!(**callee, Expr::Var(ref n) if n == "GetCurrentProcess")
                );
                assert!(
                    args.is_empty(),
                    "GetCurrentProcess should have 0 args, got {args:?}"
                );
            }
            other => panic!("expected GetCurrentProcess call, got {other:?}"),
        }
        match &stmts[1] {
            Stmt::ExprStmt(Expr::Call(callee, args)) => {
                assert!(
                    matches!(**callee, Expr::Var(ref n) if n == "TerminateProcess")
                );
                assert_eq!(args.len(), 2, "TerminateProcess should have 2 args, got {args:#?}");
                // Args are wrapped in Cast(declared_type, IntLit) by
                // the typed-call-site pass. Look through the cast to
                // assert the underlying constants.
                // Source order: arg0=hProcess (last push, 0xfeedface),
                // arg1=uExitCode (first push, 0xc0000409).
                assert_eq!(unwrap_int_lit(&args[0]), 0xfeedface, "arg0 should be the eax push (hProcess)");
                assert_eq!(unwrap_int_lit(&args[1]), 0xc0000409, "arg1 should be the pre-positioned uExitCode");
            }
            other => panic!("expected TerminateProcess call, got {other:?}"),
        }
    }

    /// Helper: unwrap an `Expr` that may be a `Cast(_, IntLit)` or a
    /// bare `IntLit`, returning the literal value. Used by the
    /// arity-cap tests so they don't have to care whether the cast
    /// wrapper from `annotate_call_args` is present or not.
    fn unwrap_int_lit(e: &Expr) -> u64 {
        match e {
            Expr::IntLit(v, _) => *v,
            Expr::Cast(_, inner) => unwrap_int_lit(inner),
            other => panic!("expected IntLit (optionally wrapped in Cast), got {other:?}"),
        }
    }

    /// When a Call's prototype is in the bundled archives, the args
    /// passed to it should be wrapped in `Expr::Cast(declared_type, ..)`
    /// so the rendered output surfaces the parameter types
    /// (`(HANDLE)result`, `(DWORD)0xc0000409`, etc.). This is the
    /// most visible PR 4c change to a user looking at the decompile
    /// view of a sub_XXXX function: even though the function itself
    /// has no archive entry, the calls it makes get type-annotated
    /// args.
    #[test]
    fn typed_call_args_get_cast_wrappers() {
        use crate::ast::CType;
        use crate::type_archive::{
            ArgType as ArchiveArg, CallingConvention, FunctionType as ArchiveFn,
            Primitive, TypeArchive, TypeRef,
        };
        use std::collections::HashMap;
        use std::sync::Arc;

        // Single-arg function: takes a HANDLE.
        let mut functions: HashMap<String, ArchiveFn> = HashMap::new();
        functions.insert(
            "CloseHandle".to_string(),
            ArchiveFn {
                name: "CloseHandle".to_string(),
                args: vec![ArchiveArg {
                    name: "hObject".to_string(),
                    ty: TypeRef::Named("HANDLE".to_string()),
                }],
                return_type: TypeRef::Primitive(Primitive::Bool),
                calling_convention: CallingConvention::Stdcall,
                is_variadic: false,
            },
        );
        let archive = Arc::new(TypeArchive {
            name: "test".to_string(),
            version: crate::type_archive::ARCHIVE_VERSION,
            functions,
            types: HashMap::new(),
        });

        // push 0xdeadbeef; call CloseHandle
        let ir = mk_ir(vec![
            IrOp::Store {
                addr: rsp4(),
                src: VarNode::constant(0xdeadbeef, 4),
            },
            IrOp::Call { target: 0x2000 },
        ]);
        let mut ctx = empty_ctx();
        ctx.function_names.insert(0x2000, "CloseHandle".to_string());
        ctx.type_archives = vec![archive];

        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Stmt::ExprStmt(Expr::Call(_, args)) => {
                assert_eq!(args.len(), 1);
                // The arg should be wrapped in Cast(Named("HANDLE"), ..).
                match &args[0] {
                    Expr::Cast(ty, inner) => {
                        assert!(
                            matches!(ty, CType::Named(n) if n == "HANDLE"),
                            "expected Cast(Named(HANDLE), ..), got Cast({ty:?}, ..)"
                        );
                        // Inner should be the original IntLit.
                        assert!(matches!(**inner, Expr::IntLit(0xdeadbeef, _)));
                    }
                    other => panic!("expected Cast wrapper, got {other:?}"),
                }
            }
            other => panic!("expected Call stmt, got {other:?}"),
        }
    }

    /// When the pending queue has more entries than the cap, only the
    /// *last* `n` are consumed as args; the prefix stays in the
    /// queue. This protects pre-positioned args for later calls
    /// without losing them. The simplest version: 3 pushes followed
    /// by a 2-arg call should yield args from the last 2 pushes,
    /// leaving the first push in `pending` until the next call or
    /// flush sweeps it.
    #[test]
    fn arity_cap_takes_last_n_leaving_prefix() {
        use crate::type_archive::{
            ArgType as ArchiveArg, CallingConvention, FunctionType as ArchiveFn,
            Primitive, TypeArchive, TypeRef,
        };
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut functions: HashMap<String, ArchiveFn> = HashMap::new();
        functions.insert(
            "two_arg".to_string(),
            ArchiveFn {
                name: "two_arg".to_string(),
                args: vec![
                    ArchiveArg {
                        name: "a".to_string(),
                        ty: TypeRef::Primitive(Primitive::UInt32),
                    },
                    ArchiveArg {
                        name: "b".to_string(),
                        ty: TypeRef::Primitive(Primitive::UInt32),
                    },
                ],
                return_type: TypeRef::Primitive(Primitive::Void),
                calling_convention: CallingConvention::Cdecl,
                is_variadic: false,
            },
        );
        let archive = Arc::new(TypeArchive {
            name: "test".to_string(),
            version: crate::type_archive::ARCHIVE_VERSION,
            functions,
            types: HashMap::new(),
        });

        // push 100; push 2; push 1; call two_arg → two_arg(1, 2)
        // The 100 push survives in the pending queue and would
        // be consumed by a later call or flushed by an
        // intervening op. Here we just check it isn't an arg.
        let ir = mk_ir(vec![
            IrOp::Store { addr: rsp4(), src: VarNode::constant(100, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(2, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(1, 4) },
            IrOp::Call { target: 0x2000 },
            // Force a flush so the test doesn't depend on end-of-block
            // flushing behavior to make the leftover observable.
            IrOp::Return { value: Operand::None },
        ]);
        let mut ctx = empty_ctx();
        ctx.function_names.insert(0x2000, "two_arg".to_string());
        ctx.type_archives = vec![archive];

        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];

        // Expected sequence:
        //   1. two_arg(1, 2)             ← consumes the last 2 pushes
        //   2. *(esp) = 100              ← leftover push, flushed at Return
        //   3. return                    ← terminator
        // The leftover-flush happens at the Return op via the
        // pre-existing flush_stack_writes path, NOT inside the call.
        assert_eq!(stmts.len(), 3, "expected 3 stmts, got {stmts:#?}");
        match &stmts[0] {
            Stmt::ExprStmt(Expr::Call(callee, args)) => {
                assert!(matches!(**callee, Expr::Var(ref n) if n == "two_arg"));
                assert_eq!(args.len(), 2);
                assert_eq!(unwrap_int_lit(&args[0]), 1);
                assert_eq!(unwrap_int_lit(&args[1]), 2);
            }
            other => panic!("expected two_arg call, got {other:?}"),
        }
        // The leftover 100 push should now be a flushed store.
        assert!(
            matches!(stmts[1], Stmt::Assign(..)),
            "expected leftover-100 to be flushed as a store, got {:?}",
            stmts[1]
        );
        assert!(matches!(stmts[2], Stmt::Return(_)));
    }

    /// Variadic functions (printf, etc.) opt out of arity capping:
    /// we can't safely cap them because the trailing `...` can consume
    /// an arbitrary number of pushed args. Verify that a variadic
    /// prototype in the archive does NOT trigger the cap.
    #[test]
    fn variadic_functions_skip_arity_cap() {
        use crate::type_archive::{
            CallingConvention, FunctionType as ArchiveFn, Primitive, TypeArchive, TypeRef,
        };
        use std::collections::HashMap;
        use std::sync::Arc;

        let mut functions: HashMap<String, ArchiveFn> = HashMap::new();
        functions.insert(
            "printf".to_string(),
            ArchiveFn {
                name: "printf".to_string(),
                // Fixed arity of 1 (the format string) + variadic tail.
                args: vec![crate::type_archive::ArgType {
                    name: "fmt".to_string(),
                    ty: TypeRef::Pointer(Box::new(TypeRef::Primitive(Primitive::Char))),
                }],
                return_type: TypeRef::Primitive(Primitive::Int32),
                calling_convention: CallingConvention::Cdecl,
                is_variadic: true,
            },
        );
        let archive = Arc::new(TypeArchive {
            name: "test".to_string(),
            version: crate::type_archive::ARCHIVE_VERSION,
            functions,
            types: HashMap::new(),
        });

        // push 3; push 2; push 1; call printf — all three should become args.
        let ir = mk_ir(vec![
            IrOp::Store { addr: rsp4(), src: VarNode::constant(3, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(2, 4) },
            IrOp::Store { addr: rsp4(), src: VarNode::constant(1, 4) },
            IrOp::Call { target: 0x2000 },
        ]);
        let mut ctx = empty_ctx();
        ctx.function_names.insert(0x2000, "printf".to_string());
        ctx.type_archives = vec![archive];

        let result = build_statements(&ir, &ctx);
        let stmts = &result[&0x1000];
        assert_eq!(stmts.len(), 1, "expected single Call stmt, got {stmts:#?}");
        if let Stmt::ExprStmt(Expr::Call(_, args)) = &stmts[0] {
            assert_eq!(args.len(), 3, "variadic printf should get all 3 args, not capped to 1");
        } else {
            panic!("expected Call, got {:?}", stmts[0]);
        }
    }
}
