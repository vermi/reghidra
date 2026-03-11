use super::{DisasmInput, LiftContext};
use crate::op::{IrOp, Operand, VarNode};
use crate::types::IrFunction;

// x86_64 register offsets (arbitrary but consistent mapping)
pub mod regs {
    pub const RAX: u64 = 0;
    pub const RCX: u64 = 1;
    pub const RDX: u64 = 2;
    pub const RBX: u64 = 3;
    pub const RSP: u64 = 4;
    pub const RBP: u64 = 5;
    pub const RSI: u64 = 6;
    pub const RDI: u64 = 7;
    pub const R8: u64 = 8;
    pub const R9: u64 = 9;
    pub const R10: u64 = 10;
    pub const R11: u64 = 11;
    pub const R12: u64 = 12;
    pub const R13: u64 = 13;
    pub const R14: u64 = 14;
    pub const R15: u64 = 15;
    pub const RIP: u64 = 16;
    pub const RFLAGS: u64 = 17;
    // x87/SSE registers start at 32
    pub const XMM0: u64 = 32;
}

/// Lift a sequence of x86_64 instructions into an IR function.
pub fn lift_function(
    name: &str,
    entry: u64,
    instructions: &[DisasmInput],
    block_leaders: &[u64],
) -> IrFunction {
    let mut ctx = LiftContext::new(entry);
    let leaders: std::collections::HashSet<u64> = block_leaders.iter().copied().collect();

    for insn in instructions {
        if leaders.contains(&insn.address) && insn.address != entry {
            ctx.start_block(insn.address);
        }
        ctx.set_address(insn.address);
        lift_instruction(&mut ctx, insn);
    }

    IrFunction {
        name: name.to_string(),
        entry_address: entry,
        blocks: ctx.finish(),
    }
}

fn lift_instruction(ctx: &mut LiftContext, insn: &DisasmInput) {
    let mnemonic = insn.mnemonic.as_str();
    let operands = insn.operands.as_str();

    match mnemonic {
        "mov" | "movabs" => lift_mov(ctx, operands, false),
        "movzx" => lift_mov(ctx, operands, true),
        "movsx" | "movsxd" => lift_movsx(ctx, operands),
        "lea" => lift_lea(ctx, operands),
        "push" => lift_push(ctx, operands),
        "pop" => lift_pop(ctx, operands),
        "add" => lift_binop(ctx, operands, BinOp::Add),
        "sub" => lift_binop(ctx, operands, BinOp::Sub),
        "imul" => lift_binop(ctx, operands, BinOp::SMul),
        "and" => lift_binop(ctx, operands, BinOp::And),
        "or" => lift_binop(ctx, operands, BinOp::Or),
        "xor" => lift_xor(ctx, operands),
        "shl" | "sal" => lift_binop(ctx, operands, BinOp::Shl),
        "shr" => lift_binop(ctx, operands, BinOp::Shr),
        "sar" => lift_binop(ctx, operands, BinOp::Sar),
        "not" => lift_not(ctx, operands),
        "neg" => lift_neg(ctx, operands),
        "inc" => lift_inc_dec(ctx, operands, true),
        "dec" => lift_inc_dec(ctx, operands, false),
        "cmp" => lift_cmp(ctx, operands),
        "test" => lift_test(ctx, operands),
        "jmp" => lift_jmp(ctx, operands),
        "je" | "jz" => lift_cjmp(ctx, operands, CondKind::Equal),
        "jne" | "jnz" => lift_cjmp(ctx, operands, CondKind::NotEqual),
        "jl" | "jnge" => lift_cjmp(ctx, operands, CondKind::SLess),
        "jge" | "jnl" => lift_cjmp(ctx, operands, CondKind::SGrEq),
        "jle" | "jng" => lift_cjmp(ctx, operands, CondKind::SLessEq),
        "jg" | "jnle" => lift_cjmp(ctx, operands, CondKind::SGrtr),
        "jb" | "jnae" | "jc" => lift_cjmp(ctx, operands, CondKind::ULess),
        "jae" | "jnb" | "jnc" => lift_cjmp(ctx, operands, CondKind::UGrEq),
        "jbe" | "jna" => lift_cjmp(ctx, operands, CondKind::ULessEq),
        "ja" | "jnbe" => lift_cjmp(ctx, operands, CondKind::UGrtr),
        "js" => lift_cjmp(ctx, operands, CondKind::Sign),
        "jns" => lift_cjmp(ctx, operands, CondKind::NotSign),
        "call" => lift_call(ctx, operands),
        "ret" | "retq" => {
            ctx.emit(IrOp::Return { value: Operand::Var(VarNode::reg(regs::RAX, 8)) });
        }
        "nop" | "endbr64" | "endbr32" => {
            ctx.emit(IrOp::Nop);
        }
        "cdqe" => {
            // sign extend eax to rax
            let eax = VarNode::reg(regs::RAX, 4);
            let rax = VarNode::reg(regs::RAX, 8);
            ctx.emit(IrOp::IntSext { dst: rax, src: eax });
        }
        _ => {
            ctx.emit(IrOp::Unimplemented {
                mnemonic: insn.mnemonic.clone(),
                operands: insn.operands.clone(),
            });
        }
    }
}

enum BinOp {
    Add,
    Sub,
    SMul,
    And,
    Or,
    Shl,
    Shr,
    Sar,
}

#[derive(Clone, Copy)]
enum CondKind {
    Equal,
    NotEqual,
    SLess,
    SGrEq,
    SLessEq,
    SGrtr,
    ULess,
    UGrEq,
    ULessEq,
    UGrtr,
    Sign,
    NotSign,
}

fn lift_mov(ctx: &mut LiftContext, operands: &str, zero_extend: bool) {
    let (dst_str, src_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "mov".into(), operands: operands.into() });
            return;
        }
    };

    let dst = parse_operand(ctx, dst_str);
    let src = parse_operand(ctx, src_str);

    if is_memory_operand(dst_str) {
        // Store: mov [mem], src
        ctx.emit(IrOp::Store { addr: dst, src });
    } else if is_memory_operand(src_str) {
        // Load: mov dst, [mem]
        if zero_extend {
            let tmp = ctx.new_temp(src.size);
            ctx.emit(IrOp::Load { dst: tmp.clone(), addr: src });
            ctx.emit(IrOp::IntZext { dst, src: tmp });
        } else {
            ctx.emit(IrOp::Load { dst, addr: src });
        }
    } else if zero_extend && src.size < dst.size {
        ctx.emit(IrOp::IntZext { dst, src });
    } else {
        ctx.emit(IrOp::Copy { dst, src });
    }
}

fn lift_movsx(ctx: &mut LiftContext, operands: &str) {
    let (dst_str, src_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "movsx".into(), operands: operands.into() });
            return;
        }
    };

    let dst = parse_operand(ctx, dst_str);
    let src = parse_operand(ctx, src_str);

    if is_memory_operand(src_str) {
        let tmp = ctx.new_temp(src.size);
        ctx.emit(IrOp::Load { dst: tmp.clone(), addr: src });
        ctx.emit(IrOp::IntSext { dst, src: tmp });
    } else {
        ctx.emit(IrOp::IntSext { dst, src });
    }
}

fn lift_lea(ctx: &mut LiftContext, operands: &str) {
    let (dst_str, src_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "lea".into(), operands: operands.into() });
            return;
        }
    };

    let dst = parse_operand(ctx, dst_str);
    let addr = parse_operand(ctx, src_str);
    // LEA computes the address, doesn't dereference it
    ctx.emit(IrOp::Copy { dst, src: addr });
}

fn lift_push(ctx: &mut LiftContext, operands: &str) {
    let src = parse_operand(ctx, operands.trim());
    let rsp = VarNode::reg(regs::RSP, 8);
    let eight = VarNode::constant(8, 8);

    // rsp -= 8
    ctx.emit(IrOp::IntSub { dst: rsp.clone(), a: rsp.clone(), b: eight });
    // *rsp = src
    ctx.emit(IrOp::Store { addr: rsp, src });
}

fn lift_pop(ctx: &mut LiftContext, operands: &str) {
    let dst = parse_operand(ctx, operands.trim());
    let rsp = VarNode::reg(regs::RSP, 8);
    let eight = VarNode::constant(8, 8);

    // dst = *rsp
    ctx.emit(IrOp::Load { dst, addr: rsp.clone() });
    // rsp += 8
    ctx.emit(IrOp::IntAdd { dst: rsp.clone(), a: rsp.clone(), b: eight });
}

fn lift_binop(ctx: &mut LiftContext, operands: &str, op: BinOp) {
    let (dst_str, src_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "binop".into(), operands: operands.into() });
            return;
        }
    };

    let dst = parse_operand(ctx, dst_str);
    let src = parse_operand(ctx, src_str);

    let a = dst.clone();
    let ir_op = match op {
        BinOp::Add => IrOp::IntAdd { dst, a, b: src },
        BinOp::Sub => IrOp::IntSub { dst, a, b: src },
        BinOp::SMul => IrOp::IntSMul { dst, a, b: src },
        BinOp::And => IrOp::IntAnd { dst, a, b: src },
        BinOp::Or => IrOp::IntOr { dst, a, b: src },
        BinOp::Shl => IrOp::IntShl { dst, a, b: src },
        BinOp::Shr => IrOp::IntShr { dst, a, b: src },
        BinOp::Sar => IrOp::IntSar { dst, a, b: src },
    };
    ctx.emit(ir_op);
}

fn lift_xor(ctx: &mut LiftContext, operands: &str) {
    let (dst_str, src_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "xor".into(), operands: operands.into() });
            return;
        }
    };

    let dst = parse_operand(ctx, dst_str);
    let src = parse_operand(ctx, src_str);

    // xor reg, reg => zero idiom
    if dst == src {
        ctx.emit(IrOp::Copy { dst, src: VarNode::constant(0, src.size) });
    } else {
        ctx.emit(IrOp::IntXor { dst: dst.clone(), a: dst, b: src });
    }
}

fn lift_not(ctx: &mut LiftContext, operands: &str) {
    let dst = parse_operand(ctx, operands.trim());
    ctx.emit(IrOp::IntNot { dst: dst.clone(), src: dst });
}

fn lift_neg(ctx: &mut LiftContext, operands: &str) {
    let dst = parse_operand(ctx, operands.trim());
    ctx.emit(IrOp::IntNeg { dst: dst.clone(), src: dst });
}

fn lift_inc_dec(ctx: &mut LiftContext, operands: &str, is_inc: bool) {
    let dst = parse_operand(ctx, operands.trim());
    let one = VarNode::constant(1, dst.size);
    if is_inc {
        ctx.emit(IrOp::IntAdd { dst: dst.clone(), a: dst, b: one });
    } else {
        ctx.emit(IrOp::IntSub { dst: dst.clone(), a: dst, b: one });
    }
}

fn lift_cmp(ctx: &mut LiftContext, operands: &str) {
    let (a_str, b_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "cmp".into(), operands: operands.into() });
            return;
        }
    };
    let a = parse_operand(ctx, a_str);
    let b = parse_operand(ctx, b_str);
    // CMP sets flags; we model this as a subtraction into RFLAGS temp
    let flags = VarNode::reg(regs::RFLAGS, 8);
    ctx.emit(IrOp::IntSub { dst: flags, a, b });
}

fn lift_test(ctx: &mut LiftContext, operands: &str) {
    let (a_str, b_str) = match split_operands(operands) {
        Some(v) => v,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "test".into(), operands: operands.into() });
            return;
        }
    };
    let a = parse_operand(ctx, a_str);
    let b = parse_operand(ctx, b_str);
    let flags = VarNode::reg(regs::RFLAGS, 8);
    ctx.emit(IrOp::IntAnd { dst: flags, a, b });
}

fn lift_jmp(ctx: &mut LiftContext, operands: &str) {
    let operands = operands.trim();
    if let Some(target) = parse_immediate(operands) {
        ctx.emit(IrOp::Branch { target });
    } else {
        let target = parse_operand(ctx, operands);
        ctx.emit(IrOp::BranchInd { target });
    }
}

fn lift_cjmp(ctx: &mut LiftContext, operands: &str, kind: CondKind) {
    let operands = operands.trim();
    let target = match parse_immediate(operands) {
        Some(t) => t,
        None => {
            ctx.emit(IrOp::Unimplemented { mnemonic: "cjmp".into(), operands: operands.into() });
            return;
        }
    };

    // The condition is derived from RFLAGS (set by prior cmp/test)
    let flags = VarNode::reg(regs::RFLAGS, 8);
    let zero = VarNode::constant(0, 8);
    let cond = ctx.new_temp(1);

    let cmp_op = match kind {
        CondKind::Equal => IrOp::IntEqual { dst: cond.clone(), a: flags, b: zero },
        CondKind::NotEqual => IrOp::IntNotEqual { dst: cond.clone(), a: flags, b: zero },
        CondKind::SLess => IrOp::IntSLess { dst: cond.clone(), a: flags, b: zero },
        CondKind::SGrEq => IrOp::IntSLessEqual { dst: cond.clone(), a: zero, b: flags },
        CondKind::SLessEq => IrOp::IntSLessEqual { dst: cond.clone(), a: flags, b: zero },
        CondKind::SGrtr => IrOp::IntSLess { dst: cond.clone(), a: zero, b: flags },
        CondKind::ULess => IrOp::IntLess { dst: cond.clone(), a: flags, b: zero },
        CondKind::UGrEq => IrOp::IntLessEqual { dst: cond.clone(), a: zero, b: flags },
        CondKind::ULessEq => IrOp::IntLessEqual { dst: cond.clone(), a: flags, b: zero },
        CondKind::UGrtr => IrOp::IntLess { dst: cond.clone(), a: zero, b: flags },
        CondKind::Sign => IrOp::IntSLess { dst: cond.clone(), a: flags, b: zero },
        CondKind::NotSign => IrOp::IntSLessEqual { dst: cond.clone(), a: zero, b: flags },
    };
    ctx.emit(cmp_op);
    ctx.emit(IrOp::CBranch { cond, target });
}

fn lift_call(ctx: &mut LiftContext, operands: &str) {
    let operands = operands.trim();
    if let Some(target) = parse_immediate(operands) {
        ctx.emit(IrOp::Call { target });
    } else {
        let target = parse_operand(ctx, operands);
        ctx.emit(IrOp::CallInd { target });
    }
}

// -- Operand parsing helpers --

fn split_operands(s: &str) -> Option<(&str, &str)> {
    // Find the first comma that's not inside brackets
    let mut depth = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                return Some((s[..i].trim(), s[i + 1..].trim()));
            }
            _ => {}
        }
    }
    None
}

fn is_memory_operand(s: &str) -> bool {
    s.contains('[')
}

fn parse_operand(ctx: &mut LiftContext, s: &str) -> VarNode {
    let s = s.trim();

    // Try as immediate
    if let Some(val) = parse_immediate(s) {
        return VarNode::constant(val, 8);
    }

    // Try as register
    if let Some(reg) = parse_register(s) {
        return reg;
    }

    // Memory operand: strip size prefix and extract address
    let inner = s
        .trim_start_matches("qword ptr ")
        .trim_start_matches("dword ptr ")
        .trim_start_matches("word ptr ")
        .trim_start_matches("byte ptr ");

    let mem_size = if s.starts_with("byte") {
        1
    } else if s.starts_with("word") {
        2
    } else if s.starts_with("dword") {
        4
    } else {
        8
    };

    if let Some(addr) = parse_memory_expression(ctx, inner) {
        VarNode { size: mem_size, ..addr }
    } else {
        // Fallback: unrecognized operand → constant 0
        VarNode::constant(0, 8)
    }
}

fn parse_immediate(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches('#');
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else if s.starts_with('-') {
        s.parse::<i64>().ok().map(|v| v as u64)
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_register(s: &str) -> Option<VarNode> {
    let s = s.trim().to_lowercase();
    let (offset, size) = match s.as_str() {
        // 64-bit
        "rax" => (regs::RAX, 8),
        "rcx" => (regs::RCX, 8),
        "rdx" => (regs::RDX, 8),
        "rbx" => (regs::RBX, 8),
        "rsp" => (regs::RSP, 8),
        "rbp" => (regs::RBP, 8),
        "rsi" => (regs::RSI, 8),
        "rdi" => (regs::RDI, 8),
        "r8" => (regs::R8, 8),
        "r9" => (regs::R9, 8),
        "r10" => (regs::R10, 8),
        "r11" => (regs::R11, 8),
        "r12" => (regs::R12, 8),
        "r13" => (regs::R13, 8),
        "r14" => (regs::R14, 8),
        "r15" => (regs::R15, 8),
        "rip" => (regs::RIP, 8),
        // 32-bit
        "eax" => (regs::RAX, 4),
        "ecx" => (regs::RCX, 4),
        "edx" => (regs::RDX, 4),
        "ebx" => (regs::RBX, 4),
        "esp" => (regs::RSP, 4),
        "ebp" => (regs::RBP, 4),
        "esi" => (regs::RSI, 4),
        "edi" => (regs::RDI, 4),
        "r8d" => (regs::R8, 4),
        "r9d" => (regs::R9, 4),
        "r10d" => (regs::R10, 4),
        "r11d" => (regs::R11, 4),
        "r12d" => (regs::R12, 4),
        "r13d" => (regs::R13, 4),
        "r14d" => (regs::R14, 4),
        "r15d" => (regs::R15, 4),
        // 16-bit
        "ax" => (regs::RAX, 2),
        "cx" => (regs::RCX, 2),
        "dx" => (regs::RDX, 2),
        "bx" => (regs::RBX, 2),
        // 8-bit
        "al" => (regs::RAX, 1),
        "cl" => (regs::RCX, 1),
        "dl" => (regs::RDX, 1),
        "bl" => (regs::RBX, 1),
        _ => return None,
    };
    Some(VarNode::reg(offset, size))
}

fn parse_memory_expression(ctx: &mut LiftContext, s: &str) -> Option<VarNode> {
    // Extract content inside brackets
    let inner = s.trim();
    if !inner.starts_with('[') || !inner.ends_with(']') {
        return None;
    }
    let inner = &inner[1..inner.len() - 1].trim();

    // Simple cases: [reg], [reg + imm], [reg - imm], [reg + reg*scale + imm]
    // We compute the effective address into a temp

    let parts: Vec<&str> = inner.split('+').map(|p| p.trim()).collect();

    if parts.len() == 1 {
        // Could be [reg], [reg - imm], or [imm]
        if let Some(reg) = parse_register(parts[0]) {
            return Some(VarNode::mem(reg.offset, 8));
        }
        // Check for subtraction: "reg - imm"
        if let Some((base_str, off_str)) = parts[0].split_once('-') {
            if let (Some(base), Some(off)) = (parse_register(base_str.trim()), parse_immediate(off_str.trim())) {
                let addr = ctx.new_temp(8);
                ctx.emit(IrOp::IntSub {
                    dst: addr.clone(),
                    a: base,
                    b: VarNode::constant(off, 8),
                });
                return Some(addr);
            }
        }
        if let Some(val) = parse_immediate(parts[0]) {
            return Some(VarNode::mem(val, 8));
        }
    } else if parts.len() == 2 {
        // [reg + imm] or [reg + reg]
        let a = parse_register(parts[0]).or_else(|| parse_immediate(parts[0]).map(|v| VarNode::constant(v, 8)));
        let b = parse_register(parts[1]).or_else(|| parse_immediate(parts[1]).map(|v| VarNode::constant(v, 8)));
        if let (Some(a), Some(b)) = (a, b) {
            let addr = ctx.new_temp(8);
            ctx.emit(IrOp::IntAdd { dst: addr.clone(), a, b });
            return Some(addr);
        }
    }

    // Fallback: emit as unresolved
    let addr = ctx.new_temp(8);
    ctx.emit(IrOp::Copy { dst: addr.clone(), src: VarNode::constant(0, 8) });
    Some(addr)
}
