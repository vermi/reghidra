use super::{DisasmInput, LiftContext};
use crate::op::{IrOp, Operand, VarNode};
use crate::types::IrFunction;

// ARM64 register offsets
pub mod regs {
    pub const X0: u64 = 0;
    pub const X1: u64 = 1;
    pub const X2: u64 = 2;
    pub const X3: u64 = 3;
    pub const X4: u64 = 4;
    pub const X5: u64 = 5;
    pub const X6: u64 = 6;
    pub const X7: u64 = 7;
    pub const X8: u64 = 8;
    pub const X9: u64 = 9;
    pub const X10: u64 = 10;
    pub const X11: u64 = 11;
    pub const X12: u64 = 12;
    pub const X13: u64 = 13;
    pub const X14: u64 = 14;
    pub const X15: u64 = 15;
    pub const X16: u64 = 16;
    pub const X17: u64 = 17;
    pub const X18: u64 = 18;
    pub const X19: u64 = 19;
    pub const X20: u64 = 20;
    pub const X21: u64 = 21;
    pub const X22: u64 = 22;
    pub const X23: u64 = 23;
    pub const X24: u64 = 24;
    pub const X25: u64 = 25;
    pub const X26: u64 = 26;
    pub const X27: u64 = 27;
    pub const X28: u64 = 28;
    pub const X29: u64 = 29; // FP
    pub const X30: u64 = 30; // LR
    pub const SP: u64 = 31;
    pub const XZR: u64 = 32; // zero register
    pub const PC: u64 = 33;
    pub const NZCV: u64 = 34; // condition flags
}

/// Lift a sequence of ARM64 instructions into an IR function.
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
        "mov" => lift_mov(ctx, operands),
        "movz" => lift_movz(ctx, operands),
        "movk" => lift_movk(ctx, operands),
        "movn" => lift_movn(ctx, operands),
        "ldr" | "ldrsw" => lift_ldr(ctx, operands, mnemonic == "ldrsw"),
        "ldrb" => lift_ldr_sized(ctx, operands, 1, false),
        "ldrh" => lift_ldr_sized(ctx, operands, 2, false),
        "ldrsb" => lift_ldr_sized(ctx, operands, 1, true),
        "ldrsh" => lift_ldr_sized(ctx, operands, 2, true),
        "str" => lift_str(ctx, operands),
        "strb" => lift_str_sized(ctx, operands, 1),
        "strh" => lift_str_sized(ctx, operands, 2),
        "stp" => lift_stp(ctx, operands),
        "ldp" => lift_ldp(ctx, operands),
        "add" => lift_binop(ctx, operands, AluOp::Add),
        "sub" | "subs" => lift_binop(ctx, operands, AluOp::Sub),
        "mul" => lift_binop(ctx, operands, AluOp::Mul),
        "and" | "ands" => lift_binop(ctx, operands, AluOp::And),
        "orr" => lift_binop(ctx, operands, AluOp::Or),
        "eor" => lift_binop(ctx, operands, AluOp::Xor),
        "lsl" => lift_binop(ctx, operands, AluOp::Shl),
        "lsr" => lift_binop(ctx, operands, AluOp::Shr),
        "asr" => lift_binop(ctx, operands, AluOp::Sar),
        "neg" => lift_neg(ctx, operands),
        "mvn" => lift_mvn(ctx, operands),
        "cmp" => lift_cmp(ctx, operands),
        "tst" => lift_tst(ctx, operands),
        "b" => lift_branch(ctx, operands),
        "bl" => lift_bl(ctx, operands),
        "blr" => lift_blr(ctx, operands),
        "br" => lift_br(ctx, operands),
        "ret" => {
            ctx.emit(IrOp::Return { value: Operand::Var(VarNode::reg(regs::X0, 8)) });
        }
        "cbz" => lift_cbz(ctx, operands, true),
        "cbnz" => lift_cbz(ctx, operands, false),
        "b.eq" | "b.ne" | "b.lt" | "b.ge" | "b.le" | "b.gt"
        | "b.lo" | "b.hs" | "b.hi" | "b.ls" | "b.mi" | "b.pl" => {
            lift_bcond(ctx, mnemonic, operands);
        }
        "adr" | "adrp" => lift_adr(ctx, operands),
        "sxtw" => lift_sxtw(ctx, operands),
        "uxtb" => lift_uxt(ctx, operands, 1),
        "uxth" => lift_uxt(ctx, operands, 2),
        "nop" => ctx.emit(IrOp::Nop),
        _ => {
            ctx.emit(IrOp::Unimplemented {
                mnemonic: insn.mnemonic.clone(),
                operands: insn.operands.clone(),
            });
        }
    }
}

enum AluOp { Add, Sub, Mul, And, Or, Xor, Shl, Shr, Sar }

fn lift_mov(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "mov", operands); }
    let dst = parse_reg(parts[0]);
    let src = parse_reg_or_imm(parts[1]);
    ctx.emit(IrOp::Copy { dst, src });
}

fn lift_movz(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() < 2 { return emit_unimpl(ctx, "movz", operands); }
    let dst = parse_reg(parts[0]);
    // movz Xd, #imm{, lsl #shift}
    let rest = parts[1];
    let (imm_str, shift) = parse_imm_with_shift(rest);
    let val = parse_immediate(imm_str).unwrap_or(0) << shift;
    ctx.emit(IrOp::Copy { dst, src: VarNode::constant(val, 8) });
}

fn lift_movk(ctx: &mut LiftContext, operands: &str) {
    // movk keeps other bits, inserts imm at shift position
    // Simplified: just emit as unimplemented for now since it requires
    // bitfield manipulation that needs proper mask support
    emit_unimpl(ctx, "movk", operands);
}

fn lift_movn(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() < 2 { return emit_unimpl(ctx, "movn", operands); }
    let dst = parse_reg(parts[0]);
    let (imm_str, shift) = parse_imm_with_shift(parts[1]);
    let val = !(parse_immediate(imm_str).unwrap_or(0) << shift);
    ctx.emit(IrOp::Copy { dst, src: VarNode::constant(val, 8) });
}

fn lift_ldr(ctx: &mut LiftContext, operands: &str, sign_extend: bool) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "ldr", operands); }
    let dst = parse_reg(parts[0]);
    let addr = parse_mem_operand(ctx, parts[1]);
    if sign_extend {
        let tmp = ctx.new_temp(4);
        ctx.emit(IrOp::Load { dst: tmp.clone(), addr });
        ctx.emit(IrOp::IntSext { dst, src: tmp });
    } else {
        ctx.emit(IrOp::Load { dst, addr });
    }
}

fn lift_ldr_sized(ctx: &mut LiftContext, operands: &str, size: u8, sign_extend: bool) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "ldr", operands); }
    let dst = parse_reg(parts[0]);
    let addr = parse_mem_operand(ctx, parts[1]);
    let tmp = ctx.new_temp(size);
    ctx.emit(IrOp::Load { dst: tmp.clone(), addr });
    if sign_extend {
        ctx.emit(IrOp::IntSext { dst, src: tmp });
    } else {
        ctx.emit(IrOp::IntZext { dst, src: tmp });
    }
}

fn lift_str(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "str", operands); }
    let src = parse_reg(parts[0]);
    let addr = parse_mem_operand(ctx, parts[1]);
    ctx.emit(IrOp::Store { addr, src });
}

fn lift_str_sized(ctx: &mut LiftContext, operands: &str, _size: u8) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "str", operands); }
    let src = parse_reg(parts[0]);
    let addr = parse_mem_operand(ctx, parts[1]);
    ctx.emit(IrOp::Store { addr, src });
}

fn lift_stp(ctx: &mut LiftContext, operands: &str) {
    // stp Rt1, Rt2, [Rn, #imm]
    let parts: Vec<&str> = operands.splitn(3, ',').map(|s| s.trim()).collect();
    if parts.len() < 3 { return emit_unimpl(ctx, "stp", operands); }
    let r1 = parse_reg(parts[0]);
    let r2 = parse_reg(parts[1]);
    let addr = parse_mem_operand(ctx, parts[2]);
    ctx.emit(IrOp::Store { addr: addr.clone(), src: r1 });
    let addr2 = ctx.new_temp(8);
    ctx.emit(IrOp::IntAdd { dst: addr2.clone(), a: addr, b: VarNode::constant(8, 8) });
    ctx.emit(IrOp::Store { addr: addr2, src: r2 });
}

fn lift_ldp(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(3, ',').map(|s| s.trim()).collect();
    if parts.len() < 3 { return emit_unimpl(ctx, "ldp", operands); }
    let r1 = parse_reg(parts[0]);
    let r2 = parse_reg(parts[1]);
    let addr = parse_mem_operand(ctx, parts[2]);
    ctx.emit(IrOp::Load { dst: r1, addr: addr.clone() });
    let addr2 = ctx.new_temp(8);
    ctx.emit(IrOp::IntAdd { dst: addr2.clone(), a: addr, b: VarNode::constant(8, 8) });
    ctx.emit(IrOp::Load { dst: r2, addr: addr2 });
}

fn lift_binop(ctx: &mut LiftContext, operands: &str, op: AluOp) {
    let parts: Vec<&str> = operands.splitn(3, ',').map(|s| s.trim()).collect();
    if parts.len() < 3 { return emit_unimpl(ctx, "alu", operands); }
    let dst = parse_reg(parts[0]);
    let a = parse_reg_or_imm(parts[1]);
    let b = parse_reg_or_imm(parts[2]);
    let ir_op = match op {
        AluOp::Add => IrOp::IntAdd { dst, a, b },
        AluOp::Sub => IrOp::IntSub { dst, a, b },
        AluOp::Mul => IrOp::IntMul { dst, a, b },
        AluOp::And => IrOp::IntAnd { dst, a, b },
        AluOp::Or => IrOp::IntOr { dst, a, b },
        AluOp::Xor => IrOp::IntXor { dst, a, b },
        AluOp::Shl => IrOp::IntShl { dst, a, b },
        AluOp::Shr => IrOp::IntShr { dst, a, b },
        AluOp::Sar => IrOp::IntSar { dst, a, b },
    };
    ctx.emit(ir_op);
}

fn lift_neg(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "neg", operands); }
    let dst = parse_reg(parts[0]);
    let src = parse_reg(parts[1]);
    ctx.emit(IrOp::IntNeg { dst, src });
}

fn lift_mvn(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "mvn", operands); }
    let dst = parse_reg(parts[0]);
    let src = parse_reg(parts[1]);
    ctx.emit(IrOp::IntNot { dst, src });
}

fn lift_cmp(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "cmp", operands); }
    let a = parse_reg_or_imm(parts[0]);
    let b = parse_reg_or_imm(parts[1]);
    let flags = VarNode::reg(regs::NZCV, 8);
    ctx.emit(IrOp::IntSub { dst: flags, a, b });
}

fn lift_tst(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "tst", operands); }
    let a = parse_reg_or_imm(parts[0]);
    let b = parse_reg_or_imm(parts[1]);
    let flags = VarNode::reg(regs::NZCV, 8);
    ctx.emit(IrOp::IntAnd { dst: flags, a, b });
}

fn lift_branch(ctx: &mut LiftContext, operands: &str) {
    if let Some(target) = parse_immediate(operands.trim()) {
        ctx.emit(IrOp::Branch { target });
    } else {
        let target = parse_reg(operands.trim());
        ctx.emit(IrOp::BranchInd { target });
    }
}

fn lift_bl(ctx: &mut LiftContext, operands: &str) {
    if let Some(target) = parse_immediate(operands.trim()) {
        ctx.emit(IrOp::Call { target });
    } else {
        emit_unimpl(ctx, "bl", operands);
    }
}

fn lift_blr(ctx: &mut LiftContext, operands: &str) {
    let target = parse_reg(operands.trim());
    ctx.emit(IrOp::CallInd { target });
}

fn lift_br(ctx: &mut LiftContext, operands: &str) {
    let target = parse_reg(operands.trim());
    ctx.emit(IrOp::BranchInd { target });
}

fn lift_cbz(ctx: &mut LiftContext, operands: &str, is_zero: bool) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "cbz", operands); }
    let reg = parse_reg(parts[0]);
    let target = match parse_immediate(parts[1]) {
        Some(t) => t,
        None => return emit_unimpl(ctx, "cbz", operands),
    };
    let cond = ctx.new_temp(1);
    let zero = VarNode::constant(0, reg.size);
    if is_zero {
        ctx.emit(IrOp::IntEqual { dst: cond.clone(), a: reg, b: zero });
    } else {
        ctx.emit(IrOp::IntNotEqual { dst: cond.clone(), a: reg, b: zero });
    }
    ctx.emit(IrOp::CBranch { cond, target });
}

fn lift_bcond(ctx: &mut LiftContext, mnemonic: &str, operands: &str) {
    let target = match parse_immediate(operands.trim()) {
        Some(t) => t,
        None => return emit_unimpl(ctx, mnemonic, operands),
    };
    let flags = VarNode::reg(regs::NZCV, 8);
    let zero = VarNode::constant(0, 8);
    let cond = ctx.new_temp(1);

    let cmp_op = match mnemonic {
        "b.eq" => IrOp::IntEqual { dst: cond.clone(), a: flags.clone(), b: zero },
        "b.ne" => IrOp::IntNotEqual { dst: cond.clone(), a: flags.clone(), b: zero },
        "b.lt" | "b.mi" => IrOp::IntSLess { dst: cond.clone(), a: flags.clone(), b: zero },
        "b.ge" | "b.pl" => IrOp::IntSLessEqual { dst: cond.clone(), a: zero.clone(), b: flags.clone() },
        "b.le" => IrOp::IntSLessEqual { dst: cond.clone(), a: flags.clone(), b: zero },
        "b.gt" => IrOp::IntSLess { dst: cond.clone(), a: zero.clone(), b: flags.clone() },
        "b.lo" => IrOp::IntLess { dst: cond.clone(), a: flags.clone(), b: zero },
        "b.hs" => IrOp::IntLessEqual { dst: cond.clone(), a: zero.clone(), b: flags.clone() },
        "b.hi" => IrOp::IntLess { dst: cond.clone(), a: zero.clone(), b: flags.clone() },
        "b.ls" => IrOp::IntLessEqual { dst: cond.clone(), a: flags.clone(), b: zero },
        _ => return emit_unimpl(ctx, mnemonic, operands),
    };
    ctx.emit(cmp_op);
    ctx.emit(IrOp::CBranch { cond, target });
}

fn lift_adr(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "adr", operands); }
    let dst = parse_reg(parts[0]);
    if let Some(addr) = parse_immediate(parts[1]) {
        ctx.emit(IrOp::Copy { dst, src: VarNode::constant(addr, 8) });
    } else {
        emit_unimpl(ctx, "adr", operands);
    }
}

fn lift_sxtw(ctx: &mut LiftContext, operands: &str) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "sxtw", operands); }
    let dst = parse_reg(parts[0]);
    let src = parse_reg(parts[1]);
    ctx.emit(IrOp::IntSext { dst, src: VarNode { size: 4, ..src } });
}

fn lift_uxt(ctx: &mut LiftContext, operands: &str, src_size: u8) {
    let parts: Vec<&str> = operands.splitn(2, ',').map(|s| s.trim()).collect();
    if parts.len() != 2 { return emit_unimpl(ctx, "uxt", operands); }
    let dst = parse_reg(parts[0]);
    let src = parse_reg(parts[1]);
    ctx.emit(IrOp::IntZext { dst, src: VarNode { size: src_size, ..src } });
}

// -- Helpers --

fn emit_unimpl(ctx: &mut LiftContext, mnemonic: &str, operands: &str) {
    ctx.emit(IrOp::Unimplemented {
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
    });
}

fn parse_reg(s: &str) -> VarNode {
    let s = s.trim().to_lowercase();
    let s = s.trim_end_matches('!'); // strip pre-index !

    // X registers (64-bit)
    if let Some(num) = s.strip_prefix('x') {
        if let Ok(n) = num.parse::<u64>() {
            if n <= 28 { return VarNode::reg(n, 8); }
        }
    }
    // W registers (32-bit, same offset as X)
    if let Some(num) = s.strip_prefix('w') {
        if let Ok(n) = num.parse::<u64>() {
            if n <= 28 { return VarNode::reg(n, 4); }
        }
        if num == "zr" { return VarNode::reg(regs::XZR, 4); }
    }

    match s {
        "x29" | "fp" => VarNode::reg(regs::X29, 8),
        "x30" | "lr" => VarNode::reg(regs::X30, 8),
        "sp" => VarNode::reg(regs::SP, 8),
        "xzr" => VarNode::reg(regs::XZR, 8),
        "wzr" => VarNode::reg(regs::XZR, 4),
        "pc" => VarNode::reg(regs::PC, 8),
        _ => VarNode::constant(0, 8), // fallback
    }
}

fn parse_reg_or_imm(s: &str) -> VarNode {
    let s = s.trim();
    if let Some(val) = parse_immediate(s) {
        VarNode::constant(val, 8)
    } else {
        parse_reg(s)
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

fn parse_imm_with_shift(s: &str) -> (&str, u32) {
    // "#0x1234, lsl #16" -> ("#0x1234", 16)
    if let Some((imm_part, shift_part)) = s.split_once("lsl") {
        let shift = parse_immediate(shift_part.trim()).unwrap_or(0) as u32;
        (imm_part.trim().trim_end_matches(','), shift)
    } else {
        (s.trim(), 0)
    }
}

fn parse_mem_operand(ctx: &mut LiftContext, s: &str) -> VarNode {
    let s = s.trim();
    // [Xn], [Xn, #imm], [Xn, #imm]!, [sp, #-16]!
    let inner = s.trim_start_matches('[').trim_end_matches(']').trim_end_matches('!');

    let parts: Vec<&str> = inner.splitn(2, ',').map(|p| p.trim()).collect();

    if parts.len() == 1 {
        let base = parse_reg(parts[0]);
        return base;
    }

    let base = parse_reg(parts[0]);
    if let Some(off) = parse_immediate(parts[1]) {
        let addr = ctx.new_temp(8);
        ctx.emit(IrOp::IntAdd {
            dst: addr.clone(),
            a: base,
            b: VarNode::constant(off, 8),
        });
        addr
    } else {
        // Register offset: [Xn, Xm]
        let off = parse_reg(parts[1]);
        let addr = ctx.new_temp(8);
        ctx.emit(IrOp::IntAdd { dst: addr.clone(), a: base, b: off });
        addr
    }
}
