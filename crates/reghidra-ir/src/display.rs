use crate::op::{IrOp, VarNode, VarSpace};
use crate::types::{IrBlock, IrFunction, IrInstruction};
use std::fmt;

impl fmt::Display for VarNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.space {
            VarSpace::Register => write!(f, "r{}:{}", self.offset, self.size),
            VarSpace::Temp => write!(f, "t{}:{}", self.offset, self.size),
            VarSpace::Constant => {
                if self.offset <= 255 {
                    write!(f, "#{}", self.offset)
                } else {
                    write!(f, "#0x{:x}", self.offset)
                }
            }
            VarSpace::Memory => write!(f, "mem[0x{:x}]:{}", self.offset, self.size),
            VarSpace::Stack => write!(f, "stk[0x{:x}]:{}", self.offset, self.size),
        }
    }
}

impl fmt::Display for IrOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrOp::Copy { dst, src } => write!(f, "{dst} = COPY {src}"),
            IrOp::Load { dst, addr } => write!(f, "{dst} = LOAD [{addr}]"),
            IrOp::Store { addr, src } => write!(f, "STORE [{addr}] = {src}"),
            IrOp::IntAdd { dst, a, b } => write!(f, "{dst} = ADD {a}, {b}"),
            IrOp::IntSub { dst, a, b } => write!(f, "{dst} = SUB {a}, {b}"),
            IrOp::IntMul { dst, a, b } => write!(f, "{dst} = MUL {a}, {b}"),
            IrOp::IntDiv { dst, a, b } => write!(f, "{dst} = DIV {a}, {b}"),
            IrOp::IntRem { dst, a, b } => write!(f, "{dst} = REM {a}, {b}"),
            IrOp::IntSMul { dst, a, b } => write!(f, "{dst} = SMUL {a}, {b}"),
            IrOp::IntSDiv { dst, a, b } => write!(f, "{dst} = SDIV {a}, {b}"),
            IrOp::IntSRem { dst, a, b } => write!(f, "{dst} = SREM {a}, {b}"),
            IrOp::IntNeg { dst, src } => write!(f, "{dst} = NEG {src}"),
            IrOp::IntAnd { dst, a, b } => write!(f, "{dst} = AND {a}, {b}"),
            IrOp::IntOr { dst, a, b } => write!(f, "{dst} = OR {a}, {b}"),
            IrOp::IntXor { dst, a, b } => write!(f, "{dst} = XOR {a}, {b}"),
            IrOp::IntNot { dst, src } => write!(f, "{dst} = NOT {src}"),
            IrOp::IntShl { dst, a, b } => write!(f, "{dst} = SHL {a}, {b}"),
            IrOp::IntShr { dst, a, b } => write!(f, "{dst} = SHR {a}, {b}"),
            IrOp::IntSar { dst, a, b } => write!(f, "{dst} = SAR {a}, {b}"),
            IrOp::IntEqual { dst, a, b } => write!(f, "{dst} = EQ {a}, {b}"),
            IrOp::IntNotEqual { dst, a, b } => write!(f, "{dst} = NE {a}, {b}"),
            IrOp::IntLess { dst, a, b } => write!(f, "{dst} = ULT {a}, {b}"),
            IrOp::IntLessEqual { dst, a, b } => write!(f, "{dst} = ULE {a}, {b}"),
            IrOp::IntSLess { dst, a, b } => write!(f, "{dst} = SLT {a}, {b}"),
            IrOp::IntSLessEqual { dst, a, b } => write!(f, "{dst} = SLE {a}, {b}"),
            IrOp::IntZext { dst, src } => write!(f, "{dst} = ZEXT {src}"),
            IrOp::IntSext { dst, src } => write!(f, "{dst} = SEXT {src}"),
            IrOp::Subpiece { dst, src, offset } => write!(f, "{dst} = SUB({src}, {offset})"),
            IrOp::Branch { target } => write!(f, "BRANCH 0x{target:x}"),
            IrOp::CBranch { cond, target } => write!(f, "CBRANCH {cond} -> 0x{target:x}"),
            IrOp::Call { target } => write!(f, "CALL 0x{target:x}"),
            IrOp::CallInd { target } => write!(f, "CALL [{target}]"),
            IrOp::Return { value } => {
                if let Some(v) = value.var() {
                    write!(f, "RETURN {v}")
                } else {
                    write!(f, "RETURN")
                }
            }
            IrOp::BranchInd { target } => write!(f, "BRANCH [{target}]"),
            IrOp::Phi { dst, inputs } => {
                let inputs_str: Vec<String> = inputs.iter().map(|v| v.to_string()).collect();
                write!(f, "{dst} = PHI({})", inputs_str.join(", "))
            }
            IrOp::Nop => write!(f, "NOP"),
            IrOp::Unimplemented { mnemonic, operands } => {
                write!(f, "UNIMPL {mnemonic} {operands}")
            }
        }
    }
}

impl fmt::Display for IrInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}.{:02}  {}", self.address, self.sub_index, self.op)
    }
}

impl fmt::Display for IrBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  block_0x{:x}:", self.address)?;
        for insn in &self.instructions {
            writeln!(f, "    {insn}")?;
        }
        Ok(())
    }
}

impl fmt::Display for IrFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "function {} @ 0x{:x} ({} blocks, {} ops):",
            self.name, self.entry_address, self.blocks.len(), self.instruction_count())?;
        for block in &self.blocks {
            write!(f, "{block}")?;
        }
        Ok(())
    }
}
