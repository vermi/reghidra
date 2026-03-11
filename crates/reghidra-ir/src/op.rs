use serde::{Deserialize, Serialize};

/// Address space for a varnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VarSpace {
    /// A machine register (e.g., RAX, X0).
    Register,
    /// A temporary variable created during lifting.
    Temp,
    /// A constant/immediate value.
    Constant,
    /// RAM / main memory.
    Memory,
    /// Stack-relative offset.
    Stack,
}

/// A varnode: a sized reference to a location in some address space.
/// This is the fundamental data unit in the IR (inspired by Ghidra's P-code varnodes).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VarNode {
    /// Which address space this varnode lives in.
    pub space: VarSpace,
    /// Offset within the space (register index, memory address, constant value, temp id).
    pub offset: u64,
    /// Size in bytes.
    pub size: u8,
}

impl VarNode {
    pub fn reg(offset: u64, size: u8) -> Self {
        Self { space: VarSpace::Register, offset, size }
    }

    pub fn temp(id: u64, size: u8) -> Self {
        Self { space: VarSpace::Temp, offset: id, size }
    }

    pub fn constant(value: u64, size: u8) -> Self {
        Self { space: VarSpace::Constant, offset: value, size }
    }

    pub fn mem(addr: u64, size: u8) -> Self {
        Self { space: VarSpace::Memory, offset: addr, size }
    }

    pub fn stack(offset: u64, size: u8) -> Self {
        Self { space: VarSpace::Stack, offset, size }
    }

    pub fn is_const(&self) -> bool {
        self.space == VarSpace::Constant
    }

    pub fn is_temp(&self) -> bool {
        self.space == VarSpace::Temp
    }

    pub fn const_value(&self) -> Option<u64> {
        if self.space == VarSpace::Constant { Some(self.offset) } else { None }
    }
}

/// An operand in an IR instruction: either a varnode or absent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operand {
    Var(VarNode),
    None,
}

impl Operand {
    pub fn var(&self) -> Option<&VarNode> {
        match self {
            Operand::Var(v) => Some(v),
            Operand::None => None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Operand::None)
    }
}

impl From<VarNode> for Operand {
    fn from(v: VarNode) -> Self {
        Operand::Var(v)
    }
}

/// IR operations — architecture-neutral instruction set.
/// Modeled after Ghidra's P-code with some simplifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrOp {
    // -- Data movement --
    /// dst = src
    Copy { dst: VarNode, src: VarNode },
    /// dst = *src (load from memory)
    Load { dst: VarNode, addr: VarNode },
    /// *addr = src (store to memory)
    Store { addr: VarNode, src: VarNode },

    // -- Arithmetic --
    /// dst = a + b
    IntAdd { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a - b
    IntSub { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a * b (unsigned)
    IntMul { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a / b (unsigned)
    IntDiv { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a % b (unsigned)
    IntRem { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a * b (signed)
    IntSMul { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a / b (signed)
    IntSDiv { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a % b (signed)
    IntSRem { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = -a
    IntNeg { dst: VarNode, src: VarNode },

    // -- Bitwise --
    /// dst = a & b
    IntAnd { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a | b
    IntOr { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a ^ b
    IntXor { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = ~a
    IntNot { dst: VarNode, src: VarNode },
    /// dst = a << b
    IntShl { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a >> b (logical)
    IntShr { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = a >> b (arithmetic)
    IntSar { dst: VarNode, a: VarNode, b: VarNode },

    // -- Comparison (result is 1-byte boolean) --
    /// dst = (a == b)
    IntEqual { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = (a != b)
    IntNotEqual { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = (a < b) unsigned
    IntLess { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = (a <= b) unsigned
    IntLessEqual { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = (a < b) signed
    IntSLess { dst: VarNode, a: VarNode, b: VarNode },
    /// dst = (a <= b) signed
    IntSLessEqual { dst: VarNode, a: VarNode, b: VarNode },

    // -- Extension / Truncation --
    /// dst = zero_extend(src)
    IntZext { dst: VarNode, src: VarNode },
    /// dst = sign_extend(src)
    IntSext { dst: VarNode, src: VarNode },
    /// dst = truncate(src) — take low bytes
    Subpiece { dst: VarNode, src: VarNode, offset: u8 },

    // -- Control flow --
    /// Unconditional branch to target address.
    Branch { target: u64 },
    /// Conditional branch: if cond != 0, branch to target.
    CBranch { cond: VarNode, target: u64 },
    /// Call a function at target address.
    Call { target: u64 },
    /// Indirect call through a register/varnode.
    CallInd { target: VarNode },
    /// Return from function.
    Return { value: Operand },
    /// Indirect branch through a register/varnode.
    BranchInd { target: VarNode },

    // -- SSA/Analysis --
    /// Phi node (SSA): dst = phi(inputs...). Added during SSA construction.
    Phi { dst: VarNode, inputs: Vec<VarNode> },

    // -- Special --
    /// No operation.
    Nop,
    /// Unimplemented/unlifted instruction (preserves the original mnemonic).
    Unimplemented { mnemonic: String, operands: String },
}

impl IrOp {
    /// Get the destination varnode if this op writes to one.
    pub fn dst(&self) -> Option<&VarNode> {
        match self {
            IrOp::Copy { dst, .. }
            | IrOp::Load { dst, .. }
            | IrOp::IntAdd { dst, .. }
            | IrOp::IntSub { dst, .. }
            | IrOp::IntMul { dst, .. }
            | IrOp::IntDiv { dst, .. }
            | IrOp::IntRem { dst, .. }
            | IrOp::IntSMul { dst, .. }
            | IrOp::IntSDiv { dst, .. }
            | IrOp::IntSRem { dst, .. }
            | IrOp::IntNeg { dst, .. }
            | IrOp::IntAnd { dst, .. }
            | IrOp::IntOr { dst, .. }
            | IrOp::IntXor { dst, .. }
            | IrOp::IntNot { dst, .. }
            | IrOp::IntShl { dst, .. }
            | IrOp::IntShr { dst, .. }
            | IrOp::IntSar { dst, .. }
            | IrOp::IntEqual { dst, .. }
            | IrOp::IntNotEqual { dst, .. }
            | IrOp::IntLess { dst, .. }
            | IrOp::IntLessEqual { dst, .. }
            | IrOp::IntSLess { dst, .. }
            | IrOp::IntSLessEqual { dst, .. }
            | IrOp::IntZext { dst, .. }
            | IrOp::IntSext { dst, .. }
            | IrOp::Subpiece { dst, .. }
            | IrOp::Phi { dst, .. } => Some(dst),
            _ => None,
        }
    }

    /// Get all source varnodes read by this op.
    pub fn sources(&self) -> Vec<&VarNode> {
        match self {
            IrOp::Copy { src, .. } => vec![src],
            IrOp::Load { addr, .. } => vec![addr],
            IrOp::Store { addr, src } => vec![addr, src],
            IrOp::IntAdd { a, b, .. }
            | IrOp::IntSub { a, b, .. }
            | IrOp::IntMul { a, b, .. }
            | IrOp::IntDiv { a, b, .. }
            | IrOp::IntRem { a, b, .. }
            | IrOp::IntSMul { a, b, .. }
            | IrOp::IntSDiv { a, b, .. }
            | IrOp::IntSRem { a, b, .. }
            | IrOp::IntAnd { a, b, .. }
            | IrOp::IntOr { a, b, .. }
            | IrOp::IntXor { a, b, .. }
            | IrOp::IntShl { a, b, .. }
            | IrOp::IntShr { a, b, .. }
            | IrOp::IntSar { a, b, .. }
            | IrOp::IntEqual { a, b, .. }
            | IrOp::IntNotEqual { a, b, .. }
            | IrOp::IntLess { a, b, .. }
            | IrOp::IntLessEqual { a, b, .. }
            | IrOp::IntSLess { a, b, .. }
            | IrOp::IntSLessEqual { a, b, .. } => vec![a, b],
            IrOp::IntNeg { src, .. }
            | IrOp::IntNot { src, .. }
            | IrOp::IntZext { src, .. }
            | IrOp::IntSext { src, .. }
            | IrOp::Subpiece { src, .. } => vec![src],
            IrOp::CBranch { cond, .. } => vec![cond],
            IrOp::CallInd { target } | IrOp::BranchInd { target } => vec![target],
            IrOp::Return { value } => {
                if let Some(v) = value.var() { vec![v] } else { vec![] }
            }
            IrOp::Phi { inputs, .. } => inputs.iter().collect(),
            _ => vec![],
        }
    }

    /// Whether this op is a control flow terminator.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            IrOp::Branch { .. }
                | IrOp::CBranch { .. }
                | IrOp::Return { .. }
                | IrOp::BranchInd { .. }
        )
    }
}
