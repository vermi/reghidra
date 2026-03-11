use crate::ast::CType;
use reghidra_ir::op::{VarNode, VarSpace};

/// Infer a C type for a varnode based on how it's used in the IR.
pub fn infer_type(varnode: &VarNode) -> CType {
    match varnode.space {
        VarSpace::Constant => CType::from_size(varnode.size, false),
        VarSpace::Register => CType::from_size(varnode.size, false),
        VarSpace::Temp => CType::from_size(varnode.size, false),
        VarSpace::Memory => CType::Pointer(Box::new(CType::from_size(varnode.size, false))),
        VarSpace::Stack => CType::from_size(varnode.size, false),
    }
}
