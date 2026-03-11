pub mod ast;
pub mod emit;
pub mod expr_builder;
pub mod structuring;
pub mod types;
pub mod varnames;

pub use emit::AnnotatedLine;

use reghidra_ir::IrFunction;

/// Decompile context: everything needed to decompile one function.
pub struct DecompileContext {
    /// Known function names by address (for resolving call targets).
    pub function_names: std::collections::HashMap<u64, String>,
    /// Known string literals by address.
    pub string_literals: std::collections::HashMap<u64, String>,
    /// CFG successors for each block.
    pub successors: std::collections::HashMap<u64, Vec<u64>>,
    /// CFG predecessors for each block.
    pub predecessors: std::collections::HashMap<u64, Vec<u64>>,
}

/// Decompile an IR function into C-like pseudocode.
pub fn decompile(ir: &IrFunction, ctx: &DecompileContext) -> String {
    // Step 1: Build expressions from IR ops
    let block_stmts = expr_builder::build_statements(ir, ctx);

    // Step 2: Structure control flow
    let body = structuring::structure(ir, &block_stmts, ctx);

    // Step 3: Assign variable names
    let body = varnames::rename_variables(body);

    // Step 4: Emit C-like code
    emit::emit_function(&ir.name, &body)
}

/// Decompile an IR function into annotated lines (text + source address per line).
pub fn decompile_annotated(ir: &IrFunction, ctx: &DecompileContext) -> Vec<AnnotatedLine> {
    let block_stmts = expr_builder::build_statements(ir, ctx);
    let body = structuring::structure(ir, &block_stmts, ctx);
    let body = varnames::rename_variables(body);
    emit::emit_function_annotated(&ir.name, &body)
}
