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
    /// User-renamed labels (block address → display name). Replaces the
    /// default `label_XXXX` form when present.
    pub label_names: std::collections::HashMap<u64, String>,
    /// User-renamed local variables: post-heuristic displayed name → user name.
    pub variable_names: std::collections::HashMap<String, String>,
    /// Optional display name for the current function. When set, `emit_function`
    /// prefers this over the IR function's canonical `name`. Used to show a
    /// demangled form (e.g. MSVC C++ signatures) while keeping the mangled name
    /// as the canonical identifier in storage and xrefs.
    pub current_function_display_name: Option<String>,
}

/// Decompile an IR function into C-like pseudocode.
pub fn decompile(ir: &IrFunction, ctx: &DecompileContext) -> String {
    // Step 1: Build expressions from IR ops
    let block_stmts = expr_builder::build_statements(ir, ctx);

    // Step 2: Structure control flow
    let body = structuring::structure(ir, &block_stmts, ctx);

    // Step 3: Assign variable names (with user overrides applied as a final pass)
    let body = varnames::rename_variables(body, &ctx.variable_names);

    // Step 4: Emit C-like code
    let display_name = ctx.current_function_display_name.as_deref().unwrap_or(&ir.name);
    emit::emit_function(display_name, &body, &ctx.label_names)
}

/// Decompile an IR function into annotated lines and the set of post-rename
/// variable names that appear in the output (for the GUI's right-click
/// tokenizer).
pub fn decompile_annotated(
    ir: &IrFunction,
    ctx: &DecompileContext,
) -> (Vec<AnnotatedLine>, Vec<String>) {
    let block_stmts = expr_builder::build_statements(ir, ctx);
    let body = structuring::structure(ir, &block_stmts, ctx);
    let body = varnames::rename_variables(body, &ctx.variable_names);
    let var_names = varnames::collect_displayed_names(&body);
    let display_name = ctx.current_function_display_name.as_deref().unwrap_or(&ir.name);
    let lines = emit::emit_function_annotated(display_name, &body, &ctx.label_names);
    (lines, var_names)
}
