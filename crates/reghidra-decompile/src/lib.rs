pub mod ast;
pub mod emit;
pub mod expr_builder;
pub mod stackframe;
pub mod structuring;
pub mod type_archive;
pub mod types;
pub mod varnames;

pub use emit::AnnotatedLine;
pub use stackframe::{FrameLayout, StackSlot};
pub use type_archive::TypeArchive;

use reghidra_ir::IrFunction;
use std::sync::Arc;

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
    /// Bundled type archives matching the current binary's format and
    /// architecture. Consumed in later Phase 5c PRs for arity capping on
    /// stack-arg collapse, typed `VarDecl` emission, and return-type
    /// propagation. Carried by `Arc` so the context can be cheaply
    /// constructed per-function without cloning the underlying archive.
    /// Empty during PR 2 — the field is wired in but not yet read.
    pub type_archives: Vec<Arc<TypeArchive>>,
}

/// Output of [`decompile`]: the rendered C-like pseudocode plus the frame
/// layout recovered by the tier-2 heuristic stack-frame pass.
///
/// The frame layout is returned (rather than discarded internally) so that
/// callers higher up in the stack — `reghidra-core::project`, session
/// persistence, the retype UI — can inspect and mutate the detected slots
/// without re-running the decompile pipeline.
pub struct DecompileOutput {
    pub text: String,
    pub frame_layout: FrameLayout,
}

/// Output of [`decompile_annotated`]: annotated emit lines, the set of
/// post-rename variable names that appear in the output (used by the GUI's
/// right-click tokenizer), and the recovered frame layout.
pub struct DecompileAnnotated {
    pub lines: Vec<AnnotatedLine>,
    pub variable_names: Vec<String>,
    pub frame_layout: FrameLayout,
}

/// Decompile an IR function into C-like pseudocode.
pub fn decompile(ir: &IrFunction, ctx: &DecompileContext) -> DecompileOutput {
    // Step 1: Build expressions from IR ops
    let block_stmts = expr_builder::build_statements(ir, ctx);

    // Step 2: Structure control flow
    let body = structuring::structure(ir, &block_stmts, ctx);

    // Step 3: Stack frame analysis. Rewrites *(rbp±k) / via-temp stack
    // derefs into named local_/arg_ slots, drops the prologue bookkeeping,
    // and emits VarDecl statements at the top for each discovered slot.
    // Runs BEFORE rename_variables so the rbp/rsp detection sees the raw
    // register names the expression builder emits.
    let (body, frame_layout) = stackframe::analyze_and_rewrite(body);

    // Step 4: Assign variable names (with user overrides applied as a final pass)
    let body = varnames::rename_variables(body, &ctx.variable_names);

    // Step 5: Emit C-like code
    let display_name = ctx.current_function_display_name.as_deref().unwrap_or(&ir.name);
    let text = emit::emit_function(display_name, &body, &ctx.label_names);
    DecompileOutput { text, frame_layout }
}

/// Decompile an IR function into annotated lines, the set of post-rename
/// variable names that appear in the output (for the GUI's right-click
/// tokenizer), and the recovered frame layout.
pub fn decompile_annotated(
    ir: &IrFunction,
    ctx: &DecompileContext,
) -> DecompileAnnotated {
    let block_stmts = expr_builder::build_statements(ir, ctx);
    let body = structuring::structure(ir, &block_stmts, ctx);
    let (body, frame_layout) = stackframe::analyze_and_rewrite(body);
    let body = varnames::rename_variables(body, &ctx.variable_names);
    let variable_names = varnames::collect_displayed_names(&body);
    let display_name = ctx.current_function_display_name.as_deref().unwrap_or(&ir.name);
    let lines = emit::emit_function_annotated(display_name, &body, &ctx.label_names);
    DecompileAnnotated { lines, variable_names, frame_layout }
}
