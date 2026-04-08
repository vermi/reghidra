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
pub use type_archive::{FunctionType, TypeArchive};

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
    /// architecture. Consumed by the Phase 5c typing consumers (arity
    /// capping on stack-arg collapse, typed `VarDecl` emission, and
    /// return-type propagation). Carried by `Arc` so the context can
    /// be cheaply constructed per-function without cloning the
    /// underlying archive.
    pub type_archives: Vec<Arc<TypeArchive>>,
}

impl DecompileContext {
    /// Look up a function prototype across the loaded [`TypeArchive`]s
    /// in order, returning the first match. Used by arity capping,
    /// typed `VarDecl` emission, and (future) return-type propagation
    /// as a single primitive so they all key off the same name-resolution
    /// rule: first archive wins on collision.
    ///
    /// The lookup key is whatever string the caller already has for
    /// the function — typically the display name from
    /// [`Self::function_names`] at the call site or the IR function's
    /// canonical `name` at the current-function boundary. Callers
    /// should NOT pre-demangle the key; archives are keyed on the
    /// same form the naming pipeline produces (mangled for C++,
    /// unmangled for C).
    ///
    /// # Name decoration fallback
    ///
    /// MSVC and older cdecl/stdcall toolchains decorate C function
    /// names with leading underscores (`_printf`, `_fclose`,
    /// `__exit`) while libc/POSIX archives store the bare names. When
    /// an exact-match lookup fails, retry with one and two leading
    /// underscores stripped so FLIRT-matched CRT names resolve to
    /// their POSIX prototypes. This is safe because:
    ///
    /// - Win32 APIs (`CreateFileA`) never start with an underscore,
    ///   so the fallback can't displace them.
    /// - Archive keys for C++ (mangled `?foo@Bar@@...`) start with
    ///   `?` or `@`, never underscore, so the fallback is a no-op
    ///   for them.
    /// - The worst case on an underscore-having-but-otherwise-named
    ///   function is a collision with an unrelated POSIX function of
    ///   the trimmed name, which is rare enough that we accept it.
    pub fn lookup_prototype(&self, name: &str) -> Option<&FunctionType> {
        for archive in &self.type_archives {
            if let Some(f) = archive.functions.get(name) {
                return Some(f);
            }
        }
        // Fallback: strip MSVC-style leading underscore decoration and
        // retry across all archives. Try one underscore first, then two.
        let stripped1 = name.strip_prefix('_');
        if let Some(s) = stripped1 {
            if !s.is_empty() && !s.starts_with('_') {
                for archive in &self.type_archives {
                    if let Some(f) = archive.functions.get(s) {
                        return Some(f);
                    }
                }
            }
        }
        let stripped2 = name.strip_prefix("__");
        if let Some(s) = stripped2 {
            if !s.is_empty() && !s.starts_with('_') {
                for archive in &self.type_archives {
                    if let Some(f) = archive.functions.get(s) {
                        return Some(f);
                    }
                }
            }
        }
        None
    }
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

/// Look up the prototype for the function being decompiled. Tries the
/// display name first (so user renames are honored — if a user
/// renamed a function to a known archive name, that should resolve)
/// then falls back to the IR's canonical name. Returns `None` when
/// neither is found; that's the common case for user-defined
/// functions and is fine — the typing layer just leaves slots as
/// `Unknown(size)`.
fn current_function_prototype<'a>(
    ir: &IrFunction,
    ctx: &'a DecompileContext,
) -> Option<&'a FunctionType> {
    if let Some(display) = ctx.current_function_display_name.as_deref() {
        if let Some(proto) = ctx.lookup_prototype(display) {
            return Some(proto);
        }
    }
    ctx.lookup_prototype(&ir.name)
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
    // register names the expression builder emits. The current function's
    // prototype (if known to the bundled type archives) is passed in so
    // arg slots can be typed from the prototype's parameter list.
    let prototype = current_function_prototype(ir, ctx);
    let (body, frame_layout) = stackframe::analyze_and_rewrite(body, prototype);

    // Step 4: Assign variable names (with user overrides applied as a final pass)
    let body = varnames::rename_variables(body, &ctx.variable_names);

    // Step 5: Emit C-like code. Pass the prototype through so the
    // signature line shows real types (`int _fclose(FILE* arg0)`) for
    // FLIRT-matched CRT functions instead of the generic
    // `void _fclose(void)` fallback.
    let display_name = ctx.current_function_display_name.as_deref().unwrap_or(&ir.name);
    let text = emit::emit_function(display_name, &body, &ctx.label_names, prototype);
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
    let prototype = current_function_prototype(ir, ctx);
    let (body, frame_layout) = stackframe::analyze_and_rewrite(body, prototype);
    let body = varnames::rename_variables(body, &ctx.variable_names);
    let variable_names = varnames::collect_displayed_names(&body);
    let display_name = ctx.current_function_display_name.as_deref().unwrap_or(&ir.name);
    let lines = emit::emit_function_annotated(display_name, &body, &ctx.label_names, prototype);
    DecompileAnnotated { lines, variable_names, frame_layout }
}
