//! Integration test for the PR 4c typed-call-site-cast feature.
//!
//! Constructs a synthetic IR function exhibiting the canonical
//! `push HANDLE_const; call CloseHandle` pattern that x86-32
//! cdecl/stdcall code uses to call Win32 APIs, runs it through the
//! full `decompile()` pipeline (NOT just `build_statements`), and
//! asserts the rendered text contains the typed cast wrappers.
//!
//! Why this lives here and not in `crates/reghidra-core/tests/typed_decompile.rs`:
//! the fixture-based version of this test was unreliable because
//! real-world binaries from `tests/fixtures/` (cmd.exe,
//! Borland-built strip.exe, etc.) don't necessarily exhibit the
//! `push HANDLE_const; call SomeWin32API` pattern in any function.
//! Their calling conventions, archive coverage, and how their
//! imports are wrapped happen to skip the typed-cast path. The
//! synthetic-IR approach decouples integration coverage from "what
//! does this particular binary happen to compile to."
//!
//! What this guards against:
//!
//! - PR 4c regressions in `expr_builder::annotate_call_args` (the
//!   `Cast(declared_type, arg)` wrap).
//! - Context plumbing regressions: `type_archives` not flowing into
//!   `DecompileContext`, `lookup_prototype` not finding the function,
//!   the underscore-strip fallback breaking, etc.
//! - Render regressions in `emit::emit_function` that drop or
//!   mis-format `Cast` expressions.
//! - Pipeline ordering regressions: a future PR that runs a pass
//!   between `build_statements` and `emit` that strips Cast nodes.
//!
//! The expr_builder unit tests check the *AST* shape after
//! `build_statements` directly. This test checks the *rendered text*
//! after `decompile()` runs end-to-end, which is what the user sees.

use reghidra_decompile::type_archive::{
    ArgType, CallingConvention, FunctionType, Primitive, TypeArchive, TypeRef, ARCHIVE_VERSION,
};
use reghidra_decompile::{decompile, DecompileContext};
use reghidra_ir::op::{IrOp, Operand, VarNode};
use reghidra_ir::types::{IrBlock, IrFunction, IrInstruction};
use std::collections::HashMap;
use std::sync::Arc;

/// x86-32 esp varnode (offset=4, size=4 — matches the lifter's RSP constant).
fn esp4() -> VarNode {
    VarNode::reg(4, 4)
}

/// Build a single-block IR function from a list of ops.
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
        name: "caller".to_string(),
        entry_address: 0x1000,
        blocks: vec![block],
    }
}

fn empty_ctx() -> DecompileContext {
    DecompileContext {
        function_names: HashMap::new(),
        string_literals: HashMap::new(),
        successors: HashMap::new(),
        predecessors: HashMap::new(),
        label_names: HashMap::new(),
        variable_names: HashMap::new(),
        variable_types: HashMap::new(),
        current_function_display_name: None,
        type_archives: Vec::new(),
    }
}

/// Build a one-function archive whose entry has the given name and
/// arg types. Used to give `lookup_prototype` something to find.
fn mk_archive(name: &str, fn_name: &str, args: Vec<(&str, TypeRef)>) -> Arc<TypeArchive> {
    let mut functions = HashMap::new();
    functions.insert(
        fn_name.to_string(),
        FunctionType {
            name: fn_name.to_string(),
            args: args
                .into_iter()
                .map(|(arg_name, ty)| ArgType {
                    name: arg_name.to_string(),
                    ty,
                })
                .collect(),
            return_type: TypeRef::Primitive(Primitive::Bool),
            calling_convention: CallingConvention::Stdcall,
            is_variadic: false,
        },
    );
    Arc::new(TypeArchive {
        name: name.to_string(),
        version: ARCHIVE_VERSION,
        functions,
        types: HashMap::new(),
    })
}

/// The canonical PR 4c case: a sub_XXXX caller pushes a HANDLE
/// constant and calls `CloseHandle`. The bundled archive has a
/// prototype for `CloseHandle` taking a `HANDLE`. After full
/// `decompile()`, the rendered text should contain `(HANDLE)` as a
/// cast wrapping the call argument.
#[test]
fn typed_handle_cast_appears_in_rendered_text() {
    // push 0xdeadbeef; call CloseHandle
    let ir = mk_ir(vec![
        IrOp::Store {
            addr: esp4(),
            src: VarNode::constant(0xdeadbeef, 4),
        },
        IrOp::Call { target: 0x2000 },
        IrOp::Return { value: Operand::None },
    ]);

    let mut ctx = empty_ctx();
    ctx.function_names.insert(0x2000, "CloseHandle".to_string());
    ctx.type_archives = vec![mk_archive(
        "test-windows",
        "CloseHandle",
        vec![("hObject", TypeRef::Named("HANDLE".to_string()))],
    )];

    let out = decompile(&ir, &ctx);

    // The whole point: the cast must reach the user-visible rendered
    // text, not just the AST. If a future render pass strips Cast
    // nodes or formats them wrong, this assertion catches it.
    assert!(
        out.text.contains("CloseHandle("),
        "expected `CloseHandle(` in rendered output, got:\n{}",
        out.text
    );
    assert!(
        out.text.contains("(HANDLE)"),
        "expected `(HANDLE)` cast in rendered output, got:\n{}",
        out.text
    );

    // Tighter check: the cast should appear *inside* the call's
    // argument list, not as a stray bareword. We require the
    // sequence `CloseHandle((HANDLE)` somewhere in the output.
    assert!(
        out.text.contains("CloseHandle((HANDLE)"),
        "expected `CloseHandle((HANDLE)` (cast inside call args), got:\n{}",
        out.text
    );
}

/// Multi-arg variant: a 2-arg Win32-style call with one HANDLE and
/// one DWORD. Catches a different class of regression — the cast
/// pass dropping casts on later args while preserving the first.
#[test]
fn typed_multi_arg_call_renders_all_casts() {
    // push 0xc0000409; push 0xdeadbeef; call TerminateProcess
    let ir = mk_ir(vec![
        IrOp::Store {
            addr: esp4(),
            src: VarNode::constant(0xc0000409, 4),
        },
        IrOp::Store {
            addr: esp4(),
            src: VarNode::constant(0xdeadbeef, 4),
        },
        IrOp::Call { target: 0x2000 },
        IrOp::Return { value: Operand::None },
    ]);

    let mut ctx = empty_ctx();
    ctx.function_names
        .insert(0x2000, "TerminateProcess".to_string());
    ctx.type_archives = vec![mk_archive(
        "test-windows",
        "TerminateProcess",
        vec![
            ("hProcess", TypeRef::Named("HANDLE".to_string())),
            ("uExitCode", TypeRef::Named("DWORD".to_string())),
        ],
    )];

    let out = decompile(&ir, &ctx);

    assert!(
        out.text.contains("TerminateProcess("),
        "expected `TerminateProcess(` in rendered output, got:\n{}",
        out.text
    );
    assert!(
        out.text.contains("(HANDLE)"),
        "expected `(HANDLE)` cast on first arg, got:\n{}",
        out.text
    );
    assert!(
        out.text.contains("(DWORD)"),
        "expected `(DWORD)` cast on second arg, got:\n{}",
        out.text
    );
}

/// Negative control: when the callee has no archive entry, no casts
/// should be wrapped on the args. Confirms the typed-cast path is
/// gated on prototype lookup, not unconditional. If a regression
/// makes `annotate_call_args` cast everything (e.g. defaulting to
/// `void*` when no prototype is found), the rendered output would
/// pick up `(void*)` casts here and the test fails.
#[test]
fn untyped_call_does_not_get_casts() {
    let ir = mk_ir(vec![
        IrOp::Store {
            addr: esp4(),
            src: VarNode::constant(0xdeadbeef, 4),
        },
        IrOp::Call { target: 0x2000 },
        IrOp::Return { value: Operand::None },
    ]);

    let mut ctx = empty_ctx();
    ctx.function_names
        .insert(0x2000, "unknown_function".to_string());
    // No type archive for `unknown_function` — lookup_prototype
    // returns None and annotate_call_args should pass args through.

    let out = decompile(&ir, &ctx);

    assert!(
        out.text.contains("unknown_function("),
        "expected `unknown_function(` in rendered output, got:\n{}",
        out.text
    );
    // The `(HANDLE)` / `(DWORD)` / `(void*)` shouldn't appear because
    // there's no prototype to drive the cast.
    assert!(
        !out.text.contains("(HANDLE)"),
        "unexpected (HANDLE) cast on untyped call:\n{}",
        out.text
    );
    assert!(
        !out.text.contains("(DWORD)"),
        "unexpected (DWORD) cast on untyped call:\n{}",
        out.text
    );
}
