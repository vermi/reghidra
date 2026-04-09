//! Integration test for Phase 5c slot subsumption.
//!
//! Constructs a synthetic IR function with two adjacent stack arg
//! slots (`arg_8` and `arg_c` in the x86-32 cdecl frame), runs it
//! through the full `decompile()` pipeline twice — once with no user
//! retypes, once with `arg_8` retyped to `int64_t` — and asserts
//! that the second pass collapses `arg_c` into `arg_8` everywhere it
//! matters: only one VarDecl in the rendered text, the typed name
//! reaches the body, and the swallowed name disappears.
//!
//! What this guards against:
//!
//! - `FrameLayout::retype_slot` returning the wrong child set for a
//!   widening retype.
//! - `apply_user_variable_types` failing to thread the layout in
//!   from `decompile()` (the parameter was added in this PR).
//! - `prepend_var_decls` regressing to render both halves of a
//!   merged slot.
//! - `rewrite_var_refs` missing a body location (`Return`,
//!   `Assign`, `If` cond, etc.) when rewriting child → parent.

use reghidra_decompile::{decompile, DecompileContext};
use reghidra_ir::op::{IrOp, Operand, VarNode};
use reghidra_ir::types::{IrBlock, IrFunction, IrInstruction};
use std::collections::HashMap;

/// x86-32 esp varnode (offset=4, size=4).
fn esp4() -> VarNode {
    VarNode::reg(4, 4)
}

/// x86-32 ebp varnode (offset=5, size=4).
fn ebp4() -> VarNode {
    VarNode::reg(5, 4)
}

/// x86-32 eax varnode (offset=0, size=4).
fn eax4() -> VarNode {
    VarNode::reg(0, 4)
}

/// x86-32 edx varnode (offset=2, size=4).
fn edx4() -> VarNode {
    VarNode::reg(2, 4)
}

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
        name: "f".to_string(),
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

/// Build an IR function that establishes an x86-32 frame pointer
/// (`mov ebp, esp`) and reads from both `[ebp+8]` (arg_8) and
/// `[ebp+c]` (arg_c). The reads land into eax and edx so the
/// stackframe pass picks up both slots and the rewriter has body
/// locations to mutate when subsumption fires.
fn frame_with_two_arg_slots() -> IrFunction {
    use reghidra_ir::op::VarSpace;
    // We need the IR to look like:
    //   ebp = esp                      ; frame pointer setup
    //   t0  = ebp + 8
    //   eax = *(t0)                    ; read arg_8
    //   t1  = ebp + 0xc
    //   edx = *(t1)                    ; read arg_c
    //   return
    //
    // Use Temp varnodes for t0/t1 so the lifter-style "via temp"
    // pattern in stackframe.rs's RewriteCtx fires.
    let t0 = VarNode {
        space: VarSpace::Temp,
        offset: 0,
        size: 4,
    };
    let t1 = VarNode {
        space: VarSpace::Temp,
        offset: 1,
        size: 4,
    };
    mk_ir(vec![
        IrOp::Copy {
            dst: ebp4(),
            src: esp4(),
        },
        IrOp::IntAdd {
            dst: t0.clone(),
            a: ebp4(),
            b: VarNode::constant(8, 4),
        },
        IrOp::Load {
            dst: eax4(),
            addr: t0,
        },
        IrOp::IntAdd {
            dst: t1.clone(),
            a: ebp4(),
            b: VarNode::constant(0xc, 4),
        },
        IrOp::Load {
            dst: edx4(),
            addr: t1,
        },
        IrOp::Return { value: Operand::None },
    ])
}

/// Without any user retypes, both `arg_8` and `arg_c` should appear
/// in the rendered output. This is the baseline that the
/// subsumption test compares against — if the baseline regresses,
/// the subsumption assertion isn't actually testing the right thing.
#[test]
fn baseline_two_arg_slots_render_independently() {
    let ir = frame_with_two_arg_slots();
    let ctx = empty_ctx();
    let out = decompile(&ir, &ctx);
    assert!(
        out.text.contains("arg_8"),
        "baseline should render arg_8, got:\n{}",
        out.text
    );
    assert!(
        out.text.contains("arg_c"),
        "baseline should render arg_c, got:\n{}",
        out.text
    );
}

/// User retypes `arg_8` to `int64_t`. The 8-byte width consumes the
/// adjacent `arg_c` slot. After decompile():
///
/// - The rendered text contains a single `arg_8` declaration with
///   `int64_t`.
/// - There is no `arg_c` declaration line.
/// - The body's read of what was `arg_c` is rewritten to `arg_8`,
///   so `arg_c` does not appear anywhere in the output.
#[test]
fn retyping_arg_8_to_int64_consumes_arg_c() {
    let ir = frame_with_two_arg_slots();
    let mut ctx = empty_ctx();
    ctx.variable_types
        .insert("arg_8".to_string(), "int64_t".to_string());
    let out = decompile(&ir, &ctx);

    // The merged slot's typed VarDecl should appear.
    assert!(
        out.text.contains("int64_t arg_8")
            || out.text.contains("int64_t  arg_8")
            || out.text.contains("int64_t\targ_8"),
        "expected `int64_t arg_8` declaration, got:\n{}",
        out.text
    );
    // arg_c must not appear at all — neither as a declaration nor
    // as a body reference.
    assert!(
        !out.text.contains("arg_c"),
        "arg_c should be subsumed but still appears in:\n{}",
        out.text
    );
    // Sanity: the function should still render.
    assert!(out.text.contains("arg_8"), "rendered:\n{}", out.text);
}

/// Same-width retype (`arg_8` → `uint32_t`) should NOT consume any
/// neighbor. Both slots stay declared. This is the negative control
/// for the widening path: a regression that always subsumes (not
/// gated on width comparison) would fail this assertion.
#[test]
fn same_width_retype_does_not_consume_neighbor() {
    let ir = frame_with_two_arg_slots();
    let mut ctx = empty_ctx();
    ctx.variable_types
        .insert("arg_8".to_string(), "uint32_t".to_string());
    let out = decompile(&ir, &ctx);
    assert!(
        out.text.contains("arg_8"),
        "arg_8 should still render, got:\n{}",
        out.text
    );
    assert!(
        out.text.contains("arg_c"),
        "arg_c should NOT be subsumed by a same-width retype, got:\n{}",
        out.text
    );
}
