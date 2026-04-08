//! Heuristic stack frame analysis.
//!
//! Runs between `structure::structure` and `varnames::rename_variables`. Its
//! job is to turn raw stack-pointer arithmetic (`*(rbp - 0x8)`, `*(t0)` where
//! `t0 = rbp - 0x8`, etc.) into named locals and parameters (`local_8`,
//! `arg_8`) with offset-keyed names that remain stable across edits and
//! retypes. It also drops the x86 prologue/epilogue bookkeeping (`push rbp;
//! mov rbp, rsp`) once the frame has been recognized, so the resulting
//! pseudocode has no visible `rsp`/`rbp` assignments or the traditional
//! scaffolding.
//!
//! Scope of this first cut (tier-2 heuristic):
//! - Only x86/x86-64 functions that establish a frame pointer via the
//!   canonical `push rbp; mov rbp, rsp` pattern are recognized. Functions
//!   without a frame pointer (FPO/omit-frame-pointer builds) fall through
//!   unchanged — their rsp-relative accesses still show up as raw arithmetic.
//!   A follow-up can add rsp-delta tracking.
//! - ARM64 frames (`stp x29, x30, [sp, #-N]!; mov x29, sp`) are not yet
//!   recognized here — the shape of the setup is different, so support for
//!   it can be layered on without disturbing the x86 path.
//! - Slot types are always `Unknown(n)` where `n` is the observed access
//!   size. Typing information (PDB, bundled archives) will be merged into
//!   this layer in Phase 5c.
//!
//! Design choices worth remembering:
//! - Slots are named by *hex offset* (`local_8`, `arg_c`), IDA-style. This
//!   is a deliberate divergence from Ghidra's sequential numbering — it
//!   means retyping a slot doesn't renumber anything else, which is what
//!   the user wanted when we sketched the retype-collapses-other-slots
//!   behavior.
//! - All register-name comparisons accept both 64-bit and 32-bit aliases
//!   (`rbp`/`ebp`, `rsp`/`esp`). The expression builder emits the
//!   architecture-correct sized name, so we must handle both here.
//! - This pass runs *before* `rename_variables`, so temporaries still look
//!   like `tN` (not `var_N`) and the stack registers still look like
//!   `rbp`/`rsp` (not `frame_pointer` or whatever a rename might produce).

use crate::ast::{BinOp, CType, Expr, Stmt};
use crate::type_archive::{type_ref_to_ctype, FunctionType};
use std::collections::{BTreeMap, HashMap, HashSet};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A single discovered stack slot.
#[derive(Debug, Clone)]
pub struct StackSlot {
    /// Signed offset from the frame pointer. Negative values are locals
    /// (below `rbp`), positive values are inbound arguments (above the
    /// saved return address).
    pub offset: i64,
    /// Largest access size observed for this slot, in bytes.
    pub size: u8,
    /// How many times this slot was referenced in the function body.
    pub ref_count: usize,
    /// Display name (`local_8`, `arg_c`, etc.).
    pub name: String,
    /// Inferred C type. `None` until the typing layer lands — slots default
    /// to `CType::Unknown(size)` at declaration time.
    pub ctype: Option<CType>,
}

/// Complete stack frame layout for one function.
#[derive(Debug, Clone, Default)]
pub struct FrameLayout {
    /// Did we recognize a frame pointer setup? When `false`, the other
    /// fields are empty and the pass made no rewrites.
    pub has_frame_pointer: bool,
    /// All slots discovered, keyed by signed offset from the frame pointer.
    /// `BTreeMap` gives us a sorted iteration order for declaration emit.
    pub slots: BTreeMap<i64, StackSlot>,
}

/// Analyze the function body, rewrite recognized stack accesses, drop the
/// prologue bookkeeping, and prepend `VarDecl` statements for the discovered
/// slots. Returns the rewritten body and the layout that was built.
///
/// `prototype` is an optional prototype for the *current* function from
/// the bundled type archive. When provided, the discovered positive-offset
/// slots (the function's incoming arguments on x86-32 cdecl/stdcall) are
/// matched against the prototype's parameter list in declaration order,
/// and each slot's `ctype` is populated from the prototype. This makes
/// the prepended `VarDecl`s render with concrete types like
/// `HANDLE arg_8;` instead of `unk32 arg_8;`. Slot *names* are NOT
/// rewritten in this PR — using the prototype's parameter names
/// (`HANDLE hProcess`) requires a body-level rename pass that's
/// scoped for a follow-up. Slot offsets without a matching prototype
/// arg keep their `Unknown(size)` type as before.
pub fn analyze_and_rewrite(
    body: Vec<Stmt>,
    prototype: Option<&FunctionType>,
) -> (Vec<Stmt>, FrameLayout) {
    let mut layout = FrameLayout::default();

    // Step 1: look for the canonical `rbp = rsp` assignment anywhere in the
    // body. When present, we know the function is using a frame pointer and
    // all `rbp ± k` references can be treated as stable slot offsets.
    if !has_frame_pointer_setup(&body) {
        // Fallback: MSVC SEH4 prolog functions (`__SEH_prolog4`,
        // `__SEH_prolog4_GS`, `_EH_prolog`, etc.) jump straight into a
        // CRT helper to set up their frame and never emit the canonical
        // `mov ebp, esp` we look for above. The body is opaque to the
        // tier-2 walker, so no slots are recovered. But when the
        // function ALSO has a known prototype in the bundled archives
        // (typically a FLIRT-matched MSVC CRT internal — `__lockexit`,
        // `__ftbuf`, `__commit`, etc.), we can still synthesize
        // positive-offset arg slots directly from the prototype's arg
        // list at standard x86-32 cdecl/stdcall stack offsets and
        // prepend the typed `VarDecl`s. This gives the user a visible
        // signature for the function body even though the access sites
        // remain opaque. See `synthesize_arg_slots_from_prototype`
        // for the offset convention. SEH4 is x86-32-only (x86-64 SEH
        // is table-based and has no runtime prolog helper) so this
        // assumption is safe.
        if let Some(proto) = prototype {
            if is_seh_prolog_function(&body) {
                synthesize_arg_slots_from_prototype(&mut layout, proto);
                layout.has_frame_pointer = true;
                let body = prepend_var_decls(body, &layout);
                return (body, layout);
            }
        }
        return (body, layout);
    }
    layout.has_frame_pointer = true;

    // Step 2: build a temp → (reg, offset) map so that when we see
    // `*(t0)` we can resolve it to a known slot address. The IR optimizer
    // already folds pure constant chains, but `rbp + k` stays as a live
    // IntAdd that becomes a temp assignment at the statement level.
    let temp_offsets = collect_temp_offsets(&body);

    // Step 3: walk the body, rewrite matched derefs to named slots, and
    // populate `layout.slots` as we go.
    let mut ctx = RewriteCtx {
        temp_offsets: &temp_offsets,
        layout: &mut layout,
        used_temps: HashSet::new(),
    };
    let body: Vec<Stmt> = body.into_iter().map(|s| ctx.rewrite_stmt(s)).collect();
    let surviving_temp_uses = ctx.used_temps;

    // Step 4: drop (a) the prologue bookkeeping, and (b) any temp definitions
    // that were only used as stack-access addresses. We know a temp was only
    // used as an address if it's in `temp_offsets` (meaning we classified it)
    // but NOT in `surviving_temp_uses` (meaning after rewriting, nothing
    // references it anymore).
    let body = strip_prologue_and_dead_temps(body, &temp_offsets, &surviving_temp_uses);

    // Step 5: apply prototype types to incoming-argument slots, if a
    // prototype is available. Done before VarDecl emission so the
    // emitted decls pick up the typed `ctype` automatically.
    if let Some(proto) = prototype {
        apply_prototype_arg_types(&mut layout, proto);
    }

    // Step 6: emit `VarDecl` statements at the top of the body for every
    // slot we discovered. These give users a visible "variables list" like
    // Ghidra's, and become the handle for retyping in Phase 5c.
    let body = prepend_var_decls(body, &layout);

    (body, layout)
}

/// Walk the discovered positive-offset (incoming-argument) slots in
/// ascending offset order and pair them with the prototype's parameter
/// list, assigning each slot's `ctype` from the corresponding
/// prototype arg.
///
/// On x86-32 cdecl/stdcall, the caller pushes arguments right-to-left
/// before the call, so the callee sees them at consecutive `ebp+8`,
/// `ebp+c`, `ebp+10`, ... offsets in declaration order. The walker
/// pairs them positionally — slot at smallest positive offset → arg
/// 0, next → arg 1, and so on. This is correct for the common case
/// where every argument fits in a single 4-byte stack slot. For
/// large argument types (`int64_t`, structs > 4 bytes), the
/// alignment between slots and prototype args drifts after the first
/// such argument; the walker stops typing slots beyond the drift
/// rather than misattributing types past it.
///
/// On x86-64 (both Win64 and SysV), most arguments arrive in
/// registers and don't appear as positive-offset stack slots at all.
/// The mapping is correct for the few stack-resident args (7th
/// onwards on SysV, after the shadow space on Win64), but most
/// prototype args have no slot to type. Functions whose first six
/// args fit in registers therefore see no benefit from this pass on
/// x64 — the wins are concentrated in 32-bit Win32 binaries, which
/// are the most common reverse-engineering target anyway.
fn apply_prototype_arg_types(layout: &mut FrameLayout, proto: &FunctionType) {
    // Collect arg-slot offsets in ascending order. `BTreeMap`'s
    // natural iteration is sorted, so we just need to skip the
    // negatives (locals).
    let arg_offsets: Vec<i64> = layout
        .slots
        .keys()
        .copied()
        .filter(|k| *k > 0)
        .collect();

    // Pair slots with prototype args positionally. Stop on the
    // shorter of the two — extra slots stay as `Unknown(size)` and
    // extra prototype args have no slot to attach to.
    for (slot_offset, proto_arg) in arg_offsets.iter().zip(proto.args.iter()) {
        if let Some(slot) = layout.slots.get_mut(slot_offset) {
            slot.ctype = Some(type_ref_to_ctype(&proto_arg.ty));
        }
    }
}

/// Walk the body looking for a Call to a function whose name marks
/// it as an MSVC SEH-style prolog helper. Microsoft's CRT compiles
/// `__try`/`__except` blocks into a frame setup that hands off to one
/// of these helpers instead of inlining a frame pointer assignment,
/// so the tier-2 `rbp = rsp` detection misses them. Recognized names:
///
/// - `__SEH_prolog4` / `__SEH_prolog4_GS` — modern MSVC SEH4 prolog
/// - `_SEH_prolog4` / `_SEH_prolog4_GS` — older underscore decoration
/// - `_EH_prolog` / `__EH_prolog` — pre-SEH4 32-bit C++ EH prolog
///
/// Match is by leading-prefix substring so future Microsoft variants
/// (`__SEH_prolog4_kernel`, etc.) get caught without code changes.
fn is_seh_prolog_function(body: &[Stmt]) -> bool {
    let mut found = false;
    walk_stmts(body, &mut |stmt| {
        let call_target = match stmt {
            Stmt::ExprStmt(Expr::Call(callee, _)) => Some(callee.as_ref()),
            Stmt::Assign(_, Expr::Call(callee, _)) => Some(callee.as_ref()),
            _ => None,
        };
        if let Some(Expr::Var(name)) = call_target {
            if is_seh_prolog_name(name) {
                found = true;
            }
        }
    });
    found
}

fn is_seh_prolog_name(name: &str) -> bool {
    // Strip up to two leading underscores so all decorations match.
    let trimmed = name.trim_start_matches('_');
    trimmed.starts_with("SEH_prolog") || trimmed.starts_with("EH_prolog")
}

/// Synthesize positive-offset arg slots directly from the prototype's
/// parameter list at standard x86-32 cdecl/stdcall stack offsets:
///
/// ```text
///   arg 0 → ebp + 0x08   ("arg_8")
///   arg 1 → ebp + 0x0c   ("arg_c")
///   arg 2 → ebp + 0x10   ("arg_10")
///   ...
/// ```
///
/// Each slot's `ctype` is populated from the corresponding prototype
/// arg, and `size` is the byte width of the C type. Slots wider than
/// 4 bytes (`int64_t`, structs) consume the next slot's offset, so
/// the next arg's offset is bumped to maintain the cdecl alignment.
/// This matches the convention `apply_prototype_arg_types` already
/// uses for the frame-pointer-recognized path, just laid down ahead
/// of time instead of recovered from access sites.
///
/// Used only for the SEH-prolog fallback in `analyze_and_rewrite`.
/// The frame-pointer-recognized path keeps using
/// `apply_prototype_arg_types` so its slot widths come from the
/// observed access sizes (which can be more precise than the
/// prototype declarations when the access is narrower).
fn synthesize_arg_slots_from_prototype(layout: &mut FrameLayout, proto: &FunctionType) {
    // x86-32 cdecl/stdcall: first arg is at [ebp+8] (saved-ebp at +0,
    // return address at +4). Each subsequent arg is at +sizeof(prev)
    // rounded up to 4 bytes.
    let mut offset: i64 = 8;
    for arg in &proto.args {
        let ctype = type_ref_to_ctype(&arg.ty);
        let size = ctype.size().max(1);
        let name = format!("arg_{:x}", offset);
        layout.slots.insert(
            offset,
            StackSlot {
                offset,
                size,
                ref_count: 0,
                name,
                ctype: Some(ctype),
            },
        );
        // Round up to 4-byte alignment for the next arg's offset.
        let stride = ((size as i64) + 3) & !3;
        offset += stride.max(4);
    }
}

// ---------------------------------------------------------------------------
// Frame pointer detection
// ---------------------------------------------------------------------------

fn has_frame_pointer_setup(body: &[Stmt]) -> bool {
    // A single `fp = sp` (x86 `mov ebp, esp` or ARM64 `mov x29, sp`) or
    // `fp = sp ± const` (ARM64 `add x29, sp, #16` after `stp x29, x30,
    // [sp, #-16]!`) assignment anywhere in the function is sufficient
    // evidence that the function has a frame pointer. In practice these
    // only appear in the prologue because nothing else touches fp in
    // standard frame-pointer code, but we don't restrict position here
    // — the important thing is that fp tracks sp at entry, which means
    // `fp ± k` offsets are stable for the whole function.
    //
    // ARM64 note: the prologue is typically two instructions —
    // `stp x29, x30, [sp, #-16]!` (saves old fp and lr, writes back to
    // sp) followed by `mov x29, sp` (or `add x29, sp, #0` which also
    // becomes `fp = sp`). A frame-pointer-omission build skips the
    // `mov`/`add` entirely and this detector correctly returns false.
    let mut found = false;
    walk_stmts(body, &mut |stmt| {
        if let Stmt::Assign(Expr::Var(lhs), rhs) = stmt {
            if !is_rbp(lhs) {
                return;
            }
            match rhs {
                // `fp = sp` (x86 `mov ebp, esp`, ARM64 `mov x29, sp`).
                Expr::Var(rhs_name) if is_rsp(rhs_name) => found = true,
                // `fp = sp ± k` (ARM64 `add x29, sp, #16`). The magnitude
                // doesn't matter here — only that the RHS has the shape of
                // a stack-pointer-derived constant, which guarantees fp
                // tracks sp at this program point.
                Expr::Binary(BinOp::Add | BinOp::Sub, a, b) => {
                    let a_is_sp = matches!(a.as_ref(), Expr::Var(n) if is_rsp(n));
                    let b_is_const = matches!(b.as_ref(), Expr::IntLit(_, _));
                    if a_is_sp && b_is_const {
                        found = true;
                    }
                }
                _ => {}
            }
        }
    });
    found
}

// ---------------------------------------------------------------------------
// Temp offset collection
// ---------------------------------------------------------------------------

/// Reference to one of the stack registers. Only rbp matters for the current
/// implementation (we don't track rsp-delta yet), but the enum gives us a
/// place to grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackReg {
    Rbp,
    // Rsp (future: tracked via a running delta)
}

fn collect_temp_offsets(body: &[Stmt]) -> HashMap<String, (StackReg, i64)> {
    let mut map = HashMap::new();
    walk_stmts(body, &mut |stmt| {
        if let Stmt::Assign(Expr::Var(name), rhs) = stmt {
            if !is_temp_name(name) {
                return;
            }
            if let Some((reg, off)) = classify_stack_expr(rhs) {
                map.insert(name.clone(), (reg, off));
            }
        }
    });
    map
}

/// Recognize `rbp`, `rbp + k`, or `rbp - k` as a stack-relative address and
/// return the classified (reg, offset). Returns `None` for anything else.
fn classify_stack_expr(expr: &Expr) -> Option<(StackReg, i64)> {
    match expr {
        Expr::Var(name) if is_rbp(name) => Some((StackReg::Rbp, 0)),
        Expr::Binary(BinOp::Add, a, b) => classify_stack_binop(a, b, 1),
        Expr::Binary(BinOp::Sub, a, b) => classify_stack_binop(a, b, -1),
        _ => None,
    }
}

fn classify_stack_binop(a: &Expr, b: &Expr, sign: i64) -> Option<(StackReg, i64)> {
    // We only accept `<reg> ± <const>`, not `<const> ± <reg>`, because the
    // latter is unusual for stack offsets and catching it would require
    // distinguishing subtraction order. The lifter's memory-operand parser
    // always emits the register on the left for `[reg+imm]` / `[reg-imm]`.
    let Expr::Var(name) = a else {
        return None;
    };
    if !is_rbp(name) {
        return None;
    }
    let Expr::IntLit(k, _) = b else {
        return None;
    };
    // `IntLit` stores unsigned; convert to signed with wrap so that the
    // lifter's (`rbp + 0xFFFFFFF8`) sign-extension case also maps cleanly to
    // a negative offset. In practice the lifter already subtracts, so most
    // negatives come in via the Sub path, but this keeps the Add path honest.
    let signed = *k as i64;
    Some((StackReg::Rbp, sign * signed))
}

fn is_temp_name(s: &str) -> bool {
    s.len() >= 2 && s.starts_with('t') && s[1..].chars().all(|c| c.is_ascii_digit())
}

/// Recognize any sized alias of the architectural frame pointer.
/// x86: `rbp` / `ebp`. ARM64: `fp` (canonical alias for `x29`).
fn is_rbp(s: &str) -> bool {
    matches!(s, "rbp" | "ebp" | "fp")
}

/// Recognize any sized alias of the architectural stack pointer.
/// x86: `rsp` / `esp`. ARM64: `sp` (canonical alias for `x31`).
fn is_rsp(s: &str) -> bool {
    matches!(s, "rsp" | "esp" | "sp")
}

// ---------------------------------------------------------------------------
// Rewrite pass
// ---------------------------------------------------------------------------

struct RewriteCtx<'a> {
    temp_offsets: &'a HashMap<String, (StackReg, i64)>,
    layout: &'a mut FrameLayout,
    /// Names of temps that are still referenced after rewriting. If a temp
    /// definition exists in `temp_offsets` but its name never ends up in
    /// this set, the definition is dead and we drop it.
    used_temps: HashSet<String>,
}

impl RewriteCtx<'_> {
    fn rewrite_stmt(&mut self, stmt: Stmt) -> Stmt {
        match stmt {
            Stmt::Assign(lhs, rhs) => {
                // LHS is a def site, not a use — rewrite its shape (so e.g.
                // `*(rbp - 8)` on the left of an assignment becomes
                // `local_8`), but don't let a bare `Var` on the left count
                // as a live reference in `used_temps`. Otherwise a
                // `tN = rbp + k` definition would look like it uses `tN`
                // and the dead-temp cleanup would never fire.
                let new_lhs = self.rewrite_lhs(lhs);
                let new_rhs = self.rewrite_expr(rhs);
                Stmt::Assign(new_lhs, new_rhs)
            }
            Stmt::ExprStmt(e) => Stmt::ExprStmt(self.rewrite_expr(e)),
            Stmt::Return(Some(e)) => Stmt::Return(Some(self.rewrite_expr(e))),
            Stmt::If { cond, then_body, else_body } => Stmt::If {
                cond: self.rewrite_expr(cond),
                then_body: then_body.into_iter().map(|s| self.rewrite_stmt(s)).collect(),
                else_body: else_body.into_iter().map(|s| self.rewrite_stmt(s)).collect(),
            },
            Stmt::While { cond, body } => Stmt::While {
                cond: self.rewrite_expr(cond),
                body: body.into_iter().map(|s| self.rewrite_stmt(s)).collect(),
            },
            Stmt::Loop { body } => Stmt::Loop {
                body: body.into_iter().map(|s| self.rewrite_stmt(s)).collect(),
            },
            other => other,
        }
    }

    /// Rewrite an assignment's left-hand side. Bare-Var LHS is passed
    /// through untouched (no use-tracking); `Deref` LHS (store addresses)
    /// still go through the full rewrite so `*(rbp ± k) = ...` stores
    /// get their address rewritten to a named slot. Anything else falls
    /// through to the regular expression rewriter.
    fn rewrite_lhs(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Var(_) => expr,
            Expr::Deref(_, _) => self.rewrite_expr(expr),
            other => self.rewrite_expr(other),
        }
    }

    fn rewrite_expr(&mut self, expr: Expr) -> Expr {
        // Bottom-up: handle deref patterns first (so nested stack derefs get
        // caught), then fall through to structural recursion on every other
        // variant. We intentionally don't recurse into a `Deref` before
        // checking the shape — the match below handles both the inline and
        // the via-temp form.
        if let Expr::Deref(inner, ctype) = &expr {
            let size = ctype.size().max(1);
            if let Some((reg, offset)) = self.resolve_stack_addr(inner) {
                return self.slot_expr(reg, offset, size);
            }
        }
        match expr {
            Expr::Var(name) => {
                // Track surviving temp references so we can distinguish
                // dead temp definitions from live ones in step 4.
                if is_temp_name(&name) {
                    self.used_temps.insert(name.clone());
                }
                Expr::Var(name)
            }
            Expr::Binary(op, a, b) => Expr::Binary(
                op,
                Box::new(self.rewrite_expr(*a)),
                Box::new(self.rewrite_expr(*b)),
            ),
            Expr::Unary(op, e) => Expr::Unary(op, Box::new(self.rewrite_expr(*e))),
            Expr::Call(func, args) => Expr::Call(
                Box::new(self.rewrite_expr(*func)),
                args.into_iter().map(|a| self.rewrite_expr(a)).collect(),
            ),
            Expr::Deref(e, t) => Expr::Deref(Box::new(self.rewrite_expr(*e)), t),
            Expr::AddrOf(e) => Expr::AddrOf(Box::new(self.rewrite_expr(*e))),
            Expr::Cast(t, e) => Expr::Cast(t, Box::new(self.rewrite_expr(*e))),
            Expr::Index(b, i) => Expr::Index(
                Box::new(self.rewrite_expr(*b)),
                Box::new(self.rewrite_expr(*i)),
            ),
            Expr::Member(e, f) => Expr::Member(Box::new(self.rewrite_expr(*e)), f),
            Expr::Ternary(c, a, b) => Expr::Ternary(
                Box::new(self.rewrite_expr(*c)),
                Box::new(self.rewrite_expr(*a)),
                Box::new(self.rewrite_expr(*b)),
            ),
            other => other,
        }
    }

    /// Try to classify an expression as a stack-relative address. Returns
    /// `None` if the expression is anything we don't recognize.
    fn resolve_stack_addr(&self, expr: &Expr) -> Option<(StackReg, i64)> {
        // Inline form: `rbp`, `rbp + k`, `rbp - k`.
        if let Some((reg, off)) = classify_stack_expr(expr) {
            return Some((reg, off));
        }
        // Via-temp form: the expression is a Var referencing a previously
        // classified temp.
        if let Expr::Var(name) = expr {
            if let Some(&(reg, off)) = self.temp_offsets.get(name) {
                return Some((reg, off));
            }
        }
        None
    }

    fn slot_expr(&mut self, reg: StackReg, offset: i64, size: u8) -> Expr {
        // Offset 0 on an rbp-based frame is the saved caller rbp push —
        // it's part of the linkage, not a user variable, and should never
        // appear in the body as `arg_0`. Leave accesses at offset 0 as
        // their original deref so they stay visually distinct from real
        // slots. In practice this expression is rare (a function almost
        // never reads its own saved rbp) and dropping the rewrite here
        // keeps us from inventing a bogus slot.
        if offset == 0 {
            return match reg {
                StackReg::Rbp => Expr::Deref(
                    Box::new(Expr::Var("rbp".to_string())),
                    CType::from_size(size, false),
                ),
            };
        }
        let name = slot_name(reg, offset);
        let slot = self
            .layout
            .slots
            .entry(offset)
            .or_insert_with(|| StackSlot {
                offset,
                size,
                ref_count: 0,
                name: name.clone(),
                ctype: None,
            });
        slot.ref_count += 1;
        if size > slot.size {
            slot.size = size;
        }
        Expr::Var(name)
    }
}

fn slot_name(reg: StackReg, offset: i64) -> String {
    match reg {
        StackReg::Rbp => {
            if offset >= 0 {
                // Positive rbp-offsets are inbound arguments on the cdecl /
                // SysV stack: [rbp+0] holds the saved rbp, [rbp+wordsize]
                // holds the return address, and [rbp+2*wordsize] onwards
                // are the stack-passed arguments.
                format!("arg_{:x}", offset)
            } else {
                // Negatives are locals. Use the absolute value so that
                // `rbp - 0x10` renders as `local_10` (no leading minus).
                format!("local_{:x}", (-offset) as u64)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Prologue + dead-temp cleanup
// ---------------------------------------------------------------------------

fn strip_prologue_and_dead_temps(
    body: Vec<Stmt>,
    temp_offsets: &HashMap<String, (StackReg, i64)>,
    surviving_temp_uses: &HashSet<String>,
) -> Vec<Stmt> {
    body.into_iter()
        .filter(|stmt| !is_droppable(stmt, temp_offsets, surviving_temp_uses))
        .map(|stmt| filter_nested(stmt, temp_offsets, surviving_temp_uses))
        .collect()
}

fn filter_nested(
    stmt: Stmt,
    temp_offsets: &HashMap<String, (StackReg, i64)>,
    surviving: &HashSet<String>,
) -> Stmt {
    // Recurse into structured bodies. Same filter logic applies inside
    // if/while/loop — prologue ops typically aren't in there but dead temp
    // defs might be if the optimizer reshaped anything unusual.
    match stmt {
        Stmt::If { cond, then_body, else_body } => Stmt::If {
            cond,
            then_body: strip_prologue_and_dead_temps(then_body, temp_offsets, surviving),
            else_body: strip_prologue_and_dead_temps(else_body, temp_offsets, surviving),
        },
        Stmt::While { cond, body } => Stmt::While {
            cond,
            body: strip_prologue_and_dead_temps(body, temp_offsets, surviving),
        },
        Stmt::Loop { body } => Stmt::Loop {
            body: strip_prologue_and_dead_temps(body, temp_offsets, surviving),
        },
        other => other,
    }
}

fn is_droppable(
    stmt: &Stmt,
    temp_offsets: &HashMap<String, (StackReg, i64)>,
    surviving: &HashSet<String>,
) -> bool {
    match stmt {
        // Drop `rbp = rsp` — the frame-pointer setup marker.
        // (x86 `mov ebp, esp`, ARM64 `mov x29, sp`.)
        Stmt::Assign(Expr::Var(l), Expr::Var(r)) if is_rbp(l) && is_rsp(r) => true,
        // Drop `fp = sp ± k` — ARM64 prologue's frame-pointer setup
        // that follows a pre-indexed `stp x29, x30, [sp, #-N]!`
        // (emitted as `add x29, sp, #0` or `add x29, sp, #16`). Same
        // role as `mov ebp, esp` on x86; once stripped, downstream
        // fp-relative accesses are already rewritten to named slots.
        Stmt::Assign(Expr::Var(l), Expr::Binary(BinOp::Add | BinOp::Sub, a, b))
            if is_rbp(l)
                && matches!(a.as_ref(), Expr::Var(n) if is_rsp(n))
                && matches!(b.as_ref(), Expr::IntLit(_, _)) =>
        {
            true
        }
        // Drop `rsp = rsp ± k` — stack adjustment bookkeeping (sub rsp, N in
        // the prologue; add rsp, N in the epilogue). These stopped carrying
        // useful information the moment we started referring to slots by
        // their rbp-relative offset.
        Stmt::Assign(Expr::Var(l), Expr::Binary(BinOp::Add | BinOp::Sub, a, b))
            if is_rsp(l) && matches!(a.as_ref(), Expr::Var(n) if is_rsp(n))
                && matches!(b.as_ref(), Expr::IntLit(_, _)) =>
        {
            true
        }
        // Drop `*(rsp) = rbp` — the saved-rbp push. (`rsp` assignment is
        // dropped above, and the saved rbp store is now noise.)
        Stmt::Assign(Expr::Deref(inner, _), Expr::Var(r))
            if is_rsp(r_or_empty(inner)) && is_rbp(r) =>
        {
            // The pattern `*(rsp) = rbp` lands here only if `inner` is
            // exactly `Var("rsp")` — i.e. rsp directly, not a computed addr.
            true
        }
        // Drop `rbp = *(rsp)` — the saved-rbp restore in the epilogue.
        Stmt::Assign(Expr::Var(l), Expr::Deref(inner, _))
            if is_rbp(l) && is_rsp(r_or_empty(inner)) =>
        {
            true
        }
        // Drop dead temp definitions (`tN = rbp ± k`) when tN wasn't
        // referenced after the rewrite pass. If a temp was classified as a
        // stack address and all its uses were rewritten away, the defining
        // statement is now dead code.
        Stmt::Assign(Expr::Var(name), _)
            if temp_offsets.contains_key(name) && !surviving.contains(name) =>
        {
            true
        }
        _ => false,
    }
}

/// Borrow-helper: returns the Var name inside a `Box<Expr>` if it's a bare
/// Var, or an empty string otherwise. Used by the `r_or_empty` matchers
/// above so we can pattern-match without unboxing explicitly.
fn r_or_empty(e: &Expr) -> &str {
    match e {
        Expr::Var(n) => n.as_str(),
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// VarDecl emission
// ---------------------------------------------------------------------------

fn prepend_var_decls(body: Vec<Stmt>, layout: &FrameLayout) -> Vec<Stmt> {
    if layout.slots.is_empty() {
        return body;
    }
    // Split slots into args (positive offsets excluding the saved-rbp/return-
    // address pair at 0 and +wordsize) and locals (negative offsets). Both
    // groups are iterated in signed-offset order, which `BTreeMap` gives us
    // for free.
    let mut decls: Vec<Stmt> = Vec::new();
    for slot in layout.slots.values() {
        decls.push(Stmt::VarDecl {
            name: slot.name.clone(),
            ctype: slot
                .ctype
                .clone()
                .unwrap_or_else(|| CType::Unknown(slot.size.max(1))),
            init: None,
        });
    }
    decls.extend(body);
    decls
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursive walker used by the detect/collect passes. `f` is called on every
/// statement encountered in document order (including nested ones inside
/// if/while/loop bodies).
fn walk_stmts(body: &[Stmt], f: &mut dyn FnMut(&Stmt)) {
    for stmt in body {
        f(stmt);
        match stmt {
            Stmt::If { then_body, else_body, .. } => {
                walk_stmts(then_body, f);
                walk_stmts(else_body, f);
            }
            Stmt::While { body, .. } | Stmt::Loop { body } => walk_stmts(body, f),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn int(n: u64) -> Expr {
        Expr::IntLit(n, CType::UInt32)
    }

    fn var(s: &str) -> Expr {
        Expr::Var(s.to_string())
    }

    fn deref(e: Expr) -> Expr {
        Expr::Deref(Box::new(e), CType::UInt32)
    }

    fn assign(l: Expr, r: Expr) -> Stmt {
        Stmt::Assign(l, r)
    }

    fn has_var(stmts: &[Stmt], needle: &str) -> bool {
        let mut found = false;
        walk_stmts(stmts, &mut |s| {
            let mut scan = |e: &Expr| {
                if let Expr::Var(n) = e {
                    if n == needle {
                        found = true;
                    }
                }
            };
            match s {
                Stmt::Assign(l, r) => { scan(l); scan(r); }
                Stmt::ExprStmt(e) | Stmt::Return(Some(e)) => scan(e),
                _ => {}
            }
        });
        found
    }

    #[test]
    fn no_frame_pointer_no_rewrites() {
        // No `rbp = rsp` assignment anywhere — pass should return the body
        // unchanged and an empty layout.
        let body = vec![assign(var("eax"), int(1))];
        let (out, layout) = analyze_and_rewrite(body.clone(), None);
        assert!(!layout.has_frame_pointer);
        assert!(layout.slots.is_empty());
        assert_eq!(out.len(), body.len());
    }

    #[test]
    fn inline_rbp_minus_const_becomes_local() {
        // `*(rbp - 8) = eax`  ->  `local_8 = eax`
        // Prologue scaffolding (rsp adjust + save + `rbp = rsp`) is dropped.
        let body = vec![
            assign(var("rsp"), Expr::Binary(BinOp::Sub, Box::new(var("rsp")), Box::new(int(8)))),
            assign(deref(var("rsp")), var("rbp")),
            assign(var("rbp"), var("rsp")),
            assign(
                deref(Expr::Binary(BinOp::Sub, Box::new(var("rbp")), Box::new(int(8)))),
                var("eax"),
            ),
        ];
        let (out, layout) = analyze_and_rewrite(body, None);
        assert!(layout.has_frame_pointer);
        assert_eq!(layout.slots.len(), 1);
        let slot = layout.slots.values().next().unwrap();
        assert_eq!(slot.offset, -8);
        assert_eq!(slot.name, "local_8");
        // Prologue lines are gone, only a VarDecl + the rewritten assign remain.
        assert!(matches!(out[0], Stmt::VarDecl { .. }));
        assert!(has_var(&out, "local_8"));
        assert!(!has_var(&out, "rbp"));
        assert!(!has_var(&out, "rsp"));
    }

    #[test]
    fn via_temp_rbp_plus_const_becomes_arg() {
        // t0 = rbp + 8; *(t0) = eax  ->  arg_8 = eax
        // The temp definition is dead after rewrite and gets dropped.
        let body = vec![
            assign(var("rbp"), var("rsp")),
            assign(
                var("t0"),
                Expr::Binary(BinOp::Add, Box::new(var("rbp")), Box::new(int(8))),
            ),
            assign(deref(var("t0")), var("eax")),
        ];
        let (out, layout) = analyze_and_rewrite(body, None);
        assert!(layout.has_frame_pointer);
        let slot = layout.slots.get(&8).expect("slot at +8 should exist");
        assert_eq!(slot.name, "arg_8");
        // The t0 definition must be gone.
        assert!(!has_var(&out, "t0"));
        assert!(has_var(&out, "arg_8"));
    }

    #[test]
    fn multiple_slots_each_get_a_decl() {
        // local_4 and arg_8 both referenced -> both get decls.
        let body = vec![
            assign(var("rbp"), var("rsp")),
            assign(
                deref(Expr::Binary(BinOp::Sub, Box::new(var("rbp")), Box::new(int(4)))),
                int(0),
            ),
            assign(
                var("edx"),
                deref(Expr::Binary(BinOp::Add, Box::new(var("rbp")), Box::new(int(8)))),
            ),
        ];
        let (out, layout) = analyze_and_rewrite(body, None);
        assert_eq!(layout.slots.len(), 2);
        let decl_count = out.iter().filter(|s| matches!(s, Stmt::VarDecl { .. })).count();
        assert_eq!(decl_count, 2);
    }

    #[test]
    fn repeated_access_increments_ref_count() {
        let body = vec![
            assign(var("rbp"), var("rsp")),
            assign(
                deref(Expr::Binary(BinOp::Sub, Box::new(var("rbp")), Box::new(int(0x10)))),
                int(0),
            ),
            assign(
                var("eax"),
                deref(Expr::Binary(BinOp::Sub, Box::new(var("rbp")), Box::new(int(0x10)))),
            ),
        ];
        let (_, layout) = analyze_and_rewrite(body, None);
        let slot = layout.slots.get(&-0x10).unwrap();
        assert_eq!(slot.ref_count, 2);
    }

    #[test]
    fn live_temp_is_not_dropped() {
        // A temp that's used somewhere other than a stack deref (e.g., it
        // flows into an arithmetic result) must NOT be dropped, even if we
        // classified its definition as a stack address. This guards against
        // eating a `t = rbp + k` line that's being used as an address-taken
        // computation (`&local_N`), not as a load/store address.
        let body = vec![
            assign(var("rbp"), var("rsp")),
            assign(
                var("t0"),
                Expr::Binary(BinOp::Sub, Box::new(var("rbp")), Box::new(int(8))),
            ),
            // Here t0 is used as a value, not as a deref address.
            assign(var("eax"), var("t0")),
        ];
        let (out, _layout) = analyze_and_rewrite(body, None);
        assert!(has_var(&out, "t0"), "t0 defn was dropped but it has a live non-address use");
    }

    /// When a prototype is supplied for the current function, the
    /// stackframe pass should pair its arg slots with the prototype's
    /// parameter list (smallest positive offset → arg 0, etc.) and
    /// populate each slot's `ctype` from the corresponding prototype
    /// arg's type. The slot *names* stay as `arg_8`/`arg_c`/etc. for
    /// PR 4 — name renaming is a follow-up — but the prepended
    /// `VarDecl`s now carry concrete types.
    #[test]
    fn prototype_arg_types_propagate_to_slots() {
        use crate::type_archive::{
            ArgType as ArchiveArg, CallingConvention, FunctionType as ArchiveFn, Primitive,
            TypeRef,
        };

        // Two args: arg[0] is HANDLE (Named), arg[1] is uint32_t.
        let proto = ArchiveFn {
            name: "TerminateProcess".to_string(),
            args: vec![
                ArchiveArg {
                    name: "hProcess".to_string(),
                    ty: TypeRef::Named("HANDLE".to_string()),
                },
                ArchiveArg {
                    name: "uExitCode".to_string(),
                    ty: TypeRef::Primitive(Primitive::UInt32),
                },
            ],
            return_type: TypeRef::Primitive(Primitive::Bool),
            calling_convention: CallingConvention::Stdcall,
            is_variadic: false,
        };

        // Body that touches arg_8 and arg_c.
        let body = vec![
            assign(var("rbp"), var("rsp")),
            assign(
                var("eax"),
                deref(Expr::Binary(BinOp::Add, Box::new(var("rbp")), Box::new(int(8)))),
            ),
            assign(
                var("edx"),
                deref(Expr::Binary(BinOp::Add, Box::new(var("rbp")), Box::new(int(0xc)))),
            ),
        ];
        let (out, layout) = analyze_and_rewrite(body, Some(&proto));

        // Two arg slots discovered.
        let arg_slots: Vec<&StackSlot> =
            layout.slots.values().filter(|s| s.offset > 0).collect();
        assert_eq!(arg_slots.len(), 2);

        // First slot (offset 8) should be Named("HANDLE").
        let slot8 = layout.slots.get(&8).expect("arg slot at +8");
        match &slot8.ctype {
            Some(CType::Named(n)) => assert_eq!(n, "HANDLE"),
            other => panic!("arg_8 ctype should be Named(HANDLE), got {other:?}"),
        }

        // Second slot (offset 12) should be UInt32.
        let slot_c = layout.slots.get(&0xc).expect("arg slot at +c");
        assert!(matches!(slot_c.ctype, Some(CType::UInt32)));

        // The prepended VarDecls should carry these types.
        let decl_for = |name: &str| -> Option<&Stmt> {
            out.iter().find(|s| {
                matches!(s, Stmt::VarDecl { name: n, .. } if n == name)
            })
        };
        assert!(decl_for("arg_8").is_some(), "arg_8 VarDecl missing");
        assert!(decl_for("arg_c").is_some(), "arg_c VarDecl missing");
        if let Some(Stmt::VarDecl { ctype, .. }) = decl_for("arg_8") {
            assert!(matches!(ctype, CType::Named(n) if n == "HANDLE"));
        }
        if let Some(Stmt::VarDecl { ctype, .. }) = decl_for("arg_c") {
            assert!(matches!(ctype, CType::UInt32));
        }
    }

    /// MSVC SEH4 prolog functions don't establish the canonical
    /// `mov ebp, esp` pattern — they hand off to `__SEH_prolog4`
    /// instead. The fallback path in `analyze_and_rewrite` should
    /// detect the call to a SEH-prolog helper, treat it as a
    /// recognized frame, and synthesize positive-offset arg slots
    /// directly from the supplied prototype's parameter list at
    /// standard x86-32 cdecl/stdcall offsets.
    #[test]
    fn seh_prolog_with_prototype_synthesizes_arg_slots() {
        use crate::type_archive::{
            ArgType as ArchiveArg, CallingConvention, FunctionType as ArchiveFn, Primitive,
            TypeRef,
        };

        let proto = ArchiveFn {
            name: "__lockexit".to_string(),
            args: vec![
                ArchiveArg {
                    name: "code".to_string(),
                    ty: TypeRef::Primitive(Primitive::Int32),
                },
                ArchiveArg {
                    name: "flag".to_string(),
                    ty: TypeRef::Primitive(Primitive::Int32),
                },
            ],
            return_type: TypeRef::Primitive(Primitive::Void),
            calling_convention: CallingConvention::Cdecl,
            is_variadic: false,
        };

        // Body has no `mov ebp, esp` — instead it calls __SEH_prolog4.
        let body = vec![
            Stmt::ExprStmt(Expr::Call(
                Box::new(var("__SEH_prolog4")),
                vec![],
            )),
            assign(var("eax"), int(0)),
        ];
        let (out, layout) = analyze_and_rewrite(body, Some(&proto));

        // Frame should be reported as recognized via the SEH path.
        assert!(layout.has_frame_pointer, "SEH4 fallback should set has_frame_pointer");
        // Two arg slots at +8 and +c.
        assert_eq!(layout.slots.len(), 2);
        let slot8 = layout.slots.get(&8).expect("arg slot at +8");
        assert_eq!(slot8.name, "arg_8");
        assert!(matches!(slot8.ctype, Some(CType::Int32)));
        let slot_c = layout.slots.get(&0xc).expect("arg slot at +c");
        assert_eq!(slot_c.name, "arg_c");
        assert!(matches!(slot_c.ctype, Some(CType::Int32)));

        // VarDecls should be prepended to the body.
        assert!(matches!(out.first(), Some(Stmt::VarDecl { .. })));
        let decl_count = out.iter().filter(|s| matches!(s, Stmt::VarDecl { .. })).count();
        assert_eq!(decl_count, 2);
    }

    /// SEH4 fallback only fires when a prototype is supplied. Without
    /// one we have nothing to synthesize from, so the body should
    /// pass through unchanged with `has_frame_pointer = false`.
    #[test]
    fn seh_prolog_without_prototype_no_synthesis() {
        let body = vec![
            Stmt::ExprStmt(Expr::Call(
                Box::new(var("__SEH_prolog4")),
                vec![],
            )),
        ];
        let (out, layout) = analyze_and_rewrite(body, None);
        assert!(!layout.has_frame_pointer);
        assert!(layout.slots.is_empty());
        assert_eq!(out.len(), 1);
    }

    /// ARM64 prologues establish the frame pointer via
    /// `mov x29, sp` (which shows up as `fp = sp` in the IR after the
    /// renamer canonicalizes x29 → fp). The tier-2 pass should
    /// recognize this and rewrite `fp ± k` accesses to named slots
    /// just like the x86 rbp case.
    #[test]
    fn arm64_mov_fp_sp_is_recognized() {
        // `*(fp - 0x10) = w0`  ->  `local_10 = w0`
        let body = vec![
            assign(var("fp"), var("sp")),
            assign(
                deref(Expr::Binary(BinOp::Sub, Box::new(var("fp")), Box::new(int(0x10)))),
                var("w0"),
            ),
        ];
        let (out, layout) = analyze_and_rewrite(body, None);
        assert!(layout.has_frame_pointer, "mov x29, sp should be recognized");
        let slot = layout.slots.get(&-0x10).expect("slot at -0x10");
        assert_eq!(slot.name, "local_10");
        // The `fp = sp` prologue marker should be dropped.
        assert!(!out.iter().any(|s| matches!(
            s,
            Stmt::Assign(Expr::Var(l), Expr::Var(r)) if l == "fp" && r == "sp"
        )));
        assert!(has_var(&out, "local_10"));
    }

    /// ARM64 also emits `add x29, sp, #16` after a pre-indexed
    /// `stp x29, x30, [sp, #-16]!`, which in the IR looks like
    /// `fp = sp + 16`. The frame-pointer detector should accept
    /// this shape alongside the bare `mov` form, and the prologue
    /// stripper should drop it.
    #[test]
    fn arm64_add_fp_sp_const_is_recognized() {
        let body = vec![
            assign(
                var("fp"),
                Expr::Binary(BinOp::Add, Box::new(var("sp")), Box::new(int(0x10))),
            ),
            assign(
                deref(Expr::Binary(BinOp::Sub, Box::new(var("fp")), Box::new(int(8)))),
                var("w0"),
            ),
        ];
        let (out, layout) = analyze_and_rewrite(body, None);
        assert!(layout.has_frame_pointer, "add x29, sp, #16 should be recognized");
        assert!(layout.slots.get(&-8).is_some());
        // `fp = sp + 16` should be stripped.
        assert!(!out.iter().any(|s| matches!(
            s,
            Stmt::Assign(Expr::Var(l), Expr::Binary(..)) if l == "fp"
        )));
    }

    /// ARM64 positive-offset accesses via fp (stack args, though
    /// rare on AArch64) should still land as arg_N slots, reusing
    /// the same convention as x86.
    #[test]
    fn arm64_fp_positive_offset_becomes_arg() {
        let body = vec![
            assign(var("fp"), var("sp")),
            assign(
                var("w0"),
                deref(Expr::Binary(BinOp::Add, Box::new(var("fp")), Box::new(int(0x20)))),
            ),
        ];
        let (_out, layout) = analyze_and_rewrite(body, None);
        let slot = layout.slots.get(&0x20).expect("slot at +0x20");
        assert_eq!(slot.name, "arg_20");
    }

    /// Underscore-decoration variants of the SEH/EH prolog name should
    /// all be recognized.
    #[test]
    fn seh_prolog_name_recognition() {
        assert!(is_seh_prolog_name("__SEH_prolog4"));
        assert!(is_seh_prolog_name("_SEH_prolog4"));
        assert!(is_seh_prolog_name("SEH_prolog4"));
        assert!(is_seh_prolog_name("__SEH_prolog4_GS"));
        assert!(is_seh_prolog_name("__EH_prolog"));
        assert!(is_seh_prolog_name("_EH_prolog"));
        assert!(!is_seh_prolog_name("_setjmp"));
        assert!(!is_seh_prolog_name("__main"));
    }
}
