use crate::ast::{BinOp, CType, Expr, Stmt};
use crate::type_archive::{type_ref_to_ctype, FunctionType};
use std::collections::HashMap;

/// A line of decompiled output with optional source address.
#[derive(Debug, Clone)]
pub struct AnnotatedLine {
    pub text: String,
    pub addr: Option<u64>,
}

/// Look up a label's display form, applying user-renames if present.
fn label_text(addr: u64, label_names: &HashMap<u64, String>) -> String {
    match label_names.get(&addr) {
        Some(name) => name.clone(),
        None => format!("label_{addr:x}"),
    }
}

/// Emit a complete function as C-like pseudocode.
pub fn emit_function(
    name: &str,
    body: &[Stmt],
    label_names: &HashMap<u64, String>,
    prototype: Option<&FunctionType>,
) -> String {
    let lines = emit_function_annotated(name, body, label_names, prototype);
    lines.into_iter().map(|l| l.text).collect::<Vec<_>>().join("\n")
}

/// Build the function signature line (`int foo(FILE* arg_8, ...)`) from
/// an archive prototype when available, falling back to
/// `void name(void)` when no prototype is known. The displayed name is
/// always the caller-supplied `name` (which may be demangled or
/// user-renamed), regardless of the prototype's own `name` field —
/// we use the prototype only for types, not identity.
fn format_signature(name: &str, prototype: Option<&FunctionType>) -> String {
    let Some(proto) = prototype else {
        // C-correct empty parameter list. `void foo()` and
        // `void foo(void)` mean different things in strict C (the
        // former is an "unspecified prototype" holdover from K&R C),
        // and the UChicago style guide we follow calls out the
        // latter as the correct declaration form.
        return format!("void {name}(void) {{");
    };
    let ret = type_ref_to_ctype(&proto.return_type);
    let ret_str = match ret {
        CType::Void => "void".to_string(),
        other => other.to_string(),
    };
    if proto.args.is_empty() && !proto.is_variadic {
        return format!("{ret_str} {name}(void) {{");
    }
    let mut params: Vec<String> = proto
        .args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            let ty = type_ref_to_ctype(&arg.ty);
            // Use the archive's arg name if present, otherwise
            // number parameters positionally. Archive-sourced arg
            // names come from the binding crate (windows-sys param
            // names are real; libc's are typically `arg0`, `arg1`).
            let pname = if arg.name.is_empty() {
                format!("arg{i}")
            } else {
                arg.name.clone()
            };
            format!("{ty} {pname}")
        })
        .collect();
    if proto.is_variadic {
        params.push("...".to_string());
    }
    format!("{ret_str} {name}({}) {{", params.join(", "))
}

/// Emit a complete function as annotated lines (text + source address).
pub fn emit_function_annotated(
    name: &str,
    body: &[Stmt],
    label_names: &HashMap<u64, String>,
    prototype: Option<&FunctionType>,
) -> Vec<AnnotatedLine> {
    let mut lines = Vec::new();
    let mut current_addr: Option<u64> = None;

    lines.push(AnnotatedLine {
        text: format_signature(name, prototype),
        addr: None,
    });

    emit_body_with_separators(&mut lines, body, 1, &mut current_addr, label_names);

    lines.push(AnnotatedLine {
        text: "}".to_string(),
        addr: None,
    });

    lines
}

/// Emit a sequence of statements at the given indent, inserting blank
/// separator lines between logical sections per the UChicago C style
/// guide rule: "the body of the function should include blank lines to
/// indicate logical sections (with at most one blank line separating
/// each logical section)."
///
/// We never emit two blank lines in a row, and we never emit a leading
/// or trailing blank inside a brace block. The decision is local: it
/// looks at the previous *visible* statement (skipping `SourceAddr`
/// markers, which produce no output) and the current statement, and
/// asks `should_separate` whether the transition crosses a section
/// boundary worth flagging.
fn emit_body_with_separators(
    lines: &mut Vec<AnnotatedLine>,
    body: &[Stmt],
    indent: usize,
    current_addr: &mut Option<u64>,
    label_names: &HashMap<u64, String>,
) {
    let mut prev_visible: Option<&Stmt> = None;
    for stmt in body {
        // SourceAddr markers update tracking state but emit no line, so
        // they shouldn't anchor a separation decision.
        if matches!(stmt, Stmt::SourceAddr(_)) {
            emit_stmt_annotated(lines, stmt, indent, current_addr, label_names);
            continue;
        }
        if let Some(prev) = prev_visible {
            if should_separate(prev, stmt) {
                lines.push(AnnotatedLine {
                    text: String::new(),
                    addr: None,
                });
            }
        }
        emit_stmt_annotated(lines, stmt, indent, current_addr, label_names);
        prev_visible = Some(stmt);
    }
}

/// Decide whether a blank line should appear between the two adjacent
/// (visible) statements. Rules, in priority order:
///
/// 1. **VarDecl block boundary** — the leading variable declarations are
///    a distinct preamble. Always separate them from the first non-decl
///    line so the variables list reads as its own section like Ghidra/IDA.
/// 2. **Labels are section anchors** — a label always starts a new
///    section, so insert a blank before any label that isn't the very
///    first statement.
/// 3. **Control-flow blocks** (`if` / `while` / `for`/loop) — we want a
///    blank between such a block and adjacent straight-line code, so the
///    structure pops out visually. Two adjacent blocks are NOT separated
///    (e.g. an `if` followed immediately by another `if` reads fine).
/// 4. **After `return`** — anything after a return is reachable only via
///    a label or fall-through-into-block, both of which are unusual and
///    deserve a visual break.
/// 5. **Around comment lines** — `/* unimpl: ... */` annotations mark
///    transitions worth flagging.
fn should_separate(prev: &Stmt, curr: &Stmt) -> bool {
    let prev_is_decl = matches!(prev, Stmt::VarDecl { .. });
    let curr_is_decl = matches!(curr, Stmt::VarDecl { .. });
    if prev_is_decl != curr_is_decl {
        return true;
    }

    if matches!(curr, Stmt::Label(_)) {
        return true;
    }

    let prev_is_block = is_block_stmt(prev);
    let curr_is_block = is_block_stmt(curr);
    if prev_is_block != curr_is_block {
        return true;
    }

    if matches!(prev, Stmt::Return(_) | Stmt::Goto(_)) {
        return true;
    }

    if matches!(prev, Stmt::Comment(_)) || matches!(curr, Stmt::Comment(_)) {
        return true;
    }

    false
}

/// True for the structured control-flow forms that visually contain a
/// brace block. These are the statements that benefit from being
/// visually offset from straight-line code around them.
fn is_block_stmt(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::If { .. } | Stmt::While { .. } | Stmt::Loop { .. }
    )
}

fn emit_stmt_annotated(
    lines: &mut Vec<AnnotatedLine>,
    stmt: &Stmt,
    indent: usize,
    current_addr: &mut Option<u64>,
    label_names: &HashMap<u64, String>,
) {
    let pad = "    ".repeat(indent);
    match stmt {
        Stmt::SourceAddr(addr) => {
            *current_addr = Some(*addr);
            // No output line for this marker
        }
        Stmt::Assign(lhs, rhs) => {
            if is_flags_var(lhs) {
                return;
            }
            if is_stack_ptr(lhs) && is_simple_stack_adjust(rhs) {
                return;
            }
            lines.push(AnnotatedLine {
                text: format!("{pad}{} = {};", emit_expr(lhs), emit_expr(rhs)),
                addr: *current_addr,
            });
        }
        Stmt::ExprStmt(e) => {
            lines.push(AnnotatedLine {
                text: format!("{pad}{};", emit_expr(e)),
                addr: *current_addr,
            });
        }
        Stmt::Return(Some(e)) => {
            lines.push(AnnotatedLine {
                text: format!("{pad}return {};", emit_expr(e)),
                addr: *current_addr,
            });
        }
        Stmt::Return(None) => {
            lines.push(AnnotatedLine {
                text: format!("{pad}return;"),
                addr: *current_addr,
            });
        }
        Stmt::If { cond, then_body, else_body } => {
            lines.push(AnnotatedLine {
                text: format!("{pad}if ({}) {{", emit_expr(cond)),
                addr: *current_addr,
            });
            emit_body_with_separators(lines, then_body, indent + 1, current_addr, label_names);
            if else_body.is_empty() {
                lines.push(AnnotatedLine {
                    text: format!("{pad}}}"),
                    addr: *current_addr,
                });
            } else {
                lines.push(AnnotatedLine {
                    text: format!("{pad}}} else {{"),
                    addr: *current_addr,
                });
                emit_body_with_separators(lines, else_body, indent + 1, current_addr, label_names);
                lines.push(AnnotatedLine {
                    text: format!("{pad}}}"),
                    addr: *current_addr,
                });
            }
        }
        Stmt::While { cond, body } => {
            lines.push(AnnotatedLine {
                text: format!("{pad}while ({}) {{", emit_expr(cond)),
                addr: *current_addr,
            });
            emit_body_with_separators(lines, body, indent + 1, current_addr, label_names);
            lines.push(AnnotatedLine {
                text: format!("{pad}}}"),
                addr: *current_addr,
            });
        }
        Stmt::Loop { body } => {
            lines.push(AnnotatedLine {
                text: format!("{pad}for (;;) {{"),
                addr: *current_addr,
            });
            emit_body_with_separators(lines, body, indent + 1, current_addr, label_names);
            lines.push(AnnotatedLine {
                text: format!("{pad}}}"),
                addr: *current_addr,
            });
        }
        Stmt::Break => {
            lines.push(AnnotatedLine {
                text: format!("{pad}break;"),
                addr: *current_addr,
            });
        }
        Stmt::Continue => {
            lines.push(AnnotatedLine {
                text: format!("{pad}continue;"),
                addr: *current_addr,
            });
        }
        Stmt::Goto(target) => {
            let label = label_text(*target, label_names);
            lines.push(AnnotatedLine {
                text: format!("{pad}goto {label};"),
                addr: *current_addr,
            });
        }
        Stmt::Label(addr) => {
            let label = label_text(*addr, label_names);
            lines.push(AnnotatedLine {
                text: format!("{label}:"),
                addr: Some(*addr),
            });
        }
        Stmt::Comment(text) => {
            lines.push(AnnotatedLine {
                text: format!("{pad}/* {text} */"),
                addr: *current_addr,
            });
        }
        Stmt::VarDecl { name, ctype, init } => {
            let text = if let Some(init_expr) = init {
                format!("{pad}{ctype} {name} = {};", emit_expr(init_expr))
            } else {
                format!("{pad}{ctype} {name};")
            };
            lines.push(AnnotatedLine {
                text,
                addr: *current_addr,
            });
        }
    }
}

fn emit_expr(expr: &Expr) -> String {
    match expr {
        Expr::Var(name) => name.clone(),
        Expr::IntLit(val, _typ) => {
            if *val == 0 {
                "0".into()
            } else if *val <= 9 {
                format!("{val}")
            } else if *val <= 0xFF {
                format!("0x{val:x}")
            } else {
                format!("0x{val:x}")
            }
        }
        Expr::StringLit(s) => format!("\"{s}\""),
        Expr::Unary(op, e) => {
            // Unary `-`, `~`, `!` bind tighter than binary operators, so
            // wrap the operand in parens whenever it's a Binary expression
            // — `-(x + y)` would otherwise render as `-x + y` and silently
            // change meaning. Other operand shapes (variables, literals,
            // calls, casts, derefs, etc.) don't need parens because they
            // already group tightly.
            let inner = emit_expr(e);
            if matches!(e.as_ref(), Expr::Binary(..) | Expr::Ternary(..)) {
                format!("{op}({inner})")
            } else {
                format!("{op}{inner}")
            }
        }
        Expr::Binary(op, a, b) => {
            let left = emit_expr_with_parens(a, op, true);
            let right = emit_expr_with_parens(b, op, false);
            format!("{left} {op} {right}")
        }
        Expr::Call(func, args) => {
            let func_str = emit_expr(func);
            let args_str: Vec<String> = args.iter().map(|a| emit_expr(a)).collect();
            format!("{func_str}({})", args_str.join(", "))
        }
        Expr::Index(base, idx) => {
            format!("{}[{}]", emit_expr(base), emit_expr(idx))
        }
        Expr::Member(e, field) => {
            format!("{}.{field}", emit_expr(e))
        }
        Expr::Cast(typ, e) => {
            format!("({}){}", typ, emit_expr(e))
        }
        Expr::Deref(e, _typ) => {
            // Per the UChicago C style guide: "No spaces around dereference
            // (*), dot (.), or arrow (->) operators." For a bare variable
            // or a similarly tight operand the parens are also noise, so
            // elide them and emit `*var` instead of `*(var)`. For anything
            // more complex (binary op, cast, etc.) keep the parens so
            // precedence stays unambiguous.
            if needs_no_deref_parens(e) {
                format!("*{}", emit_expr(e))
            } else {
                format!("*({})", emit_expr(e))
            }
        }
        Expr::AddrOf(e) => {
            if needs_no_deref_parens(e) {
                format!("&{}", emit_expr(e))
            } else {
                format!("&({})", emit_expr(e))
            }
        }
        Expr::Ternary(c, a, b) => {
            format!("{} ? {} : {}", emit_expr(c), emit_expr(a), emit_expr(b))
        }
    }
}

/// True if `expr` is "tight" enough that wrapping it in parens after a
/// unary `*` or `&` adds only noise. Variables, indices, members, and
/// already-parenthesised things (calls, derefs, string literals, ints)
/// qualify. Binary ops and casts do not — they need the parens for the
/// reader to track precedence.
fn needs_no_deref_parens(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Var(_)
            | Expr::IntLit(_, _)
            | Expr::StringLit(_)
            | Expr::Call(..)
            | Expr::Index(..)
            | Expr::Member(..)
            | Expr::Deref(..)
            | Expr::AddrOf(..)
    )
}

fn emit_expr_with_parens(expr: &Expr, parent_op: &BinOp, is_left: bool) -> String {
    let inner = emit_expr(expr);
    if let Expr::Binary(child_op, _, _) = expr {
        if needs_parens(child_op, parent_op, is_left) {
            return format!("({inner})");
        }
    }
    inner
}

fn needs_parens(child: &BinOp, parent: &BinOp, _is_left: bool) -> bool {
    precedence(child) < precedence(parent)
}

fn precedence(op: &BinOp) -> u8 {
    match op {
        BinOp::LogOr => 1,
        BinOp::LogAnd => 2,
        BinOp::BitOr => 3,
        BinOp::BitXor => 4,
        BinOp::BitAnd => 5,
        BinOp::Eq | BinOp::Ne => 6,
        BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => 7,
        BinOp::Shl | BinOp::Shr => 8,
        BinOp::Add | BinOp::Sub => 9,
        BinOp::Mul | BinOp::Div | BinOp::Mod => 10,
    }
}

/// Check if an expression refers to flags register.
fn is_flags_var(expr: &Expr) -> bool {
    matches!(expr, Expr::Var(name) if name == "flags" || name == "nzcv")
}

/// Check if an expression refers to stack pointer.
fn is_stack_ptr(expr: &Expr) -> bool {
    matches!(expr, Expr::Var(name) if name == "rsp" || name == "esp" || name == "sp")
}

/// Check if an expression is a simple stack adjustment (rsp +/- const).
fn is_simple_stack_adjust(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(BinOp::Add | BinOp::Sub, a, b) => {
            is_stack_ptr(a) && matches!(b.as_ref(), Expr::IntLit(_, _))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{CType, Expr, Stmt};

    fn var(s: &str) -> Expr {
        Expr::Var(s.to_string())
    }

    fn int(n: u64) -> Expr {
        Expr::IntLit(n, CType::UInt32)
    }

    fn assign(l: Expr, r: Expr) -> Stmt {
        Stmt::Assign(l, r)
    }

    fn decl(name: &str) -> Stmt {
        Stmt::VarDecl {
            name: name.to_string(),
            ctype: CType::UInt32,
            init: None,
        }
    }

    fn render(body: &[Stmt]) -> Vec<String> {
        let labels = HashMap::new();
        emit_function_annotated("f", body, &labels, None)
            .into_iter()
            .map(|l| l.text)
            .collect()
    }

    fn count_blank_runs(lines: &[String]) -> usize {
        // Returns the number of distinct blank-line spans. Two consecutive
        // blanks would count as one (which we never want — the style guide
        // caps at one blank between sections).
        let mut runs = 0;
        let mut in_blank = false;
        for l in lines {
            if l.is_empty() {
                if !in_blank {
                    runs += 1;
                    in_blank = true;
                }
            } else {
                in_blank = false;
            }
        }
        runs
    }

    #[test]
    fn no_decls_no_leading_blank() {
        // A body with no VarDecls and no control flow shouldn't have any
        // blank lines — there are no logical sections to separate.
        let body = vec![
            assign(var("eax"), int(1)),
            assign(var("edx"), int(2)),
        ];
        let lines = render(&body);
        assert!(lines.iter().all(|l| !l.is_empty()), "unexpected blank in {:?}", lines);
    }

    #[test]
    fn vardecl_block_separated_from_body() {
        // Variables declared up front get a blank line between the decl
        // block and the first body statement.
        let body = vec![
            decl("local_4"),
            decl("local_8"),
            assign(var("eax"), int(1)),
        ];
        let lines = render(&body);
        let blank_idx = lines.iter().position(|l| l.is_empty()).expect("expected a blank line");
        // The blank should fall between the decls and the first body line.
        assert!(lines[blank_idx - 1].contains("local_8"));
        assert!(lines[blank_idx + 1].contains("eax"));
    }

    #[test]
    fn no_blank_when_only_decls() {
        // No blank line should follow the decls if there's no body after them.
        let body = vec![decl("local_4"), decl("local_8")];
        let lines = render(&body);
        assert_eq!(count_blank_runs(&lines), 0);
    }

    #[test]
    fn if_block_separated_from_surrounding_code() {
        let body = vec![
            assign(var("eax"), int(1)),
            Stmt::If {
                cond: var("eax"),
                then_body: vec![assign(var("edx"), int(2))],
                else_body: vec![],
            },
            assign(var("ecx"), int(3)),
        ];
        let lines = render(&body);
        // Two blank-line runs: one before the if, one after the if.
        assert_eq!(count_blank_runs(&lines), 2, "lines: {:?}", lines);
    }

    #[test]
    fn back_to_back_ifs_not_separated() {
        // Two control-flow blocks back-to-back are NOT separated — they
        // already read as distinct units thanks to the brace formatting.
        let body = vec![
            Stmt::If {
                cond: var("eax"),
                then_body: vec![assign(var("edx"), int(1))],
                else_body: vec![],
            },
            Stmt::If {
                cond: var("ecx"),
                then_body: vec![assign(var("edx"), int(2))],
                else_body: vec![],
            },
        ];
        let lines = render(&body);
        assert_eq!(count_blank_runs(&lines), 0, "lines: {:?}", lines);
    }

    #[test]
    fn label_starts_a_section() {
        let body = vec![
            assign(var("eax"), int(1)),
            Stmt::Label(0x401000),
            assign(var("edx"), int(2)),
        ];
        let lines = render(&body);
        let label_idx = lines.iter().position(|l| l.contains("label_401000")).unwrap();
        assert!(lines[label_idx - 1].is_empty(), "expected blank before label, lines: {:?}", lines);
    }

    #[test]
    fn no_double_blank_lines() {
        // The "at most one blank line between sections" rule. Even when
        // multiple separation triggers fire at the same boundary, we
        // never emit two blanks in a row.
        let body = vec![
            decl("local_4"),
            Stmt::If {
                cond: var("eax"),
                then_body: vec![assign(var("edx"), int(1))],
                else_body: vec![],
            },
        ];
        let lines = render(&body);
        // Walk lines; assert no two consecutive empty entries.
        for w in lines.windows(2) {
            assert!(!(w[0].is_empty() && w[1].is_empty()), "double blank in {:?}", lines);
        }
    }

    #[test]
    fn nested_block_bodies_also_get_separators() {
        // The rule applies recursively inside if/while/loop bodies, not
        // just at top level.
        let body = vec![Stmt::If {
            cond: var("eax"),
            then_body: vec![
                assign(var("edx"), int(1)),
                Stmt::If {
                    cond: var("ecx"),
                    then_body: vec![assign(var("edi"), int(2))],
                    else_body: vec![],
                },
                assign(var("esi"), int(3)),
            ],
            else_body: vec![],
        }];
        let lines = render(&body);
        // Inside the outer if, the inner if should be flanked by blanks.
        assert!(count_blank_runs(&lines) >= 2, "expected nested separators, lines: {:?}", lines);
    }

    #[test]
    fn no_leading_or_trailing_blank_inside_block() {
        // The very first line inside a brace block must not be blank,
        // and the closing `}` must not be preceded by a blank.
        let body = vec![Stmt::If {
            cond: var("eax"),
            then_body: vec![
                assign(var("edx"), int(1)),
                assign(var("ecx"), int(2)),
            ],
            else_body: vec![],
        }];
        let lines = render(&body);
        // Find the if-open line and the matching close.
        let open_idx = lines.iter().position(|l| l.contains("if (eax)")).unwrap();
        let close_idx = lines.iter().rposition(|l| l.trim() == "}").unwrap();
        // The line right after the open and right before the close are
        // never blank.
        assert!(!lines[open_idx + 1].is_empty(), "leading blank inside block: {:?}", lines);
        assert!(!lines[close_idx - 1].is_empty(), "trailing blank inside block: {:?}", lines);
    }
}
