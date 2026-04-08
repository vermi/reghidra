use crate::ast::{BinOp, Expr, Stmt};
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
pub fn emit_function(name: &str, body: &[Stmt], label_names: &HashMap<u64, String>) -> String {
    let lines = emit_function_annotated(name, body, label_names);
    lines.into_iter().map(|l| l.text).collect::<Vec<_>>().join("\n")
}

/// Emit a complete function as annotated lines (text + source address).
pub fn emit_function_annotated(
    name: &str,
    body: &[Stmt],
    label_names: &HashMap<u64, String>,
) -> Vec<AnnotatedLine> {
    let mut lines = Vec::new();
    let mut current_addr: Option<u64> = None;

    // C-correct empty parameter list. `void foo()` and `void foo(void)`
    // mean different things in strict C (the former is an "unspecified
    // prototype" holdover from K&R C), and the UChicago style guide we
    // follow calls out the latter as the correct declaration form.
    lines.push(AnnotatedLine {
        text: format!("void {name}(void) {{"),
        addr: None,
    });

    // Count the leading VarDecl statements so we can emit a blank line
    // between the variables block and the function body. This is a
    // readability rule — Ghidra/IDA both visually separate the declaration
    // block, and without it the decomp view reads as a dense wall of code.
    let leading_decls = body
        .iter()
        .take_while(|s| matches!(s, Stmt::VarDecl { .. }))
        .count();

    for (idx, stmt) in body.iter().enumerate() {
        emit_stmt_annotated(&mut lines, stmt, 1, &mut current_addr, label_names);
        // After the last VarDecl (and only if there's body code after it),
        // insert a blank separator line.
        if idx + 1 == leading_decls && leading_decls > 0 && leading_decls < body.len() {
            lines.push(AnnotatedLine {
                text: String::new(),
                addr: None,
            });
        }
    }

    lines.push(AnnotatedLine {
        text: "}".to_string(),
        addr: None,
    });

    lines
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
            for s in then_body {
                emit_stmt_annotated(lines, s, indent + 1, current_addr, label_names);
            }
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
                for s in else_body {
                    emit_stmt_annotated(lines, s, indent + 1, current_addr, label_names);
                }
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
            for s in body {
                emit_stmt_annotated(lines, s, indent + 1, current_addr, label_names);
            }
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
            for s in body {
                emit_stmt_annotated(lines, s, indent + 1, current_addr, label_names);
            }
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
            let inner = emit_expr(e);
            format!("{op}{inner}")
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
