use crate::ast::{BinOp, Expr, Stmt};

/// Emit a complete function as C-like pseudocode.
pub fn emit_function(name: &str, body: &[Stmt]) -> String {
    let mut out = String::new();
    out.push_str(&format!("void {name}() {{\n"));
    for stmt in body {
        emit_stmt(&mut out, stmt, 1);
    }
    out.push_str("}\n");
    out
}

fn emit_stmt(out: &mut String, stmt: &Stmt, indent: usize) {
    let pad = "    ".repeat(indent);
    match stmt {
        Stmt::Assign(lhs, rhs) => {
            // Skip flag assignments for cleaner output
            if is_flags_var(lhs) {
                return;
            }
            // Skip stack pointer manipulation for cleaner output
            if is_stack_ptr(lhs) && is_simple_stack_adjust(rhs) {
                return;
            }
            out.push_str(&format!("{pad}{} = {};\n", emit_expr(lhs), emit_expr(rhs)));
        }
        Stmt::ExprStmt(e) => {
            out.push_str(&format!("{pad}{};\n", emit_expr(e)));
        }
        Stmt::Return(Some(e)) => {
            out.push_str(&format!("{pad}return {};\n", emit_expr(e)));
        }
        Stmt::Return(None) => {
            out.push_str(&format!("{pad}return;\n"));
        }
        Stmt::If { cond, then_body, else_body } => {
            out.push_str(&format!("{pad}if ({}) {{\n", emit_expr(cond)));
            for s in then_body {
                emit_stmt(out, s, indent + 1);
            }
            if else_body.is_empty() {
                out.push_str(&format!("{pad}}}\n"));
            } else {
                out.push_str(&format!("{pad}}} else {{\n"));
                for s in else_body {
                    emit_stmt(out, s, indent + 1);
                }
                out.push_str(&format!("{pad}}}\n"));
            }
        }
        Stmt::While { cond, body } => {
            out.push_str(&format!("{pad}while ({}) {{\n", emit_expr(cond)));
            for s in body {
                emit_stmt(out, s, indent + 1);
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::Loop { body } => {
            out.push_str(&format!("{pad}for (;;) {{\n"));
            for s in body {
                emit_stmt(out, s, indent + 1);
            }
            out.push_str(&format!("{pad}}}\n"));
        }
        Stmt::Break => {
            out.push_str(&format!("{pad}break;\n"));
        }
        Stmt::Continue => {
            out.push_str(&format!("{pad}continue;\n"));
        }
        Stmt::Goto(target) => {
            out.push_str(&format!("{pad}goto label_{target:x};\n"));
        }
        Stmt::Label(addr) => {
            out.push_str(&format!("label_{addr:x}:\n"));
        }
        Stmt::Comment(text) => {
            out.push_str(&format!("{pad}/* {text} */\n"));
        }
        Stmt::VarDecl { name, ctype, init } => {
            if let Some(init_expr) = init {
                out.push_str(&format!("{pad}{ctype} {name} = {};\n", emit_expr(init_expr)));
            } else {
                out.push_str(&format!("{pad}{ctype} {name};\n"));
            }
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
            format!("*({})", emit_expr(e))
        }
        Expr::AddrOf(e) => {
            format!("&({})", emit_expr(e))
        }
        Expr::Ternary(c, a, b) => {
            format!("{} ? {} : {}", emit_expr(c), emit_expr(a), emit_expr(b))
        }
    }
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
