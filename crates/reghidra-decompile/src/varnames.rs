use crate::ast::{Expr, Stmt};
use std::collections::HashMap;

/// Rename variables to more readable names.
/// Registers get semantic names, temps get var_N names.
pub fn rename_variables(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut renamer = VarRenamer::new();

    // First pass: collect all variable names
    for stmt in &stmts {
        collect_vars(stmt, &mut renamer);
    }

    // Second pass: rename
    stmts.into_iter().map(|s| renamer.rename_stmt(s)).collect()
}

struct VarRenamer {
    renames: HashMap<String, String>,
    next_var: usize,
    next_arg: usize,
}

impl VarRenamer {
    fn new() -> Self {
        Self {
            renames: HashMap::new(),
            next_var: 0,
            next_arg: 0,
        }
    }

    fn get_name(&mut self, original: &str) -> String {
        if let Some(existing) = self.renames.get(original) {
            return existing.clone();
        }

        let new_name = match original {
            // x86_64 argument registers
            "rdi" | "x0" => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "rsi" | "x1" => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "rdx" | "x2" => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "rcx" | "x3" => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "r8" | "x4" => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "r9" | "x5" => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            // Return value
            "rax" => "result".into(),
            "eax" => "result".into(),
            // Stack/frame
            "rsp" | "esp" | "sp" => return original.to_string(),
            "rbp" | "ebp" | "fp" => return original.to_string(),
            // Flags — skip renaming
            "flags" | "nzcv" => return original.to_string(),
            // Temp variables
            s if s.starts_with('t') => {
                let n = format!("var_{}", self.next_var);
                self.next_var += 1;
                n
            }
            // Keep everything else
            _ => return original.to_string(),
        };

        self.renames.insert(original.to_string(), new_name.clone());
        new_name
    }

    fn rename_expr(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Var(name) => Expr::Var(self.get_name(&name)),
            Expr::Binary(op, a, b) => Expr::Binary(
                op,
                Box::new(self.rename_expr(*a)),
                Box::new(self.rename_expr(*b)),
            ),
            Expr::Unary(op, e) => Expr::Unary(op, Box::new(self.rename_expr(*e))),
            Expr::Call(func, args) => Expr::Call(
                Box::new(self.rename_expr(*func)),
                args.into_iter().map(|a| self.rename_expr(a)).collect(),
            ),
            Expr::Deref(e, t) => Expr::Deref(Box::new(self.rename_expr(*e)), t),
            Expr::Cast(t, e) => Expr::Cast(t, Box::new(self.rename_expr(*e))),
            Expr::Index(base, idx) => Expr::Index(
                Box::new(self.rename_expr(*base)),
                Box::new(self.rename_expr(*idx)),
            ),
            Expr::Member(e, field) => Expr::Member(Box::new(self.rename_expr(*e)), field),
            Expr::AddrOf(e) => Expr::AddrOf(Box::new(self.rename_expr(*e))),
            Expr::Ternary(c, a, b) => Expr::Ternary(
                Box::new(self.rename_expr(*c)),
                Box::new(self.rename_expr(*a)),
                Box::new(self.rename_expr(*b)),
            ),
            other => other,
        }
    }

    fn rename_stmt(&mut self, stmt: Stmt) -> Stmt {
        match stmt {
            Stmt::Assign(lhs, rhs) => {
                Stmt::Assign(self.rename_expr(lhs), self.rename_expr(rhs))
            }
            Stmt::ExprStmt(e) => Stmt::ExprStmt(self.rename_expr(e)),
            Stmt::Return(Some(e)) => Stmt::Return(Some(self.rename_expr(e))),
            Stmt::If { cond, then_body, else_body } => Stmt::If {
                cond: self.rename_expr(cond),
                then_body: then_body.into_iter().map(|s| self.rename_stmt(s)).collect(),
                else_body: else_body.into_iter().map(|s| self.rename_stmt(s)).collect(),
            },
            Stmt::While { cond, body } => Stmt::While {
                cond: self.rename_expr(cond),
                body: body.into_iter().map(|s| self.rename_stmt(s)).collect(),
            },
            Stmt::Loop { body } => Stmt::Loop {
                body: body.into_iter().map(|s| self.rename_stmt(s)).collect(),
            },
            Stmt::VarDecl { name, ctype, init } => Stmt::VarDecl {
                name: self.get_name(&name),
                ctype,
                init: init.map(|e| self.rename_expr(e)),
            },
            other => other,
        }
    }
}

fn collect_vars(stmt: &Stmt, renamer: &mut VarRenamer) {
    match stmt {
        Stmt::Assign(lhs, rhs) => {
            collect_expr_vars(lhs, renamer);
            collect_expr_vars(rhs, renamer);
        }
        Stmt::ExprStmt(e) => collect_expr_vars(e, renamer),
        Stmt::Return(Some(e)) => collect_expr_vars(e, renamer),
        Stmt::If { cond, then_body, else_body } => {
            collect_expr_vars(cond, renamer);
            for s in then_body { collect_vars(s, renamer); }
            for s in else_body { collect_vars(s, renamer); }
        }
        Stmt::While { cond, body } => {
            collect_expr_vars(cond, renamer);
            for s in body { collect_vars(s, renamer); }
        }
        Stmt::Loop { body } => {
            for s in body { collect_vars(s, renamer); }
        }
        _ => {}
    }
}

fn collect_expr_vars(expr: &Expr, renamer: &mut VarRenamer) {
    match expr {
        Expr::Var(name) => { renamer.get_name(name); }
        Expr::Binary(_, a, b) => {
            collect_expr_vars(a, renamer);
            collect_expr_vars(b, renamer);
        }
        Expr::Unary(_, e) | Expr::Deref(e, _) | Expr::Cast(_, e) | Expr::AddrOf(e) => {
            collect_expr_vars(e, renamer);
        }
        Expr::Call(f, args) => {
            collect_expr_vars(f, renamer);
            for a in args { collect_expr_vars(a, renamer); }
        }
        _ => {}
    }
}
