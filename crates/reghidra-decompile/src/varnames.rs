use crate::ast::{Expr, Stmt};
use std::collections::{HashMap, HashSet};

/// Rename variables to more readable names.
/// Registers get semantic names, temps get var_N names. After the heuristic
/// pass, `user_renames` is applied as a final pass: it maps post-heuristic
/// names (e.g. "arg0", "var_1") to user-chosen names.
pub fn rename_variables(
    stmts: Vec<Stmt>,
    user_renames: &HashMap<String, String>,
) -> Vec<Stmt> {
    let mut renamer = VarRenamer::new();

    // First pass: collect all variable names
    for stmt in &stmts {
        collect_vars(stmt, &mut renamer);
    }

    // Second pass: rename
    let renamed: Vec<Stmt> = stmts.into_iter().map(|s| renamer.rename_stmt(s)).collect();

    if user_renames.is_empty() {
        return renamed;
    }

    // Third pass: apply user overrides (post-heuristic name → user name)
    let mut user = UserRenamer { map: user_renames };
    renamed.into_iter().map(|s| user.rename_stmt(s)).collect()
}

/// Walk the AST and return every distinct variable name that appears.
/// Used by the GUI to tokenize variable references for right-click renaming.
pub fn collect_displayed_names(stmts: &[Stmt]) -> Vec<String> {
    let mut set: HashSet<String> = HashSet::new();
    for s in stmts {
        gather_names_stmt(s, &mut set);
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

fn gather_names_stmt(stmt: &Stmt, out: &mut HashSet<String>) {
    match stmt {
        Stmt::Assign(lhs, rhs) => {
            gather_names_expr(lhs, out);
            gather_names_expr(rhs, out);
        }
        Stmt::ExprStmt(e) => gather_names_expr(e, out),
        Stmt::Return(Some(e)) => gather_names_expr(e, out),
        Stmt::If { cond, then_body, else_body } => {
            gather_names_expr(cond, out);
            for s in then_body { gather_names_stmt(s, out); }
            for s in else_body { gather_names_stmt(s, out); }
        }
        Stmt::While { cond, body } => {
            gather_names_expr(cond, out);
            for s in body { gather_names_stmt(s, out); }
        }
        Stmt::Loop { body } => {
            for s in body { gather_names_stmt(s, out); }
        }
        Stmt::VarDecl { name, init, .. } => {
            out.insert(name.clone());
            if let Some(e) = init { gather_names_expr(e, out); }
        }
        _ => {}
    }
}

fn gather_names_expr(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Var(name) => { out.insert(name.clone()); }
        Expr::Binary(_, a, b) => { gather_names_expr(a, out); gather_names_expr(b, out); }
        Expr::Unary(_, e) | Expr::Deref(e, _) | Expr::Cast(_, e) | Expr::AddrOf(e) => {
            gather_names_expr(e, out);
        }
        Expr::Call(f, args) => {
            gather_names_expr(f, out);
            for a in args { gather_names_expr(a, out); }
        }
        Expr::Index(b, i) => { gather_names_expr(b, out); gather_names_expr(i, out); }
        Expr::Member(e, _) => gather_names_expr(e, out),
        Expr::Ternary(c, a, b) => {
            gather_names_expr(c, out);
            gather_names_expr(a, out);
            gather_names_expr(b, out);
        }
        _ => {}
    }
}

/// Final-pass renamer that applies user-chosen names on top of the heuristic.
struct UserRenamer<'a> {
    map: &'a HashMap<String, String>,
}

impl<'a> UserRenamer<'a> {
    fn rename_name(&self, name: &str) -> String {
        self.map.get(name).cloned().unwrap_or_else(|| name.to_string())
    }

    fn rename_expr(&mut self, expr: Expr) -> Expr {
        match expr {
            Expr::Var(name) => Expr::Var(self.rename_name(&name)),
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
                name: self.rename_name(&name),
                ctype,
                init: init.map(|e| self.rename_expr(e)),
            },
            other => other,
        }
    }
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
            Stmt::SourceAddr(addr) => Stmt::SourceAddr(addr),
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
