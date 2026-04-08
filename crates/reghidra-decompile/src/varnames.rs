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

    // Pre-pass: scan for any 32-bit x86 register names so we can switch the
    // calling-convention assumption before any get_name() call caches a
    // potentially-wrong argN mapping.
    for stmt in &stmts {
        scan_for_x86_32(stmt, &mut renamer);
    }

    // First pass: collect all variable names (assigns deterministic numbers
    // in source order).
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

/// Map any sized alias of an x86 / ARM64 register to its canonical 64-bit name.
/// Returns the input unchanged if it's not a recognized register name.
pub(crate) fn canonical_reg_name(name: &str) -> &str {
    match name {
        // x86 GPRs
        "rax" | "eax" | "ax" | "ah" | "al" => "rax",
        "rcx" | "ecx" | "cx" | "ch" | "cl" => "rcx",
        "rdx" | "edx" | "dx" | "dh" | "dl" => "rdx",
        "rbx" | "ebx" | "bx" | "bh" | "bl" => "rbx",
        "rsp" | "esp" | "sp" | "spl"       => "rsp",
        "rbp" | "ebp" | "bp" | "bpl"       => "rbp",
        "rsi" | "esi" | "si" | "sil"       => "rsi",
        "rdi" | "edi" | "di" | "dil"       => "rdi",
        "r8"  | "r8d"  | "r8w"  | "r8b"    => "r8",
        "r9"  | "r9d"  | "r9w"  | "r9b"    => "r9",
        "r10" | "r10d" | "r10w" | "r10b"   => "r10",
        "r11" | "r11d" | "r11w" | "r11b"   => "r11",
        "r12" | "r12d" | "r12w" | "r12b"   => "r12",
        "r13" | "r13d" | "r13w" | "r13b"   => "r13",
        "r14" | "r14d" | "r14w" | "r14b"   => "r14",
        "r15" | "r15d" | "r15w" | "r15b"   => "r15",
        "rip" | "eip"                      => "rip",
        // ARM64: w0..w28 are 32-bit halves of x0..x28; sp/fp/lr/pc/xzr already canonical.
        s if s.len() >= 2 && s.starts_with('w') && s[1..].chars().all(|c| c.is_ascii_digit()) => {
            // Map "wN" -> "xN". We can't return a borrowed slice for the
            // synthesized name, so the caller's `renames` map will end up
            // keyed on the original string for ARM in the rare cases where
            // both "wN" and "xN" appear — acceptable for now.
            name
        }
        _ => name,
    }
}

/// True if `name` looks like a register identifier produced by
/// `register_name` in the expression builder. Used to decide whether an
/// unrecognized variable should be renamed to a scratch local or left alone.
fn is_known_register_name(name: &str) -> bool {
    matches!(
        name,
        "rax" | "rcx" | "rdx" | "rbx" | "rsp" | "rbp" | "rsi" | "rdi"
        | "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15"
        | "rip" | "flags" | "nzcv" | "fp" | "lr" | "sp" | "pc" | "xzr"
    ) || (
        name.len() >= 2
            && (name.starts_with('x') || name.starts_with('w'))
            && name[1..].chars().all(|c| c.is_ascii_digit())
    )
}

struct VarRenamer {
    renames: HashMap<String, String>,
    next_var: usize,
    next_arg: usize,
    /// Set during collect_vars when any 32-bit x86 register name is seen.
    /// In that mode no general-purpose register is treated as a calling-
    /// convention arg (x86-32 cdecl/stdcall pass everything on the stack),
    /// so rcx/rdx/rsi/rdi all become scratch locals instead of argN.
    x86_32_mode: bool,
}

impl VarRenamer {
    fn new() -> Self {
        Self {
            renames: HashMap::new(),
            next_var: 0,
            next_arg: 0,
            x86_32_mode: false,
        }
    }

    fn note_register_seen(&mut self, name: &str) {
        if matches!(
            name,
            "eax" | "ecx" | "edx" | "ebx" | "esp" | "ebp" | "esi" | "edi"
                | "ax" | "cx" | "dx" | "bx" | "sp" | "bp" | "si" | "di"
        ) {
            self.x86_32_mode = true;
        }
    }

    fn get_name(&mut self, original: &str) -> String {
        // Canonicalize sized aliases of the same hardware register to a single
        // key, so that e.g. eax and rax (or ecx and rcx) share one rename.
        let key = canonical_reg_name(original);

        if let Some(existing) = self.renames.get(key) {
            return existing.clone();
        }

        // In x86-32 mode no GPR is a calling-convention arg, so route those
        // straight to scratch locals.
        let arg_capable = !self.x86_32_mode;

        let new_name: String = match key {
            // x86_64 SysV / ARM64 argument registers (best effort — Windows x64
            // and 32-bit Windows fastcall use different conventions, but at
            // least these get a consistent semantic name instead of a register).
            "rdi" | "x0" if arg_capable => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "rsi" | "x1" if arg_capable => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "rdx" | "x2" if arg_capable => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "rcx" | "x3" if arg_capable => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "r8"  | "x4" if arg_capable => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            "r9"  | "x5" if arg_capable => { let n = format!("arg{}", self.next_arg); self.next_arg += 1; n }
            // Return value
            "rax" => "result".into(),
            // Stack pointer / frame pointer / IP / flags: surface as-is, but
            // use the canonical 64-bit name so all sized aliases collapse.
            "rsp" | "rbp" | "rip" | "sp" | "fp" | "lr" | "pc" | "flags" | "nzcv" => {
                let s = key.to_string();
                self.renames.insert(key.to_string(), s.clone());
                return s;
            }
            // Lifter temps (offset namespace, displayed as `tN`)
            s if s.starts_with('t') && s[1..].chars().all(|c| c.is_ascii_digit()) => {
                let n = format!("var_{}", self.next_var);
                self.next_var += 1;
                n
            }
            // Any other register name (rbx, r10..r15, the unmapped 32/16/8-bit
            // halves, ARM x6+, etc.) becomes a fresh scratch local.
            s if is_known_register_name(s) => {
                let n = format!("var_{}", self.next_var);
                self.next_var += 1;
                n
            }
            // Anything we don't recognize (already-renamed names, function
            // names appearing as Var, globals, etc.) — keep as-is.
            _ => return original.to_string(),
        };

        self.renames.insert(key.to_string(), new_name.clone());
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

fn scan_for_x86_32(stmt: &Stmt, renamer: &mut VarRenamer) {
    match stmt {
        Stmt::Assign(lhs, rhs) => {
            scan_expr_for_x86_32(lhs, renamer);
            scan_expr_for_x86_32(rhs, renamer);
        }
        Stmt::ExprStmt(e) => scan_expr_for_x86_32(e, renamer),
        Stmt::Return(Some(e)) => scan_expr_for_x86_32(e, renamer),
        Stmt::If { cond, then_body, else_body } => {
            scan_expr_for_x86_32(cond, renamer);
            for s in then_body { scan_for_x86_32(s, renamer); }
            for s in else_body { scan_for_x86_32(s, renamer); }
        }
        Stmt::While { cond, body } => {
            scan_expr_for_x86_32(cond, renamer);
            for s in body { scan_for_x86_32(s, renamer); }
        }
        Stmt::Loop { body } => {
            for s in body { scan_for_x86_32(s, renamer); }
        }
        _ => {}
    }
}

fn scan_expr_for_x86_32(expr: &Expr, renamer: &mut VarRenamer) {
    match expr {
        Expr::Var(name) => renamer.note_register_seen(name),
        Expr::Binary(_, a, b) => {
            scan_expr_for_x86_32(a, renamer);
            scan_expr_for_x86_32(b, renamer);
        }
        Expr::Unary(_, e) | Expr::Deref(e, _) | Expr::Cast(_, e) | Expr::AddrOf(e) => {
            scan_expr_for_x86_32(e, renamer);
        }
        Expr::Call(f, args) => {
            scan_expr_for_x86_32(f, renamer);
            for a in args { scan_expr_for_x86_32(a, renamer); }
        }
        Expr::Index(b, i) => { scan_expr_for_x86_32(b, renamer); scan_expr_for_x86_32(i, renamer); }
        Expr::Member(e, _) => scan_expr_for_x86_32(e, renamer),
        Expr::Ternary(c, a, b) => {
            scan_expr_for_x86_32(c, renamer);
            scan_expr_for_x86_32(a, renamer);
            scan_expr_for_x86_32(b, renamer);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::CType;

    fn rename(stmts: Vec<Stmt>) -> Vec<Stmt> {
        rename_variables(stmts, &HashMap::new())
    }

    fn assign(name: &str, value: Expr) -> Stmt {
        Stmt::Assign(Expr::Var(name.into()), value)
    }

    fn intlit(v: u64) -> Expr {
        Expr::IntLit(v, CType::UInt32)
    }

    #[test]
    fn x86_32_mode_routes_gprs_to_var_n() {
        // ecx and edx in the same function: both should become var_N, NOT argN.
        let stmts = vec![
            assign("ecx", intlit(1)),
            assign("edx", intlit(2)),
            assign("eax", intlit(3)),
        ];
        let renamed = rename(stmts);
        match &renamed[0] {
            Stmt::Assign(Expr::Var(name), _) => assert!(name.starts_with("var_"), "ecx -> {name}"),
            _ => panic!(),
        }
        match &renamed[1] {
            Stmt::Assign(Expr::Var(name), _) => assert!(name.starts_with("var_"), "edx -> {name}"),
            _ => panic!(),
        }
        // eax always becomes "result"
        assert!(matches!(&renamed[2], Stmt::Assign(Expr::Var(n), _) if n == "result"));
    }

    #[test]
    fn ecx_and_rcx_canonicalize_to_same_name() {
        // If both `ecx` and `rcx` appear (mixed-width access on x86-64), they
        // refer to the same hardware register and must rename to one variable.
        let stmts = vec![
            assign("rcx", intlit(0)),
            assign("ecx", intlit(1)),
        ];
        let renamed = rename(stmts);
        let n0 = match &renamed[0] {
            Stmt::Assign(Expr::Var(n), _) => n.clone(),
            _ => panic!(),
        };
        let n1 = match &renamed[1] {
            Stmt::Assign(Expr::Var(n), _) => n.clone(),
            _ => panic!(),
        };
        assert_eq!(n0, n1, "rcx and ecx must canonicalize to the same name");
    }

    #[test]
    fn x86_64_mode_keeps_argn_mapping() {
        // No 32-bit names → assume x86-64 SysV / ARM64; rdi/rsi/rdx → arg0/1/2
        let stmts = vec![
            assign("rdi", intlit(1)),
            assign("rsi", intlit(2)),
            assign("rdx", intlit(3)),
        ];
        let renamed = rename(stmts);
        let names: Vec<String> = renamed
            .iter()
            .map(|s| match s {
                Stmt::Assign(Expr::Var(n), _) => n.clone(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(names, vec!["arg0", "arg1", "arg2"]);
    }

    #[test]
    fn rsp_rbp_kept_visible() {
        // Stack/frame pointers should not be renamed away — they have
        // semantic meaning we haven't yet eliminated.
        let stmts = vec![assign("rsp", intlit(0)), assign("rbp", intlit(0))];
        let renamed = rename(stmts);
        assert!(matches!(&renamed[0], Stmt::Assign(Expr::Var(n), _) if n == "rsp"));
        assert!(matches!(&renamed[1], Stmt::Assign(Expr::Var(n), _) if n == "rbp"));
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
