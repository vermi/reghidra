/// C-like expression AST node.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A variable reference: "var_0", "arg0", "rax"
    Var(String),
    /// An integer literal
    IntLit(u64, CType),
    /// A string literal reference
    StringLit(String),
    /// Unary operation: !x, -x, ~x, *x, &x
    Unary(UnaryOp, Box<Expr>),
    /// Binary operation: a + b, a == b, etc.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// Function call: func(args...)
    Call(Box<Expr>, Vec<Expr>),
    /// Array/pointer index: base[index]
    Index(Box<Expr>, Box<Expr>),
    /// Member access: expr.field
    Member(Box<Expr>, String),
    /// Cast: (type)expr
    Cast(CType, Box<Expr>),
    /// Dereference: *(type*)addr
    Deref(Box<Expr>, CType),
    /// Address-of: &expr
    AddrOf(Box<Expr>),
    /// Ternary: cond ? a : b
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
pub enum UnaryOp {
    Neg,       // -x
    BitNot,    // ~x
    LogNot,    // !x
}

#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    BitAnd, BitOr, BitXor,
    Shl, Shr,
    Eq, Ne,
    Lt, Le, Gt, Ge,
    LogAnd, LogOr,
}

/// C-like statement AST node.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// Assignment: lhs = rhs;
    Assign(Expr, Expr),
    /// Expression statement: expr;
    ExprStmt(Expr),
    /// Return statement: return expr;
    Return(Option<Expr>),
    /// If statement: if (cond) { then } else { else }
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    /// While loop: while (cond) { body }
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    /// Infinite loop: for(;;) { body } or loop { body }
    Loop {
        body: Vec<Stmt>,
    },
    /// Break statement
    Break,
    /// Continue statement
    Continue,
    /// Goto (fallback for unstructured flow)
    Goto(u64),
    /// Label
    Label(u64),
    /// Block comment / annotation
    Comment(String),
    /// Variable declaration: type name = init;
    VarDecl {
        name: String,
        ctype: CType,
        init: Option<Expr>,
    },
    /// Source address marker (used to track which block produced this code).
    SourceAddr(u64),
}

/// Simple C type representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CType {
    Void,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Pointer(Box<CType>),
    /// Named type from the bundled archives (e.g. `HANDLE`, `DWORD`,
    /// `LPCSTR`, or `size_t`). The name is what gets rendered in the
    /// decompile output verbatim — consumers that need to know the
    /// underlying width should resolve the name via the archive's
    /// `types` map on demand rather than carrying the expansion here.
    Named(String),
    /// Unknown type with a byte size
    Unknown(u8),
}

impl CType {
    /// Infer a C type from a varnode size.
    pub fn from_size(size: u8, signed: bool) -> Self {
        match (size, signed) {
            (1, true) => CType::Int8,
            (1, false) => CType::UInt8,
            (2, true) => CType::Int16,
            (2, false) => CType::UInt16,
            (4, true) => CType::Int32,
            (4, false) => CType::UInt32,
            (8, true) => CType::Int64,
            (8, false) => CType::UInt64,
            _ => CType::Unknown(size),
        }
    }

    pub fn size(&self) -> u8 {
        match self {
            CType::Void => 0,
            CType::Int8 | CType::UInt8 => 1,
            CType::Int16 | CType::UInt16 => 2,
            CType::Int32 | CType::UInt32 => 4,
            CType::Int64 | CType::UInt64 | CType::Pointer(_) => 8,
            // Named types fall through to 0 because the decompile
            // emit layer doesn't use the width — it just prints the
            // name. Callers that need an actual size for layout
            // should resolve the name via the archive's `types` map.
            CType::Named(_) => 0,
            CType::Unknown(s) => *s,
        }
    }
}

/// Parse a free-form user-supplied C type string into a [`CType`].
///
/// Intended for the "Set Type" context-menu popup, where the user
/// types a type name like `HANDLE`, `uint32_t`, or `char*` into a
/// plain text box. The parser is deliberately permissive:
///
/// - Whitespace is trimmed and `const` / `volatile` / `restrict`
///   qualifiers are stripped — they're display noise as far as the
///   decompile output is concerned.
/// - `struct ` / `union ` / `enum ` tag prefixes are stripped so
///   `struct FILE` and `FILE` map to the same type.
/// - Trailing `*`s become `CType::Pointer` wrappings (so `char**`
///   is two levels of pointer).
/// - Recognized primitive names (`void`, `int`, `uint32_t`,
///   `int64_t`, `size_t`, `float`, `double`, `bool`, and the
///   common Windows aliases `BYTE`/`WORD`/`DWORD`/`QWORD`) resolve
///   to the matching [`CType`] variant.
/// - Anything else becomes `CType::Named(base)`, which the emit
///   layer just prints verbatim. This is the fallback for named
///   types the user expects the archive to resolve (`HANDLE`,
///   `LPCSTR`, `PROCESS_INFORMATION`, etc.).
///
/// Returns `None` for empty input (the caller should treat that as
/// "clear the override" rather than "set the empty type"), or for
/// input that ended up completely empty after qualifier stripping.
pub fn parse_user_ctype(raw: &str) -> Option<CType> {
    let mut s = raw.trim().to_string();
    if s.is_empty() {
        return None;
    }
    for q in ["const ", "volatile ", "restrict "] {
        while let Some(idx) = s.find(q) {
            s.replace_range(idx..idx + q.len(), "");
        }
    }
    for tag in ["struct ", "union ", "enum "] {
        while let Some(idx) = s.find(tag) {
            s.replace_range(idx..idx + tag.len(), "");
        }
    }
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Count trailing `*`s for pointer depth. Allow whitespace between
    // the base type and the first `*` (`char *` is the same as `char*`).
    let trimmed = s.trim_end_matches(|c: char| c == '*' || c.is_whitespace());
    let ptr_depth = s[trimmed.len()..].chars().filter(|c| *c == '*').count();
    let base = trimmed.trim();
    if base.is_empty() && ptr_depth == 0 {
        return None;
    }

    let mut inner = match base {
        "void" => CType::Void,
        "bool" | "_Bool" => CType::Unknown(1), // no Bool variant; treat as 1-byte
        "char" | "signed char" => CType::Int8,
        "unsigned char" | "BYTE" | "byte" => CType::UInt8,
        "int8_t" => CType::Int8,
        "uint8_t" => CType::UInt8,
        "short" | "short int" | "signed short" | "int16_t" => CType::Int16,
        "unsigned short" | "WORD" | "uint16_t" => CType::UInt16,
        "int" | "signed int" | "long" | "signed long" | "int32_t" => CType::Int32,
        "unsigned" | "unsigned int" | "unsigned long" | "DWORD" | "uint32_t" => CType::UInt32,
        "long long" | "signed long long" | "__int64" | "int64_t" => CType::Int64,
        "unsigned long long" | "QWORD" | "__uint64" | "uint64_t" | "size_t" | "SIZE_T" => {
            CType::UInt64
        }
        "float" => CType::Unknown(4),
        "double" | "long double" => CType::Unknown(8),
        "" => {
            // All `*`s, no base — treat as `void*`.
            CType::Void
        }
        other => CType::Named(other.to_string()),
    };
    for _ in 0..ptr_depth {
        inner = CType::Pointer(Box::new(inner));
    }
    Some(inner)
}

impl std::fmt::Display for CType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CType::Void => write!(f, "void"),
            CType::Int8 => write!(f, "int8_t"),
            CType::UInt8 => write!(f, "uint8_t"),
            CType::Int16 => write!(f, "int16_t"),
            CType::UInt16 => write!(f, "uint16_t"),
            CType::Int32 => write!(f, "int32_t"),
            CType::UInt32 => write!(f, "uint32_t"),
            CType::Int64 => write!(f, "int64_t"),
            CType::UInt64 => write!(f, "uint64_t"),
            CType::Pointer(inner) => write!(f, "{inner}*"),
            CType::Named(name) => write!(f, "{name}"),
            CType::Unknown(s) => write!(f, "unk{}", s * 8),
        }
    }
}

impl std::fmt::Display for BinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinOp::Add => write!(f, "+"),
            BinOp::Sub => write!(f, "-"),
            BinOp::Mul => write!(f, "*"),
            BinOp::Div => write!(f, "/"),
            BinOp::Mod => write!(f, "%"),
            BinOp::BitAnd => write!(f, "&"),
            BinOp::BitOr => write!(f, "|"),
            BinOp::BitXor => write!(f, "^"),
            BinOp::Shl => write!(f, "<<"),
            BinOp::Shr => write!(f, ">>"),
            BinOp::Eq => write!(f, "=="),
            BinOp::Ne => write!(f, "!="),
            BinOp::Lt => write!(f, "<"),
            BinOp::Le => write!(f, "<="),
            BinOp::Gt => write!(f, ">"),
            BinOp::Ge => write!(f, ">="),
            BinOp::LogAnd => write!(f, "&&"),
            BinOp::LogOr => write!(f, "||"),
        }
    }
}

impl std::fmt::Display for UnaryOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOp::Neg => write!(f, "-"),
            UnaryOp::BitNot => write!(f, "~"),
            UnaryOp::LogNot => write!(f, "!"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_ctype_primitives() {
        assert!(matches!(parse_user_ctype("void"), Some(CType::Void)));
        assert!(matches!(parse_user_ctype("int"), Some(CType::Int32)));
        assert!(matches!(parse_user_ctype("uint32_t"), Some(CType::UInt32)));
        assert!(matches!(parse_user_ctype("int64_t"), Some(CType::Int64)));
        assert!(matches!(parse_user_ctype("size_t"), Some(CType::UInt64)));
        assert!(matches!(parse_user_ctype("DWORD"), Some(CType::UInt32)));
    }

    #[test]
    fn parse_user_ctype_named_fallback() {
        match parse_user_ctype("HANDLE") {
            Some(CType::Named(n)) => assert_eq!(n, "HANDLE"),
            other => panic!("expected Named(HANDLE), got {other:?}"),
        }
        match parse_user_ctype("PROCESS_INFORMATION") {
            Some(CType::Named(n)) => assert_eq!(n, "PROCESS_INFORMATION"),
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn parse_user_ctype_pointers() {
        // char* → Pointer(Int8)
        match parse_user_ctype("char*") {
            Some(CType::Pointer(inner)) => assert!(matches!(*inner, CType::Int8)),
            other => panic!("got {other:?}"),
        }
        // HANDLE* → Pointer(Named(HANDLE))
        match parse_user_ctype("HANDLE*") {
            Some(CType::Pointer(inner)) => {
                assert!(matches!(*inner, CType::Named(ref n) if n == "HANDLE"))
            }
            other => panic!("got {other:?}"),
        }
        // char** → Pointer(Pointer(Int8))
        match parse_user_ctype("char**") {
            Some(CType::Pointer(inner)) => match *inner {
                CType::Pointer(i2) => assert!(matches!(*i2, CType::Int8)),
                _ => panic!("expected nested Pointer"),
            },
            _ => panic!("expected Pointer"),
        }
    }

    #[test]
    fn parse_user_ctype_qualifier_stripping() {
        // `const char*` should parse as if `const` weren't there.
        match parse_user_ctype("const char*") {
            Some(CType::Pointer(inner)) => assert!(matches!(*inner, CType::Int8)),
            other => panic!("got {other:?}"),
        }
        // `struct FILE` → Named("FILE")
        match parse_user_ctype("struct FILE") {
            Some(CType::Named(n)) => assert_eq!(n, "FILE"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn parse_user_ctype_whitespace_and_empty() {
        assert!(parse_user_ctype("").is_none());
        assert!(parse_user_ctype("   ").is_none());
        assert!(matches!(parse_user_ctype("  int  "), Some(CType::Int32)));
        // `char *` (space before `*`) should still be Pointer(Int8).
        match parse_user_ctype("char *") {
            Some(CType::Pointer(inner)) => assert!(matches!(*inner, CType::Int8)),
            other => panic!("got {other:?}"),
        }
    }
}
