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
            CType::Unknown(s) => *s,
        }
    }
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
