pub mod analysis;
pub mod arch;
pub mod binary;
pub mod demangle;
pub mod disasm;
pub mod error;
pub mod project;

pub use analysis::cfg::{BasicBlock, CfgEdge, ControlFlowGraph, EdgeKind};
pub use analysis::functions::{Function, FunctionSource};
pub use analysis::xrefs::{XRef, XRefDatabase, XRefKind};
pub use analysis::flirt::FlirtDatabase;
pub use analysis::AnalysisResults;
pub use arch::Architecture;
pub use binary::{sanitize_to_name, BinaryInfo, DetectedString, LoadedBinary, Section, Symbol, SymbolKind};
pub use disasm::{DisassembledInstruction, Disassembler};
pub use error::CoreError;
pub use project::{Project, Session};
pub use reghidra_decompile::AnnotatedLine;

/// Re-export of the decompile-layer AST module so GUI / CLI consumers
/// can call `parse_user_ctype` and pattern-match `CType` without
/// adding a direct `reghidra-decompile` dependency.
pub mod ast {
    pub use reghidra_decompile::ast::{parse_user_ctype, CType};
}
