pub mod cfg;
pub mod functions;
pub mod lifting;
pub mod naming;
pub mod xrefs;

use crate::binary::LoadedBinary;
use crate::disasm::DisassembledInstruction;
use cfg::ControlFlowGraph;
use functions::Function;
use reghidra_ir::IrFunction;
use xrefs::XRefDatabase;

/// Results of automated analysis on a binary.
pub struct AnalysisResults {
    pub functions: Vec<Function>,
    pub xrefs: XRefDatabase,
    pub cfgs: std::collections::HashMap<u64, ControlFlowGraph>,
    pub ir_functions: std::collections::HashMap<u64, IrFunction>,
}

impl AnalysisResults {
    /// Run all analysis passes on the binary.
    pub fn analyze(
        binary: &LoadedBinary,
        instructions: &[DisassembledInstruction],
    ) -> Self {
        let mut functions = functions::detect_functions(binary, instructions);
        let xrefs = xrefs::build_xrefs(binary, instructions);

        // Auto-name functions using heuristics (thunks, wrappers, string-refs, API patterns)
        naming::auto_name_functions(&mut functions, &xrefs, &binary.strings, instructions);

        let cfgs: std::collections::HashMap<u64, ControlFlowGraph> = functions
            .iter()
            .filter_map(|f| {
                let cfg = cfg::build_cfg(f, instructions);
                Some((f.entry_address, cfg))
            })
            .collect();

        // Lift functions to IR
        let ir_functions = lifting::lift_all(
            binary.info.architecture,
            &functions,
            &cfgs,
            instructions,
        );

        Self {
            functions,
            xrefs,
            cfgs,
            ir_functions,
        }
    }

    /// Get a function by its entry address.
    pub fn function_at(&self, addr: u64) -> Option<&Function> {
        self.functions.iter().find(|f| f.entry_address == addr)
    }

    /// Get the function containing a given address.
    pub fn function_containing(&self, addr: u64) -> Option<&Function> {
        self.functions.iter().find(|f| {
            addr >= f.entry_address && addr < f.entry_address + f.size
        })
    }

    /// Get the lifted IR for a function.
    pub fn ir_for(&self, entry: u64) -> Option<&IrFunction> {
        self.ir_functions.get(&entry)
    }
}
