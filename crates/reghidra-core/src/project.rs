use crate::analysis::AnalysisResults;
use crate::binary::LoadedBinary;
use crate::disasm::{DisassembledInstruction, Disassembler};
use crate::error::CoreError;
use std::collections::HashMap;
use std::path::Path;

/// A reghidra project: a loaded binary with its analysis results.
pub struct Project {
    pub binary: LoadedBinary,
    pub instructions: Vec<DisassembledInstruction>,
    pub analysis: AnalysisResults,
    pub comments: HashMap<u64, String>,
    pub renamed_functions: HashMap<u64, String>,
    pub bookmarks: Vec<u64>,
}

impl Project {
    /// Open a binary file, parse, disassemble, and analyze it.
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let binary = LoadedBinary::load(path)?;
        let disassembler = Disassembler::new(binary.info.architecture)?;
        let instructions = disassembler.disassemble_binary(&binary)?;
        let analysis = AnalysisResults::analyze(&binary, &instructions);

        Ok(Self {
            binary,
            instructions,
            analysis,
            comments: HashMap::new(),
            renamed_functions: HashMap::new(),
            bookmarks: Vec::new(),
        })
    }

    /// Get the display name for a function at the given address.
    pub fn function_name(&self, address: u64) -> Option<&str> {
        if let Some(name) = self.renamed_functions.get(&address) {
            return Some(name);
        }
        self.analysis
            .function_at(address)
            .map(|f| f.name.as_str())
    }

    /// Get the symbol at or near an address.
    pub fn symbol_at(&self, address: u64) -> Option<&crate::binary::Symbol> {
        self.binary.symbols.iter().find(|s| {
            address >= s.address && (s.size == 0 || address < s.address + s.size)
        })
    }

    /// Set a user comment at an address.
    pub fn set_comment(&mut self, address: u64, comment: String) {
        if comment.is_empty() {
            self.comments.remove(&address);
        } else {
            self.comments.insert(address, comment);
        }
    }

    /// Rename a function at an address.
    pub fn rename_function(&mut self, address: u64, name: String) {
        if name.is_empty() {
            self.renamed_functions.remove(&address);
        } else {
            self.renamed_functions.insert(address, name);
        }
    }

    /// Decompile the function at the given entry address.
    pub fn decompile(&self, entry: u64) -> Option<String> {
        let ir = self.analysis.ir_for(entry)?;

        // Build decompile context
        let mut function_names = HashMap::new();
        for func in &self.analysis.functions {
            let name = self
                .renamed_functions
                .get(&func.entry_address)
                .cloned()
                .unwrap_or_else(|| func.name.clone());
            function_names.insert(func.entry_address, name);
        }

        let string_literals: HashMap<u64, String> = self
            .binary
            .strings
            .iter()
            .map(|s| (s.address, s.value.clone()))
            .collect();

        let cfg = self.analysis.cfgs.get(&entry)?;
        let ctx = reghidra_decompile::DecompileContext {
            function_names,
            string_literals,
            successors: cfg.successors.clone(),
            predecessors: cfg.predecessors.clone(),
        };

        Some(reghidra_decompile::decompile(ir, &ctx))
    }

    /// Get all detected functions with display names.
    pub fn functions(&self) -> Vec<(u64, String)> {
        let mut funcs: Vec<(u64, String)> = self
            .analysis
            .functions
            .iter()
            .filter(|f| f.entry_address != 0)
            .map(|f| {
                let name = self
                    .renamed_functions
                    .get(&f.entry_address)
                    .cloned()
                    .unwrap_or_else(|| f.name.clone());
                (f.entry_address, name)
            })
            .collect();
        funcs.sort_by_key(|(addr, _)| *addr);
        funcs.dedup_by_key(|(addr, _)| *addr);
        funcs
    }
}
