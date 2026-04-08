use crate::analysis::bundled_sigs;
use crate::analysis::flirt::FlirtDatabase;
use crate::analysis::AnalysisResults;
use crate::binary::LoadedBinary;
use crate::disasm::{DisassembledInstruction, Disassembler};
use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A reghidra project: a loaded binary with its analysis results.
pub struct Project {
    pub binary: LoadedBinary,
    pub instructions: Vec<DisassembledInstruction>,
    pub analysis: AnalysisResults,
    pub comments: HashMap<u64, String>,
    pub renamed_functions: HashMap<u64, String>,
    /// User-renamed labels (CFG block addresses → display name).
    pub label_names: HashMap<u64, String>,
    /// User-renamed local variables, keyed by (function entry, displayed name).
    /// The "displayed name" is the post-heuristic name (e.g. "arg0", "var_1").
    pub variable_names: HashMap<(u64, String), String>,
    pub bookmarks: Vec<u64>,
    /// Bundled signature databases (auto-loaded on open).
    pub bundled_dbs: Vec<FlirtDatabase>,
    /// User-loaded signature databases (via File > Load Signatures).
    pub user_dbs: Vec<FlirtDatabase>,
    pub sig_status: Option<String>,
}

impl Project {
    /// Open a binary file, parse, disassemble, and analyze it.
    /// Automatically loads and applies bundled FLIRT signatures matching the
    /// binary's format and architecture.
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let binary = LoadedBinary::load(path)?;
        let disassembler = Disassembler::new(binary.info.architecture)?;
        let instructions = disassembler.disassemble_binary(&binary)?;

        // Load bundled signatures for this binary's format + architecture
        let (bundled_dbs, bundled_status) = bundled_sigs::load_bundled_signatures(
            binary.info.format,
            binary.info.architecture,
        );

        // Run analysis with bundled sigs applied
        let db_refs: Vec<&FlirtDatabase> = bundled_dbs.iter().collect();
        let analysis = AnalysisResults::analyze_with_signatures(
            &binary,
            &instructions,
            &db_refs,
        );

        let match_count = analysis
            .functions
            .iter()
            .filter(|f| f.source == crate::analysis::functions::FunctionSource::Signature)
            .count();

        let sig_status = if bundled_dbs.is_empty() {
            None
        } else {
            Some(format!("{bundled_status}, {match_count} matched"))
        };

        Ok(Self {
            binary,
            instructions,
            analysis,
            comments: HashMap::new(),
            renamed_functions: HashMap::new(),
            label_names: HashMap::new(),
            variable_names: HashMap::new(),
            bookmarks: Vec::new(),
            bundled_dbs,
            user_dbs: Vec::new(),
            sig_status,
        })
    }

    /// Load a user-provided FLIRT .sig file and re-run analysis with all signatures.
    /// Returns the number of functions matched by this new database.
    pub fn load_signatures(&mut self, path: &Path) -> Result<usize, CoreError> {
        let db = FlirtDatabase::load(path)?;
        let lib_name = db.header.name.clone();
        let sig_count = db.signature_count;

        self.user_dbs.push(db);

        // Re-run analysis with all signature databases (bundled + user)
        let all_db_refs: Vec<&FlirtDatabase> = self
            .bundled_dbs
            .iter()
            .chain(self.user_dbs.iter())
            .collect();

        self.analysis = AnalysisResults::analyze_with_signatures(
            &self.binary,
            &self.instructions,
            &all_db_refs,
        );

        let match_count = self
            .analysis
            .functions
            .iter()
            .filter(|f| f.source == crate::analysis::functions::FunctionSource::Signature)
            .count();

        self.sig_status = Some(format!(
            "{sig_count} sigs loaded ({lib_name}), {match_count} total matched"
        ));

        Ok(match_count)
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

    /// Rename a label (CFG block address). Empty name resets to default.
    pub fn rename_label(&mut self, address: u64, name: String) {
        if name.is_empty() {
            self.label_names.remove(&address);
        } else {
            self.label_names.insert(address, name);
        }
    }

    /// Rename a local variable inside a function. Keyed by the displayed name
    /// produced by the auto-naming pass (e.g. "arg0", "var_1"). Empty name
    /// resets to default.
    pub fn rename_variable(&mut self, func_entry: u64, displayed_name: String, new_name: String) {
        let key = (func_entry, displayed_name);
        if new_name.is_empty() {
            self.variable_names.remove(&key);
        } else {
            self.variable_names.insert(key, new_name);
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
        // Expose imports by IAT-slot address so that `call [IAT]` (lifted as
        // a direct Call whose target is the IAT slot) displays the import name.
        for (addr, name) in &self.binary.import_addr_map {
            function_names.entry(*addr).or_insert_with(|| name.clone());
        }

        let string_literals: HashMap<u64, String> = self
            .binary
            .strings
            .iter()
            .map(|s| (s.address, s.value.clone()))
            .collect();

        let cfg = self.analysis.cfgs.get(&entry)?;
        let var_names_for_func: HashMap<String, String> = self
            .variable_names
            .iter()
            .filter_map(|((fe, displayed), user)| {
                if *fe == entry {
                    Some((displayed.clone(), user.clone()))
                } else {
                    None
                }
            })
            .collect();
        let ctx = reghidra_decompile::DecompileContext {
            function_names,
            string_literals,
            successors: cfg.successors.clone(),
            predecessors: cfg.predecessors.clone(),
            label_names: self.label_names.clone(),
            variable_names: var_names_for_func,
        };

        Some(reghidra_decompile::decompile(ir, &ctx))
    }

    /// Decompile the function at the given entry address, returning annotated
    /// lines and the set of post-rename variable names that appear (used by
    /// the GUI to tokenize variable references for right-click rename).
    pub fn decompile_annotated(
        &self,
        entry: u64,
    ) -> Option<(Vec<reghidra_decompile::AnnotatedLine>, Vec<String>)> {
        let ir = self.analysis.ir_for(entry)?;

        let mut function_names = HashMap::new();
        for func in &self.analysis.functions {
            let name = self
                .renamed_functions
                .get(&func.entry_address)
                .cloned()
                .unwrap_or_else(|| func.name.clone());
            function_names.insert(func.entry_address, name);
        }
        // Expose imports by IAT-slot address so that `call [IAT]` (lifted as
        // a direct Call whose target is the IAT slot) displays the import name.
        for (addr, name) in &self.binary.import_addr_map {
            function_names.entry(*addr).or_insert_with(|| name.clone());
        }

        let string_literals: HashMap<u64, String> = self
            .binary
            .strings
            .iter()
            .map(|s| (s.address, s.value.clone()))
            .collect();

        let cfg = self.analysis.cfgs.get(&entry)?;
        let var_names_for_func: HashMap<String, String> = self
            .variable_names
            .iter()
            .filter_map(|((fe, displayed), user)| {
                if *fe == entry {
                    Some((displayed.clone(), user.clone()))
                } else {
                    None
                }
            })
            .collect();
        let ctx = reghidra_decompile::DecompileContext {
            function_names,
            string_literals,
            successors: cfg.successors.clone(),
            predecessors: cfg.predecessors.clone(),
            label_names: self.label_names.clone(),
            variable_names: var_names_for_func,
        };

        Some(reghidra_decompile::decompile_annotated(ir, &ctx))
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

    /// Save user annotations to a session file.
    pub fn save_session(&self, path: &Path) -> Result<(), CoreError> {
        let session = Session {
            version: 1,
            binary_path: self.binary.info.path.clone(),
            comments: self.comments.clone(),
            renamed_functions: self.renamed_functions.clone(),
            bookmarks: self.bookmarks.clone(),
            label_names: self.label_names.clone(),
            variable_names: self
                .variable_names
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        let json = serde_json::to_string_pretty(&session)
            .map_err(|e| CoreError::Other(format!("Failed to serialize session: {e}")))?;
        std::fs::write(path, json)
            .map_err(|e| CoreError::Other(format!("Failed to write session file: {e}")))?;
        Ok(())
    }

    /// Load a session file and apply saved annotations to this project.
    pub fn load_session(&mut self, path: &Path) -> Result<(), CoreError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| CoreError::Other(format!("Failed to read session file: {e}")))?;
        let session: Session = serde_json::from_str(&data)
            .map_err(|e| CoreError::Other(format!("Failed to parse session file: {e}")))?;
        self.comments = session.comments;
        self.renamed_functions = session.renamed_functions;
        self.bookmarks = session.bookmarks;
        self.label_names = session.label_names;
        self.variable_names = session.variable_names.into_iter().collect();
        Ok(())
    }

    /// Open a binary and restore a session file's annotations.
    pub fn open_with_session(session_path: &Path) -> Result<Self, CoreError> {
        let data = std::fs::read_to_string(session_path)
            .map_err(|e| CoreError::Other(format!("Failed to read session file: {e}")))?;
        let session: Session = serde_json::from_str(&data)
            .map_err(|e| CoreError::Other(format!("Failed to parse session file: {e}")))?;

        let mut project = Self::open(&session.binary_path)?;
        project.comments = session.comments;
        project.renamed_functions = session.renamed_functions;
        project.bookmarks = session.bookmarks;
        project.label_names = session.label_names;
        project.variable_names = session.variable_names.into_iter().collect();
        Ok(project)
    }
}

/// Serializable session state — stores user annotations alongside the binary path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub binary_path: PathBuf,
    pub comments: HashMap<u64, String>,
    pub renamed_functions: HashMap<u64, String>,
    pub bookmarks: Vec<u64>,
    #[serde(default)]
    pub label_names: HashMap<u64, String>,
    /// Stored as Vec because tuple keys aren't supported in JSON object keys.
    #[serde(default)]
    pub variable_names: Vec<((u64, String), String)>,
}
