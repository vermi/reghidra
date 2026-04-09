use crate::analysis::bundled_sigs;
use crate::analysis::flirt::FlirtDatabase;
use crate::analysis::AnalysisResults;
use crate::arch::Architecture;
use crate::binary::{BinaryFormat, BinaryInfo, LoadedBinary};
use crate::disasm::{DisassembledInstruction, Disassembler};
use crate::error::CoreError;
use reghidra_decompile::type_archive::{self, TypeArchive};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Archive stems to load for a given binary format and architecture. This
/// lives in `reghidra-core` rather than `reghidra-decompile::type_archive`
/// because it's the only place [`BinaryFormat`] and [`Architecture`] are
/// in scope — the decompile crate sits below core in the dep graph.
fn archive_stems_for(info: &BinaryInfo) -> Vec<&'static str> {
    match (info.format, info.architecture) {
        // PE precedence (first match wins on collision):
        //   1. windows-{arch}: Win32 API surface (windows-sys-sourced),
        //      ~20 k functions per arch
        //   2. ucrt:           MSVC CRT (libc-sourced from src/windows/),
        //      ~226 functions covering `_open`, `_close`, `_commit`,
        //      `_flushall`, `printf`, `fopen`, etc. — the canonical
        //      MSVC underscore-decorated CRT names that FLIRT picks up
        //      in statically linked MSVC binaries
        //   3. posix:          POSIX (libc-sourced from src/unix/),
        //      ~450 functions; lower-precedence catch-all for CRT
        //      functions whose Microsoft form aliases a POSIX name
        //      (`exit`, `abort`, `strlen`)
        // ucrt sits between Win32 and POSIX because it's the
        // authoritative source for MSVC-decorated CRT names; POSIX
        // remains as a fallback for the bare-name aliases.
        //
        // `rizin-windows` and `rizin-libc` (Phase 5c PR — Rizin SDB
        // import) come last so they only fill gaps left by the
        // authoritative binding-crate-sourced archives. Rizin's
        // SDB is a hand-curated GPLv3 reference covering ~5.4 k
        // Win32 functions across 35 headers (some not in
        // `windows-sys`'s default feature set) and ~530
        // POSIX/libc/linux/macos functions. First-archive-wins
        // ordering means a `CreateFileA` lookup still resolves
        // through `windows-x64` if present and only falls through
        // to `rizin-windows` for entries the binding crate didn't
        // expose.
        (BinaryFormat::Pe, Architecture::X86_64) => {
            vec!["windows-x64", "ucrt", "posix", "rizin-windows", "rizin-libc"]
        }
        (BinaryFormat::Pe, Architecture::X86_32) => {
            vec!["windows-x86", "ucrt", "posix", "rizin-windows", "rizin-libc"]
        }
        (BinaryFormat::Pe, Architecture::Arm64) => {
            vec!["windows-arm64", "ucrt", "posix", "rizin-windows", "rizin-libc"]
        }
        (BinaryFormat::Elf, _) => vec!["posix", "rizin-libc"],
        (BinaryFormat::MachO, _) => vec!["posix", "rizin-libc"],
        _ => vec![],
    }
}

/// Load all type archives matching a binary's format and architecture.
/// Missing archives are silently skipped — expected during early Phase 5c
/// PRs when the `types/` tree is empty or partial.
fn load_type_archives(info: &BinaryInfo) -> Vec<Arc<TypeArchive>> {
    archive_stems_for(info)
        .into_iter()
        .filter_map(type_archive::load_embedded)
        .collect()
}

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
    /// User-supplied type overrides for local variables, keyed identically
    /// to [`Self::variable_names`]. Values are free-form type strings
    /// (`"HANDLE"`, `"uint32_t"`, `"char*"`) parsed via
    /// `reghidra_decompile::ast::parse_user_ctype` at decompile time.
    /// Empty = no override (the slot shows whichever type the heuristic/
    /// archive/return-type passes inferred). Session-persisted alongside
    /// renames.
    pub variable_types: HashMap<(u64, String), String>,
    pub bookmarks: Vec<u64>,
    /// Bundled signature databases (auto-loaded on open).
    pub bundled_dbs: Vec<FlirtDatabase>,
    /// User-loaded signature databases (via File > Load Signatures).
    pub user_dbs: Vec<FlirtDatabase>,
    pub sig_status: Option<String>,
    /// Bundled type archives auto-selected by format+arch at open time.
    /// Currently unconsumed — Phase 5c PR 4 wires them into the decompile
    /// pipeline for arity capping, typed decls, and return-type propagation.
    /// Kept behind `Arc` because the decompile context clones references
    /// cheaply per-function.
    pub type_archives: Vec<Arc<TypeArchive>>,
    /// Per-database enable flags for the Loaded Data Sources panel.
    /// Parallel to [`Self::bundled_dbs`] / [`Self::user_dbs`] /
    /// [`Self::type_archives`]. Toggling recomputes the effective sets
    /// returned by [`Self::effective_flirt_db_refs`] and
    /// [`Self::effective_type_archives`]; FLIRT toggles also force a
    /// full re-analysis (rename application happens at analysis time,
    /// not decompile time). Not session-persisted in v1 — these are
    /// reset every project open.
    pub bundled_db_enabled: Vec<bool>,
    pub user_db_enabled: Vec<bool>,
    pub type_archive_enabled: Vec<bool>,
    /// Per-source hit counts on the *current* binary, computed against
    /// the *currently enabled* sources. A disabled source shows 0 even
    /// if it would otherwise resolve names — that surfaces the
    /// precedence chain ("disable windows-x64 and watch rizin-windows
    /// take over"). Recomputed by [`Self::recompute_hit_counts`] after
    /// every analysis run and after every enable toggle.
    pub bundled_db_hits: Vec<usize>,
    pub user_db_hits: Vec<usize>,
    pub type_archive_hits: Vec<usize>,
    /// Every embedded type archive stem the binary ships with, regardless
    /// of whether the format/arch heuristic auto-loaded it. Used by the
    /// Loaded Data Sources panel so the user can see (and opt into) the
    /// archives that weren't auto-selected — e.g. on a PE x86 binary,
    /// `windows-x64` and `windows-arm64` are listed but unchecked, and
    /// checking one lazy-loads it via [`Self::set_type_archive_loaded`].
    /// Sorted lexicographically for stable display.
    pub available_archive_stems: Vec<String>,
    /// Every embedded `.sig` file the binary ships with, regardless of
    /// whether the format/arch subdir match auto-loaded it. Same opt-in
    /// flow as [`Self::available_archive_stems`]. Grouped by `subdir` in
    /// the panel for the platform/arch tree view.
    pub available_bundled_sigs: Vec<bundled_sigs::AvailableSig>,
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

        // Load bundled type archives matching this binary's format+arch.
        // The `types/` tree may be empty or only partially populated during
        // early Phase 5c PRs; the loader tolerates that and returns an empty
        // vec. Nothing in the pipeline consumes these yet — they're wired
        // in by later PRs (arity capping, typed VarDecls, retype UI).
        let type_archives = load_type_archives(&binary.info);

        let bundled_db_enabled = vec![true; bundled_dbs.len()];
        let type_archive_enabled = vec![true; type_archives.len()];
        let bundled_db_hits = vec![0; bundled_dbs.len()];
        let type_archive_hits = vec![0; type_archives.len()];

        let available_archive_stems = type_archive::available_stems();
        let available_bundled_sigs = bundled_sigs::available_sigs();

        let mut project = Self {
            binary,
            instructions,
            analysis,
            comments: HashMap::new(),
            renamed_functions: HashMap::new(),
            label_names: HashMap::new(),
            variable_names: HashMap::new(),
            variable_types: HashMap::new(),
            bookmarks: Vec::new(),
            bundled_dbs,
            user_dbs: Vec::new(),
            sig_status,
            type_archives,
            bundled_db_enabled,
            user_db_enabled: Vec::new(),
            type_archive_enabled,
            bundled_db_hits,
            user_db_hits: Vec::new(),
            type_archive_hits,
            available_archive_stems,
            available_bundled_sigs,
        };
        project.recompute_hit_counts();
        Ok(project)
    }

    /// Load a user-provided FLIRT .sig file and re-run analysis with all signatures.
    /// Returns the number of functions matched by this new database.
    pub fn load_signatures(&mut self, path: &Path) -> Result<usize, CoreError> {
        let db = FlirtDatabase::load(path)?;
        let lib_name = db.header.name.clone();
        let sig_count = db.signature_count;

        self.user_dbs.push(db);
        self.user_db_enabled.push(true);
        self.user_db_hits.push(0);

        self.reanalyze_with_current_signatures();

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

    /// Re-run analysis using only currently-enabled FLIRT databases.
    /// Used by [`Self::load_signatures`] and the Loaded Data Sources
    /// panel toggles. Always followed by a hit-count recompute so the
    /// panel reflects the new state.
    fn reanalyze_with_current_signatures(&mut self) {
        let all_db_refs: Vec<&FlirtDatabase> = self.effective_flirt_db_refs();
        self.analysis = AnalysisResults::analyze_with_signatures(
            &self.binary,
            &self.instructions,
            &all_db_refs,
        );
        self.recompute_hit_counts();
    }

    /// Currently-enabled FLIRT databases as references, in
    /// bundled-then-user order. Used by re-analysis after toggles and
    /// by `load_signatures`. Order matters: the first match wins, so
    /// bundled IDA-precedence ordering is preserved.
    pub fn effective_flirt_db_refs(&self) -> Vec<&FlirtDatabase> {
        self.bundled_dbs
            .iter()
            .zip(self.bundled_db_enabled.iter())
            .filter_map(|(db, on)| on.then_some(db))
            .chain(
                self.user_dbs
                    .iter()
                    .zip(self.user_db_enabled.iter())
                    .filter_map(|(db, on)| on.then_some(db)),
            )
            .collect()
    }

    /// Currently-enabled type archives, in declared precedence order.
    /// Cloned cheaply since each archive is `Arc`-wrapped. Plumbed
    /// into [`reghidra_decompile::DecompileContext`] at decompile time
    /// instead of `self.type_archives` so that disabling an archive
    /// from the Loaded Data Sources panel takes effect on the next
    /// re-render without needing to rebuild the project.
    pub fn effective_type_archives(&self) -> Vec<Arc<TypeArchive>> {
        self.type_archives
            .iter()
            .zip(self.type_archive_enabled.iter())
            .filter(|(_, on)| **on)
            .map(|(a, _)| a.clone())
            .collect()
    }

    /// Toggle a bundled FLIRT database on/off. Triggers a full
    /// re-analysis because FLIRT renames are baked in at analysis time
    /// (`apply_signatures` mutates `Function::name` / `Function::source`).
    /// Caller is responsible for forcing any UI re-render that depends
    /// on function names.
    pub fn set_bundled_db_enabled(&mut self, idx: usize, enabled: bool) {
        if let Some(slot) = self.bundled_db_enabled.get_mut(idx) {
            if *slot == enabled {
                return;
            }
            *slot = enabled;
            self.reanalyze_with_current_signatures();
        }
    }

    /// Toggle a user-loaded FLIRT database on/off. See
    /// [`Self::set_bundled_db_enabled`].
    pub fn set_user_db_enabled(&mut self, idx: usize, enabled: bool) {
        if let Some(slot) = self.user_db_enabled.get_mut(idx) {
            if *slot == enabled {
                return;
            }
            *slot = enabled;
            self.reanalyze_with_current_signatures();
        }
    }

    /// Lazy-load an embedded type archive by stem (one of
    /// [`Self::available_archive_stems`]) and append it to
    /// [`Self::type_archives`] enabled. No-op if already loaded. Returns
    /// the index in `type_archives` (newly assigned or existing) so the
    /// caller can flip enable state.
    ///
    /// "Loaded but disabled" is the resting state when the user unchecks
    /// an entry — we keep the parsed archive in memory so re-checking
    /// is instant. Memory cost is bounded by the embedded `types/` tree
    /// (~25 MB total even if everything ends up loaded), well below
    /// what would justify a drop-and-reparse churn cycle.
    pub fn load_type_archive_by_stem(&mut self, stem: &str) -> Option<usize> {
        if let Some(idx) = self.type_archives.iter().position(|a| a.name == stem) {
            return Some(idx);
        }
        let archive = type_archive::load_embedded(stem)?;
        let idx = self.type_archives.len();
        self.type_archives.push(archive);
        self.type_archive_enabled.push(true);
        self.type_archive_hits.push(0);
        self.recompute_hit_counts();
        Some(idx)
    }

    /// Lazy-load an embedded FLIRT signature database by `(subdir, stem)`
    /// and append it to [`Self::bundled_dbs`] enabled. No-op if already
    /// loaded. Returns the new (or existing) index. Triggers a full
    /// re-analysis since FLIRT renames bake in at analysis time.
    ///
    /// Identity is `(subdir, stem)`, NOT just stem — the same stem can
    /// ship under multiple arch dirs (e.g. `VisualStudio2017` exists
    /// in `pe/x86/32`, `pe/arm/32`, `pe/arm/64`) and they must remain
    /// independently toggleable. The `source_path` encodes both as
    /// `bundled:<subdir>/<stem>` so the GUI's loaded-by-key map can
    /// recover both halves.
    pub fn load_bundled_sig(&mut self, subdir: &str, stem: &str) -> Option<usize> {
        let key = format!("bundled:{subdir}/{stem}");
        if let Some(idx) = self
            .bundled_dbs
            .iter()
            .position(|db| db.source_path.to_str() == Some(key.as_str()))
        {
            return Some(idx);
        }
        let bytes = bundled_sigs::embedded_sig_bytes(subdir, stem)?;
        let source_path = PathBuf::from(&key);
        match FlirtDatabase::parse(bytes, source_path) {
            Ok(db) => {
                // Insert at the FRONT of `bundled_dbs` so the newly
                // lazy-loaded sig gets first-match priority on the
                // next re-analyze pass. The user explicitly clicked
                // "enable" on this sig in the Loaded Data Sources
                // panel (or called `sources load-sig` via the CLI);
                // giving it priority over the auto-loaded set matches
                // intent and — combined with the longer-match-wins
                // fix in `apply_signatures` — means a lazy-loaded
                // legacy sig can actually claim its CRT thunks
                // instead of being blocked by a generic modern sig
                // that happened to match a short `jmp` pattern first.
                //
                // `bundled_db_enabled` and `bundled_db_hits` have
                // parallel indexing with `bundled_dbs`, so they get
                // the same insertion.
                self.bundled_dbs.insert(0, db);
                self.bundled_db_enabled.insert(0, true);
                self.bundled_db_hits.insert(0, 0);
                self.reanalyze_with_current_signatures();
                Some(0)
            }
            Err(e) => {
                log::warn!("Failed to lazy-load bundled sig '{stem}': {e}");
                None
            }
        }
    }

    /// Toggle a bundled type archive on/off. Does NOT re-run analysis
    /// because type archives are consumed at decompile time, not at
    /// analysis time — the next call to [`Self::decompile`] /
    /// [`Self::decompile_annotated`] picks up the new effective set
    /// via [`Self::effective_type_archives`]. The hit counts are
    /// recomputed inline so the panel reflects the new precedence
    /// chain immediately.
    pub fn set_type_archive_enabled(&mut self, idx: usize, enabled: bool) {
        if let Some(slot) = self.type_archive_enabled.get_mut(idx) {
            if *slot == enabled {
                return;
            }
            *slot = enabled;
            self.recompute_hit_counts();
        }
    }

    /// Build the menu of type names the user can pick when
    /// retyping a local. Returns a sorted, deduped vector of:
    ///
    /// - C primitive names (`void`, `int8_t`..`uint64_t`,
    ///   `char`, `int`, `size_t`, `bool`, `float`, `double`)
    /// - Every `TypeDef` key from each currently-enabled archive's
    ///   `types` map (struct/union/enum/typedef names)
    /// - A small static list of common Win32 / POSIX width aliases
    ///   that may not be present in the archive's `types` map
    ///   (`HANDLE`, `DWORD`, `BOOL`, `LPCSTR`, `BYTE`, `WORD`, etc.)
    ///
    /// The list is recomputed on each call. The cost is dominated
    /// by walking each archive's `types` map (low thousands of
    /// entries even on the largest archives) and is negligible
    /// against the rest of the popup-render path. Caching is left
    /// for a follow-up if profiling proves it warranted.
    pub fn known_type_names(&self) -> Vec<String> {
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // C primitives — match what `parse_user_ctype` can resolve
        // without going through the Named fallback.
        for p in [
            "void", "bool", "char", "int", "short", "long", "int8_t", "uint8_t", "int16_t",
            "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t", "size_t", "float",
            "double",
        ] {
            names.insert(p.to_string());
        }
        // Common width aliases that user retypes commonly produce
        // and that the assignment-compat predicate's built-in
        // fallback recognizes. Mirrors the tail branches of
        // `type_archive::ctype_size_bytes` and
        // `resolve_named_to_ctype` so the dropdown surfaces
        // every name those functions know about.
        for w in [
            "HANDLE", "BOOL", "BYTE", "WORD", "DWORD", "QWORD", "LPCSTR", "LPSTR",
            "LPCWSTR", "LPWSTR", "LPVOID", "PVOID", "HWND", "HMODULE", "HINSTANCE",
            "FILE", "wchar_t",
        ] {
            names.insert(w.to_string());
        }
        // Walk every loaded type archive (regardless of
        // enable-state — the user may pick a name that lives in a
        // currently-disabled archive, and the resulting Named
        // ctype will still render correctly even if the strip
        // pass can't resolve it). Iterating both enabled and
        // disabled keeps the picker stable across enable-toggles.
        for archive in &self.type_archives {
            for type_name in archive.types.keys() {
                // Filter out leaked debug-format names from older
                // walker runs (`Type::Never { ... }`). The same
                // defensive filter lives in `type_ref_to_ctype`.
                if type_name.starts_with("Type::") || type_name.contains('{') {
                    continue;
                }
                names.insert(type_name.clone());
            }
        }
        names.into_iter().collect()
    }

    /// Recompute per-source hit counts on the current binary.
    ///
    /// **FLIRT hits** are attributed via `Function::matched_signature_db`
    /// (set by `apply_signatures`) — a one-pass walk over
    /// `analysis.functions` filtered to those whose `matched_signature_db`
    /// is set, matching the lib name against each enabled db's
    /// `header.name`. Disabled dbs always show 0.
    ///
    /// **Type archive hits** mirror what the decompiler actually
    /// resolves at call sites, which is the union of:
    ///
    /// * names in `analysis.functions` — covers FLIRT-renamed CRT
    ///   stubs, symbol-table imports (ELF PLT), and any function
    ///   `resolve_import_functions` was able to rename in place;
    /// * names in `binary.import_addr_map` — covers PE x86/x64 IAT
    ///   imports whose IAT slot addresses don't coincide with any
    ///   `Function::entry_address` and so never get renamed onto an
    ///   `analysis.functions` entry. These are the bulk of Win32 API
    ///   resolutions on a typical PE binary; missing them was the
    ///   reason `windows-x64`/`windows-x86` panels appeared as zero
    ///   hits in the first cut.
    ///
    /// The two sources are deduplicated by name (via a `HashSet`) so a
    /// function that appears as both an analysis entry AND an import
    /// only counts once.
    ///
    /// The lookup uses
    /// [`reghidra_decompile::type_archive::which_archive_resolves`]
    /// over the *enabled* archive list so the count reflects the
    /// effective precedence chain — disabling a higher-precedence
    /// archive shifts hits to whatever resolves the same name next.
    pub fn recompute_hit_counts(&mut self) {
        let mut bundled_hits = vec![0usize; self.bundled_dbs.len()];
        let mut user_hits = vec![0usize; self.user_dbs.len()];
        let mut archive_hits = vec![0usize; self.type_archives.len()];

        // Pre-resolve which db slot owns each lib name; lookup tables
        // beat re-scanning the db lists per function and avoid the
        // self-borrow tangle of nested iter+find inside the loop.
        let bundled_lookup: HashMap<&str, usize> = self
            .bundled_dbs
            .iter()
            .enumerate()
            .filter(|(i, _)| self.bundled_db_enabled[*i])
            .map(|(i, db)| (db.header.name.as_str(), i))
            .collect();
        let user_lookup: HashMap<&str, usize> = self
            .user_dbs
            .iter()
            .enumerate()
            .filter(|(i, _)| self.user_db_enabled[*i])
            .map(|(i, db)| (db.header.name.as_str(), i))
            .collect();

        // FLIRT attribution: only walks analysis.functions because
        // FLIRT only ever matches functions that exist as analysis
        // entries (it operates on byte patterns at function entry
        // addresses).
        for func in &self.analysis.functions {
            if let Some(lib) = func.matched_signature_db.as_deref() {
                if let Some(&i) = bundled_lookup.get(lib) {
                    bundled_hits[i] += 1;
                } else if let Some(&i) = user_lookup.get(lib) {
                    user_hits[i] += 1;
                }
            }
        }

        // Type archive attribution: walk the deduplicated union of
        // analysis.functions names and import_addr_map values, which
        // matches what `build_display_function_names` exposes to
        // `DecompileContext::lookup_prototype` at decompile time.
        let enabled_indices: Vec<usize> = self
            .type_archive_enabled
            .iter()
            .enumerate()
            .filter_map(|(i, on)| on.then_some(i))
            .collect();
        let enabled_archives: Vec<Arc<TypeArchive>> = enabled_indices
            .iter()
            .map(|i| self.type_archives[*i].clone())
            .collect();
        if !enabled_archives.is_empty() {
            let mut seen: std::collections::HashSet<&str> =
                std::collections::HashSet::with_capacity(
                    self.analysis.functions.len() + self.binary.import_addr_map.len(),
                );
            for func in &self.analysis.functions {
                if !seen.insert(func.name.as_str()) {
                    continue;
                }
                if let Some(local_idx) =
                    type_archive::which_archive_resolves(&func.name, &enabled_archives)
                {
                    archive_hits[enabled_indices[local_idx]] += 1;
                }
            }
            for name in self.binary.import_addr_map.values() {
                if !seen.insert(name.as_str()) {
                    continue;
                }
                if let Some(local_idx) =
                    type_archive::which_archive_resolves(name, &enabled_archives)
                {
                    archive_hits[enabled_indices[local_idx]] += 1;
                }
            }
        }

        self.bundled_db_hits = bundled_hits;
        self.user_db_hits = user_hits;
        self.type_archive_hits = archive_hits;
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

    /// Display-friendly function name at the given address.
    ///
    /// Returns the user rename if present, otherwise the demangled form of
    /// the canonical analysis name. Use this for GUI labels and xref
    /// listings; use [`Self::function_name`] for canonical identifier
    /// lookups where the mangled form is required.
    pub fn display_function_name(&self, address: u64) -> Option<String> {
        if let Some(name) = self.renamed_functions.get(&address) {
            return Some(name.clone());
        }
        self.analysis
            .function_at(address)
            .map(|f| crate::demangle::display_name_short(&f.name).into_owned())
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

    /// Set a user type override for a local variable inside a function.
    /// Keyed by the *currently displayed* name (post auto-rename and
    /// user rename), matching what the user sees in the decompile view.
    /// Empty type string clears the override and falls back to the
    /// heuristic/archive type.
    pub fn set_variable_type(
        &mut self,
        func_entry: u64,
        displayed_name: String,
        new_type: String,
    ) {
        let key = (func_entry, displayed_name);
        if new_type.trim().is_empty() {
            self.variable_types.remove(&key);
        } else {
            self.variable_types.insert(key, new_type);
        }
    }

    /// Build the display-name map used by the decompiler for call targets.
    ///
    /// User-renamed functions pass through unchanged (they're already in
    /// the form the user wants). Raw analysis names and import names are
    /// run through [`crate::demangle::display_name`] so that MSVC C++
    /// mangled names show up as readable signatures.
    fn build_display_function_names(&self) -> HashMap<u64, String> {
        let mut function_names = HashMap::new();
        for func in &self.analysis.functions {
            if let Some(user) = self.renamed_functions.get(&func.entry_address) {
                function_names.insert(func.entry_address, user.clone());
            } else {
                function_names
                    .insert(func.entry_address, crate::demangle::display_name(&func.name).into_owned());
            }
        }
        // Expose imports by IAT-slot address so that `call [IAT]` (lifted as
        // a direct Call whose target is the IAT slot) displays the import name.
        for (addr, name) in &self.binary.import_addr_map {
            function_names
                .entry(*addr)
                .or_insert_with(|| crate::demangle::display_name(name).into_owned());
        }
        function_names
    }

    /// Return the demangled display form of the current function's name,
    /// honoring user renames. Returns `None` when the user rename (or the
    /// canonical name) already matches the display form.
    fn current_function_display_name(&self, entry: u64, ir_name: &str) -> Option<String> {
        if let Some(user) = self.renamed_functions.get(&entry) {
            if user != ir_name {
                return Some(user.clone());
            }
            return None;
        }
        let demangled = crate::demangle::display_name(ir_name);
        if demangled == ir_name {
            None
        } else {
            Some(demangled.into_owned())
        }
    }

    /// Decompile the function at the given entry address.
    pub fn decompile(&self, entry: u64) -> Option<String> {
        let ir = self.analysis.ir_for(entry)?;

        let function_names = self.build_display_function_names();

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
        let var_types_for_func: HashMap<String, String> = self
            .variable_types
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
            variable_types: var_types_for_func,
            current_function_display_name: self.current_function_display_name(entry, &ir.name),
            type_archives: self.effective_type_archives(),
        };

        // The FrameLayout returned here is currently discarded at the
        // project boundary — consumers that need it (arity capping, typed
        // decls, retype UI) are wired up in later Phase 5c PRs and will
        // grow their own project-level accessors at that time.
        Some(reghidra_decompile::decompile(ir, &ctx).text)
    }

    /// Decompile the function at the given entry address, returning annotated
    /// lines and the set of post-rename variable names that appear (used by
    /// the GUI to tokenize variable references for right-click rename).
    pub fn decompile_annotated(
        &self,
        entry: u64,
    ) -> Option<(Vec<reghidra_decompile::AnnotatedLine>, Vec<String>)> {
        let ir = self.analysis.ir_for(entry)?;

        let function_names = self.build_display_function_names();

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
        let var_types_for_func: HashMap<String, String> = self
            .variable_types
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
            variable_types: var_types_for_func,
            current_function_display_name: self.current_function_display_name(entry, &ir.name),
            type_archives: self.effective_type_archives(),
        };

        // Same frame-layout discard as `decompile` above — see that comment.
        let annotated = reghidra_decompile::decompile_annotated(ir, &ctx);
        Some((annotated.lines, annotated.variable_names))
    }

    /// Get all detected functions with display names.
    pub fn functions(&self) -> Vec<(u64, String)> {
        let mut funcs: Vec<(u64, String)> = self
            .analysis
            .functions
            .iter()
            .filter(|f| f.entry_address != 0)
            .map(|f| {
                // Function list is a compact sidebar — use the short form
                // (symbol only, no parameter list) so long C++ signatures
                // don't overflow the UI. The full signature is shown in
                // the decompile view header.
                let name = self
                    .renamed_functions
                    .get(&f.entry_address)
                    .cloned()
                    .unwrap_or_else(|| crate::demangle::display_name_short(&f.name).into_owned());
                (f.entry_address, name)
            })
            .collect();
        funcs.sort_by_key(|(addr, _)| *addr);
        funcs.dedup_by_key(|(addr, _)| *addr);
        funcs
    }

    /// Save user annotations to a session file.
    pub fn save_session(&self, path: &Path) -> Result<(), CoreError> {
        let session = self.to_session();
        let json = serde_json::to_string_pretty(&session)
            .map_err(|e| CoreError::Other(format!("Failed to serialize session: {e}")))?;
        std::fs::write(path, json)
            .map_err(|e| CoreError::Other(format!("Failed to write session file: {e}")))?;
        Ok(())
    }

    /// Build a [`Session`] snapshot of the current project state.
    /// Mostly used by [`Self::save_session`], exposed publicly so the
    /// CLI can manipulate sessions without re-deriving the field set.
    pub fn to_session(&self) -> Session {
        // Snapshot per-source enable flags as overrides. We persist EVERY
        // current flag (not just diffs from default) because the auto-load
        // default depends on the binary's format/arch and the embedded
        // sig set, both of which can change between runs. Storing the full
        // snapshot makes the persisted state self-describing.
        let mut overrides = Vec::new();
        for (i, db) in self.bundled_dbs.iter().enumerate() {
            let key = db
                .source_path
                .to_str()
                .and_then(|s| s.strip_prefix("bundled:"))
                .unwrap_or("")
                .to_string();
            if !key.is_empty() {
                overrides.push(DataSourceOverride {
                    kind: "bundled".to_string(),
                    key,
                    enabled: self.bundled_db_enabled.get(i).copied().unwrap_or(true),
                });
            }
        }
        for (i, db) in self.user_dbs.iter().enumerate() {
            overrides.push(DataSourceOverride {
                kind: "user".to_string(),
                key: db.header.name.clone(),
                enabled: self.user_db_enabled.get(i).copied().unwrap_or(true),
            });
        }
        for (i, archive) in self.type_archives.iter().enumerate() {
            overrides.push(DataSourceOverride {
                kind: "archive".to_string(),
                key: archive.name.clone(),
                enabled: self.type_archive_enabled.get(i).copied().unwrap_or(true),
            });
        }

        // Persist every currently-loaded archive stem, including ones the
        // user lazy-loaded after open. On replay, `apply_data_source_state`
        // iterates this list and calls `load_type_archive_by_stem` so the
        // opt-in selection survives a session round-trip.
        let loaded_archive_stems = self
            .type_archives
            .iter()
            .map(|a| a.name.clone())
            .collect();

        // Same logic for bundled FLIRT: anything currently loaded that
        // isn't part of the auto-load set was either auto-selected for a
        // different (subdir, stem) or explicitly opted in. We replay the
        // full set so behavior is reproducible.
        let loaded_bundled_sigs = self
            .bundled_dbs
            .iter()
            .filter_map(|db| {
                let s = db.source_path.to_str()?.strip_prefix("bundled:")?;
                let (subdir, stem) = s.rsplit_once('/')?;
                Some((subdir.to_string(), stem.to_string()))
            })
            .collect();

        // User-loaded sigs come from filesystem paths via
        // `load_signatures`; persist the paths so reload can replay them.
        let loaded_user_sig_paths: Vec<PathBuf> = self
            .user_dbs
            .iter()
            .map(|db| db.source_path.clone())
            .collect();

        Session {
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
            variable_types: self
                .variable_types
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            data_source_overrides: overrides,
            loaded_archive_stems,
            loaded_bundled_sigs,
            loaded_user_sig_paths,
        }
    }

    /// Load a session file and apply saved annotations to this project.
    pub fn load_session(&mut self, path: &Path) -> Result<(), CoreError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| CoreError::Other(format!("Failed to read session file: {e}")))?;
        let session: Session = serde_json::from_str(&data)
            .map_err(|e| CoreError::Other(format!("Failed to parse session file: {e}")))?;
        self.apply_session(session);
        Ok(())
    }

    /// Apply a deserialized [`Session`] to this project. Mutates in place.
    /// Used by both [`Self::load_session`] and [`Self::open_with_session`]
    /// so the replay logic for data source overrides only lives once.
    pub fn apply_session(&mut self, session: Session) {
        self.comments = session.comments;
        self.renamed_functions = session.renamed_functions;
        self.bookmarks = session.bookmarks;
        self.label_names = session.label_names;
        self.variable_names = session.variable_names.into_iter().collect();
        self.variable_types = session.variable_types.into_iter().collect();

        // Replay opt-in lazy loads first so the override pass below has
        // something to find. Failures (missing stems, parse errors) are
        // logged but don't abort the load — sessions should be tolerant
        // of moving fixtures around.
        for stem in &session.loaded_archive_stems {
            if !self.type_archives.iter().any(|a| a.name == *stem) {
                if self.load_type_archive_by_stem(stem).is_none() {
                    log::warn!("session: failed to lazy-load type archive '{stem}'");
                }
            }
        }
        for (subdir, stem) in &session.loaded_bundled_sigs {
            let key = format!("bundled:{subdir}/{stem}");
            let already_loaded = self
                .bundled_dbs
                .iter()
                .any(|db| db.source_path.to_str() == Some(key.as_str()));
            if !already_loaded {
                if self.load_bundled_sig(subdir, stem).is_none() {
                    log::warn!(
                        "session: failed to lazy-load bundled sig '{subdir}/{stem}'"
                    );
                }
            }
        }
        // Replay user-loaded sigs by re-reading them from disk. Missing
        // files are warned + skipped so a moved/renamed sig doesn't
        // poison the whole session.
        for path in &session.loaded_user_sig_paths {
            let already_loaded = self
                .user_dbs
                .iter()
                .any(|db| db.source_path == *path);
            if !already_loaded {
                if let Err(e) = self.load_signatures(path) {
                    log::warn!(
                        "session: failed to reload user sig '{}': {e}",
                        path.display()
                    );
                }
            }
        }

        // Apply per-source enable overrides. Anything not mentioned keeps
        // its post-open default (enabled).
        let mut needs_reanalysis = false;
        for ov in &session.data_source_overrides {
            match ov.kind.as_str() {
                "bundled" => {
                    let target_path = format!("bundled:{}", ov.key);
                    if let Some(idx) = self
                        .bundled_dbs
                        .iter()
                        .position(|db| db.source_path.to_str() == Some(target_path.as_str()))
                    {
                        if let Some(slot) = self.bundled_db_enabled.get_mut(idx) {
                            if *slot != ov.enabled {
                                *slot = ov.enabled;
                                needs_reanalysis = true;
                            }
                        }
                    }
                }
                "user" => {
                    if let Some(idx) =
                        self.user_dbs.iter().position(|db| db.header.name == ov.key)
                    {
                        if let Some(slot) = self.user_db_enabled.get_mut(idx) {
                            if *slot != ov.enabled {
                                *slot = ov.enabled;
                                needs_reanalysis = true;
                            }
                        }
                    }
                }
                "archive" => {
                    if let Some(idx) =
                        self.type_archives.iter().position(|a| a.name == ov.key)
                    {
                        if let Some(slot) = self.type_archive_enabled.get_mut(idx) {
                            *slot = ov.enabled;
                        }
                    }
                }
                other => log::warn!("session: unknown data source kind '{other}'"),
            }
        }

        if needs_reanalysis {
            self.reanalyze_with_current_signatures();
        } else {
            self.recompute_hit_counts();
        }
    }

    /// Open a binary and restore a session file's annotations.
    pub fn open_with_session(session_path: &Path) -> Result<Self, CoreError> {
        let data = std::fs::read_to_string(session_path)
            .map_err(|e| CoreError::Other(format!("Failed to read session file: {e}")))?;
        let session: Session = serde_json::from_str(&data)
            .map_err(|e| CoreError::Other(format!("Failed to parse session file: {e}")))?;

        let mut project = Self::open(&session.binary_path)?;
        project.apply_session(session);
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
    /// User type overrides for local variables. Same keying as
    /// `variable_names`; values are free-form type strings.
    #[serde(default)]
    pub variable_types: Vec<((u64, String), String)>,
    /// Per-data-source enable overrides. Persisted as `(kind, key, enabled)`
    /// triples so the file remains schema-stable when entries are added or
    /// reordered between runs. `kind` is one of `bundled` / `user` / `archive`.
    /// `key` is `<subdir>/<stem>` for bundled FLIRT, the stem (header name)
    /// for user FLIRT, and the archive stem for type archives. Entries that
    /// don't appear in this list inherit the auto-loaded default (enabled).
    /// Used by both the GUI's Loaded Data Sources panel and `reghidra-cli
    /// sources enable/disable`.
    #[serde(default)]
    pub data_source_overrides: Vec<DataSourceOverride>,
    /// Lazy-loaded type archives that the user opted into via the panel
    /// or `reghidra-cli sources load-archive`. Replayed on session load
    /// so opt-in archives don't disappear on reopen.
    #[serde(default)]
    pub loaded_archive_stems: Vec<String>,
    /// Lazy-loaded bundled FLIRT sigs that the user opted into. Each
    /// entry is a `(subdir, stem)` pair so the same stem under multiple
    /// arch dirs stays independently addressable.
    #[serde(default)]
    pub loaded_bundled_sigs: Vec<(String, String)>,
    /// Filesystem paths of `.sig` files the user loaded via
    /// `load_signatures` (CLI: `sources load-user-sig`, GUI: File →
    /// Load Signatures). Replayed on session reload so user sigs
    /// survive across CLI invocations. Missing files are warned and
    /// skipped — sessions should be tolerant of moving fixtures.
    #[serde(default)]
    pub loaded_user_sig_paths: Vec<PathBuf>,
}

/// One persisted enable/disable override. See [`Session::data_source_overrides`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceOverride {
    pub kind: String,
    pub key: String,
    pub enabled: bool,
}
