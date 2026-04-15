//! Build a [`reghidra_detect::Features`] snapshot from a live [`crate::project::Project`].
//!
//! This module is the glue layer between reghidra-core's analysis data model
//! and the detection engine's feature representation.

use crate::binary::{BinaryFormat, LoadedBinary};
use crate::analysis::AnalysisResults;
use crate::analysis::xrefs::XRefKind;
use reghidra_detect::features::{
    BinaryFormat as DetectFormat, Features, FileFeatures, FunctionFeatures, Import, PeFeatures,
    RichEntry as DetectRichEntry, SectionInfo,
};

/// Build the full [`Features`] snapshot from a project's binary + analysis data.
///
/// Per-function features include:
/// - `name`: the resolved function name (post-FLIRT/rename)
/// - `apis`: callee names resolved via xrefs of `XRefKind::Call`
/// - `string_refs`: strings whose address is referenced by a StringRef xref
///   from any instruction inside the function's CFG blocks
/// - `mnemonics`: all instruction mnemonics in CFG order
/// - `xref_in_count`: call/jump xrefs targeting the function entry
/// - `xref_out_count`: call xrefs from the function body
pub fn build_features(
    binary: &LoadedBinary,
    analysis: &AnalysisResults,
    function_names: &std::collections::HashMap<u64, String>,
) -> Features {
    let mut f = Features::default();

    // --- File-level features ---
    f.file = build_file_features(binary);

    // --- Per-function features ---
    for func in &analysis.functions {
        let ff = build_function_features(func, binary, analysis, function_names);
        f.by_function.insert(func.entry_address, ff);
    }

    f
}

fn build_file_features(binary: &LoadedBinary) -> FileFeatures {
    let format = match binary.info.format {
        BinaryFormat::Elf => DetectFormat::Elf,
        BinaryFormat::Pe => DetectFormat::Pe,
        BinaryFormat::MachO => DetectFormat::MachO,
    };

    // Imports: use import_addr_map (IAT/PLT keyed by VA → name).
    // We don't store the originating DLL name in the Symbol struct, so lib = "".
    // Rules that need lib matching should use a wildcard for lib.
    let imports: Vec<Import> = binary
        .import_addr_map
        .values()
        .map(|name| Import {
            lib: String::new(),
            sym: name.clone(),
        })
        .collect();

    let strings: Vec<String> = binary.strings.iter().map(|s| s.value.clone()).collect();

    let sections: Vec<SectionInfo> = binary
        .sections
        .iter()
        .map(|s| SectionInfo {
            name: s.name.clone(),
            size: s.file_size,
            entropy: s.entropy,
            writable: s.is_writable,
            executable: s.is_executable,
        })
        .collect();

    let pe = if binary.info.format == BinaryFormat::Pe {
        let rich_entries = binary
            .info
            .rich_header
            .as_ref()
            .map(|rh| {
                rh.entries
                    .iter()
                    .map(|e| DetectRichEntry {
                        prod_id: e.prod_id,
                        build: e.build,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(PeFeatures {
            rich_entries,
            imphash: binary.info.imphash.clone(),
            tls_callbacks: binary.info.tls_callbacks_present,
            overlay: binary.info.overlay_present,
        })
    } else {
        None
    };

    FileFeatures {
        format,
        imports,
        strings,
        sections,
        pe,
    }
}

fn build_function_features(
    func: &crate::analysis::functions::Function,
    binary: &LoadedBinary,
    analysis: &AnalysisResults,
    function_names: &std::collections::HashMap<u64, String>,
) -> FunctionFeatures {
    let name = function_names
        .get(&func.entry_address)
        .cloned()
        .unwrap_or_else(|| func.name.clone());

    // Collect mnemonics and instruction addresses from CFG blocks.
    let mut mnemonics: Vec<String> = Vec::new();
    let mut insn_addresses: Vec<u64> = Vec::new();

    if let Some(cfg) = analysis.cfgs.get(&func.entry_address) {
        // BTreeMap iteration gives blocks in address order.
        for block in cfg.blocks.values() {
            for insn in &block.instructions {
                mnemonics.push(insn.mnemonic.clone());
                insn_addresses.push(insn.address);
            }
        }
    }

    // Callee names via Call xrefs from each instruction in the function.
    let mut apis: Vec<String> = Vec::new();
    for &addr in &insn_addresses {
        for xref in analysis.xrefs.xrefs_from(addr) {
            if xref.kind == XRefKind::Call {
                if let Some(callee_name) = function_names.get(&xref.to) {
                    apis.push(callee_name.clone());
                } else {
                    // Try to find by function entry
                    if let Some(f) = analysis.functions.iter().find(|f| f.entry_address == xref.to) {
                        apis.push(f.name.clone());
                    }
                }
            }
        }
    }

    // String refs: find strings referenced by StringRef xrefs from function instructions.
    let mut string_refs: Vec<String> = Vec::new();
    let string_addr_map: std::collections::HashMap<u64, &str> = binary
        .strings
        .iter()
        .map(|s| (s.address, s.value.as_str()))
        .collect();

    for &addr in &insn_addresses {
        for xref in analysis.xrefs.xrefs_from(addr) {
            if xref.kind == XRefKind::StringRef {
                if let Some(&val) = string_addr_map.get(&xref.to) {
                    string_refs.push(val.to_string());
                }
            }
        }
    }

    // Xref in/out counts.
    let xref_in_count = analysis
        .xrefs
        .xrefs_to(func.entry_address)
        .iter()
        .filter(|x| matches!(x.kind, XRefKind::Call | XRefKind::Jump | XRefKind::ConditionalJump))
        .count();

    let xref_out_count = insn_addresses
        .iter()
        .flat_map(|&a| analysis.xrefs.xrefs_from(a))
        .filter(|x| x.kind == XRefKind::Call)
        .count();

    FunctionFeatures {
        name,
        apis,
        string_refs,
        mnemonics,
        xref_in_count,
        xref_out_count,
    }
}
