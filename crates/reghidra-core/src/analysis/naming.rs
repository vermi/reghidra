use crate::analysis::functions::{Function, FunctionSource};
use crate::analysis::xrefs::{XRefDatabase, XRefKind};
use crate::binary::{sanitize_to_name, DetectedString};
use crate::disasm::DisassembledInstruction;
use std::collections::HashMap;

/// Auto-name functions using heuristics. Only renames functions with
/// `FunctionSource::CallTarget` or `Prologue` (i.e. those with `sub_<hex>` names).
/// Strategies are applied in priority order: thunk, wrapper, string-ref, API pattern.
pub fn auto_name_functions(
    functions: &mut [Function],
    xrefs: &XRefDatabase,
    strings: &[DetectedString],
    instructions: &[DisassembledInstruction],
) {
    // Build lookup maps
    let func_name_by_addr: HashMap<u64, &str> = functions
        .iter()
        .map(|f| (f.entry_address, f.name.as_str()))
        .collect();

    let string_by_addr: HashMap<u64, &DetectedString> =
        strings.iter().map(|s| (s.address, s)).collect();

    // Build instruction index by address for fast range lookups
    let insn_by_addr: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, insn)| (insn.address, i))
        .collect();

    // Collect naming decisions (addr -> new_name) to avoid borrow issues
    let mut new_names: HashMap<u64, String> = HashMap::new();

    for func in functions.iter() {
        if !is_auto_nameable(func) {
            continue;
        }

        // Get instructions in this function's range
        let func_end = func.entry_address + func.size;

        // Strategy 1: Thunk detection
        if let Some(name) = detect_thunk(func, instructions, &insn_by_addr, &func_name_by_addr) {
            new_names.insert(func.entry_address, name);
            continue;
        }

        // Strategy 2: Wrapper detection
        if let Some(name) =
            detect_wrapper(func, func_end, xrefs, instructions, &insn_by_addr, &func_name_by_addr)
        {
            new_names.insert(func.entry_address, name);
            continue;
        }

        // Strategy 3: String-reference naming
        if let Some(name) = detect_string_ref(func, func_end, xrefs, instructions, &insn_by_addr, &string_by_addr) {
            new_names.insert(func.entry_address, name);
            continue;
        }

        // Strategy 4: API pattern naming
        if let Some(name) =
            detect_api_pattern(func, func_end, xrefs, instructions, &insn_by_addr, &func_name_by_addr)
        {
            new_names.insert(func.entry_address, name);
        }
    }

    // Apply names
    for func in functions.iter_mut() {
        if let Some(name) = new_names.remove(&func.entry_address) {
            func.name = name;
            func.source = FunctionSource::AutoNamed;
        }
    }

    // Dedup pass
    dedup_function_names(functions);
}

fn is_auto_nameable(func: &Function) -> bool {
    matches!(func.source, FunctionSource::CallTarget | FunctionSource::Prologue)
}

/// Thunk: function body is a single unconditional jump (possibly preceded by endbr64)
/// to a named function.
fn detect_thunk(
    func: &Function,
    instructions: &[DisassembledInstruction],
    insn_by_addr: &HashMap<u64, usize>,
    func_name_by_addr: &HashMap<u64, &str>,
) -> Option<String> {
    let start_idx = *insn_by_addr.get(&func.entry_address)?;
    let func_end = func.entry_address + func.size;

    // Collect instructions in this function (max 3 to be safe)
    let mut func_insns = Vec::new();
    for i in start_idx..instructions.len().min(start_idx + 3) {
        if instructions[i].address >= func_end {
            break;
        }
        func_insns.push(&instructions[i]);
    }

    if func_insns.is_empty() {
        return None;
    }

    // Skip leading endbr64/endbr32
    let meaningful: Vec<_> = func_insns
        .iter()
        .filter(|i| i.mnemonic != "endbr64" && i.mnemonic != "endbr32")
        .collect();

    // Must be exactly one meaningful instruction: an unconditional jump
    if meaningful.len() != 1 {
        return None;
    }

    let jmp = meaningful[0];
    if !is_unconditional_jump(&jmp.mnemonic) {
        return None;
    }

    let target = super::functions::parse_branch_target(&jmp.operands)?;
    let target_name = func_name_by_addr.get(&target)?;

    // Don't create thunk_sub_xxx names
    if target_name.starts_with("sub_") {
        return None;
    }

    Some(format!("thunk_{target_name}"))
}

/// Wrapper: function makes exactly one Call xref to a named target.
fn detect_wrapper(
    func: &Function,
    func_end: u64,
    xrefs: &XRefDatabase,
    instructions: &[DisassembledInstruction],
    insn_by_addr: &HashMap<u64, usize>,
    func_name_by_addr: &HashMap<u64, &str>,
) -> Option<String> {
    let start_idx = *insn_by_addr.get(&func.entry_address)?;

    let mut call_targets = Vec::new();
    for i in start_idx..instructions.len() {
        let insn = &instructions[i];
        if insn.address >= func_end {
            break;
        }
        for xref in xrefs.xrefs_from(insn.address) {
            if xref.kind == XRefKind::Call && xref.to != func.entry_address {
                call_targets.push(xref.to);
            }
        }
    }

    if call_targets.len() != 1 {
        return None;
    }

    let target = call_targets[0];
    let target_name = func_name_by_addr.get(&target)?;

    // Don't create sub_xxx_wrapper names
    if target_name.starts_with("sub_") {
        return None;
    }

    Some(format!("{target_name}_wrapper"))
}

/// String-reference naming: function has exactly one StringRef to a "distinctive" string.
fn detect_string_ref(
    func: &Function,
    func_end: u64,
    xrefs: &XRefDatabase,
    instructions: &[DisassembledInstruction],
    insn_by_addr: &HashMap<u64, usize>,
    string_by_addr: &HashMap<u64, &DetectedString>,
) -> Option<String> {
    let start_idx = *insn_by_addr.get(&func.entry_address)?;

    let mut string_refs = Vec::new();
    for i in start_idx..instructions.len() {
        let insn = &instructions[i];
        if insn.address >= func_end {
            break;
        }
        for xref in xrefs.xrefs_from(insn.address) {
            if xref.kind == XRefKind::StringRef {
                if let Some(ds) = string_by_addr.get(&xref.to) {
                    if is_distinctive_string(&ds.value) {
                        string_refs.push(*ds);
                    }
                }
            }
        }
    }

    if string_refs.len() != 1 {
        return None;
    }

    let ds = string_refs[0];
    Some(sanitize_to_name(&ds.value, "fn_", 32, func.entry_address))
}

/// Check if a string is "distinctive" enough to name a function after.
fn is_distinctive_string(value: &str) -> bool {
    if value.len() < 6 {
        return false;
    }
    let lower = value.to_lowercase();
    !matches!(
        lower.as_str(),
        "%s" | "%d" | "%u" | "%x" | "%f" | "%p" | "%ld" | "%lu"
            | "true" | "false" | "null" | "none" | "yes" | "no"
            | "%s\n" | "%d\n"
    )
}

/// API pattern: function calls named targets matching known API categories.
fn detect_api_pattern(
    func: &Function,
    func_end: u64,
    xrefs: &XRefDatabase,
    instructions: &[DisassembledInstruction],
    insn_by_addr: &HashMap<u64, usize>,
    func_name_by_addr: &HashMap<u64, &str>,
) -> Option<String> {
    let start_idx = *insn_by_addr.get(&func.entry_address)?;

    let mut categories: Vec<&str> = Vec::new();

    for i in start_idx..instructions.len() {
        let insn = &instructions[i];
        if insn.address >= func_end {
            break;
        }
        for xref in xrefs.xrefs_from(insn.address) {
            if xref.kind == XRefKind::Call {
                if let Some(name) = func_name_by_addr.get(&xref.to) {
                    if let Some(cat) = classify_api(name) {
                        if !categories.contains(&cat) {
                            categories.push(cat);
                        }
                    }
                }
            }
        }
    }

    if categories.is_empty() {
        return None;
    }

    // Use the first (most relevant) category
    let cat = categories[0];
    let short_hex = &format!("{:x}", func.entry_address);
    let suffix = if short_hex.len() > 4 {
        &short_hex[short_hex.len() - 4..]
    } else {
        short_hex.as_str()
    };
    Some(format!("fn_{cat}_{suffix}"))
}

fn classify_api(name: &str) -> Option<&'static str> {
    match name {
        "malloc" | "calloc" | "realloc" | "_malloc" | "_calloc" | "_realloc" => Some("alloc"),
        "free" | "_free" => Some("dealloc"),
        "fopen" | "fclose" | "fread" | "fwrite" | "fseek" | "ftell" | "fgets" | "fputs"
        | "_fopen" | "_fclose" | "_fread" | "_fwrite" => Some("file_io"),
        "socket" | "bind" | "listen" | "connect" | "accept" | "send" | "recv" | "sendto"
        | "recvfrom" | "_socket" | "_bind" | "_listen" | "_connect" | "_accept" => {
            Some("network")
        }
        "printf" | "fprintf" | "sprintf" | "snprintf" | "puts" | "vprintf"
        | "_printf" | "_fprintf" | "_sprintf" => Some("print"),
        "memcpy" | "memmove" | "memset" | "memcmp" | "_memcpy" | "_memmove" | "_memset" => {
            Some("memory")
        }
        _ => None,
    }
}

fn is_unconditional_jump(mnemonic: &str) -> bool {
    matches!(mnemonic, "jmp" | "b" | "j" | "ba")
}

/// Deduplicate function names: lower-addressed function keeps bare name,
/// others get `_2`, `_3` suffixes. Only affects AutoNamed functions.
fn dedup_function_names(functions: &mut [Function]) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for f in functions.iter() {
        if f.source == FunctionSource::AutoNamed {
            *counts.entry(f.name.clone()).or_insert(0) += 1;
        }
    }

    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in functions.iter_mut() {
        if f.source != FunctionSource::AutoNamed {
            continue;
        }
        let count = counts.get(&f.name).copied().unwrap_or(0);
        if count > 1 {
            let idx = seen.entry(f.name.clone()).or_insert(0);
            *idx += 1;
            if *idx > 1 {
                f.name = format!("{}_{}", f.name, idx);
            }
        }
    }
}
