use crate::binary::{LoadedBinary, SymbolKind};
use crate::disasm::DisassembledInstruction;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A detected function in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub entry_address: u64,
    pub size: u64,
    pub name: String,
    pub source: FunctionSource,
    pub instruction_count: usize,
}

/// How the function was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionSource {
    /// From a symbol table entry.
    Symbol,
    /// Entry point of the binary.
    EntryPoint,
    /// Target of a CALL instruction.
    CallTarget,
    /// Heuristic prologue pattern match.
    Prologue,
    /// Auto-named by heuristic analysis (thunk, wrapper, string-ref, API pattern).
    AutoNamed,
    /// Identified by FLIRT signature matching.
    Signature,
}

/// Detect functions using multiple strategies.
pub fn detect_functions(
    binary: &LoadedBinary,
    instructions: &[DisassembledInstruction],
) -> Vec<Function> {
    let mut entry_points: BTreeSet<u64> = BTreeSet::new();
    let mut names: std::collections::HashMap<u64, (String, FunctionSource)> =
        std::collections::HashMap::new();

    // 1. Entry point
    if binary.info.entry_point != 0 {
        entry_points.insert(binary.info.entry_point);
        names.insert(
            binary.info.entry_point,
            ("_start".to_string(), FunctionSource::EntryPoint),
        );
    }

    // 2. Symbol table functions
    for sym in &binary.symbols {
        if sym.kind == SymbolKind::Function && sym.address != 0 {
            entry_points.insert(sym.address);
            // Only set name if we don't already have one, or if this is from symbols
            names
                .entry(sym.address)
                .or_insert_with(|| (sym.name.clone(), FunctionSource::Symbol));
        }
    }

    // 3. Call targets from disassembly
    for insn in instructions {
        if is_call_instruction(&insn.mnemonic) {
            if let Some(target) = parse_branch_target(&insn.operands) {
                // Verify the target is within an executable section
                if binary.executable_sections().iter().any(|s| {
                    target >= s.virtual_address
                        && target < s.virtual_address + s.virtual_size
                }) {
                    entry_points.insert(target);
                    names
                        .entry(target)
                        .or_insert_with(|| {
                            (format!("sub_{target:x}"), FunctionSource::CallTarget)
                        });
                }
            }
        }
    }

    // 4. Prologue pattern detection
    detect_prologues(binary, instructions, &mut entry_points, &mut names);

    // Build instruction address index for fast lookup
    let insn_addrs: Vec<u64> = instructions.iter().map(|i| i.address).collect();

    // Build functions with size estimation
    let entry_vec: Vec<u64> = entry_points.iter().copied().collect();
    let mut functions = Vec::new();

    for (i, &entry) in entry_vec.iter().enumerate() {
        // Find the instruction index for this entry
        let start_idx = match insn_addrs.binary_search(&entry) {
            Ok(idx) => idx,
            Err(_) => continue, // Entry doesn't correspond to a real instruction
        };

        // Estimate function end: scan to the next function entry or a final
        // return instruction.  We don't stop at the *first* ret because
        // functions with multiple exit paths (early returns, conditional
        // cleanup, etc.) have valid code after the first ret.
        let next_entry = entry_vec.get(i + 1).copied();
        let mut end_addr = entry;
        let mut insn_count = 0;
        let mut last_ret_end = None;

        for idx in start_idx..instructions.len() {
            let insn = &instructions[idx];

            // Stop if we've reached the next function
            if let Some(next) = next_entry {
                if insn.address >= next {
                    break;
                }
            }

            end_addr = insn.address + insn.bytes.len() as u64;
            insn_count += 1;

            if is_return_instruction(&insn.mnemonic) {
                last_ret_end = Some((end_addr, insn_count));
            }
        }

        // If we stopped because of the next function entry (not end of
        // instructions), use that boundary.  Otherwise, if we found at
        // least one ret, trim to the last one to avoid trailing padding.
        if next_entry.is_none() || next_entry.is_some_and(|n| end_addr < n) {
            if let Some((ret_end, ret_count)) = last_ret_end {
                end_addr = ret_end;
                insn_count = ret_count;
            }
        }

        let (name, source) = names
            .get(&entry)
            .cloned()
            .unwrap_or_else(|| (format!("sub_{entry:x}"), FunctionSource::Prologue));

        let size = end_addr.saturating_sub(entry);
        if size > 0 {
            functions.push(Function {
                entry_address: entry,
                size,
                name,
                source,
                instruction_count: insn_count,
            });
        }
    }

    functions.sort_by_key(|f| f.entry_address);
    functions
}

/// Detect common function prologues in executable sections.
fn detect_prologues(
    binary: &LoadedBinary,
    instructions: &[DisassembledInstruction],
    entry_points: &mut BTreeSet<u64>,
    names: &mut std::collections::HashMap<u64, (String, FunctionSource)>,
) {
    // Look for common prologue patterns that aren't already known functions
    for (i, insn) in instructions.iter().enumerate() {
        if entry_points.contains(&insn.address) {
            continue;
        }

        let is_prologue = match binary.info.architecture {
            crate::arch::Architecture::X86_32 | crate::arch::Architecture::X86_64 => {
                is_x86_prologue(insn, instructions.get(i + 1))
            }
            crate::arch::Architecture::Arm64 => is_arm64_prologue(insn),
            crate::arch::Architecture::Arm32 => is_arm32_prologue(insn),
            _ => false,
        };

        if is_prologue {
            // Extra check: is the preceding instruction a return or unconditional jump?
            // This helps avoid false positives in the middle of functions
            if i > 0 {
                let prev = &instructions[i - 1];
                if is_return_instruction(&prev.mnemonic)
                    || is_unconditional_jump(&prev.mnemonic)
                    || prev.mnemonic == "int3"
                    || prev.mnemonic == "nop"
                    || prev.mnemonic == "ud2"
                {
                    entry_points.insert(insn.address);
                    names.entry(insn.address).or_insert_with(|| {
                        (
                            format!("sub_{:x}", insn.address),
                            FunctionSource::Prologue,
                        )
                    });
                }
            }
        }
    }
}

fn is_x86_prologue(
    insn: &DisassembledInstruction,
    next: Option<&DisassembledInstruction>,
) -> bool {
    // push rbp/ebp; mov rbp/ebp, rsp/esp
    if insn.mnemonic == "push" && (insn.operands == "rbp" || insn.operands == "ebp") {
        if let Some(next) = next {
            if next.mnemonic == "mov"
                && (next.operands == "rbp, rsp" || next.operands == "ebp, esp")
            {
                return true;
            }
        }
    }
    // sub rsp, N (frameless prologue)
    if insn.mnemonic == "sub" && insn.operands.starts_with("rsp,") {
        return true;
    }
    // endbr64/endbr32 (CET prologues)
    if insn.mnemonic == "endbr64" || insn.mnemonic == "endbr32" {
        return true;
    }
    false
}

fn is_arm64_prologue(insn: &DisassembledInstruction) -> bool {
    // stp x29, x30, [sp, #-N]! — standard ARM64 prologue
    if insn.mnemonic == "stp" && insn.operands.contains("x29") && insn.operands.contains("x30") {
        return true;
    }
    // sub sp, sp, #N
    if insn.mnemonic == "sub" && insn.operands.starts_with("sp, sp,") {
        return true;
    }
    false
}

fn is_arm32_prologue(insn: &DisassembledInstruction) -> bool {
    // push {fp, lr} or push {r4, ..., fp, lr}
    if insn.mnemonic == "push" && insn.operands.contains("lr") {
        return true;
    }
    // stmfd sp!, {...}
    if insn.mnemonic == "stmfd" || insn.mnemonic == "stmdb" {
        return true;
    }
    false
}

fn is_call_instruction(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "call" | "bl" | "blr" | "blx" | "jal" | "jalr" | "bctrl"
    )
}

fn is_return_instruction(mnemonic: &str) -> bool {
    matches!(mnemonic, "ret" | "retq" | "retn" | "bx lr" | "jr ra")
        || mnemonic == "retf"
        || mnemonic == "iret"
        || mnemonic == "iretd"
        || mnemonic == "iretq"
}

fn is_unconditional_jump(mnemonic: &str) -> bool {
    matches!(mnemonic, "jmp" | "b" | "j" | "ba")
}

/// Parse a branch/call target address from operand string.
/// Returns None for register-indirect or complex operands.
pub fn parse_branch_target(operands: &str) -> Option<u64> {
    let operands = operands.trim();

    // Skip register-indirect calls like "call rax" or "blr x8"
    if operands.is_empty() {
        return None;
    }

    // Try to parse as hex: "0x401000" or "#0x401000"
    let cleaned = operands
        .trim_start_matches('#')
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    // Only parse if it looks like a hex number
    if cleaned.chars().all(|c| c.is_ascii_hexdigit()) && !cleaned.is_empty() {
        u64::from_str_radix(cleaned, 16).ok()
    } else {
        None
    }
}
