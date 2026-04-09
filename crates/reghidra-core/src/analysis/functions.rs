use crate::analysis::cfg::{self, ControlFlowGraph};
use crate::arch::Architecture;
use crate::binary::{LoadedBinary, SymbolKind};
use crate::disasm::DisassembledInstruction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// A detected function in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub entry_address: u64,
    pub size: u64,
    pub name: String,
    pub source: FunctionSource,
    pub instruction_count: usize,
    /// FLIRT library name (`SigHeader::name`) of the database that matched
    /// this function, when `source == FunctionSource::Signature`. Powers
    /// per-database hit attribution in the Loaded Data Sources panel; the
    /// total `Signature`-source count alone can't tell which bundled or
    /// user-loaded `.sig` was responsible.
    #[serde(default)]
    pub matched_signature_db: Option<String>,
    /// `module_length` of the current FLIRT match, when
    /// `source == FunctionSource::Signature`. Used by `apply_signatures`
    /// as a match-quality tiebreaker across databases: when a later db
    /// produces a match with a strictly longer `module_length`, it wins
    /// over the currently-recorded match. This stops generic sigs
    /// (e.g. a WDK entry whose pattern is just a short `jmp` thunk)
    /// from "poisoning" function names and blocking more specific
    /// later sigs — the canonical case being a lazy-loaded BDS/Borland
    /// sig that wants to rename a function an earlier auto-loaded sig
    /// already claimed with a garbage 5-byte match.
    #[serde(default)]
    pub matched_signature_length: Option<u32>,
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
    /// Target of an unconditional JMP (tail call).
    TailCallTarget,
    /// Heuristic prologue pattern match.
    Prologue,
    /// Auto-named by heuristic analysis (thunk, wrapper, string-ref, API pattern).
    AutoNamed,
    /// Identified by FLIRT signature matching.
    Signature,
    /// From PE .pdata exception table (x64).
    PData,
    /// From PE Guard CF function table.
    GuardCf,
}

/// Detect functions using multiple strategies and compute their CFGs.
///
/// Two-pass design:
///   1. Discover candidate entry points from every available source
///      (binary entry, symbols, call targets, gated tail-call jmp targets,
///      prologue patterns, and any extra entries from the caller).
///   2. For each entry, build a CFG via reachability (stopping at other
///      known entries, returns, and indirect branches) and derive the
///      function's true address span from that CFG.
pub fn detect_functions(
    binary: &LoadedBinary,
    instructions: &[DisassembledInstruction],
    extra_entries: &[(u64, String, FunctionSource)],
) -> (Vec<Function>, HashMap<u64, ControlFlowGraph>) {
    // ------------------------------------------------------------------
    // Pass 1: entry discovery
    // ------------------------------------------------------------------
    let mut entries: BTreeSet<u64> = BTreeSet::new();
    let mut names: HashMap<u64, (String, FunctionSource)> = HashMap::new();

    // 0. Caller-supplied high-confidence entries (e.g. PE .pdata, Guard CF).
    for (addr, name, source) in extra_entries {
        if *addr == 0 {
            continue;
        }
        entries.insert(*addr);
        names.entry(*addr).or_insert_with(|| (name.clone(), *source));
    }

    // 1. Binary entry point
    if binary.info.entry_point != 0 {
        entries.insert(binary.info.entry_point);
        names
            .entry(binary.info.entry_point)
            .or_insert_with(|| ("_start".to_string(), FunctionSource::EntryPoint));
    }

    // 2. Symbol-table functions
    for sym in &binary.symbols {
        if sym.kind == SymbolKind::Function && sym.address != 0 {
            entries.insert(sym.address);
            names
                .entry(sym.address)
                .or_insert_with(|| (sym.name.clone(), FunctionSource::Symbol));
        }
    }

    // Build an address→index map once; reused by branch-target gating,
    // prologue detection, and the CFG builder below.
    let addr_to_idx: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, insn)| (insn.address, i))
        .collect();

    // 3. Direct-call targets and 4. gated tail-call jmp targets.
    collect_branch_targets(
        binary,
        instructions,
        &addr_to_idx,
        &mut entries,
        &mut names,
    );

    // 5. Heuristic prologue detection (now also catches MSVC hotpatch prologues).
    detect_prologues(binary, instructions, &mut entries, &mut names);

    // ------------------------------------------------------------------
    // Pass 2: CFG-reachability-based extent
    // ------------------------------------------------------------------
    let mut functions = Vec::new();
    let mut cfgs: HashMap<u64, ControlFlowGraph> = HashMap::new();

    for &entry in &entries {
        // Drop entries that don't land on a real instruction (e.g. alignment
        // padding, imported-function thunks in data, or decoding gaps).
        if !addr_to_idx.contains_key(&entry) {
            continue;
        }

        let cfg = cfg::build_cfg_from_entry(entry, instructions, &entries, &addr_to_idx);
        if cfg.blocks.is_empty() {
            continue;
        }

        let (size, insn_count) = cfg.extent();
        if size == 0 {
            continue;
        }

        let (name, source) = names
            .get(&entry)
            .cloned()
            .unwrap_or_else(|| (format!("sub_{entry:x}"), FunctionSource::Prologue));

        functions.push(Function {
            entry_address: entry,
            size,
            name,
            source,
            instruction_count: insn_count,
            matched_signature_db: None,
            matched_signature_length: None,
        });
        cfgs.insert(entry, cfg);
    }

    functions.sort_by_key(|f| f.entry_address);
    (functions, cfgs)
}

/// Collect `call imm` targets (always) and `jmp imm` targets (gated) as
/// function entries.
///
/// A `jmp imm` is promoted to a function entry only if one of the following
/// holds for the target address:
///   (a) the preceding instruction is a terminator (ret / unconditional jmp /
///       int3 / ud2), *or*
///   (b) the target begins with a recognized function prologue.
///
/// This captures tail-called helpers (e.g. MSVC `__report_gsfailure`) while
/// avoiding splitting functions on ordinary intra-function jumps.
fn collect_branch_targets(
    binary: &LoadedBinary,
    instructions: &[DisassembledInstruction],
    addr_to_idx: &HashMap<u64, usize>,
    entries: &mut BTreeSet<u64>,
    names: &mut HashMap<u64, (String, FunctionSource)>,
) {
    for insn in instructions {
        if is_call_instruction(&insn.mnemonic) {
            if let Some(target) = parse_branch_target(&insn.operands) {
                if target != 0 && is_in_executable_section(binary, target) {
                    entries.insert(target);
                    names
                        .entry(target)
                        .or_insert_with(|| (format!("sub_{target:x}"), FunctionSource::CallTarget));
                }
            }
        } else if is_unconditional_jump_mnemonic(&insn.mnemonic) {
            if let Some(target) = parse_branch_target(&insn.operands) {
                if target != 0
                    && is_in_executable_section(binary, target)
                    && is_likely_tail_call_target(
                        target,
                        addr_to_idx,
                        instructions,
                        binary.info.architecture,
                    )
                {
                    entries.insert(target);
                    names.entry(target).or_insert_with(|| {
                        (
                            format!("sub_{target:x}"),
                            FunctionSource::TailCallTarget,
                        )
                    });
                }
            }
        }
    }
}

/// True if promoting a `jmp` target to a function entry is justified.
fn is_likely_tail_call_target(
    target: u64,
    addr_to_idx: &HashMap<u64, usize>,
    instructions: &[DisassembledInstruction],
    arch: Architecture,
) -> bool {
    let Some(&idx) = addr_to_idx.get(&target) else {
        return false;
    };

    // (a) Preceding instruction is a terminator.
    if idx > 0 {
        let prev = &instructions[idx - 1];
        if is_return_instruction(&prev.mnemonic)
            || is_unconditional_jump_mnemonic(&prev.mnemonic)
            || prev.mnemonic == "int3"
            || prev.mnemonic == "ud2"
        {
            return true;
        }
    } else {
        // First instruction in the stream — nothing to contradict.
        return true;
    }

    // (b) Target begins with a recognized prologue.
    let insn = &instructions[idx];
    let next = instructions.get(idx + 1);
    match arch {
        Architecture::X86_32 | Architecture::X86_64 => is_x86_prologue(insn, next),
        Architecture::Arm64 => is_arm64_prologue(insn),
        Architecture::Arm32 => is_arm32_prologue(insn),
        _ => false,
    }
}

fn is_in_executable_section(binary: &LoadedBinary, addr: u64) -> bool {
    binary
        .executable_sections()
        .iter()
        .any(|s| addr >= s.virtual_address && addr < s.virtual_address + s.virtual_size)
}

/// Detect common function prologues in executable sections.
fn detect_prologues(
    binary: &LoadedBinary,
    instructions: &[DisassembledInstruction],
    entry_points: &mut BTreeSet<u64>,
    names: &mut HashMap<u64, (String, FunctionSource)>,
) {
    for (i, insn) in instructions.iter().enumerate() {
        if entry_points.contains(&insn.address) {
            continue;
        }

        let is_prologue = match binary.info.architecture {
            Architecture::X86_32 | Architecture::X86_64 => {
                is_x86_prologue(insn, instructions.get(i + 1))
            }
            Architecture::Arm64 => is_arm64_prologue(insn),
            Architecture::Arm32 => is_arm32_prologue(insn),
            _ => false,
        };

        if !is_prologue {
            continue;
        }

        // Require the immediately preceding instruction to be a hard
        // terminator. This avoids promoting mid-function prologue lookalikes
        // (e.g. an intra-function `push ebp; mov ebp, esp` pair used to set
        // up a nested frame).
        if i == 0 {
            entry_points.insert(insn.address);
            names.entry(insn.address).or_insert_with(|| {
                (
                    format!("sub_{:x}", insn.address),
                    FunctionSource::Prologue,
                )
            });
            continue;
        }

        let prev = &instructions[i - 1];
        let prev_is_terminator = is_return_instruction(&prev.mnemonic)
            || is_unconditional_jump_mnemonic(&prev.mnemonic)
            || prev.mnemonic == "int3"
            || prev.mnemonic == "nop"
            || prev.mnemonic == "ud2";

        if prev_is_terminator {
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

fn is_x86_prologue(
    insn: &DisassembledInstruction,
    next: Option<&DisassembledInstruction>,
) -> bool {
    // push rbp/ebp ; mov rbp/ebp, rsp/esp
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
    // MSVC x86 hotpatch prologue: mov edi, edi ; {push ebp | sub esp, N}
    // The 2-byte `mov edi, edi` is emitted by MSVC (/hotpatch) so that live
    // patches can replace it with a short jump to a trampoline.
    if insn.mnemonic == "mov" && insn.operands == "edi, edi" {
        if let Some(n1) = next {
            if n1.mnemonic == "push" && (n1.operands == "ebp" || n1.operands == "rbp") {
                return true;
            }
            if n1.mnemonic == "sub"
                && (n1.operands.starts_with("esp,") || n1.operands.starts_with("rsp,"))
            {
                return true;
            }
        }
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

pub(crate) fn is_return_instruction(mnemonic: &str) -> bool {
    matches!(mnemonic, "ret" | "retq" | "retn" | "bx lr" | "jr ra")
        || mnemonic == "retf"
        || mnemonic == "iret"
        || mnemonic == "iretd"
        || mnemonic == "iretq"
}

pub(crate) fn is_unconditional_jump_mnemonic(mnemonic: &str) -> bool {
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
