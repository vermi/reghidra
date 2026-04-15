use crate::binary::LoadedBinary;
use crate::disasm::DisassembledInstruction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum XRefKind {
    /// A call instruction (call, bl, etc.)
    Call,
    /// An unconditional jump (jmp, b)
    Jump,
    /// A conditional branch (je, bne, etc.)
    ConditionalJump,
    /// A data read reference (mov reg, [addr])
    DataRead,
    /// A data write reference (mov [addr], reg)
    DataWrite,
    /// A lea/adr-style address reference
    AddressOf,
    /// A string reference
    StringRef,
}

/// A single cross-reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRef {
    /// Address of the referring instruction.
    pub from: u64,
    /// Address being referred to.
    pub to: u64,
    /// Type of reference.
    pub kind: XRefKind,
}

/// Database of cross-references for efficient lookup.
pub struct XRefDatabase {
    /// Xrefs indexed by target address (who references this address?)
    refs_to: HashMap<u64, Vec<XRef>>,
    /// Xrefs indexed by source address (what does this address reference?)
    refs_from: HashMap<u64, Vec<XRef>>,
}

impl Default for XRefDatabase {
    fn default() -> Self {
        Self {
            refs_to: HashMap::new(),
            refs_from: HashMap::new(),
        }
    }
}

impl XRefDatabase {
    /// Get all references TO a given address.
    pub fn xrefs_to(&self, addr: u64) -> &[XRef] {
        self.refs_to.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get all references FROM a given address.
    pub fn xrefs_from(&self, addr: u64) -> &[XRef] {
        self.refs_from
            .get(&addr)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the number of references to an address.
    pub fn ref_count_to(&self, addr: u64) -> usize {
        self.refs_to.get(&addr).map(|v| v.len()).unwrap_or(0)
    }

    /// Total number of cross-references.
    pub fn total_count(&self) -> usize {
        self.refs_to.values().map(|v| v.len()).sum()
    }

    fn add(&mut self, xref: XRef) {
        self.refs_to
            .entry(xref.to)
            .or_default()
            .push(xref.clone());
        self.refs_from.entry(xref.from).or_default().push(xref);
    }
}

/// Build the cross-reference database from disassembled instructions.
pub fn build_xrefs(
    binary: &LoadedBinary,
    instructions: &[DisassembledInstruction],
) -> XRefDatabase {
    let mut db = XRefDatabase {
        refs_to: HashMap::new(),
        refs_from: HashMap::new(),
    };

    // Build a set of known string addresses for string xref detection
    let string_addrs: HashMap<u64, &str> = binary
        .strings
        .iter()
        .map(|s| (s.address, s.value.as_str()))
        .collect();

    for insn in instructions {
        let mnemonic = insn.mnemonic.as_str();

        // Code references: calls, jumps, branches
        if let Some(target) = super::functions::parse_branch_target(&insn.operands) {
            let kind = classify_branch(mnemonic);
            db.add(XRef {
                from: insn.address,
                to: target,
                kind,
            });
            continue;
        }

        // Indirect call/jump through memory (e.g. `call dword ptr [0x40bfaa]`)
        // Emit a Call/Jump xref to the IAT/GOT address so naming can resolve it
        if is_call(mnemonic) || is_unconditional_jump(mnemonic) {
            if let Some(addr) = extract_indirect_target(&insn.operands) {
                let kind = classify_branch(mnemonic);
                db.add(XRef {
                    from: insn.address,
                    to: addr,
                    kind,
                });
                continue;
            }
        }

        // Data references: lea, adr, adrp, mov with memory operands
        if let Some(targets) = extract_data_references(mnemonic, &insn.operands) {
            for (target, kind) in targets {
                // Check if it's a string reference
                let final_kind = if string_addrs.contains_key(&target) {
                    XRefKind::StringRef
                } else {
                    kind
                };
                db.add(XRef {
                    from: insn.address,
                    to: target,
                    kind: final_kind,
                });
            }
        }
    }

    db
}

/// Classify a branch mnemonic into an XRefKind.
fn classify_branch(mnemonic: &str) -> XRefKind {
    if is_call(mnemonic) {
        XRefKind::Call
    } else if is_unconditional_jump(mnemonic) {
        XRefKind::Jump
    } else {
        XRefKind::ConditionalJump
    }
}

fn is_call(m: &str) -> bool {
    matches!(m, "call" | "bl" | "blr" | "blx" | "jal" | "jalr" | "bctrl")
}

fn is_unconditional_jump(m: &str) -> bool {
    matches!(m, "jmp" | "b" | "j" | "ba")
}

/// Extract data address references from instruction operands.
fn extract_data_references(mnemonic: &str, operands: &str) -> Option<Vec<(u64, XRefKind)>> {
    let mut results = Vec::new();

    match mnemonic {
        // lea/adr/adrp compute an address
        "lea" | "adr" | "adrp" => {
            if let Some(addr) = extract_address_from_operands(operands) {
                results.push((addr, XRefKind::AddressOf));
            }
        }
        // mov with memory operand
        "mov" | "movzx" | "movsx" | "movsxd" | "movabs" => {
            if let Some(addr) = extract_memory_address(operands) {
                // If the address is in the destination, it's a write; otherwise read
                let kind = if operands.starts_with('[') || operands.contains("], ") {
                    XRefKind::DataWrite
                } else {
                    XRefKind::DataRead
                };
                results.push((addr, kind));
            }
        }
        // Load instructions
        "ldr" | "ldrsw" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldp" => {
            if let Some(addr) = extract_address_from_operands(operands) {
                results.push((addr, XRefKind::DataRead));
            }
        }
        // Store instructions
        "str" | "strb" | "strh" | "stp" => {
            if let Some(addr) = extract_address_from_operands(operands) {
                results.push((addr, XRefKind::DataWrite));
            }
        }
        _ => {}
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Try to extract an absolute address from operands containing [rip + 0xNN] or similar.
fn extract_memory_address(operands: &str) -> Option<u64> {
    // Look for patterns like [0x401000] or [rip + 0x1234]
    // For RIP-relative, we can't resolve without knowing the instruction address,
    // so we just look for absolute addresses
    extract_address_from_operands(operands)
}

/// Extract target from indirect call/jump operands like `dword ptr [0x40bfaa]`
/// or `qword ptr [rip + 0x200bc2]`.
fn extract_indirect_target(operands: &str) -> Option<u64> {
    // Match patterns like "[0x40bfaa]" or "dword ptr [0x40bfaa]"
    // But NOT register-indirect like "[rax]" or "[rbx + rcx]"
    let bracket_start = operands.find('[')?;
    let bracket_end = operands.find(']')?;
    if bracket_end <= bracket_start {
        return None;
    }
    let inner = &operands[bracket_start + 1..bracket_end].trim();

    // Skip if it contains a register-only reference without an absolute address
    // Accept: "0x40bfaa", "rip + 0x200bc2"
    // Skip: "rax", "rbx + rcx*4"
    extract_address_from_operands(inner)
}

/// Extract a hex address from operand text.
fn extract_address_from_operands(operands: &str) -> Option<u64> {
    // Find 0x... patterns in the operands
    for part in operands.split(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X') {
        let cleaned = part
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        if cleaned.len() >= 4 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(addr) = u64::from_str_radix(cleaned, 16) {
                if addr > 0x1000 {
                    return Some(addr);
                }
            }
        }
    }
    None
}
