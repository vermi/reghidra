use crate::arch::Architecture;
use crate::binary::LoadedBinary;
use crate::error::CoreError;
use capstone::prelude::*;
use serde::{Deserialize, Serialize};

/// A single disassembled instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

impl DisassembledInstruction {
    /// Format as a single line: "0x401000: mov rax, rbx"
    pub fn display(&self, show_bytes: bool) -> String {
        if show_bytes {
            let hex: String = self.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
            format!("0x{:08x}  {:<24} {} {}", self.address, hex, self.mnemonic, self.operands)
        } else {
            format!("0x{:08x}  {} {}", self.address, self.mnemonic, self.operands)
        }
    }
}

/// Disassembler wrapping capstone.
pub struct Disassembler {
    cs: Capstone,
}

impl Disassembler {
    /// Create a new disassembler for the given architecture.
    pub fn new(arch: Architecture) -> Result<Self, CoreError> {
        let cs = match arch {
            Architecture::X86_32 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .detail(true)
                .build(),
            Architecture::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build(),
            Architecture::Arm32 => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build(),
            Architecture::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build(),
            Architecture::Mips32 => Capstone::new()
                .mips()
                .mode(arch::mips::ArchMode::Mips32)
                .detail(true)
                .build(),
            Architecture::Mips64 => Capstone::new()
                .mips()
                .mode(arch::mips::ArchMode::Mips64)
                .detail(true)
                .build(),
            Architecture::PowerPc32 => Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode32)
                .detail(true)
                .build(),
            Architecture::PowerPc64 => Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode64)
                .detail(true)
                .build(),
            Architecture::Riscv32 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV32)
                .detail(true)
                .build(),
            Architecture::Riscv64 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV64)
                .detail(true)
                .build(),
        }
        .map_err(|e| CoreError::Disassembly(e.to_string()))?;

        Ok(Self { cs })
    }

    /// Disassemble a slice of bytes at the given base address.
    pub fn disassemble(&self, code: &[u8], base_address: u64) -> Result<Vec<DisassembledInstruction>, CoreError> {
        let insns = self
            .cs
            .disasm_all(code, base_address)
            .map_err(|e| CoreError::Disassembly(e.to_string()))?;

        Ok(insns
            .iter()
            .map(|insn| DisassembledInstruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: insn.mnemonic().unwrap_or("???").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
            })
            .collect())
    }

    /// Disassemble all executable sections of a loaded binary.
    pub fn disassemble_binary(&self, binary: &LoadedBinary) -> Result<Vec<DisassembledInstruction>, CoreError> {
        let mut all_instructions = Vec::new();

        for section in binary.executable_sections() {
            let start = section.file_offset as usize;
            let end = start + section.file_size as usize;
            if end > binary.data.len() {
                continue;
            }

            let code = &binary.data[start..end];
            let instructions = self.disassemble(code, section.virtual_address)?;
            all_instructions.extend(instructions);
        }

        // Sort by address
        all_instructions.sort_by_key(|i| i.address);
        Ok(all_instructions)
    }
}
