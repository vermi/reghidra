use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    X86_32,
    X86_64,
    Arm32,
    Arm64,
    Mips32,
    Mips64,
    PowerPc32,
    PowerPc64,
    Riscv32,
    Riscv64,
}

impl Architecture {
    /// Pointer size in bytes for this architecture.
    pub fn pointer_size(self) -> usize {
        match self {
            Self::X86_32 | Self::Arm32 | Self::Mips32 | Self::PowerPc32 | Self::Riscv32 => 4,
            Self::X86_64 | Self::Arm64 | Self::Mips64 | Self::PowerPc64 | Self::Riscv64 => 8,
        }
    }

    /// Whether this architecture uses big-endian byte order.
    pub fn is_big_endian(self) -> bool {
        matches!(self, Self::PowerPc32 | Self::PowerPc64)
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_32 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32 => write!(f, "ARM"),
            Self::Arm64 => write!(f, "AArch64"),
            Self::Mips32 => write!(f, "MIPS"),
            Self::Mips64 => write!(f, "MIPS64"),
            Self::PowerPc32 => write!(f, "PowerPC"),
            Self::PowerPc64 => write!(f, "PowerPC64"),
            Self::Riscv32 => write!(f, "RISC-V 32"),
            Self::Riscv64 => write!(f, "RISC-V 64"),
        }
    }
}
