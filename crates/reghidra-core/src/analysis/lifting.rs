use crate::arch::Architecture;
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::functions::Function;
use crate::disasm::DisassembledInstruction;
use reghidra_ir::lifter::{DisasmInput, x86_64, arm64};
use reghidra_ir::optimize;
use reghidra_ir::IrFunction;
use std::collections::HashMap;

/// Lift all detected functions to IR.
pub fn lift_all(
    arch: Architecture,
    functions: &[Function],
    cfgs: &HashMap<u64, ControlFlowGraph>,
    instructions: &[DisassembledInstruction],
) -> HashMap<u64, IrFunction> {
    let mut result = HashMap::new();

    for func in functions {
        let cfg = match cfgs.get(&func.entry_address) {
            Some(c) => c,
            None => continue,
        };

        // Collect instructions for this function
        let func_insns: Vec<DisasmInput> = instructions
            .iter()
            .filter(|i| {
                i.address >= func.entry_address
                    && i.address < func.entry_address + func.size
            })
            .map(|i| DisasmInput {
                address: i.address,
                mnemonic: i.mnemonic.clone(),
                operands: i.operands.clone(),
                bytes: i.bytes.clone(),
            })
            .collect();

        if func_insns.is_empty() {
            continue;
        }

        let block_leaders: Vec<u64> = cfg.blocks.keys().copied().collect();

        let mut ir_func = match arch {
            Architecture::X86_64 | Architecture::X86_32 => {
                x86_64::lift_function(&func.name, func.entry_address, &func_insns, &block_leaders)
            }
            Architecture::Arm64 => {
                arm64::lift_function(&func.name, func.entry_address, &func_insns, &block_leaders)
            }
            _ => {
                // For unsupported architectures, create a stub with all unimplemented
                IrFunction::new(func.name.clone(), func.entry_address)
            }
        };

        // Run optimization passes
        optimize::optimize(&mut ir_func);

        result.insert(func.entry_address, ir_func);
    }

    result
}
