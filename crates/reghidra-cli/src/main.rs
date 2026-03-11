use anyhow::Result;
use reghidra_core::Project;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: reghidra-cli <binary>");
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    println!("Loading {}...", path.display());

    let project = Project::open(path)?;
    let info = &project.binary.info;

    println!("Format:       {}", info.format);
    println!("Architecture: {}", info.architecture);
    println!("Entry point:  0x{:x}", info.entry_point);
    println!("64-bit:       {}", info.is_64bit);
    println!("Sections:     {}", project.binary.sections.len());
    println!("Symbols:      {}", project.binary.symbols.len());
    println!("Instructions: {}", project.instructions.len());
    println!("Functions:    {}", project.analysis.functions.len());
    println!("Xrefs:        {}", project.analysis.xrefs.total_count());
    println!("CFGs:         {}", project.analysis.cfgs.len());
    println!("IR functions: {}", project.analysis.ir_functions.len());
    println!("Strings:      {}", project.binary.strings.len());

    println!("\n--- Sections ---");
    for sec in &project.binary.sections {
        println!(
            "  {:<20} 0x{:08x}  size=0x{:x}  {}{}{}",
            sec.name,
            sec.virtual_address,
            sec.virtual_size,
            if sec.is_readable { "r" } else { "-" },
            if sec.is_writable { "w" } else { "-" },
            if sec.is_executable { "x" } else { "-" },
        );
    }

    println!("\n--- Functions (first 30) ---");
    for func in project.analysis.functions.iter().take(30) {
        let cfg = project.analysis.cfgs.get(&func.entry_address);
        let blocks = cfg.map(|c| c.block_count()).unwrap_or(0);
        let xrefs_to = project.analysis.xrefs.ref_count_to(func.entry_address);
        println!(
            "  0x{:08x}  {:<30} {:>4} insns  {:>3} blocks  {:>3} xrefs  [{:?}]",
            func.entry_address,
            func.name,
            func.instruction_count,
            blocks,
            xrefs_to,
            func.source,
        );
    }

    // Show a sample CFG
    if let Some(func) = project.analysis.functions.iter().find(|f| {
        f.instruction_count > 5
            && project
                .analysis
                .cfgs
                .get(&f.entry_address)
                .map(|c| c.block_count() > 1)
                .unwrap_or(false)
    }) {
        println!("\n--- CFG for {} ---", func.name);
        if let Some(cfg) = project.analysis.cfgs.get(&func.entry_address) {
            for (addr, block) in &cfg.blocks {
                let succs = cfg.succs(*addr);
                let preds = cfg.preds(*addr);
                println!(
                    "  Block 0x{:08x} ({} insns)  preds={:x?}  succs={:x?}",
                    addr,
                    block.instructions.len(),
                    preds,
                    succs,
                );
                for insn in &block.instructions {
                    println!("    {}", insn.display(false));
                }
            }
            println!("  {} edges:", cfg.edges.len());
            for edge in &cfg.edges {
                println!(
                    "    0x{:08x} -> 0x{:08x}  [{:?}]",
                    edge.from, edge.to, edge.kind
                );
            }
        }
    }

    // Show IR and decompiled output for a function with branches
    if let Some(func) = project.analysis.functions.iter().find(|f| {
        f.instruction_count > 10 && f.instruction_count < 25
            && project.analysis.cfgs.get(&f.entry_address)
                .map(|c| c.block_count() > 2).unwrap_or(false)
    }) {
        if let Some(ir) = project.analysis.ir_for(func.entry_address) {
            println!("\n--- IR for {} ---", func.name);
            print!("{ir}");
        }
        if let Some(decomp) = project.decompile(func.entry_address) {
            println!("\n--- Decompiled {} ---", func.name);
            print!("{decomp}");
        }
    }

    // Show xrefs for a function
    if let Some(func) = project
        .analysis
        .functions
        .iter()
        .find(|f| project.analysis.xrefs.ref_count_to(f.entry_address) > 2)
    {
        println!("\n--- Xrefs TO {} (0x{:x}) ---", func.name, func.entry_address);
        for xref in project.analysis.xrefs.xrefs_to(func.entry_address) {
            let caller = project
                .analysis
                .function_containing(xref.from)
                .map(|f| f.name.as_str())
                .unwrap_or("???");
            println!(
                "  0x{:08x} ({})  [{:?}]",
                xref.from, caller, xref.kind
            );
        }
    }

    println!("\n--- Disassembly (first 30 instructions) ---");
    for insn in project.instructions.iter().take(30) {
        let mut line = insn.display(true);
        // Show xrefs from this instruction
        let xrefs = project.analysis.xrefs.xrefs_from(insn.address);
        if !xrefs.is_empty() {
            for xref in xrefs {
                let target_name = project
                    .function_name(xref.to)
                    .unwrap_or("");
                if !target_name.is_empty() {
                    line.push_str(&format!("  ; -> {target_name}"));
                }
            }
        }
        if let Some(comment) = project.comments.get(&insn.address) {
            line.push_str(&format!("  ; {comment}"));
        }
        println!("  {line}");
    }

    println!("\n--- Strings (first 20) ---");
    for s in project.binary.strings.iter().take(20) {
        let xrefs = project.analysis.xrefs.ref_count_to(s.address);
        println!("  0x{:08x}  ({} xrefs)  \"{}\"", s.address, xrefs, s.value);
    }

    Ok(())
}
