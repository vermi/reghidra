use reghidra_core::Project;
use std::path::Path;

fn main() {
    let p = Project::open(Path::new(
        "/Users/justin.vermillion/claude-projects/reghidra/tests/fixtures/wildfire-test-pe-file.exe",
    )).expect("load");

    // Print import_addr_map entries near 0x40a018..0x40a028
    println!("-- imports in range --");
    let mut imps: Vec<_> = p.binary.import_addr_map.iter().collect();
    imps.sort_by_key(|(a, _)| *a);
    for (a, n) in &imps {
        if **a >= 0x40a000 && **a < 0x40a100 {
            println!("  0x{:08x} -> {}", a, n);
        }
    }

    println!("\n-- function at 0x4014b6 --");
    let func = p.analysis.functions.iter().find(|f| f.entry_address == 0x4014b6);
    match func {
        Some(f) => println!("  found: name={} size={}", f.name, f.size),
        None => {
            println!("  NOT FOUND. nearby:");
            for f in p.analysis.functions.iter().filter(|f| f.entry_address >= 0x401400 && f.entry_address <= 0x401500) {
                println!("    0x{:08x}  {}", f.entry_address, f.name);
            }
        }
    }

    if let Some(d) = p.decompile(0x4014b6) {
        println!("\n-- decompile --\n{}", d);
    } else {
        println!("\n-- decompile returned None --");
    }
}
