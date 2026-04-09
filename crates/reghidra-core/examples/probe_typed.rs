//! One-shot probe: load a fixture once, walk every detected function,
//! decompile it, and report the first function whose decompile output
//! exhibits typed call-site casts (HANDLE, DWORD, etc.) or known Win32
//! import resolution. Used to find candidate canaries for the
//! integration tests in `typed_decompile.rs`.
//!
//! Run with: `cargo run --example probe_typed --release -- <fixture-path>`

use reghidra_core::Project;
use std::env;
use std::path::PathBuf;

fn main() {
    let path = env::args()
        .nth(1)
        .expect("usage: probe_typed <fixture>");
    let project = Project::open(&PathBuf::from(&path)).expect("open");

    println!(
        "loaded {}: {} functions, {} archives, {} imports",
        path,
        project.analysis.functions.len(),
        project.type_archives.len(),
        project.binary.import_addr_map.len(),
    );

    let win_types = [
        "HANDLE",
        "DWORD",
        "HWND",
        "HKEY",
        "HMODULE",
        "LPCSTR",
        "LPSTR",
        "LPCWSTR",
        "LPWSTR",
        "LPVOID",
        "LPCVOID",
        "FARPROC",
        "BOOL",
        "UINT",
    ];

    let mut typed_call_examples: Vec<(u64, String, String)> = Vec::new();
    let mut import_resolved_examples: Vec<(u64, String, String)> = Vec::new();
    let mut typed_sig_examples: Vec<(u64, String, String)> = Vec::new();

    let import_names: Vec<&String> = project.binary.import_addr_map.values().collect();

    for func in project.analysis.functions.iter() {
        let Some(text) = project.decompile(func.entry_address) else {
            continue;
        };

        // Typed call-site cast canary: look for `(HANDLE)` etc. (full scan)
        for ty in &win_types {
            let needle = format!("({})", ty);
            if text.contains(&needle) {
                typed_call_examples.push((
                    func.entry_address,
                    func.name.clone(),
                    ty.to_string(),
                ));
                break;
            }
        }

        // Import-resolved-by-name canary: look for any import name in body.
        if import_resolved_examples.len() < 3 {
            for imp in &import_names {
                if text.contains(imp.as_str()) {
                    import_resolved_examples.push((
                        func.entry_address,
                        func.name.clone(),
                        (*imp).clone(),
                    ));
                    break;
                }
            }
        }

        // Typed signature canary (non-`void name(void)` first line).
        if typed_sig_examples.len() < 3 {
            let first = text.lines().next().unwrap_or("");
            let untyped = first.starts_with("void ") && first.contains("(void)");
            if !untyped && !first.is_empty() {
                typed_sig_examples.push((
                    func.entry_address,
                    func.name.clone(),
                    first.to_string(),
                ));
            }
        }

    }

    println!("\n=== typed call-site casts ({} found) ===", typed_call_examples.len());
    for (addr, name, ty) in &typed_call_examples {
        println!("  {addr:#x}  {name}  -> contains ({ty})");
    }

    println!("\n=== imports resolved by name in body ({} found) ===", import_resolved_examples.len());
    for (addr, name, imp) in &import_resolved_examples {
        println!("  {addr:#x}  {name}  -> mentions {imp}");
    }

    println!("\n=== typed signature lines ({} found) ===", typed_sig_examples.len());
    for (addr, name, sig) in &typed_sig_examples {
        println!("  {addr:#x}  {name}  -> {sig}");
    }
}
