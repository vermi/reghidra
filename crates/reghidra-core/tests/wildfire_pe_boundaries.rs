//! Regression tests for function-boundary detection on the bundled
//! `wildfire-test-pe-file.exe` fixture.
//!
//! Before the CFG-reachability refactor, the linear walk in
//! `detect_functions` would let `_start` swallow the adjacent library
//! function `__report_gsfailure` at 0x004014b6 because that function is
//! reached only via an unconditional `jmp` (tail call) and was never
//! promoted to a function entry.

use reghidra_core::Project;
use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    // Tests run with CWD at the crate root (crates/reghidra-core/).
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates/
    p.pop(); // workspace root
    p.push("tests");
    p.push("fixtures");
    p.push("wildfire-test-pe-file.exe");
    p
}

#[test]
fn start_is_tiny_stub() {
    let project = Project::open(&fixture_path()).expect("open fixture");
    let start = project
        .analysis
        .function_at(0x004014ac)
        .expect("_start should be detected at 0x4014ac");

    // The real _start is a 10-byte stub: `call 0x40434f ; jmp 0x40134b`.
    // Pre-fix it was 272 bytes because it absorbed __report_gsfailure.
    assert!(
        start.size <= 16,
        "_start size should be <= 16 bytes (call; jmp stub), got {} bytes",
        start.size
    );
    assert_eq!(start.name, "_start");
}

#[test]
fn report_gsfailure_is_its_own_function() {
    let project = Project::open(&fixture_path()).expect("open fixture");

    // Pre-fix, no function existed at 0x4014b6 — it was buried inside _start.
    let func = project
        .analysis
        .function_at(0x004014b6)
        .expect("function at 0x4014b6 (__report_gsfailure) should be detected");

    // __report_gsfailure ends at 0x4015bb (ret) — size ≈ 0x106 bytes.
    assert!(
        func.size > 0x80 && func.size < 0x120,
        "expected ~0x106 bytes for __report_gsfailure, got {:#x}",
        func.size
    );
}

#[test]
fn mid_function_address_maps_to_report_gsfailure() {
    let project = Project::open(&fixture_path()).expect("open fixture");
    // 0x004015a0 is well inside __report_gsfailure (near its cleanup epilogue).
    let func = project
        .analysis
        .function_containing(0x004015a0)
        .expect("function containing 0x4015a0 should be resolved");
    assert_eq!(
        func.entry_address, 0x004014b6,
        "address 0x4015a0 should belong to the function at 0x4014b6, not to {:#x}",
        func.entry_address
    );
}

#[test]
fn function_count_did_not_regress() {
    // Sanity floor: we should at least match the pre-fix count of 213.
    // The post-fix count is higher because tail-call targets are now
    // discovered as separate functions.
    let project = Project::open(&fixture_path()).expect("open fixture");
    assert!(
        project.analysis.functions.len() >= 213,
        "function count regressed: {}",
        project.analysis.functions.len()
    );
}
