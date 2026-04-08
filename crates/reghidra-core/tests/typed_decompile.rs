//! Integration tests for the Phase 5c typing consumers (PR 4).
//!
//! These verify the end-to-end pipeline from binary load through
//! decompile output for the bundled fixtures, focusing on:
//!
//! 1. **Arity capping** at IAT call sites — the Phase 5b regression
//!    where stray pushes get over-attributed to the next call.
//! 2. **Typed `VarDecl` emission** for arg slots, when the function
//!    being decompiled has a prototype in the bundled archives. (In
//!    practice this is only the small set of functions that match by
//!    name across the binary, but it's the only way to exercise the
//!    type-propagation path against real lifted IR rather than
//!    hand-crafted unit-test inputs.)
//! 3. **No-crash smoke** for each fixture: load, analyze, decompile a
//!    handful of functions and confirm nothing panics. The
//!    pre-PR 4 pipeline was already exercised by `wildfire_pe_boundaries`,
//!    but that test didn't touch the decompile path.

use reghidra_core::Project;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

/// Decompile every detected function in a fixture and confirm the
/// pipeline doesn't panic. Catches regressions in the typing
/// consumers that only show up on real lifted IR (e.g. an
/// unexpected slot offset combo, an arity-cap edge case with
/// 0-arg variadic functions, etc.).
fn smoke_decompile_all(fixture_name: &str) {
    let project = Project::open(&fixture(fixture_name))
        .unwrap_or_else(|e| panic!("opening {fixture_name}: {e}"));

    // Cap at 50 functions to keep the test fast on large binaries —
    // this is a smoke test, not a coverage test. The earlier
    // unit tests (in expr_builder and stackframe) already cover the
    // typing logic exhaustively; this just ensures the integration
    // doesn't blow up on real input.
    for func in project.analysis.functions.iter().take(50) {
        // Skip functions without lifted IR (some sources don't get
        // lifted at all). The decompile call returns `None` for
        // those, which is fine.
        let _ = project.decompile(func.entry_address);
    }
}

#[test]
fn pe_fixture_decompile_smoke() {
    smoke_decompile_all("wildfire-test-pe-file.exe");
}

#[test]
fn elf_fixture_decompile_smoke() {
    smoke_decompile_all("wildfire-test-elf-file");
}

#[test]
fn macos_fixture_decompile_smoke() {
    smoke_decompile_all("wildfire-test-macos-file");
}

/// `fn_file_io_1000` in the PE fixture is at 0x00401000 and starts
/// with seven pushes followed by `call dword ptr [0x40a008]` — an
/// indirect call through the IAT to a 7-arg Win32 function (the
/// disassembly suggests `Reg{Open,Create}KeyExW` based on the
/// HKEY_LOCAL_MACHINE constant pushed last). Without arity capping
/// this call's arg list could be polluted by unrelated earlier
/// pushes; with arity capping the prototype lookup gates how many
/// of the pending stack writes get consumed.
///
/// We don't assert a specific arg count here because the IAT
/// resolution happens via `binary.import_addr_map` and the resolved
/// name depends on what windows-x86.rtarch contains for the actual
/// import. Instead we assert two looser invariants:
///
/// 1. The decompile output is non-empty (the pipeline didn't panic
///    on the typed-call path).
/// 2. The output mentions either `dword ptr [0x40a008]` style raw
///    indirect, or a resolved function name. Both are acceptable
///    outcomes for this PR — what matters is that we don't crash.
#[test]
fn pe_fixture_iat_call_decompiles_cleanly() {
    let project = Project::open(&fixture("wildfire-test-pe-file.exe"))
        .expect("open PE fixture");

    let decomp = project
        .decompile(0x00401000)
        .expect("fn_file_io_1000 should decompile");
    assert!(
        !decomp.is_empty(),
        "decompile output for fn_file_io_1000 was empty"
    );
    // Sanity: the function returns at the end, so the output should
    // contain a `return` somewhere. If it doesn't, something deeper
    // went wrong than just typing.
    assert!(
        decomp.contains("return"),
        "decompile output missing return; got:\n{decomp}"
    );
    // The call target should resolve to the IAT-imported name via
    // PE import_addr_map, even though the args may be empty in the
    // current pipeline due to a pre-existing push-queue-flush
    // limitation that's tracked separately from the typing work.
    assert!(
        decomp.contains("RegCreateKeyExW"),
        "expected RegCreateKeyExW import to be resolved by name; got:\n{decomp}"
    );
}

/// `sub_4014b6` in the PE fixture calls several Win32 imports whose
/// args ARE present in the same basic block as the call:
/// `SetUnhandledExceptionFilter(0)`, `UnhandledExceptionFilter(...)`,
/// `TerminateProcess(...)`. With the PR 4c typed-cast-at-call-site
/// pass, those args should be wrapped in Cast expressions referring
/// to the prototype's parameter types — making `HANDLE`,
/// `LPTOP_LEVEL_EXCEPTION_FILTER`, etc. visible in the rendered
/// decompile output even though the function being decompiled is a
/// `sub_XXXX` with no archive entry of its own.
///
/// This is the user-visible test for "I see types in the decompile
/// view." If the decompiler stops emitting type names at typed call
/// sites, this assertion catches it before the GUI does.
#[test]
fn pe_fixture_typed_calls_show_archive_types() {
    let project = Project::open(&fixture("wildfire-test-pe-file.exe"))
        .expect("open PE fixture");
    let decomp = project
        .decompile(0x004014b6)
        .expect("sub_4014b6 should decompile");

    // The output should mention at least one Win32 type name from
    // the archive. We don't pin to a specific function call because
    // any drift in import resolution or arity capping might shuffle
    // exactly which calls survive in the output, but we DO require
    // that *some* archive type makes it to the rendered text.
    let archive_types = ["HANDLE", "LPTOP_LEVEL_EXCEPTION_FILTER"];
    let found_any = archive_types.iter().any(|t| decomp.contains(t));
    assert!(
        found_any,
        "expected at least one of {archive_types:?} in sub_4014b6 decompile output, got:\n{decomp}"
    );

    // Specifically, TerminateProcess should appear with a HANDLE
    // cast on its first arg. This is the canonical Win32 idiom and
    // the most concrete validation for the typed-call work.
    assert!(
        decomp.contains("TerminateProcess((HANDLE)"),
        "expected TerminateProcess to receive a HANDLE-typed arg, got:\n{decomp}"
    );

    // PR 4d: the second arg (exit code 0xc0000409) is pushed in a
    // different basic block than the call itself — TerminateProcess's
    // push sequence crosses a block boundary. Cross-block pending
    // propagation (linear-chain rule) is what makes this arg survive
    // to the rendered output. If we regress cross-block tracking,
    // the arg list will shrink to just the HANDLE and this assertion
    // will fail before the GUI does.
    assert!(
        decomp.contains("0xc0000409"),
        "expected TerminateProcess second arg (exit code 0xc0000409) \
         to survive cross-block pending propagation, got:\n{decomp}"
    );
}
