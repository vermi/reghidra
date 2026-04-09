//! Integration tests for the Phase 5c typing consumers (PR 4).
//!
//! These verify the end-to-end pipeline from binary load through
//! decompile output for the bundled fixtures, focusing on:
//!
//! 1. **No-crash smoke** for each fixture: load, analyze, decompile a
//!    handful of functions and confirm nothing panics.
//! 2. **Typed `VarDecl` / signature emission** for arg slots when the
//!    function being decompiled has a prototype in the bundled archives.
//!    The unit tests in `expr_builder` and `stackframe` already cover
//!    the typing logic exhaustively against hand-crafted inputs; these
//!    tests just exercise the integration path against real lifted IR.
//! 3. **IAT call resolution survives the decompile pipeline.** A
//!    function whose body resolves at least one Win32 (or libc) import
//!    by name is the canonical proof that the decompiler is consulting
//!    `binary.import_addr_map`.
//! 4. **Typed call-site casts** (the `(HANDLE)result, (DWORD)0xc0...`
//!    PR 4c feature) are exercised opportunistically: we walk every
//!    function and assert the path doesn't crash, and if any function
//!    happens to exhibit a typed cast we sanity-check the rendered text.
//!    Whether a given fixture's call patterns happen to land in the
//!    typed-cast path depends on the binary's calling convention,
//!    archive coverage, and how its imports are wrapped, so a hard
//!    assertion would false-fail when we re-vendor fixtures.
//!
//! The opportunistic-scan approach matches `disabling_all_type_archives_strips_typed_signatures`
//! in `data_sources.rs`: walk all functions, find a candidate that
//! exhibits the property under test, assert against the candidate.

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
    smoke_decompile_all("elf-Linux-x64-bash");
}

#[test]
fn macos_fixture_decompile_smoke() {
    smoke_decompile_all("MachO-OSX-x64-ls");
}

/// Walk the PE fixture's functions and assert that *some* function's
/// decompile output contains a name from `binary.import_addr_map`
/// rendered in *call form* (`name(`). The call-form requirement is
/// the tight version: bare-substring matching could false-pass on
/// short import names that happen to appear in unrelated identifiers
/// or comments. `name(` only appears when the lifter resolved a
/// `Call { target: iat_addr }` and the decompiler's call-rendering
/// path looked the address up in `function_names`.
///
/// This is the integration-level proof that IAT call resolution
/// survives the decompile pipeline — without it, every indirect call
/// would render as `dword ptr [0x40a008]`-style raw addresses.
///
/// We don't pin a specific address or import name because real
/// fixtures from the binary-samples corpus don't necessarily call
/// any particular Win32 API at any particular offset. The previous
/// version of this test pinned `RegCreateKeyExW` at `0x00401000`,
/// which only worked on the previous hand-crafted PE fixture.
#[test]
fn pe_fixture_iat_call_decompiles_cleanly() {
    let project = Project::open(&fixture("wildfire-test-pe-file.exe"))
        .expect("open PE fixture");

    // Snapshot the import names so we can check decomp output
    // against them. Filter out very short names (< 3 chars) which
    // would false-positive against `if (`, `do (`, etc.
    let import_names: Vec<String> = project
        .binary
        .import_addr_map
        .values()
        .filter(|n| n.len() >= 3)
        .cloned()
        .collect();
    assert!(
        !import_names.is_empty(),
        "PE fixture should have non-empty import_addr_map"
    );

    // Walk every function looking for one whose decompile contains
    // an import name in *call form* (`name(`). The call-form is the
    // tight assertion — bare substring would let comments and
    // identifiers slip through.
    let mut resolved_addr: Option<u64> = None;
    let mut resolved_via: Option<String> = None;
    for func in project.analysis.functions.iter() {
        let Some(text) = project.decompile(func.entry_address) else {
            continue;
        };
        if let Some(imp) = import_names
            .iter()
            .find(|n| text.contains(&format!("{n}(")))
        {
            resolved_addr = Some(func.entry_address);
            resolved_via = Some(imp.clone());
            break;
        }
    }

    let addr = resolved_addr.expect(
        "no function in PE fixture decompiled with an IAT import in call form \
         (`name(`) — binary.import_addr_map is not flowing into \
         DecompileContext.function_names, OR the call-rendering path stopped \
         using function_names for direct call targets",
    );
    let imp = resolved_via.unwrap();
    let decomp = project
        .decompile(addr)
        .expect("the function we just found should still decompile");
    assert!(
        decomp.contains(&format!("{imp}(")),
        "import name {imp}( should appear in decompile output for {addr:#x}"
    );
}

// NOTE: integration coverage for the PR 4c typed-call-site-cast
// feature lives in `crates/reghidra-decompile/tests/typed_call_render.rs`,
// which constructs a synthetic IR function exhibiting the
// `push HANDLE_const; call CloseHandle` pattern and runs it through
// the full `decompile()` pipeline. The fixture-based version of this
// test was unreliable because real-world binaries (cmd.exe,
// Borland-built strip.exe, etc.) don't necessarily exhibit the
// pattern in any function — see `tests/fixtures/SOURCES.md`.

/// FLIRT-matched CRT functions like `_realloc`, `_srand` should pick
/// up POSIX prototypes from `posix.rtarch` via the
/// leading-underscore-stripped lookup path (PR 4e). Before PR 4e, PE
/// binaries only loaded `windows-x86.rtarch`, which has no CRT
/// surface, so CRT wrappers rendered as `void _realloc(void)`. After
/// PR 4e the POSIX archive is a lower-precedence fallback and the
/// signature line pulls its types straight from the prototype.
///
/// Pinning to exact names is fragile to fixture drift, so assert only
/// that *some* CRT wrapper in the fixture has picked up a typed
/// signature — meaning the signature line contains a parameter with
/// a real type (`void*`, `int32_t`, `size_t`, ...) rather than just
/// `(void)`. The canary list covers the FLIRT-named CRT functions
/// observed on the current PE fixture; if a re-vendor drops all of
/// them this will false-positive fail and the canary list should be
/// expanded to whatever the new fixture happens to expose.
#[test]
fn pe_fixture_flirt_crt_picks_up_typed_signature() {
    let project = Project::open(&fixture("wildfire-test-pe-file.exe"))
        .expect("open PE fixture");

    // The `wildfire-test-pe-file.exe` fixture is MSVC-built, so the
    // CRT wrappers come from the Visual Studio 2008/2010 FLIRT sigs
    // (rizin.re) plus the `Microsoft VisualC 2-14/net runtime` IDA
    // sig — all of which auto-load on PE x86. The canaries below
    // cover names those sigs actually produce on this binary.
    let canaries: &[&str] = &[
        "__realloc_crt", "_malloc", "_realloc", "_free",
        "__fclose_nolock", "_fclose", "_printf", "_exit",
    ];
    let mut checked = 0usize;
    let mut typed = 0usize;
    for func in project.analysis.functions.iter() {
        if !canaries.iter().any(|c| func.name == *c) {
            continue;
        }
        checked += 1;
        let Some(decomp) = project.decompile(func.entry_address) else {
            continue;
        };
        let first_line = decomp.lines().next().unwrap_or("");
        // "void name(void) {" = untyped fallback. Anything else means
        // the archive lookup landed and format_signature pulled real
        // types in.
        if !first_line.starts_with("void ") || !first_line.contains("(void)") {
            typed += 1;
        }
    }
    assert!(
        checked > 0,
        "PE fixture should contain at least one of {canaries:?}"
    );
    assert!(
        typed > 0,
        "expected at least one FLIRT-matched CRT wrapper to render \
         with a typed signature line (checked {checked} candidates)"
    );
}
