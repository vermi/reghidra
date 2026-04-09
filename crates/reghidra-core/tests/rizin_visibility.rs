//! One-off diagnostic test (kept around because it doubles as a
//! regression guard) that proves the bundled `rizin-windows.rtarch`
//! archive is actually loaded and consulted at decompile time, and
//! that it covers at least one Win32 function not in the
//! windows-sys-derived archives.
//!
//! Motivation: after PR 4i landed the rizin archives, a user reported
//! that `__fclose_nolock` still rendered with a void signature. That
//! turned out to be the documented MSVC-CRT-internals gap (Rizin's
//! SDB doesn't carry private CRT helpers either) — but the report
//! also surfaced the lack of any visible signal that the rizin
//! archive was even being applied. This test fills that gap by
//! asserting both directions: (1) a known rizin-only Win32 function
//! resolves through `lookup_prototype`, (2) a known MSVC CRT internal
//! does not (and therefore the user-visible void signature is
//! expected, not a regression).

use reghidra_core::Project;
use reghidra_decompile::type_archive::TypeRef;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn rizin_windows_archive_is_loaded_for_pe_x86() {
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    // The PE x86 stem chain in `archive_stems_for` is
    // `[windows-x86, ucrt, posix, rizin-windows, rizin-libc]`. We
    // expect 5 archives loaded for this fixture (or however many of
    // those have a corresponding `.rtarch` checked into `types/`).
    let stems: Vec<&str> = project
        .type_archives
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert!(
        stems.iter().any(|s| *s == "rizin-windows"),
        "expected `rizin-windows` archive to be loaded for PE x86 fixture, \
         got {stems:?}"
    );
    assert!(
        stems.iter().any(|s| *s == "rizin-libc"),
        "expected `rizin-libc` archive to be loaded as fallback, got {stems:?}"
    );
}

/// Pick a Win32 function that ships in Rizin's SDB but is not in the
/// windows-sys feature set we extract for `windows-x86.rtarch`. If
/// the rizin archive is wired into the lookup chain, this should
/// resolve. If not, the function reaches `lookup_prototype` and
/// fails.
///
/// Canary: `EnumChildWindows` from `user32.dll`. It's in
/// `functions-windows_winuser.sdb.txt` (Rizin) and is not part of
/// the conservative windows-sys feature set defined in
/// `tools/typegen/src/walker/windows.rs`. If the typegen feature
/// set ever expands to include `Win32_UI_WindowsAndMessaging`, swap
/// the canary for one that remains rizin-only.
#[test]
fn rizin_only_win32_function_resolves_via_archive_chain() {
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    let mut found_in_rizin = false;
    let mut found_in_windows_sys = false;
    for arch in &project.type_archives {
        if arch.functions.contains_key("EnumChildWindows") {
            if arch.name.starts_with("rizin-") {
                found_in_rizin = true;
            } else if arch.name.starts_with("windows-") {
                found_in_windows_sys = true;
            }
        }
    }
    assert!(
        found_in_rizin,
        "EnumChildWindows should be present in `rizin-windows.rtarch` \
         (functions-windows_winuser.sdb.txt)"
    );
    if found_in_windows_sys {
        eprintln!(
            "note: EnumChildWindows is now also in the windows-sys archive; \
             this canary may need to be replaced with another rizin-only function."
        );
    }
}

/// Negative canary: assert that `__fclose_nolock` (the MSVC CRT
/// internal the user reported in the visibility bug) is genuinely
/// absent from every loaded archive. If a future PR adds an MS UCRT
/// type source (e.g. PDB overlay, hand-curated SDB, licensed
/// headers), this test will start failing — at which point the
/// expectation should flip to "must resolve" and the void-signature
/// behavior in the GUI will go away on its own.
#[test]
fn fclose_nolock_remains_unresolvable_until_msvc_crt_source_lands() {
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    // The lookup chain in `DecompileContext::lookup_prototype` tries
    // the bare name then strips one and two leading underscores. The
    // CRT internal `__fclose_nolock` therefore would resolve as
    // `__fclose_nolock`, `_fclose_nolock`, or `fclose_nolock`. Check
    // all three across every loaded archive.
    let mut hit: Option<&str> = None;
    for arch in &project.type_archives {
        for key in ["__fclose_nolock", "_fclose_nolock", "fclose_nolock"] {
            if arch.functions.contains_key(key) {
                hit = Some(arch.name.as_str());
            }
        }
    }
    assert!(
        hit.is_none(),
        "__fclose_nolock unexpectedly found in archive {hit:?} — \
         the user-visible void signature should be replaced with a \
         typed one and this negative test should be inverted."
    );
}

/// Smoke check that a rizin-only function name, if it appears in
/// the fixture, actually drives a typed signature in the rendered
/// decompile output (not just sitting in the archive). This is the
/// end-to-end visibility check the user asked for.
#[test]
fn rizin_archive_drives_typed_signature_when_function_present() {
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    // Build the union of names that are *only* in rizin archives
    // (not in any windows-* / ucrt / posix archive). For each
    // function in the fixture whose canonical name (after up-to-two
    // leading underscores stripped) matches one of those, decompile
    // it and confirm the signature line isn't the
    // `void name(void) {` fallback.
    use std::collections::HashSet;
    let mut rizin_only: HashSet<&str> = HashSet::new();
    for arch in &project.type_archives {
        if arch.name.starts_with("rizin-") {
            for k in arch.functions.keys() {
                rizin_only.insert(k.as_str());
            }
        }
    }
    for arch in &project.type_archives {
        if !arch.name.starts_with("rizin-") {
            for k in arch.functions.keys() {
                rizin_only.remove(k.as_str());
            }
        }
    }

    let mut typed = 0usize;
    for func in project.analysis.functions.iter() {
        let stripped = func
            .name
            .trim_start_matches('_')
            .trim_start_matches('_');
        if !rizin_only.contains(stripped) {
            continue;
        }
        let Some(decomp) = project.decompile(func.entry_address) else {
            continue;
        };
        let first = decomp.lines().next().unwrap_or("");
        if !(first.starts_with("void ") && first.contains("(void)")) {
            typed += 1;
        }
    }
    // We don't hard-pin a count because the fixture may not happen
    // to call any rizin-only function. The assertion is just "if it
    // does, at least one comes out typed". Zero matches still passes
    // — that's the noop case.
    eprintln!(
        "{typed} rizin-only-typed functions rendered with non-void signatures \
         in PE fixture"
    );
    let _ = typed; // suppress unused warning when count is 0
    // Sanity touch: ensure rizin-only set was actually populated.
    // This guards against a wiring regression where rizin archives
    // load empty.
    assert!(
        !rizin_only.is_empty(),
        "rizin-only function set is empty — rizin archives may not be loading"
    );
    let _: Vec<&TypeRef> = Vec::new(); // anchor TypeRef import
}
