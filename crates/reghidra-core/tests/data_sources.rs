//! Tests for the Loaded Data Sources panel plumbing on `Project`.
//!
//! Two things this guards:
//!
//! 1. **Hit counts are non-zero on a real binary.** If `recompute_hit_counts`
//!    silently regresses to all-zeros (e.g. by walking the wrong field, or
//!    by under-counting after the type-archive precedence chain changes),
//!    the panel becomes useless and the silent-magic problem comes back.
//!
//! 2. **Toggling a type archive actually changes decompile output.** A
//!    disabled archive must drop out of `effective_type_archives`, which
//!    `decompile()` consults via `DecompileContext::lookup_prototype`.
//!    Without this guarantee the per-source enable/disable buttons would
//!    be cosmetic.

use reghidra_core::Project;
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
fn pe_fixture_credits_windows_archive_for_iat_imports() {
    // Regression: in the first cut of the data sources panel,
    // `windows-x86` reported zero hits on PE fixtures even though
    // many Win32 API imports lived in `binary.import_addr_map` and
    // resolved cleanly through the archive. The undercount happened
    // because `recompute_hit_counts` walked only `analysis.functions`,
    // and on PE x86 IAT slot addresses don't coincide with any function
    // entry, so `resolve_import_functions` never copied import names
    // onto an analysis entry. This test pins the post-fix behavior:
    // import_addr_map names contribute to type archive hit counts.
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    let win_idx = project
        .type_archives
        .iter()
        .position(|a| a.name.starts_with("windows-"))
        .expect("PE fixture should load a windows-* archive");
    let win_hits = project.type_archive_hits[win_idx];

    // Lower bound is intentionally loose. pe-mingw32-strip.exe has
    // ~48 windows-x86 hits via the IAT; demanding >= 20 leaves slack
    // for fixture churn while still catching a regression to zero or
    // single digits.
    assert!(
        win_hits >= 20,
        "windows archive '{}' has only {win_hits} hits — expected >= 20 \
         from PE fixture's IAT imports. import_addr_map values may not \
         be flowing into recompute_hit_counts.",
        project.type_archives[win_idx].name
    );
}

#[test]
fn pe_fixture_reports_nonzero_type_archive_hits() {
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    let total_archive_hits: usize = project.type_archive_hits.iter().sum();
    assert!(
        total_archive_hits > 0,
        "expected at least one type archive hit on PE fixture, got 0 \
         across {} archives — recompute_hit_counts may be walking the \
         wrong field or the archives loaded empty",
        project.type_archives.len()
    );

    // The hit vec must stay parallel to the archive vec — a length
    // mismatch would let the GUI panel index out of bounds.
    assert_eq!(
        project.type_archives.len(),
        project.type_archive_hits.len(),
        "type_archive_hits length must match type_archives length"
    );
    assert_eq!(
        project.type_archives.len(),
        project.type_archive_enabled.len(),
        "type_archive_enabled length must match type_archives length"
    );
}

#[test]
fn flirt_hit_totals_match_signature_source_count() {
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    let signature_count = project
        .analysis
        .functions
        .iter()
        .filter(|f| f.source == reghidra_core::FunctionSource::Signature)
        .count();

    let bundled_total: usize = project.bundled_db_hits.iter().sum();
    let user_total: usize = project.user_db_hits.iter().sum();

    // Every signature-source function must be attributed to exactly
    // one db (its `matched_signature_db` field). If the FLIRT apply
    // path stops setting that field, this drops to zero.
    assert_eq!(
        bundled_total + user_total,
        signature_count,
        "FLIRT hit attribution lost {} matches",
        signature_count.saturating_sub(bundled_total + user_total)
    );
}

#[test]
fn disabling_type_archive_recomputes_hit_counts() {
    let mut project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    // Find an archive that actually has hits — there's no point
    // testing a toggle on a zero-hit archive.
    let Some((idx, before)) = project
        .type_archive_hits
        .iter()
        .copied()
        .enumerate()
        .find(|(_, h)| *h > 0)
    else {
        panic!("no type archive has any hits — see nonzero test");
    };

    project.set_type_archive_enabled(idx, false);

    // The disabled archive should now report 0 hits (we count against
    // the *enabled* set on purpose so the precedence chain is visible
    // when one source drops out).
    assert_eq!(
        project.type_archive_hits[idx], 0,
        "archive {} still has {} hits after being disabled",
        project.type_archives[idx].name, project.type_archive_hits[idx]
    );

    // Re-enable and confirm the count comes back.
    project.set_type_archive_enabled(idx, true);
    assert_eq!(
        project.type_archive_hits[idx], before,
        "re-enabling archive {} should restore the original hit count {}",
        project.type_archives[idx].name, before
    );
}

#[test]
fn enumeration_lists_archives_not_auto_loaded() {
    // Regression: PE x86 fixture only auto-loads `windows-x86`, but the
    // panel should still surface `windows-x64` and `windows-arm64` as
    // available-but-unloaded so the user can opt in. If
    // `available_archive_stems` regresses to just the loaded set, the
    // opt-in flow disappears and the panel becomes lossy again.
    let project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    let stems = &project.available_archive_stems;
    assert!(
        stems.iter().any(|s| s == "windows-x64"),
        "windows-x64 should appear in available stems even when not auto-loaded; got {stems:?}"
    );
    assert!(
        stems.iter().any(|s| s == "windows-arm64"),
        "windows-arm64 should appear in available stems even when not auto-loaded; got {stems:?}"
    );

    // The auto-loaded one is in the loaded set; the others are not.
    let loaded: Vec<&str> = project.type_archives.iter().map(|a| a.name.as_str()).collect();
    assert!(loaded.contains(&"windows-x86"), "windows-x86 should be auto-loaded");
    assert!(!loaded.contains(&"windows-x64"), "windows-x64 must NOT be auto-loaded on x86 fixture");
}

#[test]
fn lazy_load_type_archive_by_stem_appends_and_resolves() {
    let mut project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    let before = project.type_archives.len();
    assert!(
        !project.type_archives.iter().any(|a| a.name == "windows-x64"),
        "test precondition: windows-x64 should not be auto-loaded on x86 fixture"
    );

    let idx = project
        .load_type_archive_by_stem("windows-x64")
        .expect("windows-x64 should lazy-load");

    assert_eq!(project.type_archives.len(), before + 1);
    assert_eq!(project.type_archives[idx].name, "windows-x64");
    assert!(project.type_archive_enabled[idx], "newly loaded archive should be enabled");
    // Vec lengths must stay parallel — same invariant the panel relies on.
    assert_eq!(project.type_archives.len(), project.type_archive_enabled.len());
    assert_eq!(project.type_archives.len(), project.type_archive_hits.len());

    // No-op idempotency: a second call returns the same idx, doesn't append.
    let idx2 = project.load_type_archive_by_stem("windows-x64").unwrap();
    assert_eq!(idx, idx2);
    assert_eq!(project.type_archives.len(), before + 1);
}

#[test]
fn disabling_all_type_archives_strips_typed_signatures() {
    let mut project = Project::open(&fixture("pe-mingw32-strip.exe"))
        .expect("open PE fixture");

    // Pick a function whose decompile output currently shows a typed
    // (non-void) signature line. We don't pin a specific symbol — the
    // walker just needs *some* function whose signature changes when
    // archives go away.
    let mut canary: Option<u64> = None;
    for func in project.analysis.functions.iter() {
        let Some(text) = project.decompile(func.entry_address) else {
            continue;
        };
        let first = text.lines().next().unwrap_or("");
        if !first.starts_with("void ") || !first.contains("(void)") {
            // Looks typed (return type isn't void or it has typed args).
            canary = Some(func.entry_address);
            break;
        }
    }
    let Some(addr) = canary else {
        // The PE fixture might in principle have nothing typed; in
        // that case there's nothing to test. The non-zero-hits test
        // above already guards the live case.
        eprintln!("no typed signatures present in PE fixture; toggle test is a noop");
        return;
    };

    let typed_sig = project
        .decompile(addr)
        .and_then(|t| t.lines().next().map(|l| l.to_string()))
        .unwrap_or_default();

    // Disable every type archive.
    for i in 0..project.type_archives.len() {
        project.set_type_archive_enabled(i, false);
    }

    let untyped_sig = project
        .decompile(addr)
        .and_then(|t| t.lines().next().map(|l| l.to_string()))
        .unwrap_or_default();

    assert_ne!(
        typed_sig, untyped_sig,
        "decompile signature for {addr:#x} did not change after disabling \
         all type archives — effective_type_archives may not be wired into \
         the decompile context"
    );
}
