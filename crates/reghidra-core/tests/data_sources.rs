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
fn pe_fixture_reports_nonzero_type_archive_hits() {
    let project = Project::open(&fixture("wildfire-test-pe-file.exe"))
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
    let project = Project::open(&fixture("wildfire-test-pe-file.exe"))
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
    let mut project = Project::open(&fixture("wildfire-test-pe-file.exe"))
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
fn disabling_all_type_archives_strips_typed_signatures() {
    let mut project = Project::open(&fixture("wildfire-test-pe-file.exe"))
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
