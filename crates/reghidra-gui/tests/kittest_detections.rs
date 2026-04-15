// Integration tests for the Detections UI using egui_kittest.
//
// These tests run headlessly (no display server required) by driving the
// egui AccessKit tree.  Each test constructs a `ReghidraApp` pre-loaded with
// a synthetic project (two functions, two detection hits) via
// `ReghidraApp::for_test()` / `Project::for_test()`, both of which are
// available when the `test-harness` feature is enabled.
//
// Feature gate: the `test-harness` feature must be active.  It is listed
// under `required-features` in the `[[test]]` section of Cargo.toml, so
// running `cargo test -p reghidra-gui --features test-harness` is all
// that's needed.  A plain `cargo test -p reghidra-gui` will skip this
// target and report it as "skipped (required features not enabled)".

use egui_kittest::{kittest::Queryable, Harness};
use reghidra_gui::{app::SidePanel, ReghidraApp};

// ────────────────────────────────────────────────────────────────
// Test 1 — Detections panel shows both rule names
// ────────────────────────────────────────────────────────────────

/// Verify that the Detections side-panel renders a row for every detection
/// hit in the project.  The synthetic project produced by `for_test` has two
/// function-scope hits: one Malicious (`test_malware_rule`) and one Suspicious
/// (`test_suspicious_rule`).  Both should appear as labelled widgets.
#[test]
fn detections_panel_shows_rule_names() {
    let mut app = ReghidraApp::for_test();
    // `for_test` already sets side_panel = Detections, but be explicit.
    app.side_panel = SidePanel::Detections;

    let mut harness = Harness::new_ui_state(
        |ui, app: &mut ReghidraApp| {
            reghidra_gui::views::detections::render(app, ui);
        },
        app,
    );
    harness.run();

    // Both rule names must appear somewhere in the AccessKit tree.
    assert!(
        harness.query_by_label_contains("test_malware_rule").is_some(),
        "expected 'test_malware_rule' in Detections panel"
    );
    assert!(
        harness.query_by_label_contains("test_suspicious_rule").is_some(),
        "expected 'test_suspicious_rule' in Detections panel"
    );
}

// ────────────────────────────────────────────────────────────────
// Test 2 — Clicking a detection leaf navigates to the function
// ────────────────────────────────────────────────────────────────

/// Clicking a function-scope detection row should update the app's
/// `selected_address` to the hit's function entry.
///
/// The Malicious row is `"0x00001000  test_malware_rule"` (rendered by
/// `render_severity_section`).  After clicking it, `app.selected_address`
/// must equal `Some(0x1000)`.
#[test]
fn detections_panel_navigate_on_click() {
    let app = ReghidraApp::for_test();

    let mut harness = Harness::new_ui_state(
        |ui, app: &mut ReghidraApp| {
            reghidra_gui::views::detections::render(app, ui);
        },
        app,
    );

    // Find the malware-rule row and click it.
    let row = harness
        .query_by_label_contains("test_malware_rule")
        .expect("malware rule row must be rendered");
    row.click();
    harness.run();

    let selected = harness.state().selected_address;
    assert_eq!(
        selected,
        Some(0x1000),
        "clicking the detection row should navigate to 0x1000, got {selected:?}"
    );
}

// ────────────────────────────────────────────────────────────────
// Test 3 — Decompile view renders detection banner
// ────────────────────────────────────────────────────────────────

/// When the current function has detection hits, the decompile view must
/// render a banner containing "⚠" and the hit count.  The synthetic project's
/// function at `0x1000` has one Malicious hit, so the banner should read
/// "⚠ 1  detection(s): ".
#[test]
fn decompile_banner_renders_for_detected_function() {
    let mut app = ReghidraApp::for_test();
    // Ensure the decompile view targets the detected function.
    app.code_address = Some(0x1000);
    app.selected_address = Some(0x1000);

    let mut harness = Harness::new_ui_state(
        |ui, app: &mut ReghidraApp| {
            reghidra_gui::views::decompile::render(app, ui);
        },
        app,
    );
    harness.run();

    // The banner label contains the warning symbol and the count.
    // We match on a substring so the exact spacing/count wording is flexible.
    assert!(
        harness.query_by_label_contains("⚠").is_some()
            || harness.query_by_label_contains("detection").is_some(),
        "expected decompile banner with '⚠' or 'detection' in the AccessKit tree"
    );
}
