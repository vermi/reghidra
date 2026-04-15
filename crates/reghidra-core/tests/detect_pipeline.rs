use reghidra_core::project::Project;
use std::io::Write;
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
fn open_loads_bundled_rules_and_evaluates() {
    let p = Project::open(&fixture("wildfire-test-pe-file.exe")).unwrap();
    // Bundled rules are now shipped and auto-loaded on open. The
    // generation counter is bumped once per evaluate_detections call;
    // with N bundled rule files it starts at N (one call per file loaded).
    assert!(p.detections_generation >= 1);
    // At least one bundled rule file is present.
    assert!(!p.loaded_rule_files.is_empty());
}

fn write_rule_file(path: &std::path::Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    writeln!(f, "{content}").unwrap();
}

#[test]
fn load_user_rule_file_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("test.yml");
    write_rule_file(
        &rule_path,
        "rule: { name: test_rule, severity: info, scope: file, description: \"\", \
         features: { overlay: false } }",
    );

    let mut proj = Project::open(&fixture("wildfire-test-pe-file.exe")).unwrap();
    let gen_before = proj.detections_generation;

    let count_before = proj.loaded_rule_files.len();
    proj.load_user_rule_file(&rule_path).unwrap();
    assert_eq!(
        proj.loaded_rule_files.len(),
        count_before + 1,
        "first load adds entry"
    );
    let gen_after_first = proj.detections_generation;
    assert!(gen_after_first > gen_before, "generation bumped on first load");

    // Second call with the same path must be a no-op.
    proj.load_user_rule_file(&rule_path).unwrap();
    assert_eq!(
        proj.loaded_rule_files.len(),
        count_before + 1,
        "second load is idempotent"
    );
    assert_eq!(
        proj.detections_generation, gen_after_first,
        "generation not bumped on duplicate load"
    );
}

#[test]
fn disable_rule_file_bumps_generation() {
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("rule2.yml");
    write_rule_file(
        &rule_path,
        "rule: { name: disable_test, severity: medium, scope: file, description: \"\", \
         features: { overlay: false } }",
    );

    let mut proj = Project::open(&fixture("wildfire-test-pe-file.exe")).unwrap();
    proj.load_user_rule_file(&rule_path).unwrap();

    let abs = rule_path.canonicalize().unwrap();
    let source_path = abs.to_string_lossy().to_string();
    let gen_before_disable = proj.detections_generation;

    proj.set_rule_file_enabled(&source_path, false);

    assert!(proj.detections_generation > gen_before_disable, "generation bumps on disable");
    let rf = proj
        .loaded_rule_files
        .iter()
        .find(|f| f.source_path == source_path)
        .expect("rule file entry must exist");
    assert!(!rf.enabled, "file should be disabled");
}

#[test]
fn session_round_trip_preserves_rule_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let rule_path = dir.path().join("mine.yml");
    write_rule_file(
        &rule_path,
        "rule: { name: x, severity: info, scope: file, description: \"\", \
         features: { overlay: false } }",
    );

    let mut proj = Project::open(&fixture("wildfire-test-pe-file.exe")).unwrap();
    proj.load_user_rule_file(&rule_path).unwrap();

    let abs = rule_path.canonicalize().unwrap();
    let source_path = abs.to_string_lossy().to_string();
    proj.set_rule_file_enabled(&source_path, false);

    let sess = proj.to_session();

    let mut proj2 = Project::open(&fixture("wildfire-test-pe-file.exe")).unwrap();
    proj2.apply_session(sess);

    let rf = proj2
        .loaded_rule_files
        .iter()
        .find(|f| f.source_path == source_path)
        .expect("rule file reloaded into proj2");
    assert!(!rf.enabled, "disabled override survives round-trip");
}
