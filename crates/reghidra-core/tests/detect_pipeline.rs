use reghidra_core::project::Project;
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
fn open_yields_empty_detections_when_no_rules_shipped() {
    let p = Project::open(&fixture("wildfire-test-pe-file.exe")).unwrap();
    // Zero bundled rules in the current build (rules/ dir is empty save .gitkeep).
    // generation == 1 proves evaluate_detections ran exactly once during open.
    assert_eq!(p.detections_generation, 1);
    assert_eq!(p.loaded_rule_files.len(), 0);
    assert!(p.detection_results.file_hits.is_empty());
}
