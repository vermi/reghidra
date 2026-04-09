//! End-to-end tests for `reghidra-cli`. We invoke the built binary with
//! `Command::new(env!("CARGO_BIN_EXE_reghidra-cli"))` rather than calling
//! into the library so the test exercises the same surface a Python
//! script or AI agent would touch — clap parsing, JSON shape, exit
//! codes, and session round-trips.
//!
//! Coverage focus:
//!   * `info --json` returns the documented shape
//!   * `sources list` shows non-zero loaded counts on the PE fixture
//!   * `sources resolve` finds a known Win32 import via the type archives
//!   * mutating commands without `--session` exit non-zero (the contract
//!     for "this would have been silently dropped")
//!   * `sources disable` + reload persists the override across invocations
//!   * `annotate rename` round-trips through a session file
//!
//! These tests pin the documented contract for AI agent / Python script
//! consumers. If they fail, the README is wrong or a downstream consumer
//! just got broken.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_reghidra-cli"))
}

fn run_ok(args: &[&str]) -> String {
    let out = cli().args(args).output().expect("cli ran");
    assert!(
        out.status.success(),
        "cli {args:?} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

fn pe() -> PathBuf {
    fixture("wildfire-test-pe-file.exe")
}

fn run_json(args: &[&str]) -> Value {
    let out = cli().args(args).output().expect("cli ran");
    assert!(
        out.status.success(),
        "cli {args:?} failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("cli {args:?} produced invalid JSON: {e}\nstdout={}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn info_json_has_documented_shape() {
    let pe = pe();
    let v = run_json(&["info", "--binary", pe.to_str().unwrap(), "--json"]);
    // Pin the keys downstream consumers will expect — adding fields is
    // non-breaking, removing/renaming is.
    for key in [
        "path",
        "format",
        "architecture",
        "is_64bit",
        "entry_point",
        "sections",
        "symbols",
        "instructions",
        "functions",
        "xrefs",
        "cfgs",
        "strings",
        "bundled_dbs_loaded",
        "user_dbs_loaded",
        "type_archives_loaded",
        "sig_status",
    ] {
        assert!(v.get(key).is_some(), "info JSON missing key '{key}': {v:#}");
    }
    assert_eq!(v["format"], "PE");
    assert!(v["functions"].as_u64().unwrap() > 10);
    assert!(v["type_archives_loaded"].as_u64().unwrap() > 0);
}

#[test]
fn sources_list_reports_loaded_counts() {
    let pe = pe();
    let v = run_json(&[
        "sources",
        "list",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
    ]);
    let bundled = v["bundled"].as_array().expect("bundled is array");
    let archives = v["archives"].as_array().expect("archives is array");
    assert!(!bundled.is_empty(), "PE fixture should have bundled FLIRT dbs");
    assert!(!archives.is_empty(), "PE fixture should load type archives");

    // Total bundled hits across the fixture should be non-zero — this
    // matches the existing `flirt_hit_totals_match_signature_source_count`
    // test in core but exercises it through the CLI surface.
    let total_hits: u64 = bundled
        .iter()
        .map(|db| db["hits"].as_u64().unwrap_or(0))
        .sum();
    assert!(total_hits > 0, "expected bundled hits > 0, got {total_hits}");
}

#[test]
fn sources_resolve_finds_a_win32_import() {
    let pe = pe();
    // CreateFileA is in `windows-x86` (the auto-loaded archive for the
    // PE x86 fixture). The resolve path should find it without an
    // explicit underscore strip.
    let v = run_json(&[
        "sources",
        "resolve",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "CreateFileA",
    ]);
    assert_eq!(v["name"], "CreateFileA");
    let archive = v["archive"].as_str().expect("archive resolved");
    assert!(
        archive.starts_with("windows-") || archive == "rizin-windows",
        "CreateFileA should resolve via a windows-* archive, got {archive}"
    );
}

#[test]
fn mutating_commands_require_session() {
    let pe = pe();
    let out = cli()
        .args([
            "annotate",
            "rename",
            "--binary",
            pe.to_str().unwrap(),
            "0x401000",
            "my_main",
        ])
        .output()
        .expect("cli ran");
    assert!(!out.status.success(), "rename without --session must error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--session"),
        "error message should explain the --session requirement, got: {stderr}"
    );
}

#[test]
fn sources_disable_persists_via_session() {
    let pe = pe();
    let tmp = tempdir();
    let session = tmp.join("session.json");

    // 1. Initialize a session pinned to the PE fixture.
    let out = cli()
        .args([
            "session",
            "init",
            "--binary",
            pe.to_str().unwrap(),
            "--output",
            session.to_str().unwrap(),
        ])
        .output()
        .expect("session init");
    assert!(out.status.success(), "session init failed: {}", String::from_utf8_lossy(&out.stderr));

    // 2. Find the windows-x86 archive in the loaded set.
    let listing = run_json(&[
        "sources",
        "archives",
        "--session",
        session.to_str().unwrap(),
        "--json",
    ]);
    let arr = listing.as_array().expect("archives array");
    let windows = arr
        .iter()
        .find(|a| a["name"].as_str().unwrap_or("").starts_with("windows-"))
        .expect("PE fixture should have a windows-* archive loaded");
    assert_eq!(windows["enabled"], true);
    let stem = windows["name"].as_str().unwrap().to_string();

    // 3. Disable it via the CLI.
    let out = cli()
        .args([
            "sources",
            "disable",
            "--session",
            session.to_str().unwrap(),
            "--kind",
            "archive",
            &stem,
        ])
        .output()
        .expect("disable");
    assert!(
        out.status.success(),
        "disable failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 4. Re-open the session in a fresh invocation; the override should stick.
    let listing2 = run_json(&[
        "sources",
        "archives",
        "--session",
        session.to_str().unwrap(),
        "--json",
    ]);
    let arr2 = listing2.as_array().expect("archives array");
    let windows2 = arr2
        .iter()
        .find(|a| a["name"].as_str().unwrap() == stem)
        .expect("archive still listed after toggle");
    assert_eq!(
        windows2["enabled"], false,
        "disable should persist across CLI invocations via the session file"
    );
}

#[test]
fn rename_function_round_trips_through_session() {
    let pe = pe();
    let tmp = tempdir();
    let session = tmp.join("session.json");

    cli()
        .args([
            "session",
            "init",
            "--binary",
            pe.to_str().unwrap(),
            "--output",
            session.to_str().unwrap(),
        ])
        .output()
        .expect("session init");

    // Pick the entry point — it's guaranteed to be a real function.
    let info = run_json(&["info", "--session", session.to_str().unwrap(), "--json"]);
    let entry = info["entry_point"].as_u64().expect("entry point") as u64;

    let out = cli()
        .args([
            "annotate",
            "rename",
            "--session",
            session.to_str().unwrap(),
            &format!("0x{entry:x}"),
            "renamed_entry_point",
        ])
        .output()
        .expect("rename");
    assert!(
        out.status.success(),
        "rename failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify the rename comes back via `annotate list`.
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        session.to_str().unwrap(),
        "--json",
    ]);
    let renamed = v["renamed_functions"]
        .as_array()
        .expect("renamed_functions array");
    assert!(
        renamed.iter().any(|pair| {
            pair[0].as_u64() == Some(entry) && pair[1] == "renamed_entry_point"
        }),
        "expected rename for 0x{entry:x} to be persisted; got {renamed:?}"
    );
}

#[test]
fn flirt_available_lists_unloaded_sigs() {
    // The PE x86 fixture only auto-loads pe/x86/32 sigs, so pe/x86/64
    // sigs should appear in the --available output marked unloaded.
    let pe = pe();
    let v = run_json(&[
        "sources",
        "flirt",
        "--binary",
        pe.to_str().unwrap(),
        "--available",
        "--json",
    ]);
    let available = v["available"].as_array().expect("available array");
    let any_x64 = available
        .iter()
        .any(|s| s["subdir"] == "pe/x86/64" && s["loaded"] == false);
    assert!(any_x64, "expected at least one unloaded pe/x86/64 sig");
}

// ---------------------------------------------------------------------------
// Read-only inspection commands — one test per subcommand. These pin
// the JSON shape AND the human-readable fallback by asserting both
// produce non-empty output without crashing on the PE fixture.
// ---------------------------------------------------------------------------

#[test]
fn functions_command_with_filters() {
    let pe = pe();
    // Plain table mode.
    let txt = run_ok(&[
        "functions",
        "--binary",
        pe.to_str().unwrap(),
        "--limit",
        "5",
    ]);
    assert!(txt.contains("ADDR"), "functions table should have ADDR header: {txt}");

    // JSON mode with --source filter.
    let v = run_json(&[
        "functions",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--source",
        "Signature",
        "--limit",
        "3",
    ]);
    let arr = v.as_array().expect("functions array");
    assert!(!arr.is_empty(), "fixture should have Signature-source functions");
    for f in arr {
        assert_eq!(f["source"], "Signature");
        for key in ["address", "name", "display_name", "instructions", "blocks", "xrefs_to", "matched_signature_db"] {
            assert!(f.get(key).is_some(), "function JSON missing {key}");
        }
    }

    // --name filter. `realloc` appears as `__realloc_crt` via the
    // Microsoft Visual Studio 2008 FLIRT sig on the PE fixture.
    let v = run_json(&[
        "functions",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--name",
        "realloc",
    ]);
    let arr = v.as_array().expect("functions array");
    assert!(
        !arr.is_empty(),
        "PE fixture should have at least one function with 'realloc' in the name"
    );
}

#[test]
fn sections_command_table_and_json() {
    let pe = pe();
    let txt = run_ok(&["sections", "--binary", pe.to_str().unwrap()]);
    assert!(txt.contains(".text"), "sections should list .text: {txt}");

    let v = run_json(&["sections", "--binary", pe.to_str().unwrap(), "--json"]);
    let arr = v.as_array().expect("sections array");
    let text = arr
        .iter()
        .find(|s| s["name"] == ".text")
        .expect(".text section");
    assert_eq!(text["executable"], true);
}

#[test]
fn strings_command_with_pattern_filter() {
    let pe = pe();
    let v = run_json(&[
        "strings",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--pattern",
        ".dll",
        "--limit",
        "5",
    ]);
    let arr = v.as_array().expect("strings array");
    assert!(!arr.is_empty(), "PE fixture should have .dll-substring strings");
    for s in arr {
        assert!(
            s["value"].as_str().unwrap().to_lowercase().contains(".dll"),
            "pattern filter not applied: {s}"
        );
    }
}

#[test]
fn xrefs_to_and_from_an_address() {
    let pe = pe();
    // Find a function with at least 2 xrefs to it via the listing.
    let funcs = run_json(&[
        "functions",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--limit",
        "0",
    ]);
    let target = funcs
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["xrefs_to"].as_u64().unwrap_or(0) >= 2)
        .expect("at least one function should have ≥2 xrefs to it");
    let addr = format!("0x{:x}", target["address"].as_u64().unwrap());

    // --to: who calls this function
    let v = run_json(&[
        "xrefs",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--to",
        &addr,
    ]);
    let xs = v.as_array().expect("xrefs array");
    assert!(!xs.is_empty(), "expected xrefs TO {addr}");
    for x in xs {
        for key in ["from", "to", "kind"] {
            assert!(x.get(key).is_some(), "xref missing {key}");
        }
    }

    // --from: same address but it's a function entry; usually has at
    // least one xref out (the first call). Don't assert non-empty here
    // since some functions are tiny stubs — just assert the call works.
    let _ = run_ok(&[
        "xrefs",
        "--binary",
        pe.to_str().unwrap(),
        "--from",
        &addr,
    ]);
}

#[test]
fn decompile_disasm_ir_cfg_for_entry_point() {
    let pe = pe();
    let info = run_json(&["info", "--binary", pe.to_str().unwrap(), "--json"]);
    let entry = format!("0x{:x}", info["entry_point"].as_u64().unwrap());

    // decompile (text + json modes)
    let txt = run_ok(&["decompile", "--binary", pe.to_str().unwrap(), &entry]);
    assert!(!txt.trim().is_empty(), "decompile should produce text");
    let v = run_json(&[
        "decompile",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        &entry,
    ]);
    assert!(v["decompiled"].as_str().unwrap().len() > 0);

    // disasm
    let v = run_json(&[
        "disasm",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--count",
        "5",
        &entry,
    ]);
    let insns = v.as_array().expect("disasm array");
    assert!(!insns.is_empty());
    assert!(insns[0]["mnemonic"].as_str().is_some());

    // ir
    let v = run_json(&[
        "ir",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        &entry,
    ]);
    assert!(v["ir"].as_str().unwrap().len() > 0);

    // cfg
    let v = run_json(&[
        "cfg",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        &entry,
    ]);
    assert!(v["blocks"].is_array());
    assert!(v["edges"].is_array());
}

#[test]
fn find_command_substring_match() {
    let pe = pe();
    // `realloc` appears as `__realloc_crt` via the Microsoft Visual
    // Studio 2008 FLIRT sig on the PE fixture.
    let v = run_json(&[
        "find",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "realloc",
    ]);
    let hits = v.as_array().expect("find array");
    assert!(!hits.is_empty(), "find 'realloc' should match");
}

#[test]
fn disasm_default_address_is_entry_point() {
    let pe = pe();
    let info = run_json(&["info", "--binary", pe.to_str().unwrap(), "--json"]);
    let entry = info["entry_point"].as_u64().unwrap();

    // No address arg → starts at entry point.
    let v = run_json(&[
        "disasm",
        "--binary",
        pe.to_str().unwrap(),
        "--json",
        "--count",
        "1",
    ]);
    let arr = v.as_array().unwrap();
    assert_eq!(
        arr[0]["address"].as_u64().unwrap(),
        entry,
        "disasm default should start at entry point"
    );
}

// ---------------------------------------------------------------------------
// Mutating commands — one test per `annotate` subcommand. These verify
// the mutation lands in the session JSON via `annotate list --json` so
// every code path through the dispatcher is exercised end-to-end.
// ---------------------------------------------------------------------------

fn fresh_session(name: &str) -> PathBuf {
    let tmp = tempdir();
    let session = tmp.join(format!("{name}.json"));
    let pe = pe();
    let out = cli()
        .args([
            "session",
            "init",
            "--binary",
            pe.to_str().unwrap(),
            "--output",
            session.to_str().unwrap(),
        ])
        .output()
        .expect("session init");
    assert!(out.status.success());
    session
}

#[test]
fn annotate_comment_round_trips() {
    let s = fresh_session("comment");
    run_ok(&[
        "annotate",
        "comment",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
        "hello world",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let comments = v["comments"].as_array().unwrap();
    assert!(comments.iter().any(|c| c[0] == 0x401000 && c[1] == "hello world"));

    // Empty text clears.
    run_ok(&[
        "annotate",
        "comment",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
        "",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    assert!(v["comments"].as_array().unwrap().is_empty());
}

#[test]
fn annotate_rename_label_round_trips() {
    let s = fresh_session("rename_label");
    run_ok(&[
        "annotate",
        "rename-label",
        "--session",
        s.to_str().unwrap(),
        "0x401050",
        "my_label",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    assert!(v["label_names"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l[0] == 0x401050 && l[1] == "my_label"));
}

#[test]
fn annotate_rename_var_round_trips() {
    let s = fresh_session("rename_var");
    run_ok(&[
        "annotate",
        "rename-var",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
        "arg_8",
        "buffer",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let vars = v["variable_names"].as_array().unwrap();
    assert!(
        vars.iter().any(|p| p[0][0] == 0x401000 && p[0][1] == "arg_8" && p[1] == "buffer"),
        "rename-var did not persist: {vars:#?}"
    );
}

#[test]
fn annotate_retype_round_trips() {
    let s = fresh_session("retype");
    run_ok(&[
        "annotate",
        "retype",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
        "local_4",
        "uint32_t",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let types = v["variable_types"].as_array().unwrap();
    assert!(
        types.iter().any(|p| p[0][0] == 0x401000 && p[0][1] == "local_4" && p[1] == "uint32_t"),
        "retype did not persist"
    );
}

#[test]
fn annotate_bookmark_and_unbookmark() {
    let s = fresh_session("bookmark");
    run_ok(&[
        "annotate",
        "bookmark",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    assert!(v["bookmarks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a.as_u64() == Some(0x401000)));

    // Idempotent (no duplicate).
    run_ok(&[
        "annotate",
        "bookmark",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let count = v["bookmarks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a.as_u64() == Some(0x401000))
        .count();
    assert_eq!(count, 1, "bookmark should be idempotent");

    run_ok(&[
        "annotate",
        "unbookmark",
        "--session",
        s.to_str().unwrap(),
        "0x401000",
    ]);
    let v = run_json(&[
        "annotate",
        "list",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    assert!(!v["bookmarks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a.as_u64() == Some(0x401000)));
}

// ---------------------------------------------------------------------------
// `sources` mutating commands — exercise enable / lazy load paths
// for every kind, including the bundled and user variants the original
// test suite missed.
// ---------------------------------------------------------------------------

#[test]
fn sources_enable_disable_bundled_round_trips() {
    let s = fresh_session("bundled_toggle");
    let listing = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let key = listing["bundled"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["enabled"] == true)
        .expect("at least one enabled bundled db")
        ["key"]
        .as_str()
        .unwrap()
        .to_string();

    run_ok(&[
        "sources",
        "disable",
        "--session",
        s.to_str().unwrap(),
        "--kind",
        "bundled",
        &key,
    ]);
    let v = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let row = v["bundled"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["key"] == key.as_str())
        .expect("toggled row still present");
    assert_eq!(row["enabled"], false);

    // Re-enable.
    run_ok(&[
        "sources",
        "enable",
        "--session",
        s.to_str().unwrap(),
        "--kind",
        "bundled",
        &key,
    ]);
    let v = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let row = v["bundled"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["key"] == key.as_str())
        .unwrap();
    assert_eq!(row["enabled"], true);
}

#[test]
fn sources_load_archive_persists() {
    let s = fresh_session("load_archive");
    // windows-x64 is NOT auto-loaded for the PE x86 fixture.
    run_ok(&[
        "sources",
        "load-archive",
        "--session",
        s.to_str().unwrap(),
        "windows-x64",
    ]);
    let v = run_json(&[
        "sources",
        "archives",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    assert!(v
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["name"] == "windows-x64"));
}

#[test]
fn sources_load_sig_persists_unloaded_subdir() {
    let s = fresh_session("load_sig");
    // Pick any sig from a NOT-loaded subdir on the PE x86 fixture and
    // load it. We use the --available enumeration to find one
    // dynamically so this test doesn't break when sig fixtures change.
    let v = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--available",
        "--json",
    ]);
    let target = v["available"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["loaded"] == false)
        .expect("at least one unloaded embedded sig");
    let subdir = target["subdir"].as_str().unwrap().to_string();
    let stem = target["stem"].as_str().unwrap().to_string();

    run_ok(&[
        "sources",
        "load-sig",
        "--session",
        s.to_str().unwrap(),
        "--subdir",
        &subdir,
        "--stem",
        &stem,
    ]);
    let v = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let key = format!("{subdir}/{stem}");
    assert!(
        v["bundled"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["key"] == key.as_str()),
        "loaded sig {key} should appear in bundled list"
    );
}

#[test]
fn sources_load_user_sig_and_toggle() {
    let s = fresh_session("user_sig");
    // Load a real bundled .sig file from disk via the user path.
    let sig_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("signatures/pe/x86/32");
    let any_sig = std::fs::read_dir(&sig_path)
        .expect("signatures dir")
        .filter_map(|e| e.ok())
        .find(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sig"))
        .expect("at least one .sig file");

    run_ok(&[
        "sources",
        "load-user-sig",
        "--session",
        s.to_str().unwrap(),
        any_sig.path().to_str().unwrap(),
    ]);
    let v = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let user = v["user"].as_array().unwrap();
    assert!(!user.is_empty(), "user-loaded sig should appear in user list");

    // Toggle the user db off and back on by header name.
    let user_key = user[0]["key"].as_str().unwrap().to_string();
    run_ok(&[
        "sources",
        "disable",
        "--session",
        s.to_str().unwrap(),
        "--kind",
        "user",
        &user_key,
    ]);
    let v = run_json(&[
        "sources",
        "flirt",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        v["user"].as_array().unwrap()[0]["enabled"],
        false,
        "user db disable should persist"
    );
}

// ---------------------------------------------------------------------------
// `session` subcommand surface — show + refresh
// ---------------------------------------------------------------------------

#[test]
fn session_show_returns_valid_json() {
    let s = fresh_session("show");
    let txt = run_ok(&["session", "show", s.to_str().unwrap()]);
    let v: Value = serde_json::from_str(&txt).expect("session show is valid JSON");
    assert!(v.get("binary_path").is_some());
    assert!(v.get("data_source_overrides").is_some());
}

#[test]
fn session_refresh_preserves_overrides() {
    let s = fresh_session("refresh");
    // Disable a known archive.
    let archives = run_json(&[
        "sources",
        "archives",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let name = archives.as_array().unwrap()[0]["name"]
        .as_str()
        .unwrap()
        .to_string();
    run_ok(&[
        "sources",
        "disable",
        "--session",
        s.to_str().unwrap(),
        "--kind",
        "archive",
        &name,
    ]);

    // Refresh and confirm the override survives.
    run_ok(&["session", "refresh", s.to_str().unwrap()]);
    let v = run_json(&[
        "sources",
        "archives",
        "--session",
        s.to_str().unwrap(),
        "--json",
    ]);
    let row = v
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == name.as_str())
        .unwrap();
    assert_eq!(row["enabled"], false, "session refresh dropped override");
}

// ---------------------------------------------------------------------------
// Tiny tempdir helper — std::env::temp_dir + a uniqueness counter is enough
// for this test surface and avoids the `tempfile` dep.
// ---------------------------------------------------------------------------

fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("reghidra-cli-test-{pid}-{id}"));
    std::fs::create_dir_all(&path).expect("create tempdir");
    path
}
