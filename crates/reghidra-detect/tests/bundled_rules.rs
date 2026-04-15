//! One synthetic-Features unit test per bundled rule.
//! For each rule we (a) build a Features that MUST fire it and (b) one that MUST NOT.

use reghidra_detect::*;
use std::collections::HashMap;

fn empty_feats() -> Features { Features::default() }

fn one_fn(mnemonics: Vec<&str>, apis: Vec<&str>, strings: Vec<&str>) -> Features {
    let mut bf = HashMap::new();
    bf.insert(0x1000, FunctionFeatures {
        name: "t".into(),
        apis: apis.into_iter().map(String::from).collect(),
        string_refs: strings.into_iter().map(String::from).collect(),
        mnemonics: mnemonics.into_iter().map(String::from).collect(),
        xref_in_count: 0, xref_out_count: 0,
    });
    Features { by_function: bf, ..Features::default() }
}

fn load(stem_subdir: &str, stem: &str) -> Vec<Rule> {
    let path = format!("{stem_subdir}/{stem}.yml");
    let src = bundled_rule_contents(&path).expect("bundled rule exists");
    parse_rules_from_str(src, &path).expect("parses")
}

#[test]
fn rdtsc_timing_fires_on_two_rdtscs() {
    let rules = load("anti_analysis", "rdtsc-timing");
    let feats = one_fn(vec!["push", "rdtsc", "mov", "rdtsc"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 1);
}

#[test]
fn rdtsc_timing_no_fire_on_single_rdtsc() {
    let rules = load("anti_analysis", "rdtsc-timing");
    let feats = one_fn(vec!["rdtsc"], vec![], vec![]);
    assert_eq!(evaluate(&rules, &feats).function_hits.len(), 0);
}
