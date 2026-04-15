use reghidra_detect::*;
use std::collections::HashMap;

fn pe_feats() -> Features {
    let mut by_function = HashMap::new();
    by_function.insert(0x1000, FunctionFeatures {
        name: "sub_1000".into(),
        apis: vec!["IsDebuggerPresent".into(), "Sleep".into()],
        string_refs: vec!["MZ".into()],
        mnemonics: vec!["push".into(), "cpuid".into(), "rdtsc".into(), "rdtsc".into()],
        xref_in_count: 3,
        xref_out_count: 2,
    });
    Features {
        file: FileFeatures {
            format: BinaryFormat::Pe,
            imports: vec![Import { lib: "kernel32.dll".into(), sym: "IsDebuggerPresent".into() }],
            strings: vec!["DEBUG".into()],
            sections: vec![SectionInfo {
                name: ".text".into(), size: 0x1000, entropy: 6.3,
                writable: false, executable: true,
            }],
            pe: Some(PeFeatures::default()),
        },
        by_function,
    }
}

fn parse_one(y: &str) -> Rule {
    parse_rules_from_str(y, "inline").unwrap().into_iter().next().unwrap()
}

fn rule(y: &str) -> Rule { parse_one(y) }

#[test]
fn mnemonic_matches() {
    let r = rule("rule: { name: t, severity: info, scope: function, description: '',
                  features: { mnemonic: rdtsc } }");
    let hits = evaluate(&[r], &pe_feats());
    assert_eq!(hits.function_hits.get(&0x1000).map(|v| v.len()), Some(1));
}

#[test]
fn mnemonic_mismatch() {
    let r = rule("rule: { name: t, severity: info, scope: function, description: '',
                  features: { mnemonic: syscall } }");
    let hits = evaluate(&[r], &pe_feats());
    assert!(hits.function_hits.is_empty());
}

#[test]
fn import_file_scope() {
    let r = rule("rule: { name: t, severity: info, scope: file, description: '',
                  features: { import: { lib: kernel32.dll, sym: IsDebuggerPresent } } }");
    let hits = evaluate(&[r], &pe_feats());
    assert_eq!(hits.file_hits.len(), 1);
}

#[test]
fn count_wrapper() {
    let r = rule("rule: { name: t, severity: info, scope: function, description: '',
                  features: { count: { feature: { mnemonic: rdtsc }, min: 2 } } }");
    assert_eq!(evaluate(&[r], &pe_feats()).function_hits.get(&0x1000).map(|v| v.len()), Some(1));
}

#[test]
fn and_or_not() {
    let r = rule(r#"
rule:
  name: t
  severity: info
  scope: function
  description: ""
  features:
    and:
      - mnemonic: cpuid
      - not:
          mnemonic: syscall
      - or:
          - mnemonic: rdtsc
          - mnemonic: nonexistent
"#);
    assert_eq!(evaluate(&[r], &pe_feats()).function_hits.get(&0x1000).map(|v| v.len()), Some(1));
}

#[test]
fn section_entropy_gt() {
    let r = rule(r#"
rule: { name: t, severity: info, scope: file, description: "",
        features: { section: { entropy: { op: gt, value: 6.0 } } } }
"#);
    assert_eq!(evaluate(&[r], &pe_feats()).file_hits.len(), 1);
}

#[test]
fn matches_references_other_rule() {
    let a = rule("rule: { name: has-rdtsc, severity: info, scope: function, description: '',
                  features: { mnemonic: rdtsc } }");
    let b = rule("rule: { name: aggregator, severity: suspicious, scope: file, description: '',
                  features: { matches: has-rdtsc } }");
    let hits = evaluate(&[a, b], &pe_feats());
    assert_eq!(hits.file_hits.len(), 1);
    assert_eq!(hits.file_hits[0].rule_name, "aggregator");
}
