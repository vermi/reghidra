use reghidra_detect::{parse_rules_from_str, Severity, Scope};

#[test]
fn parses_single_mnemonic_rule() {
    let yaml = r#"
rule:
  name: anti-debug.rdtsc
  severity: suspicious
  scope: function
  description: RDTSC present.
  features:
    mnemonic: rdtsc
"#;
    let rules = parse_rules_from_str(yaml, "inline").unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "anti-debug.rdtsc");
    assert_eq!(rules[0].severity, Severity::Suspicious);
    assert_eq!(rules[0].scope, Scope::Function);
}

#[test]
fn parses_rules_list_form() {
    let yaml = r#"
rules:
  - name: a
    severity: info
    scope: file
    description: ""
    features: { mnemonic: cpuid }
  - name: b
    severity: malicious
    scope: function
    description: ""
    features: { mnemonic: rdtsc }
"#;
    let rules = parse_rules_from_str(yaml, "inline").unwrap();
    assert_eq!(rules.len(), 2);
}

use reghidra_detect::{FeatureExpr, StrMatcher, Comparison};

fn single(y: &str) -> FeatureExpr {
    let rules = parse_rules_from_str(y, "inline").expect("parse");
    rules.into_iter().next().unwrap().expr
}

fn wrap(feat: &str) -> String {
    format!("rule:\n  name: t\n  severity: info\n  scope: function\n  description: \"\"\n  features:\n    {feat}\n")
}

#[test]
fn parses_import() {
    let e = single(&wrap("import: { lib: kernel32.dll, sym: VirtualAlloc }"));
    assert!(matches!(e, FeatureExpr::Import { .. }));
}

#[test]
fn parses_api_regex() {
    let e = single(&wrap("api: /crypt.*/i"));
    match e {
        FeatureExpr::Api(StrMatcher::Regex(r)) => assert!(r.is_match("CryptAcquireContextA")),
        _ => panic!("expected regex Api"),
    }
}

#[test]
fn parses_string_literal() {
    let e = single(&wrap("string: \"IsDebuggerPresent\""));
    assert!(matches!(e, FeatureExpr::StringFeature(StrMatcher::Literal(s)) if s == "IsDebuggerPresent"));
}

#[test]
fn parses_name() {
    let _ = single(&wrap("name: /^sub_/"));
}

#[test]
fn parses_section_entropy() {
    let e = single(&wrap("section: { entropy: { op: gt, value: 7.5 } }"));
    match e {
        FeatureExpr::Section { entropy_cmp: Some((Comparison::Gt, v)), .. } => {
            assert!((v - 7.5).abs() < 1e-9);
        }
        _ => panic!("expected entropy comparison"),
    }
}

#[test]
fn parses_section_wx() {
    let e = single(&wrap("section: { wx: true }"));
    match e {
        FeatureExpr::Section { wx: Some(true), .. } => {}
        _ => panic!("expected wx=true"),
    }
}

#[test]
fn parses_rich_comp_id() {
    let e = single(&wrap("rich_comp_id: 259"));
    assert!(matches!(e, FeatureExpr::RichCompId(259)));
}

#[test]
fn parses_imphash_list() {
    let e = single(&wrap("imphash: [\"aabbcc\", \"ddeeff\"]"));
    match e {
        FeatureExpr::Imphash(v) => assert_eq!(v, vec!["aabbcc", "ddeeff"]),
        _ => panic!("expected Imphash"),
    }
}

#[test]
fn parses_tls_and_overlay() {
    assert!(matches!(single(&wrap("tls_callbacks: true")), FeatureExpr::TlsCallbacks(true)));
    assert!(matches!(single(&wrap("overlay: true")), FeatureExpr::Overlay(true)));
}

#[test]
fn parses_mnemonic_sequence() {
    let e = single(&wrap("mnemonic_sequence: [cpuid, rdtsc]"));
    match e {
        FeatureExpr::MnemonicSequence(v) => assert_eq!(v.len(), 2),
        _ => panic!("expected MnemonicSequence"),
    }
}

#[test]
fn parses_xrefs_to_min() {
    let e = single(&wrap("xrefs_to: { min: 3 }"));
    match e {
        FeatureExpr::XrefsTo(r) => { assert_eq!(r.min, 3); assert!(r.max.is_none()); }
        _ => panic!(),
    }
}

#[test]
fn parses_matches() {
    let e = single(&wrap("matches: some-other-rule"));
    assert!(matches!(e, FeatureExpr::Matches(ref s) if s == "some-other-rule"));
}

#[test]
fn parses_and_or_not() {
    let y = r#"
rule:
  name: t
  severity: info
  scope: function
  description: ""
  features:
    and:
      - mnemonic: rdtsc
      - or:
          - mnemonic: cpuid
          - not:
              mnemonic: syscall
"#;
    match single_expr(y) {
        FeatureExpr::And(v) => {
            assert_eq!(v.len(), 2);
            assert!(matches!(v[1], FeatureExpr::Or(_)));
        }
        _ => panic!(),
    }
}

#[test]
fn parses_n_or_more() {
    let y = r#"
rule:
  name: t
  severity: info
  scope: function
  description: ""
  features:
    n_or_more:
      n: 3
      of:
        - mnemonic: rdtsc
        - mnemonic: cpuid
        - mnemonic: in
        - mnemonic: out
"#;
    match single_expr(y) {
        FeatureExpr::NorMore { n, of } => { assert_eq!(n, 3); assert_eq!(of.len(), 4); }
        _ => panic!(),
    }
}

#[test]
fn parses_bare_list_as_and() {
    let y = r#"
rule:
  name: t
  severity: info
  scope: function
  description: ""
  features:
    - mnemonic: rdtsc
    - mnemonic: cpuid
"#;
    assert!(matches!(single_expr(y), FeatureExpr::And(v) if v.len() == 2));
}

#[test]
fn parses_count_wrapper() {
    let y = r#"
rule:
  name: t
  severity: info
  scope: function
  description: ""
  features:
    count:
      feature:
        mnemonic: rdtsc
      min: 2
"#;
    match single_expr(y) {
        FeatureExpr::Count { range, .. } => assert_eq!(range.min, 2),
        _ => panic!(),
    }
}

fn single_expr(y: &str) -> FeatureExpr {
    parse_rules_from_str(y, "inline").unwrap().into_iter().next().unwrap().expr
}
