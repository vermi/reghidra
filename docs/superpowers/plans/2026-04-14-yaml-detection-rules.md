# YAML Detection Rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reghidra-native YAML rule engine for malicious/suspicious behavior detection, wired into the existing FLIRT/type-archive data-source pattern, with ~40–60 bundled rules and full CLI/GUI parity.

**Architecture:** New `reghidra-detect` crate owns the rule AST, YAML parser, `Features` snapshot, and evaluator. `reghidra-core::project::Project` computes `DetectionResults` as a post-analysis step and exposes lazy-load/enable/disable hooks that mirror the existing `bundled_sigs` / `type_archive` surfaces. CLI and GUI consume `DetectionResults` + new `sources rules *` commands.

**Tech Stack:** Rust, `serde_yaml`, `regex`, `include_dir`, egui. Follows Phase 5c action-queue / enumerate-all-lazy-load / session-round-trip conventions already in the codebase.

**Spec:** `docs/superpowers/specs/2026-04-14-yaml-detection-rules-design.md` — read this before starting.

**Branch:** `detections-yaml-rules` (already created).

---

## File Structure

### New files

- `crates/reghidra-detect/Cargo.toml` — crate manifest
- `crates/reghidra-detect/src/lib.rs` — public API re-exports
- `crates/reghidra-detect/src/entropy.rs` — Shannon entropy helper
- `crates/reghidra-detect/src/features.rs` — `Features` snapshot types + builder signature
- `crates/reghidra-detect/src/rule.rs` — `Rule`, `FeatureExpr`, `Severity`, `Scope`, `CompileError`
- `crates/reghidra-detect/src/parser.rs` — YAML → compiled `Rule`
- `crates/reghidra-detect/src/eval.rs` — evaluator
- `crates/reghidra-detect/src/bundled.rs` — `include_dir!("../../rules")` + `available_bundled_rulefiles`
- `crates/reghidra-detect/tests/parser.rs` — parser unit tests
- `crates/reghidra-detect/tests/eval.rs` — evaluator unit tests
- `crates/reghidra-detect/tests/bundled_rules.rs` — one sanity test per bundled rule
- `rules/README.md` — authoring guide
- `rules/<category>/<rule>.yml` — ~40–60 bundled rules
- `crates/reghidra-gui/src/views/detections.rs` — new panel
- `crates/reghidra-core/tests/detect_pipeline.rs` — end-to-end integration test

### Modified files

- `Cargo.toml` (workspace) — add member, shared deps
- `crates/reghidra-core/Cargo.toml` — depend on `reghidra-detect`
- `crates/reghidra-core/src/binary.rs` — per-section entropy on `LoadedSection`
- `crates/reghidra-core/src/lib.rs` — re-export detect types
- `crates/reghidra-core/src/project.rs` — `DetectionResults`, pipeline integration, lazy-load, Session fields
- `crates/reghidra-cli/src/main.rs` — `detect list`, `sources rules *`
- `crates/reghidra-cli/tests/cli.rs` — new CLI tests
- `crates/reghidra-cli/README.md` — document new commands
- `crates/reghidra-gui/src/app.rs` — `detections_generation` counter, panel toggle
- `crates/reghidra-gui/src/views/data_sources.rs` — rules section
- `crates/reghidra-gui/src/views/decompile.rs` — detections banner
- `crates/reghidra-gui/src/views/side_panel.rs` — wire in detections panel
- `crates/reghidra-gui/src/palette.rs` — new commands

### Suggested subagent dispatch

Tasks 16A–16G (bundled rule authoring) are the only parallelizable chunk. Everything else builds on the previous task and should run sequentially. The user explicitly authorized subagents — use `superpowers:dispatching-parallel-agents` for 16A–16G after Task 15 lands the rule-test pattern.

---

## Task 1: Scaffold `reghidra-detect` crate

**Files:**
- Create: `crates/reghidra-detect/Cargo.toml`
- Create: `crates/reghidra-detect/src/lib.rs`
- Modify: `Cargo.toml` (workspace root) — add to `members`

- [ ] **Step 1: Write the crate manifest**

`crates/reghidra-detect/Cargo.toml`:
```toml
[package]
name = "reghidra-detect"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde = { workspace = true, features = ["derive"] }
serde_yaml = "0.9"
regex = "1"
include_dir = "0.7"
thiserror = { workspace = true }

[dev-dependencies]
# none yet
```

- [ ] **Step 2: Write the lib skeleton**

`crates/reghidra-detect/src/lib.rs`:
```rust
//! YAML-driven detection engine for reghidra.
//!
//! Evaluates declarative rules against a [`Features`] snapshot derived from a
//! [`reghidra_core::project::Project`] and returns [`DetectionHit`]s.

pub mod entropy;

// Re-exports grow as each subsequent task lands.
```

- [ ] **Step 3: Register in workspace**

In `Cargo.toml` (repo root), append to `workspace.members`:
```
    "crates/reghidra-detect",
```
Keep the list alphabetically sorted if it already is.

- [ ] **Step 4: Verify**

Run: `cargo check -p reghidra-detect`
Expected: compiles cleanly with no warnings.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/reghidra-detect
git commit -m "detect: scaffold reghidra-detect crate"
```

---

## Task 2: Shannon entropy helper (TDD)

**Files:**
- Create: `crates/reghidra-detect/src/entropy.rs`

- [ ] **Step 1: Write the failing tests**

`crates/reghidra-detect/src/entropy.rs`:
```rust
//! Shannon entropy over a byte slice. Result is in bits/byte, range [0.0, 8.0].

pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn uniform_byte_is_zero() {
        assert_eq!(shannon(&[0x41; 1024]), 0.0);
    }

    #[test]
    fn fully_uniform_distribution_is_eight() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        let h = shannon(&bytes);
        assert!((h - 8.0).abs() < 1e-9, "expected ~8.0, got {h}");
    }

    #[test]
    fn realistic_text_is_mid_range() {
        let lorem = b"the quick brown fox jumps over the lazy dog ".repeat(32);
        let h = shannon(&lorem);
        assert!(h > 3.5 && h < 5.0, "expected mid-range, got {h}");
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Already exported via `pub mod entropy;` in Task 1.

- [ ] **Step 3: Run tests**

Run: `cargo test -p reghidra-detect entropy`
Expected: 4 passed.

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-detect/src/entropy.rs
git commit -m "detect: Shannon entropy helper"
```

---

## Task 3: Per-section entropy on `LoadedSection`

**Files:**
- Modify: `crates/reghidra-core/src/binary.rs`
- Modify: `crates/reghidra-core/Cargo.toml` (add `reghidra-detect` dep)

- [ ] **Step 1: Add the dependency**

In `crates/reghidra-core/Cargo.toml` under `[dependencies]`:
```toml
reghidra-detect = { path = "../reghidra-detect" }
```

- [ ] **Step 2: Find the existing section struct**

Run: `grep -n "pub struct LoadedSection" crates/reghidra-core/src/binary.rs`

Identify the struct (name may be `LoadedSection`, `SectionInfo`, or similar — use what's there). This task adds one field.

- [ ] **Step 3: Add the `entropy: f64` field**

Extend the section struct definition with a new field:
```rust
    /// Shannon entropy (bits/byte) over the section's raw bytes.
    /// 0.0 for empty or uninitialized sections.
    pub entropy: f64,
```

- [ ] **Step 4: Populate at load time**

In every constructor site where a section is pushed (ELF, PE, Mach-O paths — search for fields of the struct being set), add:
```rust
    entropy: reghidra_detect::entropy::shannon(&raw_bytes),
```
where `raw_bytes` is the slice already being read for that section. For zero-size / uninitialized (`.bss`-style) sections, pass `&[]` — yields 0.0.

- [ ] **Step 5: Write a test**

Append to `crates/reghidra-core/src/binary.rs` (or the existing binary test file):
```rust
#[cfg(test)]
mod entropy_tests {
    use super::*;

    #[test]
    fn loaded_section_has_entropy() {
        let fixture = std::path::Path::new("../../tests/fixtures/wildfire-test-pe-file.exe");
        let binary = LoadedBinary::from_path(fixture).unwrap();
        let text = binary.sections.iter().find(|s| s.name == ".text").unwrap();
        assert!(text.entropy > 4.0 && text.entropy < 7.5,
                ".text entropy unexpectedly out of code-section range: {}", text.entropy);
    }
}
```

Adjust the `LoadedBinary::from_path` name / sections accessor to what actually exists — verify with `grep -n "pub fn from_path\|pub fn sections\|sections:" crates/reghidra-core/src/binary.rs`.

- [ ] **Step 6: Run**

Run: `cargo test -p reghidra-core entropy`
Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add crates/reghidra-core
git commit -m "core: per-section Shannon entropy on LoadedSection"
```

---

## Task 4: Rule AST types

**Files:**
- Create: `crates/reghidra-detect/src/rule.rs`
- Modify: `crates/reghidra-detect/src/lib.rs`

- [ ] **Step 1: Write `rule.rs`**

```rust
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Info, Suspicious, Malicious }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope { Function, File }

/// Literal string or precompiled regex (with flags already applied).
#[derive(Debug, Clone)]
pub enum StrMatcher {
    Literal(String),
    Regex(Arc<Regex>),
}

impl StrMatcher {
    pub fn is_match(&self, haystack: &str) -> bool {
        match self {
            StrMatcher::Literal(s) => haystack == s,
            StrMatcher::Regex(r) => r.is_match(haystack),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CountRange { pub min: u32, pub max: Option<u32> }
impl CountRange {
    pub fn contains(&self, n: u32) -> bool {
        n >= self.min && self.max.map_or(true, |m| n <= m)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison { Gt, Ge, Lt, Le, Eq }

#[derive(Debug, Clone)]
pub enum FeatureExpr {
    // Leaf features
    Import { lib: StrMatcher, sym: StrMatcher },
    Api(StrMatcher),
    StringFeature(StrMatcher),
    Name(StrMatcher),
    Section { name: Option<StrMatcher>, entropy_cmp: Option<(Comparison, f64)>, wx: Option<bool> },
    RichCompId(u16),
    Imphash(Vec<String>),      // hex strings, lowercased
    TlsCallbacks(bool),
    Overlay(bool),
    Mnemonic(StrMatcher),
    MnemonicSequence(Vec<StrMatcher>),
    XrefsTo(CountRange),
    XrefsFrom(CountRange),
    Matches(String),           // rule name reference (file-scope only)

    // Combinators
    And(Vec<FeatureExpr>),
    Or(Vec<FeatureExpr>),
    Not(Box<FeatureExpr>),
    NorMore { n: usize, of: Vec<FeatureExpr> },
    Count { inner: Box<FeatureExpr>, range: CountRange },
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub severity: Severity,
    pub scope: Scope,
    pub description: String,
    pub author: Option<String>,
    pub references: Vec<String>,
    pub attack: Vec<String>,    // MITRE ATT&CK IDs, optional
    pub expr: FeatureExpr,
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("regex compile error in rule '{rule}': {err}")]
    Regex { rule: String, err: regex::Error },
    #[error("invalid rule '{rule}': {msg}")]
    Invalid { rule: String, msg: String },
}
```

- [ ] **Step 2: Re-export**

In `crates/reghidra-detect/src/lib.rs`:
```rust
pub mod entropy;
pub mod rule;

pub use rule::{
    CompileError, Comparison, CountRange, FeatureExpr, Rule, Scope, Severity, StrMatcher,
};
```

- [ ] **Step 3: Verify compile**

Run: `cargo check -p reghidra-detect`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-detect
git commit -m "detect: rule AST types"
```

---

## Task 5: YAML parser — minimal (mnemonic only, full frame)

**Files:**
- Create: `crates/reghidra-detect/src/parser.rs`
- Create: `crates/reghidra-detect/tests/parser.rs`
- Modify: `crates/reghidra-detect/src/lib.rs`

- [ ] **Step 1: Write the failing test**

`crates/reghidra-detect/tests/parser.rs`:
```rust
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
```

- [ ] **Step 2: Run it (should FAIL to compile)**

Run: `cargo test -p reghidra-detect --test parser`
Expected: FAIL — `parse_rules_from_str` unresolved.

- [ ] **Step 3: Write the parser**

`crates/reghidra-detect/src/parser.rs`:
```rust
use crate::rule::*;
use regex::Regex;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuleFile {
    One { rule: RawRule },
    Many { rules: Vec<RawRule> },
    Bare(RawRule),
}

#[derive(Debug, Deserialize)]
struct RawRule {
    name: String,
    severity: Severity,
    scope: Scope,
    #[serde(default)]
    description: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    attack: Vec<String>,
    features: serde_yaml::Value,
}

pub fn parse_rules_from_str(src: &str, source_path: &str) -> Result<Vec<Rule>, CompileError> {
    let mut out = Vec::new();
    // Support multi-document YAML streams too.
    for doc in serde_yaml::Deserializer::from_str(src) {
        let v = serde_yaml::Value::deserialize(doc)?;
        let file: RuleFile = serde_yaml::from_value(v)
            .map_err(CompileError::from)?;
        match file {
            RuleFile::One { rule } => out.push(compile_rule(rule, source_path)?),
            RuleFile::Many { rules } => {
                for r in rules { out.push(compile_rule(r, source_path)?); }
            }
            RuleFile::Bare(r) => out.push(compile_rule(r, source_path)?),
        }
    }
    Ok(out)
}

fn compile_rule(raw: RawRule, _source: &str) -> Result<Rule, CompileError> {
    let expr = compile_expr(&raw.name, &raw.features)?;
    Ok(Rule {
        name: raw.name,
        severity: raw.severity,
        scope: raw.scope,
        description: raw.description,
        author: raw.author,
        references: raw.references,
        attack: raw.attack,
        expr,
    })
}

fn compile_expr(rule_name: &str, v: &serde_yaml::Value) -> Result<FeatureExpr, CompileError> {
    // v1: only mnemonic + bare mapping. Extended in Task 6.
    use serde_yaml::Value;
    match v {
        Value::Mapping(map) => {
            if map.len() != 1 {
                return Err(invalid(rule_name,
                    "feature mapping must have exactly one key (use `and:` to combine)"));
            }
            let (k, val) = map.iter().next().unwrap();
            let key = k.as_str().ok_or_else(|| invalid(rule_name, "feature key must be a string"))?;
            compile_single(rule_name, key, val)
        }
        _ => Err(invalid(rule_name, "features must be a mapping")),
    }
}

fn compile_single(rule_name: &str, key: &str, val: &serde_yaml::Value)
    -> Result<FeatureExpr, CompileError>
{
    match key {
        "mnemonic" => {
            let s = val.as_str()
                .ok_or_else(|| invalid(rule_name, "mnemonic: expects a string"))?;
            Ok(FeatureExpr::Mnemonic(str_matcher(rule_name, s)?))
        }
        other => Err(invalid(rule_name, &format!("unknown feature `{other}`"))),
    }
}

pub(crate) fn str_matcher(rule_name: &str, s: &str) -> Result<StrMatcher, CompileError> {
    // /regex/flags form; otherwise literal.
    if s.starts_with('/') {
        if let Some(end) = s[1..].rfind('/') {
            let body = &s[1..=end];
            let flags = &s[end + 2..];
            let mut pat = String::new();
            if flags.contains('i') { pat.push_str("(?i)"); }
            if flags.contains('m') { pat.push_str("(?m)"); }
            if flags.contains('s') { pat.push_str("(?s)"); }
            pat.push_str(body);
            let re = Regex::new(&pat).map_err(|e| CompileError::Regex {
                rule: rule_name.to_string(), err: e,
            })?;
            return Ok(StrMatcher::Regex(Arc::new(re)));
        }
    }
    Ok(StrMatcher::Literal(s.to_string()))
}

pub(crate) fn invalid(rule: &str, msg: &str) -> CompileError {
    CompileError::Invalid { rule: rule.to_string(), msg: msg.to_string() }
}
```

- [ ] **Step 4: Re-export**

In `crates/reghidra-detect/src/lib.rs`:
```rust
pub mod parser;
pub use parser::parse_rules_from_str;
```

- [ ] **Step 5: Run tests — expect pass**

Run: `cargo test -p reghidra-detect --test parser`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/reghidra-detect
git commit -m "detect: minimal YAML parser (mnemonic)"
```

---

## Task 6: Parser — remaining leaf features

Every feature from the spec's feature-vocabulary table, TDD per feature.

**Files:**
- Modify: `crates/reghidra-detect/src/parser.rs`
- Modify: `crates/reghidra-detect/tests/parser.rs`

- [ ] **Step 1: Write one failing test per feature**

Append to `tests/parser.rs`:
```rust
use reghidra_detect::{parse_rules_from_str, FeatureExpr, StrMatcher, Comparison};

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
```

- [ ] **Step 2: Extend `compile_single`**

In `parser.rs`, replace the `match key` block with the full vocabulary. Show this complete:
```rust
fn compile_single(rule_name: &str, key: &str, val: &serde_yaml::Value)
    -> Result<FeatureExpr, CompileError>
{
    use serde_yaml::Value;
    match key {
        "mnemonic" => {
            let s = val.as_str().ok_or_else(|| invalid(rule_name, "mnemonic: expects a string"))?;
            Ok(FeatureExpr::Mnemonic(str_matcher(rule_name, s)?))
        }
        "api" => {
            let s = val.as_str().ok_or_else(|| invalid(rule_name, "api: expects a string"))?;
            Ok(FeatureExpr::Api(str_matcher(rule_name, s)?))
        }
        "string" => {
            let s = val.as_str().ok_or_else(|| invalid(rule_name, "string: expects a string"))?;
            Ok(FeatureExpr::StringFeature(str_matcher(rule_name, s)?))
        }
        "name" => {
            let s = val.as_str().ok_or_else(|| invalid(rule_name, "name: expects a string"))?;
            Ok(FeatureExpr::Name(str_matcher(rule_name, s)?))
        }
        "import" => {
            let m = val.as_mapping()
                .ok_or_else(|| invalid(rule_name, "import: expects {lib, sym}"))?;
            let lib = get_str(rule_name, m, "lib")?;
            let sym = get_str(rule_name, m, "sym")?;
            Ok(FeatureExpr::Import {
                lib: str_matcher(rule_name, lib)?,
                sym: str_matcher(rule_name, sym)?,
            })
        }
        "section" => {
            let m = val.as_mapping()
                .ok_or_else(|| invalid(rule_name, "section: expects a mapping"))?;
            let name = opt_str(m, "name")
                .map(|s| str_matcher(rule_name, s)).transpose()?;
            let entropy_cmp = match m.get(&Value::String("entropy".into())) {
                Some(v) => Some(parse_entropy_cmp(rule_name, v)?),
                None => None,
            };
            let wx = m.get(&Value::String("wx".into())).and_then(|v| v.as_bool());
            Ok(FeatureExpr::Section { name, entropy_cmp, wx })
        }
        "rich_comp_id" => {
            let n = val.as_u64().ok_or_else(|| invalid(rule_name, "rich_comp_id expects int"))?;
            Ok(FeatureExpr::RichCompId(n as u16))
        }
        "imphash" => {
            let list: Vec<String> = match val {
                Value::String(s) => vec![s.to_lowercase()],
                Value::Sequence(seq) => seq.iter()
                    .map(|v| v.as_str().map(|s| s.to_lowercase())
                        .ok_or_else(|| invalid(rule_name, "imphash entries must be strings")))
                    .collect::<Result<_, _>>()?,
                _ => return Err(invalid(rule_name, "imphash expects string or list")),
            };
            Ok(FeatureExpr::Imphash(list))
        }
        "tls_callbacks" => {
            let b = val.as_bool().ok_or_else(|| invalid(rule_name, "tls_callbacks expects bool"))?;
            Ok(FeatureExpr::TlsCallbacks(b))
        }
        "overlay" => {
            let b = val.as_bool().ok_or_else(|| invalid(rule_name, "overlay expects bool"))?;
            Ok(FeatureExpr::Overlay(b))
        }
        "mnemonic_sequence" => {
            let seq = val.as_sequence()
                .ok_or_else(|| invalid(rule_name, "mnemonic_sequence expects list"))?;
            let mut mms = Vec::with_capacity(seq.len());
            for item in seq {
                let s = item.as_str()
                    .ok_or_else(|| invalid(rule_name, "mnemonic_sequence items must be strings"))?;
                mms.push(str_matcher(rule_name, s)?);
            }
            Ok(FeatureExpr::MnemonicSequence(mms))
        }
        "xrefs_to" => Ok(FeatureExpr::XrefsTo(parse_count_range(rule_name, val)?)),
        "xrefs_from" => Ok(FeatureExpr::XrefsFrom(parse_count_range(rule_name, val)?)),
        "matches" => {
            let s = val.as_str().ok_or_else(|| invalid(rule_name, "matches: expects a string"))?;
            Ok(FeatureExpr::Matches(s.to_string()))
        }
        other => Err(invalid(rule_name, &format!("unknown feature `{other}`"))),
    }
}

fn get_str<'a>(rule: &str, m: &'a serde_yaml::Mapping, key: &str) -> Result<&'a str, CompileError> {
    m.get(&serde_yaml::Value::String(key.into()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid(rule, &format!("missing string field `{key}`")))
}

fn opt_str<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    m.get(&serde_yaml::Value::String(key.into())).and_then(|v| v.as_str())
}

fn parse_entropy_cmp(rule: &str, v: &serde_yaml::Value) -> Result<(Comparison, f64), CompileError> {
    let m = v.as_mapping().ok_or_else(|| invalid(rule, "entropy expects {op, value}"))?;
    let op = get_str(rule, m, "op")?;
    let value = m.get(&serde_yaml::Value::String("value".into()))
        .and_then(|v| v.as_f64())
        .ok_or_else(|| invalid(rule, "entropy.value must be a number"))?;
    let cmp = match op {
        "gt" => Comparison::Gt, "ge" => Comparison::Ge,
        "lt" => Comparison::Lt, "le" => Comparison::Le, "eq" => Comparison::Eq,
        other => return Err(invalid(rule, &format!("entropy.op `{other}` invalid"))),
    };
    Ok((cmp, value))
}

fn parse_count_range(rule: &str, v: &serde_yaml::Value) -> Result<CountRange, CompileError> {
    let m = v.as_mapping().ok_or_else(|| invalid(rule, "expects {min[, max]}"))?;
    let min = m.get(&serde_yaml::Value::String("min".into()))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid(rule, "missing min"))? as u32;
    let max = m.get(&serde_yaml::Value::String("max".into()))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    Ok(CountRange { min, max })
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p reghidra-detect --test parser`
Expected: all passed.

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-detect
git commit -m "detect: parser supports full leaf feature vocabulary"
```

---

## Task 7: Parser — combinators and count wrappers

**Files:**
- Modify: `crates/reghidra-detect/src/parser.rs`
- Modify: `crates/reghidra-detect/tests/parser.rs`

- [ ] **Step 1: Failing tests**

Append to `tests/parser.rs`:
```rust
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
```

- [ ] **Step 2: Update `compile_expr` to handle list + combinators**

Replace `compile_expr` body:
```rust
fn compile_expr(rule_name: &str, v: &serde_yaml::Value) -> Result<FeatureExpr, CompileError> {
    use serde_yaml::Value;
    match v {
        Value::Sequence(seq) => {
            let mut items = Vec::with_capacity(seq.len());
            for it in seq { items.push(compile_expr(rule_name, it)?); }
            Ok(FeatureExpr::And(items))
        }
        Value::Mapping(map) => {
            if map.len() != 1 {
                return Err(invalid(rule_name,
                    "feature mapping must have exactly one key; use `and:` to combine"));
            }
            let (k, val) = map.iter().next().unwrap();
            let key = k.as_str().ok_or_else(|| invalid(rule_name, "feature key must be a string"))?;
            match key {
                "and" => compile_list(rule_name, val, FeatureExpr::And),
                "or" => compile_list(rule_name, val, FeatureExpr::Or),
                "not" => {
                    let inner = compile_expr(rule_name, val)?;
                    Ok(FeatureExpr::Not(Box::new(inner)))
                }
                "n_or_more" => {
                    let m = val.as_mapping()
                        .ok_or_else(|| invalid(rule_name, "n_or_more expects {n, of}"))?;
                    let n = m.get(&Value::String("n".into()))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| invalid(rule_name, "n_or_more.n required"))? as usize;
                    let of_v = m.get(&Value::String("of".into()))
                        .ok_or_else(|| invalid(rule_name, "n_or_more.of required"))?;
                    let of_seq = of_v.as_sequence()
                        .ok_or_else(|| invalid(rule_name, "n_or_more.of must be list"))?;
                    let mut of = Vec::with_capacity(of_seq.len());
                    for it in of_seq { of.push(compile_expr(rule_name, it)?); }
                    Ok(FeatureExpr::NorMore { n, of })
                }
                "count" => {
                    let m = val.as_mapping()
                        .ok_or_else(|| invalid(rule_name, "count expects {feature, min[, max]}"))?;
                    let feature_v = m.get(&Value::String("feature".into()))
                        .ok_or_else(|| invalid(rule_name, "count.feature required"))?;
                    let inner = compile_expr(rule_name, feature_v)?;
                    let min = m.get(&Value::String("min".into()))
                        .and_then(|v| v.as_u64())
                        .ok_or_else(|| invalid(rule_name, "count.min required"))? as u32;
                    let max = m.get(&Value::String("max".into()))
                        .and_then(|v| v.as_u64()).map(|n| n as u32);
                    Ok(FeatureExpr::Count { inner: Box::new(inner), range: CountRange { min, max } })
                }
                other => compile_single(rule_name, other, val),
            }
        }
        _ => Err(invalid(rule_name, "features must be a mapping or list")),
    }
}

fn compile_list<F: Fn(Vec<FeatureExpr>) -> FeatureExpr>(
    rule_name: &str, v: &serde_yaml::Value, wrap: F,
) -> Result<FeatureExpr, CompileError> {
    let seq = v.as_sequence().ok_or_else(|| invalid(rule_name, "expects a list"))?;
    let mut items = Vec::with_capacity(seq.len());
    for it in seq { items.push(compile_expr(rule_name, it)?); }
    Ok(wrap(items))
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p reghidra-detect --test parser`
Expected: all passed.

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-detect
git commit -m "detect: parser supports combinators and count wrapper"
```

---

## Task 8: `Features` snapshot types + builder

**Files:**
- Create: `crates/reghidra-detect/src/features.rs`
- Modify: `crates/reghidra-detect/src/lib.rs`

Builder construction from `Project` lives in `reghidra-core::project` (Task 12) so this crate stays upstream. Here we define the types and a `FeaturesBuilder` helper.

- [ ] **Step 1: Write the types**

`crates/reghidra-detect/src/features.rs`:
```rust
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Features {
    pub file: FileFeatures,
    pub by_function: HashMap<u64, FunctionFeatures>,
}

#[derive(Debug, Default, Clone)]
pub struct FileFeatures {
    pub format: BinaryFormat,
    pub imports: Vec<Import>,
    pub strings: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub pe: Option<PeFeatures>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    #[default] Unknown,
    Elf, Pe, MachO,
}

#[derive(Debug, Clone)]
pub struct Import { pub lib: String, pub sym: String }

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Default, Clone)]
pub struct PeFeatures {
    pub rich_entries: Vec<RichEntry>,        // (prod_id, build)
    pub imphash: Option<String>,             // lowercased hex
    pub tls_callbacks: bool,
    pub overlay: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RichEntry { pub prod_id: u16, pub build: u16 }

#[derive(Debug, Default, Clone)]
pub struct FunctionFeatures {
    pub name: String,
    pub apis: Vec<String>,
    pub string_refs: Vec<String>,
    pub mnemonics: Vec<String>,      // in-order instruction mnemonics
    pub xref_in_count: usize,
    pub xref_out_count: usize,
}
```

- [ ] **Step 2: Re-export**

In `lib.rs`:
```rust
pub mod features;
pub use features::{
    BinaryFormat, FileFeatures, Features, FunctionFeatures, Import, PeFeatures,
    RichEntry, SectionInfo,
};
```

- [ ] **Step 3: Verify**

Run: `cargo check -p reghidra-detect`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-detect
git commit -m "detect: Features snapshot types"
```

---

## Task 9: Evaluator — leaf features

**Files:**
- Create: `crates/reghidra-detect/src/eval.rs`
- Create: `crates/reghidra-detect/tests/eval.rs`
- Modify: `crates/reghidra-detect/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

`crates/reghidra-detect/tests/eval.rs`:
```rust
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
```

- [ ] **Step 2: Write `eval.rs`**

```rust
use crate::features::*;
use crate::rule::*;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default, Clone)]
pub struct DetectionResults {
    pub file_hits: Vec<DetectionHit>,
    pub function_hits: HashMap<u64, Vec<DetectionHit>>,
    pub per_rule_file_counts: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct DetectionHit {
    pub rule_name: String,
    pub severity: Severity,
    pub source_path: String,
    pub description: String,
    pub match_count: u32,
}

pub fn evaluate(rules: &[Rule], f: &Features) -> DetectionResults {
    let mut out = DetectionResults::default();
    let mut fired_rules: HashSet<&str> = HashSet::new();

    // Pass 1: function-scope + file-scope without `matches:`.
    for rule in rules {
        match rule.scope {
            Scope::Function => {
                for (&addr, ff) in &f.by_function {
                    let count = eval_expr(&rule.expr, f, Some(ff), None);
                    if count > 0 {
                        out.function_hits.entry(addr).or_default().push(hit(rule, count));
                        fired_rules.insert(rule.name.as_str());
                    }
                }
            }
            Scope::File => {
                if references_matches(&rule.expr) { continue; }
                let count = eval_expr(&rule.expr, f, None, None);
                if count > 0 {
                    out.file_hits.push(hit(rule, count));
                    fired_rules.insert(rule.name.as_str());
                }
            }
        }
    }

    // Pass 2: file-scope rules that reference `matches:`.
    for rule in rules {
        if rule.scope == Scope::File && references_matches(&rule.expr) {
            let count = eval_expr(&rule.expr, f, None, Some(&fired_rules));
            if count > 0 {
                out.file_hits.push(hit(rule, count));
            }
        }
    }

    out
}

fn hit(rule: &Rule, match_count: u32) -> DetectionHit {
    DetectionHit {
        rule_name: rule.name.clone(),
        severity: rule.severity,
        source_path: String::new(),        // populated by the caller when loading a file
        description: rule.description.clone(),
        match_count,
    }
}

fn references_matches(e: &FeatureExpr) -> bool {
    match e {
        FeatureExpr::Matches(_) => true,
        FeatureExpr::And(v) | FeatureExpr::Or(v) | FeatureExpr::NorMore { of: v, .. } =>
            v.iter().any(references_matches),
        FeatureExpr::Not(inner) | FeatureExpr::Count { inner, .. } => references_matches(inner),
        _ => false,
    }
}

/// Returns the *match count* (0 = no match). Used by `count:` wrappers.
fn eval_expr(
    e: &FeatureExpr, f: &Features, ff: Option<&FunctionFeatures>, fired: Option<&HashSet<&str>>,
) -> u32 {
    use FeatureExpr::*;
    match e {
        Import { lib, sym } => f.file.imports.iter()
            .filter(|i| lib.is_match(&i.lib) && sym.is_match(&i.sym)).count() as u32,
        Api(m) => ff.map(|ff| ff.apis.iter().filter(|a| m.is_match(a)).count() as u32).unwrap_or(0),
        StringFeature(m) => {
            let file_hits = f.file.strings.iter().filter(|s| m.is_match(s)).count() as u32;
            let fn_hits = ff.map(|ff| ff.string_refs.iter().filter(|s| m.is_match(s)).count() as u32).unwrap_or(0);
            file_hits + fn_hits
        }
        Name(m) => ff.map(|ff| if m.is_match(&ff.name) { 1 } else { 0 }).unwrap_or(0),
        Section { name, entropy_cmp, wx } => {
            f.file.sections.iter().filter(|s| {
                name.as_ref().map_or(true, |m| m.is_match(&s.name))
                    && entropy_cmp.map_or(true, |(op, v)| cmp(op, s.entropy, v))
                    && wx.map_or(true, |want| (s.writable && s.executable) == want)
            }).count() as u32
        }
        RichCompId(id) => f.file.pe.as_ref()
            .map(|pe| pe.rich_entries.iter().filter(|r| r.prod_id == *id).count() as u32)
            .unwrap_or(0),
        Imphash(list) => f.file.pe.as_ref()
            .and_then(|pe| pe.imphash.as_ref())
            .map(|h| if list.iter().any(|x| x == h) { 1 } else { 0 })
            .unwrap_or(0),
        TlsCallbacks(want) => f.file.pe.as_ref()
            .map(|pe| if pe.tls_callbacks == *want { 1 } else { 0 }).unwrap_or(0),
        Overlay(want) => f.file.pe.as_ref()
            .map(|pe| if pe.overlay == *want { 1 } else { 0 }).unwrap_or(0),
        Mnemonic(m) => ff.map(|ff| ff.mnemonics.iter().filter(|x| m.is_match(x)).count() as u32).unwrap_or(0),
        MnemonicSequence(seq) => ff.map(|ff| count_sequence(&ff.mnemonics, seq)).unwrap_or(0),
        XrefsTo(r) => ff.map(|ff| if r.contains(ff.xref_in_count as u32) { 1 } else { 0 }).unwrap_or(0),
        XrefsFrom(r) => ff.map(|ff| if r.contains(ff.xref_out_count as u32) { 1 } else { 0 }).unwrap_or(0),
        Matches(name) => fired.map(|s| if s.contains(name.as_str()) { 1 } else { 0 }).unwrap_or(0),

        And(v) => if v.iter().all(|x| eval_expr(x, f, ff, fired) > 0) { 1 } else { 0 },
        Or(v) => if v.iter().any(|x| eval_expr(x, f, ff, fired) > 0) { 1 } else { 0 },
        Not(inner) => if eval_expr(inner, f, ff, fired) == 0 { 1 } else { 0 },
        NorMore { n, of } => {
            let hits = of.iter().filter(|x| eval_expr(x, f, ff, fired) > 0).count();
            if hits >= *n { 1 } else { 0 }
        }
        Count { inner, range } => {
            let n = eval_expr(inner, f, ff, fired);
            if range.contains(n) { 1 } else { 0 }
        }
    }
}

fn cmp(op: Comparison, a: f64, b: f64) -> bool {
    match op {
        Comparison::Gt => a > b, Comparison::Ge => a >= b,
        Comparison::Lt => a < b, Comparison::Le => a <= b,
        Comparison::Eq => (a - b).abs() < f64::EPSILON,
    }
}

fn count_sequence(mnems: &[String], seq: &[StrMatcher]) -> u32 {
    if seq.is_empty() || mnems.len() < seq.len() { return 0; }
    let mut hits = 0u32;
    'outer: for i in 0..=mnems.len() - seq.len() {
        for (j, m) in seq.iter().enumerate() {
            if !m.is_match(&mnems[i + j]) { continue 'outer; }
        }
        hits += 1;
    }
    hits
}
```

- [ ] **Step 3: Re-export**

In `lib.rs`:
```rust
pub mod eval;
pub use eval::{evaluate, DetectionHit, DetectionResults};
```

- [ ] **Step 4: Run**

Run: `cargo test -p reghidra-detect --test eval`
Expected: all 7 pass.

- [ ] **Step 5: Commit**

```bash
git add crates/reghidra-detect
git commit -m "detect: evaluator for leaf features, combinators, counts, cross-rule matches"
```

---

## Task 10: Bundled rule embed

**Files:**
- Create: `rules/.gitkeep` (so the dir exists)
- Create: `crates/reghidra-detect/src/bundled.rs`
- Modify: `crates/reghidra-detect/src/lib.rs`

- [ ] **Step 1: Create rules dir**

```bash
mkdir -p rules && touch rules/.gitkeep
```

- [ ] **Step 2: Write `bundled.rs`**

```rust
use include_dir::{include_dir, Dir};

pub static BUNDLED_RULES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../rules");

#[derive(Debug, Clone)]
pub struct AvailableRuleFile {
    pub subdir: String,            // e.g. "anti_analysis"
    pub stem: String,              // e.g. "rdtsc-timing"
    pub path: String,              // "anti_analysis/rdtsc-timing.yml"
}

/// Walk the embedded tree and return every `*.yml` without parsing.
/// Mirrors `bundled_sigs::available_sigs` / `type_archive::available_stems`.
pub fn available_bundled_rulefiles() -> Vec<AvailableRuleFile> {
    fn walk<'a>(dir: &'a Dir<'a>, prefix: &str, out: &mut Vec<AvailableRuleFile>) {
        for entry in dir.entries() {
            match entry {
                include_dir::DirEntry::File(f) => {
                    let p = f.path().to_string_lossy().to_string();
                    if !p.ends_with(".yml") && !p.ends_with(".yaml") { continue; }
                    let (subdir, stem) = match p.rsplit_once('/') {
                        Some((d, f)) => (d.to_string(), f.trim_end_matches(".yml")
                            .trim_end_matches(".yaml").to_string()),
                        None => (String::new(), p.trim_end_matches(".yml")
                            .trim_end_matches(".yaml").to_string()),
                    };
                    out.push(AvailableRuleFile { subdir, stem, path: p });
                }
                include_dir::DirEntry::Dir(d) => {
                    let new_prefix = if prefix.is_empty() { d.path().to_string_lossy().to_string() }
                                     else { format!("{prefix}/{}", d.path().display()) };
                    walk(d, &new_prefix, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&BUNDLED_RULES_DIR, "", &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn bundled_rule_contents(path: &str) -> Option<&'static str> {
    BUNDLED_RULES_DIR.get_file(path).and_then(|f| f.contents_utf8())
}
```

- [ ] **Step 3: Re-export**

In `lib.rs`:
```rust
pub mod bundled;
pub use bundled::{available_bundled_rulefiles, bundled_rule_contents, AvailableRuleFile};
```

- [ ] **Step 4: Verify**

Run: `cargo check -p reghidra-detect`
Expected: clean (0 rules is fine; `available_bundled_rulefiles()` returns empty).

- [ ] **Step 5: Commit**

```bash
git add rules crates/reghidra-detect
git commit -m "detect: bundled-rules include_dir scaffold"
```

---

## Task 11: PE-specific features — imphash, rich, tls, overlay

**Files:**
- Modify: `crates/reghidra-core/src/binary.rs`

Imphash = MD5 of `lib.sym,lib.sym,...` lowercased, comma-joined (standard pefile formula). Rich header entries already exist on `BinaryInfo.rich_header`. TLS-callbacks + overlay need a lookup.

- [ ] **Step 1: Pin the contract with a test**

Append to `crates/reghidra-core/tests/` (or inline as `#[cfg(test)]`):
```rust
#[test]
fn pe_imphash_computed() {
    let fixture = std::path::Path::new("../../tests/fixtures/wildfire-test-pe-file.exe");
    let binary = LoadedBinary::from_path(fixture).unwrap();
    assert!(binary.info.imphash.as_ref().is_some_and(|h| h.len() == 32),
            "imphash should be 32-char lowercase hex");
    assert_eq!(binary.info.tls_callbacks_present, false);   // adjust if fixture has TLS
}
```

- [ ] **Step 2: Extend `BinaryInfo`**

```rust
    /// PE only: lowercased hex MD5 of imports-formula string.
    pub imphash: Option<String>,
    /// PE only: TLS directory has at least one callback.
    pub tls_callbacks_present: bool,
    /// PE only: file has trailing bytes after the last section.
    pub overlay_present: bool,
```

- [ ] **Step 3: Add a dep**

In `crates/reghidra-core/Cargo.toml`:
```toml
md-5 = "0.10"
```

- [ ] **Step 4: Compute at PE load time**

In the PE loader path (find it via `grep -n "BinaryFormat::Pe" src/binary.rs`), after import parsing:
```rust
use md5::{Digest, Md5};

fn compute_imphash(imports: &[goblin::pe::import::Import]) -> String {
    // Standard pefile imphash: insertion-order (NOT sorted), lowercased
    // "<lib-stem>.<sym>" entries, comma-joined, MD5.
    let parts: Vec<String> = imports.iter().map(|i| {
        let lib = std::path::Path::new(&*i.dll).file_stem()
            .and_then(|s| s.to_str()).unwrap_or(&i.dll).to_lowercase();
        format!("{lib}.{}", i.name.to_lowercase())
    }).collect();
    let joined = parts.join(",");
    hex::encode(Md5::digest(joined.as_bytes()))
}
```

Add `hex = "0.4"` to `crates/reghidra-core/Cargo.toml` if not already present. Tests pin the exact hex value for the fixture.

For TLS callbacks: `pe.header.optional_header.as_ref().and_then(|o| o.data_directories.get_tls_table())` present AND non-empty.

For overlay: `overlay_present = highest(section.pointer_to_raw_data + size_of_raw_data) < file_len`.

- [ ] **Step 5: Run**

Run: `cargo test -p reghidra-core imphash`
Expected: pass with concrete fixture values pinned.

- [ ] **Step 6: Commit**

```bash
git add crates/reghidra-core
git commit -m "core: PE imphash, TLS-callbacks presence, overlay detection"
```

---

## Task 12: Project integration — build `Features`, run `evaluate`, expose `DetectionResults`

**Files:**
- Modify: `crates/reghidra-core/src/project.rs`
- Modify: `crates/reghidra-core/src/lib.rs`

- [ ] **Step 1: Add fields to `Project`**

```rust
    pub detection_results: reghidra_detect::DetectionResults,
    pub loaded_rule_files: Vec<LoadedRuleFile>,
    pub detections_generation: u64,
    pub available_bundled_rulefiles: Vec<reghidra_detect::AvailableRuleFile>,
```

```rust
pub struct LoadedRuleFile {
    pub source_path: String,       // "bundled:<subdir>/<stem>" or absolute user path
    pub rules: Vec<reghidra_detect::Rule>,
    pub enabled: bool,
    pub parse_errors: Vec<String>,
}
```

Initialize in `Project::open`: default empty, then populate:
- `self.available_bundled_rulefiles = reghidra_detect::available_bundled_rulefiles();`
- Auto-load every bundled rule file (first ship — smart subsetting is a follow-up; matches the Type Archives auto-load default).

- [ ] **Step 2: Build `Features` from the project**

New module: `crates/reghidra-core/src/analysis/detect_features.rs`:
```rust
use reghidra_detect::features::*;

pub fn build_features(project: &crate::project::Project) -> Features {
    let mut by_function = std::collections::HashMap::new();
    for func in &project.functions {
        let ff = FunctionFeatures {
            name: func.name.clone(),
            apis: func.callees_resolved.iter().cloned().collect(),
            string_refs: func.string_refs.iter().cloned().collect(),
            mnemonics: func.instructions.iter().map(|i| i.mnemonic.clone()).collect(),
            xref_in_count: project.xrefs_to(func.entry).len(),
            xref_out_count: project.xrefs_from(func.entry).len(),
        };
        by_function.insert(func.entry, ff);
    }

    let file = FileFeatures {
        format: match project.binary.info.format {
            crate::binary::BinaryFormat::Elf => BinaryFormat::Elf,
            crate::binary::BinaryFormat::Pe => BinaryFormat::Pe,
            crate::binary::BinaryFormat::MachO => BinaryFormat::MachO,
        },
        imports: project.binary.imports.iter()
            .map(|i| Import { lib: i.dll.clone(), sym: i.name.clone() }).collect(),
        strings: project.strings.iter().map(|s| s.text.clone()).collect(),
        sections: project.binary.sections.iter().map(|s| SectionInfo {
            name: s.name.clone(), size: s.size, entropy: s.entropy,
            writable: s.writable, executable: s.executable,
        }).collect(),
        pe: if project.binary.info.format == crate::binary::BinaryFormat::Pe {
            Some(PeFeatures {
                rich_entries: project.binary.info.rich_header.as_ref()
                    .map(|r| r.entries.iter().map(|e| RichEntry { prod_id: e.prod_id, build: e.build }).collect())
                    .unwrap_or_default(),
                imphash: project.binary.info.imphash.clone(),
                tls_callbacks: project.binary.info.tls_callbacks_present,
                overlay: project.binary.info.overlay_present,
            })
        } else { None },
    };

    Features { file, by_function }
}
```

Fields like `project.functions`, `func.callees_resolved`, `func.string_refs`, `func.instructions`, `project.xrefs_to`, `project.xrefs_from`, `project.strings`, `project.binary.imports` are indicative — verify names by:

```bash
grep -n "pub functions\|pub fn xrefs_to\|pub fn xrefs_from\|pub strings\|string_refs" crates/reghidra-core/src/project.rs
```

and adjust the builder to match. The contract is: one `FunctionFeatures` per detected function with APIs, string refs, mnemonics, xref counts.

- [ ] **Step 3: Call the evaluator**

Add `Project::evaluate_detections(&mut self)`:
```rust
pub fn evaluate_detections(&mut self) {
    let feats = crate::analysis::detect_features::build_features(self);
    let all_rules: Vec<_> = self.loaded_rule_files.iter()
        .filter(|f| f.enabled)
        .flat_map(|f| f.rules.iter().cloned().map(move |r| (r, f.source_path.clone())))
        .collect();

    let only_rules: Vec<_> = all_rules.iter().map(|(r, _)| r.clone()).collect();
    let mut results = reghidra_detect::evaluate(&only_rules, &feats);

    // Stamp source_path onto each hit.
    let name_to_src: std::collections::HashMap<_, _> = all_rules.iter()
        .map(|(r, s)| (r.name.clone(), s.clone())).collect();
    for h in results.file_hits.iter_mut() {
        if let Some(src) = name_to_src.get(&h.rule_name) { h.source_path = src.clone(); }
    }
    for hits in results.function_hits.values_mut() {
        for h in hits {
            if let Some(src) = name_to_src.get(&h.rule_name) { h.source_path = src.clone(); }
        }
    }

    // per_rule_file_counts.
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for h in &results.file_hits { *counts.entry(h.source_path.clone()).or_default() += 1; }
    for hits in results.function_hits.values() {
        for h in hits { *counts.entry(h.source_path.clone()).or_default() += 1; }
    }
    results.per_rule_file_counts = counts;

    self.detection_results = results;
    self.detections_generation = self.detections_generation.wrapping_add(1);
}
```

Call it at the end of `Project::open` and any `reanalyze_*` pathways.

- [ ] **Step 4: Auto-load bundled rules on open**

After scaffolding `loaded_rule_files = Vec::new()`, loop over `available_bundled_rulefiles` and for each, call `load_bundled_rule_file` (defined in Task 13). Wrap with a `for` so parse errors on one file don't stop others.

- [ ] **Step 5: Write an integration test**

`crates/reghidra-core/tests/detect_pipeline.rs`:
```rust
use reghidra_core::project::Project;

#[test]
fn open_yields_empty_detections_when_no_rules_shipped() {
    let p = Project::open("tests/fixtures/wildfire-test-pe-file.exe").unwrap();
    // Zero bundled rules at this point in the plan. Just assert the field exists
    // and generation is 1 (we ran evaluate once).
    assert_eq!(p.detections_generation, 1);
    assert_eq!(p.loaded_rule_files.len(), 0);
    assert_eq!(p.detection_results.file_hits.len(), 0);
}
```

(This test will get strengthened in Task 25 after rules land.)

- [ ] **Step 6: Re-export**

In `crates/reghidra-core/src/lib.rs`:
```rust
pub use reghidra_detect::{
    DetectionHit, DetectionResults, Rule as DetectionRule, Severity as DetectionSeverity,
    Scope as DetectionScope,
};
```

- [ ] **Step 7: Run**

```bash
cargo test -p reghidra-core detect_pipeline
```
Expected: pass.

- [ ] **Step 8: Commit**

```bash
git add crates/reghidra-core
git commit -m "core: wire detection engine into Project pipeline"
```

---

## Task 13: Project — lazy-load, enable/disable, user-file load

**Files:**
- Modify: `crates/reghidra-core/src/project.rs`

- [ ] **Step 1: Add loader methods**

```rust
impl Project {
    pub fn load_bundled_rule_file(&mut self, subdir: &str, stem: &str) -> Result<(), String> {
        let path = if subdir.is_empty() { format!("{stem}.yml") }
                   else { format!("{subdir}/{stem}.yml") };
        let source_path = format!("bundled:{path}");
        if self.loaded_rule_files.iter().any(|f| f.source_path == source_path) { return Ok(()); }
        let yaml = reghidra_detect::bundled_rule_contents(&path)
            .ok_or_else(|| format!("bundled rule not found: {path}"))?;
        let (rules, errors) = parse_collect_errors(yaml, &source_path);
        self.loaded_rule_files.insert(0, LoadedRuleFile {
            source_path, rules, enabled: true, parse_errors: errors,
        });
        self.evaluate_detections();
        Ok(())
    }

    pub fn load_user_rule_file(&mut self, path: &std::path::Path) -> Result<(), String> {
        let abs = path.canonicalize().map_err(|e| e.to_string())?;
        let source_path = abs.to_string_lossy().to_string();
        if self.loaded_rule_files.iter().any(|f| f.source_path == source_path) { return Ok(()); }
        let yaml = std::fs::read_to_string(&abs).map_err(|e| e.to_string())?;
        let (rules, errors) = parse_collect_errors(&yaml, &source_path);
        self.loaded_rule_files.insert(0, LoadedRuleFile {
            source_path, rules, enabled: true, parse_errors: errors,
        });
        self.evaluate_detections();
        Ok(())
    }

    pub fn set_rule_file_enabled(&mut self, source_path: &str, enabled: bool) {
        if let Some(f) = self.loaded_rule_files.iter_mut().find(|f| f.source_path == source_path) {
            if f.enabled != enabled {
                f.enabled = enabled;
                self.evaluate_detections();
            }
        }
    }
}

fn parse_collect_errors(yaml: &str, source: &str) -> (Vec<reghidra_detect::Rule>, Vec<String>) {
    match reghidra_detect::parse_rules_from_str(yaml, source) {
        Ok(r) => (r, Vec::new()),
        Err(e) => (Vec::new(), vec![e.to_string()]),
    }
}
```

- [ ] **Step 2: Tests**

Append to `crates/reghidra-core/tests/detect_pipeline.rs`:
```rust
#[test]
fn load_user_rule_file_is_idempotent() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("mine.yml");
    let mut f = std::fs::File::create(&p).unwrap();
    writeln!(f, "rule: {{ name: test, severity: info, scope: file, description: \"\", features: {{ overlay: false }} }}").unwrap();

    let mut proj = Project::open("tests/fixtures/wildfire-test-pe-file.exe").unwrap();
    proj.load_user_rule_file(&p).unwrap();
    let before = proj.loaded_rule_files.len();
    proj.load_user_rule_file(&p).unwrap();
    assert_eq!(proj.loaded_rule_files.len(), before);
}

#[test]
fn disable_rule_file_bumps_generation() {
    let mut proj = Project::open("tests/fixtures/wildfire-test-pe-file.exe").unwrap();
    if let Some(f) = proj.loaded_rule_files.first() {
        let path = f.source_path.clone();
        let gen0 = proj.detections_generation;
        proj.set_rule_file_enabled(&path, false);
        assert_ne!(gen0, proj.detections_generation);
    }
}
```

Add `tempfile = "3"` to `[dev-dependencies]` in `crates/reghidra-core/Cargo.toml` if not present.

- [ ] **Step 3: Run**

Run: `cargo test -p reghidra-core detect_pipeline`
Expected: pass (disable test is no-op-safe if no rules loaded yet).

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-core
git commit -m "core: project lazy-load/enable/disable for rule files"
```

---

## Task 14: Session persistence

**Files:**
- Modify: `crates/reghidra-core/src/project.rs`

- [ ] **Step 1: Extend `Session`**

Locate the `pub struct Session` definition (line ~1093). Add:
```rust
    #[serde(default)]
    pub loaded_bundled_rule_stems: Vec<(String, String)>,   // (subdir, stem)
    #[serde(default)]
    pub loaded_user_rule_paths: Vec<PathBuf>,
    #[serde(default)]
    pub rule_file_overrides: Vec<DataSourceOverride>,       // reuses existing struct
```

- [ ] **Step 2: Extend `to_session`**

In `to_session`, populate alongside existing fields:
```rust
    let loaded_bundled_rule_stems = self.loaded_rule_files.iter()
        .filter_map(|f| f.source_path.strip_prefix("bundled:"))
        .filter_map(|p| p.rsplit_once('/').map(|(d, f)| (d.to_string(),
            f.trim_end_matches(".yml").trim_end_matches(".yaml").to_string())))
        .collect();

    let loaded_user_rule_paths: Vec<PathBuf> = self.loaded_rule_files.iter()
        .filter(|f| !f.source_path.starts_with("bundled:"))
        .map(|f| PathBuf::from(&f.source_path))
        .collect();

    let rule_file_overrides = self.loaded_rule_files.iter()
        .filter(|f| !f.enabled)
        .map(|f| DataSourceOverride { source_path: f.source_path.clone(), enabled: false })
        .collect();
```

Add to the returned `Session { ... }`.

- [ ] **Step 3: Extend `apply_session`**

Before the existing data_source_overrides loop:
```rust
    for (subdir, stem) in &session.loaded_bundled_rule_stems {
        let _ = self.load_bundled_rule_file(subdir, stem);
    }
    for path in &session.loaded_user_rule_paths {
        let _ = self.load_user_rule_file(path);
    }
    for ov in &session.rule_file_overrides {
        self.set_rule_file_enabled(&ov.source_path, ov.enabled);
    }
```

- [ ] **Step 4: Round-trip test**

Append to `tests/detect_pipeline.rs`:
```rust
#[test]
fn session_round_trip_preserves_rule_overrides() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("mine.yml");
    writeln!(std::fs::File::create(&p).unwrap(),
        "rule: {{ name: x, severity: info, scope: file, description: \"\", features: {{ overlay: false }} }}").unwrap();

    let mut proj = Project::open("tests/fixtures/wildfire-test-pe-file.exe").unwrap();
    proj.load_user_rule_file(&p).unwrap();
    proj.set_rule_file_enabled(&p.canonicalize().unwrap().to_string_lossy(), false);

    let sess = proj.to_session();
    let mut proj2 = Project::open("tests/fixtures/wildfire-test-pe-file.exe").unwrap();
    proj2.apply_session(&sess);

    let f = proj2.loaded_rule_files.iter().find(|f|
        f.source_path == p.canonicalize().unwrap().to_string_lossy()).expect("reloaded");
    assert!(!f.enabled);
}
```

- [ ] **Step 5: Run**

Run: `cargo test -p reghidra-core session_round_trip`
Expected: pass.

- [ ] **Step 6: Commit**

```bash
git add crates/reghidra-core
git commit -m "core: session round-trip for detection rule overrides"
```

---

## Task 15: First bundled rule + pattern for rule tests

**Files:**
- Create: `rules/anti_analysis/rdtsc-timing.yml`
- Create: `crates/reghidra-detect/tests/bundled_rules.rs`

- [ ] **Step 1: Author the rule**

`rules/anti_analysis/rdtsc-timing.yml`:
```yaml
rule:
  name: anti-analysis.rdtsc-timing
  severity: suspicious
  scope: function
  description: |
    RDTSC-based timing check commonly used by malware to detect debuggers
    or sandboxes by measuring instruction latency.
  author: reghidra
  references:
    - https://unprotect.it/technique/rdtsc/
  attack:
    - T1497.003
  features:
    count:
      feature:
        mnemonic: rdtsc
      min: 2
```

- [ ] **Step 2: Write the test pattern**

`crates/reghidra-detect/tests/bundled_rules.rs`:
```rust
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
```

- [ ] **Step 3: Run**

Run: `cargo test -p reghidra-detect --test bundled_rules`
Expected: 2 pass.

- [ ] **Step 4: Commit**

```bash
git add rules crates/reghidra-detect
git commit -m "rules: first bundled rule (rdtsc-timing) and bundled-rule test pattern"
```

---

## Task 16: Author remaining bundled rules

Each subcategory is its own task (16A–16G). They can be done in parallel by subagents since each touches a disjoint `rules/<subdir>/` directory and adds disjoint `#[test]` functions to `tests/bundled_rules.rs` (append-only).

**Pattern for every rule:** YAML file + one fire test + one no-fire test in `tests/bundled_rules.rs`, using the `one_fn` or analogous helper (add `file_feats(...)` etc. as needed at the top of the test file — do NOT duplicate helpers across tests).

**Ground rules for authors:**
- Every rule has `description`, `author: reghidra`, at least one `references:` link.
- Severity guidance: `info` = how something works (e.g. just calls `CreateProcess`); `suspicious` = legit software occasionally does this (e.g. RDTSC timing); `malicious` = high confidence bad or strong combo (e.g. `VirtualAllocEx + WriteProcessMemory + CreateRemoteThread`).
- Naming: `category.specific-behavior`, kebab-case.
- Run `cargo test -p reghidra-detect --test bundled_rules` after every rule.
- Commit after each subcategory finishes.

### Task 16A: anti_analysis (12 rules)

`rules/anti_analysis/`:
- `isdebuggerpresent.yml` — `api: /IsDebuggerPresent/` + severity suspicious
- `checkremotedebuggerpresent.yml`
- `ntqueryinformationprocess-debug.yml` — `api: NtQueryInformationProcess` + `string: "ProcessDebugPort"` OR one-of
- `peb-beingdebugged.yml` — mnemonic `fs:[30h]` detection via string constants + API combo
- `peb-ntglobalflag.yml`
- `int3-scan.yml` — function body contains `int3` mnemonic and at least one `cmp`
- `vmware-io-port.yml` — mnemonic `in` + string `VMXh`
- `hypervisor-bit.yml` — mnemonic_sequence: `[cpuid, bt]`
- `cpuid-brand-string.yml` — `mnemonic: cpuid` + string ref matching `/[Vv]irtual|VMware|QEMU|Xen|Hyper-?V/`
- `sleep-skew.yml` — `api: Sleep` + `mnemonic: rdtsc`
- `sandbox-username-check.yml` — strings `SANDBOX|MALWARE|VIRUS|TEST|CURRENTUSER` etc.
- `process-list-scan.yml` — API `CreateToolhelp32Snapshot` + `Process32First|Next` combo

Author each + 2 tests per rule. Run tests. Commit.

### Task 16B: injection (8 rules)

`rules/injection/`:
- `createremotethread.yml`
- `virtualallocex-writeprocessmemory.yml` — `and` of both imports
- `setwindowshookex.yml`
- `queueuserapc.yml`
- `ntmapviewofsection.yml`
- `process-hollowing.yml` — combo `CreateProcess` suspended + `NtUnmapViewOfSection|ZwUnmapViewOfSection` + `WriteProcessMemory` + `SetThreadContext` + `ResumeThread`
- `reflective-loader.yml` — strings `"ReflectiveLoader"` OR `"kernel32.dll"` + `"GetProcAddress"` in function + no IAT
- `thread-hijack.yml` — `GetThreadContext` + `SetThreadContext` in one function

### Task 16C: persistence (7 rules)

`rules/persistence/`:
- `run-key-write.yml` — strings `Software\Microsoft\Windows\CurrentVersion\Run` + `RegSetValue*` API
- `schtasks-shell.yml` — string `"schtasks"` + `CreateProcess|ShellExecute`
- `service-install.yml` — `CreateServiceA|CreateServiceW`
- `winlogon-notify-key.yml` — string `Winlogon\\Notify`
- `ifeo-debugger.yml` — string `"Image File Execution Options"`
- `appinit-dlls.yml` — string `AppInit_DLLs`
- `wmi-event-subscription.yml` — strings `"__EventFilter"` + `"CommandLineEventConsumer"`

### Task 16D: crypto (5 rules)

`rules/crypto/`:
- `aes-sbox.yml` — string feature with the AES forward S-box first eight bytes as a literal hex string (requires strings-as-bytes; for v1 match a distinctive 8-byte hex-ascii representation OR use `not: overlay` gate plus `api: /Bcrypt|Crypt32/`)
- `rc4-ksa-pattern.yml` — mnemonic_sequence `[xor, mov, add]` + `xrefs_from: { min: 2 }` heuristic
- `crypt32-full-api-chain.yml` — `and` of `api: CryptAcquireContext*`, `api: CryptCreateHash`, `api: CryptEncrypt|CryptDecrypt`
- `bcrypt-aes.yml` — `api: BCryptOpenAlgorithmProvider` + string `AES`
- `custom-xor-loop.yml` — mnemonic_sequence `[xor, inc, cmp, jne]` OR `[xor, add, cmp]`

Note the AES S-box rule needs byte-pattern scanning which we deferred. Substitute with the API/string combo form described above; park the real byte-pattern form for v2.

### Task 16E: network (5 rules)

`rules/network/`:
- `winsock-connect.yml` — `api: connect` + `api: WSAStartup` in same function (or separate if file-scope)
- `wininet-http.yml` — `api: InternetOpen*` + `api: InternetConnect*|HttpOpenRequest*`
- `winhttp.yml` — `api: WinHttpOpen` + `api: WinHttpSendRequest`
- `dns-exfil-heuristic.yml` — `api: DnsQuery_*` + string `/[A-Za-z0-9+/]{32,}/` (base64-ish)
- `raw-sockets.yml` — `api: socket` with constant `SOCK_RAW` string OR ELF binary with `AF_PACKET`-ish strings

### Task 16F: packers (5 rules)

`rules/packers/`:
- `upx-sections.yml` — file-scope, `or` of `section: { name: /^\.UPX[0-9]$/ }` and `section: { name: /^UPX[0-9]$/ }`
- `aspack-section.yml` — section name `/^\.aspack$/` or `/\.adata/`
- `themida-tls.yml` — `tls_callbacks: true` + `or` of section names `/\.themida|\.winlice/`
- `packed-high-entropy.yml` — file-scope; `and` of any section entropy > 7.5 + imports count small (approximated as `count: { feature: { import: { lib: '*', sym: '*' } }, max: 15 }`)
- `vmprotect-sections.yml` — section name `/^\.vmp[01]$/`

### Task 16G: suspicious_api (6 rules)

`rules/suspicious_api/`:
- `manual-iat.yml` — `and` of `api: LoadLibrary.*`, `api: GetProcAddress`, `count: { feature: { import: { lib: '*', sym: '*' } }, max: 10 }`
- `dynamic-api-resolution.yml` — strings matching dozens of WinAPI names in the same function (approximated: strings contains 5+ of a known set — realize via `n_or_more` across explicit `string:` features)
- `shellcode-allocate-exec.yml` — function-scope, `and` of `api: VirtualAlloc`, `string: "PAGE_EXECUTE_READWRITE"` OR RWX constant
- `token-manipulation.yml` — `api: OpenProcessToken` + `api: /AdjustTokenPrivileges|ImpersonateLoggedOnUser/`
- `privilege-escalation-apis.yml` — `api: SeDebugPrivilege` string + `api: AdjustTokenPrivileges`
- `unhook-ntdll.yml` — function contains both string `ntdll.dll` and mnemonic `syscall` or `sysenter`

### After 16A–16G

- [ ] Run all tests:
```
cargo test -p reghidra-detect
```
Expected: every added test passes.

- [ ] Verify no parse errors across the whole bundled set:
```rust
// Add this sanity test at the bottom of tests/bundled_rules.rs
#[test]
fn every_bundled_rulefile_parses() {
    for af in available_bundled_rulefiles() {
        let src = bundled_rule_contents(&af.path).unwrap();
        parse_rules_from_str(src, &af.path)
            .unwrap_or_else(|e| panic!("{} failed to parse: {e}", af.path));
    }
}
```

Run it. Expected: pass.

- [ ] Commit the final rule set:
```bash
git add rules crates/reghidra-detect/tests/bundled_rules.rs
git commit -m "rules: bundled detection rule collection (all categories)"
```

---

## Task 17: Rules authoring guide

**Files:**
- Create: `rules/README.md`

- [ ] **Step 1: Write the guide**

Full contents listed in the spec's "Authoring guide" section — implement all 8 numbered items with worked examples. Must include:

1. Anatomy of a rule (minimal valid YAML, annotated)
2. Feature reference table (every feature from the spec + a one-line example)
3. Combinators and counts
4. Choosing a scope (function vs file)
5. Severity guidance (info / suspicious / malicious — with examples)
6. Testing your rule (`reghidra-cli detect list --binary foo.exe --rule my-rule --json` + how to add a unit test in `bundled_rules.rs`)
7. Style conventions (naming, description length, references)
8. Contributing back (PR checklist)

- [ ] **Step 2: Commit**

```bash
git add rules/README.md
git commit -m "docs: rules authoring guide"
```

---

## Task 18: CLI — `detect list`

**Files:**
- Modify: `crates/reghidra-cli/src/main.rs`
- Modify: `crates/reghidra-cli/tests/cli.rs`

- [ ] **Step 1: Add clap subcommand**

Under the root command enum, add:
```rust
/// Detection rule commands.
Detect {
    #[command(subcommand)]
    cmd: DetectCmd,
},

#[derive(Subcommand, Debug)]
enum DetectCmd {
    /// List fired detections.
    List {
        #[command(flatten)]
        target: BinaryOrSession,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        rule: Option<String>,
        #[arg(long)]
        function: Option<String>,
        #[arg(long)]
        json: bool,
    },
}
```

- [ ] **Step 2: Dispatcher**

```rust
fn run_detect_list(target: BinaryOrSession, severity: Option<String>, rule: Option<String>,
    function: Option<String>, json: bool,
) -> anyhow::Result<()> {
    let proj = open_project(target)?;
    let sev_filter = severity.as_deref().map(parse_severity).transpose()?;
    let rule_filter: Option<regex::Regex> = rule.as_deref()
        .map(regex::Regex::new).transpose()?;
    let fn_filter: Option<u64> = function.as_deref().map(parse_address_or_name(&proj)).transpose()?;

    let mut flat: Vec<(Option<u64>, reghidra_core::DetectionHit)> = Vec::new();
    for h in &proj.detection_results.file_hits { flat.push((None, h.clone())); }
    for (&addr, hs) in &proj.detection_results.function_hits {
        for h in hs { flat.push((Some(addr), h.clone())); }
    }
    flat.retain(|(addr, h)| {
        sev_filter.map_or(true, |s| h.severity == s)
        && rule_filter.as_ref().map_or(true, |r| r.is_match(&h.rule_name))
        && fn_filter.map_or(true, |want| addr.map_or(false, |a| a == want))
    });

    if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            address: Option<u64>,
            rule: &'a str,
            severity: reghidra_core::DetectionSeverity,
            description: &'a str,
            source_path: &'a str,
            match_count: u32,
        }
        let items: Vec<_> = flat.iter().map(|(a, h)| Out {
            address: *a, rule: &h.rule_name, severity: h.severity,
            description: &h.description, source_path: &h.source_path, match_count: h.match_count,
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        for sev in [reghidra_core::DetectionSeverity::Malicious,
                    reghidra_core::DetectionSeverity::Suspicious,
                    reghidra_core::DetectionSeverity::Info] {
            let subset: Vec<_> = flat.iter().filter(|(_, h)| h.severity == sev).collect();
            if subset.is_empty() { continue; }
            println!("=== {sev:?} ({}) ===", subset.len());
            for (a, h) in subset {
                match a {
                    Some(addr) => println!("  {:#010x}  {}  {}", addr, h.rule_name, h.description.lines().next().unwrap_or("")),
                    None => println!("  [file]       {}  {}", h.rule_name, h.description.lines().next().unwrap_or("")),
                }
            }
        }
    }
    Ok(())
}

fn parse_severity(s: &str) -> anyhow::Result<reghidra_core::DetectionSeverity> {
    match s { "info" => Ok(reghidra_core::DetectionSeverity::Info),
              "suspicious" => Ok(reghidra_core::DetectionSeverity::Suspicious),
              "malicious" => Ok(reghidra_core::DetectionSeverity::Malicious),
              other => anyhow::bail!("invalid severity `{other}`"), }
}
```

`BinaryOrSession`, `open_project`, `parse_address_or_name` are existing CLI helpers — check their names with `grep -n "struct BinaryOrSession\|fn open_project\|parse_address" crates/reghidra-cli/src/main.rs` and adjust calls.

- [ ] **Step 3: CLI test**

Append to `crates/reghidra-cli/tests/cli.rs`:
```rust
#[test]
fn detect_list_json_has_expected_shape() {
    let out = run(&["detect", "list", "--binary", FIXTURE_PE, "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.is_array());
}

#[test]
fn detect_list_severity_filter() {
    let out = run(&["detect", "list", "--binary", FIXTURE_PE,
        "--severity", "malicious", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for item in v.as_array().unwrap() {
        assert_eq!(item["severity"].as_str().unwrap().to_lowercase(), "malicious");
    }
}
```

`FIXTURE_PE` + `run` are existing test helpers — match their names.

- [ ] **Step 4: Run + commit**

```
cargo test -p reghidra-cli detect_list
git add crates/reghidra-cli
git commit -m "cli: detect list (read-only, --binary/--session, --json)"
```

---

## Task 19: CLI — `sources rules` subcommands

**Files:**
- Modify: `crates/reghidra-cli/src/main.rs`
- Modify: `crates/reghidra-cli/tests/cli.rs`

- [ ] **Step 1: Extend `SourcesCmd`**

Find the existing `SourcesCmd` enum (mirrors `sources flirt|archives`) and add:
```rust
/// Detection rule sources.
Rules { #[command(subcommand)] cmd: RulesCmd },

#[derive(Subcommand, Debug)]
enum RulesCmd {
    List { #[command(flatten)] target: BinaryOrSession, #[arg(long)] json: bool },
    Available { #[arg(long)] json: bool },
    Load { #[command(flatten)] session: SessionArg, stem: String },      // "subdir/stem"
    LoadUserFile { #[command(flatten)] session: SessionArg, path: PathBuf },
    Enable { #[command(flatten)] session: SessionArg, source_path: String },
    Disable { #[command(flatten)] session: SessionArg, source_path: String },
    Resolve { #[command(flatten)] target: BinaryOrSession, function: String, #[arg(long)] json: bool },
}
```

- [ ] **Step 2: Implement each dispatcher**

- `list` reads `proj.loaded_rule_files`, emits rows with `source_path`, `rules.len()`, `enabled`, `hit_count` (look up in `per_rule_file_counts`).
- `available` calls `reghidra_detect::available_bundled_rulefiles()` and prints subdir/stem/path.
- `load <stem>` splits on `/`; `session.require()`; `proj.load_bundled_rule_file(subdir, stem)`; `proj.save_session(&session.path)?`.
- `load-user-file` similar, uses `load_user_rule_file`.
- `enable`/`disable` call `set_rule_file_enabled`.
- `resolve <function>` looks up that function's hits + file-scope hits whose descriptions mention the function name (approximate — cheap).

- [ ] **Step 3: Tests**

Append to `tests/cli.rs`:
```rust
#[test]
fn sources_rules_load_then_list_shows_loaded() {
    let sess = tempfile::NamedTempFile::new().unwrap();
    run_ok(&["session", "init", "--binary", FIXTURE_PE, "--session", sess.path().to_str().unwrap()]);
    run_ok(&["sources", "rules", "load", "anti_analysis/rdtsc-timing", "--session", sess.path().to_str().unwrap()]);
    let out = run(&["sources", "rules", "list", "--session", sess.path().to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.as_array().unwrap().iter().any(|x|
        x["source_path"].as_str().unwrap().ends_with("anti_analysis/rdtsc-timing.yml")));
}

#[test]
fn sources_rules_disable_and_enable_round_trip() {
    let sess = tempfile::NamedTempFile::new().unwrap();
    run_ok(&["session", "init", "--binary", FIXTURE_PE, "--session", sess.path().to_str().unwrap()]);
    run_ok(&["sources", "rules", "load", "anti_analysis/rdtsc-timing", "--session", sess.path().to_str().unwrap()]);
    let src = "bundled:anti_analysis/rdtsc-timing.yml";
    run_ok(&["sources", "rules", "disable", src, "--session", sess.path().to_str().unwrap()]);
    let out = run(&["sources", "rules", "list", "--session", sess.path().to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let e = v.as_array().unwrap().iter().find(|x|
        x["source_path"].as_str().unwrap() == src).unwrap();
    assert_eq!(e["enabled"], serde_json::json!(false));
}

#[test]
fn sources_rules_mutations_require_session() {
    let out = run(&["sources", "rules", "load", "anti_analysis/rdtsc-timing"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--session"));
}
```

- [ ] **Step 4: Run + commit**

```
cargo test -p reghidra-cli sources_rules
git add crates/reghidra-cli
git commit -m "cli: sources rules (list/available/load/load-user-file/enable/disable/resolve)"
```

---

## Task 20: CLI README — document new surface

**Files:**
- Modify: `crates/reghidra-cli/README.md`

- [ ] **Step 1: Add sections**

Add two top-level sections that mirror existing `sources flirt` / `sources archives` layout:

- **`detect`** — subcommand-level docs with every flag, example invocations, JSON shape documented.
- **`sources rules`** — list/available/load/load-user-file/enable/disable/resolve with examples.

Keep style parallel to what's there — agents read this README first.

- [ ] **Step 2: Commit**

```bash
git add crates/reghidra-cli/README.md
git commit -m "docs: CLI README covers detect + sources rules"
```

---

## Task 21: GUI — Detections side panel

**Files:**
- Create: `crates/reghidra-gui/src/views/detections.rs`
- Modify: `crates/reghidra-gui/src/views/side_panel.rs`
- Modify: `crates/reghidra-gui/src/app.rs`

- [ ] **Step 1: Write the panel view**

`views/detections.rs`:
```rust
use crate::app::ReghidraApp;
use egui::{CollapsingHeader, ScrollArea, Ui};
use reghidra_core::{DetectionHit, DetectionSeverity};

pub const DETECTIONS_ROW_HEIGHT: f32 = 18.0;

pub fn show(ui: &mut Ui, app: &mut ReghidraApp) {
    let Some(project) = app.project.as_ref() else {
        ui.label("Open a binary to see detections.");
        return;
    };

    let mut navigate: Option<u64> = None;
    for sev in [DetectionSeverity::Malicious, DetectionSeverity::Suspicious, DetectionSeverity::Info] {
        let label = format!("{sev:?} ({})", count_by_severity(project, sev));
        CollapsingHeader::new(label).default_open(sev != DetectionSeverity::Info).show(ui, |ui| {
            let rows: Vec<(Option<u64>, &DetectionHit)> = collect_flat(project, sev);
            ScrollArea::vertical().show_rows(ui, DETECTIONS_ROW_HEIGHT, rows.len(), |ui, range| {
                for (addr, h) in &rows[range] {
                    let text = match addr {
                        Some(a) => format!("  {:#010x}  {}", a, h.rule_name),
                        None => format!("  [file]       {}", h.rule_name),
                    };
                    let resp = ui.selectable_label(false, text).on_hover_text(&h.description);
                    if resp.clicked() {
                        if let Some(a) = addr { navigate = Some(*a); }
                    }
                }
            });
        });
    }
    if let Some(addr) = navigate { app.navigate_to_address(addr); }
}

fn count_by_severity(p: &reghidra_core::project::Project, sev: DetectionSeverity) -> usize {
    p.detection_results.file_hits.iter().filter(|h| h.severity == sev).count()
    + p.detection_results.function_hits.values().flatten()
        .filter(|h| h.severity == sev).count()
}

fn collect_flat(p: &reghidra_core::project::Project, sev: DetectionSeverity)
    -> Vec<(Option<u64>, &reghidra_core::DetectionHit)>
{
    let mut v: Vec<_> = p.detection_results.file_hits.iter()
        .filter(|h| h.severity == sev).map(|h| (None, h)).collect();
    let mut fns: Vec<_> = p.detection_results.function_hits.iter()
        .flat_map(|(a, hs)| hs.iter().filter(|h| h.severity == sev).map(move |h| (Some(*a), h)))
        .collect();
    fns.sort_by_key(|(a, _)| *a);
    v.extend(fns);
    v
}
```

- [ ] **Step 2: Wire into `side_panel.rs`**

Find the existing `SidePanelTab` enum / tab bar (`grep -n "enum SidePanelTab\|Functions\|Symbols" views/side_panel.rs`). Add a `Detections` variant and a draw-arm:
```rust
SidePanelTab::Detections => crate::views::detections::show(ui, app),
```
Add a new tab button "Detections".

- [ ] **Step 3: Register module**

In `views/mod.rs` (or wherever views are listed), add `pub mod detections;`.

- [ ] **Step 4: Verify manually**

Run: `cargo run -p reghidra-gui --release -- tests/fixtures/wildfire-test-pe-file.exe`

Confirm:
- New "Detections" tab in the side panel.
- Clicking a function-scope leaf scrolls disasm/decompile to that address.
- Empty severity groups still render (with "(0)" count).

- [ ] **Step 5: Commit**

```bash
git add crates/reghidra-gui
git commit -m "gui: Detections side panel"
```

---

## Task 22: GUI — Loaded Data Sources panel, Rules section

**Files:**
- Modify: `crates/reghidra-gui/src/views/data_sources.rs`

- [ ] **Step 1: Add a third section**

Below the existing FLIRT + Type Archives sections in `data_sources.rs`, add a "Detection Rules" `CollapsingHeader`. Rows come from `project.loaded_rule_files` with:
- Enable/disable checkbox
- Rule count, hit count, source path
- Parse-error indicator (yellow `⚠` icon + tooltip if `parse_errors` non-empty)

Use the **action-queue pattern** already in this file — buffer `(source_path, new_enabled)` tuples during the immutable `Grid::show` closure, drain with `&mut project` after.

- [ ] **Step 2: "Load…" buttons**

- "Load bundled…" — nested `CollapsingHeader` per `<subdir>` from `available_bundled_rulefiles()` minus already-loaded. Click → enqueue `LoadBundled(subdir, stem)`.
- "Load user file…" — `rfd::FileDialog`; enqueue `LoadUserFile(path)`.

- [ ] **Step 3: Manual verification**

Run the GUI, open a PE, see the Rules section. Toggle a checkbox, confirm the Detections panel refreshes.

- [ ] **Step 4: Commit**

```bash
git add crates/reghidra-gui
git commit -m "gui: Loaded Data Sources panel shows detection rules section"
```

---

## Task 23: GUI — Function-row badge + decompile banner

**Files:**
- Modify: `crates/reghidra-gui/src/views/side_panel.rs` (Functions tab)
- Modify: `crates/reghidra-gui/src/views/decompile.rs`
- Modify: `crates/reghidra-gui/src/theme.rs`

- [ ] **Step 1: Theme colors**

In `theme.rs`, add three colors (and matching `Theme::dark`/`Theme::light` defaults):
```rust
    pub detection_info: Color32,
    pub detection_suspicious: Color32,
    pub detection_malicious: Color32,
```
Dark: greenish / amber / red. Light: Solarized equivalents.

- [ ] **Step 2: Function-row badge**

In the Functions side-panel tab (`views/side_panel.rs`), when a row renders, look up `project.detection_results.function_hits.get(&func.entry)`. If present, paint a small `8x8` circle in the highest severity's color, positioned right of the name. Hover tooltip lists rule names.

- [ ] **Step 3: Decompile-view banner**

At the top of `views/decompile.rs` render (before the signature line), for the current function:
```rust
if let Some(hits) = proj.detection_results.function_hits.get(&current_func_entry) {
    if !hits.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label("⚠");
            let rules: Vec<String> = hits.iter().map(|h| h.rule_name.clone()).collect();
            ui.label(format!("{} detection{}:", hits.len(), if hits.len() == 1 { "" } else { "s" }));
            for (i, h) in hits.iter().enumerate() {
                if i > 0 { ui.label("·"); }
                let color = match h.severity {
                    DetectionSeverity::Info => theme.detection_info,
                    DetectionSeverity::Suspicious => theme.detection_suspicious,
                    DetectionSeverity::Malicious => theme.detection_malicious,
                };
                if ui.add(egui::Label::new(egui::RichText::new(&h.rule_name).color(color))
                    .sense(egui::Sense::click())).clicked()
                {
                    app.copy_to_clipboard(&h.rule_name);
                }
                ui.label("").on_hover_text(&h.description);
            }
        });
        ui.separator();
    }
}
```

- [ ] **Step 4: Manual verification**

Open a binary with bundled rules loaded. At least a few detections should fire on any real PE (the sandbox-scan/rdtsc-timing rules fire on most MSVC binaries). Confirm dots appear in Functions list and banner appears in decompile view.

- [ ] **Step 5: Commit**

```bash
git add crates/reghidra-gui
git commit -m "gui: detection badges in Functions panel, banner in decompile view"
```

---

## Task 24: GUI — Palette commands

**Files:**
- Modify: `crates/reghidra-gui/src/palette.rs`

- [ ] **Step 1: Add commands**

Find the existing `Command` enum / palette action list. Add:
- `"Toggle Detections Panel"` → switches side-panel tab to Detections
- `"Reload Detection Rules"` → calls `project.evaluate_detections()` (no reload of sources — just re-run)
- `"Load Detection Rules…"` → opens file picker, calls `project.load_user_rule_file`

- [ ] **Step 2: Commit**

```bash
git add crates/reghidra-gui
git commit -m "gui: command palette entries for detections"
```

---

## Task 25: End-to-end integration test

**Files:**
- Modify: `crates/reghidra-core/tests/detect_pipeline.rs`

- [ ] **Step 1: Pin the fixture's detection set**

Open the wildfire fixture with default (auto-loaded) bundled rules; assert a stable set of rule names fires. Run:
```bash
cargo run -p reghidra-cli -- detect list --binary tests/fixtures/wildfire-test-pe-file.exe --json | jq '[.[].rule] | unique | sort'
```

Paste the output into the test as the expected set. Example:
```rust
#[test]
fn wildfire_fixture_fires_expected_rules() {
    let proj = reghidra_core::project::Project::open(
        "tests/fixtures/wildfire-test-pe-file.exe").unwrap();
    let mut fired: Vec<String> = proj.detection_results.file_hits.iter()
        .map(|h| h.rule_name.clone())
        .chain(proj.detection_results.function_hits.values()
            .flatten().map(|h| h.rule_name.clone()))
        .collect();
    fired.sort();
    fired.dedup();

    let expected: Vec<&str> = vec![
        // PASTE exact names from the jq output above.
    ];
    let expected_set: std::collections::BTreeSet<_> = expected.iter().map(|s| s.to_string()).collect();
    let fired_set: std::collections::BTreeSet<_> = fired.into_iter().collect();
    assert_eq!(fired_set, expected_set,
        "rule firing set drifted; update test if intentional");
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p reghidra-core wildfire_fixture_fires_expected_rules`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add crates/reghidra-core/tests/detect_pipeline.rs
git commit -m "tests: wildfire fixture detection regression canary"
```

---

## Task 26: Final verification

- [ ] **Step 1: Full test suite**

```bash
cargo test --workspace
```
Expected: all pass.

- [ ] **Step 2: Clippy on just this PR's crates**

```bash
cargo clippy -p reghidra-detect -p reghidra-core -p reghidra-cli -p reghidra-gui -- -D warnings
```
Expected: clean. (Note: workspace-wide clippy has known baseline failures in `reghidra-ir/optimize.rs` — do NOT run clippy on the whole workspace.)

- [ ] **Step 3: Release build compiles**

```bash
cargo build --release --workspace
```
Expected: clean.

- [ ] **Step 4: Manual GUI smoke**

```bash
cargo run --release -p reghidra-gui -- tests/fixtures/wildfire-test-pe-file.exe
```

Check:
- Detections side panel shows hits.
- Click a function-scope hit → navigates.
- Loaded Data Sources → Rules section toggles propagate.
- Decompile banner visible on a detected function.
- Ctrl/Cmd-K palette → "Reload Detection Rules" works.

- [ ] **Step 5: Update CLAUDE.md**

Add a "Phase 5e — YAML Detection Rules [DONE]" section to `CLAUDE.md` summarizing what shipped, mirroring the existing phase sections. Keep it tight — one paragraph per subsystem (engine / rules / CLI / GUI) with the key invariants future contributors need.

- [ ] **Step 6: Final commit + open PR**

```bash
git add CLAUDE.md
git commit -m "docs: Phase 5e notes in CLAUDE.md"
```

Then open the PR per the repo's usual flow — do NOT auto-open until the user confirms.

---

## Follow-up task (separate PR)

**egui_kittest harness.** After this PR merges, stand up `egui_kittest` (see `crates/reghidra-gui/tests/kittest_smoke.rs` as the new home) and write tests that:
1. Build a synthetic `Project` with two function-scope detections.
2. Render the Detections panel and assert rule names appear.
3. Simulate a click on a leaf and assert the selected-address state changes.
4. Render the decompile banner and assert the rule-name label is present.

Scope as its own plan — doesn't block this feature shipping.
