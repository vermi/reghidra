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
                name.as_ref().is_none_or(|m| m.is_match(&s.name))
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
