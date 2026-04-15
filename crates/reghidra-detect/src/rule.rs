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
