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
