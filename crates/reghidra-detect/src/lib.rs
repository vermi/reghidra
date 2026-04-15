//! YAML-driven detection engine for reghidra.
//!
//! Evaluates declarative rules against a [`Features`] snapshot derived from a
//! [`reghidra_core::project::Project`] and returns [`DetectionHit`]s.

pub mod entropy;
pub mod rule;
pub mod parser;
pub mod features;

pub use rule::{
    CompileError, Comparison, CountRange, FeatureExpr, Rule, Scope, Severity, StrMatcher,
};
pub use parser::parse_rules_from_str;
pub use features::{
    BinaryFormat, FileFeatures, Features, FunctionFeatures, Import, PeFeatures,
    RichEntry, SectionInfo,
};
