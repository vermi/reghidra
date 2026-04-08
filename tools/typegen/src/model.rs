//! Local copy of the [`reghidra_decompile::type_archive`] data model.
//!
//! This crate sits outside the main Reghidra workspace and deliberately
//! avoids taking a path dependency on `reghidra-decompile` — that would
//! pull in `reghidra-ir`, `capstone`, and a transitive chain we don't
//! need for archive generation. Instead we duplicate the struct
//! definitions here and rely on postcard's structural wire format to
//! keep the two in sync. Any field change in the main crate must be
//! mirrored here; the CI drift check (PR 3 step 6) will catch
//! divergence by refusing to regenerate an archive whose on-disk shape
//! differs from the checked-in version.
//!
//! **If you edit these structs, you MUST make the same edit to
//! `crates/reghidra-decompile/src/type_archive/mod.rs`** (and bump
//! `ARCHIVE_VERSION` if the change is not backwards compatible through
//! serde defaults).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Must match `reghidra_decompile::type_archive::ARCHIVE_VERSION`.
pub const ARCHIVE_VERSION: u32 = 1;

// Why `BTreeMap` here but `HashMap` on the runtime side?
//
// This is the TOOL side: it serializes archives into bytes that get
// checked into the repo and diffed by the CI drift check. `HashMap`'s
// iteration order is randomized per-process (SipHash with a random
// seed), so two runs of the tool with identical input would produce
// different byte sequences and the drift check would fail spuriously
// on every CI run. `BTreeMap` iterates in sorted key order, giving
// byte-stable output.
//
// The runtime side (`reghidra-decompile::type_archive`) deserializes
// these bytes into its own maps. Postcard's wire format for both
// `HashMap<K, V>` and `BTreeMap<K, V>` is the same: a length-prefixed
// sequence of (K, V) pairs. So the runtime can use whichever
// collection is ergonomic there (currently `HashMap` — no ordering
// needs at lookup time) without affecting the archive format or
// breaking compatibility with the tool-produced bytes.
//
// If you change the runtime side to `BTreeMap`, nothing here needs
// to change. If you change this side to `HashMap`, CI drift checks
// will start failing on every run and you'll have a bad time.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeArchive {
    pub name: String,
    pub version: u32,
    pub functions: BTreeMap<String, FunctionType>,
    pub types: BTreeMap<String, TypeDef>,
}

impl TypeArchive {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: ARCHIVE_VERSION,
            functions: BTreeMap::new(),
            types: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionType {
    pub name: String,
    pub args: Vec<ArgType>,
    pub return_type: TypeRef,
    pub calling_convention: CallingConvention,
    pub is_variadic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgType {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeRef {
    Primitive(Primitive),
    Pointer(Box<TypeRef>),
    Array(Box<TypeRef>, u32),
    FunctionPointer(Box<FunctionType>),
    Named(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Primitive {
    Void,
    Bool,
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Char,
    WChar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallingConvention {
    Default,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Win64,
    SysV64,
    Aapcs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    pub name: String,
    pub kind: TypeDefKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeDefKind {
    Alias(TypeRef),
    Struct {
        fields: Vec<StructField>,
        size: Option<u32>,
    },
    Union {
        fields: Vec<StructField>,
        size: Option<u32>,
    },
    Enum {
        underlying: Primitive,
        variants: Vec<(String, i64)>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub ty: TypeRef,
    pub offset: u32,
}
