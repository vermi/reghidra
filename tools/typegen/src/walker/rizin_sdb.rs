//! Walker for Rizin's `librz/arch/types/*.sdb.txt` type database.
//!
//! Rizin (GPLv3) ships a hand-curated text-format function-signature
//! database at `librz/arch/types/` covering POSIX, Linux, macOS,
//! Android, and ~35 per-header Windows API headers. Each file is a
//! flat `key=value` list that describes one function per group of
//! lines:
//!
//! ```text
//! #### winbase.h ####              <- section comment, skipped
//!
//! GlobalAlloc=func
//! func.GlobalAlloc.args=2
//! func.GlobalAlloc.arg.0=UINT,uFlags
//! func.GlobalAlloc.arg.1=SIZE_T,dwBytes
//! func.GlobalAlloc.ret=HGLOBAL
//! func.GlobalAlloc.cc=stdapi         <- optional
//! func.GlobalAlloc.noreturn=true     <- optional
//! ```
//!
//! The format is trivially line-oriented; no nesting, no escaping.
//! This walker reads one or more SDB files from a caller-supplied
//! path (file or directory), parses the key=value pairs into a
//! [`TypeArchive`], and returns it. It does NOT fetch or check out
//! the Rizin source tree itself — the CLI expects `--input` to
//! point at either a single `.sdb.txt` file or a directory
//! containing one or more such files.
//!
//! # License
//!
//! Rizin's SDB content is GPLv3. Reghidra itself is GPL-3.0-or-later
//! (as of the PR 4g relicense), so derived archives can be bundled
//! under the same terms. **Any archive produced by this walker must
//! carry the source file path and Rizin commit SHA in the archive
//! metadata, and the project LICENSE must call out the Rizin import
//! explicitly.** The walker currently encodes the source path in the
//! archive's `name` field (e.g. `rizin-libc@<commit>`) — callers are
//! responsible for passing a sensible `--name` or `--out` that makes
//! provenance clear.
//!
//! # Parser scope
//!
//! This walker parses only the `func.*` key space. It ignores:
//!
//! - `cc-*.sdb.txt` files (calling convention definitions; not
//!   function signatures) — skipped at load time.
//! - `types-*.sdb.txt` files (struct/union/enum definitions) — a
//!   follow-up may add struct extraction, but for the MSVC CRT
//!   typing gap we're trying to close, function signatures alone
//!   are sufficient.
//! - Any non-`func.*` keys (`noreturn` hints, `cc` calling convention
//!   references — for now we default to `CallingConvention::Default`
//!   and let the decompiler pick based on platform).
//!
//! Unknown or unparseable type strings are coerced to
//! `TypeRef::Named(string)` so downstream consumers still get a
//! printable name even if we don't understand the declaration.

use crate::model::{
    ArgType, CallingConvention, FunctionType, Primitive, TypeArchive, TypeRef,
};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Walk a single SDB file or a directory of SDB files and produce a
/// [`TypeArchive`]. When `input` is a directory, every file whose
/// name starts with `functions-` and ends with `.sdb.txt` is
/// processed; other files are skipped. When `input` is a single
/// file, it's processed regardless of name (so maintainers can
/// feed cc-*.sdb.txt or types-*.sdb.txt manually if a future walker
/// variant wants them, though the current parser will ignore
/// non-`func.*` keys).
///
/// `filter_prefixes` further restricts directory-mode discovery to
/// files matching `functions-{prefix}*.sdb.txt` for at least one of
/// the supplied prefixes. An empty slice disables filtering and the
/// directory walk falls back to the unrestricted `functions-*.sdb.txt`
/// pattern. Single-file inputs ignore the filter — the maintainer is
/// expected to know what they passed.
pub fn walk(input: &Path, archive_name: &str, filter_prefixes: &[String]) -> Result<TypeArchive> {
    let mut archive = TypeArchive::new(archive_name);

    let files: Vec<PathBuf> = if input.is_dir() {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(input)
            .with_context(|| format!("reading directory {}", input.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !(name.starts_with("functions-") && name.ends_with(".sdb.txt")) {
                continue;
            }
            if !filter_prefixes.is_empty() {
                // Match `functions-{prefix}` exactly OR
                // `functions-{prefix}.sdb.txt` OR
                // `functions-{prefix}_...sdb.txt`. The trailing
                // delimiter check stops `linux` from matching
                // `linux64` style names if they ever appear; today
                // there are none, but it's the obviously correct
                // semantics for a prefix filter.
                let stem = &name["functions-".len()..name.len() - ".sdb.txt".len()];
                let matches = filter_prefixes.iter().any(|p| {
                    stem == p.as_str()
                        || stem
                            .strip_prefix(p.as_str())
                            .map(|rest| rest.starts_with('_') || rest.starts_with('.'))
                            .unwrap_or(false)
                });
                if !matches {
                    continue;
                }
            }
            out.push(path);
        }
        out.sort();
        out
    } else if input.is_file() {
        vec![input.to_path_buf()]
    } else {
        return Err(anyhow!(
            "input path does not exist or is not a file/directory: {}",
            input.display()
        ));
    };

    if files.is_empty() {
        return Err(anyhow!(
            "no SDB files found at {} (expected functions-*.sdb.txt{})",
            input.display(),
            if filter_prefixes.is_empty() {
                String::new()
            } else {
                format!(" matching prefixes {filter_prefixes:?}")
            }
        ));
    }

    log::info!("walking {} SDB file(s)", files.len());

    for file in &files {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("reading {}", file.display()))?;
        let n_before = archive.functions.len();
        parse_sdb_into(&text, &mut archive.functions)
            .with_context(|| format!("parsing {}", file.display()))?;
        log::info!(
            "  {}: +{} functions",
            file.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
            archive.functions.len() - n_before
        );
    }

    Ok(archive)
}

/// Parse the text of one SDB file into the supplied functions map.
///
/// Exposed separately from [`walk`] so tests can run against inlined
/// SDB content without touching the filesystem.
pub fn parse_sdb_into(
    text: &str,
    functions: &mut BTreeMap<String, FunctionType>,
) -> Result<()> {
    // First pass: collect all key=value pairs into a flat map keyed
    // on the full key string. The SDB format has no intrinsic
    // grouping — all `func.NAME.*` keys for one function appear in
    // arbitrary order within a section — so we build the index first
    // and then materialize FunctionType records from it.
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // Skip blank lines and section comments (`#### header.h ####`).
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            // Lines without `=` are silently ignored. The SDB format
            // doesn't use any other line shape, so a malformed line
            // is either a typo in the source or a comment we missed.
            continue;
        };
        kv.insert(key.trim().to_string(), value.trim().to_string());
    }

    // Second pass: walk the keys looking for `NAME=func` entries and
    // build a FunctionType for each. `func.NAME.*` keys are resolved
    // via lookup against the flat map. Any missing required key
    // (args, arg.N, ret) causes that particular function to be
    // skipped with a log warning rather than failing the whole file
    // — partial data is better than no data.
    for (key, value) in kv.iter() {
        if value != "func" || key.contains('.') {
            continue;
        }
        let name = key.as_str();
        match build_function(name, &kv) {
            Ok(ft) => {
                functions.insert(name.to_string(), ft);
            }
            Err(e) => {
                log::debug!("  skipped {name}: {e}");
            }
        }
    }

    Ok(())
}

fn build_function(name: &str, kv: &BTreeMap<String, String>) -> Result<FunctionType> {
    let args_key = format!("func.{name}.args");
    let n_args: usize = kv
        .get(&args_key)
        .ok_or_else(|| anyhow!("missing {args_key}"))?
        .parse()
        .with_context(|| format!("parsing {args_key}"))?;

    let mut args = Vec::with_capacity(n_args);
    for i in 0..n_args {
        let arg_key = format!("func.{name}.arg.{i}");
        let Some(raw) = kv.get(&arg_key) else {
            return Err(anyhow!("missing {arg_key}"));
        };
        // Format: `TYPE,PARAMNAME`. The type can contain commas
        // (`struct x, y`? — doesn't happen in practice in Rizin SDB,
        // but be defensive). Split on the LAST comma to be safe.
        let (ty_str, param_name) = match raw.rsplit_once(',') {
            Some((t, n)) => (t.trim(), n.trim()),
            None => (raw.trim(), ""),
        };
        args.push(ArgType {
            name: param_name.to_string(),
            ty: parse_type_string(ty_str),
        });
    }

    let ret_key = format!("func.{name}.ret");
    let ret_str = kv
        .get(&ret_key)
        .ok_or_else(|| anyhow!("missing {ret_key}"))?;
    let return_type = parse_type_string(ret_str);

    // `func.NAME.cc` is optional. Rizin's calling-convention names
    // (`cdecl`, `stdcall`, `fastcall`, `stdapi`, etc.) don't all
    // map cleanly to our enum, so we treat it as an advisory hint
    // and default to `Default` otherwise. The runtime side resolves
    // calling convention per-platform anyway.
    let cc_key = format!("func.{name}.cc");
    let calling_convention = match kv.get(&cc_key).map(String::as_str) {
        Some("cdecl") => CallingConvention::Cdecl,
        Some("stdcall") | Some("stdapi") => CallingConvention::Stdcall,
        Some("fastcall") => CallingConvention::Fastcall,
        Some("thiscall") => CallingConvention::Thiscall,
        Some("ms") => CallingConvention::Win64,
        Some("amd64") => CallingConvention::SysV64,
        Some("arm64") | Some("arm32") => CallingConvention::Aapcs,
        _ => CallingConvention::Default,
    };

    Ok(FunctionType {
        name: name.to_string(),
        args,
        return_type,
        calling_convention,
        is_variadic: false,
    })
}

/// Convert a Rizin SDB type string (`"int"`, `"char*"`, `"const char*"`,
/// `"FILE*"`, `"HANDLE"`, etc.) into a [`TypeRef`].
///
/// Strategy:
/// 1. Strip `const` and whitespace normalization.
/// 2. Count trailing `*`s for pointer depth.
/// 3. The remaining base name is either a recognized primitive
///    (via [`parse_primitive`]) or a `TypeRef::Named(base)` fallback.
///
/// This is deliberately permissive: unknown types become `Named(...)`
/// so the decompiler still has a printable name even if we don't
/// understand the underlying shape. Named types also integrate
/// naturally with the runtime archive's `types` map (future struct
/// walker) because the runtime resolves them by name on demand.
fn parse_type_string(raw: &str) -> TypeRef {
    // Normalize whitespace and strip `const` / `volatile` qualifiers.
    // Rizin SDB uses them sparingly but consistently where present.
    let mut s = raw.trim().to_string();
    for q in ["const ", "volatile ", "restrict "] {
        while let Some(idx) = s.find(q) {
            s.replace_range(idx..idx + q.len(), "");
        }
    }
    // Also drop `struct `/`union `/`enum ` tag prefixes — Rizin uses
    // them for C struct tags (`struct sockaddr*`), but we want the
    // bare tag as the type name so it matches what the archive's
    // types map would key on later.
    for tag in ["struct ", "union ", "enum " ] {
        while let Some(idx) = s.find(tag) {
            s.replace_range(idx..idx + tag.len(), "");
        }
    }
    let s = s.trim();

    // Count trailing `*`s for pointer depth.
    let base_end = s.trim_end_matches('*').len();
    let ptr_depth = s.len() - base_end;
    let base = s[..base_end].trim();

    let mut inner = if let Some(prim) = parse_primitive(base) {
        TypeRef::Primitive(prim)
    } else if base.is_empty() {
        // Shouldn't happen — type with only `*`s is malformed.
        TypeRef::Primitive(Primitive::Void)
    } else {
        TypeRef::Named(base.to_string())
    };
    for _ in 0..ptr_depth {
        inner = TypeRef::Pointer(Box::new(inner));
    }
    inner
}

fn parse_primitive(name: &str) -> Option<Primitive> {
    match name {
        "void" => Some(Primitive::Void),
        "bool" | "_Bool" => Some(Primitive::Bool),
        "char" => Some(Primitive::Char),
        "wchar_t" | "WCHAR" => Some(Primitive::WChar),
        "int8_t" | "signed char" => Some(Primitive::Int8),
        "uint8_t" | "unsigned char" | "BYTE" | "byte" => Some(Primitive::UInt8),
        "int16_t" | "short" | "short int" | "signed short" => Some(Primitive::Int16),
        "uint16_t" | "unsigned short" | "WORD" => Some(Primitive::UInt16),
        "int32_t" | "int" | "signed int" | "long" | "signed long" => {
            Some(Primitive::Int32)
        }
        "uint32_t" | "unsigned int" | "unsigned" | "unsigned long" | "DWORD" => {
            Some(Primitive::UInt32)
        }
        "int64_t" | "long long" | "signed long long" | "__int64" => Some(Primitive::Int64),
        "uint64_t" | "unsigned long long" | "QWORD" | "__uint64" | "size_t" | "SIZE_T" => {
            Some(Primitive::UInt64)
        }
        "float" => Some(Primitive::Float),
        "double" | "long double" => Some(Primitive::Double),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sdb() -> &'static str {
        // Minimal slice mirroring the real Rizin SDB format, with a
        // handful of functions covering the common shapes: zero-arg,
        // one-arg with pointer and param name, multi-arg, cc hint,
        // and const-qualified types.
        r#"
#### stdlib.h ####

malloc=func
func.malloc.args=1
func.malloc.arg.0=size_t,size
func.malloc.ret=void*

free=func
func.free.args=1
func.free.arg.0=void*,ptr
func.free.ret=void

strcmp=func
func.strcmp.args=2
func.strcmp.arg.0=const char*,s1
func.strcmp.arg.1=const char*,s2
func.strcmp.ret=int

GetLastError=func
func.GetLastError.args=0
func.GetLastError.ret=DWORD
func.GetLastError.cc=stdapi

CreateFileA=func
func.CreateFileA.args=3
func.CreateFileA.arg.0=LPCSTR,lpFileName
func.CreateFileA.arg.1=DWORD,dwAccess
func.CreateFileA.arg.2=struct sockaddr*,ignored
func.CreateFileA.ret=HANDLE
func.CreateFileA.cc=stdapi
"#
    }

    #[test]
    fn parses_basic_functions() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        assert!(fns.contains_key("malloc"));
        assert!(fns.contains_key("free"));
        assert!(fns.contains_key("strcmp"));
        assert!(fns.contains_key("GetLastError"));
        assert!(fns.contains_key("CreateFileA"));
    }

    #[test]
    fn malloc_signature_is_correct() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        let m = fns.get("malloc").unwrap();
        assert_eq!(m.args.len(), 1);
        assert_eq!(m.args[0].name, "size");
        // size_t → UInt64 primitive
        assert!(matches!(m.args[0].ty, TypeRef::Primitive(Primitive::UInt64)));
        // void* return
        match &m.return_type {
            TypeRef::Pointer(inner) => {
                assert!(matches!(**inner, TypeRef::Primitive(Primitive::Void)));
            }
            other => panic!("expected void*, got {other:?}"),
        }
    }

    #[test]
    fn const_char_pointer_parses() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        let c = fns.get("strcmp").unwrap();
        assert_eq!(c.args.len(), 2);
        // `const char*` → Pointer(Primitive::Char); const is stripped.
        match &c.args[0].ty {
            TypeRef::Pointer(inner) => {
                assert!(matches!(**inner, TypeRef::Primitive(Primitive::Char)));
            }
            other => panic!("expected char*, got {other:?}"),
        }
    }

    #[test]
    fn unknown_named_type_becomes_named_ref() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        let g = fns.get("GetLastError").unwrap();
        // DWORD is in the primitives table → UInt32.
        assert!(matches!(g.return_type, TypeRef::Primitive(Primitive::UInt32)));

        let cf = fns.get("CreateFileA").unwrap();
        // HANDLE isn't in the primitives table → Named("HANDLE").
        match &cf.return_type {
            TypeRef::Named(n) => assert_eq!(n, "HANDLE"),
            other => panic!("expected Named(HANDLE), got {other:?}"),
        }
    }

    #[test]
    fn stdapi_cc_maps_to_stdcall() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        let g = fns.get("GetLastError").unwrap();
        assert!(matches!(g.calling_convention, CallingConvention::Stdcall));
    }

    #[test]
    fn struct_tag_prefix_is_stripped() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        let cf = fns.get("CreateFileA").unwrap();
        // Third arg is declared `struct sockaddr*` — the `struct ` tag
        // should be stripped and we should see Pointer(Named(sockaddr)).
        match &cf.args[2].ty {
            TypeRef::Pointer(inner) => match inner.as_ref() {
                TypeRef::Named(n) => assert_eq!(n, "sockaddr"),
                other => panic!("expected Named(sockaddr), got {other:?}"),
            },
            other => panic!("expected Pointer, got {other:?}"),
        }
    }

    #[test]
    fn zero_arg_function_parses() {
        let mut fns = BTreeMap::new();
        parse_sdb_into(sample_sdb(), &mut fns).unwrap();
        let g = fns.get("GetLastError").unwrap();
        assert_eq!(g.args.len(), 0);
    }

    #[test]
    fn missing_required_key_skips_function_gracefully() {
        // Missing `args` key: the function should be skipped rather
        // than failing the whole parse.
        let text = r#"
broken=func
func.broken.ret=void

working=func
func.working.args=0
func.working.ret=void
"#;
        let mut fns = BTreeMap::new();
        parse_sdb_into(text, &mut fns).unwrap();
        assert!(!fns.contains_key("broken"));
        assert!(fns.contains_key("working"));
    }

    #[test]
    fn blank_lines_and_section_comments_ignored() {
        let text = r#"
#### winbase.h ####


# stray comment



foo=func
func.foo.args=0
func.foo.ret=void
"#;
        let mut fns = BTreeMap::new();
        parse_sdb_into(text, &mut fns).unwrap();
        assert_eq!(fns.len(), 1);
        assert!(fns.contains_key("foo"));
    }
}
