//! Walker for the `libc` crate.
//!
//! `libc` declares POSIX functions and types as plain Rust with
//! `extern "C" { pub fn ... }` blocks, `pub type` aliases, and
//! `#[repr(C)] pub struct` definitions. Source files are organized
//! under `src/` by target OS and architecture with `#[cfg(target_os =
//! ...)]` / `#[cfg(target_arch = ...)]` gating at the `mod` level.
//!
//! The walker strategy:
//!
//! 1. Locate the `libc` source directory via `cargo metadata`. Cargo's
//!    metadata command is the only reliable way to resolve a
//!    dependency's filesystem location — `CARGO_MANIFEST_DIR` points
//!    at this tool crate, not the dep, and registry paths vary by
//!    user / machine.
//!
//! 2. Parse `src/lib.rs` with `syn::parse_file`, then recursively
//!    follow `mod Foo;` declarations to their file locations
//!    (`Foo.rs` or `Foo/mod.rs`), filtering by the target OS's
//!    `#[cfg(target_os = ...)]` attribute at each step. This mirrors
//!    what `cargo` would do during compilation but without needing to
//!    actually invoke the compiler.
//!
//! 3. At each module, extract `extern "C" { pub fn ... }` blocks
//!    (`ItemForeignMod`), `pub type` aliases (`ItemType`), and
//!    `pub struct` definitions (`ItemStruct`) into the archive.
//!
//! 4. Return the populated archive for the caller to serialize.
//!
//! This PR (PR 3) only covers functions and type aliases — the struct
//! walk is stubbed out and will be wired in during PR 4 when the
//! typing consumers land and we have a concrete need for field
//! layout. Leaving it stubbed keeps PR 3 small and avoids burning time
//! on repr/alignment edge cases before we have consumers to validate
//! against.

use crate::model::{
    ArgType, CallingConvention, FunctionType, TypeArchive, TypeDef, TypeDefKind, TypeRef,
};
use crate::walker::rust_ty::{rust_type_to_ref, TypeCtx};
use crate::Target;
use anyhow::{anyhow, Context, Result};
use cargo_metadata::MetadataCommand;
use proc_macro2::TokenStream;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use syn::parse::{Parse, ParseStream};
use syn::{
    braced, Abi, Attribute, ForeignItem, ForeignItemFn, Item, ItemForeignMod, ItemMod, ItemType,
    Lit, LitStr, Meta, MetaNameValue, ReturnType, Token,
};

/// Resolve the `libc` crate's source directory using `cargo metadata`.
/// Returns the directory containing `src/lib.rs` for the version of
/// libc pinned in this tool's Cargo.toml.
pub fn find_source_dir() -> Result<PathBuf> {
    // Run `cargo metadata` inside this crate's directory so it picks
    // up our Cargo.toml (which lists libc as a dep), not the root
    // Reghidra workspace (which doesn't). We pass an explicit
    // manifest path to make the behavior independent of cwd.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest)
        .exec()
        .with_context(|| format!("cargo metadata failed for {}", manifest.display()))?;

    let pkg = metadata
        .packages
        .iter()
        .find(|p| p.name.as_str() == "libc")
        .ok_or_else(|| anyhow!("libc not listed as a dependency of reghidra-typegen"))?;

    let src = pkg
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("libc manifest path has no parent: {}", pkg.manifest_path))?
        .join("src");
    Ok(src.into_std_path_buf())
}

/// Walk the `libc` source tree rooted at `src_dir`, producing an
/// archive for the given target OS. Archive name goes into the
/// `TypeArchive::name` metadata field for display.
pub fn walk(src_dir: &Path, target: Target, archive_name: &str) -> Result<TypeArchive> {
    let mut archive = TypeArchive::new(archive_name);
    let mut visited: HashSet<PathBuf> = HashSet::new();

    // Both supported libc targets (Linux and macOS) are LP64 on the
    // architectures we care about (x86-64, ARM64). 32-bit libc archives
    // aren't a current goal; if they become one, split this by
    // (target_os, target_arch) and add an `--arch` CLI flag.
    let type_ctx = TypeCtx::LP64;

    let lib_rs = src_dir.join("lib.rs");
    walk_file(&lib_rs, target, type_ctx, &mut archive, &mut visited)
        .with_context(|| format!("walking {}", lib_rs.display()))?;

    Ok(archive)
}

/// Recursively walk one source file, extracting items into `archive`
/// and descending into `mod` declarations whose `cfg` predicates
/// permit the current target. `visited` tracks which files we've
/// already processed to break cycles (libc has a few `#[path = ...]`
/// reexports that can reference the same file from multiple parents).
fn walk_file(
    path: &Path,
    target: Target,
    type_ctx: TypeCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    if !path.exists() {
        // Missing file is not fatal — it usually means the parent
        // module's `mod foo;` declaration is gated behind a cfg we
        // haven't matched, and libc pruned the corresponding file
        // from the crate for this target. Log and move on.
        log::debug!("skipping missing file: {}", path.display());
        return Ok(());
    }

    let source = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file = syn::parse_file(&source)
        .with_context(|| format!("parsing {}", path.display()))?;

    let parent_dir = path.parent().unwrap_or_else(|| Path::new(""));
    for item in &file.items {
        handle_item(item, parent_dir, target, type_ctx, archive, visited)?;
    }
    Ok(())
}

/// Process one top-level item: descend into modules, extract extern
/// functions and type aliases, handle `cfg_if!` macro expansion, and
/// (eventually in PR 4) extract struct definitions.
fn handle_item(
    item: &Item,
    parent_dir: &Path,
    target: Target,
    type_ctx: TypeCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    match item {
        Item::Mod(m) => handle_mod(m, parent_dir, target, type_ctx, archive, visited)?,
        Item::ForeignMod(fm) => handle_foreign_mod(fm, type_ctx, archive),
        Item::Type(t) => handle_type_alias(t, target, type_ctx, archive),
        Item::Macro(m) => handle_macro(m, parent_dir, target, type_ctx, archive, visited)?,
        // ItemStruct / ItemUnion / ItemEnum fall through to the stub.
        // PR 4 wires them in once the typed-decl consumers need field
        // layout info. Ignoring them for now keeps the archive size
        // down and avoids repr/alignment edge cases until there's a
        // consumer to validate against.
        _ => {}
    }
    Ok(())
}

/// Handle top-level macro invocations. `libc` uses several custom
/// macros that wrap what would otherwise be plain items:
///
/// - **`cfg_if! { if #[cfg(...)] { ... } else if ... { ... } else { ... } }`**
///   — picks the first matching branch and processes its items. This is
///   THE critical one: libc's `lib.rs` uses `cfg_if!` to gate the
///   per-OS module declarations (e.g. `mod unix;` on Unix), so a
///   walker that ignores `cfg_if!` only ever sees the handful of items
///   at the very top level and misses the entire module tree.
///
/// - **`s! { ... }`, `s_no_extra_traits! { ... }`, `extern_ty! { ... }`,
///   `prelude!()`** — these wrap struct/type/prelude declarations in
///   custom macros so libc can attach derives or trait impls
///   automatically. We don't extract struct definitions in PR 3
///   (that's PR 4 when typed-decl consumers land), so we ignore these
///   for now. When PR 4 arrives, recognizing `s!` will be important
///   because almost every libc struct is declared that way.
///
/// Any other macro invocation is a debug-only log and pass-through —
/// the item contributes nothing to the archive, and we can't
/// meaningfully recover it without crate-specific parsing.
fn handle_macro(
    m: &syn::ItemMacro,
    parent_dir: &Path,
    target: Target,
    type_ctx: TypeCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    // Attribute cfg gating can also wrap the macro invocation itself,
    // so honor it before spending effort parsing the body.
    if !cfg_permits(&m.attrs, target) {
        return Ok(());
    }
    let Some(name) = m.mac.path.segments.last().map(|s| s.ident.to_string()) else {
        return Ok(());
    };
    match name.as_str() {
        "cfg_if" => handle_cfg_if(&m.mac.tokens, parent_dir, target, type_ctx, archive, visited)?,
        // Struct/type declaration macros — defer to PR 4.
        "s" | "s_no_extra_traits" | "s_paren" | "extern_ty" | "prelude" => {}
        // Other macro invocations are opaque to us.
        other => log::debug!("skipping unknown top-level macro: {other}"),
    }
    Ok(())
}

/// Parse the body of a `cfg_if!` invocation and walk the first
/// branch whose `#[cfg(...)]` predicate permits the current target,
/// matching how `cfg_if` itself behaves at compile time. If no
/// branch matches, walk the `else` fallback (if present).
fn handle_cfg_if(
    tokens: &TokenStream,
    parent_dir: &Path,
    target: Target,
    type_ctx: TypeCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    // The body is a sequence of `if <cfg-attr> { items } [else if ...] [else { items }]`.
    // We parse it via a custom `Parse` impl that captures each branch's
    // attribute and item list.
    let body = syn::parse2::<CfgIfBody>(tokens.clone())
        .context("parsing cfg_if! body")?;

    for branch in &body.branches {
        if cfg_permits(&branch.attrs, target) {
            for item in &branch.items {
                handle_item(item, parent_dir, target, type_ctx, archive, visited)?;
            }
            return Ok(());
        }
    }
    // No branch matched — take the else fallback if present.
    for item in &body.fallback {
        handle_item(item, parent_dir, target, type_ctx, archive, visited)?;
    }
    Ok(())
}

/// AST for a `cfg_if!` body. Custom `Parse` impl because the
/// invocation grammar (`if <attr> { ... } else if ... { ... } else { ... }`)
/// isn't a standard Rust syntactic category — it's a DSL that only
/// the `cfg_if` macro understands.
struct CfgIfBody {
    branches: Vec<CfgIfBranch>,
    /// Items from the trailing `else { ... }` block, if present.
    /// `cfg_if!` runs these only when every preceding branch's cfg
    /// predicate evaluated false.
    fallback: Vec<Item>,
}

struct CfgIfBranch {
    attrs: Vec<Attribute>,
    items: Vec<Item>,
}

impl Parse for CfgIfBody {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut branches = Vec::new();
        let mut fallback = Vec::new();

        // First branch: mandatory `if <attr> { ... }`.
        input.parse::<Token![if]>()?;
        let attrs = input.call(Attribute::parse_outer)?;
        let content;
        braced!(content in input);
        let items = parse_items_until_end(&content)?;
        branches.push(CfgIfBranch { attrs, items });

        // Optional chain: `else if <attr> { ... }` or final `else { ... }`.
        while input.peek(Token![else]) {
            input.parse::<Token![else]>()?;
            if input.peek(Token![if]) {
                input.parse::<Token![if]>()?;
                let attrs = input.call(Attribute::parse_outer)?;
                let content;
                braced!(content in input);
                let items = parse_items_until_end(&content)?;
                branches.push(CfgIfBranch { attrs, items });
            } else {
                let content;
                braced!(content in input);
                fallback = parse_items_until_end(&content)?;
                break;
            }
        }
        Ok(CfgIfBody { branches, fallback })
    }
}

/// Parse all remaining tokens in a stream as a sequence of `syn::Item`
/// values. Used for the bodies of cfg_if branches. Similar to the
/// top-level `syn::File::parse` but without the file-level attribute
/// handling.
fn parse_items_until_end(input: ParseStream) -> syn::Result<Vec<Item>> {
    let mut items = Vec::new();
    while !input.is_empty() {
        items.push(input.parse::<Item>()?);
    }
    Ok(items)
}

/// Descend into a `mod` declaration. Three shapes to handle:
/// 1. `mod foo { ... }` — inline module, walk `content` in place.
/// 2. `mod foo;` with a sibling `foo.rs` — walk that file.
/// 3. `mod foo;` with a sibling `foo/mod.rs` — walk that file.
///
/// Gated by [`cfg_permits`] so cfg-mismatched branches don't get
/// followed; otherwise we'd pull Linux-only modules into a macOS
/// archive and produce type collisions.
fn handle_mod(
    m: &ItemMod,
    parent_dir: &Path,
    target: Target,
    type_ctx: TypeCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    if !cfg_permits(&m.attrs, target) {
        return Ok(());
    }

    if let Some((_, items)) = &m.content {
        // Inline module — recurse in place. The parent_dir stays the
        // same because inline modules don't change filesystem layout.
        for item in items {
            handle_item(item, parent_dir, target, type_ctx, archive, visited)?;
        }
        return Ok(());
    }

    // File-backed module. A `#[path = "..."]` attribute takes
    // precedence over the default `foo.rs` / `foo/mod.rs` lookup and
    // is how libc handles its OS-specific file tree.
    let name = m.ident.to_string();
    let candidates: Vec<PathBuf> = if let Some(explicit) = path_attr(&m.attrs) {
        vec![parent_dir.join(explicit)]
    } else {
        vec![
            parent_dir.join(format!("{name}.rs")),
            parent_dir.join(&name).join("mod.rs"),
        ]
    };

    for c in candidates {
        if c.exists() {
            walk_file(&c, target, type_ctx, archive, visited)?;
            return Ok(());
        }
    }
    // If none of the candidates exist, we assume the mod is gated by
    // a cfg we matched incorrectly or that libc has a stub we're
    // safe to skip. Log at debug so noise stays out of normal runs.
    log::debug!("no file backing mod {name} under {}", parent_dir.display());
    Ok(())
}

/// Extract functions from an `extern "C" { ... }` block. Non-C ABIs
/// (e.g. `extern "system"`, `extern "stdcall"`) are recorded as
/// `CallingConvention::Default` because libc only uses cdecl. The
/// PR 3b windows-sys walker has its own ABI-aware logic.
fn handle_foreign_mod(fm: &ItemForeignMod, type_ctx: TypeCtx, archive: &mut TypeArchive) {
    let cc = abi_to_calling_convention(&fm.abi);
    for item in &fm.items {
        let ForeignItem::Fn(f) = item else { continue };
        if let Some(func) = foreign_fn_to_model(f, cc, type_ctx) {
            archive.functions.insert(func.name.clone(), func);
        }
    }
}

/// Convert a single `ForeignItemFn` into our [`FunctionType`] model.
/// Variadic functions (`fn foo(fmt: *const c_char, ...);`) are
/// flagged via `is_variadic`; the fixed args come through normally.
fn foreign_fn_to_model(
    f: &ForeignItemFn,
    cc: CallingConvention,
    type_ctx: TypeCtx,
) -> Option<FunctionType> {
    let name = f.sig.ident.to_string();
    let is_variadic = f.sig.variadic.is_some();

    let mut args = Vec::new();
    for input in &f.sig.inputs {
        let syn::FnArg::Typed(pat) = input else {
            // `self` parameters shouldn't appear in extern blocks; if
            // they do, we can't represent them in our model, so skip
            // the whole function.
            return None;
        };
        let arg_name = match pat.pat.as_ref() {
            syn::Pat::Ident(i) => i.ident.to_string(),
            // Anonymous (pattern) parameters — libc occasionally
            // declares these. Name them positionally so the archive
            // consumer can still reference the slot.
            _ => format!("arg_{}", args.len()),
        };
        args.push(ArgType {
            name: arg_name,
            ty: rust_type_to_ref(&pat.ty, type_ctx),
        });
    }

    let return_type = match &f.sig.output {
        ReturnType::Default => TypeRef::Primitive(crate::model::Primitive::Void),
        ReturnType::Type(_, ty) => rust_type_to_ref(ty, type_ctx),
    };

    Some(FunctionType {
        name,
        args,
        return_type,
        calling_convention: cc,
        is_variadic,
    })
}

/// Record a `pub type Name = Inner;` as a [`TypeDef::Alias`]. Gated
/// type aliases (`#[cfg(target_os = "...")]`) are filtered so we
/// don't record a Linux-specific `time_t` alias when generating a
/// macOS archive.
fn handle_type_alias(t: &ItemType, target: Target, type_ctx: TypeCtx, archive: &mut TypeArchive) {
    if !cfg_permits(&t.attrs, target) {
        return;
    }
    let name = t.ident.to_string();
    let ty = rust_type_to_ref(&t.ty, type_ctx);
    archive.types.insert(
        name.clone(),
        TypeDef {
            name,
            kind: TypeDefKind::Alias(ty),
        },
    );
}

/// Map a `syn::Abi` to our [`CallingConvention`]. libc blocks are
/// `extern "C"`, which is cdecl on x86 and the default ABI on other
/// architectures. The walker treats unknown ABIs as `Default` so the
/// caller doesn't have to special-case each possible variant.
fn abi_to_calling_convention(abi: &Abi) -> CallingConvention {
    let Some(LitStr { .. }) = &abi.name else {
        return CallingConvention::Default;
    };
    match abi.name.as_ref().unwrap().value().as_str() {
        "C" | "cdecl" => CallingConvention::Cdecl,
        "system" => CallingConvention::Stdcall,
        "stdcall" => CallingConvention::Stdcall,
        "fastcall" => CallingConvention::Fastcall,
        "thiscall" => CallingConvention::Thiscall,
        _ => CallingConvention::Default,
    }
}

// ---------------------------------------------------------------------------
// cfg filtering
// ---------------------------------------------------------------------------

/// Return true if an item's attribute list permits the current
/// target. We implement a small subset of the `cfg` predicate
/// grammar — enough for libc's actual usage:
///
/// - `#[cfg(target_os = "linux")]` → match
/// - `#[cfg(target_os = "macos")]` → match
/// - `#[cfg(not(target_os = "..."))]` → inverted match
/// - `#[cfg(all(...))]` → all subpredicates must permit
/// - `#[cfg(any(...))]` → at least one subpredicate must permit
/// - Unrecognized predicates (e.g. `target_arch`, `feature`, `doc`)
///   → pass through (assume permits). This is the pragmatic choice:
///   libc gates per-arch struct layouts we don't extract yet, and
///   pessimistically filtering them out would prune legitimate
///   functions that happen to live near an arch-gated type.
///
/// When multiple `#[cfg(...)]` attributes decorate the same item,
/// ALL must permit (matches rustc's semantics).
fn cfg_permits(attrs: &[Attribute], target: Target) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("cfg") {
            continue;
        }
        let Ok(meta) = attr.parse_args::<Meta>() else {
            // Failed to parse the cfg predicate — don't block the
            // item on parser errors; assume permissive.
            continue;
        };
        if !cfg_meta_permits(&meta, target) {
            return false;
        }
    }
    true
}

fn cfg_meta_permits(meta: &Meta, target: Target) -> bool {
    match meta {
        Meta::NameValue(nv) => name_value_permits(nv, target),
        Meta::List(list) => {
            let ident = list.path.get_ident().map(|i| i.to_string());
            match ident.as_deref() {
                Some("not") => {
                    // #[cfg(not(...))] — invert the inner predicate.
                    let inner = list.parse_args::<Meta>();
                    match inner {
                        Ok(m) => !cfg_meta_permits(&m, target),
                        Err(_) => true,
                    }
                }
                Some("all") => {
                    let Ok(items) = list.parse_args_with(
                        syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                    ) else {
                        return true;
                    };
                    items.iter().all(|m| cfg_meta_permits(m, target))
                }
                Some("any") => {
                    let Ok(items) = list.parse_args_with(
                        syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                    ) else {
                        return true;
                    };
                    items.iter().any(|m| cfg_meta_permits(m, target))
                }
                // Unknown list-shaped predicate → pass through.
                _ => true,
            }
        }
        // Bare path predicates like `#[cfg(unix)]` — libc uses `unix`
        // as an umbrella that covers both Linux and macOS, so it
        // always permits for our current target set.
        Meta::Path(path) => {
            let Some(ident) = path.get_ident() else { return true };
            match ident.to_string().as_str() {
                "unix" => true,
                "windows" => false,
                _ => true,
            }
        }
    }
}

fn name_value_permits(nv: &MetaNameValue, target: Target) -> bool {
    let Some(key) = nv.path.get_ident().map(|i| i.to_string()) else {
        return true;
    };
    let Some(value) = lit_str_value(&nv.value) else {
        // Non-string rhs — pass through rather than risk a false
        // negative. Our recognized cfg keys all take string literals.
        return true;
    };
    match key.as_str() {
        "target_os" => value == target.cfg_value(),
        // Arch-gated items are pass-through for now. libc uses
        // target_arch heavily for struct field layouts, which we
        // don't extract in PR 3; in PR 4 when struct extraction
        // lands, we'll need an --arch flag on the CLI and a matching
        // filter here.
        "target_arch" | "target_pointer_width" | "target_env" | "feature" | "doc" => true,
        _ => true,
    }
}

/// Extract the string value from a literal expression (`"linux"`).
/// Returns `None` for anything non-literal or non-string.
fn lit_str_value(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Lit(lit) = expr else { return None };
    let Lit::Str(s) = &lit.lit else { return None };
    Some(s.value())
}

/// Extract a `#[path = "..."]` attribute value. Used when a `mod foo;`
/// declaration wants to point at a non-standard file location, which
/// libc does heavily under its OS subdirectories.
fn path_attr(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        if let Meta::NameValue(nv) = &attr.meta {
            if let Some(v) = lit_str_value(&nv.value) {
                return Some(v);
            }
        }
    }
    None
}
