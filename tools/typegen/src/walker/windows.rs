//! Walker for the `windows-sys` crate.
//!
//! `windows-sys` is structurally different from `libc`: instead of
//! declaring foreign functions in `extern "system" { ... }` blocks,
//! it uses a macro invocation of the form
//!
//! ```text
//! windows_targets::link!("kernel32.dll" "system" fn CloseHandle(hobject : HANDLE) -> BOOL);
//! ```
//!
//! for every Win32 function. The macro is provided by the
//! `windows-targets` crate (0.52) and expands into a platform-specific
//! `#[link]` + `extern "system"` stanza at compile time. From `syn`'s
//! point of view it's just an `ItemMacro` whose token stream has to
//! be parsed by the walker itself — no amount of `Item::ForeignMod`
//! matching will find these functions.
//!
//! Other differences worth knowing about:
//!
//! - The crate root uses `include!("Windows/mod.rs")` instead of a
//!   top-level `mod Windows;`, so the walker's module-descent logic
//!   has to look for `syn::ItemMacro` path `include` and inline the
//!   referenced file.
//! - Module declarations under `Windows/Win32/` are gated by
//!   `#[cfg(feature = "Win32_...")]`. The walker IGNORES feature
//!   gates and walks every module unconditionally, because Windows
//!   namespaces its features and ignoring the gates gives us full
//!   coverage of whichever features Cargo happens to have enabled
//!   (Cargo's feature unification makes every transitively-enabled
//!   feature visible in the source tree regardless).
//! - Types like `HANDLE`, `BOOL`, `PCSTR` are declared inside the
//!   same crate via `pub type` aliases, so the walker's existing
//!   `ItemType` handling picks them up without any special casing.
//! - Struct/union declarations use plain `#[repr(C)] pub struct`,
//!   not a custom macro — so PR 4 (when struct extraction lands)
//!   can share code between the libc and windows walkers.

use crate::model::{
    ArgType, CallingConvention, FunctionType, TypeArchive, TypeDef, TypeDefKind, TypeRef,
};
use crate::walker::rust_ty::{rust_type_to_ref, TypeCtx};
use anyhow::{anyhow, Context, Result};
use cargo_metadata::MetadataCommand;
use proc_macro2::TokenStream;
use quote::quote;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use syn::parse::{Parse, ParseStream};
use syn::{
    ForeignItemFn, Item, ItemMacro, ItemMod, ItemType, LitStr, Macro, Meta, ReturnType,
};

/// Which Windows target this walk is producing an archive for.
/// Drives both the [`TypeCtx`] selection (pointer width, `c_long`
/// width) and the default [`CallingConvention`] tag stamped onto
/// each extracted function. Functions whose explicit ABI string
/// doesn't match the platform default are flagged individually —
/// the ABI recorded in the `link!` macro always wins over the target
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsTarget {
    /// 64-bit Windows on x86-64 (Win64 calling convention, LLP64).
    X86_64,
    /// 32-bit Windows on x86 (stdcall for Win32 APIs, ILP32).
    X86,
    /// 64-bit Windows on ARM64 (AAPCS64, LLP64).
    Arm64,
}

impl WindowsTarget {
    fn type_ctx(self) -> TypeCtx {
        match self {
            Self::X86_64 | Self::Arm64 => TypeCtx::LLP64,
            Self::X86 => TypeCtx::ILP32,
        }
    }

    /// Default calling convention for functions declared in `link!`
    /// with ABI `"system"`. On x86-32, `extern "system"` means
    /// stdcall; on x86-64 and ARM64 there's only one ABI so we record
    /// `Win64` / `Aapcs` respectively for clarity. Overridden per
    /// function when the macro specifies a different ABI string.
    fn default_cc(self) -> CallingConvention {
        match self {
            Self::X86_64 => CallingConvention::Win64,
            Self::X86 => CallingConvention::Stdcall,
            Self::Arm64 => CallingConvention::Aapcs,
        }
    }
}

/// Resolve the `windows-sys` crate's source directory using
/// `cargo metadata`. Returns the directory containing `src/lib.rs`
/// for the version pinned in the tool's `Cargo.toml`.
pub fn find_source_dir() -> Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest)
        .exec()
        .with_context(|| format!("cargo metadata failed for {}", manifest.display()))?;

    let pkg = metadata
        .packages
        .iter()
        .find(|p| p.name.as_str() == "windows-sys")
        .ok_or_else(|| anyhow!("windows-sys not listed as a dependency of reghidra-typegen"))?;

    let src = pkg
        .manifest_path
        .parent()
        .ok_or_else(|| {
            anyhow!("windows-sys manifest path has no parent: {}", pkg.manifest_path)
        })?
        .join("src");
    Ok(src.into_std_path_buf())
}

/// Walk the windows-sys source tree producing an archive for the
/// given target. Returns the populated [`TypeArchive`].
pub fn walk(src_dir: &Path, target: WindowsTarget, archive_name: &str) -> Result<TypeArchive> {
    let mut archive = TypeArchive::new(archive_name);
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let ctx = WinCtx {
        target,
        type_ctx: target.type_ctx(),
    };

    let lib_rs = src_dir.join("lib.rs");
    walk_file(&lib_rs, &ctx, &mut archive, &mut visited)
        .with_context(|| format!("walking {}", lib_rs.display()))?;

    Ok(archive)
}

/// Walker context bundle. Threaded through every recursive step so
/// the handlers don't have to take four extra positional params.
struct WinCtx {
    target: WindowsTarget,
    type_ctx: TypeCtx,
}

fn walk_file(
    path: &Path,
    ctx: &WinCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    if !path.exists() {
        log::debug!("skipping missing file: {}", path.display());
        return Ok(());
    }

    let source = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file = syn::parse_file(&source)
        .with_context(|| format!("parsing {}", path.display()))?;

    let parent_dir = path.parent().unwrap_or_else(|| Path::new(""));

    // The crate root `lib.rs` uses `include!("Windows/mod.rs")` at
    // the top level (a `Stmt`, not an `Item`), which lands in
    // `file.items` as an `Item::Macro` with macro path `include`.
    // The walker descends into its referenced file before processing
    // the rest of the items — effectively inlining the included file
    // in place.
    for item in &file.items {
        handle_item(item, parent_dir, ctx, archive, visited)?;
    }
    Ok(())
}

fn handle_item(
    item: &Item,
    parent_dir: &Path,
    ctx: &WinCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    match item {
        Item::Mod(m) => handle_mod(m, parent_dir, ctx, archive, visited)?,
        Item::Type(t) => handle_type_alias(t, ctx, archive),
        Item::Macro(m) => handle_macro(m, parent_dir, ctx, archive, visited)?,
        // Plain `extern "system" { ... }` blocks do appear in some
        // `core` helpers even though the main Win32 bindings use the
        // `link!` macro. Harvest these too so we don't miss the
        // handful of functions that happen to be declared directly.
        Item::ForeignMod(fm) => handle_foreign_mod(fm, ctx, archive),
        // Constants, enums, unions, structs: ignored in PR 3b for the
        // same reason as in the libc walker — PR 4 will pick these up
        // when the typed-decl consumers need struct/union layouts.
        _ => {}
    }
    Ok(())
}

/// Descend into a `mod foo;` or `mod foo { ... }` declaration. The
/// windows-sys crate uses both forms: `lib.rs` declares `pub mod core;`
/// inline while Win32 submodules are file-backed via `pub mod Foo;`.
/// Feature gates (`#[cfg(feature = "...")]`) are IGNORED per the
/// rationale at the top of the file — every module gets walked so
/// the archive doesn't arbitrarily depend on which features cargo
/// happened to enable when the tool was built.
fn handle_mod(
    m: &ItemMod,
    parent_dir: &Path,
    ctx: &WinCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    if let Some((_, items)) = &m.content {
        for item in items {
            handle_item(item, parent_dir, ctx, archive, visited)?;
        }
        return Ok(());
    }

    let name = m.ident.to_string();
    let candidates: Vec<PathBuf> = vec![
        parent_dir.join(format!("{name}.rs")),
        parent_dir.join(&name).join("mod.rs"),
    ];

    for c in candidates {
        if c.exists() {
            walk_file(&c, ctx, archive, visited)?;
            return Ok(());
        }
    }
    log::debug!("no file backing mod {name} under {}", parent_dir.display());
    Ok(())
}

/// Record a `pub type Name = Inner;` as a [`TypeDef::Alias`]. Unlike
/// libc, windows-sys has no target-os-gated type aliases — every
/// alias applies uniformly — so there's no cfg filter here.
fn handle_type_alias(t: &ItemType, ctx: &WinCtx, archive: &mut TypeArchive) {
    let name = t.ident.to_string();
    let ty = rust_type_to_ref(&t.ty, ctx.type_ctx);
    archive.types.insert(
        name.clone(),
        TypeDef {
            name,
            kind: TypeDefKind::Alias(ty),
        },
    );
}

/// Harvest plain `extern "system" { ... }` blocks. Rarely used in
/// windows-sys proper but does appear in internal helpers, and we
/// might as well grab them since the parsing is almost free via the
/// libc walker's pattern.
fn handle_foreign_mod(
    fm: &syn::ItemForeignMod,
    ctx: &WinCtx,
    archive: &mut TypeArchive,
) {
    let cc = match fm.abi.name.as_ref().map(|s| s.value()) {
        Some(ref s) if s == "system" => ctx.target.default_cc(),
        Some(ref s) if s == "stdcall" => CallingConvention::Stdcall,
        Some(ref s) if s == "fastcall" => CallingConvention::Fastcall,
        Some(ref s) if s == "C" || s == "cdecl" => CallingConvention::Cdecl,
        _ => CallingConvention::Default,
    };
    for item in &fm.items {
        let syn::ForeignItem::Fn(f) = item else { continue };
        if let Some(func) = foreign_fn_to_model(f, cc, ctx.type_ctx) {
            archive.functions.insert(func.name.clone(), func);
        }
    }
}

/// Handle a top-level macro invocation. Windows-sys uses several
/// distinct macros, most of which we care about:
///
/// - **`include!("...")`** — inlines another source file. Used by
///   `lib.rs` to include `Windows/mod.rs`. The walker follows the
///   reference to the target file and processes its items as if
///   they'd appeared in the current file, so module descent works
///   through the include.
///
/// - **`windows_targets::link!("dll" "abi" fn name(args) -> ret)`** —
///   the canonical Win32 function declaration. Parsed by a custom
///   [`WindowsLink`] `syn::Parse` impl that strips the two string
///   literals and re-parses the remainder as a `ForeignItemFn`.
///   This is the bulk of the archive.
///
/// - Other macros (`windows_targets::link!` variations, `vtables!`,
///   etc.) are logged at debug level and skipped.
fn handle_macro(
    m: &ItemMacro,
    parent_dir: &Path,
    ctx: &WinCtx,
    archive: &mut TypeArchive,
    visited: &mut HashSet<PathBuf>,
) -> Result<()> {
    // Skip macro invocations gated by a cfg attribute that we can't
    // evaluate. Windows-sys doesn't put target_os cfgs on its item
    // macros (they're already in a platform-specific crate), but
    // being defensive here lets the walker survive future changes
    // without silently producing bad data.
    if has_inapplicable_cfg(&m.attrs, ctx) {
        return Ok(());
    }

    let Some(last_segment) = m.mac.path.segments.last() else {
        return Ok(());
    };
    let name = last_segment.ident.to_string();

    match name.as_str() {
        // `include!("path.rs")` — inline the referenced file. The
        // referenced path is relative to the crate manifest dir in
        // practice because libraries that call include! from lib.rs
        // use paths relative to `CARGO_MANIFEST_DIR`, which for a
        // fetched crate in the registry resolves to its src/
        // directory. For a walker, that means we resolve the include
        // target relative to the current file's parent directory
        // (`parent_dir`) — which happens to be `src/` for lib.rs
        // invocations, matching the crate's runtime behavior.
        "include" => {
            if let Some(rel) = include_target_path(&m.mac) {
                let path = parent_dir.join(rel);
                walk_file(&path, ctx, archive, visited)?;
            } else {
                log::debug!("include! with unparseable argument");
            }
        }
        // The main Win32 function declaration macro.
        "link" => {
            if let Some(func) = parse_windows_link(&m.mac.tokens, ctx) {
                archive.functions.insert(func.name.clone(), func);
            } else {
                log::debug!("link! with unparseable body");
            }
        }
        // Other macro invocations we don't recognize yet. Log at
        // debug so they're easy to grep for when adding support.
        other => log::debug!("skipping unknown windows-sys macro: {other}"),
    }
    Ok(())
}

/// Return true if any of the attrs contains a `#[cfg(...)]` predicate
/// that we know doesn't apply. Conservative: unrecognized predicates
/// are treated as applicable so the walker errs on the side of
/// inclusion.
fn has_inapplicable_cfg(attrs: &[syn::Attribute], _ctx: &WinCtx) -> bool {
    for attr in attrs {
        if !attr.path().is_ident("cfg") {
            continue;
        }
        let Ok(meta) = attr.parse_args::<Meta>() else {
            continue;
        };
        // Only reject cfgs that are explicitly non-Windows. We don't
        // try to evaluate feature predicates — ignoring them is the
        // whole point of the "walk everything" rationale above.
        if let Meta::NameValue(nv) = &meta {
            if nv.path.is_ident("target_os") {
                if let syn::Expr::Lit(lit) = &nv.value {
                    if let syn::Lit::Str(s) = &lit.lit {
                        let os = s.value();
                        if os != "windows" {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Extract the string argument of an `include!(...)` macro call.
/// Returns `None` if the argument isn't a single string literal.
fn include_target_path(mac: &Macro) -> Option<PathBuf> {
    let lit: LitStr = syn::parse2(mac.tokens.clone()).ok()?;
    Some(PathBuf::from(lit.value()))
}

// ---------------------------------------------------------------------------
// windows_targets::link! macro parser
// ---------------------------------------------------------------------------

/// Parse a `windows_targets::link!` macro body into a
/// [`FunctionType`]. Returns `None` if the body doesn't match the
/// expected grammar or contains a Rust type the mapper doesn't
/// understand.
///
/// Expected grammar:
///
/// ```text
/// "<dllname>" "<abi>" fn <ident>(<arg_name> : <type>, ...) [-> <ret_type>]
/// ```
///
/// `<abi>` is one of `"system"`, `"stdcall"`, `"fastcall"`, `"C"`.
/// If `-> <ret_type>` is omitted the function returns void.
///
/// The trailing semicolon that `ForeignItemFn::parse` would normally
/// require is synthesized here by appending a `;` token to the
/// remaining stream before re-parsing.
fn parse_windows_link(tokens: &TokenStream, ctx: &WinCtx) -> Option<FunctionType> {
    let parsed: WindowsLink = syn::parse2(tokens.clone()).ok()?;
    let cc = match parsed.abi.as_str() {
        "system" => ctx.target.default_cc(),
        "stdcall" => CallingConvention::Stdcall,
        "fastcall" => CallingConvention::Fastcall,
        "C" | "cdecl" => CallingConvention::Cdecl,
        _ => CallingConvention::Default,
    };
    foreign_fn_to_model(&parsed.func, cc, ctx.type_ctx)
}

/// Custom `syn::Parse` target matching the `windows_targets::link!`
/// body grammar. Parses the two ABI string literals, then synthesizes
/// a trailing semicolon on the remaining token stream and re-parses
/// it as a `ForeignItemFn`.
struct WindowsLink {
    /// DLL name (e.g. `"kernel32.dll"`). Recorded but unused — the
    /// walker doesn't distinguish per-library at archive time
    /// because the runtime lookup is by function name only.
    #[allow(dead_code)]
    dll: String,
    /// ABI string (e.g. `"system"`).
    abi: String,
    /// The parsed function declaration, treated as if it had been
    /// written as `extern "system" { pub fn name(...) -> ret; }`.
    func: ForeignItemFn,
}

impl Parse for WindowsLink {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let dll_lit: LitStr = input.parse()?;
        let abi_lit: LitStr = input.parse()?;
        // Remaining tokens are the function signature without a
        // trailing semicolon. `ForeignItemFn::parse` needs the
        // semicolon, so we synthesize it via quote! — this is
        // cheaper than handwriting a TokenTree append.
        let rest: TokenStream = input.parse()?;
        let with_semi = quote!(#rest ;);
        let func: ForeignItemFn = syn::parse2(with_semi).map_err(|e| {
            // Wrap the error with context so debug logs point at the
            // specific macro body that failed to parse, rather than
            // a bare "expected semicolon" from deep inside syn.
            syn::Error::new(e.span(), format!("parsing link! body: {e}"))
        })?;
        Ok(Self {
            dll: dll_lit.value(),
            abi: abi_lit.value(),
            func,
        })
    }
}

/// Convert a `ForeignItemFn` into our [`FunctionType`] model. Shared
/// between the plain `extern "system"` path and the `link!` macro
/// path so the type mapping logic lives in one place. This is a
/// near-duplicate of the libc walker's `foreign_fn_to_model`
/// (unavoidable while the two walkers remain siblings); if more than
/// one consumer needs it we can factor it out into `walker::common`.
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
            return None;
        };
        let arg_name = match pat.pat.as_ref() {
            syn::Pat::Ident(i) => i.ident.to_string(),
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
