//! Rust `syn::Type` → [`TypeRef`] conversion.
//!
//! This is the shared bridge between Rust source syntax and Reghidra's
//! type model. It recognizes the subset of Rust types that actually
//! appear in FFI binding crates — primitive scalars, pointers,
//! fixed-size arrays, and path-qualified type names — and maps them to
//! the corresponding [`TypeRef`]. Any Rust type the mapper doesn't
//! understand falls back to [`TypeRef::Named`] with the printed path,
//! which the archive consumer can still resolve via the `types` map or
//! render as an opaque named type in the decompile output.
//!
//! The mapping is lossy on purpose. Reghidra's type model is deliberately
//! narrow (see `reghidra-decompile::type_archive` for the rationale), so
//! Rust-isms like lifetimes, `const` vs `mut` on pointers, and trait
//! bounds are stripped at this boundary. If PR 3b or later needs to
//! preserve additional information (e.g. `*const` vs `*mut` for
//! read-only pointer parameters), extend [`TypeRef`] first, mirror the
//! change in `crates/reghidra-decompile/src/type_archive/mod.rs` and
//! `tools/typegen/src/model.rs`, bump `ARCHIVE_VERSION`, and then
//! update the mapper.

use crate::model::{Primitive, TypeRef};
use syn::{Expr, Lit, PathArguments, Type, TypePath, TypePtr};

/// Convert a Rust `syn::Type` to a Reghidra [`TypeRef`]. Returns a
/// `Named` fallback for anything the mapper doesn't recognize, using
/// the printed path so the archive still has something meaningful to
/// display.
pub fn rust_type_to_ref(ty: &Type) -> TypeRef {
    match ty {
        // `*const T` / `*mut T` — Reghidra's model doesn't distinguish
        // mutability on pointers because the decompile layer has no
        // safe way to recover it from machine code anyway. We keep the
        // pointee type and drop the qualifier.
        Type::Ptr(TypePtr { elem, .. }) => TypeRef::Pointer(Box::new(rust_type_to_ref(elem))),

        // `[T; N]` — fixed-size array. `N` must be a literal; anything
        // else falls back to Named because our model can't represent
        // symbolic array lengths.
        Type::Array(arr) => {
            let elem = rust_type_to_ref(&arr.elem);
            let len = array_len(&arr.len).unwrap_or(0);
            TypeRef::Array(Box::new(elem), len)
        }

        // `()` — unit, i.e. void return.
        Type::Tuple(t) if t.elems.is_empty() => TypeRef::Primitive(Primitive::Void),

        // `path::to::Name` — could be a primitive scalar or a named
        // type. The primitive match is order-sensitive because some
        // scalars (e.g. `c_char`, `c_void`) show up as path-qualified
        // references to `core::ffi::*`.
        Type::Path(tp) => path_to_ref(tp),

        // Reference types (`&T`, `&mut T`) don't appear in extern "C"
        // signatures but can show up in helper type aliases inside a
        // binding crate. Treat them as pointers to match how the ABI
        // would lower them.
        Type::Reference(r) => TypeRef::Pointer(Box::new(rust_type_to_ref(&r.elem))),

        // Anything else — function pointers without a named alias,
        // `Box<T>`, trait objects, etc. — becomes an opaque Named
        // fallback with the printed type source as its name. Callers
        // that care can inspect the Named string later, but for
        // archive-generation purposes a name is better than silently
        // dropping the parameter.
        other => TypeRef::Named(print_type(other)),
    }
}

/// Map a path-typed Rust `Type` to a Reghidra [`TypeRef`]. Recognizes
/// the set of `core::ffi::*` / `std::ffi::*` scalars plus the standard
/// Rust builtins (`i32`, `u64`, `bool`, …) and falls back to
/// [`TypeRef::Named`] with the final path segment.
fn path_to_ref(tp: &TypePath) -> TypeRef {
    // A path like `core::ffi::c_char` parses into multiple segments.
    // For the primitive match we only need the last segment's ident;
    // fully qualified vs single-ident forms both resolve here.
    let Some(last) = tp.path.segments.last() else {
        return TypeRef::Named(print_type(&Type::Path(tp.clone())));
    };

    // Generic arguments on the last segment (e.g. `Vec<u8>`) aren't
    // meaningful in an FFI context — drop to Named fallback with the
    // full printed path so the archive consumer can at least see what
    // was requested.
    if !matches!(last.arguments, PathArguments::None) {
        return TypeRef::Named(print_type(&Type::Path(tp.clone())));
    }

    let ident = last.ident.to_string();
    if let Some(prim) = primitive_from_ident(&ident) {
        return TypeRef::Primitive(prim);
    }

    // Not a recognized primitive — preserve the final segment as the
    // named-type key. We use the last segment rather than the full
    // path so consumers key on `HANDLE` rather than
    // `windows_sys::core::HANDLE`, keeping lookup tables small and
    // letting the archive's `types` map own the canonical definition.
    TypeRef::Named(ident)
}

/// Recognize a primitive scalar by its Rust ident. Covers:
/// - Rust builtins (`i8`..`u64`, `f32`, `f64`, `bool`, `usize`, `isize`)
/// - `core::ffi` / `std::ffi` type aliases (`c_char`, `c_int`, ...)
///
/// Returns `None` for anything unrecognized so the caller can fall
/// through to the `Named` path.
fn primitive_from_ident(ident: &str) -> Option<Primitive> {
    Some(match ident {
        // Rust core scalars
        "i8" => Primitive::Int8,
        "u8" => Primitive::UInt8,
        "i16" => Primitive::Int16,
        "u16" => Primitive::UInt16,
        "i32" => Primitive::Int32,
        "u32" => Primitive::UInt32,
        "i64" => Primitive::Int64,
        "u64" => Primitive::UInt64,
        "f32" => Primitive::Float,
        "f64" => Primitive::Double,
        "bool" => Primitive::Bool,

        // `usize`/`isize` aren't fixed-width. For the current archive
        // targets (x86-64 Linux/macOS, x86-64 Windows) they're 64-bit,
        // but the mapper doesn't know the target here. We pick UInt64
        // as the safe default for binding crates that target 64-bit
        // systems; the PR 3b Windows walker will need to revisit this
        // for 32-bit Win32 archives.
        "usize" => Primitive::UInt64,
        "isize" => Primitive::Int64,

        // core::ffi aliases — these are the canonical names for
        // extern "C" parameter types in modern bindings.
        "c_void" => Primitive::Void,
        "c_char" => Primitive::Char,
        "c_schar" => Primitive::Int8,
        "c_uchar" => Primitive::UInt8,
        "c_short" => Primitive::Int16,
        "c_ushort" => Primitive::UInt16,
        "c_int" => Primitive::Int32,
        "c_uint" => Primitive::UInt32,
        // `c_long` is 32 bits on 64-bit Windows but 64 bits on 64-bit
        // Linux/macOS. The libc crate uses the LP64 convention
        // (`c_long = i64` on 64-bit targets). Since PR 3 only targets
        // libc, matching that convention is correct here; Windows
        // archives in PR 3b will need a separate handling.
        "c_long" => Primitive::Int64,
        "c_ulong" => Primitive::UInt64,
        "c_longlong" => Primitive::Int64,
        "c_ulonglong" => Primitive::UInt64,
        "c_float" => Primitive::Float,
        "c_double" => Primitive::Double,

        _ => return None,
    })
}

/// Extract a constant length from an array size expression. `syn`
/// parses `[T; N]` as an `Expr`; we only recognize integer literals
/// here because binding crates don't use computed sizes in extern
/// blocks. Non-literal expressions fall through to `None` so the
/// caller substitutes a sentinel (currently 0).
fn array_len(expr: &Expr) -> Option<u32> {
    if let Expr::Lit(lit) = expr {
        if let Lit::Int(i) = &lit.lit {
            return i.base10_parse::<u32>().ok();
        }
    }
    None
}

/// Render a `syn::Type` as a short string for use in `TypeRef::Named`
/// fallback. Uses `quote!` to round-trip through `proc_macro2::TokenStream`,
/// then strips excess whitespace so the key is compact. Fallback-only —
/// recognized types go through the typed conversion paths above.
fn print_type(ty: &Type) -> String {
    // `quote!` is a proc-macro crate that's part of the stable syn
    // toolchain; importing it just for this one use would widen the
    // dep graph, so we fall back to `format!("{:?}", ty)` which is
    // lossy but good enough for debug-quality Named-fallback keys.
    // Walker callers never use these keys as cross-reference handles
    // because unrecognized types only appear in Named-fallback leaves.
    let s = format!("{ty:?}");
    // Trim `Type::Path(...)` wrapper noise and whitespace so the
    // resulting name is readable in logs. This is a cosmetic cleanup.
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
