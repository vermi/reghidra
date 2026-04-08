//! Symbol demangling utilities.
//!
//! Canonical names stay mangled (they're used as identifiers for xrefs,
//! renames, and session persistence). Callers who want a human-readable
//! form for display call [`display_name`] (full signature, good for
//! decompile headers and anywhere a user expects to see parameter types)
//! or [`display_name_short`] (symbol-only, good for sidebars, function
//! lists, and disasm block headers).
//!
//! Recognized forms:
//! - MSVC C++ mangled names (`?foo@@YAHH@Z`) via `msvc-demangler`.
//! - MSVC `__fastcall` decoration `@name@bytes` → `name`.
//! - MSVC `__stdcall` decoration `_name@bytes` → `name`.
//!
//! All other inputs are returned unchanged as a borrow. Bare leading
//! underscores (cdecl `_foo`) are intentionally left alone to avoid
//! stripping legitimate prefixes on ELF symbols like `_start`.

use std::borrow::Cow;

use msvc_demangler::DemangleFlags;

const BASE_FLAGS: DemangleFlags = DemangleFlags::from_bits_truncate(
    DemangleFlags::NO_ACCESS_SPECIFIERS.bits()
        | DemangleFlags::NO_MEMBER_TYPE.bits()
        | DemangleFlags::NO_MS_KEYWORDS.bits()
        | DemangleFlags::SPACE_AFTER_COMMA.bits(),
);

/// Full-signature display form. For MSVC C++ mangled names this includes
/// the parameter types, for `@name@N` / `_name@N` decorations it strips
/// the decoration, and for everything else it's an identity pass-through.
pub fn display_name(name: &str) -> Cow<'_, str> {
    if name.starts_with('?') {
        let flags = BASE_FLAGS | DemangleFlags::NO_FUNCTION_RETURNS;
        if let Ok(demangled) = msvc_demangler::demangle(name, flags) {
            if !demangled.is_empty() && demangled != name {
                return Cow::Owned(demangled);
            }
        }
    }
    if let Some(stripped) = strip_msvc_decoration(name) {
        return Cow::Owned(stripped.to_string());
    }
    Cow::Borrowed(name)
}

/// Symbol-only display form. For MSVC C++ mangled names this returns just
/// the (possibly qualified) function name, no parameter list. Intended
/// for spaces like the sidebar function list and disassembly block
/// headers where only an identifier is wanted and signatures would bloat
/// the layout.
pub fn display_name_short(name: &str) -> Cow<'_, str> {
    if name.starts_with('?') {
        let flags = BASE_FLAGS | DemangleFlags::NAME_ONLY;
        if let Ok(demangled) = msvc_demangler::demangle(name, flags) {
            if !demangled.is_empty() && demangled != name {
                return Cow::Owned(demangled);
            }
        }
    }
    if let Some(stripped) = strip_msvc_decoration(name) {
        return Cow::Owned(stripped.to_string());
    }
    Cow::Borrowed(name)
}

/// Strip MSVC `__fastcall` (`@name@N`) or `__stdcall` (`_name@N`) decoration
/// from a symbol, returning `Some(undecorated)` when a decoration was
/// matched and `None` otherwise. The `@N` suffix is the caller-cleanup
/// stack byte count that MSVC emits — purely a calling-convention marker,
/// never part of the source name, so it's safe to drop for display.
fn strip_msvc_decoration(name: &str) -> Option<&str> {
    // `@foo@4` → `foo` (fastcall). The leading `@` is unambiguous; bare
    // `@` prefixes don't occur in non-decorated symbols.
    if let Some(rest) = name.strip_prefix('@') {
        if let Some((base, tail)) = rest.rsplit_once('@') {
            if !base.is_empty() && is_decimal(tail) {
                return Some(base);
            }
        }
    }
    // `_foo@4` → `foo` (stdcall). We require the `@N` suffix so we don't
    // strip legitimate cdecl `_foo` symbols that happen to have no suffix.
    if let Some(rest) = name.strip_prefix('_') {
        if let Some((base, tail)) = rest.rsplit_once('@') {
            if !base.is_empty() && is_decimal(tail) {
                return Some(base);
            }
        }
    }
    None
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_through_unmangled() {
        assert_eq!(display_name("main"), "main");
        assert_eq!(display_name("_start"), "_start");
        assert_eq!(display_name("GetLastError"), "GetLastError");
    }

    #[test]
    fn demangles_msvc_cxx() {
        let out = display_name("?foo@@YAHH@Z");
        assert_ne!(out, "?foo@@YAHH@Z", "expected demangled output");
        assert!(out.contains("foo"), "output should contain 'foo': {}", out);
    }

    #[test]
    fn demangles_msvc_method() {
        let out = display_name("?bar@Baz@@QAEXXZ");
        assert_ne!(out, "?bar@Baz@@QAEXXZ");
        assert!(out.contains("Baz"));
        assert!(out.contains("bar"));
    }

    #[test]
    fn invalid_mangled_returns_original() {
        // Looks like MSVC (starts with ?) but isn't valid — should pass through.
        let input = "?not a real mangled name";
        assert_eq!(display_name(input), input);
    }

    #[test]
    fn strips_fastcall_decoration() {
        assert_eq!(display_name("@__security_check_cookie@4"), "__security_check_cookie");
        assert_eq!(display_name_short("@foo@8"), "foo");
    }

    #[test]
    fn strips_stdcall_decoration() {
        assert_eq!(display_name("_GetStartupInfoA@4"), "GetStartupInfoA");
        assert_eq!(display_name_short("_SendMessageW@16"), "SendMessageW");
    }

    #[test]
    fn does_not_strip_bare_leading_underscore() {
        // cdecl `_foo` without `@N` suffix must pass through — might be a
        // legit symbol like `_start` or `_init`.
        assert_eq!(display_name("_start"), "_start");
        assert_eq!(display_name("_exit"), "_exit");
    }

    #[test]
    fn short_name_is_name_only() {
        // Full form contains the parameter list, short form shouldn't.
        let full = display_name("?foo@@YAHHH@Z");
        let short = display_name_short("?foo@@YAHHH@Z");
        assert!(short.contains("foo"));
        // Short form should not carry a parameter list, full form typically will.
        assert!(!short.contains('('), "short name should not include params: {}", short);
        assert_ne!(full, short, "full and short should differ for functions with params");
    }

    #[test]
    fn short_name_on_method() {
        let short = display_name_short("?bar@Baz@@QAEXXZ");
        assert!(short.contains("bar"));
        assert!(!short.contains('('));
    }
}
