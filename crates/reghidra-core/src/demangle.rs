//! Symbol demangling utilities.
//!
//! Canonical names stay mangled (they're used as identifiers for xrefs,
//! renames, and session persistence). Callers who want a human-readable
//! form for display call [`display_name`], which returns a demangled
//! string for recognized mangled forms and passes everything else through
//! unchanged.
//!
//! Currently supports MSVC C++ names (those starting with `?`). Itanium
//! (`_Z...`) and Rust (`_R...`) demangling can be added later if needed.

use std::borrow::Cow;

use msvc_demangler::DemangleFlags;

/// Return a display-friendly form of a symbol name.
///
/// - MSVC C++ mangled names (`?foo@@YA...`) are demangled into readable
///   C++ signatures, with Microsoft-specific noise (access specifiers,
///   `throw()` specs, etc.) stripped for a compact display form.
/// - All other inputs are returned unchanged as a borrow.
pub fn display_name(name: &str) -> Cow<'_, str> {
    if name.starts_with('?') {
        let flags = DemangleFlags::NO_ACCESS_SPECIFIERS
            | DemangleFlags::NO_FUNCTION_RETURNS
            | DemangleFlags::NO_MEMBER_TYPE
            | DemangleFlags::NO_MS_KEYWORDS
            | DemangleFlags::SPACE_AFTER_COMMA;
        if let Ok(demangled) = msvc_demangler::demangle(name, flags) {
            if !demangled.is_empty() && demangled != name {
                return Cow::Owned(demangled);
            }
        }
    }
    Cow::Borrowed(name)
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
}
