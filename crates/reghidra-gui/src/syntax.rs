//! C-style syntax tokenizer for the decompile view.
//!
//! Splits a rendered decompile line into a sequence of non-overlapping
//! `(byte_range, SyntaxKind)` spans. The GUI's `render_interactive_line`
//! walks these spans and paints each one in the theme's per-category
//! color, replacing the old per-line colorizer that made everything
//! inside a line look identical.
//!
//! This is intentionally a shallow lexer, not a C parser:
//! - It recognizes block comments (`/* ... */`) and single-line `//`
//!   comments, but doesn't care about nesting (C comments don't nest).
//! - Keywords and type names come from hand-curated lists that cover
//!   what reghidra's decompiler actually emits plus the common Windows
//!   API type aliases (DWORD, HANDLE, etc.). It's trivial to extend.
//! - Identifiers are everything alphanumeric-plus-underscore that
//!   isn't a keyword or type. The GUI's own clickable-token pass
//!   (`views/decompile::tokenize_line`) overrides specific identifier
//!   spans for function calls, variable names, labels, and g_dat_/
//!   label_/sub_ style synthetic identifiers, so the "Identifier"
//!   category here is just the default for names that nothing else
//!   claimed.
//! - Numbers cover decimal, hex (`0x...`), and octal forms. No suffix
//!   handling — the emit layer doesn't produce literal suffixes today.
//! - Operators are the ASCII-punct subset of C (`+ - * / = < > & | ^
//!   ! ~ ?`). Multi-char operators (`==`, `!=`, `<=`, `>=`, `&&`, `||`,
//!   `<<`, `>>`) are coalesced into one span.
//! - Punctuation covers structural characters (`; , ( ) { } [ ] :`)
//!   which are colored dimmer than real operators so the reader's eye
//!   isn't drawn to them.

/// A single syntax category. Each category maps to exactly one theme
/// color via `Theme::decomp_color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntaxKind {
    Comment,
    Keyword,
    Return,
    Goto,
    Type,
    Number,
    String,
    Operator,
    Punctuation,
    Identifier,
    Whitespace,
}

/// One typed span in a rendered line. `start`/`end` are byte offsets
/// into the original string.
#[derive(Debug, Clone, Copy)]
pub struct SyntaxToken {
    pub start: usize,
    pub end: usize,
    pub kind: SyntaxKind,
}

/// Tokenize a decompile line into syntax spans. Every byte of `text` is
/// covered by exactly one token — whitespace ends up in `Whitespace`
/// spans so the caller can just concatenate `text[s.start..s.end]` in
/// order and get back the original string.
pub fn tokenize_c_syntax(text: &str) -> Vec<SyntaxToken> {
    let bytes = text.as_bytes();
    let mut out: Vec<SyntaxToken> = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // -------- whitespace --------
        if b == b' ' || b == b'\t' {
            let start = i;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            out.push(SyntaxToken { start, end: i, kind: SyntaxKind::Whitespace });
            continue;
        }

        // -------- block comment `/* ... */` --------
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            // Consume the closing `*/` if present; otherwise the comment
            // runs to end-of-line (the line is rendered alone).
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                i = bytes.len();
            }
            out.push(SyntaxToken { start, end: i, kind: SyntaxKind::Comment });
            continue;
        }

        // -------- line comment `// ...` --------
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            let start = i;
            i = bytes.len();
            out.push(SyntaxToken { start, end: i, kind: SyntaxKind::Comment });
            continue;
        }

        // -------- string literal `"..."` --------
        // We don't try to validate escape sequences here — the span
        // runs from the opening quote to the first closing quote that
        // isn't preceded by a backslash. Good enough for decomp output
        // which never contains raw or multi-line strings.
        if b == b'"' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(SyntaxToken { start, end: i, kind: SyntaxKind::String });
            continue;
        }

        // -------- number literal --------
        // `0x...`, `0o...`, plain decimal. Allow a-f/A-F inside hex, and
        // bare digits elsewhere. The lexer doesn't try to distinguish
        // octal from decimal — both fall into the same `Number` span.
        if b.is_ascii_digit() {
            let start = i;
            if b == b'0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
                i += 2;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            out.push(SyntaxToken { start, end: i, kind: SyntaxKind::Number });
            continue;
        }

        // -------- identifier or keyword --------
        // C identifiers start with letter or `_`, then letters/digits/`_`.
        // After scanning we classify by table lookup.
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            let word = &text[start..i];
            let kind = classify_word(word);
            out.push(SyntaxToken { start, end: i, kind });
            continue;
        }

        // -------- multi-char operator coalescing --------
        // Try the two-character operators first (`==`, `!=`, `<=`, `>=`,
        // `&&`, `||`, `<<`, `>>`, `->`, `++`, `--`, `+=`, `-=`, `*=`,
        // `/=`, `%=`, `&=`, `|=`, `^=`). If none match, fall through to
        // the single-char path below.
        if i + 1 < bytes.len() && is_two_char_operator(bytes[i], bytes[i + 1]) {
            out.push(SyntaxToken { start: i, end: i + 2, kind: SyntaxKind::Operator });
            i += 2;
            continue;
        }

        // -------- single-char punctuation / operator --------
        let kind = match b {
            b';' | b',' | b'(' | b')' | b'{' | b'}' | b'[' | b']' | b':' => {
                SyntaxKind::Punctuation
            }
            b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'<' | b'>' | b'&'
            | b'|' | b'^' | b'!' | b'~' | b'?' | b'.' => SyntaxKind::Operator,
            _ => {
                // Anything we don't recognize — non-ASCII in a comment,
                // stray character, etc. — falls through as an identifier
                // span so we don't drop bytes.
                SyntaxKind::Identifier
            }
        };
        out.push(SyntaxToken { start: i, end: i + 1, kind });
        i += 1;
    }

    out
}

fn is_two_char_operator(a: u8, b: u8) -> bool {
    matches!(
        (a, b),
        (b'=', b'=')
            | (b'!', b'=')
            | (b'<', b'=')
            | (b'>', b'=')
            | (b'&', b'&')
            | (b'|', b'|')
            | (b'<', b'<')
            | (b'>', b'>')
            | (b'-', b'>')
            | (b'+', b'+')
            | (b'-', b'-')
            | (b'+', b'=')
            | (b'-', b'=')
            | (b'*', b'=')
            | (b'/', b'=')
            | (b'%', b'=')
            | (b'&', b'=')
            | (b'|', b'=')
            | (b'^', b'=')
    )
}

fn classify_word(word: &str) -> SyntaxKind {
    // `return`, `goto`, `break`, and `continue` get their own standout
    // categories so the theme can highlight them differently from
    // ordinary control-flow keywords.
    match word {
        "return" => return SyntaxKind::Return,
        "goto" | "break" | "continue" => return SyntaxKind::Goto,
        _ => {}
    }
    if CONTROL_KEYWORDS.binary_search(&word).is_ok() {
        return SyntaxKind::Keyword;
    }
    if C_TYPE_KEYWORDS.binary_search(&word).is_ok() {
        return SyntaxKind::Type;
    }
    SyntaxKind::Identifier
}

/// C control-flow and storage-class keywords the decompiler actually
/// emits. Kept in sorted order so we can use `binary_search`.
const CONTROL_KEYWORDS: &[&str] = &[
    "auto", "case", "const", "default", "do", "else", "enum", "extern",
    "for", "if", "inline", "register", "restrict", "sizeof", "static",
    "struct", "switch", "typedef", "union", "volatile", "while",
];

/// C primitive types plus common Windows API type aliases and stdint
/// synonyms. Kept in sorted order. Add entries as needed; missing
/// types just fall through as `Identifier` and take the default color.
const C_TYPE_KEYWORDS: &[&str] = &[
    "ATOM", "BOOL", "BOOLEAN", "BYTE", "CCHAR", "CHAR", "DWORD", "DWORD32",
    "DWORD64", "DWORDLONG", "DWORD_PTR", "FLOAT", "HANDLE", "HBITMAP",
    "HBRUSH", "HDC", "HFONT", "HGLOBAL", "HICON", "HINSTANCE", "HKEY",
    "HLOCAL", "HMENU", "HMODULE", "HPEN", "HRESULT", "HWND", "INT",
    "INT16", "INT32", "INT64", "INT8", "INT_PTR", "LARGE_INTEGER",
    "LONG", "LONG32", "LONG64", "LONGLONG", "LONG_PTR", "LPARAM",
    "LPBYTE", "LPCSTR", "LPCVOID", "LPCWSTR", "LPDWORD", "LPSTR",
    "LPVOID", "LPWORD", "LPWSTR", "LRESULT", "NTSTATUS", "PBOOL",
    "PBYTE", "PCHAR", "PCSTR", "PCWSTR", "PDWORD", "PHANDLE", "PINT",
    "PLONG", "PSTR", "PUCHAR", "PULONG", "PUSHORT", "PVOID", "PWCHAR",
    "PWORD", "PWSTR", "QWORD", "SHORT", "SIZE_T", "SSIZE_T", "UCHAR",
    "UINT", "UINT16", "UINT32", "UINT64", "UINT8", "UINT_PTR", "ULONG",
    "ULONG32", "ULONG64", "ULONGLONG", "ULONG_PTR", "USHORT", "VOID",
    "WCHAR", "WORD", "WPARAM", "_Bool", "bool", "char", "double",
    "float", "int", "int16_t", "int32_t", "int64_t", "int8_t", "long",
    "ptrdiff_t", "short", "signed", "size_t", "ssize_t", "uint16_t",
    "uint32_t", "uint64_t", "uint8_t", "uintptr_t", "unk128", "unk16",
    "unk32", "unk64", "unk8", "unsigned", "void", "wchar_t",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(text: &str) {
        // Invariant: concatenating every span reproduces the original.
        let toks = tokenize_c_syntax(text);
        let reassembled: String = toks
            .iter()
            .map(|t| &text[t.start..t.end])
            .collect();
        assert_eq!(reassembled, text, "tokenizer lost bytes for {:?}", text);
    }

    fn kinds(text: &str) -> Vec<SyntaxKind> {
        tokenize_c_syntax(text)
            .into_iter()
            .filter(|t| t.kind != SyntaxKind::Whitespace)
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn empty_line() {
        assert!(tokenize_c_syntax("").is_empty());
    }

    #[test]
    fn whitespace_only_roundtrips() {
        roundtrip("    ");
        let toks = tokenize_c_syntax("    ");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].kind, SyntaxKind::Whitespace);
    }

    #[test]
    fn block_comment() {
        roundtrip("    /* unimpl: xorps */");
        let k = kinds("    /* unimpl: xorps */");
        assert_eq!(k, vec![SyntaxKind::Comment]);
    }

    #[test]
    fn return_statement() {
        roundtrip("    return rax;");
        let k = kinds("    return rax;");
        assert_eq!(
            k,
            vec![SyntaxKind::Return, SyntaxKind::Identifier, SyntaxKind::Punctuation]
        );
    }

    #[test]
    fn if_and_binary_op() {
        roundtrip("    if (eax == 0) {");
        let k = kinds("    if (eax == 0) {");
        assert_eq!(
            k,
            vec![
                SyntaxKind::Keyword,       // if
                SyntaxKind::Punctuation,   // (
                SyntaxKind::Identifier,    // eax
                SyntaxKind::Operator,      // ==
                SyntaxKind::Number,        // 0
                SyntaxKind::Punctuation,   // )
                SyntaxKind::Punctuation,   // {
            ]
        );
    }

    #[test]
    fn hex_number_and_type() {
        roundtrip("    uint32_t local_8 = 0x40dfd8;");
        let k = kinds("    uint32_t local_8 = 0x40dfd8;");
        assert_eq!(
            k,
            vec![
                SyntaxKind::Type,          // uint32_t
                SyntaxKind::Identifier,    // local_8
                SyntaxKind::Operator,      // =
                SyntaxKind::Number,        // 0x40dfd8
                SyntaxKind::Punctuation,   // ;
            ]
        );
    }

    #[test]
    fn string_literal() {
        roundtrip("    puts(\"hello\");");
        let toks = tokenize_c_syntax("    puts(\"hello\");");
        let str_tok = toks.iter().find(|t| t.kind == SyntaxKind::String).unwrap();
        assert_eq!(&"    puts(\"hello\");"[str_tok.start..str_tok.end], "\"hello\"");
    }

    #[test]
    fn string_with_escaped_quote() {
        roundtrip("    f(\"a\\\"b\");");
        let toks = tokenize_c_syntax("    f(\"a\\\"b\");");
        let string_spans: Vec<_> = toks.iter().filter(|t| t.kind == SyntaxKind::String).collect();
        assert_eq!(string_spans.len(), 1);
        assert_eq!(
            &"    f(\"a\\\"b\");"[string_spans[0].start..string_spans[0].end],
            "\"a\\\"b\""
        );
    }

    #[test]
    fn goto_is_standout() {
        let k = kinds("    goto label_401000;");
        assert_eq!(k[0], SyntaxKind::Goto);
    }

    #[test]
    fn keywords_are_only_classified_as_whole_words() {
        // `ifx` shouldn't classify as a keyword — it's a whole-word match.
        let k = kinds("    ifx = 1;");
        assert_eq!(k[0], SyntaxKind::Identifier);
    }

    #[test]
    fn multi_char_operators_coalesced() {
        let toks: Vec<_> = tokenize_c_syntax("a <<= b")
            .into_iter()
            .filter(|t| t.kind != SyntaxKind::Whitespace)
            .collect();
        // We coalesce `<<` into one Operator, then `=` as another.
        assert_eq!(toks[1].kind, SyntaxKind::Operator);
        assert_eq!(&"a <<= b"[toks[1].start..toks[1].end], "<<");
    }

    #[test]
    fn deref_and_identifier() {
        let k = kinds("    *rbp = eax;");
        assert_eq!(
            k,
            vec![
                SyntaxKind::Operator,      // *
                SyntaxKind::Identifier,    // rbp
                SyntaxKind::Operator,      // =
                SyntaxKind::Identifier,    // eax
                SyntaxKind::Punctuation,   // ;
            ]
        );
    }
}
