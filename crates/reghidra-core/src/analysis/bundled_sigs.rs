use crate::arch::Architecture;
use crate::binary::BinaryFormat;
use include_dir::{include_dir, Dir};
use std::path::PathBuf;

use super::flirt::FlirtDatabase;

/// Embedded signature files from https://github.com/rizinorg/sigdb
static SIGNATURES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../signatures");

/// A bundled signature entry: subdir + name + raw .sig bytes. The
/// subdir is part of the identity because the same stem can appear
/// under multiple arch directories (e.g. `VisualStudio2017.sig`
/// shipped for `pe/x86/32`, `pe/arm/32`, `pe/arm/64`) and they must
/// be addressable independently for the per-source toggle UI.
struct BundledSig {
    subdir: &'static str,
    name: &'static str,
    data: &'static [u8],
}

/// Returns the signature subdirectory path for a given binary format and architecture.
///
/// The sigdb layout is: `{elf,pe}/{arch}/{bitness}/`
fn sig_subdirs(format: BinaryFormat, arch: Architecture) -> Vec<&'static str> {
    match (format, arch) {
        (BinaryFormat::Elf, Architecture::X86_32) => vec!["elf/x86/32"],
        (BinaryFormat::Elf, Architecture::X86_64) => vec!["elf/x86/64"],
        (BinaryFormat::Elf, Architecture::Arm32) => vec!["elf/arm/32"],
        (BinaryFormat::Elf, Architecture::Arm64) => vec!["elf/arm/64"],
        (BinaryFormat::Elf, Architecture::Mips32) => vec!["elf/mips/32"],
        (BinaryFormat::Elf, Architecture::Mips64) => vec!["elf/mips/64"],
        (BinaryFormat::Pe, Architecture::X86_32) => vec!["pe/x86/32"],
        (BinaryFormat::Pe, Architecture::X86_64) => vec!["pe/x86/64"],
        (BinaryFormat::Pe, Architecture::Arm32) => vec!["pe/arm/32"],
        (BinaryFormat::Pe, Architecture::Arm64) => vec!["pe/arm/64"],
        (BinaryFormat::Pe, Architecture::Mips32) => vec!["pe/mips/32"],
        // Mach-O shares the same ABI as the arch, no dedicated sigdb dir
        // Fall back to elf sigs for matching arch (better than nothing)
        (BinaryFormat::MachO, Architecture::X86_32) => vec!["elf/x86/32"],
        (BinaryFormat::MachO, Architecture::X86_64) => vec!["elf/x86/64"],
        (BinaryFormat::MachO, Architecture::Arm64) => vec!["elf/arm/64"],
        _ => vec![],
    }
}

/// Returns true if a sig filename (stem) is one of the rizinorg/sigdb-sourced
/// databases. IDA-sourced sigs take precedence over these: at apply time the
/// first database to match a function wins, so non-rizinorg sigs are loaded
/// first.
fn is_rizinorg_sig(stem: &str) -> bool {
    stem.starts_with("VisualStudio")
        || stem.starts_with("ubuntu-")
        || stem.starts_with("fedora-")
        || stem.starts_with("android-")
        || matches!(stem, "masm32" | "mingw32-zlib" | "winsdk")
}

/// Returns true if a sig filename (stem) is for a legacy toolchain
/// that the user is unlikely to encounter in modern targets. Legacy
/// sigs still ship in the embedded tree and are visible in the
/// Loaded Data Sources panel, but they are NOT auto-loaded at
/// `Project::open` time: the user must opt in via the panel's
/// lazy-load path. This cuts open-time memory and parse cost
/// dramatically on PE x86 — the Borland/Watcom/Delphi/MFC2-era sigs
/// account for the bulk of the old `collect_bundled_sigs` working
/// set even though they almost never produce matches on binaries
/// built in the last 15 years.
///
/// Categories currently flagged:
///
/// - **Borland / Delphi / C++ Builder** — `b*`, `bds*`, `bh32*`,
///   `c4vcl`, `d3-d5vcl`, `bcb*`, `bdsboost`, `bdsext`
/// - **Watcom** — `wa32rt*`, `og70`
/// - **Digital Mars / Symantec** — `dm*`, `sm32rw32`, `omvc60`,
///   `osc60`, `otp60`
/// - **Old MFC (MSVC 2.x, 1990s)** — `msmfc2`, `msmfc2d`, `msmfc2u`
/// - **VisualAge C++ / Intel C / misc 1990s linkers** — `vac35wc`,
///   `iclapp`, `iclmat`, `ulink`, `mccor`, `vireobc`, `vireoms`
///
/// Flipping a sig between modern and legacy is a one-line edit to
/// this function. If a category later becomes relevant (e.g. we
/// start caring about Delphi targets), moving it out of the legacy
/// set re-enables auto-load without any file moves or session
/// migration.
pub fn is_legacy_sig(stem: &str) -> bool {
    // Borland / Delphi / C++ Builder. `bcb*` catches `bcb5rt` etc.
    // `bds*` catches `bds`, `bds2006`, `bds40`, `bds8*`, `bdsboost`,
    // `bdsext`. `b32vcl`, `b5132mfc`, `b532cgw` all start with `b`
    // followed by a digit — we gate on that to avoid false-positives
    // against sigs like `bridge*` or anything else modern that may
    // start with `b`.
    if stem.starts_with("bds")
        || stem.starts_with("bcb")
        || stem.starts_with("bh32")
        || stem.starts_with("c4vcl")
        || matches!(stem, "d3vcl" | "d4vcl" | "d5vcl")
    {
        return true;
    }
    if let Some(rest) = stem.strip_prefix('b') {
        if rest
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            return true;
        }
    }
    // Watcom
    if stem.starts_with("wa32rt") || stem == "og70" {
        return true;
    }
    // Digital Mars / Symantec
    if stem.starts_with("dm")
        || matches!(stem, "sm32rw32" | "omvc60" | "osc60" | "otp60")
    {
        return true;
    }
    // Old MFC (MSVC 2.x)
    if matches!(stem, "msmfc2" | "msmfc2d" | "msmfc2u") {
        return true;
    }
    // VisualAge / Intel C / misc 1990s linkers
    if matches!(
        stem,
        "vac35wc" | "iclapp" | "iclmat" | "iclapp64" | "iclmat64" | "ulink"
            | "ulink64" | "mccor" | "vireobc" | "vireoms"
    ) {
        return true;
    }
    false
}

/// Metadata for an embedded `.sig` file: its tree-relative subdir
/// (`pe/x86/32`, `elf/arm/64`, ...), filename stem (`vc32_14`,
/// `ubuntu-libc6`), and the friendly library name + function count
/// pulled from the .sig header. Library name is `None` only if the
/// header parse failed — which would also kill the full parse, so
/// such sigs would be unusable anyway.
///
/// The header parse is cheap (no trie walk), so we eat the cost at
/// enumeration time to make the Loaded Data Sources tree show
/// `Visual Studio 2010 Professional` instead of `vc32_14`.
#[derive(Debug, Clone)]
pub struct AvailableSig {
    pub subdir: String,
    pub stem: String,
    pub library_name: Option<String>,
    pub n_functions: Option<u32>,
    /// True when this sig's stem matches [`is_legacy_sig`]. Legacy
    /// sigs are enumerated and shown in the Loaded Data Sources
    /// panel but are NOT auto-loaded at project open time. Computed
    /// once at walk time so the panel doesn't have to re-check on
    /// every render.
    pub is_legacy: bool,
}

/// Walk the entire embedded `signatures/` tree and return one
/// [`AvailableSig`] per `.sig` file. Two-level recursion (format then
/// arch then bitness); the rizinorg/sigdb layout is fixed at three
/// levels deep so an explicit walker is fine. Sorted by `(subdir,
/// stem)` for stable display order.
pub fn available_sigs() -> Vec<AvailableSig> {
    let mut out = Vec::new();
    walk_sigs(&SIGNATURES_DIR, &mut out);
    out.sort_by(|a, b| a.subdir.cmp(&b.subdir).then(a.stem.cmp(&b.stem)));
    out
}

fn walk_sigs(dir: &Dir<'static>, out: &mut Vec<AvailableSig>) {
    for f in dir.files() {
        let path = f.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sig") {
            continue;
        }
        let Some(parent) = path.parent().and_then(|p| p.to_str()) else {
            continue;
        };
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // Header parse failures get logged but still emit a row, so
        // the tree doesn't silently drop a sig over a parser bug; the
        // panel will fall back to the file stem.
        let (library_name, n_functions) = match super::flirt::parse_header(f.contents()) {
            Ok((hdr, _)) => (Some(hdr.name), Some(hdr.n_functions)),
            Err(e) => {
                log::debug!("sig header parse failed for {}: {e}", path.display());
                (None, None)
            }
        };
        out.push(AvailableSig {
            subdir: parent.to_string(),
            stem: stem.to_string(),
            library_name,
            n_functions,
            is_legacy: is_legacy_sig(stem),
        });
    }
    for sub in dir.dirs() {
        walk_sigs(sub, out);
    }
}

/// Look up an embedded `.sig` file's raw bytes by `(subdir, stem)`.
/// Used by `Project` to lazy-load a sig the user toggled on from the
/// Loaded Data Sources panel without re-walking the whole tree.
pub fn embedded_sig_bytes(subdir: &str, stem: &str) -> Option<&'static [u8]> {
    let path = format!("{subdir}/{stem}.sig");
    SIGNATURES_DIR.get_file(&path).map(|f| f.contents())
}

/// Subdir paths that the format/arch heuristic would auto-load. Used by
/// `Project` to seed the enabled flags for embedded sigs at open time:
/// sigs whose subdir is in this list start checked, everything else
/// starts unchecked. Mirrors [`sig_subdirs`].
pub fn auto_load_subdirs(format: BinaryFormat, arch: Architecture) -> Vec<&'static str> {
    sig_subdirs(format, arch)
}

/// Collect all bundled .sig file entries matching the given format and architecture.
///
/// Order: IDA-sourced sigs first, rizinorg/sigdb sigs last. This gives IDA
/// signatures precedence when the same function matches both sources.
fn collect_bundled_sigs(format: BinaryFormat, arch: Architecture) -> Vec<BundledSig> {
    let mut ida = Vec::new();
    let mut rizinorg = Vec::new();

    for subdir_path in sig_subdirs(format, arch) {
        if let Some(subdir) = SIGNATURES_DIR.get_dir(subdir_path) {
            for file in subdir.files() {
                if let Some(ext) = file.path().extension() {
                    if ext == "sig" {
                        let name = file
                            .path()
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown");
                        // Legacy sigs (Borland/Watcom/Digital Mars/
                        // old MFC/etc.) are enumerated by
                        // `available_sigs` and reachable via the
                        // panel's lazy-load path, but they are not
                        // auto-loaded. Skipping them here cuts the
                        // open-time FLIRT working set substantially
                        // on PE x86 targets where ~half the shipped
                        // sigs are pre-2010 toolchains that almost
                        // never match modern binaries.
                        if is_legacy_sig(name) {
                            continue;
                        }
                        let entry = BundledSig {
                            subdir: subdir_path,
                            name,
                            data: file.contents(),
                        };
                        if is_rizinorg_sig(name) {
                            rizinorg.push(entry);
                        } else {
                            ida.push(entry);
                        }
                    }
                }
            }
        }
    }

    ida.extend(rizinorg);
    ida
}

/// Load and apply all bundled FLIRT signature databases that match the given
/// binary format and architecture.
///
/// Returns a vec of successfully parsed databases and a status summary string.
pub fn load_bundled_signatures(
    format: BinaryFormat,
    arch: Architecture,
) -> (Vec<FlirtDatabase>, String) {
    let entries = collect_bundled_sigs(format, arch);
    if entries.is_empty() {
        return (Vec::new(), String::new());
    }

    let total = entries.len();
    let mut databases = Vec::new();
    let mut loaded_names = Vec::new();

    for entry in &entries {
        // `bundled:<subdir>/<stem>` — subdir is essential because the
        // same stem can come from multiple arch dirs and the GUI keys
        // its loaded-vs-available join on the full (subdir, stem) pair.
        let source_path =
            PathBuf::from(format!("bundled:{}/{}", entry.subdir, entry.name));
        match FlirtDatabase::parse(entry.data, source_path) {
            Ok(db) => {
                loaded_names.push(entry.name);
                databases.push(db);
            }
            Err(e) => {
                log::warn!("Failed to parse bundled sig '{}': {}", entry.name, e);
            }
        }
    }

    let loaded = databases.len();
    let total_sigs: usize = databases.iter().map(|db| db.signature_count).sum();
    let status = format!(
        "{loaded}/{total} bundled sig databases loaded ({total_sigs} signatures)"
    );
    log::info!("{status}");

    (databases, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_subdirs() {
        let dirs = sig_subdirs(BinaryFormat::Elf, Architecture::X86_64);
        assert_eq!(dirs, vec!["elf/x86/64"]);

        let dirs = sig_subdirs(BinaryFormat::Pe, Architecture::X86_32);
        assert_eq!(dirs, vec!["pe/x86/32"]);

        // PowerPC has no sigs
        let dirs = sig_subdirs(BinaryFormat::Elf, Architecture::PowerPc32);
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_collect_bundled_sigs_elf_x86_64() {
        let sigs = collect_bundled_sigs(BinaryFormat::Elf, Architecture::X86_64);
        // Should find ubuntu-libc6, ubuntu-openssl, etc.
        assert!(!sigs.is_empty(), "expected bundled sigs for elf/x86/64");
        // All should start with IDASGN magic
        for sig in &sigs {
            assert!(
                sig.data.len() >= 6 && &sig.data[..6] == b"IDASGN",
                "bundled sig '{}' has invalid magic",
                sig.name
            );
        }
    }

    #[test]
    fn test_load_bundled_signatures() {
        let (dbs, status) = load_bundled_signatures(BinaryFormat::Elf, Architecture::X86_64);
        assert!(!dbs.is_empty());
        assert!(!status.is_empty());
    }

    #[test]
    fn test_load_bundled_pe_signatures_parse() {
        // Every bundled PE sig (including merged IDA sigs) must parse.
        for (fmt, arch) in [
            (BinaryFormat::Pe, Architecture::X86_32),
            (BinaryFormat::Pe, Architecture::X86_64),
        ] {
            let entries = collect_bundled_sigs(fmt, arch);
            assert!(!entries.is_empty(), "no bundled sigs for {fmt:?}/{arch:?}");
            for e in &entries {
                let src = PathBuf::from(format!("bundled:{}/{}", e.subdir, e.name));
                FlirtDatabase::parse(e.data, src)
                    .unwrap_or_else(|err| panic!("sig {} failed: {err}", e.name));
            }
        }
    }
}
