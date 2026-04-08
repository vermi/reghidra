use crate::arch::Architecture;
use crate::binary::BinaryFormat;
use include_dir::{include_dir, Dir};
use std::path::PathBuf;

use super::flirt::FlirtDatabase;

/// Embedded signature files from https://github.com/rizinorg/sigdb
static SIGNATURES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../signatures");

/// A bundled signature entry: name and raw .sig bytes.
struct BundledSig {
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
                        let entry = BundledSig {
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
        let source_path = PathBuf::from(format!("bundled:{}", entry.name));
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
                let src = PathBuf::from(format!("bundled:{}", e.name));
                FlirtDatabase::parse(e.data, src)
                    .unwrap_or_else(|err| panic!("sig {} failed: {err}", e.name));
            }
        }
    }
}
