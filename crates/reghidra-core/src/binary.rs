use crate::arch::Architecture;
use crate::error::CoreError;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// High-level information about a parsed binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: PathBuf,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub entry_point: u64,
    pub is_64bit: bool,
    pub is_big_endian: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::Pe => write!(f, "PE"),
            Self::MachO => write!(f, "Mach-O"),
        }
    }
}

/// A section from the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

/// A symbol extracted from the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub is_import: bool,
    pub is_export: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Object,
    Section,
    File,
    Unknown,
}

/// A fully loaded binary ready for analysis.
pub struct LoadedBinary {
    pub info: BinaryInfo,
    pub data: Vec<u8>,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Symbol>,
    pub exports: Vec<Symbol>,
    pub strings: Vec<DetectedString>,
    /// ELF: PLT stub address → import name. PE: IAT entry address → import name.
    pub import_addr_map: HashMap<u64, String>,
}

/// A string found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedString {
    pub address: u64,
    pub value: String,
    pub section: Option<String>,
    /// IDA-style auto-generated label (e.g. `s_EnterPassword`).
    pub auto_name: String,
}

/// Sanitize a string value into a valid identifier with the given prefix.
///
/// Walks chars: alphanumeric chars are kept (capitalized after word boundaries);
/// spaces/punctuation mark the next char as a word boundary.
/// Truncates content portion to `max_len` chars.
/// Falls back to `<prefix><hex_addr>` if empty.
pub fn sanitize_to_name(value: &str, prefix: &str, max_len: usize, addr: u64) -> String {
    let mut result = String::with_capacity(prefix.len() + max_len);
    result.push_str(prefix);

    let mut at_boundary = true;
    let mut content_len = 0;

    for ch in value.chars() {
        if content_len >= max_len {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            if at_boundary {
                for uc in ch.to_uppercase() {
                    result.push(uc);
                }
            } else {
                result.push(ch);
            }
            at_boundary = false;
            content_len += 1;
        } else {
            // Space, punctuation, etc. — mark next as word boundary
            at_boundary = true;
        }
    }

    // Fall back to hex address if content is empty
    if content_len == 0 {
        result.clear();
        result.push_str(&format!("{prefix}{addr:x}"));
    }

    result
}

/// Deduplicate names in a list by appending `_2`, `_3`, etc. for collisions.
fn dedup_auto_names(strings: &mut [DetectedString]) {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    // First pass: count occurrences
    for s in strings.iter() {
        *counts.entry(s.auto_name.clone()).or_insert(0) += 1;
    }
    // Second pass: assign suffixes for duplicates
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for s in strings.iter_mut() {
        let count = counts.get(&s.auto_name).copied().unwrap_or(0);
        if count > 1 {
            let idx = seen.entry(s.auto_name.clone()).or_insert(0);
            *idx += 1;
            if *idx > 1 {
                s.auto_name = format!("{}_{}", s.auto_name, idx);
            }
        }
    }
}

impl LoadedBinary {
    /// Load and parse a binary from the given path.
    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let data = std::fs::read(path)?;
        // Clone data for parsing since goblin borrows it, but we need to move it into the result
        let object = Object::parse(&data).map_err(|e| CoreError::Parse(e.to_string()))?;

        // We need to re-parse inside each arm to avoid borrow issues.
        // The cost is negligible since parsing is fast.
        drop(object);

        let object = Object::parse(&data).map_err(|e| CoreError::Parse(e.to_string()))?;
        match &object {
            Object::Elf(elf) => Self::from_elf(path, &data, elf),
            Object::PE(pe) => Self::from_pe(path, &data, pe),
            Object::Mach(mach) => Self::from_mach(path, &data, mach),
            _ => Err(CoreError::UnsupportedFormat),
        }
    }

    /// Read bytes from the binary at a given virtual address.
    pub fn read_bytes_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        for section in &self.sections {
            let sec_end = section.virtual_address + section.virtual_size;
            if va >= section.virtual_address && va < sec_end {
                let offset_in_section = (va - section.virtual_address) as usize;
                let file_offset = section.file_offset as usize + offset_in_section;
                let available = self.data.len().saturating_sub(file_offset);
                let read_len = len.min(available).min((sec_end - va) as usize);
                if read_len > 0 {
                    return Some(&self.data[file_offset..file_offset + read_len]);
                }
            }
        }
        None
    }

    /// Find the section containing a virtual address.
    pub fn section_at_va(&self, va: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            va >= s.virtual_address && va < s.virtual_address + s.virtual_size
        })
    }

    /// Get all executable sections.
    pub fn executable_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_executable).collect()
    }

    fn from_elf(
        path: &Path,
        data: &[u8],
        elf: &goblin::elf::Elf,
    ) -> Result<Self, CoreError> {
        let architecture = match (elf.header.e_machine, elf.is_64) {
            (goblin::elf::header::EM_386, _) => Architecture::X86_32,
            (goblin::elf::header::EM_X86_64, _) => Architecture::X86_64,
            (goblin::elf::header::EM_ARM, _) => Architecture::Arm32,
            (goblin::elf::header::EM_AARCH64, _) => Architecture::Arm64,
            (goblin::elf::header::EM_MIPS, false) => Architecture::Mips32,
            (goblin::elf::header::EM_MIPS, true) => Architecture::Mips64,
            (goblin::elf::header::EM_PPC, _) => Architecture::PowerPc32,
            (goblin::elf::header::EM_PPC64, _) => Architecture::PowerPc64,
            (goblin::elf::header::EM_RISCV, false) => Architecture::Riscv32,
            (goblin::elf::header::EM_RISCV, true) => Architecture::Riscv64,
            (m, _) => return Err(CoreError::UnsupportedArch(format!("ELF machine {m}"))),
        };

        let is_big_endian = match elf.header.endianness() {
            Ok(goblin::container::Endian::Big) => true,
            _ => false,
        };

        let info = BinaryInfo {
            path: path.to_path_buf(),
            format: BinaryFormat::Elf,
            architecture,
            entry_point: elf.entry,
            is_64bit: elf.is_64,
            is_big_endian,
        };

        let sections: Vec<Section> = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                if name.is_empty() || sh.sh_size == 0 {
                    return None;
                }
                Some(Section {
                    name,
                    virtual_address: sh.sh_addr,
                    virtual_size: sh.sh_size,
                    file_offset: sh.sh_offset,
                    file_size: sh.sh_size,
                    is_executable: sh.is_executable(),
                    is_writable: sh.is_writable(),
                    is_readable: sh.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0,
                })
            })
            .collect();

        let mut symbols = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();

        for sym in elf.syms.iter() {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let kind = match sym.st_type() {
                goblin::elf::sym::STT_FUNC => SymbolKind::Function,
                goblin::elf::sym::STT_OBJECT => SymbolKind::Object,
                goblin::elf::sym::STT_SECTION => SymbolKind::Section,
                goblin::elf::sym::STT_FILE => SymbolKind::File,
                _ => SymbolKind::Unknown,
            };
            let s = Symbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
                is_import: sym.is_import(),
                is_export: !sym.is_import() && sym.st_bind() == goblin::elf::sym::STB_GLOBAL,
            };
            if s.is_import {
                imports.push(s.clone());
            }
            if s.is_export {
                exports.push(s.clone());
            }
            symbols.push(s);
        }

        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            if symbols.iter().any(|s| s.name == name && s.address == sym.st_value) {
                continue;
            }
            let kind = match sym.st_type() {
                goblin::elf::sym::STT_FUNC => SymbolKind::Function,
                goblin::elf::sym::STT_OBJECT => SymbolKind::Object,
                _ => SymbolKind::Unknown,
            };
            let s = Symbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                kind,
                is_import: sym.is_import(),
                is_export: !sym.is_import() && sym.st_bind() == goblin::elf::sym::STB_GLOBAL,
            };
            if s.is_import {
                imports.push(s.clone());
            }
            if s.is_export {
                exports.push(s.clone());
            }
            symbols.push(s);
        }

        let strings = Self::detect_strings(data, &sections);

        // Build PLT stub → import name map
        let import_addr_map = Self::build_elf_plt_map(elf, &sections);

        Ok(Self {
            info,
            data: data.to_vec(),
            sections,
            symbols,
            imports,
            exports,
            strings,
            import_addr_map,
        })
    }

    /// Build a mapping from PLT stub addresses to import names.
    /// Uses .rela.plt relocations to determine the GOT slots, then maps
    /// each PLT entry (by index) to the corresponding symbol name.
    fn build_elf_plt_map(
        elf: &goblin::elf::Elf,
        sections: &[Section],
    ) -> HashMap<u64, String> {
        let mut map = HashMap::new();

        // Find .plt section
        let plt_section = sections.iter().find(|s| s.name == ".plt");
        let Some(plt) = plt_section else {
            return map;
        };

        // Determine PLT entry size (typically 16 bytes on x86_64, 16 on x86)
        let plt_entry_size = if elf.is_64 { 16u64 } else { 16u64 };

        // Each .rela.plt relocation corresponds to a PLT entry (in order).
        // PLT[0] is the resolver stub, actual entries start at PLT[1].
        for (i, reloc) in elf.pltrelocs.iter().enumerate() {
            let sym_idx = reloc.r_sym;
            let name = elf
                .dynsyms
                .get(sym_idx)
                .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            // Clean version suffixes like "puts@@GLIBC_2.2.5"
            let clean_name = name.split('@').next().unwrap_or(name).to_string();
            let plt_addr = plt.virtual_address + (i as u64 + 1) * plt_entry_size;
            map.insert(plt_addr, clean_name);
        }

        map
    }

    fn from_pe(
        path: &Path,
        data: &[u8],
        pe: &goblin::pe::PE,
    ) -> Result<Self, CoreError> {
        let is_64bit = pe.is_64;
        let architecture = if is_64bit {
            Architecture::X86_64
        } else {
            Architecture::X86_32
        };

        let image_base = pe.image_base as u64;

        let info = BinaryInfo {
            path: path.to_path_buf(),
            format: BinaryFormat::Pe,
            architecture,
            entry_point: image_base + pe.entry as u64,
            is_64bit,
            is_big_endian: false,
        };

        let sections: Vec<Section> = pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(
                    &s.name[..s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len())],
                )
                .to_string();
                let chars = s.characteristics;
                Section {
                    name,
                    virtual_address: image_base + u64::from(s.virtual_address),
                    virtual_size: u64::from(s.virtual_size),
                    file_offset: u64::from(s.pointer_to_raw_data),
                    file_size: u64::from(s.size_of_raw_data),
                    is_executable: chars & 0x2000_0000 != 0,
                    is_writable: chars & 0x8000_0000 != 0,
                    is_readable: chars & 0x4000_0000 != 0,
                }
            })
            .collect();

        let mut symbols = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();

        for import in &pe.imports {
            let s = Symbol {
                name: import.name.to_string(),
                address: image_base + import.rva as u64,
                size: 0,
                kind: SymbolKind::Function,
                is_import: true,
                is_export: false,
            };
            imports.push(s.clone());
            symbols.push(s);
        }

        if let Some(ref export_data) = pe.export_data {
            let name_table = &export_data.export_name_pointer_table;
            let ordinal_table = &export_data.export_ordinal_table;
            let addr_table = &export_data.export_address_table;
            for (i, &name_rva) in name_table.iter().enumerate() {
                // Resolve the name from the binary data
                let name_offset = name_rva as usize;
                if name_offset >= data.len() {
                    continue;
                }
                let name_bytes = &data[name_offset..];
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

                let ordinal = ordinal_table.get(i).copied().unwrap_or(0) as usize;
                let rva = match addr_table.get(ordinal) {
                    Some(goblin::pe::export::ExportAddressTableEntry::ExportRVA(rva)) => *rva as u64,
                    Some(goblin::pe::export::ExportAddressTableEntry::ForwarderRVA(rva)) => *rva as u64,
                    None => 0,
                };

                let s = Symbol {
                    name,
                    address: image_base + rva,
                    size: 0,
                    kind: SymbolKind::Function,
                    is_import: false,
                    is_export: true,
                };
                exports.push(s.clone());
                symbols.push(s);
            }
        }

        let strings = Self::detect_strings(data, &sections);

        // Build IAT slot address → import name map for PE.
        // Code references imports via `call [IAT_addr]` where IAT_addr is the
        // virtual address of the IAT slot (not the ILT/hint-name RVA).
        let mut import_addr_map = HashMap::new();
        let ptr_size: u64 = if is_64bit { 8 } else { 4 };
        if let Some(ref import_data) = pe.import_data {
            for entry in &import_data.import_data {
                let iat_base = entry.import_directory_entry.import_address_table_rva as u64;
                // Match IAT entries with import names from the lookup table
                if let Some(ref ilt) = entry.import_lookup_table {
                    for (i, ilt_entry) in ilt.iter().enumerate() {
                        use goblin::pe::import::SyntheticImportLookupTableEntry::*;
                        let name = match ilt_entry {
                            HintNameTableRVA((_rva, hint_entry)) => {
                                hint_entry.name.to_string()
                            }
                            OrdinalNumber(_) => continue,
                        };
                        let iat_slot_addr = image_base + iat_base + (i as u64 * ptr_size);
                        import_addr_map.insert(iat_slot_addr, name);
                    }
                }
            }
        }

        Ok(Self {
            info,
            data: data.to_vec(),
            sections,
            symbols,
            imports,
            exports,
            strings,
            import_addr_map,
        })
    }

    fn from_mach(
        path: &Path,
        data: &[u8],
        mach: &goblin::mach::Mach,
    ) -> Result<Self, CoreError> {
        match mach {
            goblin::mach::Mach::Binary(macho) => Self::from_single_macho(path, data, macho),
            goblin::mach::Mach::Fat(fat) => {
                for arch in fat.iter_arches().flatten() {
                    let slice = &data[arch.offset as usize..(arch.offset + arch.size) as usize];
                    if let Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) =
                        Object::parse(slice)
                    {
                        return Self::from_single_macho(path, slice, &macho);
                    }
                }
                Err(CoreError::Parse("no usable architecture in fat binary".into()))
            }
        }
    }

    fn from_single_macho(
        path: &Path,
        data: &[u8],
        macho: &goblin::mach::MachO,
    ) -> Result<Self, CoreError> {
        let cputype = macho.header.cputype();
        let architecture = match cputype {
            goblin::mach::cputype::CPU_TYPE_X86 => Architecture::X86_32,
            goblin::mach::cputype::CPU_TYPE_X86_64 => Architecture::X86_64,
            goblin::mach::cputype::CPU_TYPE_ARM => Architecture::Arm32,
            goblin::mach::cputype::CPU_TYPE_ARM64 => Architecture::Arm64,
            goblin::mach::cputype::CPU_TYPE_POWERPC => Architecture::PowerPc32,
            goblin::mach::cputype::CPU_TYPE_POWERPC64 => Architecture::PowerPc64,
            ct => return Err(CoreError::UnsupportedArch(format!("Mach-O cputype {ct}"))),
        };

        let is_64bit = macho.is_64;
        let is_big_endian = macho.little_endian == false;

        let info = BinaryInfo {
            path: path.to_path_buf(),
            format: BinaryFormat::MachO,
            architecture,
            entry_point: macho.entry,
            is_64bit,
            is_big_endian,
        };

        let mut sections = Vec::new();
        for segment in &macho.segments {
            let seg_sections = match segment.sections() {
                Ok(s) => s,
                Err(_) => continue,
            };
            for (sec, _data) in &seg_sections {
                let name = format!(
                    "{},{}",
                    String::from_utf8_lossy(&sec.segname).trim_end_matches('\0'),
                    String::from_utf8_lossy(&sec.sectname).trim_end_matches('\0')
                );
                let initprot = segment.initprot;
                sections.push(Section {
                    name,
                    virtual_address: sec.addr,
                    virtual_size: sec.size,
                    file_offset: u64::from(sec.offset),
                    file_size: sec.size,
                    is_executable: initprot & 0x4 != 0,
                    is_writable: initprot & 0x2 != 0,
                    is_readable: initprot & 0x1 != 0,
                });
            }
        }

        let mut symbols = Vec::new();
        let mut exports = Vec::new();

        if let Some(ref syms) = macho.symbols {
            for sym in syms.iter() {
                if let Ok((name, nlist)) = sym {
                    let name = name.strip_prefix('_').unwrap_or(name).to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let s = Symbol {
                        name,
                        address: nlist.n_value,
                        size: 0,
                        kind: if nlist.is_stab() {
                            SymbolKind::Unknown
                        } else {
                            SymbolKind::Function
                        },
                        is_import: false,
                        is_export: nlist.n_type & 0x01 != 0,
                    };
                    if s.is_export {
                        exports.push(s.clone());
                    }
                    symbols.push(s);
                }
            }
        }

        let imports: Vec<Symbol> = macho
            .imports()
            .unwrap_or_default()
            .into_iter()
            .map(|imp| {
                Symbol {
                    name: imp.name.strip_prefix('_').unwrap_or(&imp.name).to_string(),
                    address: imp.offset as u64,
                    size: 0,
                    kind: SymbolKind::Function,
                    is_import: true,
                    is_export: false,
                }
            })
            .collect();

        let strings = Self::detect_strings(data, &sections);

        Ok(Self {
            info,
            data: data.to_vec(),
            sections,
            symbols,
            imports,
            exports,
            strings,
            import_addr_map: HashMap::new(),
        })
    }

    fn detect_strings(data: &[u8], sections: &[Section]) -> Vec<DetectedString> {
        let min_len = 4;
        let mut result = Vec::new();

        for section in sections {
            let start = section.file_offset as usize;
            let end = start + section.file_size as usize;
            if end > data.len() {
                continue;
            }
            let slice = &data[start..end];

            let mut current_start = None;
            for (i, &byte) in slice.iter().enumerate() {
                if byte >= 0x20 && byte < 0x7F {
                    if current_start.is_none() {
                        current_start = Some(i);
                    }
                } else if byte == 0 {
                    if let Some(s) = current_start {
                        let len = i - s;
                        if len >= min_len {
                            let value = String::from_utf8_lossy(&slice[s..i]).to_string();
                            let address = section.virtual_address + s as u64;
                            let auto_name = sanitize_to_name(&value, "s_", 40, address);
                            result.push(DetectedString {
                                address,
                                value,
                                section: Some(section.name.clone()),
                                auto_name,
                            });
                        }
                    }
                    current_start = None;
                } else {
                    current_start = None;
                }
            }
        }

        dedup_auto_names(&mut result);
        result
    }
}
