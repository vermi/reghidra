use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Features {
    pub file: FileFeatures,
    pub by_function: HashMap<u64, FunctionFeatures>,
}

#[derive(Debug, Default, Clone)]
pub struct FileFeatures {
    pub format: BinaryFormat,
    pub imports: Vec<Import>,
    pub strings: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub pe: Option<PeFeatures>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    #[default] Unknown,
    Elf, Pe, MachO,
}

#[derive(Debug, Clone)]
pub struct Import { pub lib: String, pub sym: String }

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Default, Clone)]
pub struct PeFeatures {
    pub rich_entries: Vec<RichEntry>,        // (prod_id, build)
    pub imphash: Option<String>,             // lowercased hex
    pub tls_callbacks: bool,
    pub overlay: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RichEntry { pub prod_id: u16, pub build: u16 }

#[derive(Debug, Default, Clone)]
pub struct FunctionFeatures {
    pub name: String,
    pub apis: Vec<String>,
    pub string_refs: Vec<String>,
    pub mnemonics: Vec<String>,      // in-order instruction mnemonics
    pub xref_in_count: usize,
    pub xref_out_count: usize,
}
