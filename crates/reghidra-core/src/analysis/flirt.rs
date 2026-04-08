use crate::analysis::functions::{Function, FunctionSource};
use crate::binary::LoadedBinary;
use crate::error::CoreError;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A parsed FLIRT signature database from a .sig file.
pub struct FlirtDatabase {
    pub header: SigHeader,
    pub root: TrieNode,
    pub signature_count: usize,
    pub source_path: PathBuf,
}

/// .sig file header fields.
pub struct SigHeader {
    pub version: u8,
    pub architecture: u8,
    pub features: u16,
    pub name: String,
    pub pattern_size: u16,
    pub n_functions: u32,
}

/// A trie node for pattern matching.
pub struct TrieNode {
    pub pattern: Vec<u8>,
    pub mask: Vec<bool>,
    pub children: Vec<TrieNode>,
    pub leaves: Vec<CrcGroup>,
}

/// A CRC16 disambiguation group.
pub struct CrcGroup {
    pub crc_length: u8,
    pub crc_value: u16,
    pub modules: Vec<FlirtModule>,
}

/// A single library function signature.
pub struct FlirtModule {
    pub name: String,
    pub offset: u32,
    pub length: u32,
    pub tail_bytes: Vec<TailByte>,
    pub referenced_functions: Vec<ReferencedFunction>,
    /// True if the picked name is from a static (local) function, not a public symbol.
    pub is_local: bool,
}

pub struct TailByte {
    pub offset: u32,
    pub value: u8,
}

pub struct ReferencedFunction {
    pub offset: u32,
    pub name: String,
}

/// Result of matching a function against the database.
pub struct FlirtMatch {
    pub name: String,
    pub offset: u32,
    pub module_length: u32,
}

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

const FEATURE_COMPRESSED: u16 = 0x10;

// ---------------------------------------------------------------------------
// CRC16 (reflected CRC-CCITT, polynomial 0x8408)
// ---------------------------------------------------------------------------

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Variable-length integer reading (big-endian)
// ---------------------------------------------------------------------------

struct SigReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SigReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, CoreError> {
        if self.pos >= self.data.len() {
            return Err(CoreError::Signature("unexpected end of data".into()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_short(&mut self) -> Result<u16, CoreError> {
        let hi = self.read_byte()? as u16;
        let lo = self.read_byte()? as u16;
        Ok((hi << 8) | lo)
    }

    fn read_word(&mut self) -> Result<u32, CoreError> {
        let hi = self.read_short()? as u32;
        let lo = self.read_short()? as u32;
        Ok((hi << 16) | lo)
    }

    /// Read variable-length int (max 2 bytes, 14-bit range).
    fn read_max_2_bytes(&mut self) -> Result<u16, CoreError> {
        let b0 = self.read_byte()? as u16;
        if b0 & 0x80 != 0 {
            let b1 = self.read_byte()? as u16;
            Ok(((b0 & 0x7F) << 8) | b1)
        } else {
            Ok(b0)
        }
    }

    /// Read variable-length int (up to 32 bits).
    fn read_multiple_bytes(&mut self) -> Result<u32, CoreError> {
        let b0 = self.read_byte()? as u32;
        if b0 & 0x80 == 0 {
            // 0xxxxxxx -> 7 bits
            return Ok(b0);
        }
        if b0 & 0xC0 != 0xC0 {
            // 10xxxxxx -> 14 bits
            let b1 = self.read_byte()? as u32;
            return Ok(((b0 & 0x7F) << 8) | b1);
        }
        if b0 & 0xE0 != 0xE0 {
            // 110xxxxx -> 29 bits
            let b1 = self.read_byte()? as u32;
            let b2 = self.read_short()? as u32;
            return Ok(((b0 & 0x3F) << 24) | (b1 << 16) | b2);
        }
        // 111xxxxx -> full 32 bits
        self.read_word()
    }
}

// ---------------------------------------------------------------------------
// Header parsing (little-endian fields)
// ---------------------------------------------------------------------------

fn read_le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn parse_header(data: &[u8]) -> Result<(SigHeader, usize), CoreError> {
    if data.len() < 7 {
        return Err(CoreError::Signature("file too small".into()));
    }

    // Magic
    if &data[0..6] != b"IDASGN" {
        return Err(CoreError::Signature("invalid magic (expected IDASGN)".into()));
    }

    let version = data[6];
    if !(5..=10).contains(&version) {
        return Err(CoreError::Signature(format!("unsupported sig version {version}")));
    }

    // V5 base header starts at offset 7
    // arch(1) + file_types(4) + os_types(2) + app_types(2) + features(2)
    // + old_n_functions(2) + crc16(2) + ctype(12) + library_name_len(1) + ctypes_crc16(2)
    let min_header = 7 + 1 + 4 + 2 + 2 + 2 + 2 + 2 + 12 + 1 + 2; // = 37
    if data.len() < min_header {
        return Err(CoreError::Signature("header too short".into()));
    }

    let arch = data[7];
    // file_types at 8..12
    // os_types at 12..14
    // app_types at 14..16
    let features = read_le_u16(data, 16);
    let old_n_functions = read_le_u16(data, 18);
    // crc16 at 20..22 (file checksum, we skip)
    // ctype at 22..34 (12 bytes, opaque)
    let library_name_len = data[34] as usize;
    // ctypes_crc16 at 35..37

    let mut offset = 37;
    let mut n_functions = old_n_functions as u32;
    let mut pattern_size: u16 = 32;

    // Version extensions
    if version >= 6 {
        if data.len() < offset + 4 {
            return Err(CoreError::Signature("header too short for v6+".into()));
        }
        n_functions = read_le_u32(data, offset);
        offset += 4;
    }

    if version >= 8 {
        if data.len() < offset + 2 {
            return Err(CoreError::Signature("header too short for v8+".into()));
        }
        pattern_size = read_le_u16(data, offset);
        offset += 2;
    }

    if version >= 10 {
        if data.len() < offset + 2 {
            return Err(CoreError::Signature("header too short for v10".into()));
        }
        offset += 2; // unknown field
    }

    // Library name
    if data.len() < offset + library_name_len {
        return Err(CoreError::Signature("truncated library name".into()));
    }
    let name = String::from_utf8_lossy(&data[offset..offset + library_name_len]).to_string();
    offset += library_name_len;

    Ok((
        SigHeader {
            version,
            architecture: arch,
            features,
            name,
            pattern_size,
            n_functions,
        },
        offset,
    ))
}

// ---------------------------------------------------------------------------
// Trie parsing
// ---------------------------------------------------------------------------

fn parse_trie(reader: &mut SigReader, version: u8, depth: usize, pattern_size: u16) -> Result<TrieNode, CoreError> {
    let n_children = reader.read_multiple_bytes()?;

    if n_children == 0 {
        // Leaf node: parse CRC groups
        let leaves = parse_leaves(reader, version)?;
        return Ok(TrieNode {
            pattern: Vec::new(),
            mask: Vec::new(),
            children: Vec::new(),
            leaves,
        });
    }

    let mut children = Vec::with_capacity(n_children as usize);

    for _ in 0..n_children {
        let node_length = reader.read_byte()? as usize;

        // Read variant mask
        let variant_mask = if node_length < 16 {
            reader.read_max_2_bytes()? as u64
        } else if node_length <= 32 {
            reader.read_multiple_bytes()? as u64
        } else if node_length <= 64 {
            let hi = reader.read_multiple_bytes()? as u64;
            let lo = reader.read_multiple_bytes()? as u64;
            (hi << 32) | lo
        } else {
            return Err(CoreError::Signature(format!("node_length {node_length} too large")));
        };

        // Read pattern bytes
        let mut pattern = Vec::with_capacity(node_length);
        let mut mask = Vec::with_capacity(node_length);

        for i in 0..node_length {
            let bit = 1u64 << (node_length - 1 - i);
            if variant_mask & bit != 0 {
                // Wildcard byte
                pattern.push(0x00);
                mask.push(false);
            } else {
                // Fixed byte
                pattern.push(reader.read_byte()?);
                mask.push(true);
            }
        }

        let child_depth = depth + node_length;
        let child = parse_trie(reader, version, child_depth, pattern_size)?;

        children.push(TrieNode {
            pattern,
            mask,
            children: child.children,
            leaves: child.leaves,
        });
    }

    Ok(TrieNode {
        pattern: Vec::new(),
        mask: Vec::new(),
        children,
        leaves: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Leaf / module parsing
// ---------------------------------------------------------------------------

/// Parse flags (control bits stored in last byte of name parsing):
const MORE_PUBLIC_NAMES: u8 = 0x01;
const READ_TAIL_BYTES: u8 = 0x02;
const READ_REFERENCED_FUNCTIONS: u8 = 0x04;
const MORE_MODULES_SAME_CRC: u8 = 0x08;
const MORE_CRC_GROUPS: u8 = 0x10;

fn parse_leaves(reader: &mut SigReader, version: u8) -> Result<Vec<CrcGroup>, CoreError> {
    let mut groups = Vec::new();

    loop {
        let crc_length = reader.read_byte()?;
        let crc_value = reader.read_short()?;

        let mut modules = Vec::new();
        let mut last_flags: u8;

        loop {
            let length = if version >= 9 {
                reader.read_multiple_bytes()?
            } else {
                reader.read_max_2_bytes()? as u32
            };

            let (module, flags) = parse_module(reader, version, length)?;
            last_flags = flags;
            modules.push(module);

            if flags & MORE_MODULES_SAME_CRC == 0 {
                break;
            }
        }

        groups.push(CrcGroup {
            crc_length,
            crc_value,
            modules,
        });

        if last_flags & MORE_CRC_GROUPS == 0 {
            break;
        }
    }

    Ok(groups)
}

// Function attribute flags (the optional pre-name byte, < 0x20).
// Source: rizinorg/rizin librz/sign/flirt.c
const FUNCTION_LOCAL: u8 = 0x02;
const FUNCTION_UNRESOLVED_COLLISION: u8 = 0x08;

fn parse_module(reader: &mut SigReader, version: u8, length: u32) -> Result<(FlirtModule, u8), CoreError> {
    // Read public functions (at least one). A module may declare multiple
    // public names, some marked as static (local) or as unresolved-collision
    // placeholders. We want to surface the best one for renaming.
    let mut offset: u32 = 0;
    let mut best_name = String::new();
    let mut best_offset: u32 = 0;
    let mut best_is_local = false;
    let mut best_is_collision = true; // start pessimistic so any real name wins
    let mut flags: u8;

    loop {
        // Delta-encoded offset
        let delta = if version >= 9 {
            reader.read_multiple_bytes()?
        } else {
            reader.read_max_2_bytes()? as u32
        };
        offset += delta;

        let mut current_byte = reader.read_byte()?;

        // Optional function-attribute byte (one byte, < 0x20). Bits we care about:
        //   0x02 = static (local) function
        //   0x08 = unresolved collision (sigmake placeholder; name is bogus, e.g. "?")
        let mut is_local = false;
        let mut is_collision = false;
        if current_byte < 0x20 {
            is_local = current_byte & FUNCTION_LOCAL != 0;
            is_collision = current_byte & FUNCTION_UNRESOLVED_COLLISION != 0;
            current_byte = reader.read_byte()?;
        }

        // Read name (bytes >= 0x20)
        let mut name = String::new();
        while current_byte >= 0x20 {
            name.push(current_byte as char);
            current_byte = reader.read_byte()?;
        }

        // current_byte is now the structural flags byte
        flags = current_byte;

        // Pick the best name for this module:
        //   1. Real (non-collision) > collision-placeholder
        //   2. Public > local (static)
        //   3. Earlier offset wins on ties
        let candidate_better = if name.is_empty() {
            false
        } else if best_name.is_empty() {
            true
        } else if best_is_collision && !is_collision {
            true
        } else if !best_is_collision && is_collision {
            false
        } else if best_is_local && !is_local {
            true
        } else if !best_is_local && is_local {
            false
        } else {
            offset < best_offset
        };

        if candidate_better {
            best_name = name;
            best_offset = offset;
            best_is_local = is_local;
            best_is_collision = is_collision;
        }

        if flags & MORE_PUBLIC_NAMES == 0 {
            break;
        }
    }

    // If the only names we saw were collision placeholders, drop the name
    // entirely so apply_signatures will skip this module.
    if best_is_collision {
        best_name.clear();
    }

    // Tail bytes
    let mut tail_bytes = Vec::new();
    if flags & READ_TAIL_BYTES != 0 {
        let count = if version >= 8 {
            reader.read_byte()? as usize
        } else {
            1
        };
        for _ in 0..count {
            let tb_offset = if version >= 9 {
                reader.read_multiple_bytes()?
            } else {
                reader.read_max_2_bytes()? as u32
            };
            let value = reader.read_byte()?;
            tail_bytes.push(TailByte { offset: tb_offset, value });
        }
    }

    // Referenced functions
    let mut referenced_functions = Vec::new();
    if flags & READ_REFERENCED_FUNCTIONS != 0 {
        let count = if version >= 8 {
            reader.read_byte()? as usize
        } else {
            1
        };
        for _ in 0..count {
            let ref_offset = if version >= 9 {
                reader.read_multiple_bytes()?
            } else {
                reader.read_max_2_bytes()? as u32
            };
            let name_len = reader.read_byte()? as usize;
            let actual_len = if name_len == 0 {
                reader.read_multiple_bytes()? as usize
            } else {
                name_len
            };
            let mut ref_name_bytes = Vec::with_capacity(actual_len);
            for _ in 0..actual_len {
                ref_name_bytes.push(reader.read_byte()?);
            }
            // Trim trailing null if present
            if ref_name_bytes.last() == Some(&0) {
                ref_name_bytes.pop();
            }
            let ref_name = String::from_utf8_lossy(&ref_name_bytes).to_string();
            referenced_functions.push(ReferencedFunction { offset: ref_offset, name: ref_name });
        }
    }

    Ok((
        FlirtModule {
            name: best_name,
            offset: best_offset,
            length,
            tail_bytes,
            referenced_functions,
            is_local: best_is_local,
        },
        flags,
    ))
}

// ---------------------------------------------------------------------------
// Database loading
// ---------------------------------------------------------------------------

impl FlirtDatabase {
    /// Parse a .sig file from disk.
    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let data = std::fs::read(path)?;
        Self::parse(&data, path.to_path_buf())
    }

    /// Parse a .sig file from raw bytes.
    pub fn parse(data: &[u8], source_path: PathBuf) -> Result<Self, CoreError> {
        let (header, tree_offset) = parse_header(data)?;

        let tree_data = &data[tree_offset..];

        // Decompress if needed
        let decompressed;
        let trie_bytes = if header.features & FEATURE_COMPRESSED != 0 {
            let mut buf = Vec::new();
            if header.version >= 7 {
                // zlib (with header)
                flate2::read::ZlibDecoder::new(Cursor::new(tree_data))
                    .read_to_end(&mut buf)
                    .map_err(|e| CoreError::Signature(format!("zlib decompression failed: {e}")))?;
            } else {
                // raw deflate (v5-6)
                flate2::read::DeflateDecoder::new(Cursor::new(tree_data))
                    .read_to_end(&mut buf)
                    .map_err(|e| CoreError::Signature(format!("deflate decompression failed: {e}")))?;
            }
            decompressed = buf;
            &decompressed
        } else {
            tree_data
        };

        let mut reader = SigReader::new(trie_bytes);
        let root = parse_trie(&mut reader, header.version, 0, header.pattern_size)?;

        let signature_count = header.n_functions as usize;

        Ok(FlirtDatabase {
            header,
            root,
            signature_count,
            source_path,
        })
    }

    /// Match function bytes against the signature database.
    /// Returns all matching signatures.
    pub fn match_function(&self, bytes: &[u8]) -> Vec<FlirtMatch> {
        let mut matches = Vec::new();
        self.match_node(&self.root, bytes, 0, &mut matches);
        matches
    }

    fn match_node(&self, node: &TrieNode, bytes: &[u8], offset: usize, matches: &mut Vec<FlirtMatch>) {
        // Check this node's pattern against the input bytes
        for (i, (&pat, &must_match)) in node.pattern.iter().zip(node.mask.iter()).enumerate() {
            let byte_pos = offset + i;
            if byte_pos >= bytes.len() {
                return; // Input too short
            }
            if must_match && bytes[byte_pos] != pat {
                return; // Mismatch
            }
        }

        let new_offset = offset + node.pattern.len();

        // Check leaves (CRC groups)
        for group in &node.leaves {
            self.check_crc_group(group, bytes, new_offset, matches);
        }

        // Recurse into children
        for child in &node.children {
            self.match_node(child, bytes, new_offset, matches);
        }
    }

    fn check_crc_group(&self, group: &CrcGroup, bytes: &[u8], _pattern_offset: usize, matches: &mut Vec<FlirtMatch>) {
        let pattern_size = self.header.pattern_size as usize;
        let crc_len = group.crc_length as usize;

        // CRC is computed over bytes starting at pattern_size for crc_length bytes
        if crc_len > 0 {
            let crc_start = pattern_size;
            let crc_end = crc_start + crc_len;
            if crc_end > bytes.len() {
                return; // Not enough bytes for CRC
            }
            let computed = crc16_ccitt(&bytes[crc_start..crc_end]);
            if computed != group.crc_value {
                return; // CRC mismatch
            }
        }

        // CRC matches — check each module
        for module in &group.modules {
            if self.check_module(module, bytes, pattern_size, crc_len) {
                if is_meaningful_sig_name(&module.name) {
                    matches.push(FlirtMatch {
                        name: module.name.clone(),
                        offset: module.offset,
                        module_length: module.length,
                    });
                }
            }
        }
    }

    fn check_module(&self, module: &FlirtModule, bytes: &[u8], pattern_size: usize, crc_len: usize) -> bool {
        // Check function length if specified
        if module.length > 0 && (bytes.len() as u32) < module.length {
            return false;
        }

        // Check tail bytes (offsets relative to pattern_size + crc_len)
        let tail_base = pattern_size + crc_len;
        for tb in &module.tail_bytes {
            let pos = tail_base + tb.offset as usize;
            if pos >= bytes.len() {
                return false;
            }
            if bytes[pos] != tb.value {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Integration: apply signatures to detected functions
// ---------------------------------------------------------------------------

/// Match FLIRT signatures against detected functions and rename matches.
/// Only renames functions with `sub_` prefixed names (CallTarget or Prologue source).
pub fn apply_signatures(
    db: &FlirtDatabase,
    functions: &mut [Function],
    binary: &LoadedBinary,
) -> usize {
    let mut match_count = 0;

    for func in functions.iter_mut() {
        // Only rename unnamed functions
        if !matches!(func.source, FunctionSource::CallTarget | FunctionSource::Prologue) {
            continue;
        }

        // Read function bytes from the binary
        // Use at least 256 bytes or the function size, whichever is larger
        let read_len = (func.size as usize).max(256).min(4096);
        let Some(bytes) = binary.read_bytes_at_va(func.entry_address, read_len) else {
            continue;
        };

        let matches = db.match_function(bytes);
        if matches.is_empty() {
            continue;
        }

        // Pick the best match: prefer offset 0, then longest module_length
        let best = matches
            .iter()
            .min_by_key(|m| (m.offset, u32::MAX - m.module_length))
            .unwrap();

        // Safety net: even after the collision-bit filter, some sig files
        // leak placeholder names like a bare `?`. Skip those so the
        // function stays `sub_XXXX` instead of becoming a wall of `?` in
        // the function list.
        if !is_meaningful_sig_name(&best.name) {
            continue;
        }

        func.name = best.name.clone();
        func.source = FunctionSource::Signature;
        match_count += 1;
    }

    match_count
}

/// A FLIRT module name is "meaningful" if it's non-empty and isn't just a
/// collision placeholder. `?` alone is the standard sigmake placeholder
/// for unresolved collisions; empty names occur when every candidate in
/// a module was flagged as a collision.
fn is_meaningful_sig_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && trimmed != "?"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_ccitt() {
        // Known test vector: empty input
        assert_eq!(crc16_ccitt(b""), 0xFFFF);

        // Single byte
        let crc = crc16_ccitt(b"A");
        assert_ne!(crc, 0); // Just verify it doesn't panic and produces a value
    }

    #[test]
    fn test_sig_reader_varint() {
        // Single byte: 0x42 -> 66
        let data = [0x42];
        let mut reader = SigReader::new(&data);
        assert_eq!(reader.read_multiple_bytes().unwrap(), 0x42);

        // Two bytes: 0x80 0x01 -> 1 (14-bit: (0x80 & 0x7F) << 8 | 0x01 = 0x0001)
        let data = [0x80, 0x01];
        let mut reader = SigReader::new(&data);
        assert_eq!(reader.read_multiple_bytes().unwrap(), 0x0001);

        // max_2_bytes: 0x42 -> 66
        let data = [0x42];
        let mut reader = SigReader::new(&data);
        assert_eq!(reader.read_max_2_bytes().unwrap(), 0x42);

        // max_2_bytes: 0x80 0x01 -> 1
        let data = [0x80, 0x01];
        let mut reader = SigReader::new(&data);
        assert_eq!(reader.read_max_2_bytes().unwrap(), 0x0001);
    }

    #[test]
    fn test_header_magic_check() {
        let bad_data = b"NOTASIG";
        assert!(parse_header(bad_data).is_err());
    }
}
