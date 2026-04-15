use include_dir::{include_dir, Dir};

pub static BUNDLED_RULES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../rules");

#[derive(Debug, Clone)]
pub struct AvailableRuleFile {
    pub subdir: String,            // e.g. "anti_analysis"
    pub stem: String,              // e.g. "rdtsc-timing"
    pub path: String,              // "anti_analysis/rdtsc-timing.yml"
}

/// Walk the embedded tree and return every `*.yml` without parsing.
/// Mirrors `bundled_sigs::available_sigs` / `type_archive::available_stems`.
pub fn available_bundled_rulefiles() -> Vec<AvailableRuleFile> {
    fn walk<'a>(dir: &'a Dir<'a>, prefix: &str, out: &mut Vec<AvailableRuleFile>) {
        for entry in dir.entries() {
            match entry {
                include_dir::DirEntry::File(f) => {
                    let p = f.path().to_string_lossy().to_string();
                    if !p.ends_with(".yml") && !p.ends_with(".yaml") { continue; }
                    let (subdir, stem) = match p.rsplit_once('/') {
                        Some((d, f)) => (d.to_string(), f.trim_end_matches(".yml")
                            .trim_end_matches(".yaml").to_string()),
                        None => (String::new(), p.trim_end_matches(".yml")
                            .trim_end_matches(".yaml").to_string()),
                    };
                    out.push(AvailableRuleFile { subdir, stem, path: p });
                }
                include_dir::DirEntry::Dir(d) => {
                    let new_prefix = if prefix.is_empty() { d.path().to_string_lossy().to_string() }
                                     else { format!("{prefix}/{}", d.path().display()) };
                    walk(d, &new_prefix, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&BUNDLED_RULES_DIR, "", &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn bundled_rule_contents(path: &str) -> Option<&'static str> {
    BUNDLED_RULES_DIR.get_file(path).and_then(|f| f.contents_utf8())
}
