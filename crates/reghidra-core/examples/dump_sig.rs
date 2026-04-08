use reghidra_core::analysis::flirt::{FlirtDatabase, TrieNode};

fn walk(node: &TrieNode, out: &mut Vec<String>) {
    for leaf in &node.leaves {
        for m in &leaf.modules {
            out.push(m.name.clone());
        }
    }
    for c in &node.children {
        walk(c, out);
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: dump_sig <sig> [all]");
    let mode = std::env::args().nth(2).unwrap_or_default();
    let db = FlirtDatabase::load(std::path::Path::new(&path)).unwrap();
    let mut names = Vec::new();
    walk(&db.root, &mut names);
    if mode == "all" {
        for n in &names {
            println!("{n}");
        }
    }
    let weird = names.iter().filter(|n| n.len() <= 2).count();
    eprintln!("total={} weird={}", names.len(), weird);
}
