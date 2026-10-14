//! Writes the rules of the vendored Public Suffix List, without its comments, for `src/psl.rs`
//! to compile in.

use std::path::Path;

fn main() {
    let src = "data/public_suffix_list.dat";
    println!("cargo::rerun-if-changed={src}");
    let text = std::fs::read_to_string(src).expect("the vendored Public Suffix List");
    let mut rules = String::with_capacity(text.len() / 2);
    for rule in text.lines().filter_map(|l| l.split_whitespace().next()) {
        if !rule.starts_with("//") {
            rules.push_str(rule);
            rules.push('\n');
        }
    }
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&out).join("psl-rules.txt"), rules).expect("write the rules");
}
