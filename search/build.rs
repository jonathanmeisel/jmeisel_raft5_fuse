//! Writes the search models' constants (`vector`, `view`) from
//! `data/models.json`, the one place a model is pinned: a model of the
//! same kind is changed there, not here.

use std::fmt::Write;

fn main() {
    let path = "data/models.json";
    println!("cargo::rerun-if-changed={path}");
    let text = std::fs::read_to_string(path).expect("data/models.json");
    let json: serde_json::Value = serde_json::from_str(&text).expect("models.json reads");
    let model = |key: &str| &json["models"][key];
    let mut out = String::new();
    for (key, prefix) in [("text", "TEXT"), ("clip", "CLIP")] {
        let m = model(key);
        let name = m["name"].as_str().expect("a model's name");
        let dims = m["dims"].as_u64().expect("a model's dims");
        let list = |field: &str| -> String {
            let items: Vec<String> = m[field]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| format!("{:?}", v.as_str().expect("a name")))
                        .collect()
                })
                .unwrap_or_default();
            format!("&[{}]", items.join(", "))
        };
        let num = |field: &str| -> f64 {
            m["search"][field]
                .as_f64()
                .unwrap_or_else(|| panic!("{key}'s search.{field}"))
        };
        writeln!(out, "pub const {prefix}_MODEL: &str = {name:?};").unwrap();
        writeln!(out, "pub const {prefix}_DIMS: usize = {dims};").unwrap();
        writeln!(
            out,
            "pub const {prefix}_REPLACES: &[&str] = {};",
            list("replaces")
        )
        .unwrap();
        writeln!(
            out,
            "pub const {prefix}_FLOOR: f32 = {:?};",
            num("floor") as f32
        )
        .unwrap();
        writeln!(
            out,
            "pub const {prefix}_MARGIN: f32 = {:?};",
            num("margin") as f32
        )
        .unwrap();
        writeln!(out, "pub const {prefix}_Z: f32 = {:?};", num("z") as f32).unwrap();
    }
    let words = model("text")["search"]["minWords"]
        .as_u64()
        .expect("text's search.minWords");
    writeln!(out, "pub const TEXT_MIN_WORDS: u32 = {words};").unwrap();
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("models.rs");
    std::fs::write(dest, out).unwrap();
}
