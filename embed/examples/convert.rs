//! Converts the search models from their sources (safetensors, f32) into
//! the files every client uses: Q8_0 bodies, word tables and tokenizers.
//! Run by hand, once per model change, never in a build: clients use the
//! files pinned by SHA-256 in search/data/models.json, so all of them have
//! the same bytes.
//!
//! usage: cargo run --release -p raft5fs-embed --example convert -- <src> <out>
//!
//! `<src>` holds the sources, at the revisions `fetch-sources.sh` pins:
//! - `e5/`: intfloat/multilingual-e5-small (`config.json`,
//!   `model.safetensors`, `tokenizer.json`);
//! - `mclip/`: sentence-transformers/clip-ViT-B-32-multilingual-v1 (the
//!   same, and `2_Dense/model.safetensors`);
//! - `clip/`: sentence-transformers/clip-ViT-B-32's `0_CLIPModel`
//!   (`config.json`, `model.safetensors`).
//!
//! `<out>` gets `text/` and `clip/`, and the SHA-256 and size of each file
//! are printed for models.json.

use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use candle_core::quantized::gguf_file::{self, Value};
use candle_core::quantized::{GgmlDType, QTensor};
use candle_core::{Device, Tensor};
use raft5fs_embed::{quantize_row, write_unigram, write_wordpiece};
use sha2::{Digest, Sha256};

type Tensors = HashMap<String, Tensor>;

fn load(path: &Path) -> Tensors {
    candle_core::safetensors::load(path, &Device::Cpu)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn config(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Renames a source tensor to this crate's name, by the first rule that
/// fits (`N` stands for a layer number).
fn rename(name: &str, rules: &[(&str, &str)]) -> Option<String> {
    let (layer, generic) = match name.split('.').find_map(|p| p.parse::<usize>().ok()) {
        Some(n) => (Some(n), name.replacen(&format!(".{n}."), ".N.", 1)),
        None => (None, name.to_string()),
    };
    rules
        .iter()
        .find(|(from, _)| generic == *from)
        .map(|(_, to)| match layer {
            Some(n) => to.replacen(".N.", &format!(".{n}."), 1),
            None => to.to_string(),
        })
}

/// Linear layers' weights are Q8_0; everything else stays f32.
fn quantized(name: &str, t: &Tensor) -> bool {
    t.rank() == 2
        && name.ends_with(".weight")
        && (name.contains(".attn.") || name.contains(".ffn.") || name == "vision.projection.weight")
}

/// Each layer's query, key and value weights (and biases) as one `qkv`
/// tensor, one after another, so one matmul makes all three.
fn fuse_qkv(tensors: Vec<(String, Tensor)>) -> Vec<(String, Tensor)> {
    let mut by_name: HashMap<String, Tensor> = tensors.into_iter().collect();
    let layers: Vec<String> = by_name
        .keys()
        .filter_map(|n| n.strip_suffix(".attn.q.weight").map(String::from))
        .collect();
    for at in layers {
        for part in ["weight", "bias"] {
            let take = |w: &str, m: &mut HashMap<String, Tensor>| {
                m.remove(&format!("{at}.attn.{w}.{part}"))
            };
            let (Some(q), Some(k), Some(v)) = (
                take("q", &mut by_name),
                take("k", &mut by_name),
                take("v", &mut by_name),
            ) else {
                continue;
            };
            let fused = Tensor::cat(&[&q, &k, &v], 0).unwrap();
            by_name.insert(format!("{at}.attn.qkv.{part}"), fused);
        }
    }
    let mut out: Vec<(String, Tensor)> = by_name.into_iter().collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Writes a GGUF body of `tensors` (renamed) with `settings`.
fn write_body(path: &Path, tensors: &[(String, Tensor)], settings: &[(&str, Value)]) {
    let tensors = &fuse_qkv(tensors.to_vec());
    let mut q: Vec<(String, QTensor)> = tensors
        .iter()
        .map(|(name, t)| {
            let t = t.to_dtype(candle_core::DType::F32).unwrap();
            let dtype = if quantized(name, &t) {
                GgmlDType::Q8_0
            } else {
                GgmlDType::F32
            };
            (name.clone(), QTensor::quantize(&t, dtype).unwrap())
        })
        .collect();
    q.sort_by(|a, b| a.0.cmp(&b.0));
    let keys: Vec<String> = settings
        .iter()
        .map(|(k, _)| format!("raft5fs.{k}"))
        .collect();
    let meta: Vec<(&str, &Value)> = keys
        .iter()
        .map(String::as_str)
        .zip(settings.iter().map(|(_, v)| v))
        .collect();
    let refs: Vec<(&str, &QTensor)> = q.iter().map(|(n, t)| (n.as_str(), t)).collect();
    let mut w = BufWriter::new(std::fs::File::create(path).unwrap());
    gguf_file::write(&mut w, &meta, &refs).unwrap();
    w.flush().unwrap();
}

/// Writes a word table: one Q8_0 row per token.
fn write_table(path: &Path, table: &Tensor) {
    let rows: Vec<Vec<f32>> = table
        .to_dtype(candle_core::DType::F32)
        .unwrap()
        .to_vec2()
        .unwrap();
    let mut out = Vec::new();
    for row in &rows {
        quantize_row(row, &mut out);
    }
    std::fs::write(path, out).unwrap();
}

/// An encoder's settings, as `encoder::Settings` reads them.
#[allow(clippy::too_many_arguments)]
fn encoder_settings(
    hidden: u64,
    layers: u64,
    heads: u64,
    positions: u64,
    token_types: bool,
    eps: f64,
    act: &str,
    vocab: u64,
) -> Vec<(&'static str, Value)> {
    vec![
        ("kind", Value::String("encoder".into())),
        ("hidden", Value::U32(hidden as u32)),
        ("layers", Value::U32(layers as u32)),
        ("heads", Value::U32(heads as u32)),
        ("positions", Value::U32(positions as u32)),
        ("position_offset", Value::U32(0)),
        ("token_types", Value::U32(u32::from(token_types))),
        ("eps", Value::F32(eps as f32)),
        ("act", Value::String(act.into())),
        ("vocab", Value::U32(vocab as u32)),
    ]
}

fn renamed(src: &Tensors, rules: &[(&str, &str)]) -> Vec<(String, Tensor)> {
    let mut out: Vec<(String, Tensor)> = src
        .iter()
        .filter_map(|(n, t)| Some((rename(n, rules)?, t.clone())))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

const BERT: &[(&str, &str)] = &[
    (
        "embeddings.position_embeddings.weight",
        "embeddings.position",
    ),
    (
        "embeddings.token_type_embeddings.weight",
        "embeddings.token_type",
    ),
    ("embeddings.LayerNorm.weight", "embeddings.norm.weight"),
    ("embeddings.LayerNorm.bias", "embeddings.norm.bias"),
    (
        "encoder.layer.N.attention.self.query.weight",
        "layers.N.attn.q.weight",
    ),
    (
        "encoder.layer.N.attention.self.query.bias",
        "layers.N.attn.q.bias",
    ),
    (
        "encoder.layer.N.attention.self.key.weight",
        "layers.N.attn.k.weight",
    ),
    (
        "encoder.layer.N.attention.self.key.bias",
        "layers.N.attn.k.bias",
    ),
    (
        "encoder.layer.N.attention.self.value.weight",
        "layers.N.attn.v.weight",
    ),
    (
        "encoder.layer.N.attention.self.value.bias",
        "layers.N.attn.v.bias",
    ),
    (
        "encoder.layer.N.attention.output.dense.weight",
        "layers.N.attn.out.weight",
    ),
    (
        "encoder.layer.N.attention.output.dense.bias",
        "layers.N.attn.out.bias",
    ),
    (
        "encoder.layer.N.attention.output.LayerNorm.weight",
        "layers.N.attn_norm.weight",
    ),
    (
        "encoder.layer.N.attention.output.LayerNorm.bias",
        "layers.N.attn_norm.bias",
    ),
    (
        "encoder.layer.N.intermediate.dense.weight",
        "layers.N.ffn.up.weight",
    ),
    (
        "encoder.layer.N.intermediate.dense.bias",
        "layers.N.ffn.up.bias",
    ),
    (
        "encoder.layer.N.output.dense.weight",
        "layers.N.ffn.down.weight",
    ),
    (
        "encoder.layer.N.output.dense.bias",
        "layers.N.ffn.down.bias",
    ),
    (
        "encoder.layer.N.output.LayerNorm.weight",
        "layers.N.ffn_norm.weight",
    ),
    (
        "encoder.layer.N.output.LayerNorm.bias",
        "layers.N.ffn_norm.bias",
    ),
];

const DISTILBERT: &[(&str, &str)] = &[
    (
        "embeddings.position_embeddings.weight",
        "embeddings.position",
    ),
    ("embeddings.LayerNorm.weight", "embeddings.norm.weight"),
    ("embeddings.LayerNorm.bias", "embeddings.norm.bias"),
    (
        "transformer.layer.N.attention.q_lin.weight",
        "layers.N.attn.q.weight",
    ),
    (
        "transformer.layer.N.attention.q_lin.bias",
        "layers.N.attn.q.bias",
    ),
    (
        "transformer.layer.N.attention.k_lin.weight",
        "layers.N.attn.k.weight",
    ),
    (
        "transformer.layer.N.attention.k_lin.bias",
        "layers.N.attn.k.bias",
    ),
    (
        "transformer.layer.N.attention.v_lin.weight",
        "layers.N.attn.v.weight",
    ),
    (
        "transformer.layer.N.attention.v_lin.bias",
        "layers.N.attn.v.bias",
    ),
    (
        "transformer.layer.N.attention.out_lin.weight",
        "layers.N.attn.out.weight",
    ),
    (
        "transformer.layer.N.attention.out_lin.bias",
        "layers.N.attn.out.bias",
    ),
    (
        "transformer.layer.N.sa_layer_norm.weight",
        "layers.N.attn_norm.weight",
    ),
    (
        "transformer.layer.N.sa_layer_norm.bias",
        "layers.N.attn_norm.bias",
    ),
    (
        "transformer.layer.N.ffn.lin1.weight",
        "layers.N.ffn.up.weight",
    ),
    ("transformer.layer.N.ffn.lin1.bias", "layers.N.ffn.up.bias"),
    (
        "transformer.layer.N.ffn.lin2.weight",
        "layers.N.ffn.down.weight",
    ),
    (
        "transformer.layer.N.ffn.lin2.bias",
        "layers.N.ffn.down.bias",
    ),
    (
        "transformer.layer.N.output_layer_norm.weight",
        "layers.N.ffn_norm.weight",
    ),
    (
        "transformer.layer.N.output_layer_norm.bias",
        "layers.N.ffn_norm.bias",
    ),
];

const CLIP_VISION: &[(&str, &str)] = &[
    (
        "vision_model.embeddings.patch_embedding.weight",
        "vision.patch",
    ),
    ("vision_model.embeddings.class_embedding", "vision.class"),
    (
        "vision_model.embeddings.position_embedding.weight",
        "vision.position",
    ),
    ("vision_model.pre_layrnorm.weight", "vision.pre_norm.weight"),
    ("vision_model.pre_layrnorm.bias", "vision.pre_norm.bias"),
    (
        "vision_model.post_layernorm.weight",
        "vision.post_norm.weight",
    ),
    ("vision_model.post_layernorm.bias", "vision.post_norm.bias"),
    (
        "vision_model.encoder.layers.N.layer_norm1.weight",
        "layers.N.norm1.weight",
    ),
    (
        "vision_model.encoder.layers.N.layer_norm1.bias",
        "layers.N.norm1.bias",
    ),
    (
        "vision_model.encoder.layers.N.layer_norm2.weight",
        "layers.N.norm2.weight",
    ),
    (
        "vision_model.encoder.layers.N.layer_norm2.bias",
        "layers.N.norm2.bias",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.q_proj.weight",
        "layers.N.attn.q.weight",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.q_proj.bias",
        "layers.N.attn.q.bias",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.k_proj.weight",
        "layers.N.attn.k.weight",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.k_proj.bias",
        "layers.N.attn.k.bias",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.v_proj.weight",
        "layers.N.attn.v.weight",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.v_proj.bias",
        "layers.N.attn.v.bias",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.out_proj.weight",
        "layers.N.attn.out.weight",
    ),
    (
        "vision_model.encoder.layers.N.self_attn.out_proj.bias",
        "layers.N.attn.out.bias",
    ),
    (
        "vision_model.encoder.layers.N.mlp.fc1.weight",
        "layers.N.ffn.up.weight",
    ),
    (
        "vision_model.encoder.layers.N.mlp.fc1.bias",
        "layers.N.ffn.up.bias",
    ),
    (
        "vision_model.encoder.layers.N.mlp.fc2.weight",
        "layers.N.ffn.down.weight",
    ),
    (
        "vision_model.encoder.layers.N.mlp.fc2.bias",
        "layers.N.ffn.down.bias",
    ),
    ("visual_projection.weight", "vision.projection.weight"),
];

/// A `tokenizer.json` (Unigram with a precompiled map, or WordPiece) as
/// `tokenizer.bin`.
fn tokenizer_bin(path: &Path) -> Vec<u8> {
    let t = config(path);
    let model = &t["model"];
    let id_of = |token: &str| -> u32 {
        t["added_tokens"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["content"] == token)
            .unwrap_or_else(|| panic!("no added token {token}"))["id"]
            .as_u64()
            .unwrap() as u32
    };
    match model["type"].as_str().unwrap() {
        "Unigram" => {
            let map = t["normalizer"]["normalizers"]
                .as_array()
                .and_then(|n| n.iter().find(|n| n["type"] == "Precompiled"))
                .map(|n| base64(n["precompiled_charsmap"].as_str().unwrap()))
                .unwrap_or_default();
            let pieces: Vec<(String, f64)> = model["vocab"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_f64().unwrap()))
                .collect();
            let unk = model["unk_id"].as_u64().unwrap() as u32;
            write_unigram(unk, id_of("<s>"), id_of("</s>"), &map, &pieces)
        }
        "WordPiece" => {
            let vocab = model["vocab"].as_object().unwrap();
            let mut pieces = vec![String::new(); vocab.len()];
            for (p, id) in vocab {
                pieces[id.as_u64().unwrap() as usize] = p.clone();
            }
            let max = model["max_input_chars_per_word"].as_u64().unwrap() as u32;
            let unk = id_of(model["unk_token"].as_str().unwrap());
            write_wordpiece(unk, id_of("[CLS]"), id_of("[SEP]"), max, &pieces)
        }
        other => panic!("a tokenizer of kind {other}"),
    }
}

/// Standard base64 (with padding) as bytes.
fn base64(text: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64"),
        }
    };
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let pads = chunk.iter().filter(|&&c| c == b'=').count();
        let mut n = 0u32;
        for &c in chunk {
            n = n << 6 | if c == b'=' { 0 } else { value(c) };
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pads]);
    }
    out
}

fn u(c: &serde_json::Value, k: &str) -> u64 {
    c[k].as_u64().unwrap_or_else(|| panic!("config has no {k}"))
}

fn report(dir: &Path) {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    names.sort();
    for p in names {
        let bytes = std::fs::read(&p).unwrap();
        let sha = Sha256::digest(&bytes);
        let hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
        println!("{}  {}  {}", hex, bytes.len(), p.display());
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let src = PathBuf::from(args.next().expect("the sources' folder"));
    let out = PathBuf::from(args.next().expect("the output folder"));
    let text = out.join("text");
    let clip = out.join("clip");
    std::fs::create_dir_all(&text).unwrap();
    std::fs::create_dir_all(&clip).unwrap();

    // multilingual-e5-small: BERT.
    let c = config(&src.join("e5/config.json"));
    let t = load(&src.join("e5/model.safetensors"));
    let settings = encoder_settings(
        u(&c, "hidden_size"),
        u(&c, "num_hidden_layers"),
        u(&c, "num_attention_heads"),
        u(&c, "max_position_embeddings"),
        true,
        c["layer_norm_eps"].as_f64().unwrap(),
        c["hidden_act"].as_str().unwrap(),
        u(&c, "vocab_size"),
    );
    write_body(&text.join("body.gguf"), &renamed(&t, BERT), &settings);
    write_table(
        &text.join("table.q8"),
        &t["embeddings.word_embeddings.weight"],
    );
    std::fs::write(
        text.join("tokenizer.bin"),
        tokenizer_bin(&src.join("e5/tokenizer.json")),
    )
    .unwrap();
    drop(t);

    // The multilingual CLIP text side: DistilBERT, then its Dense layer.
    let c = config(&src.join("mclip/config.json"));
    let t = load(&src.join("mclip/model.safetensors"));
    let mut tensors = renamed(&t, DISTILBERT);
    let dense = load(&src.join("mclip/2_Dense/model.safetensors"));
    tensors.push(("projection.weight".into(), dense["linear.weight"].clone()));
    let settings = encoder_settings(
        u(&c, "dim"),
        u(&c, "n_layers"),
        u(&c, "n_heads"),
        u(&c, "max_position_embeddings"),
        false,
        1e-12,
        c["activation"].as_str().unwrap(),
        u(&c, "vocab_size"),
    );
    write_body(&clip.join("text-body.gguf"), &tensors, &settings);
    write_table(
        &clip.join("text-table.q8"),
        &t["embeddings.word_embeddings.weight"],
    );
    std::fs::write(
        clip.join("tokenizer.bin"),
        tokenizer_bin(&src.join("mclip/tokenizer.json")),
    )
    .unwrap();
    drop(t);

    // CLIP ViT-B/32's image side.
    let c = config(&src.join("clip/config.json"));
    let v = &c["vision_config"];
    let t = load(&src.join("clip/model.safetensors"));
    let settings = vec![
        ("kind", Value::String("vision".into())),
        ("hidden", Value::U32(u(v, "hidden_size") as u32)),
        ("layers", Value::U32(u(v, "num_hidden_layers") as u32)),
        ("heads", Value::U32(u(v, "num_attention_heads") as u32)),
        ("patch", Value::U32(u(v, "patch_size") as u32)),
        (
            "eps",
            Value::F32(v["layer_norm_eps"].as_f64().unwrap() as f32),
        ),
        (
            "act",
            Value::String(v["hidden_act"].as_str().unwrap().into()),
        ),
    ];
    write_body(
        &clip.join("vision.gguf"),
        &renamed(&t, CLIP_VISION),
        &settings,
    );

    report(&text);
    report(&clip);
}
