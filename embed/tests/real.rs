//! Tests with the real models. Set RAFT5FS_EMBED_MODELS to the `convert`
//! example's output (`text/`, `clip/`) and, for the tokenizer test,
//! RAFT5FS_EMBED_SOURCES to its sources (`fetch-sources.sh`); run with
//! --ignored.

use std::fs::File;
use std::path::PathBuf;

use raft5fs_embed::{MappedRows, Pooling, TextModel, TextOptions, Tokenizer};

fn dir(var: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(var).unwrap_or_else(|| panic!("set {var}")))
}

fn model(sub: &str, body: &str, table: &str, max: usize, dense: bool) -> TextModel {
    let d = dir("RAFT5FS_EMBED_MODELS").join(sub);
    TextModel::load(
        &mut File::open(d.join(body)).unwrap(),
        &std::fs::read(d.join("tokenizer.bin")).unwrap(),
        Box::new(MappedRows::open(&d.join(table)).unwrap()),
        TextOptions {
            pooling: Pooling::Mean,
            max_tokens: max,
            dense,
        },
    )
    .unwrap()
}

fn cos(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Texts in many scripts, with the odd characters that normalization and
/// splitting treat specially.
fn corpus() -> Vec<String> {
    let lines = [
        "We rode our bikes on gravel roads through Vermont last summer.",
        "Die Steuererklärung ist im April fällig; die Belege aufheben.",
        "El año pasado fuimos en bicicleta por los caminos de grava de Vermont.",
        "La declaración de la renta vence en abril: guarda los recibos, ¿vale?",
        "Je n'ai pas encore reçu la facture d'électricité de décembre.",
        "東京の夏はとても暑いです。京都も同じです！",
        "北京欢迎你，我们明天见。",
        "Привет, как дела? Всё хорошо.",
        "مرحبا بك في المدينة",
        "नमस्ते, आप कैसे हैं?",
        "Hello,world!(test)[x]{y} -- foo_bar/baz.qux@example.com #tag $100 50% a&b",
        "ﬁne ligatures, ½ fractions, ² superscripts ①②, ｆｕｌｌ ｗｉｄｔｈ",
        "e\u{301}cole, \u{feff}x\u{200b}y, emoji 😀🎉🚴‍♀️👨‍👩‍👧 🇺🇸",
        "tabs\tand\nnewlines\r\nand  double  spaces   triple",
        "a looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong word",
        "",
        " ",
    ];
    let mut out: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    let words: Vec<&str> = lines.iter().flat_map(|l| l.split(' ')).collect();
    let mut seed = 1u64;
    for _ in 0..300 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let n = 1 + (seed >> 40) as usize % 60;
        out.push(
            (0..n)
                .map(|i| words[((seed >> 20) as usize + i * 7) % words.len()])
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    out
}

#[test]
#[ignore = "needs the converted models and their sources"]
fn the_tokenizers_give_hugging_faces_ids() {
    let src = dir("RAFT5FS_EMBED_SOURCES");
    let models = dir("RAFT5FS_EMBED_MODELS");
    for (json, bin, most) in [
        ("e5/tokenizer.json", "text/tokenizer.bin", 512),
        ("mclip/tokenizer.json", "clip/tokenizer.bin", 128),
    ] {
        let ours = Tokenizer::read(&std::fs::read(models.join(bin)).unwrap()).unwrap();
        let mut hf = tokenizers::Tokenizer::from_file(src.join(json)).unwrap();
        hf.with_truncation(Some(tokenizers::TruncationParams {
            max_length: most,
            ..Default::default()
        }))
        .unwrap();
        for t in corpus() {
            let want = hf.encode(t.as_str(), true).unwrap().get_ids().to_vec();
            assert_eq!(ours.encode(&t, most), want, "{json}: {t:?}");
        }
    }
}

#[test]
#[ignore = "needs the converted models"]
fn batches_and_f32_weights_give_the_same_vectors() {
    let q8 = model("text", "body.gguf", "table.q8", 512, false);
    let dense = model("text", "body.gguf", "table.q8", 512, true);
    let texts: Vec<String> = (0..20)
        .map(|i| {
            format!(
                "passage: note {i}: {}",
                "fuimos en bicicleta por Vermont y comimos tarta ".repeat(1 + i % 6)
            )
        })
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let alone: Vec<Vec<f32>> = refs
        .iter()
        .map(|t| q8.embed(&[t]).unwrap().remove(0))
        .collect();
    for (m, bar) in [(&q8, 0.9999), (&dense, 0.9995)] {
        for (a, b) in alone.iter().zip(m.embed_batched(&refs).unwrap()) {
            assert!(cos(a, &b) > bar, "{}", cos(a, &b));
        }
    }
}
