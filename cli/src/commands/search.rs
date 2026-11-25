//! `raft5fs index` and `raft5fs search`.

use clap::Args;
use raft5fs_client::cli::Context;
use raft5fs_client::indexer::read_index;
#[cfg(feature = "index")]
use raft5fs_client::indexer::{
    Embed, ImageEmbed, IndexerConfig, PassKind, PassStats, describe, index_claimed,
    indexable_volumes, new_id, survey,
};
use raft5fs_client::vault::Vault;
#[cfg(feature = "index")]
use raft5fs_indexer::clip::ImageEmbedder;
#[cfg(feature = "index")]
use raft5fs_indexer::embed::Embedder;
#[cfg(feature = "index")]
use raft5fs_indexer::{Native, native_tools};
use raft5fs_proto::errno;
#[cfg(feature = "index")]
use raft5fs_proto::types::size_text;
use raft5fs_search::vector::{CLIP_MODEL, TEXT_MODEL as MODEL};
use raft5fs_search::view::QueryVector;
use raft5fs_search::view::{View, search_many};
use tokio::runtime::Runtime;

use super::{ConnectArgs, Outcome, log_in, runtime};

/// Indexes volumes for search now, in the foreground. Mounts, WebDAV
/// servers and the web app also index in the background. Only the
/// owner's switch (`raft5fs volume indexing`) stops a volume being
/// indexed.
#[derive(Args)]
#[command(verbatim_doc_comment)]
pub struct IndexArgs {
    /// Volumes to index, as your root shows them. By default, every
    /// volume you can write.
    pub volumes: Vec<String>,
    /// Walk the whole volume, not only what the activity log says changed.
    #[arg(long)]
    pub full: bool,
    /// Read everything and say how big the index would be. Stores nothing.
    #[arg(long, conflicts_with = "full")]
    pub dry_run: bool,
    /// Show how far indexing got in each volume. Changes nothing.
    #[arg(long, conflicts_with_all = ["full", "dry_run"])]
    pub status: bool,
}

#[derive(Args)]
pub struct SearchArgs {
    /// What to look for.
    pub query: String,
    /// Search only these volumes, as your root shows them. By default,
    /// every volume you can read that has an index.
    #[arg(long = "in", value_name = "VOLUME")]
    pub volumes: Vec<String>,
    /// How many results to show.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

/// The query's vectors: for meaning, if any volume has text vectors, and
/// for what photos show, if any has photos with image vectors.
#[cfg(feature = "index")]
fn query_vectors(
    runtime: &Runtime,
    views: &[&View],
    query: &str,
) -> (Option<Vec<f32>>, Option<Vec<f32>>) {
    let text = if views.iter().any(|v| v.has_model(MODEL)) {
        match runtime.block_on(Embedder::cached().query(query)) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("warning: searching by words only: {e}");
                None
            }
        }
    } else {
        None
    };
    let image = if views.iter().any(|v| v.has_image_model(CLIP_MODEL)) {
        match runtime.block_on(ImageEmbedder::cached().query(query)) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("warning: photos not searched by what they show: {e}");
                None
            }
        }
    } else {
        None
    };
    (text, image)
}

/// A build without the models: words, places and dates only.
#[cfg(not(feature = "index"))]
fn query_vectors(_: &Runtime, views: &[&View], _: &str) -> (Option<Vec<f32>>, Option<Vec<f32>>) {
    if views
        .iter()
        .any(|v| v.has_model(MODEL) || v.has_image_model(CLIP_MODEL))
    {
        eprintln!("note: this build has no search models: searching by words only");
    }
    (None, None)
}

/// This machine's name, for the status that search shows.
#[cfg(feature = "index")]
pub fn device_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is valid for its whole length, and gethostname writes
    // at most that much.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if ok && end > 0 {
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        "this computer".into()
    }
}

/// About how long ago `ms` (milliseconds since the epoch) was.
#[cfg(feature = "index")]
fn ago(ms: u64) -> String {
    let secs = raft5fs_proto::clock::now_millis().saturating_sub(ms) / 1000;
    match secs {
        0..120 => format!("{secs}s ago"),
        120..7200 => format!("{}m ago", secs / 60),
        7200..172_800 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// The volumes `names` names (as the root shows them), by label; or with
/// none, `all`.
fn chosen(
    runtime: &Runtime,
    vault: &Vault,
    names: &[String],
    all: impl FnOnce() -> Result<Vec<u64>, String>,
) -> Result<Vec<(String, u64)>, String> {
    let labels = runtime
        .block_on(vault.grant_paths())
        .map_err(|e| format!("cannot list what is shared with this account: {e}"))?;
    if names.is_empty() {
        return Ok(all()?
            .into_iter()
            .map(|ino| {
                (
                    labels.get(&ino).cloned().unwrap_or_else(|| ino.to_string()),
                    ino,
                )
            })
            .collect());
    }
    names
        .iter()
        .map(|name| {
            let name = name.trim_matches('/');
            labels
                .iter()
                .find(|(_, l)| l.trim_matches('/') == name)
                .map(|(&ino, l)| (l.clone(), ino))
                .ok_or_else(|| format!("{name} isn't in your root"))
        })
        .collect()
}

/// A build without the models (the `index` feature): other devices index.
#[cfg(not(feature = "index"))]
pub fn index(_: &ConnectArgs, _: IndexArgs) -> Outcome {
    Err(
        "this build of raft5fs doesn't index (it has no search models): your other \
         devices index, and `raft5fs search` here searches by words, places and dates"
            .into(),
    )
}

#[cfg(feature = "index")]
pub fn index(connect: &ConnectArgs, args: IndexArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let volumes = chosen(&runtime, &vault, &args.volumes, || {
        runtime
            .block_on(indexable_volumes(&vault))
            .map_err(|e| format!("cannot list volumes to index: {e}"))
    })?;
    if volumes.is_empty() {
        println!("no volume to index: you can write none whose owner allows it");
        return Ok(0);
    }
    let mut failed = false;
    if args.status {
        for (label, ino) in volumes {
            match runtime.block_on(read_index(&vault, ino)) {
                Ok(None) => println!("{label}: not indexed yet"),
                Ok(Some(index)) => {
                    let p = index.progress;
                    let by = p
                        .updated_by
                        .map(|(user, device)| format!(" by {user} on {device}"))
                        .unwrap_or_default();
                    let view = View::new(index.entries);
                    let (photos, seen) = view.photos(CLIP_MODEL);
                    let pictures = if photos > 0 {
                        format!(", {photos} photos ({seen} searchable by what they show)")
                    } else {
                        String::new()
                    };
                    println!(
                        "{label}: {} files{pictures}; last indexed {}{by}",
                        view.len(),
                        ago(p.updated_ms)
                    );
                }
                Err(e) => {
                    println!("{label}: {e}");
                    failed = true;
                }
            }
        }
        return Ok(if failed { 2 } else { 0 });
    }
    if args.dry_run {
        for (label, ino) in volumes {
            let counted = runtime.block_on(survey(&vault, ino, &Native, &mut |_| {}));
            match counted {
                Ok(s) => {
                    println!("{label}:");
                    for (format, (files, bytes)) in &s.by_format {
                        println!("  {format}: {files} files, {}", size_text(*bytes));
                    }
                    // Each chunk's vector: a byte for each of the model's
                    // 384 dimensions, a scale, and their framing. Each photo's
                    // image vector (512), and its thumbnail (about 12 KB).
                    let vectors = s.chunks * (384 + 9);
                    let photos = s.by_format.get("photo").map_or(0, |p| p.0 as u64);
                    let pictures = photos * (512 + 9 + 12_000);
                    println!(
                        "  {} words of text in {} chunks, and {photos} photos; the index would \
                         be about {} ({} of it vectors, {} thumbnails)",
                        s.words,
                        s.chunks,
                        size_text(s.index_bytes + vectors + pictures),
                        size_text(vectors + photos * 521),
                        size_text(photos * 12_000)
                    );
                }
                Err(e) => {
                    println!("{label}: {e}");
                    failed = true;
                }
            }
        }
        return Ok(if failed { 2 } else { 0 });
    }
    let config = IndexerConfig {
        pace: std::time::Duration::ZERO,
        device: device_name(),
        ..IndexerConfig::default()
    };
    let kind = if args.full {
        PassKind::Full
    } else {
        PassKind::Auto
    };
    let id = new_id();
    let tools = native_tools();
    for (label, ino) in volumes {
        // Ctrl-C stops the pass and gives up its claim, so other devices
        // needn't wait for it to run out. The next pass finishes the work.
        let mut told = |so_far: &PassStats| eprintln!("{label}: {}", describe(so_far));
        let done = runtime.block_on(async {
            tokio::select! {
                done = index_claimed(&vault, ino, id, &config, &tools, kind, &mut told) => Some(done),
                _ = tokio::signal::ctrl_c() => {
                    let _ = vault.remote().claim_index(ino, id, true).await;
                    None
                }
            }
        });
        let Some(done) = done else {
            println!("{label}: stopped; the next pass goes on from here");
            return Ok(130);
        };
        match done {
            Ok(stats) => {
                println!("{label}: {}", describe(&stats));
                for (path, e) in &stats.failed {
                    println!("  could not read {path}: {e}");
                }
                failed |= !stats.failed.is_empty();
            }
            Err(e) if e.errno == errno::EBUSY => println!("{label}: skipped: {e}"),
            Err(e) => {
                println!("{label}: {e}");
                failed = true;
            }
        }
    }
    Ok(if failed { 2 } else { 0 })
}

pub fn search(connect: &ConnectArgs, args: SearchArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = log_in(&runtime, &ctx)?;
    let volumes = chosen(&runtime, &vault, &args.volumes, || {
        let (grants, _) = runtime
            .block_on(vault.remote().list_grants_covered())
            .map_err(|e| format!("cannot list what is shared with this account: {e}"))?;
        Ok(grants.into_iter().map(|g| g.ino).collect())
    })?;
    let mut views = Vec::new();
    for (label, ino) in &volumes {
        let index = match runtime.block_on(read_index(&vault, *ino)) {
            Ok(Some(index)) => index,
            Ok(None) => continue,
            // A folder inside a volume, or one this account can't read.
            Err(e) if e.errno == errno::EACCES || e.errno == errno::EINVAL => continue,
            Err(e) => return Err(format!("cannot read the index of {label}: {e}")),
        };
        views.push((label, *ino, View::new(index.entries)));
    }
    if views.is_empty() {
        return Err("no volume here has a search index yet: run `raft5fs index`".into());
    }
    let views_only: Vec<&View> = views.iter().map(|(_, _, v)| v).collect();
    let (query_vector, image_vector) = query_vectors(&runtime, &views_only, &args.query);
    // All the volumes are ranked as one (`view::search_many`).
    let vector = query_vector.as_deref().map(|values| QueryVector {
        model: MODEL,
        values,
    });
    let image = image_vector.as_deref().map(|values| QueryVector {
        model: CLIP_MODEL,
        values,
    });
    let merged = search_many(&views_only, &args.query, vector, image, args.limit);
    if merged.is_empty() {
        println!("nothing found");
        return Ok(1);
    }
    for (i, hit) in merged {
        let label = views[i].0;
        println!("/{label}/{}", hit.path);
        if !hit.preview.is_empty() {
            println!("    {}", hit.preview);
        }
    }
    Ok(0)
}
