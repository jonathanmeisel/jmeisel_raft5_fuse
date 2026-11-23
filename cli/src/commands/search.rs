//! `raft5fs index` and `raft5fs search`.

use std::collections::HashMap;

use clap::Args;
use raft5fs_client::cli::Context;
use raft5fs_client::indexer::{Embed, ImageEmbed};
use raft5fs_client::indexer::{
    IndexerConfig, PassKind, describe, index_claimed, indexable_volumes, new_id, read_index, survey,
};
use raft5fs_client::vault::Vault;
use raft5fs_indexer::clip::ImageEmbedder;
use raft5fs_indexer::embed::{Embedder, MODEL};
use raft5fs_indexer::{Native, native_tools};
use raft5fs_proto::errno;
use raft5fs_proto::types::size_text;
use raft5fs_search::rank::fuse;
use raft5fs_search::vector::CLIP_MODEL;
use raft5fs_search::view::QueryVector;
use raft5fs_search::view::View;
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

/// This machine's name, for the status that search shows.
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
                    let files = View::new(index.entries).len();
                    println!(
                        "{label}: {files} files; last indexed {}{by}",
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
        let done = runtime.block_on(index_claimed(
            &vault,
            ino,
            id,
            &config,
            &tools,
            kind,
            &mut |so_far| eprintln!("{label}: {}", describe(so_far)),
        ));
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
    // The query's meaning, if any volume has vectors to compare it with.
    let query_vector = if views.iter().any(|(_, _, v)| v.has_model(MODEL)) {
        match runtime.block_on(Embedder::cached().query(&args.query)) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("warning: searching by words only: {e}");
                None
            }
        }
    } else {
        None
    };
    // And what photos show, if any volume has photos with image vectors.
    let image_vector = if views.iter().any(|(_, _, v)| v.has_image_model(CLIP_MODEL)) {
        match runtime.block_on(ImageEmbedder::cached().query(&args.query)) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("warning: photos not searched by what they show: {e}");
                None
            }
        }
    } else {
        None
    };
    // Each volume ranks its own hits; the lists are then merged by rank.
    let mut lists = Vec::new();
    let mut hits = HashMap::new();
    for (label, ino, view) in &views {
        let vector = query_vector.as_deref().map(|values| QueryVector {
            model: MODEL,
            values,
        });
        let image = image_vector.as_deref().map(|values| QueryVector {
            model: CLIP_MODEL,
            values,
        });
        let list: Vec<(u64, u64)> = view
            .search_with(&args.query, vector, image, args.limit)
            .into_iter()
            .map(|h| {
                let key = (*ino, h.ino);
                hits.insert(key, ((*label).clone(), h));
                key
            })
            .collect();
        lists.push(list);
    }
    let merged = fuse(&lists);
    if merged.is_empty() {
        println!("nothing found");
        return Ok(1);
    }
    for (key, _) in merged.into_iter().take(args.limit) {
        let (label, hit) = &hits[&key];
        println!("/{label}/{}", hit.path);
        if !hit.preview.is_empty() {
            println!("    {}", hit.preview);
        }
    }
    Ok(0)
}
