//! How much memory a generation takes per file, counted by the allocator.
//! A test binary of its own: the allocator counts every thread's memory.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use raft5fs_search::record::{DocKind, Entry, Extra, Record, Stamp, Vector};
use raft5fs_search::text::chunks;

/// The system allocator, counting the bytes held.
struct Counting;

static HELD: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HELD.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HELD.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// A made-up vocabulary, and files of 300 words from it, as the browser
/// test's corpus has: about 150 distinct words a chunk.
fn records(files: usize) -> Vec<Entry> {
    let syllables = [
        "ka", "lo", "mer", "tis", "an", "dre", "vo", "lu", "pen", "sa", "ri", "gol", "bas", "ne",
        "tor", "mi",
    ];
    let mut seed: u64 = 7;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let words: Vec<String> = (0..3000)
        .map(|_| {
            (0..2 + next() % 3)
                .map(|_| syllables[next() % syllables.len()])
                .collect()
        })
        .collect();
    (0..files as u64)
        .map(|ino| {
            let text: Vec<&str> = (0..300)
                .map(|w| words[next() % if w % 7 == 0 { 50 } else { words.len() }].as_str())
                .collect();
            let mut chunks = chunks(&text.join(" "));
            for c in &mut chunks {
                c.vector = Some(Vector {
                    scale: 0.01,
                    values: vec![1; 384],
                });
            }
            Entry::Record(Record {
                ino,
                at_ms: 1,
                stamp: Stamp {
                    mtime_ns: 1,
                    size: 1,
                },
                path: format!("corpus/note-{ino}.txt"),
                kind: DocKind::Text,
                model: "m".into(),
                chunks,
                extra: Extra::default(),
            })
        })
        .collect()
}

/// A generation keeps only its rows, a path index and its centres in
/// memory: a few hundred bytes a file, however much text the files hold.
#[test]
fn a_generation_takes_little_memory_per_file() {
    use raft5fs_search::compact::{Config, build};
    use raft5fs_search::generation::pieces;
    use raft5fs_search::index::Generation;
    let records: Vec<Record> = records(1000)
        .into_iter()
        .filter_map(|e| match e {
            Entry::Record(r) => Some(r),
            _ => None,
        })
        .collect();
    let config = Config {
        text_model: "m".into(),
        ..Config::new([1; 8], [2; 32], 1)
    };
    let (header, files) = build(&records, config).unwrap();
    let all = pieces(&header, &files).unwrap();
    let resident: std::collections::HashMap<_, _> = Generation::resident(&header)
        .into_iter()
        .filter_map(|id| Some((id, all.get(&id)?.clone())))
        .collect();
    drop((records, files, all));
    let before = HELD.load(Ordering::Relaxed);
    let g = Generation::load(header, |id| resident.get(&id).cloned()).unwrap();
    let held = HELD.load(Ordering::Relaxed) - before;
    let per_file = held as usize / g.rows().len();
    println!(
        "{} files: {} KB in all, {per_file} bytes a file",
        g.rows().len(),
        held / 1024
    );
    // The sampled vectors and centres are most of it at this size.
    assert!(per_file < 2048, "{per_file} bytes a file");
}
