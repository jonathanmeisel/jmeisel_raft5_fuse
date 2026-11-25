//! How much memory a view takes per chunk, counted by the allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use raft5fs_search::record::{DocKind, Entry, Extra, Record, Stamp, Vector};
use raft5fs_search::text::chunks;
use raft5fs_search::view::View;

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

#[test]
fn a_view_takes_little_memory_per_chunk() {
    let before = HELD.load(Ordering::Relaxed);
    // `View::new` takes the entries: what is held after is the view.
    let view = View::new(records(1000));
    let held = HELD.load(Ordering::Relaxed) - before;
    let chunks = view.stats().chunks;
    let per_chunk = held as usize / chunks;
    println!(
        "{chunks} chunks: {} KB in all, {per_chunk} bytes a chunk",
        held / 1024
    );
    assert!(per_chunk < 2560, "{per_chunk} bytes a chunk");
}
