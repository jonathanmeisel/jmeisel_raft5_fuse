use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

type Key = (u64, u64);

/// Bookkeeping charged per entry on top of its bytes, so a filesystem full
/// of holes (empty entries) can't grow the cache without bound.
const ENTRY_OVERHEAD: usize = 64;

struct Slot {
    data: Arc<[u8]>,
    /// The seq these bytes were read at. A later hit asks the store
    /// whether this is still the key's current seq rather than sending
    /// the bytes again.
    version: u64,
    /// When `version` was last known current -- the fetch, or the most
    /// recent confirmation of it -- not when the bytes arrived.
    confirmed: Instant,
    tick: u64,
}

/// What a lookup found. Both arms carry the `generation` to hand back to
/// [`ChunkCache::insert`] or [`ChunkCache::confirm`] afterwards.
pub enum Lookup {
    /// Nothing usable. Fetch the chunk, then `insert` it with the seq it
    /// came back at.
    Miss { generation: u64 },
    /// Bytes that were current as of `version`. They may only be served
    /// once the store says `version` is still this key's current seq --
    /// then `confirm`; otherwise fetch and `insert` the replacement.
    Unconfirmed {
        data: Arc<[u8]>,
        version: u64,
        generation: u64,
    },
}

impl Lookup {
    #[cfg(test)]
    pub fn generation(&self) -> u64 {
        match *self {
            Self::Miss { generation } | Self::Unconfirmed { generation, .. } => generation,
        }
    }
}

/// An LRU cache of whole chunks, keyed by `(ino, chunk index)` and bounded
/// by bytes.
///
/// Local writes invalidate exactly. Another mount's writes this cache
/// cannot see at all, so a hit is never served on trust: every entry
/// carries the seq it was read at, and the caller must confirm with the
/// store that the seq is still current before using the bytes (see
/// [`Lookup`]). That check costs one small round trip whatever the chunk
/// weighs, and is answered on exactly the terms an uncached read would be,
/// so a confirmed hit is as fresh as re-reading the chunk outright.
///
/// `ttl` therefore bounds not staleness but how long an entry may sit
/// unconfirmed: it only expires entries nothing has looked at since.
///
/// A `generation` counter closes the race between a reader using a chunk
/// and a writer invalidating it: the reader notes the generation before it
/// goes to the store, and `insert`/`confirm` refuse if any invalidation
/// happened since.
pub struct ChunkCache {
    capacity: usize,
    ttl: Duration,
    bytes: usize,
    tick: u64,
    generation: u64,
    map: BTreeMap<Key, Slot>,
    /// Recency order: oldest tick first.
    lru: BTreeMap<u64, Key>,
}

fn cost(data: &[u8]) -> usize {
    data.len() + ENTRY_OVERHEAD
}

impl ChunkCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            bytes: 0,
            tick: 0,
            generation: 0,
            map: BTreeMap::new(),
            lru: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn enabled(&self) -> bool {
        self.capacity > 0
    }

    /// The cached chunk and the seq it was read at, for the caller to
    /// confirm against the store; or a miss.
    pub fn get(&mut self, ino: u64, index: u64) -> Lookup {
        let key = (ino, index);
        let Some(slot) = self.map.get_mut(&key) else {
            return Lookup::Miss {
                generation: self.generation,
            };
        };
        if slot.confirmed.elapsed() >= self.ttl {
            self.remove(key);
            return Lookup::Miss {
                generation: self.generation,
            };
        }
        self.lru.remove(&slot.tick);
        self.tick += 1;
        slot.tick = self.tick;
        self.lru.insert(self.tick, key);
        Lookup::Unconfirmed {
            data: slot.data.clone(),
            version: slot.version,
            generation: self.generation,
        }
    }

    /// Whether bytes taken at `generation` are still safe to serve, having
    /// just had their version confirmed current by the store. False once
    /// anything has been invalidated since, because a local write may have
    /// replaced them in the meantime -- the caller must fetch instead.
    ///
    /// Also restarts the entry's `ttl`, since its version is current as of
    /// now. An entry evicted for space in the meantime is simply not
    /// re-cached; the bytes in the caller's hand are still good.
    pub fn confirm(&mut self, ino: u64, index: u64, generation: u64) -> bool {
        if generation != self.generation {
            return false;
        }
        if let Some(slot) = self.map.get_mut(&(ino, index)) {
            slot.confirmed = Instant::now();
        }
        true
    }

    /// Caches `data`, read at seq `version`, unless something was
    /// invalidated since `generation` was read -- in which case `data` may
    /// already be stale.
    pub fn insert(&mut self, ino: u64, index: u64, data: Arc<[u8]>, version: u64, generation: u64) {
        let key = (ino, index);
        if generation != self.generation || cost(&data) > self.capacity {
            return;
        }
        self.remove(key);
        self.bytes += cost(&data);
        self.tick += 1;
        self.lru.insert(self.tick, key);
        self.map.insert(
            key,
            Slot {
                data,
                version,
                confirmed: Instant::now(),
                tick: self.tick,
            },
        );
        while self.bytes > self.capacity {
            let Some((_, oldest)) = self.lru.pop_first() else {
                break;
            };
            if let Some(slot) = self.map.remove(&oldest) {
                self.bytes -= cost(&slot.data);
            }
        }
    }

    /// Drops the given chunk indices of `ino`.
    pub fn invalidate(&mut self, ino: u64, indices: RangeInclusive<u64>) {
        self.generation += 1;
        let doomed: Vec<Key> = self
            .map
            .range((ino, *indices.start())..=(ino, *indices.end()))
            .map(|(k, _)| *k)
            .collect();
        for key in doomed {
            self.remove(key);
        }
    }

    pub fn invalidate_ino(&mut self, ino: u64) {
        self.invalidate(ino, 0..=u64::MAX);
    }

    fn remove(&mut self, key: Key) {
        if let Some(slot) = self.map.remove(&key) {
            self.lru.remove(&slot.tick);
            self.bytes -= cost(&slot.data);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: Duration = Duration::from_secs(3600);

    fn chunk(n: usize) -> Arc<[u8]> {
        vec![7u8; n].into()
    }

    /// The cached bytes, ignoring the version the caller would confirm.
    fn cached(c: &mut ChunkCache, ino: u64, idx: u64) -> Option<Arc<[u8]>> {
        match c.get(ino, idx) {
            Lookup::Unconfirmed { data, .. } => Some(data),
            Lookup::Miss { .. } => None,
        }
    }

    fn version_of(c: &mut ChunkCache, ino: u64, idx: u64) -> Option<u64> {
        match c.get(ino, idx) {
            Lookup::Unconfirmed { version, .. } => Some(version),
            Lookup::Miss { .. } => None,
        }
    }

    fn put(c: &mut ChunkCache, ino: u64, idx: u64, n: usize) {
        put_at(c, ino, idx, n, 1);
    }

    fn put_at(c: &mut ChunkCache, ino: u64, idx: u64, n: usize, version: u64) {
        let generation = c.get(ino, idx).generation();
        c.insert(ino, idx, chunk(n), version, generation);
    }

    #[test]
    fn hit_after_insert() {
        let mut c = ChunkCache::new(10_000, LONG);
        assert!(cached(&mut c, 1, 0).is_none());
        put_at(&mut c, 1, 0, 100, 42);
        assert_eq!(cached(&mut c, 1, 0).unwrap().len(), 100);
        assert_eq!(version_of(&mut c, 1, 0), Some(42), "the seq round trips");
    }

    #[test]
    fn evicts_least_recently_used_by_bytes() {
        let per = 100 + ENTRY_OVERHEAD;
        let mut c = ChunkCache::new(per * 2, LONG);
        put(&mut c, 1, 0, 100);
        put(&mut c, 1, 1, 100);
        cached(&mut c, 1, 0).unwrap(); // 0 is now more recent than 1
        put(&mut c, 1, 2, 100);
        assert!(cached(&mut c, 1, 1).is_none());
        assert!(cached(&mut c, 1, 0).is_some());
        assert!(cached(&mut c, 1, 2).is_some());
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn oversized_entry_is_not_cached() {
        let mut c = ChunkCache::new(100, LONG);
        put(&mut c, 1, 0, 1000);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn zero_capacity_caches_nothing() {
        let mut c = ChunkCache::new(0, LONG);
        put(&mut c, 1, 0, 0);
        assert_eq!(c.len(), 0);
        assert!(!c.enabled());
    }

    #[test]
    fn ttl_expires_entries() {
        let mut c = ChunkCache::new(10_000, Duration::ZERO);
        put(&mut c, 1, 0, 10);
        assert!(cached(&mut c, 1, 0).is_none());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn invalidates_by_index_range_and_ino() {
        let mut c = ChunkCache::new(100_000, LONG);
        for idx in 0..4 {
            put(&mut c, 1, idx, 10);
        }
        put(&mut c, 2, 0, 10);
        c.invalidate(1, 2..=u64::MAX);
        assert!(cached(&mut c, 1, 0).is_some());
        assert!(cached(&mut c, 1, 1).is_some());
        assert!(cached(&mut c, 1, 2).is_none());
        assert!(cached(&mut c, 1, 3).is_none());
        c.invalidate_ino(1);
        assert!(cached(&mut c, 1, 0).is_none());
        assert!(cached(&mut c, 2, 0).is_some());
    }

    #[test]
    fn insert_after_invalidation_is_refused() {
        let mut c = ChunkCache::new(10_000, LONG);
        let generation = c.get(1, 0).generation();
        c.invalidate(1, 0..=0);
        c.insert(1, 0, chunk(10), 1, generation);
        assert!(cached(&mut c, 1, 0).is_none());
    }

    #[test]
    fn confirm_is_refused_after_an_invalidation() {
        let mut c = ChunkCache::new(10_000, LONG);
        put(&mut c, 1, 0, 10);
        let generation = c.get(1, 0).generation();

        // A local write landing while the reader was asking the store for
        // the current seq: its bytes are superseded, however that call
        // came back.
        c.invalidate(1, 0..=0);
        assert!(!c.confirm(1, 0, generation));
    }

    #[test]
    fn confirm_restarts_the_ttl() {
        let ttl = Duration::from_millis(80);
        let mut c = ChunkCache::new(10_000, ttl);
        put(&mut c, 1, 0, 10);

        for _ in 0..4 {
            std::thread::sleep(ttl / 2);
            let generation = c.get(1, 0).generation();
            assert!(
                c.confirm(1, 0, generation),
                "a confirmed entry should not expire out from under a reader"
            );
        }
        assert!(cached(&mut c, 1, 0).is_some());
    }

    #[test]
    fn confirm_of_an_evicted_entry_still_clears_its_bytes() {
        let mut c = ChunkCache::new(100 + ENTRY_OVERHEAD, LONG);
        put(&mut c, 1, 0, 100);
        let generation = c.get(1, 0).generation();
        put(&mut c, 1, 1, 100); // evicts (1, 0) for space, no invalidation

        assert!(cached(&mut c, 1, 0).is_none());
        assert!(
            c.confirm(1, 0, generation),
            "eviction is not staleness -- the caller's bytes are still current"
        );
    }
}
