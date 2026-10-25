use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

// `std::time::Instant` panics in a browser; this is the same type natively.
use web_time::Instant;

/// The filesystem that a chunk belongs to (the live one, or one of its
/// snapshots, which use the same inode numbers; see `Vault`), its inode,
/// and its index.
type Key = (u64, u64, u64);

/// A cost charged for each entry in addition to its bytes, so a filesystem
/// full of holes (empty entries) cannot grow the cache without limit.
const ENTRY_OVERHEAD: usize = 64;

struct Slot {
    data: Arc<[u8]>,
    /// The seq that these bytes were read at. A later hit asks the store
    /// whether this is still the key's current seq, so the bytes need not
    /// be sent again.
    version: u64,
    /// When `version` was last known to be current (the fetch, or the
    /// latest confirmation), not when the bytes arrived.
    confirmed: Instant,
    tick: u64,
}

/// The result of a lookup. Both variants carry the `generation` to give
/// back to [`ChunkCache::insert`] or [`ChunkCache::confirm`] later.
pub enum Lookup {
    /// Nothing usable. Fetch the chunk, then `insert` it with the seq it
    /// came back at.
    Miss { generation: u64 },
    /// Bytes that were current at `version`. Use them only after the store
    /// says that `version` is still this key's current seq, and then call
    /// `confirm`. Otherwise fetch the chunk and `insert` the new bytes.
    Unconfirmed {
        data: Arc<[u8]>,
        version: u64,
        generation: u64,
    },
}

impl Lookup {
    /// The generation to give back to `insert` or `confirm`.
    pub fn generation(&self) -> u64 {
        match *self {
            Self::Miss { generation } | Self::Unconfirmed { generation, .. } => generation,
        }
    }
}

/// An LRU cache of whole decrypted chunks, keyed by `(space, ino, chunk
/// index)`. `space` separates the live filesystem from each snapshot, so
/// one size limit covers all of them. It is limited by bytes. It is on the
/// client, so a hit saves the round trip, the decryption, and the server's
/// store read.
///
/// - This client's own writes invalidate exactly, or replace the entry with
///   what they wrote.
/// - This client cannot see other clients' writes, so it never uses a hit
///   without a check. Every entry has the store's seq for the chunk as
///   read. A read sends that seq to the server, which sends the chunk again
///   only if the seq changed (see `Vault::read`). The check costs eight
///   bytes whatever the chunk's size, and gives the same result as a read
///   without a cache. So a confirmed hit is as fresh as a full read.
/// - A write can use an entry's bytes without a check, as the base of a
///   read-modify-write. The write sends the seq it expects, so the server
///   refuses it if the bytes were out of date.
///
/// So `ttl` does not limit staleness. It limits how long an entry can stay
/// unconfirmed: it only expires entries that nothing has used since.
///
/// A `generation` counter stops a race between a reader that uses a chunk
/// and a writer that invalidates it. The reader notes the generation before
/// it asks the server, and `insert` and `confirm` refuse if any
/// invalidation happened after that.
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
    fn enabled(&self) -> bool {
        self.capacity > 0
    }

    /// Returns the cached chunk and the seq it was read at, for the caller
    /// to confirm with the store, or a miss.
    pub fn get(&mut self, space: u64, ino: u64, index: u64) -> Lookup {
        let key = (space, ino, index);
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

    /// Whether bytes taken at `generation` are still safe to use, after the
    /// store confirmed that their version is current.
    ///
    /// - Returns false if anything was invalidated since, because a local
    ///   write may have replaced them. The caller must then fetch.
    /// - Restarts the entry's `ttl`, because its version is current now.
    /// - If the entry was evicted for space in the meantime, it is not
    ///   cached again. The caller's bytes are still good.
    pub fn confirm(&mut self, space: u64, ino: u64, index: u64, generation: u64) -> bool {
        if generation != self.generation {
            return false;
        }
        if let Some(slot) = self.map.get_mut(&(space, ino, index)) {
            slot.confirmed = Instant::now();
        }
        true
    }

    /// Caches `data`, read at seq `version`, unless something was
    /// invalidated after `generation` was read. In that case `data` could
    /// already be stale.
    pub fn insert(
        &mut self,
        space: u64,
        ino: u64,
        index: u64,
        data: Arc<[u8]>,
        version: u64,
        generation: u64,
    ) {
        let key = (space, ino, index);
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
    pub fn invalidate(&mut self, space: u64, ino: u64, indices: RangeInclusive<u64>) {
        self.generation += 1;
        let doomed: Vec<Key> = self
            .map
            .range((space, ino, *indices.start())..=(space, ino, *indices.end()))
            .map(|(k, _)| *k)
            .collect();
        for key in doomed {
            self.remove(key);
        }
    }

    pub fn invalidate_ino(&mut self, space: u64, ino: u64) {
        self.invalidate(space, ino, 0..=u64::MAX);
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

    /// The cached bytes, without the version that the caller would confirm.
    fn cached(c: &mut ChunkCache, ino: u64, idx: u64) -> Option<Arc<[u8]>> {
        match c.get(0, ino, idx) {
            Lookup::Unconfirmed { data, .. } => Some(data),
            Lookup::Miss { .. } => None,
        }
    }

    fn version_of(c: &mut ChunkCache, ino: u64, idx: u64) -> Option<u64> {
        match c.get(0, ino, idx) {
            Lookup::Unconfirmed { version, .. } => Some(version),
            Lookup::Miss { .. } => None,
        }
    }

    fn put(c: &mut ChunkCache, ino: u64, idx: u64, n: usize) {
        put_at(c, ino, idx, n, 1);
    }

    fn put_at(c: &mut ChunkCache, ino: u64, idx: u64, n: usize, version: u64) {
        let generation = c.get(0, ino, idx).generation();
        c.insert(0, ino, idx, chunk(n), version, generation);
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
        c.invalidate(0, 1, 2..=u64::MAX);
        assert!(cached(&mut c, 1, 0).is_some());
        assert!(cached(&mut c, 1, 1).is_some());
        assert!(cached(&mut c, 1, 2).is_none());
        assert!(cached(&mut c, 1, 3).is_none());
        c.invalidate_ino(0, 1);
        assert!(cached(&mut c, 1, 0).is_none());
        assert!(cached(&mut c, 2, 0).is_some());
    }

    #[test]
    fn insert_after_invalidation_is_refused() {
        let mut c = ChunkCache::new(10_000, LONG);
        let generation = c.get(0, 1, 0).generation();
        c.invalidate(0, 1, 0..=0);
        c.insert(0, 1, 0, chunk(10), 1, generation);
        assert!(cached(&mut c, 1, 0).is_none());
    }

    #[test]
    fn confirm_is_refused_after_an_invalidation() {
        let mut c = ChunkCache::new(10_000, LONG);
        put(&mut c, 1, 0, 10);
        let generation = c.get(0, 1, 0).generation();

        // A local write happened while the reader asked the store for the
        // current seq. Its bytes are out of date, whatever that call
        // returned.
        c.invalidate(0, 1, 0..=0);
        assert!(!c.confirm(0, 1, 0, generation));
    }

    #[test]
    fn confirm_restarts_the_ttl() {
        let ttl = Duration::from_millis(80);
        let mut c = ChunkCache::new(10_000, ttl);
        put(&mut c, 1, 0, 10);

        for _ in 0..4 {
            std::thread::sleep(ttl / 2);
            let generation = c.get(0, 1, 0).generation();
            assert!(
                c.confirm(0, 1, 0, generation),
                "a confirmed entry should not expire out from under a reader"
            );
        }
        assert!(cached(&mut c, 1, 0).is_some());
    }

    #[test]
    fn confirm_of_an_evicted_entry_still_clears_its_bytes() {
        let mut c = ChunkCache::new(100 + ENTRY_OVERHEAD, LONG);
        put(&mut c, 1, 0, 100);
        let generation = c.get(0, 1, 0).generation();
        put(&mut c, 1, 1, 100); // evicts (1, 0) for space, no invalidation

        assert!(cached(&mut c, 1, 0).is_none());
        assert!(
            c.confirm(0, 1, 0, generation),
            "eviction is not staleness -- the caller's bytes are still current"
        );
    }
}
