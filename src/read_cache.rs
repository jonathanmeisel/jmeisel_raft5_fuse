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
    fetched: Instant,
    tick: u64,
}

/// An LRU cache of whole chunks, keyed by `(ino, chunk index)` and bounded
/// by bytes. Local writes invalidate exactly; `ttl` bounds how stale an
/// entry can get because of another mount's writes, which this cache can't
/// see.
///
/// A `generation` counter closes the race between a reader fetching a chunk
/// and a writer invalidating it: the reader notes the generation before it
/// fetches and `insert` refuses if any invalidation happened since.
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

    pub fn enabled(&self) -> bool {
        self.capacity > 0
    }

    /// The cached chunk, or on a miss the generation to hand back to
    /// `insert` once the chunk has been fetched.
    pub fn get(&mut self, ino: u64, index: u64) -> Result<Arc<[u8]>, u64> {
        let key = (ino, index);
        let Some(slot) = self.map.get_mut(&key) else {
            return Err(self.generation);
        };
        if slot.fetched.elapsed() >= self.ttl {
            self.remove(key);
            return Err(self.generation);
        }
        self.lru.remove(&slot.tick);
        self.tick += 1;
        slot.tick = self.tick;
        self.lru.insert(self.tick, key);
        Ok(slot.data.clone())
    }

    /// Caches `data` unless something was invalidated since `generation`
    /// was read, in which case `data` may already be stale.
    pub fn insert(&mut self, ino: u64, index: u64, data: Arc<[u8]>, generation: u64) {
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
                fetched: Instant::now(),
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

    fn put(c: &mut ChunkCache, ino: u64, idx: u64, n: usize) {
        let gen_ = c.get(ino, idx).err().unwrap_or(c.generation);
        c.insert(ino, idx, chunk(n), gen_);
    }

    #[test]
    fn hit_after_insert() {
        let mut c = ChunkCache::new(10_000, LONG);
        assert!(c.get(1, 0).is_err());
        put(&mut c, 1, 0, 100);
        assert_eq!(c.get(1, 0).unwrap().len(), 100);
    }

    #[test]
    fn evicts_least_recently_used_by_bytes() {
        let per = 100 + ENTRY_OVERHEAD;
        let mut c = ChunkCache::new(per * 2, LONG);
        put(&mut c, 1, 0, 100);
        put(&mut c, 1, 1, 100);
        c.get(1, 0).unwrap(); // 0 is now more recent than 1
        put(&mut c, 1, 2, 100);
        assert!(c.get(1, 1).is_err());
        assert!(c.get(1, 0).is_ok());
        assert!(c.get(1, 2).is_ok());
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
        assert!(c.get(1, 0).is_err());
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
        assert!(c.get(1, 0).is_ok());
        assert!(c.get(1, 1).is_ok());
        assert!(c.get(1, 2).is_err());
        assert!(c.get(1, 3).is_err());
        c.invalidate_ino(1);
        assert!(c.get(1, 0).is_err());
        assert!(c.get(2, 0).is_ok());
    }

    #[test]
    fn insert_after_invalidation_is_refused() {
        let mut c = ChunkCache::new(10_000, LONG);
        let gen_ = c.get(1, 0).unwrap_err();
        c.invalidate(1, 0..=0);
        c.insert(1, 0, chunk(10), gen_);
        assert!(c.get(1, 0).is_err());
    }
}
