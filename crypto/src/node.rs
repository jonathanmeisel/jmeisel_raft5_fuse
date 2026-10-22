//! Each inode's key record.
//!
//! A node has one key for each version, starting at 1. The record holds:
//!
//! - The current version, and the version of the parent's key that wraps
//!   the current key. The server reads these two numbers, not encrypted, to
//!   find stale nodes.
//! - `wrapper`: the current key, sealed under the parent's key at that
//!   version. A volume's root has no wrapper, because it has no parent key:
//!   only grants give its key to users.
//! - `name_key`: the key for this directory's entry name tags, sealed under
//!   the current key. It never changes, because a new name key would mean
//!   renaming every entry. A rotation only seals it again.
//! - `history`: the versions from `base` up to the current one, each sealed
//!   under the next version. Any version opens all older versions down to
//!   `base`, one step at a time, but never a newer one. The history only
//!   grows, until a prune removes the oldest entries when nothing is sealed
//!   under them. `base` is `version - history.len()`.
//!
//! **Staleness.** A rotation does not change the children's keys, so they
//! stay wrapped under the old version. A user who had the old key, such as
//! a user who was just revoked, can still open them. So a child must get
//! its own new key before anything new is written under it. A node whose
//! `parent_version` is older than its parent's `version` is stale. The
//! server refuses writes below a stale node, and the writer rotates it
//! first.

use crate::{Error, KEY_LEN, Key, Reader, aad, open, put_bytes, seal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeys {
    pub version: u32,
    /// 0 for a node with no parent key: a volume's root.
    pub parent_version: u32,
    wrapper: Vec<u8>,
    name_key: Vec<u8>,
    history: Vec<Vec<u8>>,
}

fn wrap_aad(ino: u64, version: u32, parent_version: u32) -> Vec<u8> {
    aad(
        "wrap",
        &[
            &ino.to_be_bytes(),
            &version.to_be_bytes(),
            &parent_version.to_be_bytes(),
        ],
    )
}

fn name_key_aad(ino: u64, version: u32) -> Vec<u8> {
    aad("name-key", &[&ino.to_be_bytes(), &version.to_be_bytes()])
}

/// Associated data for the history entry that holds version `older`, sealed
/// under version `older + 1`.
fn history_aad(ino: u64, older: u32) -> Vec<u8> {
    aad("history", &[&ino.to_be_bytes(), &older.to_be_bytes()])
}

impl NodeKeys {
    /// A new node's record and its first key. `parent` is the parent's
    /// current key and version, or `None` for a volume's root.
    pub fn create(ino: u64, parent: Option<(&Key, u32)>) -> (Self, Key) {
        let key = Key::random();
        let name_key = Key::random();
        let (wrapper, parent_version) = wrap(ino, 1, &key, parent);
        let record = Self {
            version: 1,
            parent_version,
            wrapper,
            name_key: seal(&key, &name_key_aad(ino, 1), name_key.as_bytes()),
            history: Vec::new(),
        };
        (record, key)
    }

    /// Opens the current key with the parent's key at `parent_version`.
    pub fn open(&self, ino: u64, parent_key: &Key) -> Result<Key, Error> {
        let what = "a node's key";
        if self.parent_version == 0 {
            return Err(Error(what));
        }
        let bytes = open(
            parent_key,
            &wrap_aad(ino, self.version, self.parent_version),
            &self.wrapper,
            what,
        )?;
        Key::from_slice(&bytes)
    }

    /// Opens the directory's name-tag key with the current key. This also
    /// checks that a key from a grant is this node's current key.
    pub fn name_key(&self, ino: u64, current: &Key) -> Result<Key, Error> {
        let bytes = open(
            current,
            &name_key_aad(ino, self.version),
            &self.name_key,
            "a directory's name key",
        )?;
        Key::from_slice(&bytes)
    }

    /// The oldest key version that the history can still open.
    pub fn base(&self) -> u32 {
        self.version - self.history.len() as u32
    }

    /// Returns version `want` of the key. It opens each older version in
    /// turn, starting from the current key. Fails if `want` is below `base`
    /// or above the current version.
    pub fn older(&self, ino: u64, current: &Key, want: u32) -> Result<Key, Error> {
        let what = "an older key version";
        let base = self.base();
        if want < base.max(1) || want > self.version {
            return Err(Error(what));
        }
        let mut key = current.clone();
        for older in (want..self.version).rev() {
            let bytes = open(
                &key,
                &history_aad(ino, older),
                &self.history[(older - base) as usize],
                what,
            )?;
            key = Key::from_slice(&bytes)?;
        }
        Ok(key)
    }

    /// Makes a new current key. Returns a new record and the new key. The
    /// new record keeps the old key in its history, under the new key, and
    /// wraps the new key under `parent`'s current key.
    pub fn rotate(
        &self,
        ino: u64,
        current: &Key,
        parent: Option<(&Key, u32)>,
    ) -> Result<(Self, Key), Error> {
        let name_key = self.name_key(ino, current)?;
        let key = Key::random();
        let version = self.version + 1;
        let mut history = self.history.clone();
        history.push(seal(
            &key,
            &history_aad(ino, self.version),
            current.as_bytes(),
        ));
        let (wrapper, parent_version) = wrap(ino, version, &key, parent);
        let record = Self {
            version,
            parent_version,
            wrapper,
            name_key: seal(&key, &name_key_aad(ino, version), name_key.as_bytes()),
            history,
        };
        Ok((record, key))
    }

    /// Wraps the same key under a different parent key, for a node that
    /// moves to another directory. `current` must be this node's key.
    pub fn rewrap(&self, ino: u64, current: &Key, parent: (&Key, u32)) -> Result<Self, Error> {
        // Check that `current` is this node's key before wrapping it under
        // a new parent.
        self.name_key(ino, current)?;
        let (wrapper, parent_version) = wrap(ino, self.version, current, Some(parent));
        Ok(Self {
            parent_version,
            wrapper,
            ..self.clone()
        })
    }

    /// Returns the record with its history cut to the versions from
    /// `keep_from` up. Use this when nothing is sealed under the older
    /// versions.
    pub fn pruned(&self, keep_from: u32) -> Self {
        let keep_from = keep_from.clamp(self.base(), self.version);
        let drop = (keep_from - self.base()) as usize;
        Self {
            history: self.history[drop..].to_vec(),
            ..self.clone()
        }
    }

    /// Whether this record is `before` with only its oldest history entries
    /// removed. This is the only change a prune may make. The check needs
    /// no key.
    pub fn is_pruning_of(&self, before: &NodeKeys) -> bool {
        self.version == before.version
            && self.parent_version == before.parent_version
            && self.wrapper == before.wrapper
            && self.name_key == before.name_key
            && before.history.ends_with(&self.history)
    }

    /// Whether this node needs a new key before anything is written under
    /// it, given its parent's current version.
    pub fn is_stale(&self, parent_version_now: u32) -> bool {
        self.parent_version != 0 && self.parent_version != parent_version_now
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.parent_version.to_be_bytes());
        put_bytes(&mut out, &self.wrapper);
        put_bytes(&mut out, &self.name_key);
        out.extend_from_slice(&(self.history.len() as u32).to_be_bytes());
        for entry in &self.history {
            put_bytes(&mut out, entry);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let what = "a node key record";
        let mut r = Reader(bytes);
        let version = r.u32(what)?;
        let parent_version = r.u32(what)?;
        let wrapper = r.bytes(what)?.to_vec();
        let name_key = r.bytes(what)?.to_vec();
        let count = r.u32(what)?;
        if version == 0 || count >= version {
            return Err(Error(what));
        }
        let history = (0..count)
            .map(|_| r.bytes(what).map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        r.finish(what)?;
        Ok(Self {
            version,
            parent_version,
            wrapper,
            name_key,
            history,
        })
    }

    /// Reads only `(version, parent_version)` from an encoded record. The
    /// server needs nothing else.
    pub fn versions(bytes: &[u8]) -> Result<(u32, u32), Error> {
        let what = "a node key record";
        let mut r = Reader(bytes);
        Ok((r.u32(what)?, r.u32(what)?))
    }
}

fn wrap(ino: u64, version: u32, key: &Key, parent: Option<(&Key, u32)>) -> (Vec<u8>, u32) {
    match parent {
        Some((parent_key, parent_version)) => (
            seal(
                parent_key,
                &wrap_aad(ino, version, parent_version),
                key.as_bytes(),
            ),
            parent_version,
        ),
        None => (Vec::new(), 0),
    }
}

const _: () = assert!(KEY_LEN == 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_key_opens_through_its_parent_key_only() {
        let parent = Key::random();
        let (record, key) = NodeKeys::create(9, Some((&parent, 1)));
        assert_eq!(record.open(9, &parent).unwrap(), key);
        assert!(record.open(9, &Key::random()).is_err());
        assert!(record.open(10, &parent).is_err(), "bound to its inode");
    }

    #[test]
    fn a_volume_root_has_no_wrapper() {
        let (record, key) = NodeKeys::create(5, None);
        assert_eq!(record.parent_version, 0);
        assert!(record.open(5, &key).is_err());
        record.name_key(5, &key).unwrap();
    }

    #[test]
    fn new_keys_open_old_ones_and_old_keys_never_open_new_ones() {
        let parent = Key::random();
        let (v1, k1) = NodeKeys::create(3, Some((&parent, 1)));
        let (v2, k2) = v1.rotate(3, &k1, Some((&parent, 1))).unwrap();
        let (v3, k3) = v2.rotate(3, &k2, Some((&parent, 1))).unwrap();
        assert_eq!(v3.version, 3);
        assert_eq!(v3.older(3, &k3, 3).unwrap(), k3);
        assert_eq!(v3.older(3, &k3, 2).unwrap(), k2);
        assert_eq!(v3.older(3, &k3, 1).unwrap(), k1);
        // The old keys cannot open anything in the new record.
        assert!(v3.name_key(3, &k2).is_err());
        assert!(v3.older(3, &k2, 1).is_err());
        assert!(v3.older(3, &k3, 4).is_err());
        assert!(v3.older(3, &k3, 0).is_err());
    }

    #[test]
    fn the_name_key_survives_rotation() {
        let (v1, k1) = NodeKeys::create(3, None);
        let (v2, k2) = v1.rotate(3, &k1, None).unwrap();
        assert_eq!(v1.name_key(3, &k1).unwrap(), v2.name_key(3, &k2).unwrap());
    }

    #[test]
    fn a_rotation_wraps_under_the_parents_new_version() {
        let old_parent = Key::random();
        let new_parent = Key::random();
        let (child, key) = NodeKeys::create(4, Some((&old_parent, 1)));
        assert!(child.is_stale(2));
        assert!(!child.is_stale(1));
        let (fresh, new_key) = child.rotate(4, &key, Some((&new_parent, 2))).unwrap();
        assert!(!fresh.is_stale(2));
        assert_eq!(fresh.open(4, &new_parent).unwrap(), new_key);
        assert!(fresh.open(4, &old_parent).is_err());
    }

    #[test]
    fn a_rewrap_keeps_the_key_and_moves_the_wrapper() {
        let a = Key::random();
        let b = Key::random();
        let (record, key) = NodeKeys::create(6, Some((&a, 1)));
        let moved = record.rewrap(6, &key, (&b, 4)).unwrap();
        assert_eq!(moved.open(6, &b).unwrap(), key);
        assert_eq!(moved.parent_version, 4);
        assert!(moved.open(6, &a).is_err());
        assert!(record.rewrap(6, &Key::random(), (&b, 4)).is_err());
    }

    #[test]
    fn a_pruned_record_opens_only_what_it_kept() {
        let parent = Key::random();
        let (v1, k1) = NodeKeys::create(3, Some((&parent, 1)));
        let (v2, k2) = v1.rotate(3, &k1, Some((&parent, 1))).unwrap();
        let (v3, k3) = v2.rotate(3, &k2, Some((&parent, 1))).unwrap();
        assert_eq!(v3.base(), 1);

        let kept = v3.pruned(2);
        assert_eq!(kept.base(), 2);
        assert_eq!(kept.older(3, &k3, 2).unwrap(), k2);
        assert!(kept.older(3, &k3, 1).is_err(), "version 1 is gone");
        assert!(kept.is_pruning_of(&v3));
        assert!(!v3.is_pruning_of(&kept), "a prune can't put entries back");

        let none = v3.pruned(3);
        assert_eq!(none.base(), 3);
        assert_eq!(none.older(3, &k3, 3).unwrap(), k3);
        assert!(none.is_pruning_of(&kept));
        assert_eq!(NodeKeys::decode(&none.encode()).unwrap(), none);
        assert_eq!(none.name_key(3, &k3).unwrap(), v3.name_key(3, &k3).unwrap());
        // A rotation of a pruned record continues from where the history
        // was cut.
        let (v4, k4) = none.rotate(3, &k3, Some((&parent, 1))).unwrap();
        assert_eq!(v4.base(), 3);
        assert_eq!(v4.older(3, &k4, 3).unwrap(), k3);

        // Any change other than removing old entries is not a prune.
        let (other, _) = NodeKeys::create(3, Some((&parent, 1)));
        assert!(!other.is_pruning_of(&v1));
        assert!(!v2.pruned(2).is_pruning_of(&v3));
    }

    #[test]
    fn records_round_trip_and_garbage_is_refused() {
        let (v1, k1) = NodeKeys::create(3, Some((&Key::random(), 2)));
        let (v2, _) = v1.rotate(3, &k1, None).unwrap();
        for record in [v1, v2] {
            let bytes = record.encode();
            assert_eq!(NodeKeys::decode(&bytes).unwrap(), record);
            assert_eq!(
                NodeKeys::versions(&bytes).unwrap(),
                (record.version, record.parent_version)
            );
            assert!(NodeKeys::decode(&bytes[..bytes.len() - 1]).is_err());
        }
        assert!(NodeKeys::decode(&[]).is_err());
    }
}
