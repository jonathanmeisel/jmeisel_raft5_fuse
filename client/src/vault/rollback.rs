//! What a device remembers so that the servers can't take it back in time.
//!
//! - **Key versions.** Each node's newest key version. A server that hands
//!   back an older key record could make this device seal new data under a
//!   key that a revoked user still has.
//! - **The pin counter.** The highest counter seen on the account's sealed
//!   pins. A server that hands back an older list could bring back a key that
//!   the account has since replaced.
//!
//! A real restore from a backup looks the same as a rollback, and only a
//! person can tell them apart. So the device refuses, says so, and waits for
//! `Vault::reset_versions`. A new device has nothing to compare with.
//!
//! A version 1 key record has no older record, so the blob leaves it out and
//! stays small: only nodes that had a new key take a line.

use std::collections::HashMap;
use std::time::Duration;

use raft5fs_crypto::identity::PUBLIC_KEY_LEN;
use raft5fs_crypto::node::NodeKeys;
use raft5fs_proto::errno;
use raft5fs_proto::types::FsError;

use super::{Vault, from_hex, to_hex};

/// The end of every refusal here. The web app looks for "restored from a
/// backup" to offer a reset, and shows what comes before "Only if".
const RESTORE_HINT: &str = "The servers may be rolling this back, or the filesystem was \
     restored from a backup: ask your admin which. Only if it was restored: \
     raft5fs reset-versions";

/// How often a burst of new key versions goes to the store. One walk of a
/// folder can meet thousands, and each save writes the whole blob.
const SAVE_EVERY: Duration = Duration::from_secs(1);

/// How the blob of `PinMemory` says that the account signed its labels.
const LABELS_SIGNED: &str = "labels-signed";

/// The newest key versions this device has seen.
#[derive(Default)]
pub(super) struct Versions {
    seen: HashMap<u64, u32>,
    /// Those not in the store yet.
    unsaved: HashMap<u64, u32>,
    saved_at: Option<std::time::SystemTime>,
}

/// What this device remembers of the account's pins.
#[derive(Default)]
pub(super) struct PinMemory {
    /// The highest counter seen.
    pub(super) floor: u64,
    /// Whether the account has signed its old labels (`Vault::sign_labels`).
    pub(super) labels_signed: bool,
    /// The pins as of the last merge, or `None` before the first.
    pub(super) base: Option<HashMap<String, [u8; PUBLIC_KEY_LEN]>>,
}

fn parse_versions(data: &[u8]) -> HashMap<u64, u32> {
    String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| {
            let (ino, version) = line.split_once(' ')?;
            Some((ino.parse().ok()?, version.parse().ok()?))
        })
        .collect()
}

fn parse_pin_memory(data: &[u8]) -> PinMemory {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    let mut head = lines.next().unwrap_or_default().split_whitespace().skip(1);
    let floor = head.next().and_then(|n| n.parse().ok()).unwrap_or(0);
    let labels_signed = head.next() == Some(LABELS_SIGNED);
    let base = lines
        .filter_map(|line| {
            let (user, hex) = line.split_once(' ')?;
            Some((user.to_string(), from_hex(hex)?))
        })
        .collect();
    PinMemory {
        floor,
        labels_signed,
        base: Some(base),
    }
}

impl Vault {
    fn versions_name(&self) -> String {
        format!("{}.versions", self.known.name)
    }

    /// The blob for this account and this key pair. Enrolling again starts a
    /// new list of pins, with its own counter.
    fn pin_memory_name(&self) -> String {
        let key = self.identity.public_key();
        format!(
            "{}.sync.{}.{}",
            self.known.name,
            self.remote.username(),
            to_hex(&key[..8])
        )
    }

    /// Reads the key versions that this device remembers.
    pub(super) fn load_versions(&self) {
        let stored = self.known.store.load(&self.versions_name());
        let seen = match stored {
            Ok(data) => parse_versions(&data.unwrap_or_default()),
            Err(e) => {
                eprintln!("cannot read the key versions seen here: {e}");
                HashMap::new()
            }
        };
        *self.versions.lock().unwrap() = Versions {
            seen,
            ..Versions::default()
        };
    }

    /// Returns `EIO` if `record` is older than a record seen before for
    /// `ino`.
    pub(super) fn check_not_older(&self, ino: u64, record: &NodeKeys) -> Result<(), FsError> {
        let seen = self.versions.lock().unwrap().seen.get(&ino).copied();
        self.save_versions(false);
        match seen {
            Some(seen) if record.version < seen => Err(FsError::new(
                errno::EIO,
                format!(
                    "inode {ino}: the server handed back key version {}, older than \
                     version {seen} seen before. {RESTORE_HINT}",
                    record.version
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Remembers `version` of `ino`'s key.
    pub(super) fn saw_version(&self, ino: u64, version: u32) {
        let mut versions = self.versions.lock().unwrap();
        if versions.seen.get(&ino).is_none_or(|&seen| seen < version) {
            versions.seen.insert(ino, version);
            if version >= 2 {
                versions.unsaved.insert(ino, version);
            }
        }
        drop(versions);
        self.save_versions(false);
    }

    /// Adds new key versions to the store, at most once each `SAVE_EVERY`,
    /// unless `now`. A failure only makes this device remember less.
    pub(super) fn save_versions(&self, now: bool) {
        let unsaved = {
            let mut versions = self.versions.lock().unwrap();
            let time = raft5fs_proto::clock::now();
            let recent = versions
                .saved_at
                .and_then(|at| time.duration_since(at).ok())
                .is_some_and(|since| since < SAVE_EVERY);
            if versions.unsaved.is_empty() || (recent && !now) {
                return;
            }
            versions.saved_at = Some(time);
            std::mem::take(&mut versions.unsaved)
        };
        let name = self.versions_name();
        let store = self.known.store.as_ref();
        let saved = crate::store::locked(store, &self.known.lock_name(), || {
            let mut all = parse_versions(&store.load(&name)?.unwrap_or_default());
            for (ino, version) in &unsaved {
                let newest = all.entry(*ino).or_insert(*version);
                *newest = (*newest).max(*version);
            }
            let mut lines: Vec<_> = all.into_iter().collect();
            lines.sort();
            let text: String = lines
                .into_iter()
                .map(|(ino, version)| format!("{ino} {version}\n"))
                .collect();
            store.save(&name, text.as_bytes())
        });
        if let Err(e) = saved {
            eprintln!("cannot save the key versions seen here: {e}");
        }
    }

    /// What this device remembers of the account's pins. A device with no
    /// memory has had no merge yet.
    pub(super) fn load_pin_memory(&self) -> PinMemory {
        match self.known.store.load(&self.pin_memory_name()) {
            Ok(Some(data)) => parse_pin_memory(&data),
            Ok(None) => PinMemory::default(),
            Err(e) => {
                eprintln!("cannot read the trusted keys' last merge: {e}");
                PinMemory::default()
            }
        }
    }

    /// Remembers a merge. The counter only goes up, even if another process
    /// merged at the same time.
    pub(super) fn save_pin_memory(&self, memory: &PinMemory) -> std::io::Result<()> {
        let name = self.pin_memory_name();
        let store = self.known.store.as_ref();
        crate::store::locked(store, &self.known.lock_name(), || {
            let stored = store.load(&name)?.map_or(0, |d| parse_pin_memory(&d).floor);
            store.save(&name, memory.to_text(stored.max(memory.floor)).as_bytes())
        })
    }

    /// Fails if the servers' pins are older than this device has seen.
    pub(super) fn check_pin_counter(&self, counter: u64, floor: u64) -> Result<(), FsError> {
        if counter < floor {
            return Err(FsError::new(
                errno::EIO,
                format!(
                    "the servers' copy of your trusted keys is change {counter}, older than \
                     change {floor} seen on this device, so this device keeps its own. \
                     {RESTORE_HINT}"
                ),
            ));
        }
        Ok(())
    }

    /// Forgets what this device remembers, after a real restore. It then
    /// accepts the versions the servers give. Its own pins win over the
    /// restored copy, which may hold keys replaced since. Other handles on
    /// this account in this process keep what they saw until they restart.
    pub async fn reset_versions(&self) -> Result<(), FsError> {
        let io = |e: std::io::Error| FsError::new(errno::EIO, format!("cannot reset: {e}"));
        *self.versions.lock().unwrap() = Versions::default();
        self.forget_all();
        let store = self.known.store.as_ref();
        let (versions, pins) = (self.versions_name(), self.pin_memory_name());
        crate::store::locked(store, &self.known.lock_name(), || {
            store.save(&versions, b"")?;
            store.save(&pins, b"counter 0\n")
        })
        .map_err(io)?;
        self.sync_pins().await
    }
}

impl PinMemory {
    fn to_text(&self, floor: u64) -> String {
        let labels = if self.labels_signed {
            LABELS_SIGNED
        } else {
            ""
        };
        let mut text = format!("counter {floor} {labels}\n");
        let mut users: Vec<_> = self.base.iter().flatten().collect();
        users.sort();
        for (user, key) in users {
            text.push_str(&format!("{user} {}\n", to_hex(key)));
        }
        text
    }
}
