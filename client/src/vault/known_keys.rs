//! The account's pinned public keys, kept on this device.

use super::*;

/// Public keys that this account checked, by user. The server could give its
/// own key in place of a user's key, so a person checks a key's fingerprint
/// before the vault pins it, and the vault refuses a different key later. It
/// keeps the keys in memory and in a blob of a `Store` (one `user hex-key`
/// line for each user; natively, a file readable only by its owner).
///
/// The names come from the server, so the vault checks each one
/// (`check_username`) before it writes it to the blob. A name with a line
/// break could otherwise add a line that pins a key for a different user.
pub struct KnownKeys {
    keys: Mutex<HashMap<String, [u8; PUBLIC_KEY_LEN]>>,
    pub(super) store: Arc<dyn Store>,
    pub(super) name: String,
}

impl KnownKeys {
    /// Pins kept only in memory, forgotten when the last handle drops.
    pub fn in_memory() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            store: Arc::new(MemoryStore::new()),
            name: "known_keys".into(),
        }
    }

    /// Loads the keys pinned in blob `name` of `store`, which does not have
    /// to exist yet. New pins go into the same blob. A bad line, or a
    /// second key for the same user, makes the whole blob fail: this code
    /// did not write that blob, and it cannot know which key is correct.
    pub fn open(store: Arc<dyn Store>, name: &str) -> std::io::Result<Self> {
        let keys = read_pins(store.as_ref(), name)?;
        Ok(Self {
            keys: Mutex::new(keys),
            store,
            name: name.to_string(),
        })
    }

    /// Loads the keys pinned in `file`, which does not have to exist yet,
    /// as `open` does.
    #[cfg(unix)]
    pub fn load(file: std::path::PathBuf) -> std::io::Result<Self> {
        let bad = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} isn't a file name this can use", file.display()),
            )
        };
        let name = file.file_name().and_then(|n| n.to_str()).ok_or_else(bad)?;
        let dir = file.parent().ok_or_else(bad)?.to_path_buf();
        Self::open(Arc::new(crate::store::FileStore::new(dir)), name)
    }

    /// A copy of the pins as they are now, kept only in memory.
    pub(super) fn memory_copy(&self) -> Self {
        let copy = Self::in_memory();
        *copy.keys.lock().unwrap() = self.all();
        copy
    }

    /// Another handle on the same pins and the same store. A pin that one
    /// handle adds later reaches the other handle through the store.
    pub fn duplicate(&self) -> Self {
        Self {
            keys: Mutex::new(self.keys.lock().unwrap().clone()),
            store: Arc::clone(&self.store),
            name: self.name.clone(),
        }
    }

    pub(super) fn lock_name(&self) -> String {
        format!("{}.lock", self.name)
    }

    /// The key pinned for `user`, if there is one. If no key is known in
    /// memory, this reads the store again, because `raft5fs trust` can add
    /// a pin while a mount runs. If the blob is now bad, this adds nothing.
    pub fn pinned(&self, user: &str) -> Option<[u8; PUBLIC_KEY_LEN]> {
        let mut keys = self.keys.lock().unwrap();
        if let Some(key) = keys.get(user) {
            return Some(*key);
        }
        let key = *read_pins(self.store.as_ref(), &self.name).ok()?.get(user)?;
        keys.insert(user.to_string(), key);
        Some(key)
    }

    /// Checks `key` against the key pinned for `user`.
    ///
    /// - Returns `key` if it matches the pin.
    /// - If no key is pinned, pins `key` (also in the store) and returns
    ///   it.
    /// - Returns `EPERM` if a different key is pinned, and `EIO` if `key`
    ///   has the wrong length.
    pub fn check(&self, user: &str, key: &[u8]) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        let key: [u8; PUBLIC_KEY_LEN] = key
            .try_into()
            .map_err(|_| FsError::new(errno::EIO, format!("{user}'s public key is malformed")))?;
        // Another process could have pinned this user in the store.
        self.pinned(user);
        let mut keys = self.keys.lock().unwrap();
        match keys.get(user) {
            Some(pinned) if *pinned == key => Ok(key),
            Some(pinned) => Err(FsError::new(
                errno::EPERM,
                format!(
                    "the server gave a different key for {user} than before ({} now, {} pinned); \
                     if they enrolled again, check the new fingerprint with them and forget the old",
                    fingerprint(&key),
                    fingerprint(pinned)
                ),
            )),
            None => {
                self.append_pin(user, &key).map_err(|e| {
                    FsError::new(
                        errno::EIO,
                        format!(
                            "cannot pin {user}'s key in {}: {e}",
                            self.store.location(&self.name)
                        ),
                    )
                })?;
                keys.insert(user.to_string(), key);
                Ok(key)
            }
        }
    }

    /// Adds a `user key` line to the blob, under the store's lock so that
    /// another process's pin made at the same time is kept.
    fn append_pin(&self, user: &str, key: &[u8]) -> std::io::Result<()> {
        crate::store::locked(self.store.as_ref(), &self.lock_name(), || {
            let mut data = self.store.load(&self.name)?.unwrap_or_default();
            if !data.is_empty() && !data.ends_with(b"\n") {
                data.push(b'\n');
            }
            data.extend_from_slice(format!("{user} {}\n", to_hex(key)).as_bytes());
            self.store.save(&self.name, &data)
        })
    }

    /// Every pinned key, by user name, sorted by name.
    pub fn entries(&self) -> Vec<(String, [u8; PUBLIC_KEY_LEN])> {
        let mut entries: Vec<_> = self
            .keys
            .lock()
            .unwrap()
            .iter()
            .map(|(user, key)| (user.clone(), *key))
            .collect();
        entries.sort();
        entries
    }

    /// Removes `user`'s pinned key, so that their next key needs checking.
    pub fn forget(&self, user: &str) -> std::io::Result<()> {
        self.rewrite(user, None)
    }

    /// Pins `key` for `user`, in place of any key pinned before. Only for
    /// a key this account checked: `sync_pins` uses it for what its other
    /// devices trust.
    pub(crate) fn set(&self, user: &str, key: &[u8; PUBLIC_KEY_LEN]) -> std::io::Result<()> {
        self.rewrite(user, Some(key))
    }

    /// Every pinned key, including those that another process pinned in
    /// the store since this one loaded it.
    pub fn all(&self) -> HashMap<String, [u8; PUBLIC_KEY_LEN]> {
        let mut keys = self.keys.lock().unwrap();
        if let Ok(stored) = read_pins(self.store.as_ref(), &self.name) {
            for (other, key) in stored {
                keys.entry(other).or_insert(key);
            }
        }
        keys.clone()
    }

    /// Sets (`Some`) or removes (`None`) `user`'s pin, and writes the whole
    /// blob again.
    fn rewrite(&self, user: &str, key: Option<&[u8; PUBLIC_KEY_LEN]>) -> std::io::Result<()> {
        check_username(user).map_err(|e| std::io::Error::other(e.message))?;
        let mut keys = self.keys.lock().unwrap();
        crate::store::locked(self.store.as_ref(), &self.lock_name(), || {
            // Keep pins that another process added since this one loaded.
            if let Ok(stored) = read_pins(self.store.as_ref(), &self.name) {
                for (other, key) in stored {
                    keys.entry(other).or_insert(key);
                }
            }
            match key {
                Some(key) => keys.insert(user.to_string(), *key),
                None => keys.remove(user),
            };
            let mut users: Vec<_> = keys.iter().collect();
            users.sort();
            let text: String = users
                .into_iter()
                .map(|(user, key)| format!("{user} {}\n", to_hex(key)))
                .collect();
            self.store.save(&self.name, text.as_bytes())
        })
    }
}

/// Reads the pins in blob `name`. A missing blob has no pins. A bad line,
/// or a second key for the same user, makes the whole blob fail.
pub(super) fn read_pins(
    store: &dyn Store,
    name: &str,
) -> std::io::Result<HashMap<String, [u8; PUBLIC_KEY_LEN]>> {
    let bad = |n: usize, why: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} line {}: {why}", store.location(name), n + 1),
        )
    };
    let mut keys = HashMap::new();
    let Some(data) = store.load(name)? else {
        return Ok(keys);
    };
    let text = String::from_utf8(data).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: not text", store.location(name)),
        )
    })?;
    for (n, line) in text.lines().enumerate() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (user, hex) = match fields.as_slice() {
            [] => continue,
            [user, hex] => (*user, *hex),
            _ => return Err(bad(n, "not a user name and a key")),
        };
        check_username(user).map_err(|e| bad(n, &e.message))?;
        let key = from_hex(hex).ok_or_else(|| bad(n, "not a public key"))?;
        if keys.insert(user.to_string(), key).is_some_and(|k| k != key) {
            return Err(bad(n, &format!("a second, different key for {user}")));
        }
    }
    Ok(keys)
}

pub(super) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn from_hex(hex: &str) -> Option<[u8; PUBLIC_KEY_LEN]> {
    if hex.len() != PUBLIC_KEY_LEN * 2 {
        return None;
    }
    let mut out = [0; PUBLIC_KEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_pins_survive_a_reload(open: impl Fn() -> KnownKeys) {
        let known = open();
        known.check("alice", &[1; 32]).unwrap();
        known.check("bob", &[2; 32]).unwrap();

        let again = open();
        again.check("alice", &[1; 32]).unwrap();
        assert_eq!(
            again.check("alice", &[9; 32]).unwrap_err().errno,
            errno::EPERM
        );
        assert_eq!(
            again.check("alice", &[1; 31]).unwrap_err().errno,
            errno::EIO
        );

        // A pin made through another handle reaches this one.
        let other = open();
        known.check("carol", &[4; 32]).unwrap();
        assert_eq!(other.pinned("carol"), Some([4; 32]));

        // Forgetting keeps pins that another handle added since.
        again.forget("alice").unwrap();
        let after = open();
        assert_eq!(after.pinned("carol"), Some([4; 32]));
        after.check("alice", &[9; 32]).unwrap();
        assert_eq!(
            after.check("bob", &[3; 32]).unwrap_err().errno,
            errno::EPERM
        );
    }

    #[test]
    fn pinned_keys_survive_a_reload_and_a_different_key_is_refused() {
        let file = std::env::temp_dir().join(format!("raft5fs-known-keys-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        check_pins_survive_a_reload(|| KnownKeys::load(file.clone()).unwrap());
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(file.with_file_name(format!(
            "{}.lock",
            file.file_name().unwrap().to_str().unwrap()
        )));

        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        check_pins_survive_a_reload(|| KnownKeys::open(Arc::clone(&store), "pins").unwrap());
    }

    #[test]
    fn pins_from_two_places_at_once_all_land() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let threads: Vec<_> = (0..8u8)
            .map(|t| {
                let known = KnownKeys::open(Arc::clone(&store), "pins").unwrap();
                std::thread::spawn(move || {
                    for i in 0..10u8 {
                        known
                            .check(&format!("u{t}x{i}"), &[t * 10 + i; 32])
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let known = KnownKeys::open(store, "pins").unwrap();
        assert_eq!(known.entries().len(), 80);
    }

    #[test]
    fn a_name_that_could_forge_a_pin_line_is_refused() {
        let file =
            std::env::temp_dir().join(format!("raft5fs-known-inject-{}", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let known = KnownKeys::load(file.clone()).unwrap();
        let forged = format!("x\nbob {}\ny", to_hex(&[7; 32]));
        assert_eq!(
            known.check(&forged, &[1; 32]).unwrap_err().errno,
            errno::EINVAL
        );
        assert!(known.forget(&forged).is_err());
        known.check("bob", &[2; 32]).unwrap();
        assert_eq!(
            KnownKeys::load(file.clone()).unwrap().pinned("bob"),
            Some([2; 32])
        );
        // Only the owner can read the file.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        known.forget("bob").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_pin_file_that_isnt_one_this_wrote_is_refused() {
        let file = std::env::temp_dir().join(format!("raft5fs-known-bad-{}", std::process::id()));
        let line = |user: &str, byte: u8| format!("{user} {}\n", to_hex(&[byte; 32]));
        for text in [
            // Two keys for one user: the code cannot know which key is
            // correct.
            format!("{}{}", line("bob", 1), line("bob", 2)),
            format!("{}junk\n", line("bob", 1)),
            line("Bob", 1),
            format!("bob {} extra\n", to_hex(&[1; 32])),
            "bob 1234\n".to_string(),
        ] {
            std::fs::write(&file, &text).unwrap();
            assert!(KnownKeys::load(file.clone()).is_err(), "{text:?}");
        }
        // The same key twice, and blank lines, are accepted.
        std::fs::write(&file, format!("{}\n{}", line("bob", 1), line("bob", 1))).unwrap();
        assert_eq!(
            KnownKeys::load(file.clone()).unwrap().pinned("bob"),
            Some([1; 32])
        );
        let _ = std::fs::remove_file(&file);
    }
}
