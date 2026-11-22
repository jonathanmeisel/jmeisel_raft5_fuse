//! Merging this device's pinned keys with the account's sealed copy on the servers.

use super::*;

impl Vault {
    /// Merges this device's trusted keys with the account's copy on the
    /// servers, so that all its devices trust the same keys:
    ///
    /// - What changed here since the last merge (a key trusted, replaced or
    ///   forgotten) goes to the servers, unless another device changed the
    ///   same user later. The last merge is kept beside the pins, so this
    ///   holds after a restart too.
    /// - On this device's first merge, keys trusted only here go to the
    ///   servers too. Where the two differ, the servers' copy wins: it is
    ///   the latest that one of the account's devices checked.
    /// - Then this device trusts what the merged list says.
    /// - Returns `EIO` and changes nothing if the servers' copy is older
    ///   than one this device has seen (`rollback`).
    ///
    /// The servers can't read or change the list (raft5fs-crypto's
    /// `pins`). Does nothing on servers older than protocol 3.
    pub async fn sync_pins(&self) -> Result<(), FsError> {
        self.merge_pins(false, &[], &[]).await
    }

    /// `sync_pins`, and with `labels_signed`, records that this account has
    /// signed its old labels.
    ///
    /// `explicit` and `invites` are changes made here that say more than a
    /// key: how a key was checked, an introducer mark, an invitation. They
    /// win over older entries for the same user, as key changes do. On
    /// protocol 11, the merge also checks open invitations and takes in
    /// introductions (see `trust`).
    pub(super) async fn merge_pins(
        &self,
        labels_signed: bool,
        explicit: &[PinEntry],
        invites: &[PendingInvite],
    ) -> Result<(), FsError> {
        if self.remote.protocol() < since::PINS {
            return Ok(());
        }
        let me = self.remote.username().to_string();
        let local = self.known.all();
        let rollback::PinMemory { floor, base, .. } = self.load_pin_memory();
        let now = raft5fs_proto::clock::now_secs();
        let changes: Vec<PinEntry> = match &base {
            None => Vec::new(),
            Some(base) => base
                .keys()
                .chain(local.keys())
                .collect::<HashSet<_>>()
                .into_iter()
                .filter(|user| base.get(*user) != local.get(*user))
                .map(|user| PinEntry {
                    user: user.clone(),
                    key: local.get(user).copied(),
                    at: now,
                    source: PinSource::Checked,
                    introducer: false,
                })
                .collect(),
        };
        let inbox = self.introduction_inbox().await;
        for _ in 0..CHANGE_RETRIES {
            let (version, sealed) = self.remote.get_pins().await?;
            let stored = if sealed.is_empty() {
                PinList::default()
            } else {
                open_pins(&self.identity, &me, &sealed)
                    .map_err(|e| FsError::new(errno::EIO, format!("the servers' copy: {e}")))?
            };
            self.check_pin_counter(stored.counter, floor)?;
            let before: BTreeMap<String, PinEntry> = stored
                .entries
                .into_iter()
                .map(|e| (e.user.clone(), e))
                .collect();
            let mut merged = before.clone();
            for change in &changes {
                match merged.get(&change.user) {
                    // Already the same key: keep how it was checked.
                    Some(e) if e.key == change.key => {}
                    Some(e) if e.at > change.at => {}
                    old => {
                        let mut change = change.clone();
                        // The same person: their marks stay with a new key.
                        change.introducer = old.is_some_and(|e| e.introducer);
                        merged.insert(change.user.clone(), change);
                    }
                }
            }
            for change in explicit {
                if merged.get(&change.user).is_none_or(|e| e.at <= change.at) {
                    merged.insert(change.user.clone(), change.clone());
                }
            }
            if base.is_none() {
                for (user, key) in &local {
                    merged.entry(user.clone()).or_insert_with(|| PinEntry {
                        user: user.clone(),
                        key: Some(*key),
                        at: now,
                        source: PinSource::Checked,
                        introducer: false,
                    });
                }
            }
            let mut open_invites = trust::merge_invites(&stored.invites, invites);
            let mut found = trust::Found::default();
            self.check_invites(&me, now, &mut merged, &mut open_invites, &mut found)
                .await;
            self.take_introductions(&me, now, &inbox, &mut merged, &mut found);
            // This account pins each public link it makes, to share with it.
            // Once a link is gone, so is its pin, everywhere. Link names are
            // random and never reused, so no marker is needed: a device that
            // still has the pin sends it back, and its next merge drops it.
            // Here too: another device may have dropped it from the copy.
            let dead = self
                .dead_link_pins(merged.keys().chain(local.keys()))
                .await?;
            for user in &dead {
                merged.remove(user);
            }
            // A list from before counters has nothing to protect it until
            // it has one.
            let uncounted = stored.counter == 0 && !sealed.is_empty();
            let signed = stored.labels_signed || labels_signed;
            let mut counter = stored.counter;
            if merged != before
                || open_invites != stored.invites
                || uncounted
                || signed != stored.labels_signed
            {
                counter = stored.counter.max(floor) + 1;
                let list = PinList {
                    counter,
                    labels_signed: signed,
                    entries: merged.values().cloned().collect(),
                    invites: open_invites.clone(),
                };
                match self
                    .remote
                    .put_pins(version, seal_pins(&self.identity, &me, &list))
                    .await
                {
                    // Another device changed them: merge with theirs.
                    Err(e) if changed(&e) => continue,
                    other => other?,
                };
            }
            let io = |e: std::io::Error| FsError::new(errno::EIO, format!("trusted keys: {e}"));
            let mut changed_here = false;
            for user in dead.iter().filter(|user| local.contains_key(*user)) {
                self.known.forget(user).map_err(io)?;
            }
            for entry in merged.values() {
                match &entry.key {
                    Some(key) if local.get(&entry.user) != Some(key) => {
                        self.known.set(&entry.user, key).map_err(io)?;
                        changed_here = true;
                    }
                    None if local.contains_key(&entry.user) => {
                        self.known.forget(&entry.user).map_err(io)?;
                        changed_here = true;
                    }
                    _ => {}
                }
            }
            self.save_pin_memory(&rollback::PinMemory {
                floor: counter,
                labels_signed: signed,
                base: Some(self.known.all()),
            })
            .map_err(io)?;
            // Grants from users trusted now open as trusted.
            if changed_here {
                self.forget_all();
            }
            self.after_merge(&me, &before, &merged, open_invites, found)
                .await;
            return Ok(());
        }
        Err(FsError::new(
            errno::EAGAIN,
            "the trusted keys kept changing on the servers",
        ))
    }

    /// The users among `pinned` that are public links which no longer
    /// exist. Asks the servers only if there are any links among them.
    pub(super) async fn dead_link_pins<'a>(
        &self,
        pinned: impl Iterator<Item = &'a String>,
    ) -> Result<Vec<String>, FsError> {
        let links: HashSet<&String> = pinned.filter(|u| u.starts_with(LINK_PREFIX)).collect();
        if links.is_empty() {
            return Ok(Vec::new());
        }
        let alive: HashSet<String> = self
            .remote
            .list_links()
            .await?
            .into_iter()
            .map(|link| link.user)
            .collect();
        Ok(links
            .into_iter()
            .filter(|user| !alive.contains(*user))
            .cloned()
            .collect())
    }

    /// `sync_pins` after a change here. A failure is no loss: the change
    /// stays here, and the next merge sends it.
    pub(super) async fn share_pins(&self) {
        if let Err(e) = self.sync_pins().await {
            eprintln!("trusted keys not merged with the servers' copy yet: {e}");
        }
    }

    /// Forgets `user`'s pinned key, here and on the account's other
    /// devices.
    pub async fn forget_key(&self, user: &str) -> Result<(), FsError> {
        self.known
            .forget(user)
            .map_err(|e| FsError::new(errno::EIO, format!("cannot forget {user}'s key: {e}")))?;
        self.share_pins().await;
        Ok(())
    }
}
