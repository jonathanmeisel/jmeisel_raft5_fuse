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
        let changes = merge::local_changes(base.as_ref(), &local, now);
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
            let invites = merge::merge_invites(&stored.invites, invites);
            let enrollments = self.enrollments_of(&invites).await;
            // Every user the merge can keep, for the links among them.
            let users = stored
                .entries
                .iter()
                .map(|e| &e.user)
                .chain(base.iter().flat_map(|b| b.keys()))
                .chain(local.keys())
                .chain(explicit.iter().map(|e| &e.user));
            let dead: HashSet<String> = self.dead_link_pins(users).await?.into_iter().collect();
            let merged = merge::merge(
                merge::Inputs {
                    me: &me,
                    now,
                    stored: &stored,
                    stored_empty: sealed.is_empty(),
                    floor,
                    local: &local,
                    base: base.as_ref(),
                    explicit,
                    invites,
                    labels_signed,
                    enrollments: &enrollments,
                    inbox: &inbox,
                    identity: &self.identity,
                    dead: &dead,
                },
                &changes,
            );
            if let Some(counter) = merged.store_as {
                let list = PinList {
                    counter,
                    labels_signed: merged.labels_signed,
                    entries: merged.entries.values().cloned().collect(),
                    invites: merged.invites.clone(),
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
            for entry in merged.entries.values() {
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
                floor: merged.store_as.unwrap_or(stored.counter),
                labels_signed: merged.labels_signed,
                base: Some(self.known.all()),
            })
            .map_err(io)?;
            // Grants from users trusted now open as trusted.
            if changed_here {
                self.forget_all();
            }
            self.after_merge(&me, &merged.before, &merged.entries, merged.found)
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
