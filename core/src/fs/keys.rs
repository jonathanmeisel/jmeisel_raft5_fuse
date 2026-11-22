//! Keys and grants: key paths, grants and labels, volumes, rotations,
//! re-sealing, and prunes of old key versions.

use super::*;

impl FsCore {
    /// `caller`'s grant above `ino`, and the key records down to it (see
    /// `grants::key_path`), at snapshot `at` if one is given.
    pub async fn key_path(
        &self,
        caller: &Caller,
        ino: u64,
        at: Option<&[u8]>,
    ) -> Result<KeyPath, FsError> {
        let view = self.view(at).await?;
        grants::key_path(&view, &self.paths, &caller.user, ino).await
    }

    /// Every grant made to `caller`, as of snapshot `at` if one is given.
    pub async fn grants(&self, caller: &Caller, at: Option<&[u8]>) -> Result<Vec<Grant>, FsError> {
        let view = self.view(at).await?;
        grants::list(&view, &caller.user).await
    }

    /// `grants`, and which of them are of a folder inside another of
    /// `caller`'s grants (see `grants::covered`).
    pub async fn grants_and_covered(
        &self,
        caller: &Caller,
        at: Option<&[u8]>,
    ) -> Result<(Vec<Grant>, Vec<u64>), FsError> {
        let view = self.view(at).await?;
        let list = grants::list(&view, &caller.user).await?;
        let covered = grants::covered(&view, &self.paths, &caller.user, &list).await?;
        Ok((list, covered))
    }

    /// `user`'s public key, for sealing grants to them. Returns `ENOENT`
    /// for an account that has not enrolled.
    ///
    /// A public link needs only the key of who sealed its grant, to open it.
    /// Its holders are strangers, so for any other name they get one refusal,
    /// which doesn't say whether the account exists.
    pub async fn public_key(&self, caller: &Caller, user: &str) -> Result<Vec<u8>, FsError> {
        if caller.user.starts_with(raft5fs_proto::types::LINK_PREFIX)
            && !self.sealed_a_grant_to(caller, user).await?
        {
            return Err(FsError::new(
                errno::EACCES,
                "a public link can only ask for the key of who shared its folder",
            ));
        }
        crate::accounts::get(&self.client, user)
            .await?
            .map(|keys| keys.public_key)
            .ok_or_else(|| FsError::new(errno::ENOENT, format!("{user} hasn't enrolled")))
    }

    /// Whether `sender` sealed one of `caller`'s grants, now or in a snapshot,
    /// which keeps the grants as they were then.
    pub(super) async fn sealed_a_grant_to(
        &self,
        caller: &Caller,
        sender: &str,
    ) -> Result<bool, FsError> {
        if grants::has_sender(&self.live(), &caller.user, sender).await? {
            return Ok(true);
        }
        for snapshot in self.client.list_snapshots().await? {
            let view = View::at(&self.client, &snapshot.id);
            if grants::has_sender(&view, &caller.user, sender).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Grants directory `grant.ino` to `grantee`, and replaces any grant of
    /// it that they had.
    ///
    /// - `caller` needs a writable grant above it, and the grant must hold
    ///   its current key version.
    /// - `sealed_grantees` is the node's grantee list with this grant
    ///   added, sealed under its current key version. It replaces the
    ///   stored list if that list is still at `expected_grantees_seq`, the
    ///   seq of the list it was made from. If not, returns `EAGAIN`,
    ///   because a grant made in the meantime would be lost from it. If
    ///   nobody else has a grant of the node, the seq doesn't count.
    /// - `listed` names the users on that list. If the node is granted to
    ///   anyone else, also `EAGAIN`: the client read the grants before one
    ///   that its starting list already had, so its list leaves it out, and
    ///   the seq check can't tell. Empty (an older client) skips this.
    pub async fn grant(
        &self,
        caller: &Caller,
        grantee: &str,
        grant: &Grant,
        sealed_grantees: &[u8],
        expected_grantees_seq: u64,
        listed: &[String],
    ) -> Result<(), FsError> {
        grants::check_username(grantee)?;
        check_sealed_grant(&grant.sealed_key, &grant.sealed_label, sealed_grantees)?;
        let ino = grant.ino;
        run_txn(&self.client, move |txn| async move {
            decide!(self.guard(&txn, caller, ino, true).await?);
            // A revoked user may still have a stale key.
            decide!(self.fresh(&txn, ino).await?);
            let entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::Directory));
            if txn
                .read_one(&crate::accounts::keys_key(grantee))
                .await?
                .value
                .is_none()
            {
                return Ok(Err(FsError::new(
                    errno::ENOENT,
                    format!("{grantee} hasn't enrolled"),
                )));
            }
            decide!(
                crate::accounts::check_link_grant(&txn, &caller.user, grantee, ino, grant.writable)
                    .await?
            );
            decide!(volumes::check_owner_kept(&txn, ino, grantee, Some(grant.writable)).await?);
            let (version, _) = decide!(key_versions(&txn, ino).await?);
            if grant.key_version != version {
                return Ok(Err(FsError::new(
                    errno::EKEYEXPIRED,
                    format!("a grant must hold the current key version, {version}"),
                )));
            }
            decide!(check_grantees_version(ino, sealed_grantees, version));
            // Read in the transaction even when its seq doesn't count: a
            // grant made meanwhile writes it, so this one retries.
            let stored_seq = txn.read_one(&grantees_key(ino)).await?.seq;
            let others: Vec<String> = grants::grants_of(&txn, ino)
                .await?
                .into_keys()
                .filter(|user| user != grantee)
                .collect();
            // With no other grant, the new list loses nobody. A stored list
            // can outlive its last grant (its account was removed), and the
            // client, which saw no grants, expects seq 0.
            if stored_seq != expected_grantees_seq && !others.is_empty() {
                return Ok(Err(FsError::new(
                    errno::EAGAIN,
                    format!("inode {ino}'s grantee list changed meanwhile"),
                )));
            }
            if !listed.is_empty() {
                for user in others {
                    if !listed.contains(&user) {
                        return Ok(Err(FsError::new(
                            errno::EAGAIN,
                            format!("{user}'s grant of inode {ino} isn't on the new grantee list"),
                        )));
                    }
                }
            }
            grants::put_grant(&txn, grantee, grant).await?;
            txn.write(&grantees_key(ino), Some(sealed_grantees)).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Replaces the label of `caller`'s own grant of `ino`, which only they
    /// read. Their key and their access stay as they are. A public link's label
    /// is its creator's, and the link only reads.
    pub async fn set_grant_label(
        &self,
        caller: &Caller,
        ino: u64,
        sealed_label: &[u8],
    ) -> Result<(), FsError> {
        crate::accounts::refuse_link(&caller.user)?;
        check_sealed_size("a grant's label", sealed_label, MAX_SEALED_GRANT)?;
        run_txn(&self.client, move |txn| async move {
            let Some(row) = txn
                .read_one(&grants::grant_key(ino, &caller.user))
                .await?
                .value
            else {
                return Ok(Err(FsError::errno(errno::ENOENT)));
            };
            let mut grant = decide!(grants::decode_grant(ino, &row));
            grant.sealed_label = sealed_label.to_vec();
            grants::put_grant(&txn, &caller.user, &grant).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Makes a new volume: a directory under the real root, at `new`'s
    /// reserved inode, granted read-write to `caller` with `sealed_key`
    /// (its key, version 1) and `sealed_label`. Its name is its inode
    /// number. The name people use is only in the grants, where the server
    /// cannot read it. Needs the `volumes` capability (`EACCES`).
    pub async fn create_volume(
        &self,
        caller: &Caller,
        new: &NewNode,
        perm: u16,
        sealed_key: &[u8],
        sealed_label: &[u8],
        sealed_grantees: &[u8],
    ) -> Result<Attr, FsError> {
        let user = caller.user.as_str();
        // Read outside the transaction: it changes rarely, and only by an
        // administrator.
        if !crate::accounts::info(&self.client, user)
            .await?
            .caps
            .contains(raft5fs_proto::types::Caps::VOLUMES)
        {
            return Err(FsError::new(
                errno::EACCES,
                "you can't create volumes on this filesystem",
            ));
        }
        check_grantees_version(new.ino, sealed_grantees, 1)?;
        check_sealed_grant(sealed_key, sealed_label, sealed_grantees)?;
        check_sealed_size("a key record", &new.keys, MAX_SEALED_RECORD)?;
        let dirent = &dirent_key(ROOT_INO, OsStr::new(&new.ino.to_string()));
        let grant = &Grant {
            ino: new.ino,
            writable: true,
            key_version: 1,
            sealed_key: sealed_key.to_vec(),
            sealed_label: sealed_label.to_vec(),
        };
        let made = run_txn(&self.client, move |txn| async move {
            let mut root = decide!(live_entry(&txn, ROOT_INO).await?);
            if txn.read_one(dirent).await?.value.is_some() {
                return Ok(Err(FsError::errno(errno::EEXIST)));
            }
            // No parent key: only grants give a volume's key to users.
            decide!(self.claim(&txn, caller, new, (1, 0)).await?);
            let now = SystemTime::now();
            let entry = Entry {
                attr: Attr {
                    ino: new.ino,
                    kind: Kind::Directory,
                    size: 0,
                    perm: perm & 0o7777,
                    nlink: 2,
                    atime: now,
                    mtime: now,
                    ctime: now,
                    layout: Layout::Inline,
                },
                parent: ROOT_INO,
            };
            write_entry(&txn, &entry).await?;
            txn.write(dirent, Some(&dirent_value(new.ino, &[]))).await?;
            grants::put_grant(&txn, user, grant).await?;
            let record = raft5fs_proto::types::VolumeInfo {
                owner: Some(user.to_string()),
                offer: None,
            };
            txn.write(
                &crate::layout::volume_key(new.ino),
                Some(&volumes::encode_volume(&record)),
            )
            .await?;
            txn.write(&grantees_key(new.ino), Some(sealed_grantees))
                .await?;
            touch_dir(&txn, &mut root, now).await?;
            txn.commit().await?;
            Ok(Ok(entry.attr))
        })
        .await?;
        self.release_if_failed(caller, new.ino, made).await
    }

    /// Every node at or below `top` that is granted to anyone (see
    /// `grants::grants_under`). Needs a writable grant above `top`, because
    /// a rotation of `top`'s key needs this.
    pub async fn grants_under(
        &self,
        caller: &Caller,
        top: u64,
    ) -> Result<Vec<GrantedNode>, FsError> {
        self.guard_now(&self.live(), caller, top, true).await?;
        grants::grants_under(&self.client, top).await
    }

    /// Gives each node in `rotations` (parents before children) a new key,
    /// in one transaction:
    ///
    /// - its record one version higher, wrapped under its parent's key as
    ///   it is now, or as this transaction leaves it;
    /// - every grant of it sealed again, or (sealed empty) removed.
    ///
    /// Returns `EAGAIN` if a node is no longer at its expected version, or
    /// its grants are not the grants that the rotation seals again: another
    /// client changed it in the meantime.
    pub async fn rotate(&self, caller: &Caller, rotations: &[Rotation]) -> Result<(), FsError> {
        for r in rotations {
            check_sealed_size("a key record", &r.node_keys, MAX_SEALED_RECORD)?;
            check_sealed_size("a grantee list", &r.sealed_grantees, MAX_SEALED_RECORD)?;
            for (_, sealed) in &r.grants {
                check_sealed_size("a grant's key", sealed, MAX_SEALED_GRANT)?;
            }
        }
        let changed = |what: String| Ok(Err(FsError::new(errno::EAGAIN, what)));
        run_txn(&self.client, move |txn| async move {
            // Versions that this transaction has changed, for the children
            // that are rotated after their parents.
            let mut rotated: HashMap<u64, u32> = HashMap::new();
            for r in rotations {
                let ino = r.ino;
                decide!(self.guard(&txn, caller, ino, true).await?);
                let [entry, record] =
                    exactly(txn.read_many(&[attr_key(ino), node_keys_key(ino)]).await?);
                let entry = decide!(live(ino, entry.value).ok_or_else(enoent));
                let (version, wrapped_under) = decide!(versions_of(ino, record.value));
                if version != r.expected_version {
                    return changed(format!("inode {ino} has key version {version} now"));
                }
                let Ok((new_version, new_wrapped_under)) = NodeKeys::versions(&r.node_keys) else {
                    return Ok(Err(FsError::new(errno::EINVAL, "an unreadable key record")));
                };
                let parent_version = if wrapped_under == 0 {
                    0
                } else if let Some(&v) = rotated.get(&entry.parent) {
                    v
                } else {
                    decide!(key_versions(&txn, entry.parent).await?).0
                };
                if new_version != version + 1 {
                    return Ok(Err(FsError::new(
                        errno::EINVAL,
                        format!("inode {ino}'s new key record must be version {}", version + 1),
                    )));
                }
                if new_wrapped_under != parent_version {
                    return changed(format!(
                        "inode {ino}'s new key must be wrapped under its parent's version {parent_version}"
                    ));
                }
                let existing = grants::grants_of(&txn, ino).await?;
                let resealed: HashMap<&str, &[u8]> = r
                    .grants
                    .iter()
                    .map(|(user, sealed)| (user.as_str(), sealed.as_slice()))
                    .collect();
                if resealed.len() != existing.len()
                    || !existing.keys().all(|user| resealed.contains_key(user.as_str()))
                {
                    return changed(format!("inode {ino}'s grants aren't the ones re-sealed"));
                }
                let mut kept = 0;
                for (user, mut grant) in existing {
                    let sealed = resealed[user.as_str()];
                    if sealed.is_empty() {
                        decide!(volumes::check_owner_kept(&txn, ino, &user, None).await?);
                        grants::remove_grant(&txn, &user, ino).await?;
                    } else {
                        grant.key_version = new_version;
                        grant.sealed_key = sealed.to_vec();
                        grants::put_grant(&txn, &user, &grant).await?;
                        kept += 1;
                    }
                }
                // The remaining grantees, listed again under the new key.
                if kept > 0 {
                    decide!(check_grantees_version(ino, &r.sealed_grantees, new_version));
                    txn.write(&grantees_key(ino), Some(&r.sealed_grantees))
                        .await?;
                } else {
                    txn.write(&grantees_key(ino), None).await?;
                }
                grants::put_node_keys(&txn, ino, Some(&r.node_keys)).await?;
                rotated.insert(ino, new_version);
            }
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Seals chunks of file `ino` again under its current key version. Each
    /// chunk must still be at its `expected_seq`, which is required. The
    /// file's size and times do not change. A prune needs this first. Needs
    /// a writable grant above `ino`, with fresh keys.
    pub async fn reseal_chunks(
        &self,
        caller: &Caller,
        ino: u64,
        writes: &[ChunkWrite],
    ) -> Result<(), FsError> {
        self.check_chunk_writes(writes)?;
        if writes.iter().any(|w| w.expected_seq.is_none()) {
            return Err(FsError::new(
                errno::EINVAL,
                "a re-sealed chunk must say the seq it was read at",
            ));
        }
        let dropped = run_txn(&self.client, move |txn| async move {
            decide!(self.guard(&txn, caller, ino, true).await?);
            decide!(self.fresh(&txn, ino).await?);
            // As in `write_chunks`, read the Entry first, so no chunk is
            // stored after a deletion has started.
            let entry = decide!(live_entry(&txn, ino).await?);
            decide!(check_kind(&entry, Kind::File));
            let size = entry.attr.size;
            let dropped = decide!(put_chunks(self, &txn, &entry, writes, true, size).await?);
            txn.commit().await?;
            Ok(Ok(dropped))
        })
        .await??;
        self.discard(dropped);
        Ok(())
    }

    /// Seals entry names in directory `dir` again under its current key
    /// version, each only if its tag still names the same inode. The
    /// directory's times do not change. Needs a writable grant above `dir`,
    /// with fresh keys.
    pub async fn reseal_names(
        &self,
        caller: &Caller,
        dir: u64,
        names: &[ResealedName],
    ) -> Result<(), FsError> {
        if names.len() > RESEAL_NAMES_BATCH {
            return Err(FsError::new(
                errno::EINVAL,
                "more names than one re-seal takes",
            ));
        }
        for n in names {
            Self::check_entry_name(&n.tag, &n.sealed_name)?;
        }
        run_txn(&self.client, move |txn| async move {
            decide!(self.guard(&txn, caller, dir, true).await?);
            decide!(self.fresh(&txn, dir).await?);
            decide!(modifiable_dir(&txn, dir).await?);
            let (version, _) = decide!(key_versions(&txn, dir).await?);
            for n in names {
                decide!(check_name_version(dir, &n.sealed_name, version));
                let dirent = dirent_key(dir, &n.tag);
                if named(&txn, &dirent).await? != Some(n.ino) {
                    return Ok(Err(FsError::new(
                        errno::EAGAIN,
                        format!("an entry of inode {dir} changed meanwhile"),
                    )));
                }
                txn.write(&dirent, Some(&dirent_value(n.ino, &n.sealed_name)))
                    .await?;
            }
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Replaces `ino`'s key record, at `expected_version`, with
    /// `node_keys`: the same record with only its oldest history entries
    /// removed. Returns `EBUSY` while anything is still sealed under a
    /// version that it removes. Needs a writable grant above `ino`.
    ///
    /// The search for data under an old version runs outside any
    /// transaction. The record is then replaced only if it is still the
    /// record that the search started from. That is enough: while the
    /// record stays the same, everything the server takes in for `ino`
    /// (chunks, entry names, children's keys, grants) is checked against
    /// the current version in the transaction that stores it, and the prune
    /// keeps that version. So nothing under a removed version can appear
    /// after the search.
    pub async fn prune_keys(
        &self,
        caller: &Caller,
        ino: u64,
        expected_version: u32,
        node_keys: &[u8],
    ) -> Result<(), FsError> {
        check_sealed_size("a key record", node_keys, MAX_SEALED_RECORD)?;
        self.guard_now(&self.live(), caller, ino, true).await?;
        let pruned = NodeKeys::decode(node_keys)
            .map_err(|e| FsError::new(errno::EINVAL, format!("inode {ino}: {e}")))?;
        let before_bytes = self
            .client
            .read_one(&node_keys_key(ino))
            .await?
            .value
            .ok_or_else(|| FsError::new(errno::EIO, format!("inode {ino} has no key record")))?;
        let before = NodeKeys::decode(&before_bytes)
            .map_err(|e| FsError::new(errno::EIO, format!("inode {ino}: {e}")))?;
        if before.version != expected_version {
            return Err(FsError::new(
                errno::EAGAIN,
                format!("inode {ino} has key version {} now", before.version),
            ));
        }
        if !pruned.is_pruning_of(&before) {
            return Err(FsError::new(
                errno::EINVAL,
                format!("inode {ino}'s new key record isn't its old one cut short"),
            ));
        }
        if pruned.base() == before.base() {
            return Ok(());
        }
        if let Some(what) = self.sealed_below(ino, pruned.base()).await? {
            return Err(FsError::new(
                errno::EBUSY,
                format!(
                    "{what} of inode {ino} is still sealed under a key version before {}",
                    pruned.base()
                ),
            ));
        }
        let before_bytes = &before_bytes;
        run_txn(&self.client, move |txn| async move {
            if txn.read_one(&node_keys_key(ino)).await?.value.as_ref() != Some(before_bytes) {
                return Ok(Err(FsError::new(
                    errno::EAGAIN,
                    format!("inode {ino}'s key record changed meanwhile"),
                )));
            }
            grants::put_node_keys(&txn, ino, Some(node_keys)).await?;
            txn.commit().await?;
            Ok(Ok(()))
        })
        .await?
    }

    /// Describes the first thing found that is sealed under a version of
    /// `ino`'s key before `base`: a chunk, an entry's name, a child's key,
    /// or a grant. Returns `None` if there is none.
    pub(super) async fn sealed_below(
        &self,
        ino: u64,
        base: u32,
    ) -> Result<Option<String>, FsError> {
        let below = |blob: &[u8]| sealed_version(blob).is_ok_and(|v| v < base);
        let kind = self.resolve(&self.live(), ino).await?.attr.kind;
        if kind == Kind::File {
            let prefix = chunk_prefix(ino);
            let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
            let mut window = Vec::new();
            loop {
                let key = next_key(&mut iter)
                    .await?
                    .filter(|key| key.starts_with(&prefix));
                if let Some(key) = &key
                    && is_chunk_key(key, &prefix)
                {
                    window.push(key.clone());
                }
                if window.len() < MAX_KEYS_PER_READ && key.is_some() {
                    continue;
                }
                // Check each answer as it arrives, not a whole window of
                // chunks at once.
                let mut checked = 0;
                while checked < window.len() {
                    let entries = self.client.read_some(&window[checked..]).await?;
                    checked += entries.len();
                    for entry in entries {
                        if entry.value.as_deref().is_some_and(below) {
                            let index =
                                u64::from_be_bytes(entry.key[prefix.len()..].try_into().unwrap());
                            return Ok(Some(format!("chunk {index}")));
                        }
                    }
                }
                window.clear();
                if key.is_none() {
                    break;
                }
            }
        } else {
            let prefix = dirent_prefix(ino);
            let mut keys = Vec::new();
            let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
            while let Some(key) = next_key(&mut iter).await? {
                if !key.starts_with(&prefix) {
                    break;
                }
                keys.push(key);
            }
            let dirents: Vec<Vec<u8>> = self
                .client
                .get_many(&keys)
                .await?
                .into_iter()
                .flatten()
                .collect();
            let records: Vec<Vec<u8>> = dirents
                .iter()
                .map(|value| node_keys_key(dirent_ino(value)))
                .collect();
            let records = self.client.get_many(&records).await?;
            for (value, record) in dirents.iter().zip(records) {
                let child = dirent_ino(value);
                if below(dirent_sealed_name(value)) {
                    return Ok(Some(format!("the name of entry {child}")));
                }
                if let Ok((_, parent_version)) = versions_of(child, record)
                    && parent_version != 0
                    && parent_version < base
                {
                    return Ok(Some(format!("the key of child {child}")));
                }
            }
        }
        if let Some(sealed) = self.client.read_one(&grantees_key(ino)).await?.value
            && below(&sealed)
        {
            return Ok(Some("the grantee list".to_string()));
        }
        let prefix = grants::grant_prefix(ino);
        let mut keys = Vec::new();
        let mut iter = self.client.key_iterator(&prefix, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(&prefix) {
                break;
            }
            keys.push(key);
        }
        for (key, bytes) in keys.iter().zip(self.client.get_many(&keys).await?) {
            if let Some(bytes) = bytes
                && grants::decode_grant(ino, &bytes)?.key_version < base
            {
                let user = String::from_utf8_lossy(&key[prefix.len()..]).into_owned();
                return Ok(Some(format!("{user}'s grant")));
            }
        }
        Ok(None)
    }

    /// Removes volume `ino`, which must be empty, and every grant of it.
    /// Needs a writable grant of the volume itself.
    pub async fn delete_volume(&self, caller: &Caller, ino: u64) -> Result<(), FsError> {
        self.guard_now(&self.live(), caller, ino, true).await?;
        if self.resolve(&self.live(), ino).await?.parent != ROOT_INO {
            return Err(FsError::new(
                errno::EINVAL,
                format!("inode {ino} isn't a volume"),
            ));
        }
        let name = ino.to_string();
        self.remove_child(
            caller,
            ROOT_INO,
            OsStr::new(&name),
            ino,
            Kind::Directory,
            ino,
        )
        .await
    }
}
