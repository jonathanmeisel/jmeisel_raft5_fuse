//! Entries: looking up, listing, making, renaming and removing them, and the
//! inode numbers reserved for new ones.

use super::*;

impl FsCore {
    /// Needs a grant above `ino`, at snapshot `at` if one is given.
    pub async fn getattr(
        &self,
        caller: &Caller,
        ino: u64,
        at: Option<&[u8]>,
    ) -> Result<Attr, FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, false).await?;
        Ok(self.resolve(&view, ino).await?.attr)
    }

    /// The inode that `name` names in `parent`, without reading its
    /// attributes.
    pub(super) async fn child_ino(
        &self,
        view: &View<'_>,
        parent: u64,
        name: &OsStr,
    ) -> Result<u64, FsError> {
        self.lookup_child(view, parent, name)
            .await?
            .ok_or_else(enoent)
    }

    /// The entry `name` (a tag) in `parent`: its attributes, and its sealed
    /// name as the listing has it, so the client can check that the name
    /// points to that inode.
    pub async fn lookup(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        at: Option<&[u8]>,
    ) -> Result<(Attr, Vec<u8>), FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, parent, false).await?;
        let [dir, dirent] = exactly(
            view.read_many(&[attr_key(parent), dirent_key(parent, name)])
                .await?,
        );
        let dir = live(parent, dir.value).ok_or_else(enoent)?;
        if dir.attr.kind != Kind::Directory {
            return Err(FsError::errno(errno::ENOTDIR));
        }
        let Some(bytes) = dirent.value else {
            return Err(enoent());
        };
        let attr = self.resolve(&view, dirent_ino(&bytes)).await?.attr;
        Ok((attr, dirent_sealed_name(&bytes).to_vec()))
    }

    /// access(2), and the check for an open: whether `caller` has every
    /// right in `mask` (access(2)'s bits). With a `mask` of 0, only whether
    /// `ino` exists.
    ///
    /// - Any grant above `ino` allows read and search. A writable grant
    ///   allows write.
    /// - Writing a directory's contents is different from writing the
    ///   directory. `EISDIR` refuses the second only when `open` asks.
    /// - Nothing at a snapshot is writable (`EROFS`).
    pub async fn access(
        &self,
        caller: &Caller,
        ino: u64,
        mask: u32,
        at: Option<&[u8]>,
    ) -> Result<(), FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, mask & W != 0).await?;
        self.resolve(&view, ino).await.map(drop)
    }

    pub async fn readdir(
        &self,
        caller: &Caller,
        ino: u64,
        at: Option<&[u8]>,
    ) -> Result<Vec<DirItem>, FsError> {
        let view = self.view(at).await?;
        self.guard_now(&view, caller, ino, false).await?;
        let entry = self.resolve(&view, ino).await?;
        if entry.attr.kind != Kind::Directory {
            return Err(FsError::errno(errno::ENOTDIR));
        }

        let mut items = vec![
            DirItem {
                ino,
                kind: Kind::Directory,
                name: OsString::from("."),
                sealed_name: Vec::new(),
            },
            DirItem {
                ino: entry.parent,
                kind: Kind::Directory,
                name: OsString::from(".."),
                sealed_name: Vec::new(),
            },
        ];

        let prefix = dirent_prefix(ino);
        let mut keys = Vec::new();
        let mut iter = view.key_iterator(&prefix);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(&prefix) {
                break;
            }
            keys.push(key);
        }
        // An unlink or rmdir between the scan and this read is the only
        // cause of an empty value. Skip it.
        let dirents: Vec<(Vec<u8>, Vec<u8>)> = view
            .read_many(&keys)
            .await?
            .into_iter()
            .filter_map(|entry| Some((entry.key, entry.value?)))
            .collect();
        let children: Vec<u64> = dirents.iter().map(|(_, bytes)| dirent_ino(bytes)).collect();
        let attr_keys: Vec<Vec<u8>> = children.iter().map(|&child| attr_key(child)).collect();
        let entries = view.read_many(&attr_keys).await?;
        for (((key, bytes), child_ino), entry) in dirents.iter().zip(children).zip(entries) {
            let kind = live(child_ino, entry.value)
                .map(|e| e.attr.kind)
                .unwrap_or(Kind::File);
            items.push(DirItem {
                ino: child_ino,
                kind,
                name: OsStr::from_bytes(&key[prefix.len()..]).to_os_string(),
                sealed_name: dirent_sealed_name(bytes).to_vec(),
            });
        }
        Ok(items)
    }

    /// Applies `changes` (mode, size, and times; there are no owners) if
    /// `caller` has a writable grant above `ino`, including the data work
    /// that a size change needs. The client has already sealed again, cut
    /// short, the chunk that a new smaller size falls inside (see
    /// `write_chunks`), because the server cannot open it to cut it.
    pub async fn setattr(
        &self,
        caller: &Caller,
        ino: u64,
        changes: SetAttr,
    ) -> Result<Attr, FsError> {
        // Delete whole chunks past the new end first, before anything
        // records the smaller size. A crash here loses tail bytes that the
        // caller asked to remove. The other order would leave chunks past
        // EOF, which a later grow would bring back in place of zeros.
        if let Some(new_size) = changes.size {
            // Deleting chunks cannot be undone, and happens outside the
            // transaction below. So check the caller's right to truncate
            // before it, as well as in it.
            self.guard_now(&self.live(), caller, ino, true).await?;
            let layout = self.resolve(&self.live(), ino).await?.attr.layout;
            let first = new_size.div_ceil(self.chunk_size);
            // These chunks are gone, whatever the transaction below does.
            self.discard(self.delete_chunks_from(ino, first, layout).await?);
        }

        let (attr, change, parent) = run_txn(&self.client, move |txn| async move {
            let Some(bytes) = txn.read_one(&attr_key(ino)).await?.value else {
                return Err(enoent().into());
            };
            let mut entry = decode_entry(ino, &bytes);
            let before = entry.attr.size as i64;
            // A truncate rewrites the boundary chunk. It must not do that
            // to an inode whose deletion could already have removed it.
            if entry.is_deleted() {
                return Err(enoent().into());
            }
            self.guard(&txn, caller, ino, true).await?;
            if let Some(mode) = changes.mode {
                entry.attr.perm = (mode & 0o7777) as u16;
            }
            if let Some(new_size) = changes.size {
                if let Err(e) = self
                    .check_room(entry.parent, new_size.saturating_sub(entry.attr.size))
                    .await
                {
                    return Err(e.into());
                }
                if new_size < entry.attr.size {
                    self.check_cut_short(&txn, ino, new_size).await?;
                }
                entry.attr.size = new_size;
                self.trim_block(&txn, &entry, new_size).await?;
            }
            if let Some(atime) = changes.atime {
                entry.attr.atime = atime.resolve();
            }
            if let Some(mtime) = changes.mtime {
                entry.attr.mtime = mtime.resolve();
            }
            entry.attr.ctime = SystemTime::now();

            txn.write(&attr_key(ino), Some(&encode_entry(&entry)))
                .await?;
            txn.commit().await?;
            let change = entry.attr.size as i64 - before;
            Ok((entry.attr, change, entry.parent))
        })
        .await?;
        if attr.kind == Kind::File {
            self.count(parent, change).await;
            if changes.size.is_some() {
                self.note_edit(caller, ino, parent).await;
            }
        }
        Ok(attr)
    }

    /// `name` is the new entry's tag, and `new` is the rest of what a
    /// create sends (see `NewNode`).
    pub async fn mkdir(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        self.create_child(caller, parent, name, Kind::Directory, perm, new)
            .await
    }

    /// Same as `mkdir`.
    pub async fn create(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        self.create_child(caller, parent, name, Kind::File, perm, new)
            .await
    }

    /// The inode number that `caller`'s next create uses, kept for them
    /// until then. A node's key record is bound to its inode, so the client
    /// needs the number before it can make the record.
    pub async fn reserve_inode(&self, caller: &Caller) -> Result<u64, FsError> {
        let user = caller.user.as_str();
        crate::accounts::refuse_link(user)?;
        let ino = allocate_inode(&self.client).await?;
        let key = reservation_key(ino);
        let value = grants::reservation_value(user, clock::now_secs());
        let write = self.client.write(&key, Some(&value));
        timing::other("write", write).await?;
        Ok(ino)
    }

    /// Claims `name` in `parent` for `new`'s reserved inode, and writes the
    /// Entry, its key record, and the directory entry in one transaction.
    ///
    /// - Reading the name in that transaction makes the existence check
    ///   correct: two creates of one name at the same time cannot both find
    ///   it absent.
    /// - Reading the parent there too means that the grant check sees the
    ///   directory as it is at commit, and that a directory whose removal
    ///   has started takes no new entries.
    pub(super) async fn create_child(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        kind: Kind,
        perm: u16,
        new: &NewNode,
    ) -> Result<Attr, FsError> {
        let ino = new.ino;
        Self::check_entry_name(name, &new.sealed_name)?;
        check_sealed_size("a key record", &new.keys, MAX_SEALED_RECORD)?;
        let dirent = &dirent_key(parent, name);
        let value = &dirent_value(ino, &new.sealed_name);

        let made = run_txn(&self.client, move |txn| async move {
            self.guard(&txn, caller, parent, true).await?;
            // The new node's key and name are sealed under the parent's
            // key.
            self.fresh(&txn, parent).await?;
            let [dir, taken, record] = exactly(
                txn.read_many(&[attr_key(parent), dirent.to_vec(), node_keys_key(parent)])
                    .await?,
            );
            let mut dir = dir_entry(parent, dir.value)?;
            if taken.value.is_some() {
                return Err(FsError::errno(errno::EEXIST).into());
            }
            let (parent_version, _) = versions_of(parent, record.value)?;
            check_name_version(parent, &new.sealed_name, parent_version)?;
            self.claim(&txn, caller, new, (1, parent_version)).await?;
            let now = SystemTime::now();
            let entry = Entry {
                attr: Attr {
                    ino,
                    kind,
                    size: 0,
                    perm: perm & 0o7777,
                    nlink: if kind == Kind::Directory { 2 } else { 1 },
                    atime: now,
                    mtime: now,
                    ctime: now,
                    // A file made through a server with object storage can
                    // grow into it. A file made without it never will.
                    layout: if kind == Kind::File && self.objects.is_some() {
                        Layout::Hybrid
                    } else {
                        Layout::Inline
                    },
                },
                // Files too: the walk up to a grant goes through the
                // parent, and a file's only parent is the one directory
                // that names it.
                parent,
            };
            write_entry(&txn, &entry).await?;
            txn.write(dirent, Some(value)).await?;
            touch_dir(&txn, &mut dir, now).await?;
            txn.commit().await?;
            Ok(entry.attr)
        })
        .await;
        let made = self.release_if_failed(caller, new.ino, made).await;
        if made.is_ok() {
            let name = SealedEntryName {
                parent,
                tag: name.as_bytes().to_vec(),
                sealed: new.sealed_name.clone(),
            };
            self.note(
                caller,
                activity::change(ActivityOp::Created, kind, new.ino, parent, Some(name)),
            )
            .await;
        }
        made
    }

    /// Passes `made` through. When a create failed for good (the name is
    /// taken, the caller may not, ...), it stored nothing, and the inode's
    /// reservation goes too: nothing else would ever use or remove it. A
    /// failure that asks for a retry (`EKEYEXPIRED`, `EAGAIN`) keeps it, for
    /// the retry; if none comes, `sweep_reservations` removes it later. (A
    /// create whose outcome is unknown never gets here: see the callers.)
    pub(super) async fn release_if_failed<T>(
        &self,
        caller: &Caller,
        ino: u64,
        made: Result<T, FsError>,
    ) -> Result<T, FsError> {
        let retry = |e: &FsError| e.errno == errno::EKEYEXPIRED || e.errno == errno::EAGAIN;
        if made.as_ref().is_err_and(|e| !retry(e)) {
            let user = caller.user.as_bytes();
            let key = &reservation_key(ino);
            let released = run_txn(&self.client, move |txn| async move {
                let held = txn.read_one(key).await?.value;
                if held.as_deref().map(|v| grants::reservation_parts(v).0) == Some(user) {
                    txn.write(key, None).await?;
                    txn.commit().await?;
                }
                Ok(())
            })
            .await;
            if let Err(e) = released {
                eprintln!("could not release inode {ino}'s reservation: {e}");
            }
        }
        made
    }

    /// Removes reservations older than `age`: from clients that reserved an
    /// inode and never created it (they crashed, or lost the connection).
    /// Reservations from before they had a time count as old. Returns how
    /// many it removed.
    pub async fn sweep_reservations(&self, age: Duration) -> Result<usize, FsError> {
        let cutoff = clock::now_secs().saturating_sub(age.as_secs());
        let mut keys = Vec::new();
        let mut iter = self
            .client
            .key_iterator(crate::layout::RESERVATION_PREFIX, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(crate::layout::RESERVATION_PREFIX) {
                break;
            }
            keys.push(key);
        }
        let mut removed = 0;
        for (key, value) in keys.iter().zip(self.client.get_many(&keys).await?) {
            let Some(value) = value else { continue };
            if grants::reservation_parts(&value)
                .1
                .is_some_and(|at| at > cutoff)
            {
                continue;
            }
            // Only if it is still the same reservation.
            let value = &value;
            let gone = run_txn(&self.client, move |txn| async move {
                if txn.read_one(key).await?.value.as_ref() != Some(value) {
                    return Ok(false);
                }
                txn.write(key, None).await?;
                txn.commit().await?;
                Ok(true)
            })
            .await?;
            removed += usize::from(gone);
        }
        Ok(removed)
    }

    /// Uses `new`'s reserved inode for `caller` and stores its key record,
    /// which must have `versions`: version 1, under the parent's current
    /// key. Runs in the creating transaction.
    pub(super) async fn claim(
        &self,
        txn: &Transaction,
        caller: &Caller,
        new: &NewNode,
        versions: (u32, u32),
    ) -> Result<(), TxnError> {
        let user = caller.user.as_str();
        let [reserved, existing] = exactly(
            txn.read_many(&[reservation_key(new.ino), attr_key(new.ino)])
                .await?,
        );
        if reserved
            .value
            .as_deref()
            .map(|v| grants::reservation_parts(v).0)
            != Some(user.as_bytes())
        {
            return Err(FsError::new(
                errno::EACCES,
                format!("inode {} isn't reserved for {user}", new.ino),
            )
            .into());
        }
        if existing.value.is_some() {
            return Err(FsError::errno(errno::EEXIST).into());
        }
        match NodeKeys::versions(&new.keys) {
            Ok(found) if found == versions => {}
            // Most likely a client with an old version of the parent's key.
            // Fetching the key again fixes that.
            _ => {
                return Err(FsError::new(
                    errno::EKEYEXPIRED,
                    format!(
                        "a new node's key record must be version {} under parent version {}",
                        versions.0, versions.1
                    ),
                )
                .into());
            }
        }
        txn.write(&reservation_key(new.ino), None).await?;
        grants::put_node_keys(txn, new.ino, Some(&new.keys)).await?;
        Ok(())
    }

    /// Removes a file and returns its inode.
    pub async fn unlink(&self, caller: &Caller, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let child = self.child_ino(&self.live(), parent, name).await?;
        self.remove_child(caller, parent, name, child, Kind::File, parent)
            .await?;
        Ok(child)
    }

    /// Removes an empty directory and returns its inode.
    pub async fn rmdir(&self, caller: &Caller, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let child = self.child_ino(&self.live(), parent, name).await?;
        self.remove_child(caller, parent, name, child, Kind::Directory, parent)
            .await?;
        Ok(child)
    }

    /// Unlinks `name` from `parent` and removes the inode it named, if
    /// `caller` is allowed. The inode must be of `kind`, and a directory
    /// must be empty.
    ///
    /// It takes several steps, because an inode's chunks might not fit in
    /// one transaction:
    ///
    /// - One transaction checks the caller's rights on `guarded`, removes
    ///   the dirent, marks the Entry deleted, and records a tombstone. It
    ///   reads the dirent again, so it removes `ino` only if the name still
    ///   means `ino`. After this, no write from any process can add a chunk
    ///   (see `write_chunks`), and no create can add an entry to a removed
    ///   directory.
    /// - `finish_removal` then deletes the chunks, the Entry, and the
    ///   tombstone.
    /// - If a crash happens between the two, the tombstone stays, and
    ///   `reap_tombstones` finishes the work.
    ///
    /// The caller needs a writable grant above `guarded`: the parent, or
    /// for a volume the volume itself, because its parent (the real root)
    /// belongs to no one.
    pub(super) async fn remove_child(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        ino: u64,
        kind: Kind,
        guarded: u64,
    ) -> Result<(), FsError> {
        let dirent = &dirent_key(parent, name);
        let sealed = run_txn(&self.client, move |txn| async move {
            self.guard(&txn, caller, guarded, true).await?;
            let mut dir = modifiable_dir(&txn, parent).await?;
            let Some(value) = txn.read_one(dirent).await?.value else {
                return Err(enoent().into());
            };
            if dirent_ino(&value) != ino {
                return Err(enoent().into());
            }
            let mut entry = live_entry(&txn, ino).await?;
            check_kind(&entry, kind)?;
            let now = SystemTime::now();
            entry.mark_deleted();
            entry.attr.ctime = now;
            // Write this before the emptiness check, which needs it. If the
            // check fails, dropping the transaction undoes it.
            write_entry(&txn, &entry).await?;
            if kind == Kind::Directory && !is_empty_dir(&txn, ino).await? {
                return Err(FsError::errno(errno::ENOTEMPTY).into());
            }
            txn.write(dirent, None).await?;
            txn.write(&tombstone_key(ino), Some(&[1])).await?;
            touch_dir(&txn, &mut dir, now).await?;
            txn.commit().await?;
            Ok(dirent_sealed_name(&value).to_vec())
        })
        .await?;
        let gone = SealedEntryName {
            parent,
            tag: name.as_bytes().to_vec(),
            sealed,
        };
        self.note(
            caller,
            activity::change(ActivityOp::Deleted, kind, ino, parent, Some(gone)),
        )
        .await;
        self.finish_removal(ino).await
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`, and replaces
    /// what `new_name` named unless `noreplace`. Returns the replaced
    /// inode, if any.
    ///
    /// - It is one transaction, so the name is never missing and never in
    ///   both places.
    /// - Data does not move: chunks are keyed by inode, not by name, so the
    ///   file's size does not matter.
    /// - A replaced inode is removed as `unlink` removes one, starting with
    ///   a tombstone in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn rename(
        &self,
        caller: &Caller,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
        sealed: &SealedMove,
    ) -> Result<Option<u64>, FsError> {
        Self::check_entry_name(new_name, &sealed.sealed_name)?;
        check_sealed_size("a key record", &sealed.node_keys, MAX_SEALED_RECORD)?;
        let from = &dirent_key(parent, name);
        let to = &dirent_key(new_parent, new_name);
        let (replaced, moved) = run_txn(&self.client, move |txn| async move {
            self.guard(&txn, caller, parent, true).await?;
            if new_parent != parent {
                self.guard(&txn, caller, new_parent, true).await?;
            }
            // Read both directories and both names in one read, then both
            // inodes they name in another. Check them in the order of a
            // one-at-a-time read.
            let moves = new_parent != parent;
            let mut keys = vec![attr_key(parent), from.to_vec(), to.to_vec()];
            if moves {
                keys.push(attr_key(new_parent));
            }
            let mut found = txn.read_many(&keys).await?.into_iter().map(|e| e.value);
            let mut next = move || found.next().expect("a read of every key answers each");
            let (src_dir, from_value, to_value) = (next(), next(), next());
            let mut src_dir = dir_entry(parent, src_dir)?;
            let mut dst_dir = if moves {
                Some(dir_entry(new_parent, next())?)
            } else {
                None
            };

            let Some(ino) = from_value.as_deref().map(dirent_ino) else {
                return Err(enoent().into());
            };
            let target = to_value.map(|b| dirent_ino(&b));
            let victim_ino = target.filter(|&victim| victim != ino);
            let mut keys = vec![attr_key(ino)];
            keys.extend(victim_ino.map(attr_key));
            let mut found = txn.read_many(&keys).await?.into_iter().map(|e| e.value);
            let mut next = move || found.next().expect("a read of every key answers each");
            let mut moved = live(ino, next()).ok_or_else(enoent)?;
            if target == Some(ino) {
                // Two names for one inode: POSIX says to do nothing. With
                // no hard links, only `rename(a, a)` gets here.
                return Ok((None, None));
            }
            let old_sealed = from_value
                .as_deref()
                .map(dirent_sealed_name)
                .unwrap_or_default()
                .to_vec();

            let now = SystemTime::now();
            if let Some(victim_ino) = victim_ino {
                if noreplace {
                    return Err(FsError::errno(errno::EEXIST).into());
                }
                replace_victim(&txn, victim_ino, next(), moved.attr.kind, now).await?;
            }

            // The sealed name and key record are for one inode, which must
            // be the inode that moves.
            if sealed.ino != ino {
                return Err(FsError::new(
                    errno::ESTALE,
                    "the name moved meanwhile names another inode now",
                )
                .into());
            }
            // Only now: its answer says what the target holds and what the
            // inode's size is, for someone who may write to both folders.
            if moves && let Err(e) = self.check_move_room(ino, parent, new_parent).await {
                return Err(e.into());
            }
            self.move_keys(&txn, sealed, ino, new_parent, moves).await?;
            if moved.attr.kind == Kind::Directory && new_parent != parent {
                check_no_loop(&txn, ino, new_parent).await?;
            }
            if new_parent != parent {
                // A file's parent too: see `create_child`.
                moved.parent = new_parent;
            }
            moved.attr.ctime = now;
            write_entry(&txn, &moved).await?;
            txn.write(from, None).await?;
            txn.write(to, Some(&dirent_value(ino, &sealed.sealed_name)))
                .await?;
            touch_dir(&txn, &mut src_dir, now).await?;
            if let Some(dst_dir) = &mut dst_dir {
                touch_dir(&txn, dst_dir, now).await?;
            }
            txn.commit().await?;
            Ok((target, Some((old_sealed, moved.attr.kind))))
        })
        .await?;
        if let Some((old_sealed, kind)) = moved {
            let from = (parent, name, old_sealed);
            let to = (new_parent, new_name);
            self.note_rename(caller, sealed, from, to, kind, replaced.is_some())
                .await;
        }

        if let Some(victim) = replaced {
            // The rename is done, whatever this returns. A failure here
            // leaves the tombstone, and a later start finishes it.
            if let Err(e) = self.finish_removal(victim).await {
                eprintln!("could not finish removing inode {victim}, replaced by a rename: {e}");
            }
        }
        if new_parent != parent {
            self.count_move(sealed.ino, parent, new_parent).await;
        }
        Ok(replaced)
    }

    /// The part of `rename` that moves keys, in its transaction:
    ///
    /// - The new parent and the moved node must have fresh keys, so a
    ///   stale node doesn't look fresh after the move.
    /// - The new name must be sealed under the new parent's current key.
    /// - A move to another folder takes the node's key record with it,
    ///   wrapped again under the new parent's key, at the same version.
    async fn move_keys(
        &self,
        txn: &Transaction,
        sealed: &SealedMove,
        ino: u64,
        new_parent: u64,
        moves: bool,
    ) -> Result<(), TxnError> {
        self.fresh(txn, new_parent).await?;
        self.fresh(txn, ino).await?;
        let mut records = vec![node_keys_key(new_parent)];
        if moves {
            records.push(node_keys_key(ino));
        }
        let mut records = txn.get_many(&records).await?.into_iter();
        let (dst_version, _) = versions_of(new_parent, records.next().flatten())?;
        check_name_version(new_parent, &sealed.sealed_name, dst_version)?;
        if moves {
            let keys = &sealed.node_keys;
            let (version, _) = versions_of(ino, records.next().flatten())?;
            if NodeKeys::versions(keys).ok() != Some((version, dst_version)) {
                return Err(FsError::new(
                    errno::EKEYEXPIRED,
                    "the moved node's key record must keep its version, under the new parent's",
                )
                .into());
            }
            grants::put_node_keys(txn, ino, Some(keys)).await?;
        }
        Ok(())
    }

    /// Records a rename in the activity log: `from` is the old folder,
    /// tag and sealed name, `to` the new folder and tag.
    async fn note_rename(
        &self,
        caller: &Caller,
        sealed: &SealedMove,
        from: (u64, &OsStr, Vec<u8>),
        to: (u64, &OsStr),
        kind: Kind,
        replaced: bool,
    ) {
        let (parent, name, old_sealed) = from;
        let (new_parent, new_name) = to;
        let mut renamed = activity::change(
            ActivityOp::Renamed,
            kind,
            sealed.ino,
            new_parent,
            Some(SealedEntryName {
                parent: new_parent,
                tag: new_name.as_bytes().to_vec(),
                sealed: sealed.sealed_name.clone(),
            }),
        );
        renamed.from = Some(SealedEntryName {
            parent,
            tag: name.as_bytes().to_vec(),
            sealed: old_sealed,
        });
        renamed.replaced = replaced;
        self.note(caller, renamed).await;
    }

    /// Does everything after the tombstone: removes the chunks, then the
    /// Entry and the tombstone together. It is idempotent, so several
    /// processes can safely finish the same deletion at the same time.
    pub(super) async fn finish_removal(&self, ino: u64) -> Result<(), FsError> {
        // The Entry, marked deleted, stays until the chunks are gone. If it
        // is missing, an earlier finish got that far, and the sweep can
        // remove any chunks that are left.
        let entry = self
            .client
            .read_one(&attr_key(ino))
            .await?
            .value
            .map(|bytes| decode_entry(ino, &bytes));
        let layout = entry.as_ref().map_or(Layout::Inline, |e| e.attr.layout);
        let dropped = self.delete_chunks_from(ino, 0, layout).await?;
        run_txn(&self.client, move |txn| async move {
            txn.write(&attr_key(ino), None).await?;
            txn.write(&tombstone_key(ino), None).await?;
            txn.write(&crate::layout::volume_key(ino), None).await?;
            txn.write(&crate::layout::index_claim_key(ino), None)
                .await?;
            txn.write(&crate::layout::folder_size_key(ino), None)
                .await?;
            txn.write(&crate::layout::folder_limit_key(ino), None)
                .await?;
            // Its grants and key record are removed with it.
            grants::forget_inode(&txn, ino).await?;
            txn.commit().await?;
            Ok(())
        })
        .await?;
        self.discard(dropped);
        if let Some(entry) = &entry
            && entry.attr.kind == Kind::File
        {
            self.count(entry.parent, -(entry.attr.size as i64)).await;
        }
        if entry.is_some_and(|e| e.parent == ROOT_INO) {
            self.forget_activity(ino).await;
        }
        Ok(())
    }

    /// Finishes every deletion that an earlier process started but did not
    /// complete, and returns how many there were. The tombstone index holds
    /// only unfinished deletions, so this is cheap when there are none.
    pub(super) async fn reap_tombstones(&self) -> Result<usize, FsError> {
        let mut inos = Vec::new();
        let mut iter = self
            .client
            .key_iterator(TOMBSTONE_PREFIX, Consistency::Stale);
        while let Some(key) = next_key(&mut iter).await? {
            if !key.starts_with(TOMBSTONE_PREFIX) {
                break;
            }
            if let Ok(ino) = <[u8; 8]>::try_from(&key[TOMBSTONE_PREFIX.len()..]) {
                inos.push(u64::from_be_bytes(ino));
            }
        }
        for &ino in &inos {
            self.finish_removal(ino).await?;
        }
        Ok(inos.len())
    }
}

/// The part of `rename` that removes the entry a rename replaces, in its
/// transaction: `value` is the victim's stored Entry. It must be the same
/// kind as the moved node, and an empty folder. Its tombstone makes a
/// later start finish removing it if this server stops first.
async fn replace_victim(
    txn: &Transaction,
    victim_ino: u64,
    value: Option<Vec<u8>>,
    moved_kind: Kind,
    now: SystemTime,
) -> Result<(), TxnError> {
    let mut victim = live(victim_ino, value).ok_or_else(enoent)?;
    check_kind(&victim, moved_kind)?;
    victim.mark_deleted();
    victim.attr.ctime = now;
    write_entry(txn, &victim).await?;
    if victim.attr.kind == Kind::Directory && !is_empty_dir(txn, victim_ino).await? {
        return Err(FsError::errno(errno::ENOTEMPTY).into());
    }
    txn.write(&tombstone_key(victim_ino), Some(&[1])).await?;
    Ok(())
}

/// Refuses (`EINVAL`) to move directory `ino` below itself, by walking up
/// from `new_parent`. The walk reads every ancestor in the transaction, so
/// a rename at the same time that would close a loop the other way (and
/// writes one of them) conflicts with this one and cannot get past it.
async fn check_no_loop(txn: &Transaction, ino: u64, new_parent: u64) -> Result<(), TxnError> {
    let mut cur = new_parent;
    while cur != ROOT_INO {
        if cur == ino {
            return Err(FsError::errno(errno::EINVAL).into());
        }
        cur = live_entry(txn, cur).await?.parent;
    }
    Ok(())
}
