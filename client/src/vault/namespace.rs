//! Names: looking up, listing, making, renaming and removing entries.

use super::*;

impl Vault {
    /// Reserves an inode and makes a key for a new child `name` of
    /// `parent`. Also returns the tag that the entry is filed under.
    pub(super) async fn new_child(
        &self,
        parent: u64,
        name: &OsStr,
    ) -> Result<(NewNode, Node, OsString), FsError> {
        check_new_name(name)?;
        let parent_node = self.fresh_node(parent).await?;
        let ino = self.remote.allocate_inode().await?;
        let (record, key) =
            NodeKeys::create(ino, Some((&parent_node.key, parent_node.record.version)));
        let tag = parent_node.tag(name);
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: parent_node.seal(parent, ino, &tag, name),
        };
        Ok((new, Node::new(ino, record, key)?, tag))
    }

    /// The tag that `name` is filed under in directory `parent`.
    pub(super) async fn tag(&self, parent: u64, name: &OsStr) -> Result<OsString, FsError> {
        Ok(self.node(parent).await?.tag(name))
    }

    /// Looks up `name` in directory `parent` and returns its attributes.
    ///
    /// The entry's sealed name must open under the directory's key as
    /// `name`, and must name the inode that the server returned. If not,
    /// the server could return any inode this account can reach, and writes
    /// to `name` could go to a place that other users read. Returns `EIO`
    /// if this check fails.
    pub async fn lookup(&self, parent: u64, name: &OsStr) -> Result<Attr, FsError> {
        let mut dir = self.node(parent).await?;
        let tag = dir.tag(name);
        let (attr, sealed) = self.remote.lookup(parent, &tag).await?;
        let version = sealed_version(&sealed).map_err(|e| corrupt(parent, e))?;
        if version > dir.record.version {
            // The name is sealed under a newer key than the one known here.
            dir = self.refresh(parent).await?;
        }
        let key = dir.key_at(parent, version)?;
        open_name(
            &key,
            &dir.name_key,
            parent,
            attr.ino,
            os_bytes::bytes(&tag),
            &sealed,
        )
        .map_err(|e| {
            corrupt(
                parent,
                format!(
                    "{e}: the entry the server gave doesn't name inode {}",
                    attr.ino
                ),
            )
        })?;
        Ok(attr)
    }

    /// Drops the kept key and cached data of an inode that is gone.
    pub(super) fn forget_inode(&self, ino: u64) {
        self.nodes.lock().unwrap().remove(&ino);
        self.cache.lock().unwrap().invalidate_ino(self.space, ino);
    }

    /// Removes a file, as `Remote::unlink` does.
    pub async fn unlink(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.unlink(parent, &tag).await?;
        self.forget_inode(ino);
        Ok(ino)
    }

    /// Removes an empty directory, as `Remote::rmdir` does.
    pub async fn rmdir(&self, parent: u64, name: &OsStr) -> Result<u64, FsError> {
        let tag = self.tag(parent, name).await?;
        let ino = self.remote.rmdir(parent, &tag).await?;
        self.forget_inode(ino);
        Ok(ino)
    }

    /// Returns directory `ino`'s entries with their real names.
    ///
    /// - Fetches newer keys if a name is sealed under a newer key version.
    /// - Keeps `.` and `..`, which have no sealed name.
    /// - Leaves out, and reports on stderr, any entry whose name does not
    ///   open or does not match its tag. The directory's key holders did
    ///   not make that entry.
    pub async fn readdir(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        // Neither needs the other, so they share one round trip.
        let (items, mut dir) =
            futures_util::future::try_join(self.remote.readdir(ino), self.node(ino)).await?;
        // A name sealed under a newer key than the one known here means
        // that another client rotated the key.
        let newest = items
            .iter()
            .filter_map(|i| sealed_version(&i.sealed_name).ok())
            .max()
            .unwrap_or(0);
        if newest > dir.record.version {
            dir = self.refresh(ino).await?;
        }
        let mut named = Vec::with_capacity(items.len());
        for mut item in items {
            if item.sealed_name.is_empty() {
                // `.` and `..` have no tag.
                if item.is_dot() {
                    named.push(item);
                } else {
                    eprintln!("inode {ino}: an entry with no sealed name; left out");
                }
                continue;
            }
            let opened = dir.open_entry(
                ino,
                item.ino,
                os_bytes::bytes(&item.name),
                &item.sealed_name,
            );
            match opened {
                Ok(name) if !good_name(&name) => {
                    eprintln!("inode {ino}: a bad name for inode {}; left out", item.ino)
                }
                Ok(name) => {
                    item.name = os_bytes::into_name(name);
                    item.sealed_name = Vec::new();
                    named.push(item);
                }
                Err(e) => eprintln!("{e}; the entry for inode {} left out", item.ino),
            }
        }
        Ok(named)
    }

    /// Runs `op`. If the servers refuse it because a key on the path to
    /// `ino` is out of date (`EKEYEXPIRED`), gets new keys there and runs it
    /// once more.
    pub(super) async fn with_fresh_keys<T, Fut>(
        &self,
        ino: u64,
        op: impl Fn() -> Fut,
    ) -> Result<T, FsError>
    where
        Fut: std::future::Future<Output = Result<T, FsError>>,
    {
        match op().await {
            Err(e) if expired(&e) => {
                self.freshen(ino).await?;
                op().await
            }
            other => other,
        }
    }

    /// `readdir` without `.` and `..`: what is in the directory.
    pub async fn children(&self, ino: u64) -> Result<Vec<DirItem>, FsError> {
        let mut items = self.readdir(ino).await?;
        items.retain(|i| !i.is_dot());
        Ok(items)
    }

    pub async fn mkdir(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        self.with_fresh_keys(parent, || self.mkdir_once(parent, name, perm))
            .await
    }

    pub(super) async fn mkdir_once(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
    ) -> Result<Attr, FsError> {
        let (new, node, tag) = self.new_child(parent, name).await?;
        let attr = self.remote.mkdir(parent, &tag, perm, &new).await?;
        self.keep(attr.ino, node);
        Ok(attr)
    }

    /// Creates a file, as `Remote::create` does.
    pub async fn create(&self, parent: u64, name: &OsStr, perm: u16) -> Result<Attr, FsError> {
        self.with_fresh_keys(parent, || self.create_once(parent, name, perm))
            .await
    }

    pub(super) async fn create_once(
        &self,
        parent: u64,
        name: &OsStr,
        perm: u16,
    ) -> Result<Attr, FsError> {
        let (new, node, tag) = self.new_child(parent, name).await?;
        let attr = self.remote.create(parent, &tag, perm, &new).await?;
        self.keep(attr.ino, node);
        Ok(attr)
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`. Returns the
    /// inode it replaced, if any.
    ///
    /// Steps:
    ///
    /// - If the parent changes, give the moved node a new key first
    ///   (`rotate_moving`). Otherwise, users with the old parent's key
    ///   could read what is written to the node after the move.
    /// - Seal the new name under the new parent's key, and wrap the moved
    ///   node's key under the new parent's key.
    /// - If a key is stale (`EKEYEXPIRED`), get new keys and try once more.
    ///
    /// Nodes below the moved node become stale, so they get new keys the
    /// next time they are written.
    pub async fn rename(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        check_new_name(new_name)?;
        if parent != new_parent {
            self.rotate_moving(parent, name).await?;
        }
        match self
            .rename_once(parent, name, new_parent, new_name, noreplace)
            .await
        {
            Err(e) if expired(&e) => {
                self.freshen(new_parent).await?;
                let moved = self.lookup(parent, name).await?.ino;
                self.freshen(moved).await?;
                self.rename_once(parent, name, new_parent, new_name, noreplace)
                    .await
            }
            other => other,
        }
    }

    pub(super) async fn rename_once(
        &self,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        noreplace: bool,
    ) -> Result<Option<u64>, FsError> {
        let from = self.node(parent).await?;
        let to = self.fresh_node(new_parent).await?;
        let tag = from.tag(name);
        let new_tag = to.tag(new_name);
        let ino = self.lookup(parent, name).await?.ino;
        let mut sealed = SealedMove {
            ino,
            node_keys: Vec::new(),
            sealed_name: to.seal(new_parent, ino, &new_tag, new_name),
        };
        let mut rewrapped = None;
        if parent != new_parent {
            from.sealable(parent)?;
            let moved = self.node(ino).await?;
            let record = moved
                .record
                .rewrap(ino, &moved.key, (&to.key, to.record.version))
                .map_err(|e| corrupt(ino, e))?;
            sealed.node_keys = record.encode();
            rewrapped = Some(Node {
                record,
                key: moved.key.clone(),
                name_key: moved.name_key.clone(),
                stale: moved.stale,
                untrusted: to.untrusted.clone(),
            });
        }
        let replaced = self
            .remote
            .rename(parent, &tag, new_parent, &new_tag, noreplace, &sealed)
            .await?;
        if let Some(node) = rewrapped {
            self.keep(ino, node);
        }
        if let Some(victim) = replaced {
            self.forget_inode(victim);
        }
        Ok(replaced)
    }

    /// Gives the node that `name` refers to in `parent` a new key, wrapped
    /// under `parent`'s key, before it moves to another directory (see
    /// `rename`).
    pub(super) async fn rotate_moving(&self, parent: u64, name: &OsStr) -> Result<(), FsError> {
        for _ in 0..ROTATION_ROUNDS {
            let from = self.fresh_node(parent).await?;
            let moved = self.lookup(parent, name).await?.ino;
            match self.rotate_from(moved, Some(&from), None).await {
                Err(e) if changed(&e) || expired(&e) => {
                    self.forget_all();
                    continue;
                }
                other => return other,
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("the keys of the node moving out of inode {parent} kept changing"),
        ))
    }

    /// The inode at `path`: a root entry's name, then names below it,
    /// separated by `/`.
    pub async fn resolve(&self, path: &str) -> Result<u64, FsError> {
        let mut parts = path.split('/').filter(|p| !p.is_empty() && *p != ".");
        let first = parts
            .next()
            .ok_or_else(|| FsError::new(errno::EINVAL, "an empty path"))?;
        let mut ino = self.root_lookup(OsStr::new(first)).await?;
        for part in parts {
            ino = if is_group(ino) {
                self.group_lookup(ino, OsStr::new(part)).await?
            } else {
                self.lookup(ino, OsStr::new(part)).await?.ino
            };
        }
        Ok(ino)
    }

    /// Applies `changes` to `ino` (see `Remote::setattr`). When the file
    /// gets shorter, the client first seals the chunk at the new end again,
    /// cut short, because the server cannot open the chunk to do this. If
    /// another write fills that chunk again before the server applies the
    /// change, the server refuses it (`EAGAIN`), so this does it again.
    pub async fn setattr(&self, ino: u64, changes: SetAttr) -> Result<Attr, FsError> {
        let mut retries = 0;
        loop {
            if let Some(size) = changes.size {
                self.truncate(ino, size).await?;
            }
            let applied = self.remote.setattr(ino, changes).await;
            if let Some(size) = changes.size {
                // The chunks after the new end are gone, whatever the result
                // was.
                let chunk_size = self.remote.chunk_size();
                self.cache.lock().unwrap().invalidate(
                    self.space,
                    ino,
                    size / chunk_size..=u64::MAX,
                );
            }
            match applied {
                Err(e) if changed(&e) && retries < CHANGE_RETRIES => retries += 1,
                other => return other,
            }
        }
    }
}
