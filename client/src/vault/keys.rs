//! Getting nodes' keys: unwrapping them down from a grant, and rotating stale ones.

use super::*;

impl Vault {
    /// Fetches `ino`'s key again, with every key above it. Use this when
    /// data is sealed under a newer key version than the one known here.
    pub(super) async fn refresh(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        self.forget_all();
        self.node(ino).await
    }

    /// Returns `ino`'s key for sealing new data.
    ///
    /// - Opens the grant again if the user trusted its sender after it was
    ///   opened.
    /// - Returns `EACCES` if the key comes through an untrusted grant
    ///   (`Node::sealable`).
    /// - If the node is stale, first gives it, and every stale node above
    ///   it, a new key.
    pub(super) async fn fresh_node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        let mut node = self.node(ino).await?;
        // The user trusted the grant's sender after the grant was opened,
        // so open the grant again.
        if let Some(untrusted) = &node.untrusted
            && self.known.pinned(&untrusted.sender).is_some()
        {
            self.forget_all();
            node = self.node(ino).await?;
        }
        node.sealable(ino)?;
        if node.stale {
            return self.freshen(ino).await;
        }
        Ok(node)
    }

    pub(super) fn known_node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        self.nodes
            .lock()
            .unwrap()
            .get(&ino)
            .cloned()
            .ok_or_else(|| FsError::new(errno::EIO, format!("inode {ino}'s key went missing")))
    }

    /// Gives every stale node on the path from this account's grant to
    /// `ino` a new key, and returns `ino`'s key. Call it after the server
    /// refuses a write with `EKEYEXPIRED`.
    ///
    /// Steps, repeated up to `ROTATION_ROUNDS` times:
    ///
    /// - Fetch and unwrap the key path again.
    /// - Find the highest stale node. If there is none, return.
    /// - Rotate it, and everything below it down to each grant
    ///   (`rotate_from`). If another client rotated first, start again.
    ///
    /// Returns `EAGAIN` if the keys keep changing.
    pub async fn freshen(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        for _ in 0..ROTATION_ROUNDS {
            self.forget_all();
            let path = self.remote.key_path(ino).await?;
            let inos: Vec<u64> = path.nodes.iter().map(|&(i, _)| i).collect();
            let last = self.unwrap_path(path).await?;
            let mut stale = None;
            for pair in inos.windows(2) {
                let parent = self.known_node(pair[0])?;
                if self
                    .known_node(pair[1])?
                    .record
                    .is_stale(parent.record.version)
                {
                    stale = Some((pair[1], parent));
                    break;
                }
            }
            let Some((stale, parent)) = stale else {
                return Ok(last);
            };
            match self.rotate_from(stale, Some(&parent), None).await {
                Ok(()) => {}
                // Another client rotated the key first. Check again.
                Err(e) if changed(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("the keys above inode {ino} kept changing"),
        ))
    }

    /// Checks the server's grantee list for `granted` against the list
    /// sealed under its key. A server that lies could add a user, to get a
    /// key sealed to them.
    ///
    /// Returns each grantee's sealed entry (public key and write access),
    /// by user name.
    ///
    /// Edge cases:
    ///
    /// - Returns `EPERM` if the sealed list is missing or under an old key
    ///   version, or if the server lists a user that the sealed list does
    ///   not have, or lists them differently.
    /// - Returns `EPERM` if a different key is pinned here for a user.
    /// - Leaves out users with no keys (their account was deleted).
    /// - Leaves out users on the sealed list that the server no longer
    ///   lists, because removing a grant needs no approval.
    pub(super) fn checked_grantees(
        &self,
        node: &Node,
        ino: u64,
        granted: &GrantedNode,
    ) -> Result<HashMap<String, GranteeEntry>, FsError> {
        let mismatch = |why: String| {
            FsError::new(
                errno::EPERM,
                format!(
                    "inode {ino}: the server's list of who it is granted to doesn't match the \
                     one sealed under its key ({why}); refusing to seal its key to anyone on it"
                ),
            )
        };
        let named: Vec<&Grantee> = granted
            .grantees
            .iter()
            .filter(|g| !g.public_key.is_empty())
            .collect();
        if named.is_empty() {
            return Ok(HashMap::new());
        }
        if granted.sealed_grantees.is_empty() {
            return Err(mismatch("there is no sealed list".to_string()));
        }
        let version = sealed_version(&granted.sealed_grantees).map_err(|e| corrupt(ino, e))?;
        if version != node.record.version {
            return Err(mismatch(format!(
                "the sealed list is under key version {version}, not the current {}",
                node.record.version
            )));
        }
        let sealed = open_grantees(&node.key, ino, &granted.sealed_grantees)
            .map_err(|e| mismatch(e.to_string()))?;
        let mut out = HashMap::new();
        for grantee in named {
            check_username(&grantee.user).map_err(|e| mismatch(e.message))?;
            let Some(entry) = sealed.iter().find(|e| e.user == grantee.user) else {
                return Err(mismatch(format!(
                    "{} isn't on the sealed list",
                    grantee.user
                )));
            };
            if entry.public_key.as_slice() != grantee.public_key.as_slice() {
                return Err(mismatch(format!(
                    "{}'s key isn't the one their grant was sealed to",
                    grantee.user
                )));
            }
            if entry.writable != grantee.writable {
                return Err(mismatch(format!(
                    "{}'s grant is read-{} on the sealed list",
                    grantee.user,
                    if entry.writable { "write" } else { "only" }
                )));
            }
            // A different key is pinned here for this user. Whoever added
            // them to the list used a key that this account would not
            // accept.
            if let Some(pinned) = self.known.pinned(&grantee.user)
                && pinned != entry.public_key
            {
                self.known.check(&grantee.user, &entry.public_key)?;
            }
            out.insert(grantee.user.clone(), entry.clone());
        }
        Ok(out)
    }

    /// Gives `top`, and every node from `top` down to each grant below it,
    /// a new key. Grantees lower down cannot rotate keys above their grant,
    /// so this must happen now.
    ///
    /// Inputs:
    ///
    /// - `parent`: the node of `top`'s parent, which wraps `top`'s new key.
    ///   `None` for a volume.
    /// - `drop`: a user whose grant of `top` to remove, for a revocation.
    ///
    /// Steps:
    ///
    /// - List the grants below `top`, and order the nodes from the top
    ///   down.
    /// - Make a new key for each node, wrapped under its parent's new key.
    /// - Seal each grant again, only to the users and keys on the node's
    ///   sealed grantee list (`checked_grantees`). Seal that list again
    ///   under the new key.
    /// - Send all rotations in one request. The server refuses them with
    ///   `EAGAIN` if another client changed a key first.
    ///
    /// Returns `ENOENT` if `drop` has no grant of `top`.
    pub(super) async fn rotate_from(
        &self,
        top: u64,
        parent: Option<&Node>,
        drop: Option<&str>,
    ) -> Result<(), FsError> {
        let under: Vec<GrantedNode> = self.remote.grants_under(top).await?;
        let mut parent_of = HashMap::new();
        let mut depth = HashMap::from([(top, 0)]);
        let mut granted: HashMap<u64, GrantedNode> = HashMap::new();
        for node in under {
            for (d, pair) in node.path.windows(2).enumerate() {
                parent_of.insert(pair[1], pair[0]);
                depth.insert(pair[1], d + 1);
            }
            granted.insert(node.ino, node);
        }
        if let Some(user) = drop
            && !granted
                .get(&top)
                .is_some_and(|n| n.grantees.iter().any(|g| g.user == user))
        {
            return Err(FsError::new(
                errno::ENOENT,
                format!("{user} has no grant of inode {top}"),
            ));
        }
        let mut order: Vec<u64> = depth.keys().copied().collect();
        order.sort_by_key(|ino| (depth[ino], *ino));

        let me = self.remote.username();
        let mut new_keys: HashMap<u64, (Key, u32)> = HashMap::new();
        let mut rotations = Vec::with_capacity(order.len());
        for ino in order {
            let current = self.node(ino).await?;
            current.sealable(ino)?;
            let wrap = if current.record.parent_version == 0 {
                None
            } else if ino == top {
                let parent = parent.ok_or_else(|| {
                    FsError::new(
                        errno::EACCES,
                        format!(
                            "a new key for inode {top} must be wrapped under its parent's, \
                             which this account can't reach"
                        ),
                    )
                })?;
                parent.sealable(ino)?;
                Some((parent.key.clone(), parent.record.version))
            } else {
                Some(new_keys[&parent_of[&ino]].clone())
            };
            let (record, key) = current
                .record
                .rotate(ino, &current.key, wrap.as_ref().map(|(k, v)| (k, *v)))
                .map_err(|e| corrupt(ino, e))?;
            let mut grants = Vec::new();
            let mut kept = Vec::new();
            if let Some(node) = granted.remove(&ino) {
                // Removing a user needs no approval, so do not check the
                // user being removed. This is also how to remove a grantee
                // that the server made up.
                let dropping = |g: &Grantee| ino == top && drop == Some(g.user.as_str());
                let checked = GrantedNode {
                    grantees: node
                        .grantees
                        .iter()
                        .filter(|g| !dropping(g))
                        .cloned()
                        .collect(),
                    ..node.clone()
                };
                let listed = self.checked_grantees(&current, ino, &checked)?;
                for grantee in node.grantees {
                    let sealed = match listed.get(&grantee.user) {
                        _ if ino == top && drop == Some(grantee.user.as_str()) => Vec::new(),
                        Some(entry) => {
                            kept.push(entry.clone());
                            seal_grant(
                                &self.identity,
                                me,
                                &entry.public_key,
                                ino,
                                record.version,
                                &key,
                            )
                        }
                        // The user's account has no keys, so there is
                        // nothing to seal to. Remove the grant.
                        None => {
                            eprintln!(
                                "dropping {}'s grant of inode {ino}: they have no keys",
                                grantee.user
                            );
                            Vec::new()
                        }
                    };
                    grants.push((grantee.user, sealed));
                }
            }
            let sealed_grantees = if kept.is_empty() {
                Vec::new()
            } else {
                seal_grantees(&key, record.version, ino, &kept)
            };
            rotations.push(Rotation {
                ino,
                expected_version: current.record.version,
                node_keys: record.encode(),
                grants,
                sealed_grantees,
            });
            new_keys.insert(ino, (key, record.version));
        }
        let rotated = self.remote.rotate(rotations).await;
        self.forget_all();
        rotated
    }

    /// Takes `node`, the live key of directory `ino`, as this snapshot
    /// vault's key for it, unless it has one. The live key opens every
    /// older version of the directory's names too, and its name key never
    /// changes, so names sealed at the snapshot still open. A name sealed
    /// under a key newer than `node` makes `lookup` fetch the snapshot's own.
    pub(crate) fn adopt(&self, ino: u64, node: Arc<Node>) {
        self.nodes.lock().unwrap().entry(ino).or_insert(node);
    }

    /// Returns `ino`'s key. If it is not known yet, unwraps it from this
    /// account's grant.
    pub async fn node(&self, ino: u64) -> Result<Arc<Node>, FsError> {
        if let Some(node) = self.nodes.lock().unwrap().get(&ino) {
            return Ok(Arc::clone(node));
        }
        let path = self.remote.key_path(ino).await?;
        self.unwrap_path(path).await
    }

    /// Opens `grant` of `ino` with its sender's public key. Returns the key
    /// version, the key, and the sender if this account does not trust
    /// them. A trusted sender is this account, or a user whose key is
    /// pinned here. For other senders, the vault uses the key that the
    /// server gives, so the server could have made the grant.
    pub(super) async fn open_grant(
        &self,
        ino: u64,
        grant: &Grant,
    ) -> Result<(u32, Key, Option<Arc<Untrusted>>), FsError> {
        let refused = |e: String| FsError::new(errno::EACCES, format!("inode {ino}: {e}"));
        let sealed = &grant.sealed_key;
        let sender = grant_sender(sealed).map_err(|e| refused(e.to_string()))?;
        check_username(sender).map_err(|e| refused(e.message))?;
        if sender == self.remote.username() {
            let (version, key) = self
                .identity
                .open_grant(&self.identity.public_key(), ino, sealed)
                .map_err(|e| refused(e.to_string()))?;
            return Ok((version, key, None));
        }
        if let Some(pinned) = self.known.pinned(sender)
            && let Ok((version, key)) = self.identity.open_grant(&pinned, ino, sealed)
        {
            return Ok((version, key, None));
        }
        let served = self.sender_key(sender).await?;
        let (version, key) = self
            .identity
            .open_grant(&served, ino, sealed)
            .map_err(|e| refused(e.to_string()))?;
        let untrusted = Untrusted {
            sender: sender.to_string(),
            key: served,
        };
        Ok((version, key, Some(Arc::new(untrusted))))
    }

    /// `user`'s public key, as the server gives it.
    pub(super) async fn sender_key(&self, user: &str) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        if let Some(key) = self.senders.lock().unwrap().get(user) {
            return Ok(*key);
        }
        let key: [u8; PUBLIC_KEY_LEN] = self
            .remote
            .public_key(user)
            .await?
            .try_into()
            .map_err(|_| FsError::new(errno::EIO, format!("{user}'s public key is malformed")))?;
        self.senders.lock().unwrap().insert(user.to_string(), key);
        Ok(key)
    }

    /// Unwraps every key along `path`, from the grant down, keeps each one,
    /// and returns the last.
    ///
    /// - Refuses a key record older than one already seen
    ///   (`check_not_older`).
    /// - Marks a node stale if it, or a node above it, is wrapped under an
    ///   old version of its parent's key.
    /// - Marks every node below an untrusted grant as untrusted.
    pub(super) async fn unwrap_path(&self, path: KeyPath) -> Result<Arc<Node>, FsError> {
        let mut nodes = path.nodes.into_iter();
        let (root_ino, root_bytes) = nodes
            .next()
            .ok_or_else(|| FsError::new(errno::EIO, "an empty key path"))?;
        let record = NodeKeys::decode(&root_bytes).map_err(|e| corrupt(root_ino, e))?;
        self.check_not_older(root_ino, &record)?;
        let (version, key, untrusted) = self.open_grant(root_ino, &path.grant).await?;
        // A grant always holds the current key version, because a rotation
        // seals every grant of the node again.
        if version != record.version {
            return Err(FsError::new(
                errno::EACCES,
                format!("the grant of inode {root_ino} holds an out-of-date key"),
            ));
        }
        // `Node::new` checks the key. If the key does not open the record,
        // it is not this node's key, whatever the grant says.
        let mut root = Node::new(root_ino, record, key)?;
        if let Some(u) = &untrusted
            && self.warn_untrusted
            && self.warned.lock().unwrap().insert(root_ino)
        {
            eprintln!(
                "a share from {} is read-only here until their key is trusted: \
                 see `raft5fs pending`",
                u.sender
            );
        }
        root.untrusted = untrusted;
        let mut parent = (root_ino, self.keep(root_ino, root));
        for (ino, bytes) in nodes {
            let record = NodeKeys::decode(&bytes).map_err(|e| corrupt(ino, e))?;
            self.check_not_older(ino, &record)?;
            let wrapping = parent.1.key_at(parent.0, record.parent_version)?;
            let key = record.open(ino, &wrapping).map_err(|e| corrupt(ino, e))?;
            let stale = parent.1.stale || record.is_stale(parent.1.record.version);
            let mut node = Node::new(ino, record, key)?;
            node.stale = stale;
            node.untrusted = parent.1.untrusted.clone();
            parent = (ino, self.keep(ino, node));
        }
        Ok(parent.1)
    }

    pub(super) fn keep(&self, ino: u64, node: Node) -> Arc<Node> {
        self.saw_version(ino, node.record.version);
        let node = Arc::new(node);
        self.nodes.lock().unwrap().insert(ino, Arc::clone(&node));
        node
    }
}
