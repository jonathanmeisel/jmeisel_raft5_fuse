//! Sharing: grants, revokes, public links, and checking people's keys.

use super::*;

impl Vault {
    /// Removes `user`'s grant of directory `ino` and gives the directory a
    /// new key. This needs the key of the directory above, which wraps the
    /// new key, unless `ino` is a volume. Tries again if another client
    /// changes the keys at the same time.
    pub async fn revoke(&self, ino: u64, user: &str) -> Result<(), FsError> {
        for _ in 0..ROTATION_ROUNDS {
            self.freshen(ino).await?;
            let path = self.remote.key_path(ino).await?;
            let parent = match path.nodes.len() {
                0 | 1 => None,
                n => Some(self.node(path.nodes[n - 2].0).await?),
            };
            match self.rotate_from(ino, parent.as_deref(), Some(user)).await {
                Err(e) if changed(&e) => continue,
                other => return other,
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s keys kept changing under this revocation"),
        ))
    }

    /// The users that directory `ino` is granted to. Returns `EPERM` if the
    /// list does not agree with the grantee list sealed under its key, or
    /// with the keys pinned here.
    pub async fn grantees(&self, ino: u64) -> Result<Vec<Grantee>, FsError> {
        Ok(self.grantees_with_links(ino).await?.0)
    }

    /// `grantees`, and the secret of each public link among them, by link
    /// name, from the sealed grantee list. Needs write access to `ino`, as
    /// the list does.
    pub async fn grantees_with_links(
        &self,
        ino: u64,
    ) -> Result<(Vec<Grantee>, HashMap<String, String>), FsError> {
        let mut node = self.node(ino).await?;
        let Some(granted) = self
            .remote
            .grants_under(ino)
            .await?
            .into_iter()
            .find(|n| n.ino == ino)
        else {
            return Ok((Vec::new(), HashMap::new()));
        };
        if newer_key(&node, &granted) {
            self.forget_all();
            node = self.node(ino).await?;
        }
        let secrets = self
            .checked_grantees(&node, ino, &granted)?
            .into_values()
            .filter_map(|e| Some((e.user, e.link_secret?)))
            .collect();
        Ok((granted.grantees, secrets))
    }

    /// Grants directory `ino`, and everything below it, to `user`. The
    /// grant shows in their root as `label`.
    ///
    /// Steps:
    ///
    /// - Check that this account can seal under `ino`.
    /// - Get `user`'s public key from the server, and pin it if no key is
    ///   pinned.
    /// - Seal the key to `user`, add them to the sealed grantee list, and
    ///   send both. Try again if another client changes the grants at the
    ///   same time.
    ///
    /// Returns the public key that the grant was sealed to. If it was not
    /// pinned before, compare it with the fingerprint that the user saw
    /// when they enrolled (`raft5fs grant` calls `trust` first to require
    /// this). A pin is trust in both directions: shares from `user` are
    /// trusted after this.
    pub async fn grant(
        &self,
        ino: u64,
        user: &str,
        writable: bool,
        label: &OsStr,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        self.grant_with(ino, user, writable, label, None).await
    }

    /// `grant`, with `link_secret` kept in `user`'s sealed grantee entry
    /// when `user` is a public link.
    pub(super) async fn grant_with(
        &self,
        ino: u64,
        user: &str,
        writable: bool,
        label: &OsStr,
        link_secret: Option<&str>,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        check_new_label(label)?;
        // Check this before pinning `user`'s key. A pin also makes shares
        // from `user` trusted, and sharing from an untrusted share must not
        // cause that.
        self.fresh_node(ino).await?;
        let public_key = self.remote.public_key(user).await?;
        let public_key = self.known.check(user, &public_key)?;
        let mut expired_once = false;
        for _ in 0..CHANGE_RETRIES {
            let node = self.fresh_node(ino).await?;
            let granted = self
                .remote
                .grants_under(ino)
                .await?
                .into_iter()
                .find(|n| n.ino == ino);
            if granted.as_ref().is_some_and(|g| newer_key(&node, g)) {
                self.forget_all();
                continue;
            }
            let seq = granted.as_ref().map_or(0, |g| g.grantees_seq);
            let mut entries: Vec<GranteeEntry> = match &granted {
                Some(granted) => self
                    .checked_grantees(&node, ino, granted)?
                    .into_values()
                    .filter(|e| e.user != user)
                    .collect(),
                None => Vec::new(),
            };
            entries.push(GranteeEntry {
                user: user.to_string(),
                public_key,
                writable,
                link_secret: link_secret.map(str::to_string),
            });
            let version = node.record.version;
            let grant = Grant {
                ino,
                writable,
                key_version: version,
                sealed_key: seal_grant(
                    &self.identity,
                    self.remote.username(),
                    &public_key,
                    ino,
                    version,
                    &node.key,
                ),
                sealed_label: seal_signed_label(
                    &self.identity,
                    self.remote.username(),
                    &public_key,
                    ino,
                    os_bytes::bytes(label),
                ),
            };
            let sealed_grantees = seal_grantees(&node.key, version, ino, &entries);
            let listed = entries.iter().map(|e| e.user.clone()).collect();
            match self
                .remote
                .grant(user, grant, sealed_grantees, seq, listed)
                .await
            {
                Err(e) if expired(&e) && !expired_once => {
                    expired_once = true;
                    self.freshen(ino).await?;
                }
                // Another client changed the grants at the same time. Start
                // again from their list.
                Err(e) if changed(&e) => {}
                other => {
                    other?;
                    // A first grant to `user` pinned their key.
                    self.share_pins().await;
                    return Ok(public_key);
                }
            }
        }
        Err(FsError::new(
            errno::EAGAIN,
            format!("inode {ino}'s grantees kept changing under this grant"),
        ))
    }

    /// Makes a public link to directory `ino`: a new account that can only
    /// read it, until it expires (`expires`, in seconds since the Unix
    /// epoch) or anyone who can write the directory revokes it. Needs the
    /// `links` capability and write access.
    ///
    /// - `path` is how this account knows the directory. It is sealed to
    ///   this account's key, so only `links` here reads it back.
    /// - `label` is the name the directory shows under for the link's
    ///   visitors.
    ///
    /// Returns the link's account name and secret. The secret goes in the
    /// link (`public_link`), and in the directory's sealed grantee list, so
    /// whoever can change the directory can copy the link again
    /// (`grantees_with_links`).
    pub async fn create_link(
        &self,
        ino: u64,
        path: &str,
        label: &OsStr,
        expires: Option<u64>,
    ) -> Result<(String, String), FsError> {
        // A visitor has checked nobody, so a link can't show in a group.
        check_new_name(label)?;
        // Checked first, so a refused grant leaves no account behind.
        self.remote.access(ino, 2).await?;
        let (user, secret) = new_link_credentials();
        let note = seal_label(&self.identity.public_key(), ino, path.as_bytes());
        let key = self
            .remote
            .create_link_account(&user, &secret, expires, ino, note)
            .await?;
        // This account made the key, so it needs no fingerprint check.
        self.known.check(&user, &key)?;
        self.grant_with(ino, &user, false, label, Some(&secret))
            .await?;
        Ok((user, secret))
    }

    /// The public links that this account made, with the path each was made
    /// for (`None` if it can't be read).
    pub async fn links(&self) -> Result<Vec<(LinkAccount, Option<String>)>, FsError> {
        let links = self.remote.list_links().await?;
        Ok(links
            .into_iter()
            .map(|link| {
                let path = self
                    .identity
                    .open_label(link.info.folder, &link.info.note)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                (link, path)
            })
            .collect())
    }

    /// Pins `user`'s public key if its fingerprint matches `expected`.
    /// Spaces and case in `expected` do not matter. This makes grants from
    /// `user` trusted, and lets a first grant to them go ahead without
    /// trusting the server for their key.
    ///
    /// Returns `EPERM` if the fingerprint is different, or if a different
    /// key is already pinned.
    pub async fn trust(&self, user: &str, expected: &str) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        let served = self.matching_served_key(user, expected).await?;
        let key = self.known.check(user, &served)?;
        // Grants from this user were opened as untrusted before, so open
        // them again.
        self.forget_all();
        self.share_checked(user, key).await;
        Ok(key)
    }

    /// `trust`, for a user whose pinned key is no longer theirs because
    /// they enrolled again: pins their new key in place of the old one, if
    /// its fingerprint matches `expected`. The old pin goes only once the
    /// new key has matched, so a server can't swap a key in this way.
    pub async fn replace_key(
        &self,
        user: &str,
        expected: &str,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        let served = self.matching_served_key(user, expected).await?;
        self.known.forget(user).map_err(|e| {
            FsError::new(errno::EIO, format!("cannot forget {user}'s old key: {e}"))
        })?;
        let key = self.known.check(user, &served)?;
        self.forget_all();
        self.share_checked(user, key).await;
        Ok(key)
    }

    /// Whether the key pinned for `user` differs from the one the server
    /// gives now: most likely, they enrolled again. False if none is
    /// pinned.
    pub async fn key_changed(&self, user: &str) -> Result<bool, FsError> {
        let Some(pinned) = self.known.pinned(user) else {
            return Ok(false);
        };
        Ok(self.served_key(user).await? != pinned)
    }

    /// The key that the server gives for `user`, if its fingerprint is
    /// `expected` (spaces and case aside). `EPERM` if not.
    pub(super) async fn matching_served_key(
        &self,
        user: &str,
        expected: &str,
    ) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        let served = self.served_key(user).await?;
        let matches = fingerprint_matches(&served, expected)
            .map_err(|e| FsError::new(errno::EINVAL, format!("{expected:?}: {e}")))?;
        // It doesn't say what the server's key is: someone shown the answer
        // could copy it, and then the check would check nothing.
        if !matches {
            return Err(FsError::new(
                errno::EPERM,
                format!(
                    "those words don't match the key the servers have for {user}. Check them \
                     with {user}, one by one. If they still don't match, don't trust this key, \
                     and tell your admin."
                ),
            ));
        }
        Ok(served)
    }

    /// The public key that the server gives for `user`. Only the server
    /// says it is theirs.
    pub async fn served_key(&self, user: &str) -> Result<[u8; PUBLIC_KEY_LEN], FsError> {
        check_username(user)?;
        self.remote
            .public_key(user)
            .await?
            .try_into()
            .map_err(|_| FsError::new(errno::EIO, format!("{user}'s public key is malformed")))
    }

    /// Every grant made to this account, with its sender and whether this
    /// account trusts them (see `Node::sealable`).
    pub async fn shares(&self) -> Result<Vec<Share>, FsError> {
        let mut grants = self.remote.list_grants().await?;
        grants.sort_by_key(|g| g.ino);
        let mut shares = Vec::with_capacity(grants.len());
        for grant in grants {
            let label = self.root_label(&grant).await;
            let sender = grant_sender(&grant.sealed_key).unwrap_or("?").to_string();
            let trust = match self.open_grant(grant.ino, &grant).await {
                Ok((_, _, None)) => ShareTrust::Trusted,
                Ok((_, _, Some(untrusted))) => ShareTrust::Untrusted { key: untrusted.key },
                Err(e) => ShareTrust::Unreadable(e),
            };
            shares.push(Share {
                label,
                ino: grant.ino,
                writable: grant.writable,
                sender,
                trust,
            });
        }
        Ok(shares)
    }
}
