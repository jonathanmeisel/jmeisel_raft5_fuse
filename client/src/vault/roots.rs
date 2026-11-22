//! The virtual root: one entry for each grant, grouped by label, and volumes.

use super::*;

/// The root as this account sees it: its grants, under the names they show as,
/// in the virtual folders their labels ask for. None of this is on the servers.
/// Each person's is their own, so that a class can show as one folder to a
/// student who has two shares in it, and nothing of what else it holds.
#[derive(Default)]
pub(super) struct Roots {
    /// The root and each group, by inode.
    dirs: HashMap<u64, RootDir>,
    /// The folder that each grant shows in.
    parents: HashMap<u64, u64>,
}

#[derive(Default)]
pub(super) struct RootDir {
    parent: u64,
    /// The names of the groups around it, as labels say them.
    path: Vec<OsString>,
    /// What it shows, by name: grants and groups.
    entries: BTreeMap<OsString, u64>,
    /// Its groups, by the name labels use, which a clash can change for showing.
    groups: HashMap<OsString, u64>,
}

impl Roots {
    /// A name in folder `dir` like `wanted` that isn't taken.
    fn free_name(&self, dir: u64, wanted: &OsStr, reserved: &impl Fn(&OsStr) -> bool) -> OsString {
        let entries = self.dirs.get(&dir).map(|d| &d.entries);
        let unusable = |name: &OsStr| {
            entries.is_some_and(|e| e.contains_key(name))
                || name.is_empty()
                || (dir == VIRTUAL_ROOT && reserved(name))
        };
        let mut name = wanted.to_os_string();
        let mut n = 2;
        while unusable(&name) {
            name = wanted.to_os_string();
            name.push(format!(" ({n})"));
            n += 1;
        }
        name
    }

    /// The path that `ino` shows at, from the root, with `/` between names.
    fn shown_path(&self, ino: u64) -> Option<String> {
        let mut names = Vec::new();
        let mut at = ino;
        while at != VIRTUAL_ROOT {
            let parent = match self.parents.get(&at) {
                Some(&parent) => parent,
                None => self.dirs.get(&at)?.parent,
            };
            let (name, _) = self
                .dirs
                .get(&parent)?
                .entries
                .iter()
                .find(|(_, i)| **i == at)?;
            names.push(name.to_string_lossy().into_owned());
            at = parent;
        }
        names.reverse();
        Some(names.join("/"))
    }
}

impl Vault {
    /// Reads this account's grants again, and works out the root from them.
    /// Each grant shows under its label, in the groups the label names, made
    /// unique there. A grant of a folder inside another grant isn't one: it is
    /// reached from there, with the write access of the nearest read-write
    /// grant above.
    pub(super) async fn read_roots(&self) -> Result<(), FsError> {
        let (mut grants, covered) = self.remote.list_grants_covered().await?;
        grants.retain(|g| !covered.contains(&g.ino));
        grants.sort_by_key(|g| g.ino);
        let reserved = |name: &OsStr| self.reserved(name);
        let mut roots = Roots::default();
        roots.dirs.insert(VIRTUAL_ROOT, RootDir::default());
        for grant in grants {
            let (label, groupable) = self.shown_label(&grant).await;
            let parts = label_parts(os_bytes::bytes(&label)).filter(|_| groupable);
            let (groups, name) = match &parts {
                Some(parts) => {
                    let (name, groups) = parts.split_last().expect("a label has a name");
                    (groups, name.clone())
                }
                // Out of any group, so that its label's `/` must go.
                None => (
                    &[][..],
                    OsString::from(label.to_string_lossy().replace('/', "-")),
                ),
            };
            let mut dir = VIRTUAL_ROOT;
            for group in groups {
                dir = self.group_in(&mut roots, dir, group);
            }
            let shown = roots.free_name(dir, &name, &reserved);
            roots
                .dirs
                .get_mut(&dir)
                .expect("the folder was just made")
                .entries
                .insert(shown, grant.ino);
            roots.parents.insert(grant.ino, dir);
        }
        *self.roots.lock().unwrap() = roots;
        Ok(())
    }

    /// The group called `name` in folder `dir`, made if there is none.
    pub(super) fn group_in(&self, roots: &mut Roots, dir: u64, name: &OsStr) -> u64 {
        if let Some(&group) = roots.dirs.get(&dir).and_then(|d| d.groups.get(name)) {
            return group;
        }
        let mut path = roots
            .dirs
            .get(&dir)
            .map(|d| d.path.clone())
            .unwrap_or_default();
        path.push(name.to_os_string());
        let group = {
            let mut numbers = self.group_numbers.lock().unwrap();
            let next = GROUP_BASE + numbers.len() as u64;
            *numbers.entry(path.clone()).or_insert(next)
        };
        let shown = roots.free_name(dir, name, &|n| self.reserved(n));
        let parent = roots.dirs.get_mut(&dir).expect("the folder was just made");
        parent.entries.insert(shown, group);
        parent.groups.insert(name.to_os_string(), group);
        roots.dirs.insert(
            group,
            RootDir {
                parent: dir,
                path,
                ..RootDir::default()
            },
        );
        group
    }

    /// Reads this account's grants again and returns the root's entries:
    /// each grant's or group's name, and its inode.
    pub async fn root_entries(&self) -> Result<Vec<(OsString, u64)>, FsError> {
        self.group_entries(VIRTUAL_ROOT).await
    }

    /// `root_entries` for the root or a group. `ENOENT` if a group has gone,
    /// because nothing is left in it.
    pub async fn group_entries(&self, dir: u64) -> Result<Vec<(OsString, u64)>, FsError> {
        self.read_roots().await?;
        let roots = self.roots.lock().unwrap();
        let dir = roots
            .dirs
            .get(&dir)
            .ok_or_else(|| FsError::errno(errno::ENOENT))?;
        Ok(dir.entries.iter().map(|(n, &i)| (n.clone(), i)).collect())
    }

    /// `ENOENT` if group `dir` has gone, after reading the grants again if it
    /// isn't known here: another device may have made it.
    pub async fn check_group(&self, dir: u64) -> Result<(), FsError> {
        if self.roots.lock().unwrap().dirs.contains_key(&dir) {
            return Ok(());
        }
        self.group_entries(dir).await.map(drop)
    }

    /// What `name` refers to in the root or a group. If the name is not known,
    /// reads the grants again.
    pub async fn group_lookup(&self, dir: u64, name: &OsStr) -> Result<u64, FsError> {
        let known = |roots: &Roots| {
            roots
                .dirs
                .get(&dir)
                .and_then(|d| d.entries.get(name))
                .copied()
        };
        if let Some(ino) = known(&self.roots.lock().unwrap()) {
            return Ok(ino);
        }
        self.read_roots().await?;
        known(&self.roots.lock().unwrap()).ok_or_else(|| FsError::errno(errno::ENOENT))
    }

    /// What `..` is for `ino`, a grant or a group: the folder it shows in.
    pub fn root_parent(&self, ino: u64) -> u64 {
        let roots = self.roots.lock().unwrap();
        roots
            .parents
            .get(&ino)
            .copied()
            .or_else(|| roots.dirs.get(&ino).map(|d| d.parent))
            .unwrap_or(VIRTUAL_ROOT)
    }

    /// The label for a new volume called `name` in the root or group `dir`.
    pub(super) fn label_in(&self, dir: u64, name: &OsStr) -> OsString {
        let roots = self.roots.lock().unwrap();
        let mut label = OsString::new();
        for part in roots
            .dirs
            .get(&dir)
            .map(|d| d.path.as_slice())
            .unwrap_or_default()
        {
            label.push(part);
            label.push("/");
        }
        label.push(name);
        label
    }

    /// Makes a new volume called `name` in the root or group `dir`.
    pub async fn create_volume_in(
        &self,
        dir: u64,
        name: &OsStr,
        perm: u16,
    ) -> Result<Attr, FsError> {
        check_new_name(name)?;
        let label = self.label_in(dir, name);
        self.create_volume(&label, perm).await
    }

    /// Where each of this account's grants shows, from the root, by inode.
    pub async fn grant_paths(&self) -> Result<HashMap<u64, String>, FsError> {
        self.read_roots().await?;
        let roots = self.roots.lock().unwrap();
        Ok(roots
            .parents
            .keys()
            .filter_map(|&ino| Some((ino, roots.shown_path(ino)?)))
            .collect())
    }

    /// Where live inode `ino` is, as a path from the virtual root, or `None`
    /// if this account can't reach it by a path it shows. Lists each folder
    /// on the way (all at once); a session's `locate` uses names it already
    /// knows first.
    pub async fn locate(&self, ino: u64) -> Result<Option<String>, FsError> {
        let (chain, shown) = futures_util::join!(self.remote.key_path(ino), self.grant_paths());
        let chain = match chain {
            Ok(chain) => chain,
            Err(e) if e.errno == errno::ENOENT || e.errno == errno::EACCES => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut shown = shown?;
        let inos: Vec<u64> = chain.nodes.iter().map(|&(i, _)| i).collect();
        let Some(top) = inos.first().and_then(|top| shown.remove(top)) else {
            return Ok(None);
        };
        let names = futures_util::future::join_all(inos.windows(2).map(|w| async move {
            let items = self.readdir(w[0]).await?;
            Ok::<_, FsError>(
                items
                    .into_iter()
                    .find(|i| i.ino == w[1] && !i.is_dot())
                    .map(|i| i.name),
            )
        }))
        .await;
        let mut path = format!("/{top}");
        for name in names {
            let Some(name) = name? else {
                return Ok(None);
            };
            path.push('/');
            path.push_str(&String::from_utf8_lossy(os_bytes::bytes(&name)));
        }
        Ok(Some(path))
    }

    /// Shows this account's grant of `ino` as `label`, on all its devices. A
    /// `/` puts it in a group. This changes nothing for anyone else.
    pub async fn relabel(&self, ino: u64, label: &OsStr) -> Result<(), FsError> {
        check_new_label(label)?;
        let sealed = seal_signed_label(
            &self.identity,
            self.remote.username(),
            &self.identity.public_key(),
            ino,
            os_bytes::bytes(label),
        );
        self.remote.set_grant_label(ino, sealed).await?;
        self.read_roots().await
    }

    /// Opens `grant`'s label, and says who vouches for it.
    pub(super) async fn read_label(&self, grant: &Grant) -> Option<(Vec<u8>, LabelSource)> {
        let (ino, sealed) = (grant.ino, &grant.sealed_label);
        if let Some(signer) = label_signer(sealed)
            && check_username(signer).is_ok()
        {
            if signer == self.remote.username() {
                let me = self.identity.public_key();
                if let Ok(text) = self.identity.open_signed_label(&me, ino, sealed) {
                    return Some((text, LabelSource::Me));
                }
            }
            if let Some(pinned) = self.known.pinned(signer)
                && let Ok(text) = self.identity.open_signed_label(&pinned, ino, sealed)
            {
                return Some((text, LabelSource::Checked));
            }
            if let Ok(served) = self.sender_key(signer).await
                && let Ok(text) = self.identity.open_signed_label(&served, ino, sealed)
            {
                return Some((text, LabelSource::Unchecked));
            }
        }
        let text = self.identity.open_label(ino, sealed).ok()?;
        Some((text, LabelSource::Unsigned))
    }

    /// The name that `grant` shows as in the root.
    ///
    /// The servers could replace a label, to pass a share off as something
    /// else. So once this account has signed its old labels, a label that
    /// nobody it checked vouches for says so. Not for a share from someone it
    /// hasn't checked: the whole share already says that it needs checking,
    /// and its name shouldn't change when they check.
    pub(super) async fn root_label(&self, grant: &Grant) -> OsString {
        self.shown_label(grant).await.0
    }

    /// `root_label`, and whether it may put the grant in a group. Only a label
    /// from someone checked, on a share from someone checked, can: anyone can
    /// choose any label, and a group makes what is in it look like it belongs.
    pub(super) async fn shown_label(&self, grant: &Grant) -> (OsString, bool) {
        let unreadable = || (OsString::from(format!("unreadable-{}", grant.ino)), false);
        let Some((text, source)) = self.read_label(grant).await else {
            return unreadable();
        };
        if label_parts(&text).is_none() {
            return unreadable();
        }
        let mut label = os_bytes::into_name(text);
        let vouched = matches!(source, LabelSource::Me | LabelSource::Checked);
        let checked = self.sender_checked(grant);
        if !vouched && checked && self.load_pin_memory().labels_signed {
            label.push(" (unverified)");
        }
        (label, vouched && checked)
    }

    /// Whether this account checked the sender that `grant` names.
    pub(super) fn sender_checked(&self, grant: &Grant) -> bool {
        grant_sender(&grant.sealed_key).is_ok_and(|sender| {
            sender == self.remote.username() || self.known.pinned(sender).is_some()
        })
    }

    /// Seals this account's labels under its own key, where it can vouch for
    /// them. They then hold whatever the sharer does later, like enrolling
    /// again.
    ///
    /// - A label from someone this account checked: every time.
    /// - An unsigned label: only the first time, trusting what it sees then.
    ///   After that, this records in the sealed pins that it is done, so
    ///   that an unsigned label means someone else wrote it.
    ///
    /// A failure leaves the rest for the next login. Does nothing for a public
    /// link, which only reads, or on servers older than protocol 8.
    pub async fn sign_labels(&self) -> Result<(), FsError> {
        let me = self.remote.username();
        if self.remote.protocol() < since::SIGNED_LABELS || me.starts_with(LINK_PREFIX) {
            return Ok(());
        }
        let done = self.load_pin_memory().labels_signed;
        let own = self.identity.public_key();
        for grant in self.remote.list_grants().await? {
            let Some((text, source)) = self.read_label(&grant).await else {
                continue;
            };
            let sign = match source {
                LabelSource::Checked => true,
                LabelSource::Unsigned => !done,
                LabelSource::Me | LabelSource::Unchecked => false,
            };
            if !sign {
                continue;
            }
            let sealed = seal_signed_label(&self.identity, me, &own, grant.ino, &text);
            match self.remote.set_grant_label(grant.ino, sealed).await {
                // Revoked in the meantime.
                Err(e) if e.errno == errno::ENOENT => {}
                other => other?,
            }
        }
        if !done {
            self.merge_pins(true, &[], &[]).await?;
        }
        Ok(())
    }

    /// Whether `name` is reserved in the root. Only the live root's
    /// `.snapshot` is. A grant with that label gets a different name.
    pub(super) fn reserved(&self, name: &OsStr) -> bool {
        self.remote.snapshot().is_none() && name == SNAPSHOT_DIR
    }

    /// Returns the grant or group that `name` refers to in the root. If the
    /// name is not known, reads the grants again.
    pub async fn root_lookup(&self, name: &OsStr) -> Result<u64, FsError> {
        self.group_lookup(VIRTUAL_ROOT, name).await
    }

    /// Whether `ino` is granted to this account. These inodes are the
    /// root's entries, and their `..` is the root.
    pub fn is_grant_root(&self, ino: u64) -> bool {
        self.roots.lock().unwrap().parents.contains_key(&ino)
    }

    /// Makes a new volume, shown in this account's root as `label`.
    pub async fn create_volume(&self, label: &OsStr, perm: u16) -> Result<Attr, FsError> {
        let parts = check_new_label(label)?;
        if label == SNAPSHOT_DIR || self.label_taken(&parts).await? {
            return Err(FsError::errno(errno::EEXIST));
        }
        let ino = self.remote.allocate_inode().await?;
        let (record, key) = NodeKeys::create(ino, None);
        let me = self.identity.public_key();
        let username = self.remote.username();
        let sealed_key = seal_grant(&self.identity, username, &me, ino, record.version, &key);
        let sealed_label =
            seal_signed_label(&self.identity, username, &me, ino, os_bytes::bytes(label));
        let sealed_grantees = seal_grantees(
            &key,
            record.version,
            ino,
            &[GranteeEntry {
                user: username.to_string(),
                public_key: me,
                writable: true,
                link_secret: None,
            }],
        );
        let new = NewNode {
            ino,
            keys: record.encode(),
            sealed_name: Vec::new(),
        };
        let node = Node::new(ino, record, key)?;
        let attr = self
            .remote
            .create_volume(&new, perm, sealed_key, sealed_label, sealed_grantees)
            .await?;
        self.keep(ino, node);
        // It is made: if this fails, the next look at the root reads them.
        let _ = self.read_roots().await;
        Ok(attr)
    }

    /// Whether the root already shows something at the path `parts`.
    pub(super) async fn label_taken(&self, parts: &[OsString]) -> Result<bool, FsError> {
        let mut at = VIRTUAL_ROOT;
        for part in parts {
            match self.group_lookup(at, part).await {
                Ok(next) => at = next,
                Err(e) if e.errno == errno::ENOENT => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    /// Removes the empty volume shown as `name` in the root or group `dir`. A
    /// group goes by itself, once nothing shows in it.
    pub async fn delete_volume_in(&self, dir: u64, name: &OsStr) -> Result<(), FsError> {
        let ino = self.group_lookup(dir, name).await?;
        if is_group(ino) {
            return Err(FsError::errno(errno::ENOTEMPTY));
        }
        self.remote.delete_volume(ino).await?;
        self.forget_inode(ino);
        // It is gone: if this fails, the next look at the root reads them.
        let _ = self.read_roots().await;
        Ok(())
    }

    /// Removes the empty volume shown in the root as `label`.
    pub async fn delete_volume(&self, label: &OsStr) -> Result<(), FsError> {
        self.delete_volume_in(VIRTUAL_ROOT, label).await
    }
}
