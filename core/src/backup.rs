//! Backups: a snapshot's store contents and the objects it points to,
//! copied to a backup space that is not the serving one.
//!
//! The backup space holds, under its prefix:
//!
//! - `objects/...`: one pool of objects, shared by every backup. Object
//!   names are written once and never reused, so a name in the pool is
//!   always the right object, and each backup copies only the names that
//!   the pool does not have yet.
//! - `backups/{name}/kv/{part}`: the store's backup file, sealed to the
//!   operator's public key, in parts.
//! - `backups/{name}/manifest`: what the backup holds. It is written last,
//!   so a backup exists if and only if its manifest does. A backup that
//!   fails part way leaves files with no manifest, and `delete` removes
//!   them.
//!
//! A backup reads a snapshot that an admin took. The snapshot keeps every
//! object it points to from GC and prompt deletion, so the objects stay
//! for the whole copy. An object that is still missing fails the backup.
//!
//! One job at a time changes the backup space: `create` and `delete` hold
//! a lease in the store. So `delete`'s sweep never removes an object that
//! a running `create` copied but has not yet listed in a manifest.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use raft5_client::Client;
use raft5fs_crypto::Key;
use raft5fs_crypto::backup::{
    BACKUP_KEY_LEN, BackupKeyPair, digest, open_part, seal_data_key, seal_part,
};
use raft5fs_objstore::name::{RANDOM_LEN, millis};
use raft5fs_objstore::{Error as ObjError, ObjectName, S3Store};
use raft5fs_proto::pb::{BackupManifest, BackupObject, BackupPart};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

use crate::gc::{LEASE_TTL, mark, release_lease, take_lease};
use crate::layout::BACKUP_LEASE_KEY;
use crate::objects::recorded_grid;
use crate::snapshots::validate_name;
use crate::view::View;

/// The manifest format that this code writes and reads.
const FORMAT: u32 = 1;
/// The most plaintext in one part of the store's backup file. Separate
/// parts keep each upload small, with no multipart upload.
pub const DEFAULT_PART_SIZE: usize = 64 * 1024 * 1024;
/// How many objects are copied at once.
const COPIES: usize = 8;
/// How long a job runs before it renews its lease.
const RENEW_AFTER: Duration = Duration::from_secs(LEASE_TTL.as_secs() / 4);

/// Where backups go: the pool of objects, and the backups' own files.
pub struct BackupStore {
    /// The backup space at `{prefix}objects/`.
    pool: Arc<S3Store>,
    /// The backup space at `{prefix}`.
    files: S3Store,
    part_size: usize,
}

impl BackupStore {
    /// `pool` and `files` must be the same space, with prefixes
    /// `{prefix}objects/` and `{prefix}`.
    pub fn new(pool: S3Store, files: S3Store) -> Self {
        Self {
            pool: Arc::new(pool),
            files,
            part_size: DEFAULT_PART_SIZE,
        }
    }

    /// Sets the part size, so tests can make backups of several parts.
    pub fn with_part_size(mut self, part_size: usize) -> Self {
        self.part_size = part_size;
        self
    }
}

/// What `list` shows for one backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub name: String,
    pub created: SystemTime,
    pub objects: usize,
    /// The objects' total size.
    pub object_bytes: u64,
    /// The size of the sealed store backup.
    pub kv_bytes: u64,
}

/// What `create` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateStats {
    /// Objects that the snapshot points to.
    pub objects: usize,
    /// Of those, the ones not in the pool before, so copied now.
    pub copied: usize,
    pub kv_bytes: u64,
}

/// What `delete` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteStats {
    /// Whether the backup had a manifest.
    pub existed: bool,
    /// Pool objects that no other backup used, so deleted.
    pub objects_deleted: usize,
    /// Backups that failed part way, whose files were deleted.
    pub leftovers_deleted: usize,
}

fn manifest_path(name: &str) -> String {
    format!("backups/{name}/manifest")
}

fn part_path(name: &str, index: usize) -> String {
    format!("backups/{name}/kv/{index:05}")
}

/// A random id for this job's lease.
fn new_holder() -> [u8; 16] {
    let mut holder = [0; 16];
    getrandom::getrandom(&mut holder).expect("the OS has no randomness to give");
    holder
}

/// Holds the backup lease for one job, and renews it as the job goes.
struct Lease<'a> {
    client: &'a Client,
    holder: [u8; 16],
    renewed: SystemTime,
}

impl<'a> Lease<'a> {
    async fn take(client: &'a Client) -> Result<Self, String> {
        let holder = new_holder();
        let now = SystemTime::now();
        if !take_lease(client, BACKUP_LEASE_KEY, holder, now).await? {
            return Err("another backup job is running; try again when it is done".into());
        }
        Ok(Self {
            client,
            holder,
            renewed: now,
        })
    }

    /// Renews the lease if it is due. With `force`, renews it now: before a
    /// step that must not run without the lease.
    async fn renew(&mut self, force: bool) -> Result<(), String> {
        let now = SystemTime::now();
        if !force && now.duration_since(self.renewed).unwrap_or_default() < RENEW_AFTER {
            return Ok(());
        }
        if !take_lease(self.client, BACKUP_LEASE_KEY, self.holder, now).await? {
            return Err("lost the backup lease".into());
        }
        self.renewed = now;
        Ok(())
    }

    async fn release(self) {
        if let Err(why) = release_lease(self.client, BACKUP_LEASE_KEY, self.holder).await {
            eprintln!("backup: {why}; it expires by itself");
        }
    }
}

/// Backs up snapshot `snapshot` to `backup`, under the snapshot's name.
///
/// - `serving` is the space the filesystem keeps objects in. It may be
///   `None` only if the filesystem keeps no objects.
/// - `public_key` is the operator's: only its key pair can open the store
///   backup.
///
/// Steps, under the backup lease:
/// - Check that the snapshot exists and has no backup yet.
/// - Mark the objects the snapshot points to, and copy the ones that the
///   pool does not have. A missing object fails the backup.
/// - Take the store's backup of the snapshot into a temporary file, then
///   seal and upload it in parts.
/// - Write the manifest.
pub async fn create(
    client: &Client,
    serving: Option<Arc<S3Store>>,
    backup: &BackupStore,
    public_key: &[u8; BACKUP_KEY_LEN],
    snapshot: &str,
) -> Result<CreateStats, String> {
    validate_name(snapshot)?;
    let mut lease = Lease::take(client).await?;
    let result = create_locked(client, serving, backup, public_key, snapshot, &mut lease).await;
    lease.release().await;
    result
}

async fn create_locked(
    client: &Client,
    serving: Option<Arc<S3Store>>,
    backup: &BackupStore,
    public_key: &[u8; BACKUP_KEY_LEN],
    snapshot: &str,
    lease: &mut Lease<'_>,
) -> Result<CreateStats, String> {
    let mut stats = CreateStats::default();
    let info = client
        .list_snapshots()
        .await
        .map_err(|e| format!("listing snapshots: {e}"))?
        .into_iter()
        .find(|s| s.id == snapshot.as_bytes())
        .ok_or_else(|| format!("there is no snapshot {snapshot}"))?;
    match backup.files.get_file(&manifest_path(snapshot)).await {
        Ok(_) => return Err(format!("snapshot {snapshot} already has a backup")),
        Err(ObjError::NotFound(_)) => {}
        Err(e) => return Err(format!("checking for a backup of {snapshot}: {e}")),
    }

    let grid = recorded_grid(client).await?;
    let mut referenced = HashSet::new();
    if let Some(grid) = grid {
        mark(View::at(client, snapshot.as_bytes()), grid, &mut referenced)
            .await
            .map_err(|e| format!("finding the snapshot's objects: {e}"))?;
    }
    stats.objects = referenced.len();
    let objects = if referenced.is_empty() {
        Vec::new()
    } else {
        let serving = serving
            .ok_or("this filesystem keeps objects, so a backup needs the object store options")?;
        let (objects, copied) = copy_objects(&serving, &backup.pool, referenced, lease).await?;
        stats.copied = copied;
        objects
    };

    lease.renew(true).await?;
    let data_key = Key::random();
    let parts = upload_kv(client, backup, snapshot, &data_key, lease).await?;
    stats.kv_bytes = parts.iter().map(|p| p.sealed_len).sum();

    let manifest = BackupManifest {
        format: FORMAT,
        name: snapshot.to_string(),
        snapshot_seq: info.seq,
        created_unix_ms: millis(SystemTime::now()),
        grid_from_index: grid.map_or(0, |g| g.from_index),
        grid_per_block: grid.map_or(0, |g| g.per_block),
        sealed_data_key: seal_data_key(public_key, &data_key),
        parts,
        objects,
    };
    // Last, so a backup with a manifest is whole.
    lease.renew(true).await?;
    backup
        .files
        .put_file(&manifest_path(snapshot), manifest.encode_to_vec(), true)
        .await
        .map_err(|e| format!("writing the manifest: {e}"))?;
    Ok(stats)
}

/// Copies each object in `wanted` that `pool` lacks from `serving` to
/// `pool`, a few at a time. Returns every wanted object with its size, and
/// how many it copied.
async fn copy_objects(
    serving: &Arc<S3Store>,
    pool: &Arc<S3Store>,
    wanted: HashSet<ObjectName>,
    lease: &mut Lease<'_>,
) -> Result<(Vec<BackupObject>, usize), String> {
    let have: std::collections::HashMap<ObjectName, u64> = pool
        .list()
        .await
        .map_err(|e| format!("listing the backup pool: {e}"))?
        .into_iter()
        .filter_map(|l| Some((l.name?, l.size)))
        .collect();
    let mut objects = Vec::with_capacity(wanted.len());
    let mut missing = Vec::new();
    for name in wanted {
        match have.get(&name) {
            Some(&size) => objects.push(backup_object(&name, size)),
            None => missing.push(name),
        }
    }
    let copied = missing.len();
    let results = for_each_object(serving, pool, missing, Some(lease)).await?;
    objects.extend(results);
    Ok((objects, copied))
}

/// Copies each of `names` from `from` to `to`, `COPIES` at a time,
/// renewing `lease` (if any) as it goes. An object that `to` already has
/// counts as copied: names are written once. An object that `from` lacks
/// fails the whole copy.
async fn for_each_object(
    from: &Arc<S3Store>,
    to: &Arc<S3Store>,
    names: Vec<ObjectName>,
    mut lease: Option<&mut Lease<'_>>,
) -> Result<Vec<BackupObject>, String> {
    let mut done = Vec::with_capacity(names.len());
    let mut names = names.into_iter();
    let mut running = JoinSet::new();
    loop {
        while running.len() < COPIES
            && let Some(name) = names.next()
        {
            let (from, to) = (Arc::clone(from), Arc::clone(to));
            running.spawn(async move {
                let body = from.get(&name).await.map_err(|e| match e {
                    ObjError::NotFound(key) => {
                        format!("object {key} is gone, though the snapshot points to it")
                    }
                    e => format!("reading object {}: {e}", name.key(from.prefix())),
                })?;
                let size = body.len() as u64;
                match to.put(&name, body).await {
                    Ok(()) | Err(ObjError::AlreadyExists) => Ok(backup_object(&name, size)),
                    Err(e) => Err(format!("writing object {}: {e}", name.key(to.prefix()))),
                }
            });
        }
        let Some(result) = running.join_next().await else {
            return Ok(done);
        };
        done.push(result.map_err(|e| format!("a copy failed: {e}"))??);
        if let Some(lease) = lease.as_deref_mut() {
            lease.renew(false).await?;
        }
    }
}

fn backup_object(name: &ObjectName, size: u64) -> BackupObject {
    BackupObject {
        ino: name.ino,
        minted_ms: name.minted_ms,
        random: name.random.to_vec(),
        size,
    }
}

fn object_name(object: &BackupObject) -> Result<ObjectName, String> {
    let random: [u8; RANDOM_LEN] = object
        .random
        .as_slice()
        .try_into()
        .map_err(|_| "a manifest names an object badly".to_string())?;
    Ok(ObjectName {
        ino: object.ino,
        minted_ms: object.minted_ms,
        random,
    })
}

/// A file that is deleted when this is dropped. Made readable by its owner
/// only.
struct TempFile(PathBuf);

impl TempFile {
    fn create() -> Result<(Self, std::fs::File), String> {
        let path = std::env::temp_dir().join(format!(
            "raft5fs-backup-{}",
            new_holder()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options
            .open(&path)
            .map_err(|e| format!("making a temporary file: {e}"))?;
        Ok((Self(path), file))
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Takes the store's backup of `snapshot`, then seals and uploads it in
/// parts. The store streams a backup only once, so it goes to a temporary
/// file first. A large store takes a while, so this renews `lease` as it
/// goes.
async fn upload_kv(
    client: &Client,
    backup: &BackupStore,
    snapshot: &str,
    key: &Key,
    lease: &mut Lease<'_>,
) -> Result<Vec<BackupPart>, String> {
    let (temp, file) = TempFile::create()?;
    let mut file = tokio::fs::File::from_std(file);
    {
        let dump = client.backup(Some(snapshot.as_bytes()), &mut file);
        tokio::pin!(dump);
        loop {
            tokio::select! {
                done = &mut dump => {
                    done.map_err(|e| format!("taking the store's backup: {e}"))?;
                    break;
                }
                _ = tokio::time::sleep(RENEW_AFTER) => lease.renew(true).await?,
            }
        }
    }
    file.flush()
        .await
        .map_err(|e| format!("writing the store's backup: {e}"))?;
    drop(file);

    let mut file = tokio::fs::File::open(&temp.0)
        .await
        .map_err(|e| format!("reading the store's backup: {e}"))?;
    let total = file
        .metadata()
        .await
        .map_err(|e| format!("reading the store's backup: {e}"))?
        .len();
    let size = backup.part_size as u64;
    let count = total.div_ceil(size).max(1) as usize;
    let mut parts = Vec::with_capacity(count);
    for index in 0..count {
        let len = size.min(total - index as u64 * size) as usize;
        let mut plain = vec![0; len];
        file.read_exact(&mut plain)
            .await
            .map_err(|e| format!("reading the store's backup: {e}"))?;
        let sealed = seal_part(key, snapshot, index as u32, index + 1 == count, &plain);
        parts.push(BackupPart {
            plain_len: len as u64,
            sealed_len: sealed.len() as u64,
            sha256: digest(&sealed).to_vec(),
        });
        backup
            .files
            .put_file(&part_path(snapshot, index), sealed, false)
            .await
            .map_err(|e| format!("uploading part {index} of the store's backup: {e}"))?;
        lease.renew(false).await?;
    }
    Ok(parts)
}

async fn read_manifest(backup: &BackupStore, name: &str) -> Result<BackupManifest, String> {
    let bytes = backup
        .files
        .get_file(&manifest_path(name))
        .await
        .map_err(|e| match e {
            ObjError::NotFound(_) => format!("there is no backup {name}"),
            e => format!("reading the manifest of {name}: {e}"),
        })?;
    let manifest = BackupManifest::decode(bytes.as_slice())
        .map_err(|e| format!("the manifest of {name} is damaged: {e}"))?;
    if manifest.format != FORMAT {
        return Err(format!(
            "backup {name} has format {}; this version reads {FORMAT}",
            manifest.format
        ));
    }
    Ok(manifest)
}

/// The names of the backups with a manifest, and of the directories under
/// `backups/` without one.
async fn backup_names(
    backup: &BackupStore,
) -> Result<(BTreeSet<String>, BTreeSet<String>), String> {
    let files = backup
        .files
        .list_files("backups/")
        .await
        .map_err(|e| format!("listing backups: {e}"))?;
    let mut whole = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (path, _) in files {
        let Some((name, rest)) = path
            .strip_prefix("backups/")
            .and_then(|p| p.split_once('/'))
        else {
            continue;
        };
        seen.insert(name.to_string());
        if rest == "manifest" {
            whole.insert(name.to_string());
        }
    }
    let partial = seen.difference(&whole).cloned().collect();
    Ok((whole, partial))
}

/// Every backup with a manifest, in name order.
pub async fn list(backup: &BackupStore) -> Result<Vec<BackupInfo>, String> {
    let (whole, _) = backup_names(backup).await?;
    let mut infos = Vec::with_capacity(whole.len());
    for name in whole {
        let manifest = read_manifest(backup, &name).await?;
        infos.push(BackupInfo {
            name,
            created: UNIX_EPOCH + Duration::from_millis(manifest.created_unix_ms),
            objects: manifest.objects.len(),
            object_bytes: manifest.objects.iter().map(|o| o.size).sum(),
            kv_bytes: manifest.parts.iter().map(|p| p.sealed_len).sum(),
        });
    }
    Ok(infos)
}

/// Deletes backup `name`, then sweeps the backup space. The snapshot it
/// came from is not touched.
///
/// Steps, under the backup lease:
/// - Delete the manifest: from here the backup is gone.
/// - Delete the backup's other files.
/// - Delete the files of backups that failed part way (no manifest).
/// - Delete the pool objects that no remaining manifest names.
pub async fn delete(
    client: &Client,
    backup: &BackupStore,
    name: &str,
) -> Result<DeleteStats, String> {
    validate_name(name)?;
    let mut lease = Lease::take(client).await?;
    let result = delete_locked(backup, name, &mut lease).await;
    lease.release().await;
    result
}

async fn delete_locked(
    backup: &BackupStore,
    name: &str,
    lease: &mut Lease<'_>,
) -> Result<DeleteStats, String> {
    let mut stats = DeleteStats::default();
    let (whole, _) = backup_names(backup).await?;
    stats.existed = whole.contains(name);
    if stats.existed {
        backup
            .files
            .delete_files(&[manifest_path(name)])
            .await
            .map_err(|e| format!("deleting the manifest of {name}: {e}"))?;
    }

    let (whole, partial) = backup_names(backup).await?;
    let mut doomed = Vec::new();
    for leftover in &partial {
        let files = backup
            .files
            .list_files(&format!("backups/{leftover}/"))
            .await
            .map_err(|e| format!("listing the files of {leftover}: {e}"))?;
        doomed.extend(files.into_iter().map(|(path, _)| path));
    }
    stats.leftovers_deleted = partial.len() - usize::from(stats.existed && partial.contains(name));
    lease.renew(true).await?;
    backup
        .files
        .delete_files(&doomed)
        .await
        .map_err(|e| format!("deleting backup files: {e}"))?;

    let mut kept = HashSet::new();
    for other in &whole {
        for object in read_manifest(backup, other).await?.objects {
            kept.insert(object_name(&object)?);
        }
    }
    let unused: Vec<ObjectName> = backup
        .pool
        .list()
        .await
        .map_err(|e| format!("listing the backup pool: {e}"))?
        .into_iter()
        .filter_map(|l| l.name)
        .filter(|n| !kept.contains(n))
        .collect();
    lease.renew(true).await?;
    backup
        .pool
        .delete(&unused)
        .await
        .map_err(|e| format!("deleting unused objects: {e}"))?;
    stats.objects_deleted = unused.len();
    Ok(stats)
}

/// Opens backup `name`'s store backup with the operator's `key_pair` and
/// writes it to `out`, for raft5 to restore from. It writes to a file
/// next to `out` first, and renames it only when whole.
pub async fn fetch_kv(
    backup: &BackupStore,
    key_pair: &BackupKeyPair,
    name: &str,
    out: &Path,
) -> Result<u64, String> {
    let manifest = read_manifest(backup, name).await?;
    let key = key_pair
        .open_data_key(&manifest.sealed_data_key)
        .map_err(|_| format!("backup {name} was not sealed to this key"))?;
    if manifest.parts.is_empty() {
        return Err(format!("backup {name} has no store backup"));
    }
    let mut partial = out.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let mut file = tokio::fs::File::create(&partial)
        .await
        .map_err(|e| format!("creating {}: {e}", partial.display()))?;
    let mut written = 0;
    let count = manifest.parts.len();
    for (index, part) in manifest.parts.iter().enumerate() {
        let sealed = backup
            .files
            .get_file(&part_path(name, index))
            .await
            .map_err(|e| format!("reading part {index}: {e}"))?;
        if sealed.len() as u64 != part.sealed_len || digest(&sealed).as_slice() != part.sha256 {
            return Err(format!("part {index} of backup {name} is damaged"));
        }
        let plain = open_part(&key, name, index as u32, index + 1 == count, &sealed)
            .map_err(|e| format!("part {index} of backup {name}: {e}"))?;
        file.write_all(&plain)
            .await
            .map_err(|e| format!("writing {}: {e}", partial.display()))?;
        written += plain.len() as u64;
    }
    file.sync_all()
        .await
        .map_err(|e| format!("writing {}: {e}", partial.display()))?;
    tokio::fs::rename(&partial, out)
        .await
        .map_err(|e| format!("renaming to {}: {e}", out.display()))?;
    Ok(written)
}

/// Copies every object that backup `name` holds from the pool into
/// `serving`, the space a restored filesystem will keep objects in.
/// Returns how many objects the backup holds.
pub async fn restore_objects(
    backup: &BackupStore,
    serving: Arc<S3Store>,
    name: &str,
) -> Result<usize, String> {
    let manifest = read_manifest(backup, name).await?;
    let names = manifest
        .objects
        .iter()
        .map(object_name)
        .collect::<Result<Vec<_>, _>>()?;
    let count = names.len();
    for_each_object(&backup.pool, &serving, names, None).await?;
    Ok(count)
}
