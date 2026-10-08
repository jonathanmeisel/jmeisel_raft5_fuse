//! Plain types shared by core, the server and the client: what an
//! operation takes and returns, independent of the wire format.

use std::ffi::OsString;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
}

/// An inode's attributes, as stored. There are no owners: access goes by
/// grants, and a mount shows its own user as the owner of everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub kind: Kind,
    pub size: u64,
    pub perm: u16,
    pub nlink: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

/// Who an operation is on behalf of: the account whose grants decide what
/// it may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub user: String,
}

impl Caller {
    pub fn new(user: impl Into<String>) -> Self {
        Self { user: user.into() }
    }
}

/// A time to set, keeping "now" -- the server's clock -- distinct from an
/// explicit time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTime {
    Now,
    At(SystemTime),
}

impl SetTime {
    pub fn resolve(self) -> SystemTime {
        match self {
            Self::Now => SystemTime::now(),
            Self::At(t) => t,
        }
    }
}

/// The attribute changes one `setattr` asks for; `None` leaves a field
/// as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirItem {
    pub ino: u64,
    pub kind: Kind,
    /// The entry's tag; see `sealed_name`.
    pub name: OsString,
    /// The real name, sealed under the directory's key. Empty for `.`
    /// and `..`.
    pub sealed_name: Vec<u8>,
}

/// A directory granted to a user: whether they
/// may write under it, and its key at `key_version`, sealed to them, with
/// the name it shows up as in their root, also sealed to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub ino: u64,
    pub writable: bool,
    pub key_version: u32,
    pub sealed_key: Vec<u8>,
    pub sealed_label: Vec<u8>,
}

/// A user's grant over an inode, and the key record of each node from the
/// granted directory down to it, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPath {
    pub grant: Grant,
    pub nodes: Vec<(u64, Vec<u8>)>,
}

/// Someone a node is granted to, as the server knows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grantee {
    pub user: String,
    pub public_key: Vec<u8>,
    pub writable: bool,
}

/// A node at or under some directory that is granted to someone: the path
/// from that directory down to it (both included), and its grantees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedNode {
    pub ino: u64,
    pub path: Vec<u64>,
    pub grantees: Vec<Grantee>,
    /// Who the node's key holders say it is granted to (raft5fs-crypto's
    /// `grantees`), which `grantees` must agree with.
    pub sealed_grantees: Vec<u8>,
    /// The store's seq for `sealed_grantees`, for a grant to say which
    /// list it replaces.
    pub grantees_seq: u64,
}

/// A new key for one node: its key record a version on from
/// `expected_version`, and each of its grants re-sealed under it -- or,
/// with an empty sealed key, removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub ino: u64,
    pub expected_version: u32,
    pub node_keys: Vec<u8>,
    pub grants: Vec<(String, Vec<u8>)>,
    /// The grantees as the rotation leaves them, sealed under the new key;
    /// empty if none are left.
    pub sealed_grantees: Vec<u8>,
}

/// A file chunk as stored: sealed, with the store's sequence number for
/// it. `blob` is `None` for a hole, or for a chunk `unchanged`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    pub index: u64,
    pub seq: u64,
    pub blob: Option<Vec<u8>>,
    /// Still at the seq the client said it held, so `blob` wasn't sent.
    pub unchanged: bool,
}

/// A sealed chunk to store, if it is still at `expected_seq` (or whatever
/// it holds, without one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkWrite {
    pub index: u64,
    pub expected_seq: Option<u64>,
    pub blob: Vec<u8>,
}

/// What a create brings: the inode it reserved,
/// and the new node's key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNode {
    pub ino: u64,
    pub keys: Vec<u8>,
    /// Its real name, sealed under the parent's key. (The name the create
    /// passes is the tag.)
    pub sealed_name: Vec<u8>,
}

/// What a rename brings: the inode it moves --
/// refused if the name no longer names it -- its key record re-wrapped
/// under the new parent's key if the parent changes (empty if not), and
/// the new name sealed under the new parent's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMove {
    pub ino: u64,
    pub node_keys: Vec<u8>,
    pub sealed_name: Vec<u8>,
}

/// A snapshot of the filesystem, which mounts show at `/.snapshot/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    /// When it was taken, by the clock of whoever took it.
    pub created: SystemTime,
}

/// The most entry names one re-seal takes.
pub const RESEAL_NAMES_BATCH: usize = 256;

/// A directory entry's name sealed again, under the directory's current
/// key: the entry filed under `tag`, which must still name `ino`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResealedName {
    pub tag: OsString,
    pub ino: u64,
    pub sealed_name: Vec<u8>,
}

/// What the filesystem keeps for an account: enough to check a
/// login and to hand the client back its wrapped private key, and nothing
/// that opens anything. The fields are raft5fs-crypto's encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeys {
    pub salt: Vec<u8>,
    pub kdf_params: Vec<u8>,
    pub verifier: Vec<u8>,
    pub public_key: Vec<u8>,
    pub wrapped_private_key: Vec<u8>,
}

/// An errno plus a message. The errno is what a caller hands the kernel;
/// the message carries the real cause (usually the store's own error
/// text) so it can be logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsError {
    pub errno: i32,
    pub message: String,
}

impl FsError {
    pub fn new(errno: i32, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }

    /// An error whose errno says everything there is to say.
    pub fn errno(errno: i32) -> Self {
        Self::new(errno, std::io::Error::from_raw_os_error(errno).to_string())
    }
}

/// The longest account name there can be.
pub const MAX_USERNAME_LEN: usize = 64;

/// Whether `user` can be an account's name: a lower-case letter or `_`,
/// then up to 63 more of those, digits, `.` and `-`. Names end up in
/// store keys, in the known-keys file a client pins public keys in (one
/// `name key` line each), and in front of people, so nothing that could
/// break a line or a field, or look like another name, gets in. Both ends
/// check: the server where an account is made or named, and the client
/// on every name a server hands it.
pub fn check_username(user: &str) -> Result<(), FsError> {
    let mut chars = user.chars();
    let ok = user.len() <= MAX_USERNAME_LEN
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(FsError::new(
            libc::EINVAL,
            format!(
                "bad username {user:?}: it must start with a lower-case letter or _, \
                 then up to {} more lower-case letters, digits, _ . or -",
                MAX_USERNAME_LEN - 1
            ),
        ))
    }
}

#[cfg(feature = "raft5")]
impl From<raft5_client::Error> for FsError {
    fn from(e: raft5_client::Error) -> Self {
        Self::new(libc::EIO, e.to_string())
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FsError {}

/// A failed write: how many leading bytes had already been stored (each
/// batch commits on its own, so a failure part-way leaves the earlier
/// batches in place) and why it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteError {
    pub written: usize,
    pub error: FsError,
}

#[cfg(test)]
mod username_tests {
    use super::*;

    #[test]
    fn plain_names_pass_and_anything_that_could_break_a_line_or_key_fails() {
        for good in ["alice", "_svc", "bob.smith-2", &"a".repeat(64)] {
            check_username(good).unwrap();
        }
        for bad in [
            "",
            "Alice",
            "1abc",
            "-x",
            "a b",
            "a\nbob 00",
            "a\0b",
            "a/b",
            "ålice",
            &"a".repeat(65),
        ] {
            assert!(check_username(bad).is_err(), "{bad:?}");
        }
    }
}
