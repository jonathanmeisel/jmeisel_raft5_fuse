//! Plain types shared by core, the server and the client: what an
//! operation takes and returns, independent of the wire format.

use std::ffi::OsString;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
}

/// An inode's attributes, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub kind: Kind,
    pub size: u64,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

/// Who an operation is on behalf of: the identity permission checks use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub uid: u32,
    /// The primary group, which new files are created with.
    pub gid: u32,
    /// Supplementary groups. Whether `gid` is repeated here doesn't
    /// matter.
    pub groups: Vec<u32>,
    /// On an encrypted filesystem, the account: access there is by grant
    /// to it, and the mode bits are left out of it. `None` elsewhere.
    pub user: Option<String>,
}

impl Caller {
    pub fn new(uid: u32, gid: u32, groups: Vec<u32>) -> Self {
        Self {
            uid,
            gid,
            groups,
            user: None,
        }
    }

    /// The same identity, as account `user` of an encrypted filesystem.
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Whether grants, not mode bits, decide what this caller may do.
    pub fn by_grant(&self) -> bool {
        self.user.is_some()
    }

    /// uid 0 passes every permission check.
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }
}

/// A time to set, keeping "now" distinct from an explicit time: POSIX
/// lets anyone who can write a file set its times to now, but only the
/// owner set them to anything else.
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
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirItem {
    pub ino: u64,
    pub kind: Kind,
    /// On an encrypted filesystem, the entry's tag; see `sealed_name`.
    pub name: OsString,
    /// On an encrypted filesystem, the real name, sealed under the
    /// directory's key. Empty for `.` and `..`, and on any other
    /// filesystem.
    pub sealed_name: Vec<u8>,
}

/// A directory granted to a user on an encrypted filesystem: whether they
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

/// What a create on an encrypted filesystem brings: the inode it reserved,
/// and the new node's key record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNode {
    pub ino: u64,
    pub keys: Vec<u8>,
    /// Its real name, sealed under the parent's key. (The name the create
    /// passes is the tag.)
    pub sealed_name: Vec<u8>,
}

/// What a rename on an encrypted filesystem brings: the inode it moves --
/// refused if the name no longer names it -- its key record re-wrapped
/// under the new parent's key if the parent changes (empty if not), and
/// the new name sealed under the new parent's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMove {
    pub ino: u64,
    pub node_keys: Vec<u8>,
    pub sealed_name: Vec<u8>,
}

/// What an encrypted filesystem keeps for an account: enough to check a
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
