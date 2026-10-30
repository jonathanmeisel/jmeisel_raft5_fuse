//! Plain types that core, the server, and the client share: what each
//! operation takes and returns, separate from the wire format.

use std::ffi::OsString;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
}

/// An inode's attributes, as stored. There are no owners: grants control
/// access, and a mount shows its own user as the owner of everything.
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
    pub layout: Layout,
}

/// Where a file's data is stored. It does not change after the file is
/// made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Layout {
    /// Every chunk is in the store. This is the layout of every directory,
    /// and of every file made before object storage was turned on.
    #[default]
    Inline,
    /// Chunks before the filesystem's `ObjectGrid::from_index` are in the
    /// store, and the rest are in blocks in object storage.
    Hybrid,
}

/// How a hybrid file groups its chunks from `from_index` up into blocks,
/// one object for each block. Block `b` holds chunks `from_index + b *
/// per_block` up to (but not including) `from_index + (b + 1) * per_block`.
/// It never changes for the filesystem.
///
/// The chunk grid is the same in both layouts: a block is only consecutive
/// chunks stored together. So a chunk's index, and everything keyed or
/// sealed by it, means the same in both layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectGrid {
    pub from_index: u64,
    pub per_block: u32,
}

impl ObjectGrid {
    /// Whether chunk `index` of a hybrid file is in a block.
    pub fn in_blocks(&self, index: u64) -> bool {
        index >= self.from_index
    }

    /// The first chunk index of the block that holds chunk `index`. The
    /// block's pointer is stored under this index. Use only for an index
    /// that is `in_blocks`.
    pub fn block_start(&self, index: u64) -> u64 {
        let per = u64::from(self.per_block);
        self.from_index + (index - self.from_index) / per * per
    }

    /// The position of chunk `index` in its block. Use only for an index
    /// that is `in_blocks`.
    pub fn segment(&self, index: u64) -> u32 {
        ((index - self.from_index) % u64::from(self.per_block)) as u32
    }
}

/// The random part of an object's name.
pub const BLOCK_RANDOM_LEN: usize = 16;

/// An object that holds one block of a file (see `ObjectGrid`): `nseg`
/// chunks, all under key version `version`. Each chunk is padded with zeros
/// to the chunk size, then sealed, and the chunks are stored back to back.
///
/// Its name is the file's inode, `minted_ms`, and `random`. The inode comes
/// from the key that stores the pointer, so a pointer can only name its own
/// file's objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    pub version: u32,
    pub minted_ms: u64,
    pub random: [u8; BLOCK_RANDOM_LEN],
    pub nseg: u32,
}

/// A block that a read refers to, and a presigned URL to fetch it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockUrl {
    pub block: BlockRef,
    pub url: String,
}

/// The account that an operation is for. Its grants control what the
/// operation can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub user: String,
}

impl Caller {
    pub fn new(user: impl Into<String>) -> Self {
        Self { user: user.into() }
    }
}

/// A time to set. "Now" (the server's clock) is a separate case from an
/// explicit time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTime {
    Now,
    At(SystemTime),
}

impl SetTime {
    pub fn resolve(self) -> SystemTime {
        match self {
            Self::Now => crate::clock::now(),
            Self::At(t) => t,
        }
    }
}

/// The attribute changes that one `setattr` asks for. `None` leaves a field
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

/// A directory granted to a user: whether they can write below it, its key
/// at `key_version` sealed to them, and its label in their root, also
/// sealed to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub ino: u64,
    pub writable: bool,
    pub key_version: u32,
    pub sealed_key: Vec<u8>,
    pub sealed_label: Vec<u8>,
}

/// A user's grant above an inode, and the key record of each node from the
/// granted directory down to the inode, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPath {
    pub grant: Grant,
    pub nodes: Vec<(u64, Vec<u8>)>,
}

/// A user that a node is granted to, as the server knows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grantee {
    pub user: String,
    pub public_key: Vec<u8>,
    pub writable: bool,
}

/// A node at or below a directory, that is granted to some user: the path
/// from the directory down to the node (both included), and its grantees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedNode {
    pub ino: u64,
    pub path: Vec<u64>,
    pub grantees: Vec<Grantee>,
    /// The users that the node's key holders say it is granted to
    /// (raft5fs-crypto's `grantees`). `grantees` must agree with this list.
    pub sealed_grantees: Vec<u8>,
    /// The store's seq for `sealed_grantees`. A grant sends it to say which
    /// list it replaces.
    pub grantees_seq: u64,
}

/// A new key for one node: its key record one version after
/// `expected_version`, and each of its grants sealed again under the new
/// key. A grant with an empty sealed key is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub ino: u64,
    pub expected_version: u32,
    pub node_keys: Vec<u8>,
    pub grants: Vec<(String, Vec<u8>)>,
    /// The grantees after the rotation, sealed under the new key. Empty if
    /// no grantees are left.
    pub sealed_grantees: Vec<u8>,
}

/// A file chunk as stored, with the store's sequence number for it. For a
/// chunk in a block, this is the block's sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    pub index: u64,
    pub seq: u64,
    pub body: ChunkBody,
    /// The chunk is still at the seq that the client has, so the server did
    /// not send its body (it is `Hole`).
    pub unchanged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkBody {
    /// Never written: all zeros. An `unchanged` chunk also has this body.
    Hole,
    /// The chunk, sealed.
    Inline(Vec<u8>),
    /// Segment `segment` of block `Chunks::blocks[block]`.
    Segment { block: u32, segment: u32 },
}

/// What a chunk read returns: the file's attributes (for its size), the
/// chunks, and the blocks that hold their segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunks {
    pub attr: Attr,
    pub chunks: Vec<SealedChunk>,
    pub blocks: Vec<BlockUrl>,
}

/// A chunk or a block to store. If `expected_seq` is set, the server stores
/// it only if the stored item is still at that seq. If not, it replaces
/// whatever is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkWrite {
    pub index: u64,
    pub expected_seq: Option<u64>,
    pub body: WriteBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteBody {
    /// A sealed chunk.
    Inline(Vec<u8>),
    /// A block already uploaded through `prepare_uploads`, stored at its
    /// first chunk index.
    Block(BlockRef),
}

/// A block to upload: its first chunk index, and how many segments it will
/// hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockUpload {
    pub index: u64,
    pub nseg: u32,
}

/// Where to upload a block: the object's name, and a presigned PUT for
/// exactly its length that works one time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedUpload {
    pub minted_ms: u64,
    pub random: [u8; BLOCK_RANDOM_LEN],
    pub url: String,
}

/// What a create sends: the inode that it reserved, and the new node's key
/// record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNode {
    pub ino: u64,
    pub keys: Vec<u8>,
    /// Its real name, sealed under the parent's key. The create sends the
    /// tag as the name.
    pub sealed_name: Vec<u8>,
}

/// What a rename sends:
///
/// - the inode that moves (the server refuses the move if the name no
///   longer points to it);
/// - its key record, wrapped again under the new parent's key if the parent
///   changes (empty if not);
/// - the new name, sealed under the new parent's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMove {
    pub ino: u64,
    pub node_keys: Vec<u8>,
    pub sealed_name: Vec<u8>,
}

/// A snapshot of the filesystem. Mounts show it at `/.snapshot/<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    /// When it was taken, by the clock of the machine that took it.
    pub created: SystemTime,
}

/// The most entry names that one re-seal request takes.
pub const RESEAL_NAMES_BATCH: usize = 256;

/// A directory entry's name, sealed again under the directory's current
/// key. The entry is filed under `tag`, which must still point to `ino`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResealedName {
    pub tag: OsString,
    pub ino: u64,
    pub sealed_name: Vec<u8>,
}

/// What the filesystem keeps for an account: enough to check a login and to
/// give the client its wrapped private key, and nothing that opens
/// anything. The fields use raft5fs-crypto's encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeys {
    pub salt: Vec<u8>,
    pub kdf_params: Vec<u8>,
    pub verifier: Vec<u8>,
    pub public_key: Vec<u8>,
    pub wrapped_private_key: Vec<u8>,
}

/// What an account may do beyond what its grants allow, as a set of bits.
/// Grants decide everything about existing files; these decide what an
/// account may start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Caps(u32);

impl Caps {
    pub const NONE: Caps = Caps(0);
    /// Make new volumes (top-level folders).
    pub const VOLUMES: Caps = Caps(1);
    // Bit 2 was `invite`, before only admins could invite. Records that
    // still have it read as not having it.
    /// Make public links.
    pub const LINKS: Caps = Caps(4);
    /// Manage users: invite them, change what they may do, let them enroll
    /// again, and remove them.
    pub const ADMIN: Caps = Caps(8);
    /// Every capability, with its name.
    pub const NAMED: [(Caps, &'static str); 3] = [
        (Caps::VOLUMES, "volumes"),
        (Caps::LINKS, "links"),
        (Caps::ADMIN, "admin"),
    ];

    /// The capabilities in `bits`. Bits that no capability uses are
    /// dropped, so a newer peer's capabilities never read as more.
    pub fn from_bits(bits: u32) -> Self {
        let all = Self::NAMED.iter().fold(0, |all, (c, _)| all | c.0);
        Caps(bits & all)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    /// Whether every capability in `other` is in `self`.
    pub fn contains(self, other: Caps) -> bool {
        self.0 & other.0 == other.0
    }

    /// `self` with `other` added (`on`) or removed.
    pub fn with(self, other: Caps, on: bool) -> Self {
        if on {
            Caps(self.0 | other.0)
        } else {
            Caps(self.0 & !other.0)
        }
    }

    /// The capability called `name`.
    pub fn named(name: &str) -> Option<Self> {
        Self::NAMED
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(c, _)| *c)
    }

    /// The names of the capabilities in `self`, in a fixed order.
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMED
            .iter()
            .filter(|(c, _)| self.contains(*c))
            .map(|(_, n)| *n)
            .collect()
    }
}

impl std::ops::BitOr for Caps {
    type Output = Caps;
    fn bitor(self, other: Caps) -> Caps {
        Caps(self.0 | other.0)
    }
}

/// Who or what an account is for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AccountKind {
    #[default]
    Person,
    /// A public link: an account whose password is in a URL.
    Link,
}

/// What the servers keep about an account besides its keys: what it may
/// do, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub caps: Caps,
    pub kind: AccountKind,
    /// The user who invited this account. Empty for one that an
    /// administrator added.
    pub invited_by: String,
    /// When the account was added, in seconds since the Unix epoch. 0 if
    /// not known.
    pub created: u64,
    /// For a link: the user who made it.
    pub owner: String,
    /// For a link: when it stops working, in seconds since the Unix epoch.
    pub expires: Option<u64>,
    /// For a link: the folder it shares, as its maker said.
    pub folder: u64,
    /// For a link: a note for its maker alone (the folder's path), sealed
    /// to their key, so the servers can't read it.
    pub note: Vec<u8>,
}

impl AccountInfo {
    /// Whether this is a link that has stopped working at `now` (seconds
    /// since the Unix epoch).
    pub fn expired(&self, now: u64) -> bool {
        self.kind == AccountKind::Link && self.expires.is_some_and(|at| at <= now)
    }
}

impl Default for AccountInfo {
    /// An account with no record: one that an administrator added before
    /// capabilities existed. It may make volumes, as every account could
    /// then.
    fn default() -> Self {
        Self {
            caps: Caps::VOLUMES,
            kind: AccountKind::Person,
            invited_by: String::new(),
            created: 0,
            owner: String::new(),
            expires: None,
            folder: 0,
            note: Vec::new(),
        }
    }
}

/// A public link, as its maker sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAccount {
    pub user: String,
    pub info: AccountInfo,
}

/// The longest note that a link can hold.
pub const MAX_LINK_NOTE: usize = 4096;

/// An account, as an administrator sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub user: String,
    /// Whether it has keys. If not, it has only an invitation (a code).
    pub enrolled: bool,
    pub info: AccountInfo,
}

/// A folder or file that no account can reach any more, with everything
/// in it: the account that could was removed, or enrolled again. Its names
/// are sealed under keys nobody has, so only its shape shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreachable {
    pub ino: u64,
    /// Whether it is a whole volume (a top-level folder).
    pub volume: bool,
    pub files: u64,
    /// Folders, itself included if it is one.
    pub folders: u64,
    /// The files' sizes, added up.
    pub bytes: u64,
    /// When anything in it last changed.
    pub modified: SystemTime,
}

/// Who owns a volume: whose quota everything in it counts against. The
/// owner always has read-write access to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeInfo {
    /// `None` for a volume with no owner yet (from before owners, with
    /// several writers), which counts against nobody.
    pub owner: Option<String>,
    /// A transfer the owner offered and the recipient hasn't answered:
    /// to whom, and when (seconds since the Unix epoch).
    pub offer: Option<(String, u64)>,
}

/// How much a user's volumes hold, as their owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Storage {
    /// File sizes added up, as last measured and counted since.
    pub used: u64,
    /// When last measured, in seconds since the Unix epoch; 0 if never.
    pub measured_at: u64,
}

/// A folder's size: everything inside it, as last measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderSize {
    pub ino: u64,
    pub bytes: u64,
    pub files: u64,
    /// When measured, in seconds since the Unix epoch.
    pub measured_at: u64,
}

/// What every public link's account name starts with. Nobody can invite a
/// user with such a name.
pub const LINK_PREFIX: &str = "link-";

/// An errno and a message. The caller gives the errno to the kernel. The
/// message has the real cause (usually the store's own error text), so it
/// can be logged.
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

    /// An error that needs no message beyond its errno.
    pub fn errno(errno: i32) -> Self {
        Self::new(errno, crate::errno::describe(errno))
    }
}

/// The longest possible account name.
pub const MAX_USERNAME_LEN: usize = 64;

/// Whether `user` is a valid account name: a lower-case letter or `_`, then
/// up to 63 more of those, digits, `.`, or `-`.
///
/// Names go into store keys, into the known-keys file where a client pins
/// public keys (one `name key` line each), and in front of people. So the
/// rules block anything that could break a line or a field, or look like
/// another name. Both sides check: the server when it makes or names an
/// account, and the client on every name that a server gives it.
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
            crate::errno::EINVAL,
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
        Self::new(crate::errno::EIO, e.to_string())
    }
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FsError {}

/// A failed write: how many bytes at the start were already stored, and why
/// it failed. Each batch commits on its own, so a failure part way leaves
/// the earlier batches stored.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_arithmetic() {
        let g = ObjectGrid {
            from_index: 10,
            per_block: 4,
        };
        assert!(!g.in_blocks(9));
        for (index, start, segment) in [(10, 10, 0), (13, 10, 3), (14, 14, 0), (21, 18, 3)] {
            assert!(g.in_blocks(index));
            assert_eq!(
                (g.block_start(index), g.segment(index)),
                (start, segment),
                "{index}"
            );
        }
    }
}
