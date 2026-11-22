//! Converts between the shared types and their wire form. The code is next
//! to both, so the server and the client convert the same way. A response
//! without a required field decodes as `EIO`. The server always sets the
//! field, so this happens only between versions that do not work together.

use crate::os_bytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb;
use crate::types::{
    AccountInfo, AccountKeys, AccountKind, Activity, ActivityOp, ActivityPage, Attr,
    BLOCK_RANDOM_LEN, BlockRef, BlockUpload, BlockUrl, Caps, ChunkBody, ChunkWrite, Chunks,
    ClaimOutcome, DirItem, FolderSize, FsError, Grant, GrantedNode, Grantee, KeyPath, Kind, Layout,
    LinkAccount, ObjectGrid, Offer, Orphan, PreparedUpload, PruneClaim, ResealedName, Rotation,
    SealedChunk, SealedEntryName, SetAttr, SetTime, SnapshotInfo, Storage, Unpruned, Unreachable,
    UserEntry, VolumeInfo, WriteBody,
};

fn malformed(what: &str) -> FsError {
    FsError::new(crate::errno::EIO, format!("malformed response: no {what}"))
}

/// Both conversions of a response that carries a value or an error:
/// `From<Result<T, FsError>>`, which the servers answer with, and
/// `into_result`, which clients read it with.
///
/// - `encode` builds the `variant`'s value from a `T`.
/// - `decode` turns that value back into a `T`, or an error.
/// - A reply with neither, or with a value that `decode`'s pattern doesn't
///   match, is malformed: `what` names what was missing.
macro_rules! result_response {
    (
        $(#[$doc:meta])*
        $response:ident, $module:ident::$variant:ident, $what:literal, $ty:ty,
        encode: |$enc:pat_param| $encode:expr,
        decode: |$dec:pat_param| $decode:expr $(,)?
    ) => {
        impl From<Result<$ty, FsError>> for pb::$response {
            fn from(r: Result<$ty, FsError>) -> Self {
                use pb::$module::Result as R;
                Self {
                    result: Some(match r {
                        Ok($enc) => R::$variant($encode),
                        Err(e) => R::Error(e.into()),
                    }),
                }
            }
        }

        impl pb::$response {
            $(#[$doc])*
            pub fn into_result(self) -> Result<$ty, FsError> {
                use pb::$module::Result as R;
                match self.result {
                    Some(R::$variant($dec)) => $decode,
                    Some(R::Error(e)) => Err(e.into()),
                    _ => Err(malformed($what)),
                }
            }
        }
    };
}

/// The error that the server returns for a request field with no valid
/// meaning.
fn invalid(what: &str) -> FsError {
    FsError::new(crate::errno::EINVAL, format!("malformed request: {what}"))
}

impl From<SystemTime> for pb::Timestamp {
    fn from(t: SystemTime) -> Self {
        let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
        Self {
            secs: d.as_secs(),
            nanos: d.subsec_nanos(),
        }
    }
}

impl From<pb::Timestamp> for SystemTime {
    fn from(t: pb::Timestamp) -> Self {
        UNIX_EPOCH + Duration::new(t.secs, t.nanos.min(999_999_999))
    }
}

fn time(t: Option<pb::Timestamp>) -> SystemTime {
    t.map_or(UNIX_EPOCH, SystemTime::from)
}

impl From<Kind> for pb::Kind {
    fn from(k: Kind) -> Self {
        match k {
            Kind::File => Self::File,
            Kind::Directory => Self::Directory,
        }
    }
}

fn kind(raw: i32) -> Kind {
    match pb::Kind::try_from(raw) {
        Ok(pb::Kind::Directory) => Kind::Directory,
        _ => Kind::File,
    }
}

impl From<Layout> for pb::Layout {
    fn from(l: Layout) -> Self {
        match l {
            Layout::Inline => Self::Inline,
            Layout::Hybrid => Self::Hybrid,
        }
    }
}

fn layout(raw: i32) -> Layout {
    match pb::Layout::try_from(raw) {
        Ok(pb::Layout::Hybrid) => Layout::Hybrid,
        _ => Layout::Inline,
    }
}

impl From<Attr> for pb::Attr {
    fn from(a: Attr) -> Self {
        Self {
            ino: a.ino,
            kind: pb::Kind::from(a.kind).into(),
            size: a.size,
            perm: a.perm.into(),
            nlink: a.nlink,
            atime: Some(a.atime.into()),
            mtime: Some(a.mtime.into()),
            ctime: Some(a.ctime.into()),
            layout: pb::Layout::from(a.layout).into(),
        }
    }
}

impl From<pb::Attr> for Attr {
    fn from(a: pb::Attr) -> Self {
        Self {
            ino: a.ino,
            kind: kind(a.kind),
            size: a.size,
            perm: a.perm as u16,
            nlink: a.nlink,
            atime: time(a.atime),
            mtime: time(a.mtime),
            ctime: time(a.ctime),
            layout: layout(a.layout),
        }
    }
}

impl From<ObjectGrid> for pb::ObjectGrid {
    fn from(g: ObjectGrid) -> Self {
        Self {
            from_index: g.from_index,
            per_block: g.per_block,
        }
    }
}

impl TryFrom<pb::ObjectGrid> for ObjectGrid {
    type Error = FsError;

    fn try_from(g: pb::ObjectGrid) -> Result<Self, FsError> {
        if g.per_block == 0 {
            return Err(FsError::new(
                crate::errno::EIO,
                "malformed response: an empty block",
            ));
        }
        Ok(Self {
            from_index: g.from_index,
            per_block: g.per_block,
        })
    }
}

impl From<BlockRef> for pb::BlockRef {
    fn from(b: BlockRef) -> Self {
        Self {
            version: b.version,
            minted_ms: b.minted_ms,
            random: b.random.to_vec(),
            nseg: b.nseg,
        }
    }
}

fn random(bytes: &[u8]) -> Option<[u8; BLOCK_RANDOM_LEN]> {
    bytes.try_into().ok()
}

/// Decodes a `BlockRef`. Returns `None` if its name has the wrong length.
fn block_ref(b: pb::BlockRef) -> Option<BlockRef> {
    Some(BlockRef {
        version: b.version,
        minted_ms: b.minted_ms,
        random: random(&b.random)?,
        nseg: b.nseg,
    })
}

const AUTHORIZATION: &str = "authorization";
const BEARER: &str = "Bearer ";

/// Puts a session token in a request's metadata.
pub fn session_to_metadata(token: &str, metadata: &mut tonic::metadata::MetadataMap) {
    if let Ok(value) = format!("{BEARER}{token}").parse() {
        metadata.insert(AUTHORIZATION, value);
    }
}

/// The session token that `session_to_metadata` put in the metadata, if
/// any.
pub fn session_from_metadata(metadata: &tonic::metadata::MetadataMap) -> Option<&str> {
    metadata
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix(BEARER)
}

impl From<FsError> for pb::Error {
    fn from(e: FsError) -> Self {
        Self {
            errno: crate::errno::to_wire(e.errno),
            message: e.message,
        }
    }
}

impl From<pb::Error> for FsError {
    fn from(e: pb::Error) -> Self {
        Self::new(crate::errno::from_wire(e.errno), e.message)
    }
}

impl From<SetTime> for pb::SetTime {
    fn from(t: SetTime) -> Self {
        Self {
            time: Some(match t {
                SetTime::Now => pb::set_time::Time::Now(true),
                SetTime::At(t) => pb::set_time::Time::At(t.into()),
            }),
        }
    }
}

fn set_time(t: Option<pb::SetTime>) -> Option<SetTime> {
    match t?.time? {
        pb::set_time::Time::Now(_) => Some(SetTime::Now),
        pb::set_time::Time::At(t) => Some(SetTime::At(t.into())),
    }
}

impl pb::SetAttrRequest {
    pub fn new(ino: u64, changes: SetAttr) -> Self {
        Self {
            ino,
            mode: changes.mode,
            size: changes.size,
            atime: changes.atime.map(Into::into),
            mtime: changes.mtime.map(Into::into),
        }
    }

    pub fn changes(&self) -> SetAttr {
        SetAttr {
            mode: self.mode,
            size: self.size,
            atime: set_time(self.atime),
            mtime: set_time(self.mtime),
        }
    }
}

impl From<DirItem> for pb::DirItem {
    fn from(d: DirItem) -> Self {
        Self {
            ino: d.ino,
            kind: pb::Kind::from(d.kind).into(),
            name: os_bytes::into_bytes(d.name),
            sealed_name: d.sealed_name,
        }
    }
}

impl From<pb::DirItem> for DirItem {
    fn from(d: pb::DirItem) -> Self {
        Self {
            ino: d.ino,
            kind: kind(d.kind),
            name: os_bytes::into_name(d.name),
            sealed_name: d.sealed_name,
        }
    }
}

/// A name in its wire form.
pub fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    os_bytes::bytes(name).to_vec()
}

// -- Responses: the server builds them from results, and the client takes
// them apart again. --

result_response! {
    AttrResponse, attr_response::Attr, "attributes", Attr,
    encode: |a| a.into(),
    decode: |a| Ok(a.into()),
}

result_response! {
    /// The entry's attributes and its sealed name.
    LookupResponse, lookup_response::Entry, "a looked-up entry", (Attr, Vec<u8>),
    encode: |(attr, sealed_name)| pb::LookedUp {
        attr: Some(attr.into()),
        sealed_name,
    },
    decode: |pb::LookedUp {
        attr: Some(attr),
        sealed_name,
    }| Ok((attr.into(), sealed_name)),
}

impl From<Result<(), FsError>> for pb::EmptyResponse {
    fn from(r: Result<(), FsError>) -> Self {
        Self {
            error: r.err().map(Into::into),
        }
    }
}

impl pb::EmptyResponse {
    pub fn into_result(self) -> Result<(), FsError> {
        match self.error {
            Some(e) => Err(e.into()),
            None => Ok(()),
        }
    }
}

result_response! {
    /// The session: its token, when it expires, and the wrapped private
    /// key.
    LoginResponse, login_response::Session, "session", pb::Session,
    encode: |session| session,
    decode: |s| Ok(s),
}

result_response! {
    PreloginResponse, prelogin_response::Settings, "KDF settings", pb::KdfSettings,
    encode: |settings| settings,
    decode: |s| Ok(s),
}

impl From<AccountKeys> for pb::AccountKeys {
    fn from(k: AccountKeys) -> Self {
        Self {
            salt: k.salt,
            kdf_params: k.kdf_params,
            verifier: k.verifier,
            public_key: k.public_key,
            wrapped_private_key: k.wrapped_private_key,
        }
    }
}

impl From<pb::AccountKeys> for AccountKeys {
    fn from(k: pb::AccountKeys) -> Self {
        Self {
            salt: k.salt,
            kdf_params: k.kdf_params,
            verifier: k.verifier,
            public_key: k.public_key,
            wrapped_private_key: k.wrapped_private_key,
        }
    }
}

impl From<AccountInfo> for pb::AccountInfo {
    fn from(a: AccountInfo) -> Self {
        Self {
            capabilities: a.caps.bits(),
            kind: match a.kind {
                AccountKind::Person => pb::AccountKind::Person,
                AccountKind::Link => pb::AccountKind::Link,
            }
            .into(),
            invited_by: a.invited_by,
            created: a.created,
            owner: a.owner,
            expires: a.expires.unwrap_or(0),
            folder: a.folder,
            note: a.note,
            quota: a.quota,
        }
    }
}

impl From<pb::AccountInfo> for AccountInfo {
    fn from(a: pb::AccountInfo) -> Self {
        Self {
            caps: Caps::from_bits(a.capabilities),
            kind: match pb::AccountKind::try_from(a.kind) {
                Ok(pb::AccountKind::Link) => AccountKind::Link,
                _ => AccountKind::Person,
            },
            invited_by: a.invited_by,
            created: a.created,
            owner: a.owner,
            expires: (a.expires != 0).then_some(a.expires),
            folder: a.folder,
            note: a.note,
            quota: a.quota,
        }
    }
}

result_response! {
    AccountResponse, account_response::Account, "account", AccountInfo,
    encode: |account| account.into(),
    decode: |a| Ok(a.into()),
}

result_response! {
    LinkListResponse, link_list_response::List, "link list", Vec<LinkAccount>,
    encode: |links| pb::LinkList {
        links: links
            .into_iter()
            .map(|l| pb::LinkInfo {
                username: l.user,
                account: Some(l.info.into()),
            })
            .collect(),
    },
    decode: |l| l
        .links
        .into_iter()
        .map(|l| {
            Ok(LinkAccount {
                user: l.username,
                info: l.account.ok_or_else(|| malformed("link account"))?.into(),
            })
        })
        .collect(),
}

result_response! {
    /// The version, and the sealed trusted keys.
    PinsResponse, pins_response::Pins, "trusted keys", (u64, Vec<u8>),
    encode: |(version, sealed)| pb::Pins { version, sealed },
    decode: |p| Ok((p.version, p.sealed)),
}

result_response! {
    /// The public key, and the invitation proof (empty for none).
    EnrollmentResponse, enrollment_response::Enrollment, "enrollment", (Vec<u8>, Vec<u8>),
    encode: |(public_key, proof)| pb::Enrollment { public_key, proof },
    decode: |e| Ok((e.public_key, e.proof)),
}

result_response! {
    IntroductionsResponse, introductions_response::Introductions, "introductions", Vec<pb::Introduction>,
    encode: |introductions| pb::Introductions { introductions },
    decode: |i| Ok(i.introductions),
}

result_response! {
    IssueInviteResponse, issue_invite_response::Invite, "invitation", pb::IssuedInvite,
    encode: |invite| invite,
    decode: |i| Ok(i),
}

result_response! {
    StorageResponse, storage_response::Storage, "storage", Storage,
    encode: |s| pb::Storage {
        used: s.used,
        measured_at: s.measured_at,
        quota: s.quota,
    },
    decode: |s| Ok(Storage {
        used: s.used,
        measured_at: s.measured_at,
        quota: s.quota,
    }),
}

impl From<ActivityOp> for pb::ActivityOp {
    fn from(op: ActivityOp) -> Self {
        match op {
            ActivityOp::Created => Self::ActivityCreated,
            ActivityOp::Edited => Self::ActivityEdited,
            ActivityOp::Renamed => Self::ActivityRenamed,
            ActivityOp::Deleted => Self::ActivityDeleted,
        }
    }
}

fn activity_op(raw: i32) -> ActivityOp {
    match pb::ActivityOp::try_from(raw) {
        Ok(pb::ActivityOp::ActivityEdited) => ActivityOp::Edited,
        Ok(pb::ActivityOp::ActivityRenamed) => ActivityOp::Renamed,
        Ok(pb::ActivityOp::ActivityDeleted) => ActivityOp::Deleted,
        _ => ActivityOp::Created,
    }
}

impl From<SealedEntryName> for pb::SealedEntryName {
    fn from(n: SealedEntryName) -> Self {
        Self {
            parent: n.parent,
            tag: n.tag,
            sealed: n.sealed,
        }
    }
}

impl From<pb::SealedEntryName> for SealedEntryName {
    fn from(n: pb::SealedEntryName) -> Self {
        Self {
            parent: n.parent,
            tag: n.tag,
            sealed: n.sealed,
        }
    }
}

result_response! {
    ActivityResponse, activity_response::Page, "activity", ActivityPage,
    encode: |page| pb::ActivityPage {
        entries: page
            .entries
            .into_iter()
            .map(|a| pb::ActivityEntry {
                at_ms: a.at_ms,
                user: a.user,
                op: pb::ActivityOp::from(a.op).into(),
                kind: pb::Kind::from(a.kind).into(),
                ino: a.ino,
                parent: a.parent,
                name: a.name.map(Into::into),
                from: a.from.map(Into::into),
                replaced: a.replaced,
                moved_out: a.moved_out,
                path: a.path,
            })
            .collect(),
        next: page.next,
    },
    decode: |p| Ok(ActivityPage {
        entries: p
            .entries
            .into_iter()
            .map(|a| Activity {
                at_ms: a.at_ms,
                user: a.user,
                op: activity_op(a.op),
                kind: kind(a.kind),
                ino: a.ino,
                parent: a.parent,
                name: a.name.map(Into::into),
                from: a.from.map(Into::into),
                replaced: a.replaced,
                moved_out: a.moved_out,
                path: a.path,
            })
            .collect(),
        next: p.next,
    }),
}

result_response! {
    FolderSizesResponse, folder_sizes_response::List, "folder sizes", Vec<FolderSize>,
    encode: |sizes| pb::FolderSizeList {
        sizes: sizes
            .into_iter()
            .map(|f| pb::FolderSize {
                ino: f.ino,
                bytes: f.bytes,
                files: f.files,
                measured_at: f.measured_at,
                limit: f.limit,
            })
            .collect(),
    },
    decode: |l| Ok(l
        .sizes
        .into_iter()
        .map(|f| FolderSize {
            ino: f.ino,
            bytes: f.bytes,
            files: f.files,
            measured_at: f.measured_at,
            limit: f.limit,
        })
        .collect()),
}

fn claim_of(user: String, expires_ms: u64) -> Option<PruneClaim> {
    (!user.is_empty()).then_some(PruneClaim { user, expires_ms })
}

result_response! {
    UnprunedListResponse, unpruned_list_response::List, "nodes waiting for a prune", Vec<Unpruned>,
    encode: |nodes| pb::UnprunedList {
        nodes: nodes
            .into_iter()
            .map(|n| {
                let (claimed_by, claim_expires_ms) = n
                    .claim
                    .map_or((String::new(), 0), |c| (c.user, c.expires_ms));
                pb::UnprunedNode {
                    ino: n.ino,
                    claimed_by,
                    claim_expires_ms,
                }
            })
            .collect(),
    },
    decode: |l| Ok(l
        .nodes
        .into_iter()
        .map(|n| Unpruned {
            ino: n.ino,
            claim: claim_of(n.claimed_by, n.claim_expires_ms),
        })
        .collect()),
}

impl From<Result<ClaimOutcome, FsError>> for pb::ClaimPruneResponse {
    fn from(r: Result<ClaimOutcome, FsError>) -> Self {
        use pb::claim_prune_response::Result as R;
        Self {
            result: Some(match r {
                Ok(o) => {
                    let (claimed_by, expires_ms) = o
                        .claim
                        .map_or((String::new(), 0), |c| (c.user, c.expires_ms));
                    R::Outcome(pb::ClaimOutcome {
                        granted: o.granted,
                        claimed_by,
                        expires_ms,
                    })
                }
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::ClaimPruneResponse {
    pub fn into_result(self) -> Result<ClaimOutcome, FsError> {
        use pb::claim_prune_response::Result as R;
        match self.result {
            Some(R::Outcome(o)) => Ok(ClaimOutcome {
                granted: o.granted,
                claim: claim_of(o.claimed_by, o.expires_ms),
            }),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("a prune claim")),
        }
    }
}

result_response! {
    OrphanListResponse, orphan_list_response::List, "orphaned volumes", Vec<Orphan>,
    encode: |orphans| pb::OrphanList {
        orphans: orphans
            .into_iter()
            .map(|o| pb::Orphan {
                volume: o.volume,
                owner: o.owner,
                writers: o.writers,
                reachable: o.reachable,
                bytes: o.bytes,
            })
            .collect(),
    },
    decode: |l| Ok(l
        .orphans
        .into_iter()
        .map(|o| Orphan {
            volume: o.volume,
            owner: o.owner,
            writers: o.writers,
            reachable: o.reachable,
            bytes: o.bytes,
        })
        .collect()),
}

result_response! {
    OfferListResponse, offer_list_response::List, "offers", Vec<Offer>,
    encode: |offers| pb::OfferList {
        offers: offers
            .into_iter()
            .map(|o| pb::Offer {
                volume: o.volume,
                from: o.from,
                to: o.to,
                at: o.at,
                bytes: o.bytes,
            })
            .collect(),
    },
    decode: |l| Ok(l
        .offers
        .into_iter()
        .map(|o| Offer {
            volume: o.volume,
            from: o.from,
            to: o.to,
            at: o.at,
            bytes: o.bytes,
        })
        .collect()),
}

impl From<Result<VolumeInfo, FsError>> for pb::VolumeResponse {
    fn from(r: Result<VolumeInfo, FsError>) -> Self {
        use pb::volume_response::Result as R;
        Self {
            result: Some(match r {
                Ok(v) => {
                    let (offer_to, offer_at) = v.offer.unwrap_or_default();
                    R::Volume(pb::VolumeInfo {
                        owner: v.owner.unwrap_or_default(),
                        offer_to,
                        offer_at,
                    })
                }
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::VolumeResponse {
    pub fn into_result(self) -> Result<VolumeInfo, FsError> {
        use pb::volume_response::Result as R;
        match self.result {
            Some(R::Volume(v)) => Ok(VolumeInfo {
                owner: (!v.owner.is_empty()).then_some(v.owner),
                offer: (!v.offer_to.is_empty()).then_some((v.offer_to, v.offer_at)),
            }),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("volume")),
        }
    }
}

result_response! {
    UnreachableListResponse, unreachable_list_response::List, "unreachable list", Vec<Unreachable>,
    encode: |items| pb::UnreachableList {
        items: items
            .into_iter()
            .map(|u| pb::Unreachable {
                ino: u.ino,
                volume: u.volume,
                files: u.files,
                folders: u.folders,
                bytes: u.bytes,
                modified: Some(u.modified.into()),
            })
            .collect(),
    },
    decode: |l| Ok(l
        .items
        .into_iter()
        .map(|u| Unreachable {
            ino: u.ino,
            volume: u.volume,
            files: u.files,
            folders: u.folders,
            bytes: u.bytes,
            modified: time(u.modified),
        })
        .collect()),
}

result_response! {
    UserListResponse, user_list_response::List, "user list", Vec<UserEntry>,
    encode: |users| pb::UserList {
        users: users
            .into_iter()
            .map(|u| pb::UserEntry {
                username: u.user,
                enrolled: u.enrolled,
                account: Some(u.info.into()),
                used: u.used,
                code_expires: u.code_expires,
            })
            .collect(),
    },
    decode: |l| l
        .users
        .into_iter()
        .map(|u| {
            Ok(UserEntry {
                user: u.username,
                enrolled: u.enrolled,
                info: u.account.ok_or_else(|| malformed("account"))?.into(),
                used: u.used,
                code_expires: u.code_expires,
            })
        })
        .collect(),
}

result_response! {
    InoResponse, ino_response::Ino, "inode", u64,
    encode: |ino| ino,
    decode: |ino| Ok(ino),
}

result_response! {
    ReadDirResponse, read_dir_response::List, "listing", Vec<DirItem>,
    encode: |items| pb::DirList {
        items: items.into_iter().map(Into::into).collect(),
    },
    decode: |list| Ok(list.items.into_iter().map(Into::into).collect()),
}

impl From<Grant> for pb::GrantInfo {
    fn from(g: Grant) -> Self {
        Self {
            ino: g.ino,
            writable: g.writable,
            key_version: g.key_version,
            sealed_key: g.sealed_key,
            sealed_label: g.sealed_label,
        }
    }
}

impl From<pb::GrantInfo> for Grant {
    fn from(g: pb::GrantInfo) -> Self {
        Self {
            ino: g.ino,
            writable: g.writable,
            key_version: g.key_version,
            sealed_key: g.sealed_key,
            sealed_label: g.sealed_label,
        }
    }
}

result_response! {
    KeyPathResponse, key_path_response::Path, "key path", KeyPath,
    encode: |path| pb::KeyPath {
        grant: Some(path.grant.into()),
        nodes: path
            .nodes
            .into_iter()
            .map(|(ino, keys)| pb::NodeRecord { ino, keys })
            .collect(),
    },
    decode: |p| Ok(KeyPath {
        grant: p.grant.ok_or_else(|| malformed("grant"))?.into(),
        nodes: p.nodes.into_iter().map(|n| (n.ino, n.keys)).collect(),
    }),
}

impl From<Result<(Vec<Grant>, Vec<u64>), FsError>> for pb::GrantListResponse {
    fn from(r: Result<(Vec<Grant>, Vec<u64>), FsError>) -> Self {
        use pb::grant_list_response::Result as R;
        Self {
            result: Some(match r {
                Ok((grants, covered)) => R::List(pb::GrantList {
                    grants: grants.into_iter().map(Into::into).collect(),
                    covered,
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::GrantListResponse {
    pub fn into_result(self) -> Result<Vec<Grant>, FsError> {
        self.into_parts().map(|(grants, _)| grants)
    }

    /// The grants, and which of them are inside another of the caller's
    /// grants (none from servers too old to say).
    pub fn into_parts(self) -> Result<(Vec<Grant>, Vec<u64>), FsError> {
        use pb::grant_list_response::Result as R;
        match self.result {
            Some(R::List(l)) => Ok((l.grants.into_iter().map(Into::into).collect(), l.covered)),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("grant list")),
        }
    }
}

result_response! {
    SnapshotListResponse, snapshot_list_response::List, "snapshot list", Vec<SnapshotInfo>,
    encode: |snapshots| pb::SnapshotList {
        snapshots: snapshots
            .into_iter()
            .map(|s| pb::SnapshotInfo {
                name: s.name,
                created: Some(s.created.into()),
            })
            .collect(),
    },
    decode: |l| Ok(l
        .snapshots
        .into_iter()
        .map(|s| SnapshotInfo {
            name: s.name,
            created: time(s.created),
        })
        .collect()),
}

result_response! {
    PublicKeyResponse, public_key_response::Key, "public key", Vec<u8>,
    encode: |key| key,
    decode: |k| Ok(k),
}

impl From<Result<Chunks, FsError>> for pb::ReadChunksResponse {
    fn from(r: Result<Chunks, FsError>) -> Self {
        use pb::read_chunks_response::Result as R;
        use pb::sealed_chunk::Body;
        Self {
            result: Some(match r {
                Ok(read) => R::List(pb::ChunkList {
                    attr: Some(read.attr.into()),
                    chunks: read
                        .chunks
                        .into_iter()
                        .map(|c| pb::SealedChunk {
                            index: c.index,
                            seq: c.seq,
                            body: match c.body {
                                ChunkBody::Hole => None,
                                ChunkBody::Inline(blob) => Some(Body::Blob(blob)),
                                ChunkBody::Segment { block, segment } => {
                                    Some(Body::Segment(pb::Segment { block, segment }))
                                }
                            },
                            unchanged: c.unchanged,
                        })
                        .collect(),
                    blocks: read
                        .blocks
                        .into_iter()
                        .map(|b| pb::BlockUrl {
                            block: Some(b.block.into()),
                            url: b.url,
                        })
                        .collect(),
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::ReadChunksResponse {
    /// The file's attributes, the chunks read, and the blocks that hold
    /// them. Every segment names a block in the list.
    pub fn into_result(self) -> Result<Chunks, FsError> {
        use pb::read_chunks_response::Result as R;
        use pb::sealed_chunk::Body;
        match self.result {
            Some(R::List(l)) => {
                let attr = l.attr.ok_or_else(|| malformed("attributes"))?.into();
                let blocks = l
                    .blocks
                    .into_iter()
                    .map(|b| {
                        Ok(BlockUrl {
                            block: b
                                .block
                                .and_then(block_ref)
                                .ok_or_else(|| malformed("block"))?,
                            url: b.url,
                        })
                    })
                    .collect::<Result<Vec<_>, FsError>>()?;
                let chunks = l
                    .chunks
                    .into_iter()
                    .map(|c| {
                        let body = match c.body {
                            // An older server sends a hole as an empty
                            // blob, with no `body`.
                            None => ChunkBody::Hole,
                            Some(Body::Blob(blob)) if blob.is_empty() => ChunkBody::Hole,
                            Some(Body::Blob(blob)) => ChunkBody::Inline(blob),
                            Some(Body::Segment(s)) if (s.block as usize) < blocks.len() => {
                                ChunkBody::Segment {
                                    block: s.block,
                                    segment: s.segment,
                                }
                            }
                            Some(Body::Segment(_)) => return Err(malformed("such block")),
                        };
                        Ok(SealedChunk {
                            index: c.index,
                            seq: c.seq,
                            body,
                            unchanged: c.unchanged,
                        })
                    })
                    .collect::<Result<Vec<_>, FsError>>()?;
                Ok(Chunks {
                    attr,
                    chunks,
                    blocks,
                })
            }
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("chunk list")),
        }
    }
}

impl From<Result<(Attr, u64), FsError>> for pb::WriteChunksResponse {
    fn from(r: Result<(Attr, u64), FsError>) -> Self {
        use pb::write_chunks_response::Result as R;
        Self {
            result: Some(match r {
                Ok((attr, seq)) => R::Written(pb::ChunksWritten {
                    attr: Some(attr.into()),
                    seq,
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::WriteChunksResponse {
    /// The file's attributes, and the seq of the chunks written.
    pub fn into_result(self) -> Result<(Attr, u64), FsError> {
        use pb::write_chunks_response::Result as R;
        match self.result {
            Some(R::Written(w)) => {
                Ok((w.attr.ok_or_else(|| malformed("attributes"))?.into(), w.seq))
            }
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("written chunks")),
        }
    }
}

impl From<ChunkWrite> for pb::ChunkWrite {
    fn from(c: ChunkWrite) -> Self {
        use pb::chunk_write::Body;
        Self {
            index: c.index,
            expected_seq: c.expected_seq,
            body: Some(match c.body {
                WriteBody::Inline(blob) => Body::Blob(blob),
                WriteBody::Block(block) => Body::Block(block.into()),
            }),
        }
    }
}

impl TryFrom<pb::ChunkWrite> for ChunkWrite {
    type Error = FsError;

    /// Returns `EINVAL` for a block whose name has the wrong length. A
    /// write with no body is an empty chunk, which nothing stores, because
    /// it has no seal.
    fn try_from(c: pb::ChunkWrite) -> Result<Self, FsError> {
        use pb::chunk_write::Body;
        Ok(Self {
            index: c.index,
            expected_seq: c.expected_seq,
            body: match c.body {
                None => WriteBody::Inline(Vec::new()),
                Some(Body::Blob(blob)) => WriteBody::Inline(blob),
                Some(Body::Block(b)) => {
                    WriteBody::Block(block_ref(b).ok_or_else(|| invalid("a block's name"))?)
                }
            },
        })
    }
}

impl From<BlockUpload> for pb::BlockUpload {
    fn from(b: BlockUpload) -> Self {
        Self {
            index: b.index,
            nseg: b.nseg,
        }
    }
}

impl From<pb::BlockUpload> for BlockUpload {
    fn from(b: pb::BlockUpload) -> Self {
        Self {
            index: b.index,
            nseg: b.nseg,
        }
    }
}

result_response! {
    /// One upload for each block asked for, in the same order.
    PrepareUploadsResponse, prepare_uploads_response::Uploads, "uploads", Vec<PreparedUpload>,
    encode: |uploads| pb::PreparedUploads {
        uploads: uploads
            .into_iter()
            .map(|u| pb::PreparedUpload {
                minted_ms: u.minted_ms,
                random: u.random.to_vec(),
                url: u.url,
            })
            .collect(),
    },
    decode: |u| u
        .uploads
        .into_iter()
        .map(|u| {
            Ok(PreparedUpload {
                minted_ms: u.minted_ms,
                random: random(&u.random).ok_or_else(|| malformed("object name"))?,
                url: u.url,
            })
        })
        .collect(),
}

result_response! {
    GrantsUnderResponse, grants_under_response::List, "granted nodes", Vec<GrantedNode>,
    encode: |nodes| pb::GrantedNodes {
        nodes: nodes
            .into_iter()
            .map(|n| pb::GrantedNode {
                ino: n.ino,
                path: n.path,
                grantees: n
                    .grantees
                    .into_iter()
                    .map(|g| pb::Grantee {
                        username: g.user,
                        public_key: g.public_key,
                        writable: g.writable,
                    })
                    .collect(),
                sealed_grantees: n.sealed_grantees,
                grantees_seq: n.grantees_seq,
            })
            .collect(),
    },
    decode: |l| Ok(l
        .nodes
        .into_iter()
        .map(|n| GrantedNode {
            ino: n.ino,
            path: n.path,
            grantees: n
                .grantees
                .into_iter()
                .map(|g| Grantee {
                    user: g.username,
                    public_key: g.public_key,
                    writable: g.writable,
                })
                .collect(),
            sealed_grantees: n.sealed_grantees,
            grantees_seq: n.grantees_seq,
        })
        .collect()),
}

impl From<Rotation> for pb::Rotation {
    fn from(r: Rotation) -> Self {
        Self {
            ino: r.ino,
            expected_version: r.expected_version,
            node_keys: r.node_keys,
            grants: r
                .grants
                .into_iter()
                .map(|(username, sealed_key)| pb::ResealedGrant {
                    username,
                    sealed_key,
                })
                .collect(),
            sealed_grantees: r.sealed_grantees,
        }
    }
}

impl From<pb::Rotation> for Rotation {
    fn from(r: pb::Rotation) -> Self {
        Self {
            ino: r.ino,
            expected_version: r.expected_version,
            node_keys: r.node_keys,
            grants: r
                .grants
                .into_iter()
                .map(|g| (g.username, g.sealed_key))
                .collect(),
            sealed_grantees: r.sealed_grantees,
        }
    }
}

impl From<ResealedName> for pb::ResealedName {
    fn from(r: ResealedName) -> Self {
        Self {
            name: name_bytes(&r.tag),
            ino: r.ino,
            sealed_name: r.sealed_name,
        }
    }
}

impl From<pb::ResealedName> for ResealedName {
    fn from(r: pb::ResealedName) -> Self {
        Self {
            tag: os_bytes::into_name(r.name),
            ino: r.ino,
            sealed_name: r.sealed_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attr_round_trips() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        let a = Attr {
            ino: 9,
            kind: Kind::Directory,
            size: 4096,
            perm: 0o2770,
            nlink: 2,
            atime: t,
            mtime: t,
            ctime: t,
            layout: Layout::Hybrid,
        };
        assert_eq!(Attr::from(pb::Attr::from(a)), a);
    }

    fn block() -> BlockRef {
        BlockRef {
            version: 3,
            minted_ms: 1_760_000_000_000,
            random: [7; BLOCK_RANDOM_LEN],
            nseg: 16,
        }
    }

    fn attr() -> Attr {
        Attr {
            ino: 9,
            kind: Kind::File,
            size: 1 << 30,
            perm: 0o640,
            nlink: 1,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            layout: Layout::Hybrid,
        }
    }

    #[test]
    fn a_chunk_list_round_trips() {
        let read = Chunks {
            attr: attr(),
            chunks: vec![
                SealedChunk {
                    index: 0,
                    seq: 5,
                    body: ChunkBody::Inline(vec![1, 2, 3]),
                    unchanged: false,
                },
                SealedChunk {
                    index: 1,
                    seq: 0,
                    body: ChunkBody::Hole,
                    unchanged: false,
                },
                SealedChunk {
                    index: 10,
                    seq: 8,
                    body: ChunkBody::Segment {
                        block: 0,
                        segment: 0,
                    },
                    unchanged: false,
                },
                SealedChunk {
                    index: 11,
                    seq: 8,
                    body: ChunkBody::Hole,
                    unchanged: true,
                },
            ],
            blocks: vec![BlockUrl {
                block: block(),
                url: "https://store/obj?sig".into(),
            }],
        };
        let wire = pb::ReadChunksResponse::from(Ok(read.clone()));
        assert_eq!(wire.into_result(), Ok(read));
    }

    #[test]
    fn a_segment_must_name_a_block_in_the_list() {
        let wire = pb::ReadChunksResponse {
            result: Some(pb::read_chunks_response::Result::List(pb::ChunkList {
                attr: Some(attr().into()),
                chunks: vec![pb::SealedChunk {
                    index: 10,
                    seq: 1,
                    body: Some(pb::sealed_chunk::Body::Segment(pb::Segment {
                        block: 0,
                        segment: 0,
                    })),
                    unchanged: false,
                }],
                blocks: vec![],
            })),
        };
        assert_eq!(wire.into_result().unwrap_err().errno, crate::errno::EIO);
    }

    #[test]
    fn an_empty_blob_is_a_hole() {
        // A response as an older server sends it.
        let wire = pb::ReadChunksResponse {
            result: Some(pb::read_chunks_response::Result::List(pb::ChunkList {
                attr: Some(attr().into()),
                chunks: vec![pb::SealedChunk {
                    index: 0,
                    seq: 0,
                    body: Some(pb::sealed_chunk::Body::Blob(Vec::new())),
                    unchanged: false,
                }],
                blocks: vec![],
            })),
        };
        assert_eq!(wire.into_result().unwrap().chunks[0].body, ChunkBody::Hole);
    }

    #[test]
    fn writes_round_trip() {
        for body in [WriteBody::Inline(vec![9; 50]), WriteBody::Block(block())] {
            let w = ChunkWrite {
                index: 10,
                expected_seq: Some(4),
                body,
            };
            assert_eq!(ChunkWrite::try_from(pb::ChunkWrite::from(w.clone())), Ok(w));
        }
        let mut bad = pb::ChunkWrite::from(ChunkWrite {
            index: 10,
            expected_seq: None,
            body: WriteBody::Block(block()),
        });
        if let Some(pb::chunk_write::Body::Block(b)) = &mut bad.body {
            b.random.pop();
        }
        assert_eq!(
            ChunkWrite::try_from(bad).unwrap_err().errno,
            crate::errno::EINVAL
        );
    }

    #[test]
    fn uploads_round_trip() {
        let uploads = vec![PreparedUpload {
            minted_ms: 12,
            random: [1; BLOCK_RANDOM_LEN],
            url: "https://store/put".into(),
        }];
        let wire = pb::PrepareUploadsResponse::from(Ok(uploads.clone()));
        assert_eq!(wire.into_result(), Ok(uploads));
        let e = FsError::new(crate::errno::ENOTSUP, "no object storage");
        assert_eq!(
            pb::PrepareUploadsResponse::from(Err(e.clone())).into_result(),
            Err(e)
        );
    }

    #[test]
    fn a_grid_needs_blocks_of_something() {
        let g = ObjectGrid {
            from_index: 10,
            per_block: 16,
        };
        assert_eq!(ObjectGrid::try_from(pb::ObjectGrid::from(g)), Ok(g));
        assert!(
            ObjectGrid::try_from(pb::ObjectGrid {
                from_index: 10,
                per_block: 0
            })
            .is_err()
        );
    }

    #[test]
    fn errors_survive_the_trip() {
        let e = FsError::new(crate::errno::EACCES, "nope");
        assert_eq!(
            pb::AttrResponse::from(Err(e.clone())).into_result(),
            Err(e.clone())
        );
        assert_eq!(
            pb::WriteChunksResponse::from(Err(e.clone())).into_result(),
            Err(e)
        );
    }

    #[test]
    fn set_attr_keeps_now_distinct_from_a_time() {
        let changes = SetAttr {
            mode: Some(0o600),
            atime: Some(SetTime::Now),
            mtime: Some(SetTime::At(UNIX_EPOCH + Duration::from_secs(7))),
            ..Default::default()
        };
        assert_eq!(pb::SetAttrRequest::new(3, changes).changes(), changes);
    }

    #[test]
    fn a_non_utf8_name_survives() {
        let name = os_bytes::into_name(vec![b'a', 0xff, b'b']);
        let item = DirItem {
            ino: 1,
            kind: Kind::File,
            name: name.clone(),
            sealed_name: vec![1, 2],
        };
        assert_eq!(DirItem::from(pb::DirItem::from(item)).name, name);
    }

    #[test]
    fn a_session_survives_metadata() {
        let mut metadata = tonic::metadata::MetadataMap::new();
        assert_eq!(session_from_metadata(&metadata), None);
        session_to_metadata("abc.def.ghi", &mut metadata);
        assert_eq!(session_from_metadata(&metadata), Some("abc.def.ghi"));
    }

    #[test]
    fn written_chunks_without_attributes_are_eio() {
        let r = pb::WriteChunksResponse {
            result: Some(pb::write_chunks_response::Result::Written(
                pb::ChunksWritten { attr: None, seq: 1 },
            )),
        };
        assert_eq!(r.into_result().unwrap_err().errno, crate::errno::EIO);
    }

    #[test]
    fn a_response_missing_its_result_is_eio() {
        let r = pb::AttrResponse { result: None }.into_result();
        assert_eq!(r.unwrap_err().errno, crate::errno::EIO);
    }
}
