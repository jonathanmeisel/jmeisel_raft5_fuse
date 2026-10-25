//! Converts between the shared types and their wire form. The code is next
//! to both, so the server and the client convert the same way. A response
//! without a required field decodes as `EIO`. The server always sets the
//! field, so this happens only between versions that do not work together.

use crate::os_bytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb;
use crate::types::{
    AccountKeys, Attr, BLOCK_RANDOM_LEN, BlockRef, BlockUpload, BlockUrl, ChunkBody, ChunkWrite,
    Chunks, DirItem, FsError, Grant, GrantedNode, Grantee, KeyPath, Kind, Layout, ObjectGrid,
    PreparedUpload, ResealedName, Rotation, SealedChunk, SetAttr, SetTime, SnapshotInfo, WriteBody,
};

fn malformed(what: &str) -> FsError {
    FsError::new(crate::errno::EIO, format!("malformed response: no {what}"))
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

impl From<Result<Attr, FsError>> for pb::AttrResponse {
    fn from(r: Result<Attr, FsError>) -> Self {
        use pb::attr_response::Result as R;
        Self {
            result: Some(match r {
                Ok(a) => R::Attr(a.into()),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::AttrResponse {
    pub fn into_result(self) -> Result<Attr, FsError> {
        use pb::attr_response::Result as R;
        match self.result {
            Some(R::Attr(a)) => Ok(a.into()),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("attributes")),
        }
    }
}

impl From<Result<(Attr, Vec<u8>), FsError>> for pb::LookupResponse {
    fn from(r: Result<(Attr, Vec<u8>), FsError>) -> Self {
        use pb::lookup_response::Result as R;
        Self {
            result: Some(match r {
                Ok((attr, sealed_name)) => R::Entry(pb::LookedUp {
                    attr: Some(attr.into()),
                    sealed_name,
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::LookupResponse {
    /// The entry's attributes and its sealed name.
    pub fn into_result(self) -> Result<(Attr, Vec<u8>), FsError> {
        use pb::lookup_response::Result as R;
        match self.result {
            Some(R::Entry(pb::LookedUp {
                attr: Some(attr),
                sealed_name,
            })) => Ok((attr.into(), sealed_name)),
            Some(R::Error(e)) => Err(e.into()),
            _ => Err(malformed("a looked-up entry")),
        }
    }
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

impl From<Result<pb::Session, FsError>> for pb::LoginResponse {
    fn from(r: Result<pb::Session, FsError>) -> Self {
        use pb::login_response::Result as R;
        Self {
            result: Some(match r {
                Ok(session) => R::Session(session),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::LoginResponse {
    /// The session: its token, when it expires, and the wrapped private
    /// key.
    pub fn into_result(self) -> Result<pb::Session, FsError> {
        use pb::login_response::Result as R;
        match self.result {
            Some(R::Session(s)) => Ok(s),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("session")),
        }
    }
}

impl From<Result<pb::KdfSettings, FsError>> for pb::PreloginResponse {
    fn from(r: Result<pb::KdfSettings, FsError>) -> Self {
        use pb::prelogin_response::Result as R;
        Self {
            result: Some(match r {
                Ok(settings) => R::Settings(settings),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::PreloginResponse {
    pub fn into_result(self) -> Result<pb::KdfSettings, FsError> {
        use pb::prelogin_response::Result as R;
        match self.result {
            Some(R::Settings(s)) => Ok(s),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("KDF settings")),
        }
    }
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

impl From<Result<u64, FsError>> for pb::InoResponse {
    fn from(r: Result<u64, FsError>) -> Self {
        use pb::ino_response::Result as R;
        Self {
            result: Some(match r {
                Ok(ino) => R::Ino(ino),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::InoResponse {
    pub fn into_result(self) -> Result<u64, FsError> {
        use pb::ino_response::Result as R;
        match self.result {
            Some(R::Ino(ino)) => Ok(ino),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("inode")),
        }
    }
}

impl From<Result<Vec<DirItem>, FsError>> for pb::ReadDirResponse {
    fn from(r: Result<Vec<DirItem>, FsError>) -> Self {
        use pb::read_dir_response::Result as R;
        Self {
            result: Some(match r {
                Ok(items) => R::List(pb::DirList {
                    items: items.into_iter().map(Into::into).collect(),
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::ReadDirResponse {
    pub fn into_result(self) -> Result<Vec<DirItem>, FsError> {
        use pb::read_dir_response::Result as R;
        match self.result {
            Some(R::List(list)) => Ok(list.items.into_iter().map(Into::into).collect()),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("listing")),
        }
    }
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

impl From<Result<KeyPath, FsError>> for pb::KeyPathResponse {
    fn from(r: Result<KeyPath, FsError>) -> Self {
        use pb::key_path_response::Result as R;
        Self {
            result: Some(match r {
                Ok(path) => R::Path(pb::KeyPath {
                    grant: Some(path.grant.into()),
                    nodes: path
                        .nodes
                        .into_iter()
                        .map(|(ino, keys)| pb::NodeRecord { ino, keys })
                        .collect(),
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::KeyPathResponse {
    pub fn into_result(self) -> Result<KeyPath, FsError> {
        use pb::key_path_response::Result as R;
        match self.result {
            Some(R::Path(p)) => Ok(KeyPath {
                grant: p.grant.ok_or_else(|| malformed("grant"))?.into(),
                nodes: p.nodes.into_iter().map(|n| (n.ino, n.keys)).collect(),
            }),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("key path")),
        }
    }
}

impl From<Result<Vec<Grant>, FsError>> for pb::GrantListResponse {
    fn from(r: Result<Vec<Grant>, FsError>) -> Self {
        use pb::grant_list_response::Result as R;
        Self {
            result: Some(match r {
                Ok(grants) => R::List(pb::GrantList {
                    grants: grants.into_iter().map(Into::into).collect(),
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::GrantListResponse {
    pub fn into_result(self) -> Result<Vec<Grant>, FsError> {
        use pb::grant_list_response::Result as R;
        match self.result {
            Some(R::List(l)) => Ok(l.grants.into_iter().map(Into::into).collect()),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("grant list")),
        }
    }
}

impl From<Result<Vec<SnapshotInfo>, FsError>> for pb::SnapshotListResponse {
    fn from(r: Result<Vec<SnapshotInfo>, FsError>) -> Self {
        use pb::snapshot_list_response::Result as R;
        Self {
            result: Some(match r {
                Ok(snapshots) => R::List(pb::SnapshotList {
                    snapshots: snapshots
                        .into_iter()
                        .map(|s| pb::SnapshotInfo {
                            name: s.name,
                            created: Some(s.created.into()),
                        })
                        .collect(),
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::SnapshotListResponse {
    pub fn into_result(self) -> Result<Vec<SnapshotInfo>, FsError> {
        use pb::snapshot_list_response::Result as R;
        match self.result {
            Some(R::List(l)) => Ok(l
                .snapshots
                .into_iter()
                .map(|s| SnapshotInfo {
                    name: s.name,
                    created: time(s.created),
                })
                .collect()),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("snapshot list")),
        }
    }
}

impl From<Result<Vec<u8>, FsError>> for pb::PublicKeyResponse {
    fn from(r: Result<Vec<u8>, FsError>) -> Self {
        use pb::public_key_response::Result as R;
        Self {
            result: Some(match r {
                Ok(key) => R::Key(key),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::PublicKeyResponse {
    pub fn into_result(self) -> Result<Vec<u8>, FsError> {
        use pb::public_key_response::Result as R;
        match self.result {
            Some(R::Key(k)) => Ok(k),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("public key")),
        }
    }
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

impl From<Result<Vec<PreparedUpload>, FsError>> for pb::PrepareUploadsResponse {
    fn from(r: Result<Vec<PreparedUpload>, FsError>) -> Self {
        use pb::prepare_uploads_response::Result as R;
        Self {
            result: Some(match r {
                Ok(uploads) => R::Uploads(pb::PreparedUploads {
                    uploads: uploads
                        .into_iter()
                        .map(|u| pb::PreparedUpload {
                            minted_ms: u.minted_ms,
                            random: u.random.to_vec(),
                            url: u.url,
                        })
                        .collect(),
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::PrepareUploadsResponse {
    /// One upload for each block asked for, in the same order.
    pub fn into_result(self) -> Result<Vec<PreparedUpload>, FsError> {
        use pb::prepare_uploads_response::Result as R;
        match self.result {
            Some(R::Uploads(u)) => u
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
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("uploads")),
        }
    }
}

impl From<Result<Vec<GrantedNode>, FsError>> for pb::GrantsUnderResponse {
    fn from(r: Result<Vec<GrantedNode>, FsError>) -> Self {
        use pb::grants_under_response::Result as R;
        Self {
            result: Some(match r {
                Ok(nodes) => R::List(pb::GrantedNodes {
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
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::GrantsUnderResponse {
    pub fn into_result(self) -> Result<Vec<GrantedNode>, FsError> {
        use pb::grants_under_response::Result as R;
        match self.result {
            Some(R::List(l)) => Ok(l
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
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("granted nodes")),
        }
    }
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
