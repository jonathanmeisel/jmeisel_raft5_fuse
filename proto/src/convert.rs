//! Between the shared types and their wire form. Kept beside both so the
//! server and the client convert the same way. A response missing the
//! field it must carry decodes as `EIO`: the server always sets one, so
//! that only happens across incompatible versions.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb;
use crate::types::{AccountKeys, Attr, DirItem, FsError, Kind, SetAttr, SetTime, WriteError};

fn malformed(what: &str) -> FsError {
    FsError::new(libc::EIO, format!("malformed response: no {what}"))
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

impl From<Attr> for pb::Attr {
    fn from(a: Attr) -> Self {
        Self {
            ino: a.ino,
            kind: pb::Kind::from(a.kind).into(),
            size: a.size,
            perm: a.perm.into(),
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            atime: Some(a.atime.into()),
            mtime: Some(a.mtime.into()),
            ctime: Some(a.ctime.into()),
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
            uid: a.uid,
            gid: a.gid,
            atime: time(a.atime),
            mtime: time(a.mtime),
            ctime: time(a.ctime),
        }
    }
}

const AUTHORIZATION: &str = "authorization";
const BEARER: &str = "Bearer ";

/// Records a session token in a request's metadata.
pub fn session_to_metadata(token: &str, metadata: &mut tonic::metadata::MetadataMap) {
    if let Ok(value) = format!("{BEARER}{token}").parse() {
        metadata.insert(AUTHORIZATION, value);
    }
}

/// The session token `session_to_metadata` recorded, if any.
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
            errno: e.errno,
            message: e.message,
        }
    }
}

impl From<pb::Error> for FsError {
    fn from(e: pb::Error) -> Self {
        Self::new(e.errno, e.message)
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
    pub fn new(ino: u64, changes: SetAttr, handle: Option<String>) -> Self {
        Self {
            ino,
            handle,
            mode: changes.mode,
            uid: changes.uid,
            gid: changes.gid,
            size: changes.size,
            atime: changes.atime.map(Into::into),
            mtime: changes.mtime.map(Into::into),
        }
    }

    pub fn changes(&self) -> SetAttr {
        SetAttr {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
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
            name: d.name.into_vec(),
        }
    }
}

impl From<pb::DirItem> for DirItem {
    fn from(d: pb::DirItem) -> Self {
        Self {
            ino: d.ino,
            kind: kind(d.kind),
            name: OsString::from_vec(d.name),
        }
    }
}

/// A name as it travels.
pub fn name_bytes(name: &std::ffi::OsStr) -> Vec<u8> {
    name.as_bytes().to_vec()
}

// -- responses: server side builds them from results, client side takes
// -- them apart again.

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
    /// The session: its token, when it expires, and (on an encrypted
    /// filesystem) the wrapped private key.
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

impl From<Result<String, FsError>> for pb::OpenResponse {
    fn from(r: Result<String, FsError>) -> Self {
        use pb::open_response::Result as R;
        Self {
            result: Some(match r {
                Ok(handle) => R::Handle(handle),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::OpenResponse {
    pub fn into_result(self) -> Result<String, FsError> {
        use pb::open_response::Result as R;
        match self.result {
            Some(R::Handle(h)) => Ok(h),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("handle")),
        }
    }
}

impl From<Result<(Attr, String), FsError>> for pb::CreateResponse {
    fn from(r: Result<(Attr, String), FsError>) -> Self {
        use pb::create_response::Result as R;
        Self {
            result: Some(match r {
                Ok((attr, handle)) => R::Created(pb::Created {
                    attr: Some(attr.into()),
                    handle,
                }),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::CreateResponse {
    /// The new file's attributes, and a handle open for reading and
    /// writing it.
    pub fn into_result(self) -> Result<(Attr, String), FsError> {
        use pb::create_response::Result as R;
        match self.result {
            Some(R::Created(c)) => Ok((
                c.attr.ok_or_else(|| malformed("attributes"))?.into(),
                c.handle,
            )),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("created file")),
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

impl From<Result<Vec<u8>, FsError>> for pb::ReadResponse {
    fn from(r: Result<Vec<u8>, FsError>) -> Self {
        use pb::read_response::Result as R;
        Self {
            result: Some(match r {
                Ok(data) => R::Data(data),
                Err(e) => R::Error(e.into()),
            }),
        }
    }
}

impl pb::ReadResponse {
    pub fn into_result(self) -> Result<Vec<u8>, FsError> {
        use pb::read_response::Result as R;
        match self.result {
            Some(R::Data(data)) => Ok(data),
            Some(R::Error(e)) => Err(e.into()),
            None => Err(malformed("data")),
        }
    }
}

impl From<Result<Attr, WriteError>> for pb::WriteResponse {
    fn from(r: Result<Attr, WriteError>) -> Self {
        use pb::write_response::Result as R;
        Self {
            result: Some(match r {
                Ok(a) => R::Attr(a.into()),
                Err(e) => R::Failure(pb::WriteFailure {
                    written: e.written as u64,
                    error: Some(e.error.into()),
                }),
            }),
        }
    }
}

impl pb::WriteResponse {
    pub fn into_result(self) -> Result<Attr, WriteError> {
        use pb::write_response::Result as R;
        match self.result {
            Some(R::Attr(a)) => Ok(a.into()),
            Some(R::Failure(f)) => Err(WriteError {
                written: f.written as usize,
                error: f.error.map_or_else(|| malformed("error"), Into::into),
            }),
            None => Err(WriteError {
                written: 0,
                error: malformed("write outcome"),
            }),
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
            uid: 1001,
            gid: 100,
            atime: t,
            mtime: t,
            ctime: t,
        };
        assert_eq!(Attr::from(pb::Attr::from(a)), a);
    }

    #[test]
    fn errors_and_short_writes_survive_the_trip() {
        let e = FsError::new(libc::EACCES, "nope");
        assert_eq!(
            pb::AttrResponse::from(Err(e.clone())).into_result(),
            Err(e.clone())
        );
        let w = WriteError {
            written: 123,
            error: e,
        };
        assert_eq!(
            pb::WriteResponse::from(Err(w.clone())).into_result(),
            Err(w)
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
        assert_eq!(pb::SetAttrRequest::new(3, changes, None).changes(), changes);
    }

    #[test]
    fn a_non_utf8_name_survives() {
        let name = OsString::from_vec(vec![b'a', 0xff, b'b']);
        let item = DirItem {
            ino: 1,
            kind: Kind::File,
            name: name.clone(),
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
    fn a_created_file_without_attributes_is_eio() {
        let r = pb::CreateResponse {
            result: Some(pb::create_response::Result::Created(pb::Created {
                attr: None,
                handle: "h".into(),
            })),
        };
        assert_eq!(r.into_result().unwrap_err().errno, libc::EIO);
    }

    #[test]
    fn a_response_missing_its_result_is_eio() {
        let r = pb::AttrResponse { result: None }.into_result();
        assert_eq!(r.unwrap_err().errno, libc::EIO);
    }
}
