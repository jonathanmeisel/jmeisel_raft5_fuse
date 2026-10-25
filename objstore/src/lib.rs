//! The object store for a large file's blocks, after the size that the KV
//! store keeps inline. It has three parts, used by different tiers:
//!
//! - `name`: object names. A name holds the inode it belongs to and when
//!   the server minted it. Garbage collection needs nothing else to know
//!   about an object, so it never reads one.
//! - `S3Store`: the filesystem servers' side. It signs the URLs that mounts
//!   use (a GET to read a block, a PUT to make one), lists and deletes
//!   objects for garbage collection, and copies objects and backup files
//!   for backups. Mounts never hold bucket credentials,
//!   only URLs that a server signed after it checked their grant.
//! - `http`: the mounts' side. It fetches a range of an object, and uploads
//!   one, through those URLs.
//!
//! Every object is written once. A PUT URL signs `If-None-Match: *`, so the
//! store refuses a second upload to the same name. It also signs the
//! length, so the store refuses a body of any other size. So the object
//! that a KV pointer names never changes.

use std::fmt;

pub mod http;
pub mod name;
#[cfg(not(target_arch = "wasm32"))]
mod s3;

#[cfg(feature = "fake")]
pub mod fake;

pub use name::ObjectName;
#[cfg(not(target_arch = "wasm32"))]
pub use s3::{Listed, S3Config, S3Store};

#[derive(Debug)]
pub enum Error {
    /// The store's settings are not usable (a bad endpoint, prefix, or CA).
    Config(String),
    /// The request got no answer.
    Http(reqwest::Error),
    /// The store answered with an error.
    Status { status: u16, body: String },
    /// An upload to a name that already has an object: the URL was used
    /// before.
    AlreadyExists,
    /// No object has this key.
    NotFound(String),
    /// The store answered, but the answer is not usable.
    Malformed(String),
    /// Some deletions in a batch failed, each with the store's reason.
    NotDeleted(Vec<String>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(why) => write!(f, "object store settings: {why}"),
            Error::Http(e) => write!(f, "object store request failed: {e}"),
            Error::Status { status, body } => {
                write!(f, "object store refused the request ({status})")?;
                if !body.is_empty() {
                    write!(f, ": {body}")?;
                }
                Ok(())
            }
            Error::AlreadyExists => write!(f, "the object already exists"),
            Error::NotFound(key) => write!(f, "no object {key}"),
            Error::Malformed(why) => write!(f, "object store answered oddly: {why}"),
            Error::NotDeleted(failures) => {
                write!(
                    f,
                    "{} objects not deleted: {}",
                    failures.len(),
                    failures.join("; ")
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Http(e)
    }
}

/// How much of an error response's body `Error::Status` keeps: enough for
/// S3's `<Code>` and `<Message>`, but not a whole page.
const ERROR_BODY_LIMIT: usize = 512;

/// Makes an `Error::Status` for an unexpected response, with the start of
/// its body.
async fn status_error(response: reqwest::Response) -> Error {
    let status = response.status().as_u16();
    let mut body = response.text().await.unwrap_or_default();
    if body.len() > ERROR_BODY_LIMIT {
        let mut end = ERROR_BODY_LIMIT;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
    Error::Status { status, body }
}
