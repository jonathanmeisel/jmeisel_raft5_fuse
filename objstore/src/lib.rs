//! The object store a large file's blocks live in, past the size the KV
//! store keeps inline.
//!
//! Three parts, used by different tiers:
//!
//! - `name`: what an object is called. Its key carries the inode it
//!   belongs to and when the server minted it, which is all garbage
//!   collection needs to know about an object without reading it.
//! - `S3Store`: the filesystem servers' side. It signs the URLs mounts
//!   use -- a GET to read a block, a PUT to create one -- and lists and
//!   deletes for garbage collection. Mounts never hold bucket
//!   credentials, only URLs a server signed after checking their grant.
//! - `http`: the mounts' side. Fetching a range of an object and
//!   uploading one through those URLs.
//!
//! Every object is written once. A PUT URL signs `If-None-Match: *`, so
//! the store refuses a second upload to the same name, and the length,
//! so it refuses a body of any other size. What a pointer in the KV store
//! names therefore never changes under it.

use std::fmt;

pub mod http;
pub mod name;
mod s3;

#[cfg(feature = "fake")]
pub mod fake;

pub use name::ObjectName;
pub use s3::{Listed, S3Config, S3Store};

#[derive(Debug)]
pub enum Error {
    /// The store's settings can't be used (a bad endpoint, prefix, CA).
    Config(String),
    /// The request didn't get an answer.
    Http(reqwest::Error),
    /// The store answered with an error.
    Status { status: u16, body: String },
    /// An upload to a name that already has an object: the URL was used
    /// before.
    AlreadyExists,
    /// The store answered, but not with anything we can use.
    Malformed(String),
    /// Some of a batch of deletions failed, each with the store's reason.
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

/// How much of an error response's body is kept in an `Error::Status`:
/// enough for S3's `<Code>` and `<Message>`, not a whole page.
const ERROR_BODY_LIMIT: usize = 512;

/// `Error::Status` for a response that isn't the success expected,
/// keeping the start of its body.
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
