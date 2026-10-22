//! The WebDAV front end: `fs` makes the session a `dav_server`
//! filesystem, and `server` serves it, on loopback, to whoever has its
//! password.

mod fs;
mod server;

pub use fs::DavFs;
pub use server::{Auth, is_loopback, serve};
