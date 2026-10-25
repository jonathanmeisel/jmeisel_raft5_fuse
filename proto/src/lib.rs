//! The client/server protocol, and the plain types that core, the server,
//! and the client share.

pub mod clock;
pub mod convert;
pub mod errno;
pub mod invite;
pub mod link;
pub mod os_bytes;
pub mod timing;
pub mod types;
mod wire;

/// Generated wire types and the tonic client and server.
#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("raft5fs");
}
