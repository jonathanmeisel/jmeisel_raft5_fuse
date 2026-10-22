//! The client/server protocol, and the plain types that core, the server,
//! and the client share.

pub mod convert;
pub mod errno;
pub mod invite;
pub mod timing;
pub mod types;

/// Generated wire types and the tonic client and server.
#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("raft5fs");
}
