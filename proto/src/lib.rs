//! The client/server protocol, and the plain types shared by core, the
//! server and the client.

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
