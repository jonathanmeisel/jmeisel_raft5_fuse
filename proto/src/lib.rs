//! The client/server protocol, and the plain types that core, the server,
//! and the client share.

pub mod clock;
pub mod convert;
pub mod errno;
pub mod invite;
pub mod link;
pub mod os_bytes;
pub mod public_link;
pub mod timing;
pub mod types;
mod wire;

/// The protocol version that this build speaks, which servers send in
/// `HelloResponse.protocol`. It goes up when a change needs servers and
/// clients to agree, so that a client can refuse a server older than it
/// needs with a clear message. Servers and the web app are released apart,
/// so they can drift.
pub const PROTOCOL: u32 = 5;

/// Generated wire types and the tonic client and server.
#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("raft5fs");
}
