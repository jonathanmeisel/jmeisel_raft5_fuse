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
pub const PROTOCOL: u32 = 11;

/// The protocol version that first has each feature. A client checks the
/// servers' version before it uses one, so older servers give a clear
/// refusal (`Remote::needs_protocol`).
pub mod since {
    /// Capabilities, invitations made by admins, and public links.
    pub const CAPABILITIES: u32 = 2;
    /// Each account's trusted keys, sealed and kept on the servers.
    pub const PINS: u32 = 3;
    /// Managing users: listing, changing, re-enrolling and removing them.
    pub const USER_ADMIN: u32 = 4;
    /// Finding, and deleting, folders that no account can reach.
    pub const UNREACHABLE: u32 = 5;
    /// Volume owners, transfers, quotas, storage use and folder limits.
    pub const VOLUMES: u32 = 6;
    /// Grant labels signed by whoever made the grant.
    pub const SIGNED_LABELS: u32 = 8;
    /// The log of who changed what in a volume.
    pub const ACTIVITY: u32 = 9;
    /// Prunes that any writer can finish, with claims.
    pub const SHARED_PRUNING: u32 = 10;
    /// Invitations that check keys, and introductions.
    pub const INVITE_TRUST: u32 = 11;
}

/// Generated wire types and the tonic client and server.
#[allow(clippy::all)]
pub mod pb {
    tonic::include_proto!("raft5fs");
}
