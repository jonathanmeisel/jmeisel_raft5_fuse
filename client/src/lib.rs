mod chunk_cache;
// Profiles, terminals and config files: native front ends only.
#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
mod paths;
pub mod prune_queue;
pub mod pruner;
pub mod remote;
mod rt;
pub mod session;
mod snapshot_tree;
pub mod store;
mod timing;
pub mod vault;
pub mod write_buffer;

use sha2::{Digest, Sha256};

/// A filesystem's id: a hash of the DER of the CA certificate that its
/// servers chain to. Each device files pins and prune queues under it, and
/// the web app checks invitations against it.
pub fn fs_id(ca_der: &[u8]) -> String {
    short_hash(ca_der)
}

/// The first 8 bytes of `bytes`' SHA-256, in hex.
pub(crate) fn short_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
