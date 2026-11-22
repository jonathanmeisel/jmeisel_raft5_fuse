//! The field encoding that one-line strings (invitations, links) share; see
//! `raft5fs_wire`.

pub(crate) use raft5fs_wire::{Reader, put_bytes as put};

/// A count, written as a u32.
pub(crate) fn put_u32(out: &mut Vec<u8>, n: usize) {
    raft5fs_wire::put_u32(out, n as u32);
}
