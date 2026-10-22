//! Errnos as they cross the wire: in Linux's numbering, whatever either
//! end runs on. Errno numbers are the host's own -- they agree between
//! Linux and the BSDs (macOS among them) only up to `ERANGE` -- so an
//! `FsError` is translated from the host's numbering on the way out
//! (`to_wire`) and back into it on the way in (`from_wire`). On Linux both
//! are the identity.
//!
//! Only the errnos the filesystem uses are translated; any other passes
//! through as it is, which is right for the shared low numbers and at
//! worst a misleading errno for the rest.

/// A stale key: a write sealed under a key that has since been rotated,
/// or under a node whose parent's has (see core's `grants::check_fresh`).
/// Linux has its own errno for it; elsewhere it is one no host errno uses,
/// for the client to retry on and never hand a kernel.
#[cfg(target_os = "linux")]
pub const EKEYEXPIRED: i32 = libc::EKEYEXPIRED;
#[cfg(not(target_os = "linux"))]
pub const EKEYEXPIRED: i32 = 0x10000 + LINUX_EKEYEXPIRED;

#[cfg(not(target_os = "linux"))]
const LINUX_EKEYEXPIRED: i32 = 127;

/// Each translated errno: (the host's number, Linux's).
#[cfg(not(target_os = "linux"))]
const TABLE: &[(i32, i32)] = &[
    (libc::EAGAIN, 11),
    (libc::ENAMETOOLONG, 36),
    (libc::ENOSYS, 38),
    (libc::ENOTEMPTY, 39),
    (libc::ENOTSUP, 95),
    (libc::ENOTCONN, 107),
    (libc::ETIMEDOUT, 110),
    (libc::ECONNREFUSED, 111),
    (libc::EHOSTUNREACH, 113),
    (libc::ESTALE, 116),
    (libc::EDQUOT, 122),
    (EKEYEXPIRED, LINUX_EKEYEXPIRED),
];

/// The host's `errno`, in the wire's numbering.
#[cfg(target_os = "linux")]
pub fn to_wire(errno: i32) -> i32 {
    errno
}

/// The wire's `errno`, in the host's numbering.
#[cfg(target_os = "linux")]
pub fn from_wire(errno: i32) -> i32 {
    errno
}

#[cfg(not(target_os = "linux"))]
pub fn to_wire(errno: i32) -> i32 {
    TABLE
        .iter()
        .find(|&&(host, _)| host == errno)
        .map_or(errno, |&(_, wire)| wire)
}

#[cfg(not(target_os = "linux"))]
pub fn from_wire(errno: i32) -> i32 {
    TABLE
        .iter()
        .find(|&&(_, wire)| wire == errno)
        .map_or(errno, |&(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for errno in [
            libc::EPERM,
            libc::ENOENT,
            libc::EIO,
            libc::EAGAIN,
            libc::ENOTEMPTY,
            libc::ENOTSUP,
            libc::EHOSTUNREACH,
            EKEYEXPIRED,
        ] {
            assert_eq!(from_wire(to_wire(errno)), errno);
        }
    }

    #[test]
    fn the_wire_numbers_as_linux_does() {
        assert_eq!(to_wire(libc::ENOENT), 2);
        assert_eq!(to_wire(libc::EAGAIN), 11);
        assert_eq!(to_wire(libc::ENOTEMPTY), 39);
        assert_eq!(to_wire(EKEYEXPIRED), 127);
    }
}
