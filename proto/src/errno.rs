//! Errnos on the wire use Linux's numbers, on every platform.
//!
//! Errno numbers belong to the host. Linux and the BSDs (including macOS)
//! agree only up to `ERANGE`. So an `FsError` is translated from the host's
//! numbers when it goes out (`to_wire`), and back when it comes in
//! (`from_wire`). On Linux, both do nothing.
//!
//! Only the errnos that the filesystem uses are translated. Others pass
//! through unchanged. That is correct for the shared low numbers, and at
//! worst gives a misleading errno for the rest.

/// A stale key: a write sealed under a key that was rotated, or under a
/// node whose parent's key was rotated (see core's `grants::check_fresh`).
/// Linux has its own errno for this. On other hosts it is a number that no
/// host errno uses. The client retries on it, and never gives it to a
/// kernel.
#[cfg(target_os = "linux")]
pub const EKEYEXPIRED: i32 = libc::EKEYEXPIRED;
#[cfg(not(target_os = "linux"))]
pub const EKEYEXPIRED: i32 = 0x10000 + LINUX_EKEYEXPIRED;

#[cfg(not(target_os = "linux"))]
const LINUX_EKEYEXPIRED: i32 = 127;

/// Each translated errno: (the host's number, Linux's number).
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

/// Translates the host's `errno` to the wire's numbers.
#[cfg(target_os = "linux")]
pub fn to_wire(errno: i32) -> i32 {
    errno
}

/// Translates the wire's `errno` to the host's numbers.
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
