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
//!
//! The errnos the client uses are named here, so that code builds where
//! there is no `libc` (a browser, through WebAssembly). On Unix they are the
//! host's; elsewhere they are Linux's numbers, which are the wire's, so
//! nothing needs translating.

#[cfg(unix)]
pub use libc::{
    EACCES, EAGAIN, EBUSY, ECONNREFUSED, EDQUOT, EEXIST, EHOSTUNREACH, EINVAL, EIO, EISDIR,
    ENAMETOOLONG, ENOENT, ENOSYS, ENOTCONN, ENOTDIR, ENOTEMPTY, ENOTSUP, EPERM, EROFS, ESTALE,
    ETIMEDOUT, EXDEV,
};

/// Linux's numbers, for hosts without `libc`.
#[cfg(not(unix))]
mod linux {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EAGAIN: i32 = 11;
    pub const EACCES: i32 = 13;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const EXDEV: i32 = 18;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const EROFS: i32 = 30;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOSYS: i32 = 38;
    pub const ENOTEMPTY: i32 = 39;
    pub const ENOTSUP: i32 = 95;
    pub const ENOTCONN: i32 = 107;
    pub const ETIMEDOUT: i32 = 110;
    pub const ECONNREFUSED: i32 = 111;
    pub const EHOSTUNREACH: i32 = 113;
    pub const ESTALE: i32 = 116;
    pub const EDQUOT: i32 = 122;
}
#[cfg(not(unix))]
pub use linux::*;

/// A stale key: a write sealed under a key that was rotated, or under a
/// node whose parent's key was rotated (see core's `grants::check_fresh`).
/// Linux has its own errno for this. On other Unix hosts it is a number that
/// no host errno uses. The client retries on it, and never gives it to a
/// kernel.
#[cfg(target_os = "linux")]
pub const EKEYEXPIRED: i32 = libc::EKEYEXPIRED;
#[cfg(all(unix, not(target_os = "linux")))]
pub const EKEYEXPIRED: i32 = 0x10000 + LINUX_EKEYEXPIRED;
#[cfg(not(unix))]
pub const EKEYEXPIRED: i32 = LINUX_EKEYEXPIRED;

#[cfg(not(target_os = "linux"))]
const LINUX_EKEYEXPIRED: i32 = 127;

/// Each translated errno: (the host's number, Linux's number).
#[cfg(all(unix, not(target_os = "linux")))]
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

/// What `errno` means, in words: the host's own text where there is one.
#[cfg(unix)]
pub fn describe(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// What `errno` means, in words. Without a host to ask, the usual texts for
/// the errnos named here.
#[cfg(not(unix))]
pub fn describe(errno: i32) -> String {
    let text = match errno {
        EPERM => "Operation not permitted",
        ENOENT => "No such file or directory",
        EIO => "Input/output error",
        EAGAIN => "Resource temporarily unavailable",
        EACCES => "Permission denied",
        EBUSY => "Device or resource busy",
        EEXIST => "File exists",
        EXDEV => "Invalid cross-device link",
        ENOTDIR => "Not a directory",
        EISDIR => "Is a directory",
        EINVAL => "Invalid argument",
        EROFS => "Read-only file system",
        ENAMETOOLONG => "File name too long",
        ENOSYS => "Function not implemented",
        ENOTEMPTY => "Directory not empty",
        ENOTSUP => "Operation not supported",
        ENOTCONN => "Transport endpoint is not connected",
        ETIMEDOUT => "Connection timed out",
        ECONNREFUSED => "Connection refused",
        EHOSTUNREACH => "No route to host",
        ESTALE => "Stale file handle",
        EDQUOT => "Disk quota exceeded",
        EKEYEXPIRED => "Key has expired",
        _ => return format!("error {errno}"),
    };
    text.to_string()
}

/// Translates the host's `errno` to the wire's numbers.
#[cfg(any(target_os = "linux", not(unix)))]
pub fn to_wire(errno: i32) -> i32 {
    errno
}

/// Translates the wire's `errno` to the host's numbers.
#[cfg(any(target_os = "linux", not(unix)))]
pub fn from_wire(errno: i32) -> i32 {
    errno
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn to_wire(errno: i32) -> i32 {
    TABLE
        .iter()
        .find(|&&(host, _)| host == errno)
        .map_or(errno, |&(_, wire)| wire)
}

#[cfg(all(unix, not(target_os = "linux")))]
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
            EPERM,
            ENOENT,
            EIO,
            EAGAIN,
            ENOTEMPTY,
            ENOTSUP,
            EHOSTUNREACH,
            EKEYEXPIRED,
        ] {
            assert_eq!(from_wire(to_wire(errno)), errno);
        }
    }

    #[test]
    fn the_wire_numbers_as_linux_does() {
        assert_eq!(to_wire(ENOENT), 2);
        assert_eq!(to_wire(EAGAIN), 11);
        assert_eq!(to_wire(ENOTEMPTY), 39);
        assert_eq!(to_wire(EKEYEXPIRED), 127);
    }
}
