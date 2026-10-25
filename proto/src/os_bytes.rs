//! Names as bytes. Names on the wire, and the tags that index directory
//! entries, are raw bytes: a tag is an HMAC, not text. `OsStr` holds them.
//!
//! On Unix this is `OsStrExt`/`OsStringExt`. Elsewhere (WebAssembly) the
//! standard library also keeps an `OsStr` as plain bytes, so the encoded
//! bytes are the bytes, unchanged. Windows keeps WTF-8, which can't hold
//! arbitrary bytes, so this refuses to build there.

use std::ffi::{OsStr, OsString};

#[cfg(windows)]
compile_error!("names are raw bytes, which a Windows OsStr can't hold");

/// The bytes of `name`.
pub fn bytes(name: &OsStr) -> &[u8] {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::as_bytes(name)
    }
    #[cfg(not(unix))]
    {
        name.as_encoded_bytes()
    }
}

/// `bytes` as a name, borrowed.
pub fn as_name(bytes: &[u8]) -> &OsStr {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStrExt::from_bytes(bytes)
    }
    // SAFETY: on this target the standard library keeps an `OsStr` as plain
    // bytes (Windows, the exception, is refused above), so every byte
    // string is a valid encoding.
    #[cfg(not(unix))]
    unsafe {
        OsStr::from_encoded_bytes_unchecked(bytes)
    }
}

/// `bytes` as a name, owned.
pub fn into_name(bytes: Vec<u8>) -> OsString {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStringExt::from_vec(bytes)
    }
    // SAFETY: as in `as_name`.
    #[cfg(not(unix))]
    unsafe {
        OsString::from_encoded_bytes_unchecked(bytes)
    }
}

/// The bytes of `name`, owned.
pub fn into_bytes(name: OsString) -> Vec<u8> {
    #[cfg(unix)]
    {
        std::os::unix::ffi::OsStringExt::into_vec(name)
    }
    #[cfg(not(unix))]
    {
        name.into_encoded_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_bytes_round_trip() {
        let raw = vec![0, b'a', 0xff, 0x80, b'/', 0xfe];
        assert_eq!(bytes(as_name(&raw)), &raw[..]);
        assert_eq!(into_bytes(into_name(raw.clone())), raw);
    }
}
