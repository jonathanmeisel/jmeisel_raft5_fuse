//! File chunks and directory entry names, under their node's key.
//!
//! Both start with the key version they were sealed under, unencrypted:
//! the server checks it (a write must use the node's current version) and
//! a reader uses it to pick the right key from the node's history.
//!
//! A name has two forms. Its *tag* -- `HMAC(directory's name key, name)`
//! -- is what the server files the entry under, so lookups by name still
//! work without the server learning it. Its *sealed* form is what the
//! listing returns, readable by key holders. Opening a sealed name checks
//! it against the tag, so the server can't show one entry under another
//! entry's name.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{AEAD_OVERHEAD, Error, Key, Reader, aad, open, seal};

pub const TAG_LEN: usize = 32;
/// What sealing adds to a chunk: its version, the nonce and the tag.
pub const CHUNK_OVERHEAD: usize = 4 + AEAD_OVERHEAD;

fn chunk_aad(ino: u64, index: u64, version: u32) -> Vec<u8> {
    aad(
        "chunk",
        &[
            &ino.to_be_bytes(),
            &index.to_be_bytes(),
            &version.to_be_bytes(),
        ],
    )
}

/// Chunk `index` of file `ino`, sealed under the file's key at `version`.
pub fn seal_chunk(key: &Key, version: u32, ino: u64, index: u64, plain: &[u8]) -> Vec<u8> {
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&seal(key, &chunk_aad(ino, index, version), plain));
    out
}

/// The key version a sealed chunk or name was sealed under.
pub fn sealed_version(blob: &[u8]) -> Result<u32, Error> {
    Reader(blob).u32("a sealed version")
}

/// Opens a chunk with the file's key at the chunk's version (see
/// `sealed_version`). A chunk moved to another file or index won't open.
pub fn open_chunk(key: &Key, ino: u64, index: u64, blob: &[u8]) -> Result<Vec<u8>, Error> {
    let version = sealed_version(blob)?;
    open(
        key,
        &chunk_aad(ino, index, version),
        &blob[4..],
        "a file chunk",
    )
}

/// The tag `name` is filed under in a directory with `name_key`.
pub fn name_tag(name_key: &Key, name: &[u8]) -> [u8; TAG_LEN] {
    name_mac(name_key, name).finalize().into_bytes().into()
}

fn name_mac(name_key: &Key, name: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(name_key.as_bytes())
        .expect("HMAC takes any key length");
    mac.update(name);
    mac
}

fn name_aad(parent: u64, tag: &[u8], version: u32) -> Vec<u8> {
    aad(
        "name",
        &[&parent.to_be_bytes(), tag, &version.to_be_bytes()],
    )
}

/// `name`, filed under `tag` in directory `parent`, sealed under the
/// directory's key at `version`.
pub fn seal_name(key: &Key, version: u32, parent: u64, tag: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&seal(key, &name_aad(parent, tag, version), name));
    out
}

/// Opens a sealed name with the directory's key at its version, and
/// checks it is the name `tag` stands for.
pub fn open_name(
    key: &Key,
    name_key: &Key,
    parent: u64,
    tag: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let version = sealed_version(blob)?;
    let name = open(
        key,
        &name_aad(parent, tag, version),
        &blob[4..],
        "an entry name",
    )?;
    name_mac(name_key, &name)
        .verify_slice(tag)
        .map_err(|_| Error("an entry name"))?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_opens_only_where_it_was_sealed() {
        let key = Key::random();
        let blob = seal_chunk(&key, 2, 10, 3, b"data");
        assert_eq!(blob.len(), 4 + CHUNK_OVERHEAD);
        assert_eq!(sealed_version(&blob).unwrap(), 2);
        assert_eq!(open_chunk(&key, 10, 3, &blob).unwrap(), b"data");
        assert!(open_chunk(&key, 10, 4, &blob).is_err(), "another index");
        assert!(open_chunk(&key, 11, 3, &blob).is_err(), "another file");
        assert!(open_chunk(&Key::random(), 10, 3, &blob).is_err());
        let mut relabelled = blob.clone();
        relabelled[3] = 3;
        assert!(
            open_chunk(&key, 10, 3, &relabelled).is_err(),
            "version is bound"
        );
        assert!(open_chunk(&key, 10, 3, &blob[..3]).is_err());
    }

    #[test]
    fn tags_are_per_directory_and_deterministic() {
        let a = Key::random();
        let b = Key::random();
        assert_eq!(name_tag(&a, b"x"), name_tag(&a, b"x"));
        assert_ne!(name_tag(&a, b"x"), name_tag(&a, b"y"));
        assert_ne!(name_tag(&a, b"x"), name_tag(&b, b"x"));
    }

    #[test]
    fn a_name_opens_only_under_its_own_tag_and_directory() {
        let key = Key::random();
        let name_key = Key::random();
        let tag = name_tag(&name_key, b"report.txt");
        let other = name_tag(&name_key, b"other.txt");
        let blob = seal_name(&key, 1, 7, &tag, b"report.txt");
        assert_eq!(
            open_name(&key, &name_key, 7, &tag, &blob).unwrap(),
            b"report.txt"
        );
        assert!(open_name(&key, &name_key, 8, &tag, &blob).is_err());
        assert!(open_name(&key, &name_key, 7, &other, &blob).is_err());
        // A name sealed under the right tag but not matching it: what a
        // client with the key, but no honesty, could write.
        let lying = seal_name(&key, 1, 7, &other, b"report.txt");
        assert!(open_name(&key, &name_key, 7, &other, &lying).is_err());
    }
}
