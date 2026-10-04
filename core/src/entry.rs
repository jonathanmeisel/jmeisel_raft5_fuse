//! Inode records: what an inode's attribute key holds.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use raft5fs_proto::types::{Attr, Kind};

/// A directory's attributes plus its parent inode, so `readdir` can answer
/// `..` without a separate lookup. Files leave `parent` at 0 (unused: we
/// don't support hard links, so a file only ever has the one directory
/// entry that named it in `create`).
pub(crate) struct Entry {
    pub(crate) attr: Attr,
    pub(crate) parent: u64,
}

impl Entry {
    /// Whether this inode's deletion has started. Encoded as a link count
    /// of zero, which no live inode has -- a file is created with 1 and a
    /// directory with 2 -- so the record format doesn't change.
    pub(crate) fn is_deleted(&self) -> bool {
        self.attr.nlink == 0
    }

    pub(crate) fn mark_deleted(&mut self) {
        self.attr.nlink = 0;
    }
}

fn push_time(buf: &mut Vec<u8>, t: SystemTime) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    buf.extend_from_slice(&d.as_secs().to_be_bytes());
    buf.extend_from_slice(&d.subsec_nanos().to_be_bytes());
}

fn take_time(bytes: &[u8]) -> (SystemTime, &[u8]) {
    let (secs, rest) = bytes.split_at(8);
    let (nanos, rest) = rest.split_at(4);
    let secs = u64::from_be_bytes(secs.try_into().unwrap());
    let nanos = u32::from_be_bytes(nanos.try_into().unwrap());
    (UNIX_EPOCH + Duration::new(secs, nanos), rest)
}

pub(crate) fn encode_entry(entry: &Entry) -> Vec<u8> {
    let a = &entry.attr;
    let mut buf = Vec::with_capacity(67);
    buf.push(match a.kind {
        Kind::Directory => 1,
        Kind::File => 0,
    });
    buf.extend_from_slice(&a.perm.to_be_bytes());
    buf.extend_from_slice(&a.uid.to_be_bytes());
    buf.extend_from_slice(&a.gid.to_be_bytes());
    buf.extend_from_slice(&a.size.to_be_bytes());
    buf.extend_from_slice(&a.nlink.to_be_bytes());
    push_time(&mut buf, a.atime);
    push_time(&mut buf, a.mtime);
    push_time(&mut buf, a.ctime);
    buf.extend_from_slice(&entry.parent.to_be_bytes());
    buf
}

pub(crate) fn decode_entry(ino: u64, bytes: &[u8]) -> Entry {
    let (kind, rest) = bytes.split_at(1);
    let kind = if kind[0] == 1 {
        Kind::Directory
    } else {
        Kind::File
    };
    let (perm, rest) = rest.split_at(2);
    let (uid, rest) = rest.split_at(4);
    let (gid, rest) = rest.split_at(4);
    let (size, rest) = rest.split_at(8);
    let (nlink, rest) = rest.split_at(4);
    let (atime, rest) = take_time(rest);
    let (mtime, rest) = take_time(rest);
    let (ctime, rest) = take_time(rest);
    let parent = u64::from_be_bytes(rest.try_into().unwrap());

    let attr = Attr {
        ino,
        kind,
        size: u64::from_be_bytes(size.try_into().unwrap()),
        perm: u16::from_be_bytes(perm.try_into().unwrap()),
        nlink: u32::from_be_bytes(nlink.try_into().unwrap()),
        uid: u32::from_be_bytes(uid.try_into().unwrap()),
        gid: u32::from_be_bytes(gid.try_into().unwrap()),
        atime,
        mtime,
        ctime,
    };
    Entry { attr, parent }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_round_trips_through_its_encoding() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let entry = Entry {
            attr: Attr {
                ino: 42,
                kind: Kind::Directory,
                size: 9000,
                perm: 0o755,
                nlink: 2,
                uid: 1001,
                gid: 100,
                atime: t,
                mtime: t + Duration::from_secs(1),
                ctime: t + Duration::from_secs(2),
            },
            parent: 7,
        };
        let bytes = encode_entry(&entry);
        // The on-disk size existing stores were written with.
        assert_eq!(bytes.len(), 1 + 2 + 4 + 4 + 8 + 4 + 3 * 12 + 8);
        let back = decode_entry(42, &bytes);
        assert_eq!(back.attr, entry.attr);
        assert_eq!(back.parent, 7);
    }
}
