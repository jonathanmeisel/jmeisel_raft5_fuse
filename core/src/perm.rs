//! POSIX permission rules, as pure functions of who is asking and the
//! attributes involved. The operations in `fs` call these on attributes
//! read inside their own transaction, so a concurrent chmod can't slip in
//! between the check and the change it guards.
//!
//! None of them binds a caller on an encrypted filesystem
//! (`Caller::by_grant`): there, grants decide, and the mode bits are only
//! kept and shown.

use raft5fs_proto::types::{Attr, Caller, FsError, Kind, SetAttr, SetTime};

pub const R: u32 = libc::R_OK as u32;
pub const W: u32 = libc::W_OK as u32;
pub const X: u32 = libc::X_OK as u32;

const S_ISUID: u16 = 0o4000;
const S_ISGID: u16 = 0o2000;
const S_ISVTX: u16 = 0o1000;

/// Whether `caller` holds every right in `want` (some of `R`, `W`, `X`)
/// on `attr`. One class applies -- owner, else group, else other -- even
/// when a lower class would grant more, as POSIX has it. Root holds every
/// right, except that executing a file still takes an execute bit
/// somewhere.
pub fn may(caller: &Caller, attr: &Attr, want: u32) -> bool {
    if caller.by_grant() {
        return true;
    }
    if caller.is_root() {
        return want & X == 0 || attr.kind == Kind::Directory || attr.perm & 0o111 != 0;
    }
    let shift = if caller.uid == attr.uid {
        6
    } else if caller.in_group(attr.gid) {
        3
    } else {
        0
    };
    let granted = (u32::from(attr.perm) >> shift) & 0o7;
    granted & want == want
}

/// `may`, as an `EACCES` when it doesn't.
pub fn check(caller: &Caller, attr: &Attr, want: u32) -> Result<(), FsError> {
    if may(caller, attr, want) {
        Ok(())
    } else {
        Err(FsError::errno(libc::EACCES))
    }
}

/// What it takes to add or remove a name in `dir`: it must be a directory,
/// and the caller needs write and search on it.
pub fn check_modify_dir(caller: &Caller, dir: &Attr) -> Result<(), FsError> {
    if dir.kind != Kind::Directory {
        return Err(FsError::errno(libc::ENOTDIR));
    }
    check(caller, dir, W | X)
}

/// The sticky bit's extra rule for removing `child` from `dir`: only the
/// child's owner, the directory's owner or root may. Checked after
/// `check_modify_dir`, which applies regardless.
pub fn check_sticky(caller: &Caller, dir: &Attr, child: &Attr) -> Result<(), FsError> {
    if dir.perm & S_ISVTX == 0
        || caller.by_grant()
        || caller.is_root()
        || caller.uid == child.uid
        || caller.uid == dir.uid
    {
        Ok(())
    } else {
        Err(FsError::errno(libc::EPERM))
    }
}

/// The owner and permission bits of a new inode in `dir`. A setgid
/// directory hands its group down, and to subdirectories its setgid bit
/// too; elsewhere the creator's primary group applies. A file can't keep
/// a setgid bit for a group its creator isn't in.
pub fn new_owner(caller: &Caller, dir: &Attr, kind: Kind, perm: u16) -> (u32, u32, u16) {
    let mut perm = perm & 0o7777;
    let gid = if dir.perm & S_ISGID != 0 {
        if kind == Kind::Directory {
            perm |= S_ISGID;
        }
        dir.gid
    } else {
        caller.gid
    };
    if kind == Kind::File && !caller.is_root() && !caller.in_group(gid) {
        perm &= !S_ISGID;
    }
    (caller.uid, gid, perm)
}

/// Whether `caller` may make `changes` to `attr`. `writable_handle` says
/// the change comes through a handle opened for writing (`ftruncate`),
/// which grants a size change whatever the mode says now.
pub fn check_setattr(
    caller: &Caller,
    attr: &Attr,
    changes: &SetAttr,
    writable_handle: bool,
) -> Result<(), FsError> {
    if caller.by_grant() {
        return Ok(());
    }
    let eperm = || Err(FsError::errno(libc::EPERM));
    let root = caller.is_root();
    let owner = root || caller.uid == attr.uid;

    if changes.mode.is_some() && !owner {
        return eperm();
    }
    // Only root gives a file away. The owner may name themselves, which
    // changes nothing but is what `chown $(id -u) f` does.
    if let Some(uid) = changes.uid
        && !root
        && !(caller.uid == attr.uid && uid == attr.uid)
    {
        return eperm();
    }
    if let Some(gid) = changes.gid
        && !root
        && !(caller.uid == attr.uid && (gid == attr.gid || caller.in_group(gid)))
    {
        return eperm();
    }
    if changes.size.is_some() {
        if attr.kind == Kind::Directory {
            return Err(FsError::errno(libc::EISDIR));
        }
        if !writable_handle {
            check(caller, attr, W)?;
        }
    }
    // Setting a time to "now" is what anyone who may write the file does
    // implicitly by writing, so it is allowed with write permission. Any
    // other time takes ownership.
    let times = [changes.atime, changes.mtime];
    if times.iter().any(|t| matches!(t, Some(SetTime::At(_)))) {
        if !owner {
            return eperm();
        }
    } else if times.iter().any(Option::is_some) && !owner {
        check(caller, attr, W)?;
    }
    Ok(())
}

/// The permission bits once `changes` (already allowed by `check_setattr`)
/// apply to `attr`, including what changing the file implicitly drops:
///
/// - Changing a file's owner or group drops its setuid and setgid bits,
///   so a chown can't hand anyone a privilege the old owner set up.
/// - A truncate by anyone but root drops them too, as any modification
///   of the file does.
/// - A non-root chmod can't set setgid on a file whose group the caller
///   isn't in.
///
/// An explicit mode in the same request wins over the first two.
pub fn new_perm(caller: &Caller, attr: &Attr, changes: &SetAttr) -> u16 {
    if let Some(mode) = changes.mode {
        let mut perm = (mode & 0o7777) as u16;
        let gid = changes.gid.unwrap_or(attr.gid);
        if attr.kind == Kind::File && !caller.is_root() && !caller.in_group(gid) {
            perm &= !S_ISGID;
        }
        return perm;
    }
    let chown =
        changes.uid.is_some_and(|u| u != attr.uid) || changes.gid.is_some_and(|g| g != attr.gid);
    let truncate = changes.size.is_some() && !caller.is_root();
    if attr.kind == Kind::File && (chown || truncate) {
        attr.perm & !(S_ISUID | S_ISGID)
    } else {
        attr.perm
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    const OWNER: u32 = 1000;
    const GROUP: u32 = 100;

    fn attr(kind: Kind, perm: u16) -> Attr {
        Attr {
            ino: 2,
            kind,
            size: 0,
            perm,
            nlink: 1,
            uid: OWNER,
            gid: GROUP,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
        }
    }

    fn file(perm: u16) -> Attr {
        attr(Kind::File, perm)
    }

    fn dir(perm: u16) -> Attr {
        attr(Kind::Directory, perm)
    }

    fn owner() -> Caller {
        Caller::new(OWNER, 1, vec![])
    }

    fn member() -> Caller {
        Caller::new(2000, 1, vec![GROUP])
    }

    fn other() -> Caller {
        Caller::new(3000, 1, vec![])
    }

    #[test]
    fn grants_not_mode_bits_bind_an_encrypted_filesystems_callers() {
        let stranger = Caller::new(3000, 1, vec![]).with_user("eve");
        let locked = file(0o000);
        assert!(may(&stranger, &locked, R | W | X));
        check_sticky(&stranger, &dir(0o1777), &locked).unwrap();
        let chown = SetAttr {
            uid: Some(0),
            ..SetAttr::default()
        };
        check_setattr(&stranger, &locked, &chown, false).unwrap();
    }

    fn root() -> Caller {
        Caller::new(0, 0, vec![])
    }

    fn errno<T: std::fmt::Debug>(r: Result<T, FsError>) -> i32 {
        r.unwrap_err().errno
    }

    #[test]
    fn each_class_gets_its_own_bits() {
        let f = file(0o640);
        assert!(may(&owner(), &f, R | W));
        assert!(may(&member(), &f, R));
        assert!(!may(&member(), &f, W));
        assert!(!may(&other(), &f, R));
    }

    #[test]
    fn the_primary_group_counts_as_membership() {
        assert!(may(&Caller::new(2000, GROUP, vec![]), &file(0o040), R));
    }

    #[test]
    fn only_the_first_matching_class_applies() {
        // The owner is refused even though "other" could read.
        let f = file(0o004);
        assert!(!may(&owner(), &f, R));
        assert!(!may(&member(), &f, R));
        assert!(may(&other(), &f, R));
    }

    #[test]
    fn root_may_do_anything_but_run_a_file_nobody_may_run() {
        assert!(may(&root(), &file(0o000), R | W));
        assert!(!may(&root(), &file(0o600), X));
        assert!(may(&root(), &file(0o100), X));
        assert!(may(&root(), &dir(0o000), R | W | X));
    }

    #[test]
    fn asking_for_nothing_is_always_granted() {
        assert!(may(&other(), &file(0o000), 0));
    }

    #[test]
    fn modifying_a_directory_takes_write_and_search() {
        assert!(check_modify_dir(&owner(), &dir(0o700)).is_ok());
        assert_eq!(errno(check_modify_dir(&owner(), &dir(0o500))), libc::EACCES);
        assert_eq!(errno(check_modify_dir(&owner(), &dir(0o600))), libc::EACCES);
        assert_eq!(
            errno(check_modify_dir(&owner(), &file(0o700))),
            libc::ENOTDIR
        );
    }

    #[test]
    fn the_sticky_bit_protects_other_peoples_entries() {
        let tmp = Attr {
            uid: 0,
            ..dir(0o1777)
        };
        let theirs = file(0o644);
        assert!(check_sticky(&owner(), &tmp, &theirs).is_ok());
        assert_eq!(errno(check_sticky(&other(), &tmp, &theirs)), libc::EPERM);
        assert!(check_sticky(&root(), &tmp, &theirs).is_ok());
        // The directory's owner may remove anything in it.
        let owned_tmp = dir(0o1777);
        let strangers = Attr {
            uid: 3000,
            ..theirs
        };
        assert!(check_sticky(&owner(), &owned_tmp, &strangers).is_ok());
        // Without the bit anyone who may write the directory may remove.
        assert!(check_sticky(&other(), &dir(0o777), &theirs).is_ok());
    }

    #[test]
    fn new_inodes_take_the_creators_ids() {
        assert_eq!(
            new_owner(&member(), &dir(0o777), Kind::File, 0o644),
            (2000, 1, 0o644)
        );
    }

    #[test]
    fn a_setgid_directory_hands_down_its_group() {
        let shared = dir(0o2770);
        assert_eq!(
            new_owner(&member(), &shared, Kind::File, 0o640),
            (2000, GROUP, 0o640)
        );
        assert_eq!(
            new_owner(&member(), &shared, Kind::Directory, 0o750),
            (2000, GROUP, 0o2750)
        );
    }

    #[test]
    fn a_file_cannot_be_born_setgid_for_a_foreign_group() {
        let (_, gid, perm) = new_owner(&other(), &dir(0o2777), Kind::File, 0o2755);
        assert_eq!((gid, perm), (GROUP, 0o755));
        let (_, _, perm) = new_owner(&member(), &dir(0o2777), Kind::File, 0o2755);
        assert_eq!(perm, 0o2755);
    }

    fn chmod(mode: u32) -> SetAttr {
        SetAttr {
            mode: Some(mode),
            ..Default::default()
        }
    }

    #[test]
    fn only_the_owner_may_chmod() {
        let f = file(0o666);
        assert!(check_setattr(&owner(), &f, &chmod(0o600), false).is_ok());
        assert!(check_setattr(&root(), &f, &chmod(0o600), false).is_ok());
        assert_eq!(
            errno(check_setattr(&member(), &f, &chmod(0o600), false)),
            libc::EPERM
        );
    }

    #[test]
    fn only_root_may_give_a_file_away() {
        let f = file(0o644);
        let to = |uid| SetAttr {
            uid: Some(uid),
            ..Default::default()
        };
        assert!(check_setattr(&root(), &f, &to(3000), false).is_ok());
        assert!(check_setattr(&owner(), &f, &to(OWNER), false).is_ok());
        assert_eq!(
            errno(check_setattr(&owner(), &f, &to(3000), false)),
            libc::EPERM
        );
        assert_eq!(
            errno(check_setattr(&other(), &f, &to(OWNER), false)),
            libc::EPERM
        );
    }

    #[test]
    fn the_owner_may_chgrp_only_to_their_own_groups() {
        let f = file(0o644);
        let to = |gid| SetAttr {
            gid: Some(gid),
            ..Default::default()
        };
        let owner = Caller::new(OWNER, 1, vec![GROUP, 7]);
        assert!(check_setattr(&owner, &f, &to(7), false).is_ok());
        assert_eq!(errno(check_setattr(&owner, &f, &to(8), false)), libc::EPERM);
        assert_eq!(
            errno(check_setattr(&member(), &f, &to(GROUP), false)),
            libc::EPERM
        );
        assert!(check_setattr(&root(), &f, &to(8), false).is_ok());
    }

    #[test]
    fn truncating_takes_write_or_a_writable_handle() {
        let truncate = SetAttr {
            size: Some(0),
            ..Default::default()
        };
        assert!(check_setattr(&member(), &file(0o664), &truncate, false).is_ok());
        assert_eq!(
            errno(check_setattr(&member(), &file(0o644), &truncate, false)),
            libc::EACCES
        );
        assert!(check_setattr(&member(), &file(0o644), &truncate, true).is_ok());
        assert_eq!(
            errno(check_setattr(&owner(), &dir(0o755), &truncate, false)),
            libc::EISDIR
        );
    }

    #[test]
    fn touching_takes_write_but_backdating_takes_ownership() {
        let now = SetAttr {
            atime: Some(SetTime::Now),
            mtime: Some(SetTime::Now),
            ..Default::default()
        };
        let backdate = SetAttr {
            mtime: Some(SetTime::At(UNIX_EPOCH)),
            ..Default::default()
        };
        let shared = file(0o664);
        assert!(check_setattr(&member(), &shared, &now, false).is_ok());
        assert_eq!(
            errno(check_setattr(&other(), &shared, &now, false)),
            libc::EACCES
        );
        assert_eq!(
            errno(check_setattr(&member(), &shared, &backdate, false)),
            libc::EPERM
        );
        assert!(check_setattr(&owner(), &file(0o444), &backdate, false).is_ok());
    }

    #[test]
    fn chown_and_truncate_drop_setuid_and_setgid() {
        let f = file(0o6755);
        let chown = SetAttr {
            uid: Some(3000),
            ..Default::default()
        };
        assert_eq!(new_perm(&root(), &f, &chown), 0o755);
        let truncate = SetAttr {
            size: Some(0),
            ..Default::default()
        };
        assert_eq!(new_perm(&owner(), &f, &truncate), 0o755);
        assert_eq!(new_perm(&root(), &f, &truncate), 0o6755);
        // Directories keep setgid: it means inheritance there, not privilege.
        let d = dir(0o2775);
        let chgrp = SetAttr {
            gid: Some(7),
            ..Default::default()
        };
        assert_eq!(new_perm(&root(), &d, &chgrp), 0o2775);
    }

    #[test]
    fn chmod_cannot_set_setgid_for_a_foreign_group() {
        let f = file(0o755);
        assert_eq!(new_perm(&owner(), &f, &chmod(0o2755)), 0o755);
        let in_group = Caller::new(OWNER, GROUP, vec![]);
        assert_eq!(new_perm(&in_group, &f, &chmod(0o2755)), 0o2755);
        assert_eq!(new_perm(&root(), &f, &chmod(0o2755)), 0o2755);
        assert_eq!(new_perm(&owner(), &dir(0o755), &chmod(0o2755)), 0o2755);
    }
}
