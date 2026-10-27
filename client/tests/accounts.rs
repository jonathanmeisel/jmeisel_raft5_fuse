//! Tests capabilities and invitations: what the servers let an account
//! start, and how users invite users. They run against a real store and
//! servers.

use raft5fs_client::remote::Remote;
use raft5fs_core::accounts;
use raft5fs_crypto::password::KdfParams;
use raft5fs_proto::invite::Invite;
use raft5fs_proto::types::{AccountKind, Caps, FsError, MAX_PENDING_INVITES, NewNode};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, fs_tls};

#[test]
fn server_process_mode() {
    raft5fs_testkit::serve_if_requested();
}

fn errno<T: std::fmt::Debug>(result: Result<T, FsError>) -> i32 {
    result.unwrap_err().errno
}

fn connect(backend: &Backend, user: &str) -> Remote {
    backend
        .runtime
        .block_on(Remote::connect(
            &backend.addresses(),
            credentials(user),
            Some(fs_tls()),
        ))
        .unwrap_or_else(|e| panic!("log in as {user}: {e}"))
}

fn enrol_with(backend: &Backend, user: &str, code: &str) {
    backend
        .runtime
        .block_on(Remote::enrol(
            &backend.addresses(),
            Some(fs_tls()),
            credentials(user),
            code,
            KdfParams::TESTING,
        ))
        .unwrap_or_else(|e| panic!("enrol {user}: {e}"));
}

/// Asks the servers for a volume, with made-up keys: the capability check
/// comes before anything looks at them.
fn try_create_volume(backend: &Backend, remote: &Remote) -> Result<(), FsError> {
    backend.runtime.block_on(async {
        let ino = remote.allocate_inode().await?;
        let new = NewNode {
            ino,
            keys: Vec::new(),
            sealed_name: Vec::new(),
        };
        remote
            .create_volume(&new, 0o755, Vec::new(), Vec::new(), Vec::new())
            .await
            .map(drop)
    })
}

#[test]
fn volumes_need_the_capability() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;

    // An account from before capabilities has no record, and may make
    // volumes. (Its made-up keys are refused after the check.)
    let tester = connect(&backend, TESTER);
    let info = rt.block_on(tester.account()).unwrap();
    assert_eq!((info.caps, info.kind), (Caps::VOLUMES, AccountKind::Person));
    assert_ne!(errno(try_create_volume(&backend, &tester)), libc::EACCES);

    let code = rt
        .block_on(accounts::add(
            &backend.client,
            "reader",
            Caps::NONE,
            Caps::VOLUMES,
        ))
        .unwrap();
    enrol_with(&backend, "reader", &code);
    let reader = connect(&backend, "reader");
    assert_eq!(rt.block_on(reader.account()).unwrap().caps, Caps::NONE);
    assert_eq!(errno(try_create_volume(&backend, &reader)), libc::EACCES);

    // Turned on, it works at once; the record outlives a new enrolment.
    rt.block_on(accounts::set_caps(
        &backend.client,
        "reader",
        Caps::VOLUMES,
        Caps::NONE,
    ))
    .unwrap();
    assert_ne!(errno(try_create_volume(&backend, &reader)), libc::EACCES);
    let code = rt
        .block_on(accounts::issue_code(&backend.client, "reader"))
        .unwrap();
    enrol_with(&backend, "reader", &code);
    assert_eq!(
        rt.block_on(connect(&backend, "reader").account())
            .unwrap()
            .caps,
        Caps::VOLUMES
    );

    assert_eq!(
        errno(rt.block_on(accounts::set_caps(
            &backend.client,
            "nobody",
            Caps::INVITE,
            Caps::NONE
        ))),
        libc::ENOENT
    );
}

#[test]
fn users_invite_new_users_only() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = connect(&backend, TESTER);

    assert_eq!(
        errno(rt.block_on(tester.issue_invite("dave", Caps::NONE))),
        libc::EACCES
    );
    rt.block_on(accounts::set_caps(
        &backend.client,
        TESTER,
        Caps::INVITE,
        Caps::NONE,
    ))
    .unwrap();

    // Not more than the inviter has.
    assert_eq!(
        errno(rt.block_on(tester.issue_invite("dave", Caps::LINKS))),
        libc::EACCES
    );
    // Only new names: not an account, a pending code, or a link's name.
    rt.block_on(accounts::issue_code(&backend.client, "erin"))
        .unwrap();
    for (name, expected) in [
        (TESTER, libc::EEXIST),
        ("erin", libc::EEXIST),
        ("link-abc", libc::EINVAL),
        ("Bad Name", libc::EINVAL),
    ] {
        assert_eq!(
            errno(rt.block_on(tester.issue_invite(name, Caps::NONE))),
            expected,
            "{name}"
        );
    }

    let (code, invitation) = rt
        .block_on(tester.issue_invite("dave", Caps::VOLUMES))
        .unwrap();
    let invite =
        Invite::decode(&invitation.expect("the test servers know their addresses")).unwrap();
    assert_eq!(
        (invite.user.as_str(), invite.code.as_str()),
        ("dave", code.as_str())
    );
    assert_eq!(invite.servers.len(), 1);
    assert_eq!(
        errno(rt.block_on(tester.issue_invite("dave", Caps::NONE))),
        libc::EEXIST
    );
    let pending = rt.block_on(tester.list_invites()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        (pending[0].user.as_str(), pending[0].caps),
        ("dave", Caps::VOLUMES)
    );

    enrol_with(&backend, "dave", &code);
    assert!(rt.block_on(tester.list_invites()).unwrap().is_empty());
    let dave = connect(&backend, "dave");
    let info = rt.block_on(dave.account()).unwrap();
    assert_eq!(
        (info.caps, info.invited_by.as_str()),
        (Caps::VOLUMES, TESTER)
    );
    // Dave can't invite, and can't cancel what isn't his.
    assert_eq!(
        errno(rt.block_on(dave.issue_invite("fay", Caps::NONE))),
        libc::EACCES
    );

    // At most so many waiting at once; cancelling makes room.
    for i in 0..MAX_PENDING_INVITES {
        rt.block_on(tester.issue_invite(&format!("u{i}"), Caps::NONE))
            .unwrap();
    }
    assert_eq!(
        errno(rt.block_on(tester.issue_invite("one-more", Caps::NONE))),
        libc::EDQUOT
    );
    assert_eq!(errno(rt.block_on(dave.cancel_invite("u0"))), libc::ENOENT);
    // An enrolled account is no invitation to cancel.
    assert_eq!(
        errno(rt.block_on(tester.cancel_invite("dave"))),
        libc::ENOENT
    );
    rt.block_on(tester.cancel_invite("u0")).unwrap();
    rt.block_on(tester.issue_invite("one-more", Caps::NONE))
        .unwrap();
    // A cancelled name is free again, and its code is gone.
    assert_eq!(
        errno(rt.block_on(Remote::enrol(
            &backend.addresses(),
            Some(fs_tls()),
            credentials("u0"),
            "wrong",
            KdfParams::TESTING,
        ))),
        libc::EACCES
    );

    // The administrator's listing knows who invited whom; removing an
    // account removes its record.
    let listed = rt.block_on(accounts::list(&backend.client)).unwrap();
    let dave_row = listed.iter().find(|r| r.name == "dave").unwrap();
    assert!(dave_row.enrolled);
    assert_eq!(dave_row.info.invited_by, TESTER);
    assert!(!listed.iter().any(|r| r.name == "u0"));
    assert!(
        rt.block_on(accounts::remove(&backend.client, "dave"))
            .unwrap()
    );
    assert_eq!(
        rt.block_on(accounts::info(&backend.client, "dave"))
            .unwrap()
            .invited_by,
        ""
    );
}
