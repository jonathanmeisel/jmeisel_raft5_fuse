//! Tests capabilities and invitations: what the servers let an account
//! start, and how users invite users. They run against a real store and
//! servers.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::remote::Remote;
use raft5fs_client::vault::Vault;
use raft5fs_core::accounts;
use raft5fs_crypto::password::KdfParams;
use raft5fs_proto::invite::Invite;
use raft5fs_proto::types::{AccountKind, Caps, FsError, MAX_PENDING_INVITES, NewNode};
use raft5fs_testkit::{Backend, TEST_CHUNK_SIZE, TESTER, credentials, credentials_with, fs_tls};

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

fn enrol_with(backend: &Backend, user: &str, code: &str) -> [u8; 32] {
    backend
        .runtime
        .block_on(Remote::enrol(
            &backend.addresses(),
            Some(fs_tls()),
            credentials(user),
            code,
            KdfParams::TESTING,
        ))
        .unwrap_or_else(|e| panic!("enrol {user}: {e}"))
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

fn vault(backend: &Backend, user: &str) -> Vault {
    Vault::new(Arc::new(connect(backend, user))).unwrap()
}

/// Logs in as a link, as a visitor's browser does.
fn visit(backend: &Backend, user: &str, secret: &str) -> Result<Vault, String> {
    let remote = backend.runtime.block_on(Remote::connect(
        &backend.addresses(),
        credentials_with(user, secret),
        Some(fs_tls()),
    ))?;
    Vault::new(Arc::new(remote)).map_err(|e| e.message)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn public_links_read_one_folder_until_any_writer_revokes() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    backend.enrol("bob");
    backend.enrol("carol");
    backend.enrol("dave");
    let tester = vault(&backend, TESTER);
    let docs = rt
        .block_on(tester.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let other = rt
        .block_on(tester.create_volume(OsStr::new("other"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(tester.mkdir(docs, OsStr::new("inside"), 0o755))
        .unwrap();
    rt.block_on(tester.grant(docs, "bob", true, OsStr::new("docs")))
        .unwrap();
    rt.block_on(tester.grant(docs, "carol", false, OsStr::new("docs")))
        .unwrap();

    // Links need the capability.
    assert_eq!(
        errno(rt.block_on(tester.create_link(docs, "/docs", OsStr::new("docs"), None))),
        libc::EACCES
    );
    rt.block_on(accounts::set_caps(
        &backend.client,
        TESTER,
        Caps::LINKS,
        Caps::NONE,
    ))
    .unwrap();
    // And write access: carol only reads.
    rt.block_on(accounts::set_caps(
        &backend.client,
        "carol",
        Caps::LINKS,
        Caps::NONE,
    ))
    .unwrap();
    let carol = vault(&backend, "carol");
    assert_eq!(
        errno(rt.block_on(carol.create_link(docs, "/docs", OsStr::new("docs"), None))),
        libc::EROFS
    );

    let (link, secret) = rt
        .block_on(tester.create_link(docs, "/docs", OsStr::new("Our docs"), None))
        .unwrap();
    assert!(link.starts_with("link-"));
    let made = rt.block_on(tester.links()).unwrap();
    assert_eq!(made.len(), 1);
    assert_eq!(
        (made[0].0.user.as_str(), made[0].1.as_deref()),
        (link.as_str(), Some("/docs"))
    );

    // A visitor reads the folder, under the name it was shared as, and
    // nothing more.
    let visitor = visit(&backend, &link, &secret).unwrap();
    let roots = rt.block_on(visitor.root_entries()).unwrap();
    assert_eq!(roots, [(OsStr::new("Our docs").to_owned(), docs)]);
    let names: Vec<_> = rt
        .block_on(visitor.readdir(docs))
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert!(names.iter().any(|n| n == "inside"), "{names:?}");
    assert_ne!(
        rt.block_on(visitor.mkdir(docs, OsStr::new("mine"), 0o755))
            .map(drop),
        Ok(())
    );
    assert_eq!(
        errno(rt.block_on(visitor.create_volume(OsStr::new("v"), 0o755))),
        libc::EACCES
    );
    assert!(visit(&backend, &link, "wrong").is_err());

    // Only its maker shares with a link, and only its folder.
    let bob = vault(&backend, "bob");
    // Bob trusts the tester, so his vault would share from what they share.
    bob.known_keys().check(TESTER, &backend.tester_key).unwrap();
    let key = rt.block_on(bob.served_key(&link)).unwrap();
    bob.known_keys().check(&link, &key).unwrap();
    for (who, ino) in [(&bob, docs), (&tester, other)] {
        assert_eq!(
            errno(rt.block_on(who.grant(ino, &link, false, OsStr::new("x")))),
            libc::EPERM
        );
    }
    assert_eq!(
        errno(rt.block_on(tester.grant(docs, &link, true, OsStr::new("x")))),
        libc::EPERM
    );

    // Whoever can change the folder can copy the link again; a reader
    // can't. The secret outlives a revoke of someone else, which gives the
    // folder a new key.
    let secret_for = |who: &Vault| {
        rt.block_on(who.grantees_with_links(docs))
            .map(|(_, mut secrets)| secrets.remove(&link))
    };
    assert_eq!(secret_for(&bob).unwrap().as_deref(), Some(secret.as_str()));
    assert!(secret_for(&carol).is_err());
    rt.block_on(tester.grant(docs, "dave", false, OsStr::new("docs")))
        .unwrap();
    rt.block_on(tester.revoke(docs, "dave")).unwrap();
    assert_eq!(secret_for(&bob).unwrap().as_deref(), Some(secret.as_str()));

    // A reader can't revoke it; any writer can, and that ends the link.
    assert!(rt.block_on(carol.revoke(docs, &link)).is_err());
    rt.block_on(bob.revoke(docs, &link)).unwrap();
    assert!(
        rt.block_on(accounts::get(&backend.client, &link))
            .unwrap()
            .is_none()
    );
    assert!(rt.block_on(tester.links()).unwrap().is_empty());
    assert!(visit(&backend, &link, &secret).is_err());
    // An open session ends too.
    assert!(rt.block_on(visitor.root_entries()).is_err());

    // An expired link can't log in.
    let soon = now() + 2;
    let (link, secret) = rt
        .block_on(tester.create_link(docs, "/docs", OsStr::new("docs"), Some(soon)))
        .unwrap();
    visit(&backend, &link, &secret).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(visit(&backend, &link, &secret).is_err());
    // Deleting its folder ends it as well.
    let (link, _) = rt
        .block_on(tester.create_link(other, "/other", OsStr::new("other"), None))
        .unwrap();
    rt.block_on(tester.delete_volume(OsStr::new("other")))
        .unwrap();
    assert!(
        rt.block_on(accounts::get(&backend.client, &link))
            .unwrap()
            .is_none()
    );

    // Nobody else may take a link's name.
    assert_eq!(
        errno(rt.block_on(accounts::add(
            &backend.client,
            "link-x",
            Caps::NONE,
            Caps::NONE
        ))),
        libc::EINVAL
    );
}

#[test]
fn a_changed_key_replaces_the_pin_only_when_its_fingerprint_matches() {
    use raft5fs_crypto::identity::fingerprint_words;
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let old = backend.enrol("bob");
    let tester = vault(&backend, TESTER);
    let docs = rt
        .block_on(tester.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(tester.trust("bob", &fingerprint_words(&old)))
        .unwrap();
    assert!(!rt.block_on(tester.key_changed("bob")).unwrap());

    // Bob forgets his password and enrolls again, with a new key.
    let code = rt
        .block_on(accounts::issue_code(&backend.client, "bob"))
        .unwrap();
    let new = enrol_with(&backend, "bob", &code);
    assert!(rt.block_on(tester.key_changed("bob")).unwrap());
    assert_eq!(
        errno(rt.block_on(tester.grant(docs, "bob", true, OsStr::new("docs")))),
        libc::EPERM
    );
    // A trust can't replace a pin, and a wrong fingerprint leaves it.
    assert_eq!(
        errno(rt.block_on(tester.trust("bob", &fingerprint_words(&new)))),
        libc::EPERM
    );
    assert_eq!(
        errno(rt.block_on(tester.replace_key("bob", &fingerprint_words(&old)))),
        libc::EPERM
    );
    assert_eq!(tester.known_keys().pinned("bob"), Some(old));

    rt.block_on(tester.replace_key("bob", &fingerprint_words(&new)))
        .unwrap();
    assert_eq!(tester.known_keys().pinned("bob"), Some(new));
    assert!(!rt.block_on(tester.key_changed("bob")).unwrap());
    rt.block_on(tester.grant(docs, "bob", true, OsStr::new("docs")))
        .unwrap();
}
