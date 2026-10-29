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
use raft5fs_proto::types::{AccountKind, Caps, FsError, NewNode};
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
            Caps::ADMIN,
            Caps::NONE
        ))),
        libc::ENOENT
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
fn admins_manage_users_and_nobody_else_can() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let tester = connect(&backend, TESTER);

    // Without `admin`, none of it.
    assert_eq!(
        errno(rt.block_on(tester.issue_invite("dave", Caps::NONE))),
        libc::EACCES
    );
    assert_eq!(errno(rt.block_on(tester.list_users())), libc::EACCES);
    assert_eq!(
        errno(rt.block_on(tester.set_capabilities(TESTER, Caps::ADMIN, Caps::NONE))),
        libc::EACCES
    );
    assert_eq!(
        errno(rt.block_on(tester.reissue_invite(TESTER))),
        libc::EACCES
    );
    assert_eq!(errno(rt.block_on(tester.delete_user("x"))), libc::EACCES);
    rt.block_on(accounts::set_caps(
        &backend.client,
        TESTER,
        Caps::ADMIN,
        Caps::NONE,
    ))
    .unwrap();

    // Invitations: new names only, with any capabilities, admin included.
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
        .block_on(tester.issue_invite("dave", Caps::VOLUMES | Caps::ADMIN))
        .unwrap();
    let invite =
        Invite::decode(&invitation.expect("the test servers know their addresses")).unwrap();
    assert_eq!(
        (invite.user.as_str(), invite.code.as_str()),
        ("dave", code.as_str())
    );
    let listed = rt.block_on(tester.list_users()).unwrap();
    let dave_row = listed.iter().find(|u| u.user == "dave").unwrap();
    assert!(!dave_row.enrolled);
    assert_eq!(dave_row.info.invited_by, TESTER);
    let dave_key = enrol_with(&backend, "dave", &code);
    let dave = connect(&backend, "dave");
    assert_eq!(
        rt.block_on(dave.account()).unwrap().caps,
        Caps::VOLUMES | Caps::ADMIN
    );

    // Capabilities, for anyone but one's own admin.
    let info = rt
        .block_on(tester.set_capabilities("dave", Caps::LINKS, Caps::ADMIN))
        .unwrap();
    assert_eq!(info.caps, Caps::VOLUMES | Caps::LINKS);
    assert_eq!(
        errno(rt.block_on(dave.issue_invite("fay", Caps::NONE))),
        libc::EACCES,
        "no longer an admin"
    );
    assert_eq!(
        errno(rt.block_on(tester.set_capabilities(TESTER, Caps::NONE, Caps::ADMIN))),
        libc::EPERM
    );
    rt.block_on(tester.set_capabilities(TESTER, Caps::LINKS, Caps::NONE))
        .unwrap();
    assert_eq!(
        errno(rt.block_on(tester.set_capabilities("nobody", Caps::LINKS, Caps::NONE))),
        libc::ENOENT
    );

    // Enrolling again: a new code, which gives dave a new key.
    let (code, _) = rt.block_on(tester.reissue_invite("dave")).unwrap();
    let new_key = enrol_with(&backend, "dave", &code);
    assert_ne!(new_key, dave_key);
    assert_eq!(
        errno(rt.block_on(tester.reissue_invite("nobody"))),
        libc::ENOENT
    );

    // Removing: anyone but oneself, invitations too.
    assert_eq!(errno(rt.block_on(tester.delete_user(TESTER))), libc::EPERM);
    rt.block_on(tester.delete_user("erin")).unwrap();
    rt.block_on(tester.delete_user("dave")).unwrap();
    assert!(
        rt.block_on(accounts::get(&backend.client, "dave"))
            .unwrap()
            .is_none()
    );
    assert_eq!(errno(rt.block_on(tester.delete_user("dave"))), libc::ENOENT);
    let left: Vec<String> = rt
        .block_on(tester.list_users())
        .unwrap()
        .into_iter()
        .map(|u| u.user)
        .collect();
    assert_eq!(left, [TESTER]);
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

#[test]
fn trusted_keys_follow_the_account_to_its_other_devices() {
    use raft5fs_crypto::identity::fingerprint_words;
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob = backend.enrol("bob");
    let carol = backend.enrol("carol");
    let erin = backend.enrol("erin");
    // Two devices of one account, each with its own pins.
    let a = vault(&backend, TESTER);
    let b = vault(&backend, TESTER);
    rt.block_on(a.sync_pins()).unwrap();
    rt.block_on(b.sync_pins()).unwrap();

    // What one device trusts, the other trusts after its next merge.
    rt.block_on(a.trust("bob", &fingerprint_words(&bob)))
        .unwrap();
    rt.block_on(b.sync_pins()).unwrap();
    assert_eq!(b.known_keys().pinned("bob"), Some(bob));

    // A device's first merge sends what only it trusted, and where it
    // disagrees, takes the servers' copy.
    let c = vault(&backend, TESTER);
    c.known_keys().check("bob", &[9; 32]).unwrap();
    c.known_keys().check("erin", &erin).unwrap();
    rt.block_on(c.sync_pins()).unwrap();
    assert_eq!(c.known_keys().pinned("bob"), Some(bob));
    rt.block_on(a.sync_pins()).unwrap();
    assert_eq!(a.known_keys().pinned("erin"), Some(erin));

    // Changes on two devices at once both survive: b forgets bob (not yet
    // merged) while a trusts carol.
    b.known_keys().forget("bob").unwrap();
    rt.block_on(a.trust("carol", &fingerprint_words(&carol)))
        .unwrap();
    rt.block_on(b.sync_pins()).unwrap();
    assert_eq!(b.known_keys().pinned("bob"), None);
    assert_eq!(b.known_keys().pinned("carol"), Some(carol));
    rt.block_on(a.sync_pins()).unwrap();
    assert_eq!(
        a.known_keys().pinned("bob"),
        None,
        "a forgotten key stays forgotten"
    );

    // The servers keep only what they were given, sealed, and refuse a
    // write over a newer version.
    let (version, sealed) = rt.block_on(a.remote().get_pins()).unwrap();
    assert!(version > 0);
    assert_eq!(
        errno(rt.block_on(a.remote().put_pins(version - 1, sealed))),
        libc::EAGAIN
    );

    // Enrolling again drops them: they were sealed to the old key pair.
    let code = rt
        .block_on(accounts::issue_code(&backend.client, TESTER))
        .unwrap();
    enrol_with(&backend, TESTER, &code);
    assert_eq!(
        rt.block_on(accounts::pins(&backend.client, TESTER))
            .unwrap(),
        (0, Vec::new())
    );
}
