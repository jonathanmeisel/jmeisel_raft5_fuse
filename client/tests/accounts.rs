//! Tests capabilities and invitations: what the servers let an account
//! start, and how users invite users. They run against a real store and
//! servers.

use std::ffi::OsStr;
use std::sync::Arc;

use raft5fs_client::remote::Remote;
use raft5fs_client::store::{MemoryStore, Store};
use raft5fs_client::vault::{KnownKeys, Vault};
use raft5fs_core::accounts;
use raft5fs_crypto::identity::{fingerprint_words, label_signer, seal_label, seal_signed_label};
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

#[test]
fn folders_nobody_can_reach_are_listed_and_deleted() {
    let mut backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    rt_set_admin(&backend, TESTER);
    backend.enrol("carol");
    backend.enrol("eve");
    let rt = &backend.runtime;
    let carol = vault(&backend, "carol");
    carol
        .known_keys()
        .check(TESTER, &backend.tester_key)
        .unwrap();
    // carol's own volume, and one she shares a folder of.
    let solo = rt
        .block_on(carol.create_volume(OsStr::new("solo"), 0o755))
        .unwrap()
        .ino;
    let file = rt
        .block_on(carol.create(solo, OsStr::new("f"), 0o644))
        .unwrap()
        .ino;
    rt.block_on(carol.write(file, 0, &[7; 3000])).unwrap();
    let both = rt
        .block_on(carol.create_volume(OsStr::new("both"), 0o755))
        .unwrap()
        .ino;
    let kept = rt
        .block_on(carol.mkdir(both, OsStr::new("kept"), 0o755))
        .unwrap()
        .ino;
    let other = rt
        .block_on(carol.mkdir(both, OsStr::new("other"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(carol.grant(kept, TESTER, false, OsStr::new("kept")))
        .unwrap();

    let admin = connect(&backend, TESTER);
    assert!(rt.block_on(admin.list_unreachable()).unwrap().is_empty());
    // Removing carol would leave all of `solo`, and `other` in `both`:
    // not `kept`, which the tester can still reach, or `both`, the way to it.
    let inos = |found: Vec<raft5fs_proto::types::Unreachable>| {
        let mut inos: Vec<u64> = found.iter().map(|u| u.ino).collect();
        inos.sort();
        inos
    };
    let impact = rt.block_on(admin.removal_impact("carol")).unwrap();
    let whole = impact.iter().find(|u| u.ino == solo).unwrap();
    assert!(whole.volume);
    assert_eq!((whole.files, whole.folders, whole.bytes), (1, 1, 3000));
    assert_eq!(inos(impact), [solo.min(other), solo.max(other)]);

    rt.block_on(admin.delete_user("carol")).unwrap();
    assert_eq!(
        inos(rt.block_on(admin.list_unreachable()).unwrap()),
        [solo.min(other), solo.max(other)]
    );

    // Only admins, and only what nobody can reach.
    assert_eq!(
        errno(rt.block_on(connect(&backend, "eve").list_unreachable())),
        libc::EACCES
    );
    assert_eq!(
        errno(rt.block_on(admin.delete_unreachable(kept))),
        libc::EINVAL
    );

    // Deleting takes it out of the store, chunks and all.
    assert!(
        !backend
            .keys_with_prefix(&raft5fs_core::chunk_prefix(file))
            .is_empty()
    );
    rt.block_on(admin.delete_unreachable(solo)).unwrap();
    assert!(
        backend
            .keys_with_prefix(&raft5fs_core::chunk_prefix(file))
            .is_empty()
    );
    assert_eq!(
        inos(rt.block_on(admin.list_unreachable()).unwrap()),
        [other]
    );
    let tester = vault(&backend, TESTER);
    let roots: Vec<_> = rt
        .block_on(tester.root_entries())
        .unwrap()
        .into_iter()
        .map(|(_, ino)| ino)
        .collect();
    assert_eq!(roots, [kept]);

    // New servers start the same way: nothing about this needs memory.
    drop(backend.replace_servers(TEST_CHUNK_SIZE));
    let admin = connect(&backend, TESTER);
    assert_eq!(
        inos(backend.runtime.block_on(admin.list_unreachable()).unwrap()),
        [other]
    );
}

fn rt_set_admin(backend: &Backend, user: &str) {
    backend
        .runtime
        .block_on(accounts::set_caps(
            &backend.client,
            user,
            Caps::ADMIN | Caps::LINKS,
            Caps::NONE,
        ))
        .unwrap();
}

#[test]
fn reservations_go_when_a_create_fails_and_when_old() {
    let mut backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let reservations = |b: &Backend| b.keys_with_prefix(&[0x0A]).len();
    {
        let rt = &backend.runtime;
        let tester = vault(&backend, TESTER);
        let v = rt
            .block_on(tester.create_volume(OsStr::new("v"), 0o755))
            .unwrap()
            .ino;
        rt.block_on(tester.mkdir(v, OsStr::new("a"), 0o755))
            .unwrap();
        assert_eq!(reservations(&backend), 0);
        // A create that fails gives its reservation back.
        assert_eq!(
            errno(rt.block_on(tester.mkdir(v, OsStr::new("a"), 0o755))),
            libc::EEXIST
        );
        assert_eq!(reservations(&backend), 0);
    }
    // One left by a client that went away, from before reservations had a
    // time: new servers remove it when they start.
    backend.write_key(&[0x0A, 0, 0, 0, 0, 0, 0, 0x30, 0x39], Some(b"tester"));
    assert_eq!(reservations(&backend), 1);
    drop(backend.replace_servers(TEST_CHUNK_SIZE));
    assert_eq!(reservations(&backend), 0);
}

#[test]
fn a_deleted_links_pin_goes_from_every_device() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    rt_set_admin(&backend, TESTER);
    let rt = &backend.runtime;
    let a = vault(&backend, TESTER);
    let b = vault(&backend, TESTER);
    rt.block_on(a.sync_pins()).unwrap();
    rt.block_on(b.sync_pins()).unwrap();
    let docs = rt
        .block_on(a.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let (link, _) = rt
        .block_on(a.create_link(docs, "/docs", OsStr::new("docs"), None))
        .unwrap();
    rt.block_on(b.sync_pins()).unwrap();
    assert!(b.known_keys().pinned(&link).is_some());

    rt.block_on(a.revoke(docs, &link)).unwrap();
    rt.block_on(a.sync_pins()).unwrap();
    assert_eq!(a.known_keys().pinned(&link), None);
    rt.block_on(b.sync_pins()).unwrap();
    assert_eq!(b.known_keys().pinned(&link), None);
}

/// A share of a folder inside another share to the same user shows once,
/// as the outer one, and they can write wherever any share above is
/// read-write.
#[test]
fn a_share_inside_a_share_shows_once_and_the_widest_access_wins() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    backend.enrol("bob");
    backend.enrol("carol");
    let rt = &backend.runtime;
    let tester = vault(&backend, TESTER);
    let v = rt
        .block_on(tester.create_volume(OsStr::new("v"), 0o755))
        .unwrap()
        .ino;
    let sub = rt
        .block_on(tester.mkdir(v, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    let names = |who: &Vault| -> Vec<String> {
        let mut names: Vec<String> = rt
            .block_on(who.root_entries())
            .unwrap()
            .into_iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };

    // bob reads all of v, and writes in sub.
    rt.block_on(tester.grant(v, "bob", false, OsStr::new("v")))
        .unwrap();
    rt.block_on(tester.grant(sub, "bob", true, OsStr::new("sub")))
        .unwrap();
    let bob = vault(&backend, "bob");
    bob.known_keys().check(TESTER, &backend.tester_key).unwrap();
    assert_eq!(names(&bob), ["v"]);
    assert_eq!(
        errno(rt.block_on(bob.create(v, OsStr::new("no"), 0o644))),
        libc::EROFS
    );
    let deeper = rt
        .block_on(bob.mkdir(sub, OsStr::new("deeper"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(bob.create(deeper, OsStr::new("yes"), 0o644))
        .unwrap();

    // carol writes all of v: a read-only share of sub takes nothing away.
    rt.block_on(tester.grant(v, "carol", true, OsStr::new("v")))
        .unwrap();
    rt.block_on(tester.grant(sub, "carol", false, OsStr::new("sub")))
        .unwrap();
    let carol = vault(&backend, "carol");
    carol
        .known_keys()
        .check(TESTER, &backend.tester_key)
        .unwrap();
    assert_eq!(names(&carol), ["v"]);
    rt.block_on(carol.create(sub, OsStr::new("mine"), 0o644))
        .unwrap();

    // Without the outer share, the inner one is a root of its own again,
    // read-only.
    rt.block_on(tester.revoke(v, "carol")).unwrap();
    assert_eq!(names(&carol), ["sub"]);
    assert_eq!(
        errno(rt.block_on(carol.create(sub, OsStr::new("not now"), 0o644))),
        libc::EROFS
    );
}

/// Everyone who has a link has its secret, so nothing lets one holder change
/// the account, store things under it, or learn who has an account.
#[test]
fn a_public_link_can_only_read() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    accounts_allow_links(&backend, TESTER);
    let bob_key = backend.enrol("bob");
    let carol_key = backend.enrol("carol");
    let dave_key = backend.enrol("dave");
    let tester = vault(&backend, TESTER);
    let docs = rt
        .block_on(tester.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    tester.known_keys().check("carol", &carol_key).unwrap();
    tester.known_keys().check("dave", &dave_key).unwrap();
    rt.block_on(tester.grant(docs, "bob", true, OsStr::new("docs")))
        .unwrap();
    rt.block_on(tester.grant(docs, "carol", false, OsStr::new("docs")))
        .unwrap();
    rt.block_on(tester.grant(docs, "dave", false, OsStr::new("docs")))
        .unwrap();
    let (link, secret) = rt
        .block_on(tester.create_link(docs, "/docs", OsStr::new("docs"), None))
        .unwrap();

    let visitor = visit(&backend, &link, &secret).unwrap();
    let remote = visitor.remote();

    // It changes nothing about the account, and stores nothing.
    assert_eq!(
        errno(rt.block_on(remote.change_password("a new password here", KdfParams::TESTING))),
        libc::EACCES
    );
    assert_eq!(errno(rt.block_on(remote.allocate_inode())), libc::EACCES);
    assert_eq!(
        errno(rt.block_on(remote.put_pins(0, vec![1; 64]))),
        libc::EACCES
    );
    assert!(
        visit(&backend, &link, &secret).is_ok(),
        "the secret still works"
    );

    // It gets the key of who sealed its grant, and can't tell whether anyone
    // else has an account.
    assert_eq!(
        rt.block_on(remote.public_key(TESTER)).unwrap(),
        backend.tester_key
    );
    let real = rt.block_on(remote.public_key("bob")).unwrap_err();
    let made_up = rt.block_on(remote.public_key("nobody")).unwrap_err();
    assert_eq!(real.errno, libc::EACCES);
    assert_eq!(real, made_up);

    // A person still can tell, as they must to share.
    let person = tester.remote();
    assert_eq!(rt.block_on(person.public_key("bob")).unwrap(), bob_key);
    assert_eq!(
        errno(rt.block_on(person.public_key("nobody"))),
        libc::ENOENT
    );

    // When a writer revokes someone, they seal the link's grant again, so it
    // opens with their key, and no longer needs the tester's.
    let bob = vault(&backend, "bob");
    bob.known_keys().check(TESTER, &backend.tester_key).unwrap();
    bob.known_keys().check("carol", &carol_key).unwrap();
    bob.known_keys().check("dave", &dave_key).unwrap();
    bob.known_keys()
        .check(&link, &rt.block_on(person.public_key(&link)).unwrap())
        .unwrap();
    rt.block_on(bob.revoke(docs, "carol")).unwrap();
    let again = visit(&backend, &link, &secret).unwrap();
    rt.block_on(again.readdir(docs))
        .expect("the link opens under the new sender");
    assert_eq!(rt.block_on(remote.public_key("bob")).unwrap(), bob_key);
    assert_eq!(errno(rt.block_on(remote.public_key(TESTER))), libc::EACCES);

    // A snapshot keeps the grant as it was, so its sender stays open to the
    // link for as long as the snapshot lasts.
    backend.snapshot("before");
    rt.block_on(tester.revoke(docs, "dave")).unwrap();
    assert_eq!(
        rt.block_on(remote.public_key(TESTER)).unwrap(),
        backend.tester_key,
        "the tester sealed the grant now"
    );
    assert_eq!(
        rt.block_on(remote.public_key("bob")).unwrap(),
        bob_key,
        "bob sealed the grant in the snapshot"
    );
    backend.drop_snapshot("before");
    assert_eq!(errno(rt.block_on(remote.public_key("bob"))), libc::EACCES);
}

fn accounts_allow_links(backend: &Backend, user: &str) {
    backend
        .runtime
        .block_on(accounts::set_caps(
            &backend.client,
            user,
            Caps::LINKS,
            Caps::NONE,
        ))
        .unwrap();
}

/// A session lasts only as long as the password and key it was made with. A
/// new login works, but one with the old password doesn't, so a stolen device
/// is locked out by changing the password.
#[test]
fn a_new_password_or_a_new_enrollment_ends_earlier_sessions() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    backend.enrol("bob");
    const NEW_PASSWORD: &str = "a brand new password for this";
    let connect_with = |user: &str, password: &str| {
        rt.block_on(Remote::connect(
            &backend.addresses(),
            credentials_with(user, password),
            Some(fs_tls()),
        ))
    };
    let enrol_again = |user: &str| {
        let code = rt
            .block_on(accounts::issue_code(&backend.client, user))
            .unwrap();
        rt.block_on(Remote::enrol(
            &backend.addresses(),
            Some(fs_tls()),
            credentials_with(user, NEW_PASSWORD),
            &code,
            KdfParams::TESTING,
        ))
        .unwrap();
    };

    // A new password: this device carries on, and the other is locked out.
    let here = connect(&backend, "bob");
    let stolen = connect(&backend, "bob");
    rt.block_on(here.list_grants()).unwrap();
    rt.block_on(stolen.list_grants()).unwrap();
    rt.block_on(here.change_password(NEW_PASSWORD, KdfParams::TESTING))
        .unwrap();
    rt.block_on(here.list_grants()).unwrap();
    assert_eq!(errno(rt.block_on(stolen.list_grants())), libc::EACCES);
    assert!(connect_with("bob", NEW_PASSWORD).is_ok());

    // A new enrollment ends the sessions of the key pair before it.
    backend.enrol("carol");
    let old = connect(&backend, "carol");
    rt.block_on(old.list_grants()).unwrap();
    enrol_again("carol");
    assert_eq!(errno(rt.block_on(old.list_grants())), libc::EACCES);

    // So does removing the account, even if someone takes the name again.
    backend.enrol("dave");
    let old = connect(&backend, "dave");
    rt.block_on(old.list_grants()).unwrap();
    rt.block_on(accounts::remove(&backend.client, "dave"))
        .unwrap();
    enrol_again("dave");
    assert_eq!(errno(rt.block_on(old.list_grants())), libc::EACCES);
}

/// Anyone who can reach a server can try passwords, so each server slows that
/// down, for a name and for an address.
#[test]
fn failed_logins_are_throttled_without_saying_who_exists() {
    use raft5fs_proto::errno::EBUSY;

    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    backend.enrol("bob");
    // One server, because each keeps its own counts.
    let one = &backend.addresses()[..1];
    let try_login = |user: &str, password: &str| {
        rt.block_on(Remote::connect(
            one,
            credentials_with(user, password),
            Some(fs_tls()),
        ))
    };
    let refused = |user: &str, password: &str| {
        try_login(user, password)
            .err()
            .expect("the login should fail")
    };

    // One old password, over and over, as a stale mount sends it, is one guess.
    for _ in 0..10 {
        assert!(refused("bob", "an old password here").contains("login refused"));
    }

    // Different ones are refused, and then not even looked at. The right
    // password gets the same answer until the wait is over.
    let here = rt
        .block_on(Remote::connect(one, credentials("bob"), Some(fs_tls())))
        .unwrap();
    for i in 0..5 {
        assert!(refused("bob", &format!("guess number {i}")).contains("login refused"));
    }
    let wait = refused("bob", "guess number 5");
    assert!(wait.contains("too many failed logins"), "{wait}");
    assert!(
        refused("bob", &raft5fs_testkit::password("bob")).contains("too many failed logins"),
        "the right password waits too"
    );
    assert!(refused(TESTER, "guess number 5").contains("login refused"));

    // Changing a password takes the old one, so it waits too. A session in use
    // goes on working.
    rt.block_on(here.list_grants()).unwrap();
    assert_eq!(
        errno(rt.block_on(here.change_password("a brand new password", KdfParams::TESTING))),
        EBUSY
    );

    std::thread::sleep(std::time::Duration::from_millis(1100));
    let remote = rt
        .block_on(Remote::connect(one, credentials("bob"), Some(fs_tls())))
        .expect("the right password works once the wait is over");
    drop(remote);

    // A success cleared the count, so a typo isn't refused.
    assert!(refused("bob", "one more typo").contains("login refused"));
    drop(here);

    // A name that doesn't exist fails the same way.
    for i in 0..5 {
        assert!(refused("nobody", &format!("guess number {i}")).contains("login refused"));
    }
    assert!(refused("nobody", "guess number 5").contains("too many failed logins"));

    // Guessing at many names from one address adds up too, which also shows
    // that the servers can see the address.
    let blocked = (0..20)
        .find(|i| refused(&format!("name{i}"), "a guess").contains("too many failed logins"));
    assert!(blocked.is_some(), "an address was never blocked");
}

/// A check that shows the answer checks nothing: someone could copy it.
#[test]
fn a_wrong_fingerprint_does_not_show_the_right_one() {
    use raft5fs_crypto::identity::{fingerprint_matches, fingerprint_words};

    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob_key = backend.enrol("bob");
    let carol_key = backend.enrol("carol");
    let tester = vault(&backend, TESTER);
    let wrong = fingerprint_words(&carol_key);
    assert!(!fingerprint_matches(&bob_key, &wrong).unwrap());
    let refused = rt.block_on(tester.trust("bob", &wrong)).unwrap_err();
    assert_eq!(refused.errno, libc::EPERM);
    let right = fingerprint_words(&bob_key);
    let first_word = right.split(' ').next().unwrap();
    assert!(!refused.message.contains(&right), "{}", refused.message);
    assert!(!refused.message.contains(first_word), "{}", refused.message);
}

/// One device's pins, kept in `store` as they are across its restarts.
fn device(backend: &Backend, user: &str, store: &Arc<MemoryStore>) -> Vault {
    let store: Arc<dyn Store> = store.clone();
    vault(backend, user).with_known_keys(KnownKeys::open(store, "pins").unwrap())
}

#[test]
fn a_device_refuses_a_key_record_older_than_it_saw() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob = backend.enrol("bob");
    let store = Arc::new(MemoryStore::new());
    let a = device(&backend, TESTER, &store);
    rt.block_on(a.sync_pins()).unwrap();
    rt.block_on(a.trust("bob", &fingerprint_words(&bob)))
        .unwrap();
    let docs = rt
        .block_on(a.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let sub = rt
        .block_on(a.mkdir(docs, OsStr::new("sub"), 0o755))
        .unwrap()
        .ino;
    let key = [&[0x08], &sub.to_be_bytes()[..]].concat();
    let old = backend.read_key(&key).unwrap();

    // Revoking gives the folder a new key, which this device then sees.
    rt.block_on(a.grant(sub, "bob", false, OsStr::new("sub")))
        .unwrap();
    rt.block_on(a.revoke(sub, "bob")).unwrap();
    rt.block_on(a.readdir(sub)).unwrap();
    assert!(rt.block_on(a.node(sub)).unwrap().record.version >= 2);
    drop(a);

    // The servers hand back the old record to a restarted device.
    backend.write_key(&key, Some(&old));
    let restarted = device(&backend, TESTER, &store);
    let e = rt.block_on(restarted.readdir(sub)).unwrap_err();
    assert_eq!(e.errno, libc::EIO);
    assert!(e.message.contains("restored from a backup"), "{e:?}");
    assert!(e.message.contains("raft5fs reset-versions"), "{e:?}");

    // A new device has nothing to compare with.
    rt.block_on(vault(&backend, TESTER).readdir(sub)).unwrap();

    // After a real restore, a person resets the device.
    rt.block_on(restarted.reset_versions()).unwrap();
    rt.block_on(restarted.readdir(sub)).unwrap();
    assert_eq!(
        rt.block_on(restarted.node(sub)).unwrap().record.version,
        1,
        "it took the restored record"
    );
}

#[test]
fn a_device_refuses_pins_older_than_it_saw() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob = backend.enrol("bob");
    let carol = backend.enrol("carol");
    let store = Arc::new(MemoryStore::new());
    let key = [b"\x06p/", TESTER.as_bytes()].concat();
    let a = device(&backend, TESTER, &store);
    rt.block_on(a.sync_pins()).unwrap();
    rt.block_on(a.trust("bob", &fingerprint_words(&bob)))
        .unwrap();
    let old = backend.read_key(&key).unwrap();
    rt.block_on(a.trust("carol", &fingerprint_words(&carol)))
        .unwrap();
    let newest = backend.read_key(&key).unwrap();

    // Refused at once, and after a restart. This device keeps its pins.
    backend.write_key(&key, Some(&old));
    for device in [&a, &device(&backend, TESTER, &store)] {
        let e = rt.block_on(device.sync_pins()).unwrap_err();
        assert_eq!(e.errno, libc::EIO);
        assert!(e.message.contains("restored from a backup"), "{e:?}");
        assert_eq!(device.known_keys().pinned("carol"), Some(carol));
    }
    // Having no copy at all is older too.
    backend.write_key(&key, None);
    assert_eq!(
        rt.block_on(a.sync_pins()).unwrap_err().errno,
        libc::EIO,
        "the copy was deleted"
    );

    // A new device takes what it is given: it has nothing to compare with.
    backend.write_key(&key, Some(&old));
    let new = vault(&backend, TESTER);
    rt.block_on(new.sync_pins()).unwrap();
    assert_eq!(new.known_keys().pinned("bob"), Some(bob));
    assert_eq!(new.known_keys().pinned("carol"), None);

    // After a reset, this device's pins win over the restored copy, and the
    // counter goes on from there.
    rt.block_on(a.reset_versions()).unwrap();
    rt.block_on(a.sync_pins()).unwrap();
    assert_eq!(a.known_keys().pinned("carol"), Some(carol));
    rt.block_on(new.sync_pins()).unwrap();
    assert_eq!(new.known_keys().pinned("carol"), Some(carol));
    assert_ne!(backend.read_key(&key).unwrap(), newest);
}

/// A key trusted while the servers can't be told stays trusted after a
/// restart: the servers' copy doesn't simply replace it.
#[test]
fn a_change_made_offline_survives_a_restart() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob = backend.enrol("bob");
    let store = Arc::new(MemoryStore::new());
    let a = device(&backend, TESTER, &store);
    rt.block_on(a.sync_pins()).unwrap();
    rt.block_on(a.trust("bob", &fingerprint_words(&bob)))
        .unwrap();
    // Only here, without a merge: the new key isn't on the servers.
    a.known_keys().forget("bob").unwrap();
    a.known_keys().check("bob", &[9; 32]).unwrap();
    drop(a);

    let restarted = device(&backend, TESTER, &store);
    rt.block_on(restarted.sync_pins()).unwrap();
    assert_eq!(restarted.known_keys().pinned("bob"), Some([9; 32]));
}

/// The name `ino` shows as in the root of `vault`.
fn shown_as(backend: &Backend, vault: &Vault, ino: u64) -> String {
    let entries = backend.runtime.block_on(vault.root_entries()).unwrap();
    let (name, _) = entries.iter().find(|(_, i)| *i == ino).unwrap();
    name.to_string_lossy().into_owned()
}

fn label_of(backend: &Backend, vault: &Vault, ino: u64) -> Vec<u8> {
    let grants = backend.runtime.block_on(vault.remote().list_grants());
    let grants = grants.unwrap();
    let grant = grants.iter().find(|g| g.ino == ino).unwrap();
    grant.sealed_label.clone()
}

/// Each account signs what it sees once. After that, the servers can't pass
/// a share off as something else without it saying so.
#[test]
fn grant_labels_are_signed_once_and_then_checked() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    let bob = backend.enrol("bob");
    backend.enrol("eve");
    let me = vault(&backend, TESTER);
    rt.block_on(me.sync_pins()).unwrap();
    let own = connect(&backend, TESTER).identity().unwrap();
    let mine = own.public_key();
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    assert_eq!(label_signer(&label_of(&backend, &me, docs)), Some(TESTER));

    // A label from before signing shows as it is, and gets signed.
    let old = seal_label(&mine, docs, b"older");
    rt.block_on(me.remote().set_grant_label(docs, old)).unwrap();
    assert_eq!(shown_as(&backend, &me, docs), "older");
    rt.block_on(me.sign_labels()).unwrap();
    assert_eq!(shown_as(&backend, &me, docs), "older");
    assert_eq!(label_signer(&label_of(&backend, &me, docs)), Some(TESTER));

    // After that, a label nobody vouches for says so. Another device learns
    // that from the sealed pins, and doesn't sign it either.
    let forged = seal_label(&mine, docs, b"forged");
    rt.block_on(me.remote().set_grant_label(docs, forged))
        .unwrap();
    assert_eq!(shown_as(&backend, &me, docs), "forged (unverified)");
    let other = vault(&backend, TESTER);
    rt.block_on(other.sync_pins()).unwrap();
    rt.block_on(other.sign_labels()).unwrap();
    assert_eq!(shown_as(&backend, &other, docs), "forged (unverified)");
    assert_eq!(label_signer(&label_of(&backend, &me, docs)), None);

    // So does one signed by someone this account hasn't checked, or by
    // someone claiming to be this account.
    let eves = connect(&backend, "eve").identity().unwrap();
    let forged = seal_signed_label(&eves, "eve", &mine, docs, b"from eve");
    rt.block_on(me.remote().set_grant_label(docs, forged))
        .unwrap();
    assert_eq!(shown_as(&backend, &me, docs), "from eve (unverified)");
    let forged = seal_signed_label(&eves, TESTER, &mine, docs, b"from me");
    rt.block_on(me.remote().set_grant_label(docs, forged))
        .unwrap();
    assert!(shown_as(&backend, &me, docs).starts_with("unreadable-"));

    // Its sender's label: plain while the whole share says it needs checking,
    // and once checked, it becomes this account's own and stays so. A forgery
    // of it says so.
    let bobs = vault(&backend, "bob");
    rt.block_on(bobs.trust(TESTER, &fingerprint_words(&mine)))
        .unwrap();
    let photos = rt
        .block_on(bobs.create_volume(OsStr::new("photos"), 0o755))
        .unwrap()
        .ino;
    rt.block_on(bobs.grant(photos, TESTER, false, OsStr::new("holiday")))
        .unwrap();
    assert_eq!(shown_as(&backend, &me, photos), "holiday");
    let forged = seal_signed_label(&eves, "eve", &mine, photos, b"bills");
    rt.block_on(me.remote().set_grant_label(photos, forged))
        .unwrap();
    assert_eq!(
        shown_as(&backend, &me, photos),
        "bills",
        "needs checking anyway"
    );
    let label = seal_signed_label(
        &connect(&backend, "bob").identity().unwrap(),
        "bob",
        &mine,
        photos,
        b"holiday",
    );
    rt.block_on(me.remote().set_grant_label(photos, label))
        .unwrap();
    rt.block_on(me.trust("bob", &fingerprint_words(&bob)))
        .unwrap();
    assert_eq!(shown_as(&backend, &me, photos), "holiday");
    assert_eq!(label_signer(&label_of(&backend, &me, photos)), Some("bob"));
    rt.block_on(me.sign_labels()).unwrap();
    assert_eq!(label_signer(&label_of(&backend, &me, photos)), Some(TESTER));
    let forged = seal_signed_label(&eves, "eve", &mine, photos, b"bills");
    rt.block_on(me.remote().set_grant_label(photos, forged))
        .unwrap();
    assert_eq!(shown_as(&backend, &me, photos), "bills (unverified)");
}

/// A label is the holder's own: nobody changes another's, and a link only
/// reads.
#[test]
fn only_the_grantee_sets_a_grants_label() {
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    rt_set_admin(&backend, TESTER);
    let bob = backend.enrol("bob");
    backend.enrol("eve");
    let me = vault(&backend, TESTER);
    rt.block_on(me.trust("bob", &fingerprint_words(&bob)))
        .unwrap();
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    assert_eq!(
        errno(
            rt.block_on(
                vault(&backend, "eve")
                    .remote()
                    .set_grant_label(docs, vec![1])
            )
        ),
        libc::ENOENT
    );
    assert_eq!(
        errno(rt.block_on(me.remote().set_grant_label(docs, vec![1; 8192]))),
        libc::EINVAL
    );
    let (link, secret) = rt
        .block_on(me.create_link(docs, "/docs", OsStr::new("docs"), None))
        .unwrap();
    let visitor = visit(&backend, &link, &secret).unwrap();
    assert_eq!(
        errno(rt.block_on(visitor.remote().set_grant_label(docs, vec![1]))),
        libc::EACCES
    );
    // A link shows its signed label, and signs nothing.
    rt.block_on(visitor.sign_labels()).unwrap();
    assert_eq!(shown_as(&backend, &visitor, docs), "docs");
}

/// A writer seals what names they like. One that a path can't say stays out
/// of listings, and nobody can make one through this client.
#[test]
fn names_a_path_cant_say_stay_out_of_listings() {
    use raft5fs_client::vault::Node;
    let backend = Backend::start(TEST_CHUNK_SIZE, false, true);
    let rt = &backend.runtime;
    backend.enrol("bob");
    let me = vault(&backend, TESTER);
    rt.block_on(me.sync_pins()).unwrap();
    let docs = rt
        .block_on(me.create_volume(OsStr::new("docs"), 0o755))
        .unwrap()
        .ino;
    let real = rt
        .block_on(me.create(docs, OsStr::new("real"), 0o644))
        .unwrap()
        .ino;
    let dir: Arc<Node> = rt.block_on(me.node(docs)).unwrap();
    let forge = |name: &str| {
        let name = OsStr::new(name);
        let tag = dir.tag(name);
        let key = [&[0x03], &docs.to_be_bytes()[..], tag.as_encoded_bytes()].concat();
        let value = [
            &real.to_be_bytes()[..],
            &dir.seal(docs, real, &tag, name)[..],
        ]
        .concat();
        backend.write_key(&key, Some(&value));
    };
    forge("fine");
    for bad in ["a/b", "..", ".", "../up", "", "with\0nul"] {
        forge(bad);
    }
    let mut names: Vec<String> = rt
        .block_on(me.readdir(docs))
        .unwrap()
        .into_iter()
        .map(|item| item.name.to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, [".", "..", "fine", "real"]);

    // A label is a name too.
    let own = connect(&backend, TESTER).identity().unwrap();
    let label = seal_signed_label(&own, TESTER, &own.public_key(), docs, b"a/b");
    rt.block_on(me.remote().set_grant_label(docs, label))
        .unwrap();
    assert_eq!(shown_as(&backend, &me, docs), format!("unreadable-{docs}"));

    for bad in ["a/b", "..", ".", ""] {
        let bad = OsStr::new(bad);
        for result in [
            rt.block_on(me.mkdir(docs, bad, 0o755)).map(drop),
            rt.block_on(me.create(docs, bad, 0o644)).map(drop),
            rt.block_on(me.create_volume(bad, 0o755)).map(drop),
            rt.block_on(me.grant(docs, "bob", false, bad)).map(drop),
            rt.block_on(me.rename(docs, OsStr::new("real"), docs, bad, false))
                .map(drop),
        ] {
            assert_eq!(errno(result), libc::EINVAL, "{bad:?}");
        }
    }
}
