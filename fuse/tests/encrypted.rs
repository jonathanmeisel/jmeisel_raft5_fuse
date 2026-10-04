//! Encrypted filesystems, end to end: enrolment, logins whose password
//! never reaches a server, and password changes.

mod support;

use std::fs;

use raft5fs_core::{accounts, resolve_encryption, stored_encryption};
use raft5fs_crypto::password::KdfParams;
use raft5fs_fuse::remote::{Credentials, Remote};

/// Not really a test: the entry point that lets the harness run a
/// filesystem server as a separate process (see `support::TestServer`).
/// Returns at once in a normal run.
#[test]
fn server_process_mode() {
    support::serve_if_requested();
}

fn connect(h: &support::Harness, user: &str, password: &str) -> Result<Remote, String> {
    let credentials = Credentials {
        username: user.to_string(),
        password: password.to_string(),
    };
    h.runtime.block_on(Remote::connect(
        &h.addresses(),
        credentials,
        Some(support::fs_tls()),
    ))
}

/// Gives `name` a user table entry and a store account, but no keys.
fn add_unenrolled(h: &support::Harness, name: &str) {
    h.cluster
        .add_user(&h.runtime, &h.client, name, 50_001, 50_001, &[]);
}

fn enrol_with(
    h: &support::Harness,
    name: &str,
    code: &str,
    password: &str,
) -> Result<[u8; 32], raft5fs_core::FsError> {
    h.runtime.block_on(Remote::enrol(
        &h.addresses(),
        Some(support::fs_tls()),
        name,
        code,
        password,
        KdfParams::TESTING,
    ))
}

#[test]
fn an_enrolled_user_mounts_and_uses_the_filesystem() {
    let h = support::setup_encrypted();
    let f = h.path().join("hello");
    fs::write(&f, b"world").unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"world");
    let remote = connect(&h, support::TESTER, &support::password(support::TESTER)).unwrap();
    assert!(remote.encrypted());
    assert!(remote.identity().is_some(), "the login opened the key pair");
}

#[test]
fn a_wrong_password_and_an_unknown_user_are_refused_alike() {
    let h = support::setup_encrypted();
    let wrong = connect(&h, support::TESTER, "not it").err().unwrap();
    let unknown = connect(&h, "nobody", "anything").err().unwrap();
    assert!(wrong.contains("login refused"), "{wrong}");
    assert_eq!(wrong, unknown);
}

#[test]
fn an_enrolment_code_works_once_and_only_for_its_user() {
    let h = support::setup_encrypted();
    add_unenrolled(&h, "alice");
    add_unenrolled(&h, "bob");
    let code = h
        .runtime
        .block_on(accounts::issue_code(&h.client, "alice"))
        .unwrap();

    let wrong = enrol_with(&h, "alice", "00000000000000000000000000000000", "pw");
    assert_eq!(wrong.unwrap_err().errno, libc::EACCES);
    let someone_elses = enrol_with(&h, "bob", &code, "pw");
    assert_eq!(someone_elses.unwrap_err().errno, libc::EACCES);
    assert!(connect(&h, "alice", "pw").is_err(), "not enrolled yet");

    enrol_with(&h, "alice", &code, "pw").unwrap();
    connect(&h, "alice", "pw").unwrap();
    let again = enrol_with(&h, "alice", &code, "other");
    assert_eq!(
        again.unwrap_err().errno,
        libc::EACCES,
        "the code was used up"
    );
    connect(&h, "alice", "pw").unwrap();
}

#[test]
fn a_password_change_keeps_the_key_pair() {
    let h = support::setup_encrypted();
    h.add_user("alice", 50_001, 50_001, &[]);
    let old = support::password("alice");
    let remote = connect(&h, "alice", &old).unwrap();
    let key = remote.identity().unwrap().public_key();

    h.runtime
        .block_on(remote.change_password("new password", KdfParams::TESTING))
        .unwrap();
    assert!(connect(&h, "alice", &old).is_err());
    let after = connect(&h, "alice", "new password").unwrap();
    assert_eq!(after.identity().unwrap().public_key(), key);
}

#[test]
fn no_password_reaches_the_store() {
    let h = support::setup_encrypted();
    add_unenrolled(&h, "alice");
    let password = "correct horse battery staple";
    let code = h
        .runtime
        .block_on(accounts::issue_code(&h.client, "alice"))
        .unwrap();
    enrol_with(&h, "alice", &code, password).unwrap();
    connect(&h, "alice", password).unwrap();

    for key in h.keys_with_prefix(&[]) {
        let value = h.read_key(&key).unwrap_or_default();
        for bytes in [&key, &value] {
            assert!(
                !bytes
                    .windows(password.len())
                    .any(|w| w == password.as_bytes()),
                "the password is stored under {key:?}"
            );
        }
    }
}

#[test]
fn a_mount_logs_in_again_without_its_password() {
    let mut h = support::setup_encrypted();
    fs::write(h.path().join("before"), b"x").unwrap();
    // Every session the mount holds is now refused, so its next request
    // logs in again -- from the `auth` it kept, the password long gone.
    h.restart_servers_with_key("another key, also at least 32 bytes");
    fs::write(h.path().join("after"), b"y").unwrap();
    assert_eq!(fs::read(h.path().join("before")).unwrap(), b"x");
}

#[test]
fn enrolment_needs_an_encrypted_filesystem() {
    let h = support::setup();
    let refused = enrol_with(&h, support::TESTER, "code", "pw").unwrap_err();
    assert_eq!(refused.errno, libc::EOPNOTSUPP);
}

#[test]
fn encryption_is_fixed_when_a_filesystem_is_created() {
    let plain = support::setup();
    let run = |f| plain.runtime.block_on(f);
    assert_eq!(run(stored_encryption(&plain.client)).unwrap(), Some(false));
    let refused = plain
        .runtime
        .block_on(resolve_encryption(&plain.client, true));
    assert!(refused.unwrap_err().contains("created unencrypted"));

    let encrypted = support::setup_encrypted();
    assert_eq!(
        encrypted
            .runtime
            .block_on(stored_encryption(&encrypted.client))
            .unwrap(),
        Some(true)
    );
    let kept = encrypted
        .runtime
        .block_on(resolve_encryption(&encrypted.client, false));
    assert_eq!(kept, Ok(true));
}
