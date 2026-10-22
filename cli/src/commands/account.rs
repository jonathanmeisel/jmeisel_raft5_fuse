//! `raft5fs enrol`, `passwd` and `whoami`.

use clap::Args;
use raft5fs_crypto::password::{KdfParams, check_new_password};
use raft5fs_proto::invite::{Invite, der_to_pem};
use raft5fs_proto::types::check_username;

use super::{ConnectArgs, Outcome, runtime, show_fingerprint};
use crate::cli::{
    Context, Profile, config_dir, password_from, prompt_password, tls_from_pem, write_new_private,
};
use crate::remote::{Credentials, Remote};

#[derive(Args)]
pub struct EnrolArgs {
    /// The invitation an administrator gave you (`raft5fs-invite:1:...`),
    /// or a bare enrolment code -- which then needs --user, --server and
    /// --ca. Saves a profile named --profile, or else after the account.
    pub invitation: String,
}

/// A new password: from `var`, or asked for twice on the terminal. Long
/// enough (`check_new_password`), either way.
fn new_password(var: &str, username: &str) -> Result<String, String> {
    if let Ok(password) = std::env::var(var) {
        check_new_password(&password)?;
        return Ok(password);
    }
    let read =
        |prompt: &str| prompt_password(prompt).map_err(|e| format!("cannot read a password: {e}"));
    let first = read(&format!("new password for {username}: "))?;
    check_new_password(&first)?;
    if read("again: ")? != first {
        return Err("the passwords didn't match".to_string());
    }
    Ok(first)
}

pub fn enrol(connect: &ConnectArgs, args: EnrolArgs) -> Outcome {
    let base = config_dir();
    let (profile, ca_pem, code) = if args.invitation.trim().starts_with("raft5fs-invite:") {
        let invite = Invite::decode(&args.invitation)?;
        if connect.user.as_ref().is_some_and(|u| *u != invite.user) {
            return Err(format!("this invitation is for {}", invite.user));
        }
        let profile = Profile {
            user: invite.user.clone(),
            servers: invite.servers.clone(),
            tls_server_name: invite.tls_server_name.clone(),
            ..Profile::default()
        };
        (
            profile,
            Some(der_to_pem(&invite.ca).into_bytes()),
            invite.code,
        )
    } else {
        // A bare code: the rest from the command line alone -- not from a
        // profile, which would be someone else's account.
        let user = connect
            .user
            .clone()
            .ok_or("enrolling with a bare code needs --user (or use the invitation)")?;
        if connect.servers.is_empty() {
            return Err("enrolling with a bare code needs --server".to_string());
        }
        let ca_pem = match &connect.ca {
            Some(path) => Some(
                std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
            ),
            None if connect.insecure_plaintext => None,
            None => return Err("--ca is required (or --insecure-plaintext)".to_string()),
        };
        let profile = Profile {
            user,
            servers: connect.servers.clone(),
            tls_server_name: connect.tls_server_name.clone(),
            known_keys: connect.known_keys.clone(),
            insecure_plaintext: connect.insecure_plaintext,
            ..Profile::default()
        };
        (profile, ca_pem, args.invitation.trim().to_string())
    };
    check_username(&profile.user).map_err(|e| e.message)?;
    let name = connect.profile.clone().unwrap_or(profile.user.clone());
    // Before the code is used up: nothing is overwritten after.
    let profile_path = Profile::path(&base, &name);
    let ca_path = base.join("profiles").join(format!("{name}.ca.pem"));
    if profile_path.exists() || ca_path.exists() {
        return Err(format!(
            "there is already a profile {name} ({}); choose another name with --profile",
            profile_path.display()
        ));
    }

    let password = new_password("RAFT5FS_PASSWORD", &profile.user)?;
    let mut credentials = Credentials::new(profile.user.clone(), password);
    credentials.allow_plaintext = profile.insecure_plaintext;
    let tls = ca_pem
        .clone()
        .map(|pem| tls_from_pem(pem, profile.tls_server_name.as_deref()));
    let public_key = runtime()
        .block_on(Remote::enrol(
            &profile.servers,
            tls,
            credentials,
            &code,
            KdfParams::DEFAULT,
        ))
        .map_err(|e| format!("cannot enrol: {e}"))?;

    let mut profile = profile;
    if let Some(pem) = &ca_pem {
        write_new_private(&ca_path, pem)
            .map_err(|e| format!("enrolled, but cannot save {}: {e}", ca_path.display()))?;
        profile.ca = Some(ca_path);
    }
    let saved = profile
        .save_new(&base, &name)
        .map_err(|e| format!("enrolled, but {e}"))?;
    println!(
        "enrolled {}; saved profile {name} ({})",
        profile.user,
        saved.display()
    );
    println!("your key's fingerprint -- give it to those you share with:");
    println!("{}", show_fingerprint(&public_key));
    println!("next: raft5fs mount <MOUNTPOINT>");
    Ok(0)
}

pub fn passwd(connect: &ConnectArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let password = password_from(
        "RAFT5FS_PASSWORD",
        &format!("current password for {}: ", ctx.user),
    )
    .map_err(|e| format!("cannot read a password: {e}"))?;
    let runtime = runtime();
    let remote = runtime
        .block_on(Remote::connect(
            &ctx.servers,
            ctx.credentials(password),
            ctx.tls.clone(),
        ))
        .map_err(|e| format!("cannot log in: {e}"))?;
    let new = new_password("RAFT5FS_NEW_PASSWORD", &ctx.user)?;
    runtime
        .block_on(remote.change_password(&new, KdfParams::DEFAULT))
        .map_err(|e| format!("cannot change the password: {e}"))?;
    println!("password changed");
    Ok(0)
}

pub fn whoami(connect: &ConnectArgs) -> Outcome {
    let ctx = Context::resolve(&connect.overrides(), true)?;
    let runtime = runtime();
    let vault = super::log_in(&runtime, &ctx)?;
    let identity = vault
        .remote()
        .identity()
        .ok_or("logged in, but with no key pair")?;
    // From the key pair this machine just opened: not the server's word.
    println!("{}, whose key's fingerprint is", ctx.user);
    println!("{}", show_fingerprint(&identity.public_key()));
    Ok(0)
}
