//! `raft5fs enrol`, `passwd`, and `whoami`.

use clap::Args;
use raft5fs_crypto::password::{KdfParams, check_new_password};
use raft5fs_proto::invite::{Invite, der_to_pem};
use raft5fs_proto::types::{Caps, check_username};

use super::{ConnectArgs, Outcome, runtime, show_fingerprint};
use raft5fs_client::cli::{
    Context, Profile, config_dir, install_profile, password_from, profile_ca_path, prompt_password,
    tls_from_pem,
};
use raft5fs_client::remote::{Credentials, Remote};

#[derive(Args)]
pub struct EnrolArgs {
    /// The invitation from your administrator (`raft5fs-invite:1:...`), or
    /// a bare enrolment code, which then needs --user, --server, and --ca.
    /// Saves a profile named by --profile, or else by the account.
    pub invitation: String,
}

/// A new password, from `var` or asked for twice on the terminal. Either
/// way, it must be long enough (`check_new_password`).
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
        // A bare code: get the rest only from the command line, not from a
        // profile, which would be another account's.
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
    // Check this before the code is used up, so nothing is overwritten
    // after.
    let profile_path = Profile::path(&base, &name);
    if profile_path.exists() || profile_ca_path(&base, &name).exists() {
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

    let user = profile.user.clone();
    let saved = install_profile(&base, &name, profile, ca_pem.as_deref())
        .map_err(|e| format!("enrolled, but {e}"))?;
    println!(
        "enrolled {user}; saved profile {name} ({})",
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
    // This comes from the key pair that this machine just opened, not from
    // the server.
    println!("{}, whose key's fingerprint is", ctx.user);
    println!("{}", show_fingerprint(&identity.public_key()));
    // Older servers have no capabilities to show.
    if let Ok(account) = runtime.block_on(vault.remote().account()) {
        println!("can: {}", caps_text(account.caps));
    }
    if let Ok(storage) = runtime.block_on(vault.remote().storage()) {
        let used = raft5fs_proto::types::size_text(storage.used);
        match storage.quota {
            Some(quota) => println!(
                "storage: {used} of {} used",
                raft5fs_proto::types::size_text(quota)
            ),
            None => println!("storage: {used} used"),
        }
    }
    Ok(0)
}

pub(super) fn caps_text(caps: Caps) -> String {
    if caps == Caps::NONE {
        "only use what is shared with you".to_string()
    } else {
        caps.names().join(", ")
    }
}
