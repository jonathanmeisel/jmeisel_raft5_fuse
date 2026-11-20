//! Trust in keys with no safety codes: through invitations, and through
//! introductions from people the account trusts to check keys.
//!
//! - An invitation from this account carries a secret that the servers
//!   never see (raft5fs-crypto's `invitation`). The new user's client
//!   proves its key with it, and trusts the inviter's key from the
//!   invitation. This account checks the proof (`check_invites`).
//! - Someone that this account checked first-hand (by safety code or
//!   through an invitation) can be marked an introducer. Keys they checked
//!   first-hand then reach this account sealed from them
//!   (`take_introductions`). A key learned this way is never passed on, so
//!   an introduction goes one step at most.
//! - This account introduces each person it newly checks first-hand to
//!   everyone else it checked first-hand, and them to the new person
//!   (`send_introductions`). Each recipient decides whether to trust it.
//!
//! The servers can withhold an invitation's proof or an introduction. That
//! only leaves the safety codes to compare, as before. They can't make
//! either one that checks.

use std::collections::BTreeMap;

use raft5fs_crypto::identity::{Introduced, PUBLIC_KEY_LEN, seal_introduction};
use raft5fs_crypto::invitation::{check_invite_proof, new_invite_secret};
use raft5fs_crypto::pins::{PendingInvite, PinEntry, PinSource};
use raft5fs_proto::errno;
use raft5fs_proto::invite::{Introduction as InviteIntroduction, Invite};
use raft5fs_proto::types::{Caps, FsError, LINK_PREFIX};

use super::Vault;
use crate::remote::Introduction;

/// How long an invitation stays open: as long as its enrollment code.
const INVITE_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;
/// The most warnings kept to show.
const MAX_WARNINGS: usize = 20;

/// What the last merge said beyond the keys, for the people list.
#[derive(Default)]
pub(super) struct TrustState {
    /// How each pinned key was checked, and whether its holder is an
    /// introducer here.
    details: BTreeMap<String, (PinSource, bool)>,
    /// Checks that didn't pass, newest last.
    warnings: Vec<String>,
}

/// What a merge found, to act on once its list is stored.
#[derive(Default)]
pub(super) struct Found {
    /// Introductions left for this account that are dealt with: taken in,
    /// already known, or not worth keeping.
    done: Vec<Introduction>,
    warnings: Vec<String>,
}

/// How a pinned key was checked, as the people list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinDetails {
    pub source: PinSource,
    pub introducer: bool,
}

fn now_secs() -> u64 {
    raft5fs_proto::clock::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The open and closed invitations in `stored`, with `changes` applied:
/// per user, the later wins.
pub(super) fn merge_invites(
    stored: &[PendingInvite],
    changes: &[PendingInvite],
) -> Vec<PendingInvite> {
    let mut merged: BTreeMap<String, PendingInvite> =
        stored.iter().map(|i| (i.user.clone(), i.clone())).collect();
    for change in changes {
        if merged.get(&change.user).is_none_or(|i| i.at <= change.at) {
            merged.insert(change.user.clone(), change.clone());
        }
    }
    merged.into_values().collect()
}

/// Whether `entry` is a key this account checked itself, of a person (not a
/// public link). Only those are introduced to others.
fn first_hand(entry: &PinEntry) -> Option<[u8; PUBLIC_KEY_LEN]> {
    if entry.user.starts_with(LINK_PREFIX) || !entry.source.first_hand() {
        return None;
    }
    entry.key
}

impl Vault {
    /// Makes an invitation for `user` with `caps` (see `Remote::issue_invite`).
    /// On servers with protocol 11, it carries an introduction, so that this
    /// account and the new user trust each other's keys with no safety
    /// codes. Returns the code, and the invitation if the servers made one.
    pub async fn invite(
        &self,
        user: &str,
        caps: Caps,
    ) -> Result<(String, Option<String>), FsError> {
        let (code, invitation) = self.remote.issue_invite(user, caps).await?;
        Ok((code, self.introduce_in(user, invitation).await))
    }

    /// `invite`, for a user who has to enroll again (see
    /// `Remote::reissue_invite`). Once they do, their new key replaces the
    /// one pinned here.
    pub async fn reissue(&self, user: &str) -> Result<(String, Option<String>), FsError> {
        let (code, invitation) = self.remote.reissue_invite(user).await?;
        Ok((code, self.introduce_in(user, invitation).await))
    }

    /// Adds an introduction to `invitation` for `user`, once its secret is
    /// stored in this account's sealed list. Without that, the invitation
    /// stays as the servers made it, and the safety codes are compared as
    /// before.
    async fn introduce_in(&self, user: &str, invitation: Option<String>) -> Option<String> {
        let line = invitation?;
        if self.remote.protocol() < 11 {
            return Some(line);
        }
        let Ok(mut invite) = Invite::decode(&line) else {
            return Some(line);
        };
        let secret = new_invite_secret();
        let open = PendingInvite {
            user: user.to_string(),
            secret: Some(secret),
            at: now_secs(),
        };
        if let Err(e) = self.merge_pins(false, &[], &[open]).await {
            eprintln!("the invitation can't check {user}'s key, so compare safety codes: {e}");
            return Some(line);
        }
        invite.introduction = Some(InviteIntroduction {
            inviter: self.remote.username().to_string(),
            inviter_key: self.identity.public_key(),
            secret,
        });
        Some(invite.encode())
    }

    /// For a new account that enrolled with an invitation that held
    /// `intro`: trusts the inviter's key, and their introductions. Fails,
    /// and trusts nothing, if the servers give another key for the inviter.
    pub async fn accept_invitation(&self, intro: &InviteIntroduction) -> Result<(), FsError> {
        let served = self.served_key(&intro.inviter).await?;
        if served != intro.inviter_key {
            return Err(FsError::new(
                errno::EPERM,
                format!(
                    "the servers gave a different key for {} than your invitation holds; \
                     compare safety codes with them",
                    intro.inviter
                ),
            ));
        }
        self.known.check(&intro.inviter, &served)?;
        self.forget_all();
        let entry = PinEntry {
            user: intro.inviter.clone(),
            key: Some(served),
            at: now_secs(),
            source: PinSource::Invited,
            introducer: true,
        };
        self.merge_pins(false, &[entry], &[]).await
    }

    /// Whether this account trusts `user`'s introductions of others. Only a
    /// key checked first-hand can be an introducer.
    pub async fn set_introducer(&self, user: &str, on: bool) -> Result<(), FsError> {
        let Some(key) = self.known.pinned(user) else {
            return Err(FsError::new(
                errno::ENOENT,
                format!("check {user}'s safety code first"),
            ));
        };
        let source = self.pin_details(user).map(|d| d.source).unwrap_or_default();
        if on && !source.first_hand() {
            return Err(FsError::new(
                errno::EPERM,
                format!(
                    "someone else checked {user}'s key; check their safety code yourself first"
                ),
            ));
        }
        let entry = PinEntry {
            user: user.to_string(),
            key: Some(key),
            at: now_secs(),
            source,
            introducer: on,
        };
        self.merge_pins(false, &[entry], &[]).await
    }

    /// How the key pinned for `user` was checked, as of the last merge.
    pub fn pin_details(&self, user: &str) -> Option<PinDetails> {
        let trust = self.trust.lock().unwrap();
        let (source, introducer) = trust.details.get(user)?.clone();
        Some(PinDetails { source, introducer })
    }

    /// Checks of invitations and introductions that didn't pass, newest
    /// last.
    pub fn trust_warnings(&self) -> Vec<String> {
        self.trust.lock().unwrap().warnings.clone()
    }

    /// After a safety code check of `user`: records that this account
    /// checked `key` itself, and shares it, as `share_pins` does.
    pub(super) async fn share_checked(&self, user: &str, key: [u8; PUBLIC_KEY_LEN]) {
        let introducer = self.pin_details(user).is_some_and(|d| d.introducer);
        let entry = PinEntry {
            user: user.to_string(),
            key: Some(key),
            at: now_secs(),
            source: PinSource::Checked,
            introducer,
        };
        if let Err(e) = self.merge_pins(false, &[entry], &[]).await {
            eprintln!("trusted keys not merged with the servers' copy yet: {e}");
        }
    }

    /// The introductions left for this account, or none on servers older
    /// than protocol 11 or if the servers don't answer: they wait there.
    pub(super) async fn introduction_inbox(&self) -> Vec<Introduction> {
        if self.remote.protocol() < 11 {
            return Vec::new();
        }
        self.remote.get_introductions().await.unwrap_or_default()
    }

    /// Checks each open invitation in `invites` against what its user
    /// enrolled with:
    ///
    /// - A proof that checks: pins the key in `merged`, replacing an older
    ///   one (an invitation to enroll again), and closes the invitation.
    /// - Not enrolled yet, or no proof that checks: waits, until the
    ///   invitation is too old. Then it closes it, with a warning if the
    ///   user did enroll: their key then needs a safety code check.
    pub(super) async fn check_invites(
        &self,
        me: &str,
        now: u64,
        merged: &mut BTreeMap<String, PinEntry>,
        invites: &mut [PendingInvite],
        found: &mut Found,
    ) {
        if self.remote.protocol() < 11 {
            return;
        }
        for invite in invites.iter_mut() {
            let Some(secret) = invite.secret else {
                continue;
            };
            let expired = now.saturating_sub(invite.at) > INVITE_LIFETIME_SECS;
            let enrolled = match self.remote.get_enrollment(&invite.user).await {
                Ok(enrolled) => Some(enrolled),
                Err(e) if e.errno == errno::ENOENT => None,
                // Try again at the next merge.
                Err(_) => continue,
            };
            let proved = enrolled.as_ref().and_then(|(key, proof)| {
                let key: [u8; PUBLIC_KEY_LEN] = key.as_slice().try_into().ok()?;
                check_invite_proof(&secret, &invite.user, me, &key, proof).then_some(key)
            });
            match proved {
                Some(key) => {
                    let introducer = merged.get(&invite.user).is_some_and(|e| e.introducer);
                    merged.insert(
                        invite.user.clone(),
                        PinEntry {
                            user: invite.user.clone(),
                            key: Some(key),
                            at: now,
                            source: PinSource::Invited,
                            introducer,
                        },
                    );
                }
                None if expired => {
                    if enrolled.is_some() {
                        found.warnings.push(format!(
                            "{} enrolled, but not with the invitation you made; \
                             compare safety codes with them",
                            invite.user
                        ));
                    }
                }
                None => continue,
            }
            invite.secret = None;
            invite.at = now;
        }
    }

    /// Takes in the introductions in `inbox` that come from an introducer
    /// of this account, sealed with the key pinned for them:
    ///
    /// - A new person: pins their key, as introduced.
    /// - A key already pinned: nothing to do.
    /// - Another key for someone pinned: pins it only if the introducer
    ///   checked that it replaces the pinned one. Otherwise, a warning.
    ///
    /// Introductions from anyone who isn't an introducer here stay on the
    /// servers, in case they become one. Those that can't be opened go.
    pub(super) fn take_introductions(
        &self,
        me: &str,
        now: u64,
        inbox: &[Introduction],
        merged: &mut BTreeMap<String, PinEntry>,
        found: &mut Found,
    ) {
        found.done.clear();
        for item in inbox {
            if item.subject == me || item.subject.starts_with(LINK_PREFIX) {
                found.done.push(item.clone());
                continue;
            }
            let Some(introducer_key) = merged
                .get(&item.introducer)
                .filter(|e| e.introducer)
                .and_then(first_hand)
            else {
                continue;
            };
            let opened = match self
                .identity
                .open_introduction(&introducer_key, &item.sealed)
            {
                Ok(opened) if opened.subject == item.subject => opened,
                _ => {
                    found.done.push(item.clone());
                    continue;
                }
            };
            found.done.push(item.clone());
            let pinned = merged.get(&item.subject).and_then(|e| e.key);
            let take = match pinned {
                None => true,
                Some(key) if key == opened.key => false,
                Some(key) if opened.replaces == Some(key) => true,
                Some(_) => {
                    found.warnings.push(format!(
                        "{} says {} has a key that isn't the one you trust for them; \
                         compare safety codes with {}",
                        item.introducer, item.subject, item.subject
                    ));
                    false
                }
            };
            if take {
                let introducer = merged.get(&item.subject).is_some_and(|e| e.introducer);
                merged.insert(
                    item.subject.clone(),
                    PinEntry {
                        user: item.subject.clone(),
                        key: Some(opened.key),
                        at: now,
                        source: PinSource::Introduced {
                            by: item.introducer.clone(),
                        },
                        introducer,
                    },
                );
            }
        }
    }

    /// Once a merged list is stored: keeps what it says for the people
    /// list, removes the introductions dealt with, and introduces the
    /// people this account newly checked first-hand. Failures here only
    /// mean the next merge does it, or the safety codes are compared.
    pub(super) async fn after_merge(
        &self,
        me: &str,
        before: &BTreeMap<String, PinEntry>,
        merged: &BTreeMap<String, PinEntry>,
        _invites: Vec<PendingInvite>,
        found: Found,
    ) {
        {
            let mut trust = self.trust.lock().unwrap();
            trust.details = merged
                .values()
                .filter(|e| e.key.is_some())
                .map(|e| (e.user.clone(), (e.source.clone(), e.introducer)))
                .collect();
            for warning in found.warnings {
                if !trust.warnings.contains(&warning) {
                    trust.warnings.push(warning);
                }
            }
            let excess = trust.warnings.len().saturating_sub(MAX_WARNINGS);
            trust.warnings.drain(..excess);
        }
        if self.remote.protocol() < 11 {
            return;
        }
        if !found.done.is_empty()
            && let Err(e) = self.remote.delete_introductions(found.done).await
        {
            eprintln!("introductions taken in, but not removed from the servers: {e}");
        }
        let introductions = self.introductions_for(me, before, merged);
        for batch in introductions.chunks(500) {
            if let Err(e) = self.remote.put_introductions(batch.to_vec()).await {
                eprintln!("introductions not sent: {e}");
                return;
            }
        }
    }

    /// The introductions for each person in `merged` that this account
    /// checked first-hand, and whose key differs from `before`: them to
    /// everyone else it checked first-hand, and everyone to them.
    fn introductions_for(
        &self,
        me: &str,
        before: &BTreeMap<String, PinEntry>,
        merged: &BTreeMap<String, PinEntry>,
    ) -> Vec<Introduction> {
        let checked: Vec<(&String, [u8; PUBLIC_KEY_LEN])> = merged
            .values()
            .filter(|e| e.user != me)
            .filter_map(|e| Some((&e.user, first_hand(e)?)))
            .collect();
        let mut out: BTreeMap<(String, String), Introduction> = BTreeMap::new();
        let mut add =
            |recipient: &str, recipient_key: [u8; PUBLIC_KEY_LEN], subject: &str, key, replaces| {
                let sealed = seal_introduction(
                    &self.identity,
                    me,
                    &recipient_key,
                    &Introduced {
                        subject: subject.to_string(),
                        key,
                        replaces,
                    },
                );
                out.insert(
                    (recipient.to_string(), subject.to_string()),
                    Introduction {
                        recipient: recipient.to_string(),
                        subject: subject.to_string(),
                        introducer: String::new(),
                        sealed,
                    },
                );
            };
        for &(new, new_key) in &checked {
            let old = before.get(new).and_then(|e| e.key);
            if old == Some(new_key) {
                continue;
            }
            for &(other, other_key) in &checked {
                if other == new {
                    continue;
                }
                add(other, other_key, new, new_key, old);
                add(new, new_key, other, other_key, None);
            }
        }
        out.into_values().collect()
    }
}
