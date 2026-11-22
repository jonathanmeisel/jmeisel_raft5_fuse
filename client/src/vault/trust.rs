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

use std::collections::{BTreeMap, HashMap};

use raft5fs_crypto::identity::{Introduced, PUBLIC_KEY_LEN, seal_introduction};
use raft5fs_crypto::invitation::new_invite_secret;
use raft5fs_crypto::pins::{PendingInvite, PinEntry, PinSource};
use raft5fs_proto::errno;
use raft5fs_proto::invite::{Introduction as InviteIntroduction, Invite};
use raft5fs_proto::types::{Caps, FsError};

use super::Vault;
use super::merge::{Enrollment, Found, first_hand};
use crate::remote::Introduction;
use raft5fs_proto::clock;
use raft5fs_proto::since;

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

/// How a pinned key was checked, as the people list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinDetails {
    pub source: PinSource,
    pub introducer: bool,
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
        if self.remote.protocol() < since::INVITE_TRUST {
            return Some(line);
        }
        let Ok(mut invite) = Invite::decode(&line) else {
            return Some(line);
        };
        let secret = new_invite_secret();
        let open = PendingInvite {
            user: user.to_string(),
            secret: Some(secret),
            at: clock::now_secs(),
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
            at: clock::now_secs(),
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
            at: clock::now_secs(),
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
            at: clock::now_secs(),
            source: PinSource::Checked,
            introducer,
        };
        if let Err(e) = self.merge_pins(false, &[entry], &[]).await {
            eprintln!("trusted keys not merged with the servers' copy yet: {e}");
        }
    }

    /// What the user of each open invitation in `invites` enrolled with.
    /// A user the servers can't be asked about now is left out, so their
    /// invitation waits for the next merge.
    pub(super) async fn enrollments_of(
        &self,
        invites: &[PendingInvite],
    ) -> HashMap<String, Enrollment> {
        let mut found = HashMap::new();
        if self.remote.protocol() < since::INVITE_TRUST {
            return found;
        }
        for invite in invites.iter().filter(|i| i.secret.is_some()) {
            let enrollment = match self.remote.get_enrollment(&invite.user).await {
                Ok((key, proof)) => Enrollment::Enrolled { key, proof },
                Err(e) if e.errno == errno::ENOENT => Enrollment::NotYet,
                Err(_) => continue,
            };
            found.insert(invite.user.clone(), enrollment);
        }
        found
    }

    /// The introductions left for this account, or none on servers older
    /// than protocol 11 or if the servers don't answer: they wait there.
    pub(super) async fn introduction_inbox(&self) -> Vec<Introduction> {
        if self.remote.protocol() < since::INVITE_TRUST {
            return Vec::new();
        }
        self.remote.get_introductions().await.unwrap_or_default()
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
        if self.remote.protocol() < since::INVITE_TRUST {
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
