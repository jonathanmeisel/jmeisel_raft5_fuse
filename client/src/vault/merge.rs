//! The rules for merging this device's trusted keys with the account's
//! sealed copy on the servers (see `pins`). Everything here is pure: the
//! caller gathers what the servers say first, so the rules are tested
//! without servers.
//!
//! - Per user, the later change wins: a key, a forgotten key, how it was
//!   checked, and whether they are an introducer. Changes made on this
//!   device since its last merge are the keys that differ from that merge.
//! - An open invitation whose user enrolled with a proof that checks pins
//!   their key (see `invitation`). One with no such proof waits, and closes
//!   when too old.
//! - An introduction from an introducer of this account pins a new
//!   person's key, or replaces a key the introducer checked it replaces.
//! - A pin of a public link that no longer exists goes.

use std::collections::{BTreeMap, HashMap, HashSet};

use raft5fs_crypto::identity::{Identity, PUBLIC_KEY_LEN};
use raft5fs_crypto::invitation::check_invite_proof;
use raft5fs_crypto::pins::{PendingInvite, PinEntry, PinList, PinSource};
use raft5fs_proto::types::LINK_PREFIX;

use crate::remote::Introduction;

/// How long an invitation stays open: as long as its enrollment code.
pub(super) const INVITE_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;

type Keys = HashMap<String, [u8; PUBLIC_KEY_LEN]>;

/// What a user enrolled with, as the servers say. A user the servers
/// couldn't be asked about is missing, and their invitation waits.
pub(super) enum Enrollment {
    Enrolled { key: Vec<u8>, proof: Vec<u8> },
    NotYet,
}

/// Everything a merge needs, gathered from this device and the servers.
pub(super) struct Inputs<'a> {
    pub me: &'a str,
    pub now: u64,
    /// The servers' copy, and whether there was one at all.
    pub stored: &'a PinList,
    pub stored_empty: bool,
    /// The highest counter this device has seen.
    pub floor: u64,
    /// This device's pins now, and as of its last merge (`None` for none).
    pub local: &'a Keys,
    pub base: Option<&'a Keys>,
    /// Changes made here that say more than a key (see `Vault::merge_pins`).
    pub explicit: &'a [PinEntry],
    /// The invitations, with this device's changes merged in (`merge_invites`).
    pub invites: Vec<PendingInvite>,
    /// Whether this device has signed its old labels.
    pub labels_signed: bool,
    pub enrollments: &'a HashMap<String, Enrollment>,
    pub inbox: &'a [Introduction],
    /// Opens introductions.
    pub identity: &'a Identity,
    /// Pinned public links that no longer exist.
    pub dead: &'a HashSet<String>,
}

/// What a merge found, to act on once its list is stored.
#[derive(Default)]
pub(super) struct Found {
    /// Introductions left for this account that are dealt with: taken in,
    /// already known, or not worth keeping.
    pub done: Vec<Introduction>,
    pub warnings: Vec<String>,
}

/// The merged list, and what to do with it.
pub(super) struct Merged {
    /// The servers' entries before the merge, and after it.
    pub before: BTreeMap<String, PinEntry>,
    pub entries: BTreeMap<String, PinEntry>,
    pub invites: Vec<PendingInvite>,
    pub labels_signed: bool,
    /// The new list's counter, if it must be stored; `None` if the servers'
    /// copy needs no change.
    pub store_as: Option<u64>,
    pub found: Found,
}

/// The users whose pins differ between `base` (the last merge) and `local`
/// (this device now), each as a change made `now`. With no last merge,
/// none: a first merge takes the servers' copy first.
pub(super) fn local_changes(base: Option<&Keys>, local: &Keys, now: u64) -> Vec<PinEntry> {
    let Some(base) = base else {
        return Vec::new();
    };
    base.keys()
        .chain(local.keys())
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|user| base.get(*user) != local.get(*user))
        .map(|user| PinEntry {
            user: user.clone(),
            key: local.get(user).copied(),
            at: now,
            source: PinSource::Checked,
            introducer: false,
        })
        .collect()
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

/// Merges `changes` (from `local_changes`) and everything in `i`.
pub(super) fn merge(i: Inputs<'_>, changes: &[PinEntry]) -> Merged {
    let before: BTreeMap<String, PinEntry> = i
        .stored
        .entries
        .iter()
        .map(|e| (e.user.clone(), e.clone()))
        .collect();
    let mut merged = before.clone();
    for change in changes {
        match merged.get(&change.user) {
            // Already the same key: keep how it was checked.
            Some(e) if e.key == change.key => {}
            Some(e) if e.at > change.at => {}
            old => {
                let mut change = change.clone();
                // The same person: their marks stay with a new key.
                change.introducer = old.is_some_and(|e| e.introducer);
                merged.insert(change.user.clone(), change);
            }
        }
    }
    for change in i.explicit {
        if merged.get(&change.user).is_none_or(|e| e.at <= change.at) {
            merged.insert(change.user.clone(), change.clone());
        }
    }
    if i.base.is_none() {
        for (user, key) in i.local {
            merged.entry(user.clone()).or_insert_with(|| PinEntry {
                user: user.clone(),
                key: Some(*key),
                at: i.now,
                source: PinSource::Checked,
                introducer: false,
            });
        }
    }
    let mut invites = i.invites;
    let mut found = Found::default();
    apply_invites(
        i.me,
        i.now,
        &mut merged,
        &mut invites,
        i.enrollments,
        &mut found,
    );
    take_introductions(i.me, i.now, i.identity, i.inbox, &mut merged, &mut found);
    // This account pins each public link it makes, to share with it. Once
    // a link is gone, so is its pin, everywhere. Link names are random and
    // never reused, so no marker is needed: a device that still has the pin
    // sends it back, and its next merge drops it.
    for user in i.dead {
        merged.remove(user);
    }
    // A list from before counters has nothing to protect it until it has
    // one.
    let uncounted = i.stored.counter == 0 && !i.stored_empty;
    let labels_signed = i.stored.labels_signed || i.labels_signed;
    let changed = merged != before
        || invites != i.stored.invites
        || uncounted
        || labels_signed != i.stored.labels_signed;
    Merged {
        before,
        entries: merged,
        invites,
        labels_signed,
        store_as: changed.then(|| i.stored.counter.max(i.floor) + 1),
        found,
    }
}

/// Whether `entry` is a key this account checked itself, of a person (not a
/// public link). Only those are introduced to others, and only those can be
/// introducers.
pub(super) fn first_hand(entry: &PinEntry) -> Option<[u8; PUBLIC_KEY_LEN]> {
    if entry.user.starts_with(LINK_PREFIX) || !entry.source.first_hand() {
        return None;
    }
    entry.key
}

/// Checks each open invitation in `invites` against what its user enrolled
/// with (`enrollments`):
///
/// - A proof that checks: pins the key in `merged`, replacing an older one
///   (an invitation to enroll again), and closes the invitation.
/// - Not enrolled yet, or no proof that checks: waits, until the invitation
///   is too old. Then it closes it, with a warning if the user did enroll:
///   their key then needs a safety code check.
/// - A user the servers couldn't be asked about: waits.
fn apply_invites(
    me: &str,
    now: u64,
    merged: &mut BTreeMap<String, PinEntry>,
    invites: &mut [PendingInvite],
    enrollments: &HashMap<String, Enrollment>,
    found: &mut Found,
) {
    for invite in invites.iter_mut() {
        let Some(secret) = invite.secret else {
            continue;
        };
        let Some(enrollment) = enrollments.get(&invite.user) else {
            continue;
        };
        let expired = now.saturating_sub(invite.at) > INVITE_LIFETIME_SECS;
        let proved = match enrollment {
            Enrollment::Enrolled { key, proof } => key
                .as_slice()
                .try_into()
                .ok()
                .filter(|key| check_invite_proof(&secret, &invite.user, me, key, proof)),
            Enrollment::NotYet => None,
        };
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
                if matches!(enrollment, Enrollment::Enrolled { .. }) {
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

/// Takes in the introductions in `inbox` that come from an introducer of
/// this account, sealed with the key pinned for them:
///
/// - A new person: pins their key, as introduced.
/// - A key already pinned: nothing to do.
/// - Another key for someone pinned: pins it only if the introducer
///   checked that it replaces the pinned one. Otherwise, a warning.
///
/// Introductions from anyone who isn't an introducer here stay on the
/// servers, in case they become one. Those that can't be opened go.
fn take_introductions(
    me: &str,
    now: u64,
    identity: &Identity,
    inbox: &[Introduction],
    merged: &mut BTreeMap<String, PinEntry>,
    found: &mut Found,
) {
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
        let opened = match identity.open_introduction(&introducer_key, &item.sealed) {
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

#[cfg(test)]
mod tests {
    use raft5fs_crypto::identity::{Introduced, seal_introduction};
    use raft5fs_crypto::invitation::invite_proof;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn pin(user: &str, key: u8, at: u64, source: PinSource, introducer: bool) -> PinEntry {
        PinEntry {
            user: user.into(),
            key: Some([key; PUBLIC_KEY_LEN]),
            at,
            source,
            introducer,
        }
    }

    /// A merge's inputs with nothing in them but `stored`, `local` and
    /// `base`, which the test then fills in.
    struct Case {
        me: Identity,
        stored: PinList,
        local: Keys,
        base: Option<Keys>,
        explicit: Vec<PinEntry>,
        invites: Vec<PendingInvite>,
        enrollments: HashMap<String, Enrollment>,
        inbox: Vec<Introduction>,
        dead: HashSet<String>,
    }

    impl Case {
        fn new(stored: Vec<PinEntry>) -> Self {
            let local: Keys = stored
                .iter()
                .filter_map(|e| Some((e.user.clone(), e.key?)))
                .collect();
            Case {
                me: Identity::generate(),
                stored: PinList {
                    counter: 4,
                    entries: stored,
                    ..PinList::default()
                },
                base: Some(local.clone()),
                local,
                explicit: Vec::new(),
                invites: Vec::new(),
                enrollments: HashMap::new(),
                inbox: Vec::new(),
                dead: HashSet::new(),
            }
        }

        fn run(&self) -> Merged {
            let changes = local_changes(self.base.as_ref(), &self.local, NOW);
            merge(
                Inputs {
                    me: "me",
                    now: NOW,
                    stored: &self.stored,
                    stored_empty: false,
                    floor: 0,
                    local: &self.local,
                    base: self.base.as_ref(),
                    explicit: &self.explicit,
                    invites: self.invites.clone(),
                    labels_signed: false,
                    enrollments: &self.enrollments,
                    inbox: &self.inbox,
                    identity: &self.me,
                    dead: &self.dead,
                },
                &changes,
            )
        }
    }

    #[test]
    fn nothing_changed_stores_nothing() {
        let case = Case::new(vec![pin("bob", 2, 10, PinSource::Checked, false)]);
        let merged = case.run();
        assert_eq!(merged.store_as, None);
        assert_eq!(merged.entries, merged.before);
    }

    #[test]
    fn the_later_change_wins() {
        let mut case = Case::new(vec![pin("bob", 2, 10, PinSource::Checked, false)]);
        case.explicit = vec![pin("bob", 3, 20, PinSource::Checked, true)];
        let merged = case.run();
        assert_eq!(merged.entries["bob"].key, Some([3; PUBLIC_KEY_LEN]));
        assert_eq!(merged.store_as, Some(5));
        // An older change than the servers' copy loses.
        case.explicit = vec![pin("bob", 3, 5, PinSource::Checked, true)];
        assert_eq!(case.run().entries["bob"].key, Some([2; PUBLIC_KEY_LEN]));
    }

    #[test]
    fn a_key_checked_again_keeps_how_and_a_new_key_keeps_the_mark() {
        let mut case = Case::new(vec![pin("bob", 2, 10, PinSource::Invited, true)]);
        // A local change to the same key is no change.
        case.base = Some(Keys::new());
        assert_eq!(case.run().entries["bob"].source, PinSource::Invited);
        // A new key for bob, checked here: checked, still an introducer.
        case.base = Some(case.local.clone());
        case.local.insert("bob".into(), [7; PUBLIC_KEY_LEN]);
        let bob = &case.run().entries["bob"];
        assert_eq!(
            (bob.key, &bob.source, bob.introducer),
            (Some([7; PUBLIC_KEY_LEN]), &PinSource::Checked, true)
        );
    }

    #[test]
    fn an_invitation_pins_a_proved_key_and_waits_for_anything_else() {
        let secret = [9; 32];
        let open = |at| PendingInvite {
            user: "carol".into(),
            secret: Some(secret),
            at,
        };
        let key = [5; PUBLIC_KEY_LEN];
        let mut case = Case::new(Vec::new());
        case.invites = vec![open(NOW - 10)];
        case.enrollments.insert(
            "carol".into(),
            Enrollment::Enrolled {
                key: key.to_vec(),
                proof: invite_proof(&secret, "carol", "me", &key).to_vec(),
            },
        );
        let merged = case.run();
        assert_eq!(merged.entries["carol"].key, Some(key));
        assert_eq!(merged.entries["carol"].source, PinSource::Invited);
        assert_eq!(merged.invites[0].secret, None, "closed");

        // A key with no matching proof: nothing pinned; it waits.
        case.enrollments.insert(
            "carol".into(),
            Enrollment::Enrolled {
                key: [6; PUBLIC_KEY_LEN].to_vec(),
                proof: invite_proof(&secret, "carol", "me", &key).to_vec(),
            },
        );
        let merged = case.run();
        assert!(!merged.entries.contains_key("carol"));
        assert!(merged.invites[0].secret.is_some() && merged.found.warnings.is_empty());

        // Too old: closed, with a warning only if carol enrolled.
        case.invites = vec![open(NOW - INVITE_LIFETIME_SECS - 1)];
        let merged = case.run();
        assert_eq!(merged.invites[0].secret, None);
        assert_eq!(merged.found.warnings.len(), 1);
        case.enrollments.insert("carol".into(), Enrollment::NotYet);
        assert!(case.run().found.warnings.is_empty());

        // A user the servers couldn't be asked about waits, however old.
        case.enrollments.clear();
        assert!(case.run().invites[0].secret.is_some());
    }

    fn introduction(by: &Identity, by_name: &str, to: &Identity, what: Introduced) -> Introduction {
        Introduction {
            recipient: "me".into(),
            subject: what.subject.clone(),
            introducer: by_name.into(),
            sealed: seal_introduction(by, by_name, &to.public_key(), &what),
        }
    }

    #[test]
    fn introductions_count_only_from_introducers_and_replace_only_a_checked_key() {
        let alice = Identity::generate();
        let mut case = Case::new(Vec::new());
        let alice_pin = |introducer| PinEntry {
            key: Some(alice.public_key()),
            ..pin("alice", 0, 10, PinSource::Checked, introducer)
        };
        let carol = |key, replaces| Introduced {
            subject: "carol".into(),
            key: [key; PUBLIC_KEY_LEN],
            replaces,
        };
        case.inbox = vec![introduction(&alice, "alice", &case.me, carol(3, None))];

        // alice isn't an introducer here: the introduction stays for later.
        case.stored.entries = vec![alice_pin(false)];
        let merged = case.run();
        assert!(!merged.entries.contains_key("carol"));
        assert!(merged.found.done.is_empty());

        // She is: carol is pinned as introduced by her.
        case.stored.entries = vec![alice_pin(true)];
        let merged = case.run();
        assert_eq!(
            merged.entries["carol"].source,
            PinSource::Introduced { by: "alice".into() }
        );
        assert_eq!(merged.found.done.len(), 1);

        // Another key for a pinned carol: only with `replaces` naming hers.
        case.stored.entries = vec![
            alice_pin(true),
            pin("carol", 3, 10, PinSource::Checked, false),
        ];
        case.inbox = vec![introduction(&alice, "alice", &case.me, carol(4, None))];
        let merged = case.run();
        assert_eq!(merged.entries["carol"].key, Some([3; PUBLIC_KEY_LEN]));
        assert_eq!(merged.found.warnings.len(), 1);
        case.inbox = vec![introduction(
            &alice,
            "alice",
            &case.me,
            carol(4, Some([3; PUBLIC_KEY_LEN])),
        )];
        assert_eq!(case.run().entries["carol"].key, Some([4; PUBLIC_KEY_LEN]));

        // A box that someone else sealed in alice's name is dropped.
        let mallory = Identity::generate();
        case.inbox = vec![introduction(&mallory, "alice", &case.me, carol(4, None))];
        let merged = case.run();
        assert_eq!(merged.entries["carol"].key, Some([3; PUBLIC_KEY_LEN]));
        assert_eq!(merged.found.done.len(), 1);
    }

    #[test]
    fn a_dead_links_pin_goes() {
        let link = format!("{LINK_PREFIX}abc");
        let mut case = Case::new(vec![pin(&link, 2, 10, PinSource::Checked, false)]);
        case.dead.insert(link.clone());
        let merged = case.run();
        assert!(!merged.entries.contains_key(&link));
        assert!(merged.store_as.is_some());
    }
}
