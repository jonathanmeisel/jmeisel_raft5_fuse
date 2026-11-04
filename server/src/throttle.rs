//! Slows down password guessing against the servers.
//!
//! A login needs no session, so anyone who can reach a server can try
//! passwords, and a correct one returns the account's wrapped private key.
//! Argon2 costs the guesser, but only on their own machines. So each server
//! counts failed guesses, for each account name and each address:
//!
//! - After `NAME_FREE` failures for a name, or `ADDRESS_FREE` from an address,
//!   more attempts are refused without being checked, for a time that doubles
//!   with each failure, up to `MAX_BLOCK`. That leaves one guess a minute for
//!   a name, on each server.
//! - The same refusal comes for any name, so it doesn't say which accounts
//!   exist. It doesn't depend on the password, so it says nothing about that.
//! - Only new guesses count. A client repeating one old password, such as a
//!   mount after a password change, learns nothing new, and mustn't lock out
//!   its own user.
//! - A success clears the name's count, not the address's: otherwise someone
//!   could guess on, logging in to their own account every few tries.
//! - Public links have no count by name. Their secrets can't be guessed, and
//!   a stranger must not be able to block a link for everyone who has it.
//!
//! Anyone can use up a name's failures, which keeps its owner out for up to
//! `MAX_BLOCK` at a time while it goes on. Sessions already open are not
//! affected, and the limit is short so that this stays an annoyance.
//!
//! The counts live in memory, on each server, and go when it restarts. They
//! don't need to be exact to make guessing impractical.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use raft5fs_proto::types::LINK_PREFIX;

/// How many failures a name may have before attempts are refused.
const NAME_FREE: u32 = 5;
/// How many failures an address may have. It is higher because a household
/// shares one address.
const ADDRESS_FREE: u32 = 20;
/// The longest that attempts are refused for at a time.
const MAX_BLOCK: Duration = Duration::from_secs(60);
/// How long after its last failure a count is forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(3600);
/// How many counts each table holds before it forgets the old ones. Each name
/// or address that fails takes one, so this bounds the memory a flood can use.
const MAX_COUNTS: usize = 1 << 16;
/// How many different guesses each count remembers, to not count them twice.
const RECENT_GUESSES: usize = 4;

/// One name's or address's failures.
struct Count {
    failures: u32,
    blocked_until: Option<Instant>,
    last_failure: Instant,
    /// Hashes of the latest guesses. A hash is enough: a collision only leaves
    /// one guess uncounted.
    recent: Vec<u64>,
}

/// Failures by name or address.
struct Counts<K> {
    free: u32,
    counts: HashMap<K, Count>,
}

impl<K: Eq + Hash + Clone> Counts<K> {
    fn new(free: u32) -> Self {
        Self {
            free,
            counts: HashMap::new(),
        }
    }

    /// How long `key` must still wait, if it must.
    fn wait(&self, key: &K, now: Instant) -> Option<Duration> {
        let until = self.counts.get(key)?.blocked_until?;
        (until > now).then(|| until - now)
    }

    /// Counts a failed `guess` by `key`, if it is a new one.
    fn fail(&mut self, key: &K, guess: u64, now: Instant) {
        if self.counts.len() >= MAX_COUNTS && !self.counts.contains_key(key) {
            self.counts
                .retain(|_, count| now.duration_since(count.last_failure) < FORGET_AFTER);
            // Still full of recent ones: a flood. Forgetting them lets it make
            // a few more guesses, but memory stays bounded.
            if self.counts.len() >= MAX_COUNTS {
                self.counts.clear();
            }
        }
        let count = self.counts.entry(key.clone()).or_insert(Count {
            failures: 0,
            blocked_until: None,
            last_failure: now,
            recent: Vec::new(),
        });
        if now.duration_since(count.last_failure) >= FORGET_AFTER {
            count.failures = 0;
            count.recent.clear();
        }
        count.last_failure = now;
        if count.recent.contains(&guess) {
            return;
        }
        if count.recent.len() == RECENT_GUESSES {
            count.recent.remove(0);
        }
        count.recent.push(guess);
        count.failures += 1;
        if count.failures >= self.free {
            let doublings = (count.failures - self.free).min(16);
            let block = Duration::from_secs(1u64 << doublings).min(MAX_BLOCK);
            count.blocked_until = Some(now + block);
        }
    }

    fn clear(&mut self, key: &K) {
        self.counts.remove(key);
    }
}

/// The address to count failures against. An IPv6 client usually controls a
/// whole /64, so that counts as one address.
fn counted_address(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(octets.into())
        }
        v4 => v4,
    }
}

/// Whether failures are counted against `name` (see the top of this file).
fn counts_by_name(name: &str) -> bool {
    !name.starts_with(LINK_PREFIX)
}

pub(crate) struct LoginThrottle {
    names: Mutex<Counts<String>>,
    addresses: Mutex<Counts<IpAddr>>,
    hasher: RandomState,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self {
            names: Mutex::new(Counts::new(NAME_FREE)),
            addresses: Mutex::new(Counts::new(ADDRESS_FREE)),
            hasher: RandomState::new(),
        }
    }
}

impl LoginThrottle {
    /// How long an attempt for `name` from `address` must still wait, if it
    /// must. Ask before checking the password.
    pub(crate) fn wait(
        &self,
        name: &str,
        address: Option<IpAddr>,
        now: Instant,
    ) -> Option<Duration> {
        let by_name = self.names.lock().unwrap().wait(&name.to_string(), now);
        let by_address = address.and_then(|a| {
            self.addresses
                .lock()
                .unwrap()
                .wait(&counted_address(a), now)
        });
        by_name.max(by_address)
    }

    /// Counts a failed attempt with `auth`.
    pub(crate) fn failed(&self, name: &str, address: Option<IpAddr>, auth: &[u8], now: Instant) {
        let guess = self.hasher.hash_one((name, auth));
        if counts_by_name(name) {
            self.names
                .lock()
                .unwrap()
                .fail(&name.to_string(), guess, now);
        }
        if let Some(address) = address {
            self.addresses
                .lock()
                .unwrap()
                .fail(&counted_address(address), guess, now);
        }
    }

    /// Clears `name`'s failures, after a correct password.
    pub(crate) fn succeeded(&self, name: &str) {
        self.names.lock().unwrap().clear(&name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
    const AWAY: Option<IpAddr> = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)));

    /// Fails `n` different guesses for `name`, from `address`.
    fn fail(t: &LoginThrottle, name: &str, address: Option<IpAddr>, n: u32, now: Instant) {
        for i in 0..n {
            t.failed(name, address, format!("{name}-{i}").as_bytes(), now);
        }
    }

    #[test]
    fn a_name_is_blocked_after_its_free_failures_from_any_address() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        fail(&t, "alice", HOME, NAME_FREE - 1, now);
        assert_eq!(t.wait("alice", HOME, now), None);
        t.failed("alice", HOME, b"one more", now);
        assert_eq!(t.wait("alice", HOME, now), Some(Duration::from_secs(1)));
        assert_eq!(t.wait("alice", AWAY, now), Some(Duration::from_secs(1)));
        assert_eq!(t.wait("bob", AWAY, now), None);
        assert_eq!(t.wait("alice", HOME, now + Duration::from_secs(1)), None);
    }

    #[test]
    fn the_block_doubles_up_to_the_limit() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        fail(&t, "alice", None, NAME_FREE, now);
        for (i, seconds) in [2, 4, 8, 16, 32, 60, 60].into_iter().enumerate() {
            t.failed("alice", None, format!("guess {i}").as_bytes(), now);
            assert_eq!(
                t.wait("alice", None, now),
                Some(Duration::from_secs(seconds))
            );
        }
        // Thousands of failures don't overflow, and stay at the limit.
        fail(&t, "alice", None, 5000, now);
        assert_eq!(t.wait("alice", None, now), Some(MAX_BLOCK));
    }

    #[test]
    fn repeating_one_guess_counts_once() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..1000 {
            t.failed("alice", HOME, b"the old password", now);
        }
        assert_eq!(t.wait("alice", HOME, now), None);
    }

    #[test]
    fn a_success_clears_the_name_but_not_the_address() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        fail(&t, "alice", HOME, ADDRESS_FREE - 1, now);
        t.succeeded("alice");
        assert_eq!(t.wait("alice", AWAY, now), None);
        // Guessing at others, with logins to your own account between, still
        // adds up against the address.
        t.failed("carol", HOME, b"another", now);
        assert_eq!(t.wait("bob", HOME, now), Some(Duration::from_secs(1)));
        assert_eq!(t.wait("bob", AWAY, now), None);
    }

    #[test]
    fn a_link_has_no_count_by_name_only_by_address() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        fail(&t, "link-abc", HOME, 1000, now);
        assert_eq!(t.wait("link-abc", AWAY, now), None);
        assert!(t.wait("link-abc", HOME, now).is_some());
    }

    #[test]
    fn counts_are_forgotten_in_time() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        fail(&t, "alice", HOME, NAME_FREE, now);
        let later = now + FORGET_AFTER;
        // Past its block, and this failure starts counting from one.
        t.failed("alice", HOME, b"much later", later);
        assert_eq!(t.wait("alice", HOME, later), None);
    }

    #[test]
    fn an_ipv6_address_counts_by_its_64_and_mapped_ipv4_as_ipv4() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(counted_address(a), counted_address(b));
        assert_ne!(counted_address(a), counted_address(c));
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(counted_address(mapped), HOME.unwrap());
    }

    #[test]
    fn a_flood_of_names_stays_bounded() {
        let mut counts = Counts::<String>::new(NAME_FREE);
        let now = Instant::now();
        for i in 0..MAX_COUNTS + 10 {
            counts.fail(&format!("n{i}"), 1, now);
        }
        assert!(counts.counts.len() <= MAX_COUNTS);
    }
}
