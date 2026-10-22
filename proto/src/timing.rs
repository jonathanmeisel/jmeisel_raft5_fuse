//! Shows where a request's time went on the server, so a client can find
//! out why an operation is slow.
//!
//! A server started with `RAFT5FS_TIMING=1` adds a [`HEADER`] to every
//! response. It says how long the server took to handle the request, and
//! how much of that time it waited on the store. A client with
//! `RAFT5FS_TIMING=1` compares that with the total time it measured. The
//! rest is the network, and anything queued in front of the request on
//! either side.
//!
//! It is off on the server by default. The number of store calls tells
//! something about what the request found, and an unauthenticated caller
//! must not learn that.

use std::fmt;
use std::time::Duration;

/// The response header that a timing server adds.
pub const HEADER: &str = "x-raft5fs-timing";

/// One kind of store call: how many calls, and how long they were waited on
/// in total. Calls made at the same time are added together, so their total
/// wait can be longer than the request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Calls {
    pub count: u32,
    pub waited: Duration,
}

impl Calls {
    pub fn add(&mut self, waited: Duration) {
        self.count += 1;
        self.waited += waited;
    }
}

/// The time that a request spent on the store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreTime {
    /// Point reads, of any number of keys each. Each one is one round trip.
    pub reads: Calls,
    /// Batches of keys fetched by key walks. Each one is one round trip.
    pub scans: Calls,
    /// Transaction attempts. A transaction that aborted on a conflict and
    /// ran again counts more than once. Each attempt counts the time it
    /// took apart from its reads and scans: begin, write, commit, and the
    /// server's own work between them.
    pub txns: Calls,
    /// Anything else, such as a write outside a transaction, or a check of
    /// which snapshots exist.
    pub other: Calls,
}

/// The contents of [`HEADER`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerTiming {
    /// From when the request reaches the service to when its answer is
    /// ready to send: everything except the network.
    pub handled: Duration,
    pub store: StoreTime,
}

impl ServerTiming {
    /// Encodes as `handled=US;reads=N/US;scans=N/US;txns=N/US;other=N/US`,
    /// with times in microseconds.
    pub fn encode(&self) -> String {
        let calls = |c: &Calls| format!("{}/{}", c.count, c.waited.as_micros());
        format!(
            "handled={};reads={};scans={};txns={};other={}",
            self.handled.as_micros(),
            calls(&self.store.reads),
            calls(&self.store.scans),
            calls(&self.store.txns),
            calls(&self.store.other),
        )
    }

    /// Decodes the header's value. Returns `None` if `encode` did not make
    /// it.
    pub fn decode(value: &str) -> Option<Self> {
        let micros = |s: &str| s.parse().ok().map(Duration::from_micros);
        let calls = |s: &str| {
            let (count, waited) = s.split_once('/')?;
            Some(Calls {
                count: count.parse().ok()?,
                waited: micros(waited)?,
            })
        };
        let mut timing = Self::default();
        for field in value.split(';') {
            let (name, value) = field.split_once('=')?;
            match name {
                "handled" => timing.handled = micros(value)?,
                "reads" => timing.store.reads = calls(value)?,
                "scans" => timing.store.scans = calls(value)?,
                "txns" => timing.store.txns = calls(value)?,
                "other" => timing.store.other = calls(value)?,
                // A field from a newer server. Ignore it: the known fields
                // are still correct.
                _ => {}
            }
        }
        Some(timing)
    }
}

/// `d` in milliseconds, to one decimal place. More precision is not useful.
pub fn ms(d: Duration) -> String {
    format!("{:.1}ms", d.as_secs_f64() * 1000.0)
}

impl fmt::Display for StoreTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        for (calls, one, many) in [
            (&self.reads, "read", "reads"),
            (&self.scans, "key batch", "key batches"),
            (&self.txns, "txn attempt", "txn attempts"),
            (&self.other, "other call", "other calls"),
        ] {
            if calls.count > 0 {
                let what = if calls.count == 1 { one } else { many };
                parts.push(format!("{} {what} {}", calls.count, ms(calls.waited)));
            }
        }
        if parts.is_empty() {
            write!(f, "no store calls")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

impl fmt::Display for ServerTiming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "handled in {} ({})", ms(self.handled), self.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let timing = ServerTiming {
            handled: Duration::from_micros(5_123),
            store: StoreTime {
                reads: Calls {
                    count: 3,
                    waited: Duration::from_micros(4_700),
                },
                scans: Calls {
                    count: 1,
                    waited: Duration::from_micros(300),
                },
                txns: Calls::default(),
                other: Calls::default(),
            },
        };
        assert_eq!(
            timing.encode(),
            "handled=5123;reads=3/4700;scans=1/300;txns=0/0;other=0/0"
        );
        assert_eq!(ServerTiming::decode(&timing.encode()), Some(timing));
    }

    #[test]
    fn ignores_unknown_fields_and_refuses_garbage() {
        assert_eq!(
            ServerTiming::decode("handled=7;later=1/2").map(|t| t.handled),
            Some(Duration::from_micros(7))
        );
        assert_eq!(ServerTiming::decode("handled=seven"), None);
        assert_eq!(ServerTiming::decode("reads=3"), None);
    }

    #[test]
    fn says_only_what_happened() {
        let mut store = StoreTime::default();
        assert_eq!(store.to_string(), "no store calls");
        store.reads.add(Duration::from_micros(1_260));
        store.scans.add(Duration::from_micros(500));
        store.scans.add(Duration::from_micros(500));
        assert_eq!(store.to_string(), "1 read 1.3ms, 2 key batches 1.0ms");
    }
}
