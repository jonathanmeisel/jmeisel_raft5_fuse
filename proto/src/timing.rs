//! Where a request's time went on the server, for a client finding out
//! why an operation is slow.
//!
//! A server started with `RAFT5FS_TIMING=1` answers every request with a
//! [`HEADER`] saying how long it took to handle and how much of that it
//! spent waiting on the store; the client, given `RAFT5FS_TIMING=1` too,
//! sets that against how long the request took from where it sits. The
//! rest is the network -- and anything queued in front of the request on
//! either end.
//!
//! Off on the server unless asked for: how many store calls a request
//! made says something about what the request found, and that is no
//! business of an unauthenticated caller's.

use std::fmt;
use std::time::Duration;

/// The response header a timing server answers with.
pub const HEADER: &str = "x-raft5fs-timing";

/// One kind of store call: how many, and how long they were waited on in
/// all. Calls made concurrently are summed, so their waits can add up to
/// more than the request took.
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

/// What a request spent on the store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreTime {
    /// Point reads, any number of keys each: one round trip apiece.
    pub reads: Calls,
    /// Batches of keys fetched by key walks: one round trip apiece.
    pub scans: Calls,
    /// Transaction attempts -- more than one for a transaction that
    /// aborted on a conflict and ran again -- each counted for the time
    /// it took beyond its reads and scans: beginning, writing, committing,
    /// and the server's own work in between.
    pub txns: Calls,
    /// Anything else: a write outside a transaction, a look at which
    /// snapshots there are.
    pub other: Calls,
}

/// What [`HEADER`] carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerTiming {
    /// From the request reaching the service to its answer being ready
    /// to send: everything but the network.
    pub handled: Duration,
    pub store: StoreTime,
}

impl ServerTiming {
    /// As the header carries it:
    /// `handled=US;reads=N/US;scans=N/US;txns=N/US;other=N/US`, times in
    /// microseconds.
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

    /// The header's value, or `None` if it isn't one `encode` makes.
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
                // From a newer server: what this client knows is still good.
                _ => {}
            }
        }
        Some(timing)
    }
}

/// `d` in milliseconds, to a tenth: the resolution worth reading.
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
