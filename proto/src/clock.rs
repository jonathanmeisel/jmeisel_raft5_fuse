//! The wall clock. `SystemTime::now` panics in a browser (WebAssembly has
//! no clock of its own), so everything that reads the time asks here.
//! Values stay `std::time::SystemTime`, which works everywhere.

use std::time::SystemTime;

/// The current time.
pub fn now() -> SystemTime {
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
    }
    #[cfg(target_arch = "wasm32")]
    {
        // Milliseconds since the epoch, from the browser.
        std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(js_sys::Date::now() / 1000.0)
    }
}

/// Whole seconds from the Unix epoch to `t`, or 0 for a time before it.
pub fn secs(t: SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Milliseconds from the Unix epoch to `t`, or 0 for a time before it.
pub fn millis(t: SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}

/// `secs` of the current time.
pub fn now_secs() -> u64 {
    secs(now())
}

/// `millis` of the current time.
pub fn now_millis() -> u64 {
    millis(now())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn times_count_from_the_epoch_and_never_below_it() {
        let t = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
        assert_eq!(secs(t), 1_700_000_000);
        assert_eq!(millis(t), 1_700_000_000_123);
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!((secs(before), millis(before)), (0, 0));
    }
}
