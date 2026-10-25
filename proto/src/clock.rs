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
