//! `raft5fs`: see `commands`.

use clap::Parser;
use commands::{Cli, run};

mod commands;

fn main() {
    // Search indexing runs behind the device's own work: the models use
    // half the cores, at most four, unless the user says otherwise.
    #[cfg(feature = "index")]
    if std::env::var_os("CANDLE_NUM_THREADS").is_none() {
        let threads = std::thread::available_parallelism().map_or(1, |n| (n.get() / 2).clamp(1, 4));
        // Safety: no other thread exists yet to read the environment.
        unsafe { std::env::set_var("CANDLE_NUM_THREADS", threads.to_string()) };
    }
    std::process::exit(run(Cli::parse()));
}
